//! shbox: a foreground SSH daemon that maps authenticated keys onto
//! persistent sandbox workspaces.
//!
//! Bootstrap: resolve and validate every local input, reconcile durable
//! sandbox metadata, initialize the process-lifetime Arapuca adapter, then
//! run the public-key SSH server with the admin-only `_` host route. Adapter
//! initialization remains fail-closed for sandbox launches so host recovery
//! and metadata management do not depend on a working sandbox runtime.

mod account;
mod auth;
mod config;
mod hostkey;
mod lockfile;
mod logging;
mod paths;
mod platform;
mod sandbox;
mod server;
mod ssh;

use std::fmt;
use std::process::ExitCode;
use std::sync::Arc;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::process::CommandExt;

use crate::auth::KeyFingerprint;

use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};

/// Foreground SSH daemon mapping authenticated keys onto persistent sandbox
/// workspaces.
///
/// The v0.1 command line has no subcommands and no server-setting flags: the
/// daemon reads its configuration from XDG paths. `parse` is the process
/// entry; `--help`/`--version` print and exit 0, parse failures print to
/// stderr and exit non-zero.
#[derive(usage::Cli)]
#[usage(bin = "shbox", version)]
struct Args {}

fn main() -> ExitCode {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if embedded_arapuca_wrapper_invocation() {
        return run_embedded_arapuca_wrapper();
    }

    let _args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run()),
        Err(err) => Err(fail("building the async runtime", err)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report(&err);
            ExitCode::FAILURE
        }
    }
}

/// macOS does not need Arapuca's Linux Landlock/seccomp wrapper, but it still
/// needs the wrapper boundary for per-process rlimits. Reuse the daemon
/// executable for that small boundary when a standalone `arapuca` binary is
/// not installed. The environment sentinel is set only by Arapuca's own
/// launch path; ordinary `shbox` invocations continue through the CLI parser.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn embedded_arapuca_wrapper_invocation() -> bool {
    std::env::var_os("ARAPUCA_WRAPPER").as_deref() == Some(std::ffi::OsStr::new("1"))
        && std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--"))
}

/// Apply the rlimits prepared by Arapuca and replace this process with the
/// Seatbelt command. This mirrors the standalone Arapuca wrapper contract:
/// ARAPUCA_* control variables are consumed here and never reach the
/// sandboxed command.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_embedded_arapuca_wrapper() -> ExitCode {
    let mut args = std::env::args_os();
    let _executable = args.next();
    let separator = args.next();
    let Some(command) = args.next() else {
        eprintln!("shbox: embedded arapuca wrapper: missing command after --");
        return ExitCode::FAILURE;
    };
    if separator.as_deref() != Some(std::ffi::OsStr::new("--")) {
        eprintln!("shbox: embedded arapuca wrapper: invalid invocation");
        return ExitCode::FAILURE;
    }

    if let Err(error) = ::arapuca::rlimit::apply_from_env() {
        eprintln!("shbox: embedded arapuca wrapper: {error}");
        return ExitCode::FAILURE;
    }

    let mut child = std::process::Command::new(command);
    child.args(args);
    child.env_clear();
    for (name, value) in std::env::vars_os() {
        let is_arapuca_control = name
            .to_str()
            .is_some_and(|name| name.starts_with("ARAPUCA_"));
        if !is_arapuca_control {
            child.env(name, value);
        }
    }

    let error = child.exec();
    eprintln!("shbox: embedded arapuca wrapper: exec failed: {error}");
    ExitCode::FAILURE
}

/// A bootstrap failure with the startup step that produced it.
#[derive(Debug)]
struct BootstrapError {
    step: &'static str,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.step, self.source)
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

fn fail<E>(step: &'static str, error: E) -> BootstrapError
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    BootstrapError {
        step,
        source: error.into(),
    }
}

/// Print the error chain to stderr for the operator.
fn report(error: &BootstrapError) {
    error!(step = error.step, "startup failed: {error}");
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        eprintln!("shbox: caused by: {current}");
        cause = current.source();
    }
}

/// Resolve and validate every local input, then serve SSH until shutdown.
async fn run() -> Result<(), BootstrapError> {
    // Logging starts at info so early failures are visible; the configured
    // level replaces it as soon as the config snapshot exists.
    let logging = logging::init(LevelFilter::INFO);

    let paths = paths::Paths::resolve().map_err(|err| fail("resolving XDG paths", err))?;
    paths
        .ensure()
        .map_err(|err| fail("creating shbox directories", err))?;
    let locks =
        lockfile::Locks::acquire(&paths).map_err(|err| fail("acquiring daemon locks", err))?;
    let app_config =
        config::Config::load_snapshot(&paths).map_err(|err| fail("loading configuration", err))?;
    logging.set_level(logging::level_filter(app_config.log_level()));

    let account =
        account::current_account().map_err(|err| fail("resolving the daemon account", err))?;
    let sandbox_shell = account
        .sandbox_shell(&app_config)
        .map_err(|err| fail("selecting the sandbox shell", err))?;
    account::validate_executable(&sandbox_shell)
        .map_err(|err| fail("validating the sandbox shell", err))?;
    let host_shell = account.host_shell();
    account::validate_executable(&host_shell)
        .map_err(|err| fail("validating the host shell", err))?;

    let authorized_keys = auth::resolve_authorized_keys_path(app_config.authorized_keys())
        .map_err(|err| fail("resolving authorized_keys", err))?;
    auth::validate_authorized_keys_file(&authorized_keys)
        .map_err(|err| fail("validating authorized_keys", err))?;
    let auth_snapshot = auth::AuthSnapshot::load(&authorized_keys, app_config.admin_keys())
        .map_err(|err| fail("loading the authentication snapshot", err))?;

    let host_key = hostkey::HostKey::load_or_create(paths.host_key())
        .map_err(|err| fail("loading the host key", err))?;
    let launch_policy = platform::ArapucaLaunchPolicy::from_config(&app_config, &sandbox_shell);
    let (launcher, arapuca_launcher): (
        Arc<dyn platform::ProcessLauncher>,
        Option<Arc<platform::ArapucaLauncher>>,
    ) = match platform::ArapucaLauncher::new(launch_policy) {
        Ok(launcher) => {
            info!("sandbox process adapter initialized");
            let launcher = Arc::new(launcher);
            (
                Arc::clone(&launcher) as Arc<dyn platform::ProcessLauncher>,
                Some(launcher),
            )
        }
        Err(error) => {
            warn!(error = %error, "sandbox process adapter unavailable; launches will fail closed");
            (Arc::new(platform::UnavailableLauncher), None)
        }
    };
    let sandbox_manager = Arc::new(
        if app_config.managed_mode() {
            sandbox::SandboxManager::open_unreconciled_with_launcher(
                &paths,
                *app_config.caps(),
                launcher,
            )
        } else {
            sandbox::SandboxManager::open_with_launcher(&paths, *app_config.caps(), launcher)
        }
        .map_err(|err| fail("reconciling sandbox registry", err))?,
    );

    debug!(
        limits = ?app_config.limits(),
        caps = ?app_config.caps(),
        read_paths = app_config.read_paths().len(),
        sandbox_env = app_config.sandbox_env().len(),
        "enforcing configured limits and caps"
    );
    if app_config.managed_mode() {
        info!(
            admins = auth_snapshot.admin_count(),
            user = %account.name,
            "managed mode: host selector \"_\" is available to admin keys"
        );
        debug!(
            admins = %app_config
                .admin_keys()
                .iter()
                .map(KeyFingerprint::to_string)
                .collect::<Vec<_>>()
                .join(","),
            "admin fingerprints"
        );
    } else {
        warn!(
            "sandbox-only mode: no admin key is configured, the host selector has no recovery route"
        );
    }
    if app_config.network() == config::NetworkMode::Outbound {
        warn!(
            "network = \"outbound\": sandbox network isolation is reduced; restrict reachability with a host firewall"
        );
    }

    let account_name = account.name.clone();
    let shared = ssh::Shared {
        auth: Arc::new(auth_snapshot),
        config: Arc::new(app_config.clone()),
        account: Arc::new(account.clone()),
        sandbox: Arc::clone(&sandbox_manager),
    };
    let server = Arc::new(server::SshServer::new(
        shared,
        host_key.key().clone(),
        &app_config,
    ));
    let sockets = server::bind_all(app_config.listen())
        .await
        .map_err(|err| fail("binding listen addresses", err))?;
    let bound: Vec<_> = sockets
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut serve_task = tokio::spawn(server.clone().serve(sockets, shutdown_rx));
    let mut reconciliation_task = if app_config.managed_mode() {
        let manager = Arc::clone(&sandbox_manager);
        Some(
            std::thread::Builder::new()
                .name("shbox-startup-reconciliation".to_string())
                .spawn(move || manager.reconcile_startup())
                .map_err(|err| fail("starting sandbox reconciliation", err))?,
        )
    } else {
        None
    };
    info!(
        user = %account_name,
        listen = ?bound,
        host_key_fingerprint = %host_key.key().fingerprint(russh::keys::HashAlg::Sha256),
        "shbox ready"
    );

    let mut current_config = app_config;
    let mut signals = SignalReceiver::new();
    loop {
        tokio::select! {
            result = &mut serve_task => {
                result.map_err(|err| fail("serving SSH", err))?;
                if let Some(task) = reconciliation_task.take() {
                    join_reconciliation(task).await?;
                }
                drop(locks);
                return Ok(());
            }
            signal = signals.recv() => match signal {
                DaemonSignal::Reload => {
                    match load_reload_snapshot(&paths, &current_config, &account).await {
                        Ok(snapshot) => {
                            if let Some(launcher) = arapuca_launcher.as_ref()
                                && let Err(error) = launcher.reload_policy(snapshot.policy.clone())
                            {
                                warn!(error = %error, "SIGHUP reload rejected by sandbox adapter");
                                continue;
                            }
                            let next_shared = ssh::Shared {
                                auth: Arc::new(snapshot.auth),
                                config: Arc::new(snapshot.config.clone()),
                                account: Arc::new(account.clone()),
                                sandbox: Arc::clone(&sandbox_manager),
                            };
                            server.reload(next_shared);
                            logging.set_level(logging::level_filter(snapshot.config.log_level()));
                            current_config = snapshot.config;
                            info!("configuration and authentication snapshot reloaded");
                        }
                        Err(error) => {
                            warn!(error = %error, "SIGHUP reload rejected; keeping the previous snapshot");
                        }
                    }
                }
                DaemonSignal::Shutdown => {
                    info!("shutdown signal received: draining runtime processes");
                    let _ = shutdown_tx.send(true);
                    tokio::select! {
                        result = &mut serve_task => {
                            result.map_err(|err| fail("serving SSH", err))?;
                        }
                        _ = signals.recv_shutdown() => {
                            warn!("second shutdown signal received; stopping immediately");
                            server.force_stop_host_tasks();
                            sandbox_manager.force_shutdown_runtime();
                            serve_task.abort();
                            let _ = serve_task.await;
                            // A blocking reconciliation thread cannot be
                            // cancelled. Detach it so the second-signal path
                            // does not wait for filesystem cleanup to finish;
                            // the next startup will retry any remaining work.
                            drop(reconciliation_task.take());
                            drop(locks);
                            info!("shutdown stopped after second signal");
                            return Ok(());
                        }
                    }
                    if let Some(task) = reconciliation_task.take() {
                        join_reconciliation(task).await?;
                    }
                    drop(locks);
                    info!("shutdown complete");
                    return Ok(());
                }
            }
        }
    }
}

/// Join the managed-mode reconciliation thread only on the normal shutdown
/// path. The second-signal path deliberately drops its std thread handle so a
/// slow filesystem operation cannot hold the daemon open.
async fn join_reconciliation(task: std::thread::JoinHandle<()>) -> Result<(), BootstrapError> {
    tokio::task::spawn_blocking(move || task.join())
        .await
        .map_err(|err| fail("joining sandbox reconciliation", err))?
        .map_err(|_| {
            fail(
                "reconciling sandbox registry",
                std::io::Error::other("reconciliation thread panicked"),
            )
        })
}

struct ReloadSnapshot {
    config: config::Config,
    auth: auth::AuthSnapshot,
    policy: platform::ArapucaLaunchPolicy,
}

#[derive(Debug)]
struct ReloadError(String);

impl fmt::Display for ReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReloadError {}

/// Load and validate every reload input before publishing any part of it.
async fn load_reload_snapshot(
    paths: &paths::Paths,
    previous: &config::Config,
    account: &account::Account,
) -> Result<ReloadSnapshot, ReloadError> {
    let paths = paths.clone();
    let previous = previous.clone();
    let account = account.clone();
    tokio::task::spawn_blocking(move || {
        let config = config::Config::load_snapshot(&paths)
            .map_err(|error| ReloadError(format!("loading configuration: {error}")))?;
        if previous.loaded_from_file() && !config.loaded_from_file() {
            return Err(ReloadError(
                "configuration file disappeared after a file-backed snapshot".into(),
            ));
        }
        if previous.listen() != config.listen() {
            return Err(ReloadError(
                "listen addresses are restart-only and cannot be reloaded".into(),
            ));
        }
        let sandbox_shell = account
            .sandbox_shell(&config)
            .map_err(|error| ReloadError(format!("selecting the sandbox shell: {error}")))?;
        account::validate_executable(&sandbox_shell)
            .map_err(|error| ReloadError(format!("validating the sandbox shell: {error}")))?;
        let authorized_keys = auth::resolve_authorized_keys_path(config.authorized_keys())
            .map_err(|error| ReloadError(format!("resolving authorized_keys: {error}")))?;
        auth::validate_authorized_keys_file(&authorized_keys)
            .map_err(|error| ReloadError(format!("validating authorized_keys: {error}")))?;
        let auth = auth::AuthSnapshot::load(&authorized_keys, config.admin_keys())
            .map_err(|error| ReloadError(format!("loading authentication snapshot: {error}")))?;
        let policy = platform::ArapucaLaunchPolicy::from_config(&config, &sandbox_shell);
        Ok(ReloadSnapshot {
            config,
            auth,
            policy,
        })
    })
    .await
    .map_err(|error| ReloadError(format!("reload task failed: {error}")))?
}

enum DaemonSignal {
    Reload,
    Shutdown,
}

struct SignalReceiver {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

impl SignalReceiver {
    fn new() -> SignalReceiver {
        use tokio::signal::unix::{SignalKind, signal};
        SignalReceiver {
            interrupt: signal(SignalKind::interrupt()).expect("SIGINT handler"),
            terminate: signal(SignalKind::terminate()).expect("SIGTERM handler"),
            hangup: signal(SignalKind::hangup()).expect("SIGHUP handler"),
        }
    }

    async fn recv(&mut self) -> DaemonSignal {
        tokio::select! {
            _ = self.interrupt.recv() => DaemonSignal::Shutdown,
            _ = self.terminate.recv() => DaemonSignal::Shutdown,
            _ = self.hangup.recv() => DaemonSignal::Reload,
        }
    }

    async fn recv_shutdown(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}
