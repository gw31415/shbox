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
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::process::CommandExt;

use tracing::{debug, error, info, warn};

/// Foreground SSH daemon mapping authenticated keys onto persistent sandbox
/// workspaces.
///
/// The command line has no subcommands: `parse` is the process entry.
/// `--help`/`--version` print and exit 0, parse failures print to stderr and
/// exit non-zero. `--completions`/`--man` print their artifact and exit
/// without touching any daemon input. The flags are a thin layer on top of
/// the top-level config fields: `--listen` and `--log-level` override the
/// file's `listen` and `log_level` when given, and there is deliberately no
/// flag for anything under `[sandbox]` (`network` included). Every setting
/// resolved this way is process-lifetime: SIGHUP never re-reads it.
#[derive(usage_rs::Cli)]
#[usage(bin = "shbox", version, completion)]
struct Args {
    /// SSH listener address; repeat the flag to override the config file's
    /// `listen` entirely. Defaults to the config file value, or 0.0.0.0:22.
    #[usage(long, value_name = "ADDR")]
    listen: Option<Vec<std::net::SocketAddr>>,
    /// Daemon log verbosity; overrides the config file's `log_level`.
    /// Defaults to the config file value, or info.
    #[usage(long, value_name = "LEVEL", value_enum)]
    log_level: Option<config::LogLevel>,
    /// Print a completion script for SHELL on stdout and exit.
    #[usage(long, value_name = "SHELL", value_enum)]
    completions: Option<CompletionShell>,
    /// Print the roff man page on stdout and exit.
    #[usage(long)]
    man: bool,
}

/// A completion shell accepted by `--completions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, usage_rs::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    // The ValueEnum default spelling would be "power-shell"; every shell and
    // the usage ecosystem itself name it as one word.
    #[usage(name = "powershell")]
    PowerShell,
}

impl CompletionShell {
    fn to_usage_shell(self) -> usage_rs::complete::Shell {
        match self {
            CompletionShell::Bash => usage_rs::complete::Shell::Bash,
            CompletionShell::Zsh => usage_rs::complete::Shell::Zsh,
            CompletionShell::Fish => usage_rs::complete::Shell::Fish,
            CompletionShell::PowerShell => usage_rs::complete::Shell::PowerShell,
        }
    }
}

/// A terminal action that prints a CLI artifact and exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputAction {
    Completions(CompletionShell),
    Man,
}

/// The listener addresses the daemon binds: the CLI layer on top of the
/// config file's `listen`. An absent `--listen` keeps the config value, which
/// `config::build` has already defaulted and validated; a present one
/// replaces it wholesale. All-or-nothing binding stays the binding-time rule.
fn effective_listen(
    cli: Option<&[std::net::SocketAddr]>,
    from_config: &[std::net::SocketAddr],
) -> Result<Vec<std::net::SocketAddr>, String> {
    let Some(listen) = cli else {
        return Ok(from_config.to_vec());
    };
    let mut seen = Vec::with_capacity(listen.len());
    for address in listen {
        if seen.contains(address) {
            return Err(format!("duplicate --listen address {address}"));
        }
        seen.push(*address);
    }
    Ok(seen)
}

/// The daemon log verbosity: the CLI layer on top of the config file's
/// `log_level`.
fn effective_log_level(
    cli: Option<config::LogLevel>,
    from_config: config::LogLevel,
) -> config::LogLevel {
    cli.unwrap_or(from_config)
}

impl Args {
    /// Resolve the requested output action, rejecting conflicting requests.
    fn output_action(&self) -> Result<Option<OutputAction>, String> {
        match (self.completions, self.man) {
            (Some(shell), false) => Ok(Some(OutputAction::Completions(shell))),
            (None, true) => Ok(Some(OutputAction::Man)),
            (Some(_), true) => {
                Err("--completions and --man are mutually exclusive output actions".to_string())
            }
            (None, false) => Ok(None),
        }
    }
}

/// Render the completion script for one supported shell, in process, from the
/// same `usage` declaration that backs `--help`.
fn completion_script(shell: CompletionShell) -> String {
    Args::completion_script(shell.to_usage_shell())
}

/// Render the roff man page, in process, from the same `usage` declaration
/// that backs `--help` and the completion scripts. The derive-generated spec
/// is the single source of truth; the renderer consumes its KDL form.
fn render_man_page() -> Result<String, Box<dyn std::error::Error>> {
    // `parse_spec` is the only public usage-lib entry point that reads raw
    // KDL, which is exactly what the derive's `to_kdl()` writes; its bare
    // deprecation has no replacement.
    #[allow(deprecated)]
    let spec = usage::Spec::parse_spec(&Args::to_kdl())?;
    let man = usage::docs::manpage::ManpageRenderer::new(spec)
        .with_section(1)
        .render()?;
    Ok(man)
}

/// Print a terminal artifact on stdout and translate failure to an exit code.
fn emit(action: OutputAction) -> ExitCode {
    let outcome = match action {
        OutputAction::Completions(shell) => Ok(completion_script(shell)),
        OutputAction::Man => render_man_page(),
    };
    match outcome {
        Ok(text) => {
            let mut stdout = std::io::stdout().lock();
            match stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("shbox: cannot write output: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("shbox: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if embedded_arapuca_wrapper_invocation() {
        return run_embedded_arapuca_wrapper();
    }

    let args = Args::parse();
    match args.output_action() {
        Ok(Some(action)) => return emit(action),
        Ok(None) => {}
        Err(message) => {
            eprintln!("shbox: {message}");
            return ExitCode::FAILURE;
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run(&args)),
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

/// Print the error chain to stderr for the operator. Startup can fail before
/// logging exists — the config file is one of logging's own inputs — so fall
/// back to a plain stderr headline when no subscriber is installed.
fn report(error: &BootstrapError) {
    if logging::initialized() {
        error!(step = error.step, "startup failed: {error}");
    } else {
        eprintln!("shbox: {error}");
    }
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        eprintln!("shbox: caused by: {current}");
        cause = current.source();
    }
}

/// Resolve and validate every local input, then serve SSH until shutdown.
/// The config file carries every setting, including the top-level operational
/// ones; the CLI flags layer on top of `listen` and `log_level` only. All of
/// them stay fixed for the process lifetime.
async fn run(args: &Args) -> Result<(), BootstrapError> {
    let paths = paths::Paths::resolve().map_err(|err| fail("resolving XDG paths", err))?;
    paths
        .ensure()
        .map_err(|err| fail("creating shbox directories", err))?;
    let locks =
        lockfile::Locks::acquire(&paths).map_err(|err| fail("acquiring daemon locks", err))?;
    let app_config =
        config::Config::load_snapshot(&paths).map_err(|err| fail("loading configuration", err))?;

    // The config file is a logging input (`log_level`), so the subscriber is
    // installed only after the snapshot exists.
    let listen =
        effective_listen(args.listen.as_deref(), app_config.listen()).map_err(|message| {
            fail(
                "resolving the listen addresses",
                std::io::Error::other(message),
            )
        })?;
    logging::init(logging::level_filter(effective_log_level(
        args.log_level,
        app_config.log_level(),
    )));

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

    let host_path = auth::resolve_authorized_keys_path()
        .map_err(|err| fail("resolving authorized_keys", err))?;
    let auth_snapshot = auth::AuthSnapshot::load(&host_path, paths.allowed_keys_file())
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
    let managed_mode = auth_snapshot.admin_count() > 0;
    let sandbox_manager = Arc::new(
        if managed_mode {
            sandbox::SandboxManager::open_unreconciled_with_launcher(
                &paths,
                config::Caps::default(),
                launcher,
            )
        } else {
            sandbox::SandboxManager::open_with_launcher(&paths, config::Caps::default(), launcher)
        }
        .map_err(|err| fail("reconciling sandbox registry", err))?,
    );

    debug!(
        limits = ?config::Limits::default(),
        caps = ?config::Caps::default(),
        read_paths = app_config.read_paths().len(),
        sandbox_env = app_config.sandbox_env().len(),
        "enforcing built-in limits and caps"
    );
    if managed_mode {
        info!(
            admins = auth_snapshot.admin_count(),
            user = %account.name,
            "managed mode: host selector \"_\" is available to admin keys"
        );
    } else {
        warn!(
            "sandbox-only mode: no admin key is configured, the host selector has no recovery route"
        );
    }
    if app_config.network() == config::NetworkMode::Outbound {
        warn!(
            "sandbox.network = \"outbound\": sandbox network isolation is reduced; restrict reachability with a host firewall"
        );
    }

    let account_name = account.name.clone();
    let shared = ssh::Shared {
        auth: Arc::new(auth_snapshot),
        account: Arc::new(account.clone()),
        sandbox: Arc::clone(&sandbox_manager),
    };
    let server = Arc::new(server::SshServer::new(shared, host_key.key().clone()));
    let sockets = server::bind_all(&listen)
        .await
        .map_err(|err| fail("binding listen addresses", err))?;
    let bound: Vec<_> = sockets
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut serve_task = tokio::spawn(server.clone().serve(sockets, shutdown_rx));
    let mut reconciliation_task = if managed_mode {
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
                                account: Arc::new(account.clone()),
                                sandbox: Arc::clone(&sandbox_manager),
                            };
                            server.reload(next_shared);
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
/// The top-level operational settings (`listen`, `log_level`) and the
/// `[sandbox] network` mode are process-lifetime: a config file that changes
/// any of them is rejected whole, keeping the previous snapshot, because only
/// a restart can rebind the listener, re-resolve the verbosity, or re-select
/// the sandbox network policy. The built-in caps/limits are equally
/// process-lifetime invariants.
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
        let lifetime_changed: Vec<&str> = [
            (previous.listen() != config.listen()).then_some("listen"),
            (previous.log_level() != config.log_level()).then_some("log_level"),
            (previous.network() != config.network()).then_some("sandbox.network"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !lifetime_changed.is_empty() {
            return Err(ReloadError(format!(
                "process-lifetime settings changed in the config file ({}); restart the daemon to apply them",
                lifetime_changed.join(", ")
            )));
        }
        let sandbox_shell = account
            .sandbox_shell(&config)
            .map_err(|error| ReloadError(format!("selecting the sandbox shell: {error}")))?;
        account::validate_executable(&sandbox_shell)
            .map_err(|error| ReloadError(format!("validating the sandbox shell: {error}")))?;
        let host_path = auth::resolve_authorized_keys_path()
            .map_err(|error| ReloadError(format!("resolving authorized_keys: {error}")))?;
        let auth = auth::AuthSnapshot::load(&host_path, paths.allowed_keys_file())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn parse(argv: &[&str]) -> Result<Args, String> {
        let os: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
        Args::parse_from(&os).map_err(|err| format!("{err:?}"))
    }

    #[test]
    fn no_flags_requests_no_output_action() {
        let args = parse(&[]).expect("empty argv parses");
        assert_eq!(args.output_action().expect("no conflict"), None);
        // Without the CLI layer the config file decides, including its
        // defaults; the merge point asserts that in
        // `cli_flags_layer_on_top_of_the_config_values`.
        assert_eq!(args.listen, None);
        assert_eq!(args.log_level, None);
    }

    #[test]
    fn cli_flags_layer_on_top_of_the_config_values() {
        let args = parse(&[
            "--listen",
            "127.0.0.1:2222",
            "--listen",
            "[::1]:2222",
            "--log-level",
            "debug",
        ])
        .expect("operational options parse");
        assert_eq!(args.log_level, Some(config::LogLevel::Debug));
        let listen = args.listen.expect("listeners given");
        assert_eq!(listen.len(), 2);

        // The CLI layer wins over whatever the config file carries...
        let from_config = [std::net::SocketAddr::from(([192, 168, 0, 1], 2200))];
        assert_eq!(
            effective_listen(Some(&listen), &from_config).expect("layered listen"),
            listen
        );
        assert_eq!(
            effective_log_level(Some(config::LogLevel::Debug), config::LogLevel::Info),
            config::LogLevel::Debug
        );
        // ...and without the layer the config snapshot (already defaulted
        // and validated) applies untouched.
        assert_eq!(
            effective_listen(None, &from_config).expect("config listen"),
            from_config.to_vec()
        );
        assert_eq!(
            effective_log_level(None, config::LogLevel::Warn),
            config::LogLevel::Warn
        );
    }

    #[test]
    fn duplicate_cli_listeners_are_rejected() {
        let duplicate = parse(&["--listen", "127.0.0.1:2222", "--listen", "127.0.0.1:2222"])
            .expect("duplicate addresses parse before semantic validation");
        let message = effective_listen(duplicate.listen.as_deref(), &config::default_listen())
            .expect_err("duplicates rejected");
        assert!(message.contains("duplicate --listen"), "{message}");
    }

    #[test]
    fn retired_network_flag_is_rejected() {
        assert!(parse(&["--network", "outbound"]).is_err());
    }

    #[test]
    fn completions_requests_the_named_shell() {
        for (name, expected) in [
            ("bash", CompletionShell::Bash),
            ("zsh", CompletionShell::Zsh),
            ("fish", CompletionShell::Fish),
            ("powershell", CompletionShell::PowerShell),
        ] {
            let args = parse(&["--completions", name]).expect("valid shell");
            assert_eq!(
                args.output_action().expect("no conflict"),
                Some(OutputAction::Completions(expected)),
                "{name}"
            );
        }
    }

    #[test]
    fn unsupported_completion_shell_is_a_parse_error() {
        for name in ["nu", "elvish", "sh", "pwsh", ""] {
            assert!(
                parse(&["--completions", name]).is_err(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn conflicting_output_actions_are_rejected() {
        let args = parse(&["--completions", "zsh", "--man"]).expect("argv itself parses");
        let message = args.output_action().expect_err("conflict rejected");
        assert!(message.contains("mutually exclusive"), "{message}");
    }

    #[test]
    fn completion_scripts_carry_the_cli_flags() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
            CompletionShell::PowerShell,
        ] {
            let script = completion_script(shell);
            assert!(script.contains("@generated by usage"), "{shell:?}");
            assert!(script.contains("shbox"), "{shell:?}");
        }
    }

    #[test]
    fn man_page_renders_the_declaration() {
        let man = render_man_page().expect("man page renders");
        assert!(man.contains(".TH SHBOX 1"), "{man}");
        // roff escapes flag hyphens, so `--completions` appears as
        // `\-\-completions` in the rendered page.
        assert!(man.contains("\\-\\-completions"), "{man}");
        assert!(man.contains("\\-\\-man"), "{man}");
    }
}
