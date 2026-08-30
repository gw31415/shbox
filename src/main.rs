//! shbox: a foreground SSH daemon that maps authenticated keys onto
//! persistent sandbox workspaces.
//!
//! Milestone 4 bootstrap: resolve and validate every local input, reconcile
//! durable sandbox metadata, then run the public-key SSH server with the
//! admin-only `_` host route. The production sandbox adapter remains
//! fail-closed until the Arapuca milestone connects it.

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
    let sandbox_manager = Arc::new(
        sandbox::SandboxManager::open(&paths, *app_config.caps())
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
        account: Arc::new(account),
        sandbox: sandbox_manager,
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
    let serve_task = tokio::spawn(server.serve(sockets, shutdown_rx));
    info!(
        user = %account_name,
        listen = ?bound,
        host_key_fingerprint = %host_key.key().fingerprint(russh::keys::HashAlg::Sha256),
        "shbox ready"
    );

    wait_for_signals().await;
    let _ = shutdown_tx.send(true);
    let _ = serve_task.await;
    drop(locks);
    info!("shutdown complete");
    Ok(())
}

/// Small signal loop: SIGINT/SIGTERM shut the daemon down; SIGHUP reload is
/// implemented in a later milestone and is currently reported and ignored.
async fn wait_for_signals() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut hangup = signal(SignalKind::hangup()).expect("SIGHUP handler");
    loop {
        tokio::select! {
            _ = interrupt.recv() => {
                info!("SIGINT received: shutting down");
                break;
            }
            _ = terminate.recv() => {
                info!("SIGTERM received: shutting down");
                break;
            }
            _ = hangup.recv() => {
                warn!("SIGHUP received: config reload is not implemented yet");
            }
        }
    }
}
