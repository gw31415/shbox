//! shbox: a foreground SSH daemon that maps authenticated keys onto
//! persistent sandbox workspaces.
//!
//! Milestone 1 bootstrap: parse the command line, resolve and validate every
//! local input (XDG paths, advisory daemon locks, optional config,
//! authorized-keys file, host key, shell, listen addresses), then wait on the
//! signal loop. The SSH listener itself arrives in Milestone 2.

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

use std::fmt;
use std::process::ExitCode;

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

/// Resolve and validate every local input, then wait on the signal loop.
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

    let host_key = hostkey::HostKey::load_or_create(paths.host_key())
        .map_err(|err| fail("loading the host key", err))?;

    server::probe_listen(app_config.listen())
        .map_err(|err| fail("binding listen addresses", err))?;

    debug!(
        sandboxes_root = %paths.sandboxes_root().display(),
        limits = ?app_config.limits(),
        caps = ?app_config.caps(),
        read_paths = app_config.read_paths().len(),
        sandbox_env = app_config.sandbox_env().len(),
        "enforcing configured limits and caps"
    );
    if app_config.managed_mode() {
        info!(
            admins = app_config.admin_keys().len(),
            user = %account.name,
            "managed mode: host selector \"_\" is available to admin keys"
        );
        debug!(
            admins = %app_config.admin_keys().iter().map(KeyFingerprint::to_string).collect::<Vec<_>>().join(","),
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
    info!(
        user = %account.name,
        listen = ?app_config.listen(),
        host_key_fingerprint = %host_key.key().fingerprint(russh::keys::HashAlg::Sha256),
        authorized_keys = %authorized_keys.display(),
        sandbox_shell = %sandbox_shell.display(),
        "startup validation complete; the SSH listener arrives with the next milestone"
    );

    wait_for_signals().await;
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
