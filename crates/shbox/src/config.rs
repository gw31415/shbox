//! Typed TOML configuration, built-in defaults, validation, and immutable
//! runtime snapshots.
//!
//! The schema is exactly the one in `docs/configuration.md`: an optional
//! `config.toml`, unknown fields rejected, and no silent coercion of invalid
//! values. The top level carries the operational settings (`listen`,
//! `log_level`); the CLI flags are a thin layer on top of exactly those
//! top-level fields and never mirror anything under `[sandbox]`. Resource
//! safety limits stay built-in constants, outside this file.
//! Parsing (schema) and validation (semantics that need the filesystem) are
//! separate steps; the snapshot they produce is process-lifetime — the daemon
//! never re-reads the config file, so applying a change means restarting.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;
use serde_with::{OneOrMany, serde_as};

use crate::endpoint::ListenEndpoint;
use crate::paths::{self, Paths};

/// Maximum config file size.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Maximum size of a single sandbox environment variable value.
pub const MAX_ENV_VALUE_BYTES: usize = 4 * 1024;

/// Immutable, fully validated configuration snapshot.
///
/// Every setting here — the top-level operational ones (`listen`,
/// `log_level`), the `[sandbox] network` mode included — is process-lifetime:
/// it is read exactly once at startup, the CLI flags layer on top of the
/// first two, and nothing re-reads the file afterwards. Applying a config
/// change means restarting the daemon. `Caps` are built-in constants.
#[derive(Debug, Clone)]
pub struct Config {
    listen: Vec<ListenEndpoint>,
    log_level: LogLevel,
    network: NetworkMode,
    sandbox_shell: Option<PathBuf>,
    read_paths: Vec<PathBuf>,
    sandbox_env: BTreeMap<String, String>,
    resources: SandboxResources,
    cgroup_parent: Option<PathBuf>,
}

impl Config {
    /// Load the optional config file and validate it completely.
    ///
    /// A missing file selects the built-in defaults; a present but unusable
    /// file is an error, never a silent fallback. `cli_listen` is the
    /// already-parsed `--listen` layer: when the file omits `listen` and the
    /// CLI provides endpoints, those stand in for the file value before the
    /// default resolution runs — a `ws`-only build with an explicit
    /// `--listen` therefore starts even though it has no default listener.
    pub fn load_snapshot(
        paths: &Paths,
        cli_listen: Option<&[ListenEndpoint]>,
    ) -> Result<Config, Error> {
        let path = paths.config_file();
        let raw = match fs::metadata(path) {
            Ok(_) => Some(parse_file(path)?),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(Error::Io {
                    field: "config",
                    message: "cannot stat config file".into(),
                    source: err,
                });
            }
        };
        let mut raw = raw.unwrap_or_default();
        if raw.listen.is_none()
            && let Some(endpoints) = cli_listen
        {
            raw.listen = Some(endpoints.iter().map(|e| e.to_string()).collect());
        }
        build(raw, paths)
    }

    /// Listener endpoints to bind, with the built-in default applied.
    pub fn listen(&self) -> &[ListenEndpoint] {
        &self.listen
    }

    /// Daemon log verbosity for this run.
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Sandbox network policy for this run.
    pub fn network(&self) -> NetworkMode {
        self.network
    }

    /// Configured sandbox shell override.
    pub fn sandbox_shell(&self) -> Option<&Path> {
        self.sandbox_shell.as_deref()
    }

    /// Additional read-only subtrees for sandbox processes.
    pub fn read_paths(&self) -> &[PathBuf] {
        &self.read_paths
    }

    /// Extra environment injected into every sandbox process.
    pub fn sandbox_env(&self) -> &BTreeMap<String, String> {
        &self.sandbox_env
    }

    /// Resource limits each durable sandbox applies through one shared cgroup
    /// v2 resource domain on Linux.
    pub fn resources(&self) -> &SandboxResources {
        &self.resources
    }

    /// Operator-specified cgroup directory to create sandbox cgroups under
    /// (overriding auto-discovery).
    pub fn cgroup_parent(&self) -> Option<&Path> {
        self.cgroup_parent.as_deref()
    }
}

/// Parse a config file, enforcing the size limit and file safety first.
fn parse_file(path: &Path) -> Result<RawConfig, Error> {
    let metadata = fs::metadata(path).map_err(|err| Error::Io {
        field: "config",
        message: "cannot stat config file".into(),
        source: err,
    })?;
    if !metadata.is_file() {
        return Err(Error::Invalid {
            field: "config",
            message: "config path is not a regular file".into(),
        });
    }
    if metadata.uid() != paths::euid() {
        return Err(Error::Invalid {
            field: "config",
            message: "config file is not owned by the daemon user".into(),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(Error::Invalid {
            field: "config",
            message: "config file is group or world writable".into(),
        });
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|err| Error::Io {
            field: "config",
            message: "cannot read config file".into(),
            source: err,
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::TooLarge {
            size: bytes.len() as u64,
            limit: MAX_CONFIG_BYTES,
        });
    }
    let text = String::from_utf8(bytes).map_err(|_| Error::Invalid {
        field: "config",
        message: "config file is not valid UTF-8".into(),
    })?;
    toml::from_str(&text).map_err(|err| Error::Parse(err.message().to_string()))
}

pub fn build(raw: RawConfig, paths: &Paths) -> Result<Config, Error> {
    let listen = validate_listen(raw.listen.as_deref())?;
    let log_level = validate_log_level(raw.log_level.as_deref())?;
    let sandbox = raw.sandbox.unwrap_or_default();
    let network = validate_network(sandbox.network.as_deref())?;
    let sandbox_shell = validate_configured_path(sandbox.shell.as_deref(), "sandbox.shell")?;
    let read_paths = validate_read_paths(sandbox.read_paths.as_deref(), paths)?;
    let sandbox_env = validate_sandbox_env(sandbox.env.as_ref())?;
    let resources = validate_resources(&sandbox)?;
    let cgroup_parent = validate_cgroup_parent(sandbox.cgroup_parent.as_deref())?;
    Ok(Config {
        listen,
        log_level,
        network,
        sandbox_shell,
        read_paths,
        sandbox_env,
        resources,
        cgroup_parent,
    })
}

/// Per-sandbox resource limits, resolved from the `[sandbox]` table. Every
/// field is optional; an absent field inherits. If all fields inherit, shbox
/// does not create a Linux resource-domain cgroup for the sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SandboxResources {
    /// `memory.max` in bytes.
    pub memory_bytes: Option<u64>,
    /// `memory.swap.max` in bytes.
    pub swap_bytes: Option<u64>,
    /// `pids.max`.
    pub pids: Option<u32>,
    /// `cpu.max` quota in microseconds of CPU time per period.
    pub cpu_quota_micros: Option<u64>,
    /// `cpu.max` period in microseconds (defaults to 100000).
    pub cpu_period_micros: Option<u64>,
}

impl SandboxResources {}

fn validate_resources(sandbox: &RawSandbox) -> Result<SandboxResources, Error> {
    let reject = |field: &'static str, why: String| -> Error {
        Error::Invalid {
            field,
            message: why,
        }
    };
    let memory_bytes = match sandbox.memory_max {
        Some(0) => {
            return Err(reject(
                "sandbox.memory_max",
                "must be greater than zero bytes".into(),
            ));
        }
        other => other,
    };
    let swap_bytes = match sandbox.swap_max {
        Some(0) => {
            return Err(reject(
                "sandbox.swap_max",
                "must be greater than zero bytes".into(),
            ));
        }
        other => other,
    };
    let pids = match sandbox.pids_max {
        Some(0) => {
            return Err(reject(
                "sandbox.pids_max",
                "must be greater than zero".into(),
            ));
        }
        other => other,
    };
    let cpu_quota_micros = match sandbox.cpu_quota_micros {
        Some(0) => {
            return Err(reject(
                "sandbox.cpu_quota_micros",
                "must be greater than zero".into(),
            ));
        }
        other => other,
    };
    let cpu_period_micros = match sandbox.cpu_period_micros {
        Some(period) if !(1000..=1_000_000).contains(&period) => {
            return Err(reject(
                "sandbox.cpu_period_micros",
                "must be between 1000 and 1000000".into(),
            ));
        }
        other => other,
    };
    if cpu_period_micros.is_some() && cpu_quota_micros.is_none() {
        return Err(reject(
            "sandbox.cpu_period_micros",
            "requires sandbox.cpu_quota_micros".into(),
        ));
    }
    Ok(SandboxResources {
        memory_bytes,
        swap_bytes,
        pids,
        cpu_quota_micros,
        cpu_period_micros,
    })
}

fn validate_cgroup_parent(raw: Option<&str>) -> Result<Option<PathBuf>, Error> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Error::Invalid {
            field: "sandbox.cgroup_parent",
            message: format!("must be an absolute cgroup v2 directory, got {value:?}"),
        });
    }
    Ok(Some(path))
}

/// The listener the daemon binds when the config file names none: the
/// ordinary TCP default, available only in `tcp`-enabled builds. A `ws`-only
/// build has no WebSocket convention to fall back on and must configure
/// `listen` explicitly.
pub fn default_listen() -> Result<Vec<ListenEndpoint>, Error> {
    #[cfg(feature = "tcp")]
    {
        Ok(vec![ListenEndpoint::Tcp {
            address: std::net::SocketAddr::from(([0, 0, 0, 0], 22)),
        }])
    }
    #[cfg(not(feature = "tcp"))]
    {
        Err(Error::Invalid {
            field: "listen",
            message: "listen must be set explicitly: this build has no `tcp` feature, so there is no default listener".into(),
        })
    }
}

fn validate_listen(raw: Option<&[String]>) -> Result<Vec<ListenEndpoint>, Error> {
    let Some(values) = raw else {
        return default_listen();
    };
    if values.is_empty() {
        return Err(Error::Invalid {
            field: "listen",
            message: "listen must not be empty; omit it to use the default listener".into(),
        });
    }
    let mut listen = Vec::with_capacity(values.len());
    for value in values {
        let endpoint = ListenEndpoint::from_str(value).map_err(|err| Error::Invalid {
            field: "listen",
            message: err.to_string(),
        })?;
        if listen.contains(&endpoint) {
            return Err(Error::Invalid {
                field: "listen",
                message: format!("duplicate listen endpoint {endpoint}"),
            });
        }
        listen.push(endpoint);
    }
    Ok(listen)
}

fn validate_log_level(raw: Option<&str>) -> Result<LogLevel, Error> {
    let Some(word) = raw else {
        return Ok(LogLevel::Info);
    };
    LogLevel::from_word(word).ok_or_else(|| Error::Invalid {
        field: "log_level",
        message: format!(
            "log_level must be one of {}, got {word:?}",
            LogLevel::WORDS.join(", ")
        ),
    })
}

fn validate_network(raw: Option<&str>) -> Result<NetworkMode, Error> {
    let Some(word) = raw else {
        return Ok(NetworkMode::Disabled);
    };
    NetworkMode::from_word(word).ok_or_else(|| Error::Invalid {
        field: "sandbox.network",
        message: format!(
            "sandbox.network must be one of {}, got {word:?}",
            NetworkMode::WORDS.join(", ")
        ),
    })
}

/// The built-in defaults, as they would be parsed from an empty config.
/// A `ws`-only build has no default listener, so the test view pins an
/// explicit WebSocket endpoint instead.
#[cfg(test)]
pub fn defaults() -> Config {
    #[allow(unused_mut)]
    let mut raw = RawConfig::default();
    #[cfg(not(feature = "tcp"))]
    {
        raw.listen = Some(vec!["ws://127.0.0.1:8080/ssh".to_string()]);
    }
    build(raw, &default_paths()).expect("built-in defaults are valid")
}

/// Paths value used only to validate the built-in defaults, which reference
/// no filesystem paths.
#[cfg(test)]
fn default_paths() -> Paths {
    Paths::from_roots(
        PathBuf::from("/usr/share/empty/config"),
        PathBuf::from("/usr/share/empty/data"),
        PathBuf::from("/usr/share/empty/state"),
    )
}

fn validate_configured_path(
    raw: Option<&str>,
    field: &'static str,
) -> Result<Option<PathBuf>, Error> {
    match raw {
        None => Ok(None),
        Some(value) => {
            if !value.starts_with('/') {
                return Err(Error::Invalid {
                    field,
                    message: format!("{field} must be an absolute path, got {value:?}"),
                });
            }
            if value.bytes().any(|byte| byte == 0) {
                return Err(Error::Invalid {
                    field,
                    message: format!("{field} must not contain NUL"),
                });
            }
            Ok(Some(PathBuf::from(value)))
        }
    }
}

fn validate_read_paths(raw: Option<&[String]>, paths: &Paths) -> Result<Vec<PathBuf>, Error> {
    let mut canonical = Vec::new();
    for value in raw.unwrap_or(&[]) {
        if value.is_empty() || !value.starts_with('/') {
            return Err(Error::Invalid {
                field: "sandbox.read_paths",
                message: format!("read path must be absolute, got {value:?}"),
            });
        }
        if value.bytes().any(|byte| byte == 0) {
            return Err(Error::Invalid {
                field: "sandbox.read_paths",
                message: "read path must not contain NUL".into(),
            });
        }
        let resolved = fs::canonicalize(value).map_err(|err| Error::Io {
            field: "sandbox.read_paths",
            message: format!("read path {value:?} does not exist or is not accessible: {err}"),
            source: err,
        })?;
        for (root, role) in [
            (paths.data_dir(), "sandbox data root"),
            (paths.state_dir(), "state root"),
            (paths.config_dir(), "config directory"),
        ] {
            // Compare canonical forms: on macOS the temporary roots may live
            // behind `/var` style symlinks.
            let Ok(root) = fs::canonicalize(root) else {
                continue;
            };
            if Paths::contains(&root, &resolved) {
                return Err(Error::Invalid {
                    field: "sandbox.read_paths",
                    message: format!("read path {value:?} exposes the shbox {role}"),
                });
            }
        }
        if canonical.contains(&resolved) {
            return Err(Error::Invalid {
                field: "sandbox.read_paths",
                message: format!("duplicate read path {value:?}"),
            });
        }
        canonical.push(resolved);
    }
    Ok(canonical)
}

fn validate_sandbox_env(
    raw: Option<&BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut env = BTreeMap::new();
    let Some(entries) = raw else {
        return Ok(env);
    };
    for (name, value) in entries {
        validate_env_name(name)?;
        validate_env_value(name, value)?;
        env.insert(name.clone(), value.clone());
    }
    Ok(env)
}

/// POSIX environment name: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    match bytes.first() {
        Some(&first) if first.is_ascii_alphabetic() || first == b'_' => {}
        _ => return false,
    }
    bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn validate_env_name(name: &str) -> Result<(), Error> {
    if !is_valid_env_name(name) {
        return Err(Error::Invalid {
            field: "sandbox.env",
            message: format!("environment name {name:?} is not a POSIX identifier"),
        });
    }
    if RESERVED_ENV_NAMES.contains(&name) {
        return Err(Error::Invalid {
            field: "sandbox.env",
            message: format!("environment name {name:?} is managed by shbox and cannot be set"),
        });
    }
    if RESERVED_ENV_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Err(Error::Invalid {
            field: "sandbox.env",
            message: format!("environment name {name:?} uses a reserved prefix"),
        });
    }
    Ok(())
}

fn validate_env_value(name: &str, value: &str) -> Result<(), Error> {
    if value.bytes().any(|byte| byte == 0) {
        return Err(Error::Invalid {
            field: "sandbox.env",
            message: format!("environment value for {name:?} contains NUL"),
        });
    }
    if value.len() > MAX_ENV_VALUE_BYTES {
        return Err(Error::Invalid {
            field: "sandbox.env",
            message: format!(
                "environment value for {name:?} exceeds the {MAX_ENV_VALUE_BYTES} byte limit"
            ),
        });
    }
    Ok(())
}

/// Names shbox manages itself or refuses for injection reasons. `PATH` and
/// `LANG` are deliberately absent: operators may override them.
const RESERVED_ENV_NAMES: &[&str] = &[
    // Managed by shbox.
    "HOME",
    "PWD",
    "SHELL",
    "TMPDIR",
    "TERM",
    // Launcher/platform names.
    "AGENT_NETWORK_PROXY",
    "__COMPAT_LAYER",
    "COMSPEC",
    "PSModulePath",
    "PATHEXT",
    // Interpreter injection.
    "BASH_ENV",
    "ENV",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "ZDOTDIR",
    "IFS",
    "PROMPT_COMMAND",
    // Runtime/tool injection.
    "GCONV_PATH",
    "HOSTALIASES",
    "LOCPATH",
    "GETCONF_DIR",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "GOFLAGS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "OPENSSL_CONF",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "CARGO_HOME",
    // Proxy/certificate injection.
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "ftp_proxy",
    "FTP_PROXY",
    "SOCKS_PROXY",
    "socks_proxy",
    "CGI_HTTP_PROXY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
];

const RESERVED_ENV_PREFIXES: &[&str] = &[
    "SHBOX_", "LD_", "DYLD_", "COR_", "CORECLR_", "DOTNET_", "COMPLUS_",
];

/// Sandbox network policy. File-backed under `[sandbox]`, chosen once at
/// daemon start, and never reloaded; there is deliberately no CLI mirror for
/// this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Disabled,
    Outbound,
}

impl NetworkMode {
    /// The schema words for the sandbox network modes.
    pub const WORDS: [&str; 2] = ["disabled", "outbound"];

    /// Parse the schema word for a network mode.
    pub fn from_word(word: &str) -> Option<NetworkMode> {
        match word {
            "disabled" => Some(NetworkMode::Disabled),
            "outbound" => Some(NetworkMode::Outbound),
            _ => None,
        }
    }
}

/// Structured log verbosity. File-backed at the top level with the
/// `--log-level` flag layered on top; chosen once at daemon start and never
/// reloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, usage_rs::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// The config and CLI words for the levels, in filter order. The
    /// contract test keeps these identical to the `ValueEnum` spellings of
    /// `--log-level`.
    pub const WORDS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

    /// Parse the schema word for a level.
    pub fn from_word(word: &str) -> Option<LogLevel> {
        match word {
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" => Some(LogLevel::Trace),
            _ => None,
        }
    }
}

/// Concurrency caps; zero is forbidden for every field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub max_unauthenticated_connections: u32,
    pub max_connections: u32,
    pub max_channels_per_connection: u32,
    /// Maximum concurrent launch operations admitted for one sandbox. This
    /// is not the kernel process-count limit; Linux enforces that with
    /// `sandbox.pids_max` in the shared process-domain cgroup.
    pub max_concurrent_launches_per_sandbox: u32,
    pub max_host_processes: u32,
    pub max_auth_attempts: u32,
    pub max_sandboxes: u32,
    pub max_sandboxes_per_owner: u32,
    pub handshake_timeout_secs: u32,
}

impl Default for Caps {
    fn default() -> Caps {
        Caps {
            max_unauthenticated_connections: 32,
            max_connections: 128,
            max_channels_per_connection: 16,
            max_concurrent_launches_per_sandbox: 128,
            max_host_processes: 16,
            max_auth_attempts: 6,
            max_sandboxes: 1024,
            max_sandboxes_per_owner: 128,
            handshake_timeout_secs: 30,
        }
    }
}

/// Schema-level view of the TOML document. The top level carries the
/// process-lifetime operational settings (`listen`, `log_level`) that the
/// CLI flags may layer over; the `[sandbox]` table carries file-backed
/// sandbox policy, which has no CLI mirror. `deny_unknown_fields` turns any
/// other key — including the retired spellings `sandbox_shell`, top-level
/// `read_paths`, `[sandbox_env]`, and top-level `network` — into an explicit
/// configuration error. Every string-array field also accepts a single bare
/// string, read as a one-element array.
#[serde_as]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    #[serde_as(as = "Option<OneOrMany<_>>")]
    listen: Option<Vec<String>>,
    log_level: Option<String>,
    sandbox: Option<RawSandbox>,
}

/// Schema-level view of the `[sandbox]` table.
#[serde_as]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSandbox {
    shell: Option<String>,
    network: Option<String>,
    #[serde_as(as = "Option<OneOrMany<_>>")]
    read_paths: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    memory_max: Option<u64>,
    swap_max: Option<u64>,
    pids_max: Option<u32>,
    cpu_quota_micros: Option<u64>,
    cpu_period_micros: Option<u64>,
    cgroup_parent: Option<String>,
}

/// Configuration errors.
#[derive(Debug)]
pub enum Error {
    Parse(String),
    Invalid {
        field: &'static str,
        message: String,
    },
    TooLarge {
        size: u64,
        limit: u64,
    },
    Io {
        field: &'static str,
        message: String,
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(message) => write!(f, "invalid config: {message}"),
            Error::Invalid { field, message } => {
                write!(f, "invalid config field {field:?}: {message}")
            }
            Error::TooLarge { size, limit } => {
                write!(f, "config file is {size} bytes, the limit is {limit}")
            }
            Error::Io {
                field,
                message,
                source,
            } => write!(f, "config {field}: {message}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn test_paths() -> (TempDir, Paths) {
        let home = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            home.path().join("config"),
            home.path().join("data"),
            home.path().join("state"),
        );
        paths.ensure().expect("ensure");
        (home, paths)
    }

    fn build_toml(text: &str) -> Result<Config, Error> {
        let (_home, paths) = test_paths();
        #[allow(unused_mut)]
        let mut raw: RawConfig =
            toml::from_str(text).map_err(|err| Error::Parse(err.message().to_string()))?;
        // A `ws`-only build has no default listener; pin one so tests that
        // are not about `listen` do not depend on the compiled transports.
        #[cfg(not(feature = "tcp"))]
        if raw.listen.is_none() {
            raw.listen = Some(vec!["ws://127.0.0.1:8080/ssh".to_string()]);
        }
        build(raw, &paths)
    }

    fn build_ok(text: &str) -> Config {
        build_toml(text).expect("valid config")
    }

    fn build_err(text: &str) -> String {
        build_toml(text).expect_err("invalid config").to_string()
    }

    /// Parse raw TOML, pinning a listener in `ws`-only builds.
    fn raw_toml(text: &str) -> RawConfig {
        #[allow(unused_mut)]
        let mut raw: RawConfig = toml::from_str(text).expect("toml");
        #[cfg(not(feature = "tcp"))]
        if raw.listen.is_none() {
            raw.listen = Some(vec!["ws://127.0.0.1:8080/ssh".to_string()]);
        }
        raw
    }

    #[test]
    fn missing_file_uses_builtin_defaults() {
        let (_home, paths) = test_paths();
        let snapshot = Config::load_snapshot(&paths, None);
        #[cfg(feature = "tcp")]
        {
            let config = snapshot.expect("defaults");
            assert_eq!(
                config
                    .listen()
                    .iter()
                    .map(ListenEndpoint::to_string)
                    .collect::<Vec<_>>(),
                default_listen()
                    .expect("default listen")
                    .iter()
                    .map(ListenEndpoint::to_string)
                    .collect::<Vec<_>>()
            );
            assert_eq!(config.log_level(), LogLevel::Info);
            assert_eq!(config.network(), NetworkMode::Disabled);
            assert!(config.read_paths().is_empty());
            assert!(config.sandbox_env().is_empty());
        }
        #[cfg(not(feature = "tcp"))]
        {
            // A ws-only build must not invent a default listener.
            let message = snapshot
                .expect_err("no default in a ws-only build")
                .to_string();
            assert!(message.contains("must be set explicitly"), "{message}");
        }
    }

    #[test]
    fn present_empty_file_uses_builtin_policy() {
        let (_home, paths) = test_paths();
        // `ensure` no longer creates the read-only config directory.
        std::fs::create_dir(paths.config_dir()).expect("create config dir");
        std::fs::write(paths.config_file(), "").expect("write empty config");
        let snapshot = Config::load_snapshot(&paths, None);
        #[cfg(feature = "tcp")]
        {
            let config = snapshot.expect("empty config");
            assert!(config.read_paths().is_empty());
            assert!(config.sandbox_env().is_empty());
        }
        #[cfg(not(feature = "tcp"))]
        {
            // A ws-only build refuses an empty (listener-less) config.
            assert!(snapshot.is_err());
        }
    }

    #[test]
    fn defaults_match_documented_values() {
        let caps = Caps::default();
        assert_eq!(caps.max_unauthenticated_connections, 32);
        assert_eq!(caps.max_connections, 128);
        assert_eq!(caps.max_channels_per_connection, 16);
        assert_eq!(caps.max_concurrent_launches_per_sandbox, 128);
        assert_eq!(caps.max_host_processes, 16);
        assert_eq!(caps.max_auth_attempts, 6);
        assert_eq!(caps.max_sandboxes, 1024);
        assert_eq!(caps.max_sandboxes_per_owner, 128);
        assert_eq!(caps.handshake_timeout_secs, 30);
    }

    #[test]
    fn full_document_parses() {
        #[cfg(feature = "tcp")]
        let (listen, expected) = (
            r#""tcp://127.0.0.1:2222", "tcp://[::1]:2222""#,
            vec![
                "tcp://127.0.0.1:2222".to_string(),
                "tcp://[::1]:2222".to_string(),
            ],
        );
        #[cfg(all(not(feature = "tcp"), feature = "ws"))]
        let (listen, expected) = (
            r#""ws://127.0.0.1:2222/a", "ws://[::1]:2222/b""#,
            vec![
                "ws://127.0.0.1:2222/a".to_string(),
                "ws://[::1]:2222/b".to_string(),
            ],
        );
        let config = build_ok(&format!(
            r#"
            listen = [{listen}]
            log_level = "debug"

            [sandbox]
            shell = "/bin/bash"
            network = "outbound"
            read_paths = ["/usr/share/terminfo"]

            [sandbox.env]
            LANG = "C.UTF-8"
            EDITOR_DEFAULT = "vi"
            "#
        ));
        assert_eq!(
            config
                .listen()
                .iter()
                .map(ListenEndpoint::to_string)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(config.log_level(), LogLevel::Debug);
        assert_eq!(config.network(), NetworkMode::Outbound);
        assert_eq!(config.read_paths().len(), 1);
        assert_eq!(
            config.sandbox_env().get("LANG").map(String::as_str),
            Some("C.UTF-8")
        );
    }

    #[test]
    fn operational_fields_live_in_their_new_homes() {
        #[cfg(feature = "tcp")]
        let listen_entry = r#"listen = ["tcp://127.0.0.1:2222"]"#;
        #[cfg(all(not(feature = "tcp"), feature = "ws"))]
        let listen_entry = r#"listen = ["ws://127.0.0.1:2222/ssh"]"#;
        for text in [
            listen_entry,
            r#"log_level = "debug""#,
            "[sandbox]\nnetwork = \"outbound\"",
        ] {
            assert!(build_toml(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn cpu_period_requires_cpu_quota() {
        let message = build_err("[sandbox]\ncpu_period_micros = 50000");
        assert!(message.contains("sandbox.cpu_period_micros"), "{message}");
        assert!(message.contains("cpu_quota_micros"), "{message}");
    }

    #[test]
    fn rejects_retired_field_spellings() {
        for text in [
            r#"sandbox_shell = "/bin/bash""#,
            r#"read_paths = ["/usr/share/terminfo"]"#,
            "[sandbox_env]\nLANG = \"C.UTF-8\"",
            // The mode lives only under `[sandbox]`; the CLI has no mirror
            // and the top level never carried it.
            r#"network = "outbound""#,
            "[sandbox]\nsandbox_shell = \"/bin/bash\"",
        ] {
            let message = build_err(text);
            assert!(message.contains("unknown field"), "{text}: {message}");
        }
    }

    #[test]
    fn listen_rejects_empty_malformed_and_duplicate_entries() {
        let message = build_err("listen = []");
        assert!(message.contains("must not be empty"), "{message}");
        let message = build_err(r#"listen = ["127.0.0.1"]"#);
        assert!(message.contains("must be a transport URI"), "{message}");
        #[cfg(feature = "tcp")]
        {
            let message = build_err(r#"listen = ["tcp://127.0.0.1"]"#);
            assert!(message.contains("not a valid host:port"), "{message}");
        }
        #[cfg(not(feature = "tcp"))]
        {
            let message = build_err(r#"listen = ["tcp://127.0.0.1:2222"]"#);
            assert!(message.contains("without the `tcp` feature"), "{message}");
        }
        let message = build_err(r#"listen = ["unix:///tmp/s"]"#);
        assert!(message.contains("unknown transport scheme"), "{message}");
        #[cfg(feature = "tcp")]
        let duplicate = r#"listen = ["tcp://127.0.0.1:2222", "tcp://127.0.0.1:2222"]"#;
        #[cfg(all(not(feature = "tcp"), feature = "ws"))]
        let duplicate = r#"listen = ["ws://127.0.0.1:2222/ssh", "ws://127.0.0.1:2222/ssh"]"#;
        let message = build_err(duplicate);
        assert!(message.contains("duplicate listen endpoint"), "{message}");
    }

    #[test]
    fn ws_listen_entries_parse_when_the_transport_is_compiled_in() {
        #[cfg(feature = "ws")]
        {
            let config = build_ok(r#"listen = ["ws://127.0.0.1:8080/ssh"]"#);
            assert_eq!(
                config
                    .listen()
                    .iter()
                    .map(ListenEndpoint::to_string)
                    .collect::<Vec<_>>(),
                ["ws://127.0.0.1:8080/ssh".to_string()]
            );
        }
        #[cfg(not(feature = "ws"))]
        {
            let message = build_err(r#"listen = ["ws://127.0.0.1:8080/ssh"]"#);
            assert!(message.contains("without the `ws` feature"), "{message}");
        }
    }

    #[test]
    fn string_array_fields_accept_a_single_bare_string() {
        #[cfg(feature = "tcp")]
        let listen_value = "tcp://127.0.0.1:2222";
        #[cfg(all(not(feature = "tcp"), feature = "ws"))]
        let listen_value = "ws://127.0.0.1:2222/ssh";
        let config = build_ok(&format!(r#"listen = "{listen_value}""#));
        assert_eq!(
            config
                .listen()
                .iter()
                .map(ListenEndpoint::to_string)
                .collect::<Vec<_>>(),
            [listen_value.to_string()]
        );
        let config = build_ok("[sandbox]\nread_paths = \"/usr/share/terminfo\"");
        assert_eq!(config.read_paths(), &[PathBuf::from("/usr/share/terminfo")]);
    }

    #[test]
    fn string_array_fields_reject_non_string_values() {
        let message = build_err("listen = 2222");
        assert!(
            message.contains("could not deserialize any variant"),
            "{message}"
        );
        assert!(message.contains("expected a string"), "{message}");
        let message = build_err("[sandbox]\nread_paths = [42]");
        assert!(message.contains("invalid type: integer `42`"), "{message}");
    }

    #[test]
    fn log_level_and_network_accept_only_the_documented_words() {
        for word in LogLevel::WORDS {
            let config = build_ok(&format!(r#"log_level = "{word}""#));
            assert_eq!(config.log_level(), LogLevel::from_word(word).expect("word"));
        }
        assert_eq!(build_ok("").log_level(), LogLevel::Info);
        assert!(build_err(r#"log_level = "verbose""#).contains("log_level must be one of"));

        for word in NetworkMode::WORDS {
            let config = build_ok(&format!("[sandbox]\nnetwork = \"{word}\""));
            assert_eq!(
                config.network(),
                NetworkMode::from_word(word).expect("word")
            );
        }
        assert_eq!(build_ok("").network(), NetworkMode::Disabled);
        assert!(
            build_err("[sandbox]\nnetwork = \"proxy\"").contains("sandbox.network must be one of")
        );
    }

    #[test]
    fn rejects_unknown_fields_and_bad_types() {
        let message = build_err("unknown_field = 1");
        assert!(message.contains("unknown field"), "{message}");
        for text in ["caps = { max_connections = 1 }", "limits = { memory = 1 }"] {
            let message = build_err(text);
            assert!(message.contains("unknown field"), "{text}: {message}");
        }
    }

    #[test]
    fn rejects_retired_auth_fields() {
        for text in [
            r#"authorized_keys = "/etc/shbox/authorized_keys""#,
            r#"admin_keys = ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]"#,
            r#"allowed_keys = "/etc/shbox/allowed_keys""#,
        ] {
            let message = build_err(text);
            assert!(message.contains("unknown field"), "{text}: {message}");
        }
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(toml::from_str::<RawConfig>("sandbox = [").is_err());
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(
            build_err(
                r#"[sandbox]
shell = "bin/bash""#
            )
            .contains("absolute path")
        );
        assert!(
            build_err(
                r#"[sandbox]
read_paths = ["relative/path"]"#
            )
            .contains("absolute")
        );
        assert!(
            build_err(
                r#"[sandbox]
read_paths = [""]"#
            )
            .contains("absolute")
        );
    }

    #[test]
    fn enum_words_match_the_schema_and_cli_contract() {
        // The CLI spellings are part of the contract; keep the enum variants
        // mapped to the documented words.
        use usage_rs::spec::ValueEnum;
        assert_eq!(
            <LogLevel as ValueEnum>::CHOICES,
            &["error", "warn", "info", "debug", "trace"]
        );
        assert_eq!(LogLevel::WORDS.as_slice(), <LogLevel as ValueEnum>::CHOICES);
        for word in LogLevel::WORDS {
            assert!(LogLevel::from_word(word).is_some(), "{word}");
        }
        assert!(LogLevel::from_word("verbose").is_none());
        // `network` has no CLI mirror, so its words are config-only.
        assert_eq!(NetworkMode::WORDS, ["disabled", "outbound"]);
        for word in NetworkMode::WORDS {
            assert!(NetworkMode::from_word(word).is_some(), "{word}");
        }
        assert!(NetworkMode::from_word("proxy").is_none());
    }

    #[test]
    fn read_paths_must_exist_and_stay_out_of_shbox_roots() {
        let (home, paths) = test_paths();
        let raw = raw_toml("[sandbox]\nread_paths = [\"/definitely/not/here\"]");
        let message = build(raw, &paths).expect_err("missing path").to_string();
        assert!(message.contains("does not exist"), "{message}");

        let inside_data = paths.data_dir().join("exposed");
        std::fs::create_dir_all(&inside_data).expect("create");
        let raw = raw_toml(&format!(
            "[sandbox]\nread_paths = [{:?}]",
            inside_data.display()
        ));
        let message = build(raw, &paths).expect_err("data root").to_string();
        assert!(message.contains("sandbox data root"), "{message}");

        let inside_state = paths.state_dir().join("exposed");
        std::fs::create_dir_all(&inside_state).expect("create");
        let raw = raw_toml(&format!(
            "[sandbox]\nread_paths = [{:?}]",
            inside_state.display()
        ));
        let message = build(raw, &paths).expect_err("state root").to_string();
        assert!(message.contains("state root"), "{message}");

        // Duplicates are detected on canonical form for paths that are
        // otherwise acceptable.
        let allowed = home.path().join("extra");
        std::fs::create_dir_all(&allowed).expect("create");
        let raw = raw_toml(&format!(
            "[sandbox]\nread_paths = [{:?}, {:?}]",
            allowed.display(),
            allowed.display()
        ));
        let message = build(raw, &paths).expect_err("duplicate").to_string();
        assert!(message.contains("duplicate read path"), "{message}");
    }

    #[test]
    fn sandbox_env_rejects_reserved_names_and_prefixes() {
        for name in [
            "HOME",
            "PWD",
            "SHELL",
            "TMPDIR",
            "TERM",
            "SHBOX_LEVEL",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "BASH_ENV",
            "IFS",
            "http_proxy",
            "HTTPS_PROXY",
            "CURL_CA_BUNDLE",
            "GIT_CONFIG_GLOBAL",
            "CARGO_HOME",
            "_JAVA_OPTIONS",
            "__COMPAT_LAYER",
        ] {
            let text = format!("[sandbox.env]\n{name} = \"x\"");
            let message = build_err(&text);
            assert!(
                message.contains("managed by shbox") || message.contains("reserved prefix"),
                "{name}: {message}"
            );
        }
    }

    #[test]
    fn sandbox_env_allows_path_and_lang_overrides() {
        let config = build_ok("[sandbox.env]\nPATH = \"/opt/bin\"\nLANG = \"ja_JP.UTF-8\"\n");
        assert_eq!(
            config.sandbox_env().get("PATH").map(String::as_str),
            Some("/opt/bin")
        );
        assert_eq!(
            config.sandbox_env().get("LANG").map(String::as_str),
            Some("ja_JP.UTF-8")
        );
    }

    #[test]
    fn sandbox_env_rejects_invalid_names_and_values() {
        assert!(build_err("[sandbox.env]\n\"1BAD\" = \"x\"").contains("POSIX identifier"));
        assert!(build_err("[sandbox.env]\n\"A B\" = \"x\"").contains("POSIX identifier"));
        assert!(build_err("[sandbox.env]\n\"WITH-NUL\" = \"a\\u0000b\"").contains("NUL"));
        let big = "x".repeat(MAX_ENV_VALUE_BYTES + 1);
        assert!(build_err(&format!("[sandbox.env]\nBIG = \"{big}\"")).contains("limit"));
        let ok = "x".repeat(MAX_ENV_VALUE_BYTES);
        assert!(
            build_ok(&format!("[sandbox.env]\nBIG = \"{ok}\""))
                .sandbox_env()
                .contains_key("BIG")
        );
    }

    #[test]
    fn unsafe_config_permissions_are_rejected() {
        let home = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            home.path().join("config"),
            home.path().join("data"),
            home.path().join("state"),
        );
        paths.ensure().expect("ensure");
        // `ensure` no longer creates the read-only config directory.
        std::fs::create_dir(paths.config_dir()).expect("create config dir");
        let path = paths.config_file();
        std::fs::write(path, "[sandbox]\nnetwork = \"disabled\"").expect("write config");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        let message = match Config::load_snapshot(&paths, None) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("group writable config must be rejected"),
        };
        assert!(message.contains("group or world writable"), "{message}");
        // A missing config is still fine when nothing unsafe exists.
        std::fs::remove_file(path).expect("remove");
        let missing = Config::load_snapshot(&paths, None);
        #[cfg(feature = "tcp")]
        missing.expect("missing config");
        #[cfg(not(feature = "tcp"))]
        assert!(missing.is_err());
    }

    #[test]
    fn oversize_config_is_rejected_without_truncation() {
        let home = TempDir::new().expect("tempdir");
        let paths = Paths::from_roots(
            home.path().join("config"),
            home.path().join("data"),
            home.path().join("state"),
        );
        paths.ensure().expect("ensure");
        // `ensure` no longer creates the read-only config directory.
        std::fs::create_dir(paths.config_dir()).expect("create config dir");
        let path = paths.config_file();
        std::fs::write(path, b"#").unwrap();
        // Build a file just over the limit out of harmless comment lines.
        let line = "# ".repeat(511) + "\n";
        let mut body = String::new();
        while (body.len() as u64) <= MAX_CONFIG_BYTES {
            body.push_str(&line);
        }
        std::fs::write(path, body).expect("write big config");
        assert!(matches!(
            Config::load_snapshot(&paths, None),
            Err(Error::TooLarge { .. })
        ));
    }

    proptest! {
        #[test]
        fn env_name_validation_matches_posix_rule(name in "[ -~]{0,24}") {
            let valid = is_valid_env_name(&name);
            let expected = {
                let bytes = name.as_bytes();
                match bytes.first() {
                    Some(&first) if first.is_ascii_alphabetic() || first == b'_' => {
                        bytes[1..].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    }
                    _ => false,
                }
            };
            assert_eq!(valid, expected, "name {name:?}");
        }
    }
}
