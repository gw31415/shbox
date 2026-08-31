//! Typed TOML configuration, built-in defaults, validation, and immutable
//! runtime snapshots.
//!
//! The v0.1 schema is exactly the one in `docs/configuration.md`: an optional
//! `config.toml`, unknown fields rejected, and no silent coercion of invalid
//! values. Process-lifetime operational settings and resource safety limits
//! are intentionally outside this file.
//! Parsing (schema) and validation (semantics that need the filesystem) are
//! separate steps so that reload can reuse both independently.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::paths::{self, Paths};

/// Maximum config file size.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Maximum size of a single sandbox environment variable value.
pub const MAX_ENV_VALUE_BYTES: usize = 4 * 1024;

/// Immutable, fully validated configuration snapshot.
///
/// Only file-backed policy lives here. Process-lifetime operational settings
/// (`listen`, `network`, `log level`, host-access) are CLI options, and
/// `Caps`/`Limits` are built-in constants.
#[derive(Debug, Clone)]
pub struct Config {
    sandbox_shell: Option<PathBuf>,
    read_paths: Vec<PathBuf>,
    sandbox_env: BTreeMap<String, String>,
    loaded_from_file: bool,
}

impl Config {
    /// Load the optional config file and validate it completely.
    ///
    /// A missing file selects the built-in defaults; a present but unusable
    /// file is an error, never a silent fallback.
    pub fn load_snapshot(paths: &Paths) -> Result<Config, Error> {
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
        match raw {
            Some(raw) => {
                let mut config = build(raw, paths)?;
                config.loaded_from_file = true;
                Ok(config)
            }
            None => build(RawConfig::default(), paths),
        }
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

    /// Whether this snapshot came from a config file (drives the reload rule
    /// that a vanished file is a reload failure, not a fallback to defaults).
    /// Consumed by the Milestone 7 reload implementation.
    #[allow(dead_code)]
    pub fn loaded_from_file(&self) -> bool {
        self.loaded_from_file
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
    let sandbox_shell = validate_configured_path(raw.sandbox_shell.as_deref(), "sandbox_shell")?;
    let read_paths = validate_read_paths(raw.read_paths.as_deref(), paths)?;
    let sandbox_env = validate_sandbox_env(raw.sandbox_env.as_ref())?;
    Ok(Config {
        sandbox_shell,
        read_paths,
        sandbox_env,
        loaded_from_file: false,
    })
}

/// The built-in defaults, as they would be parsed from an empty config.
/// Test-only until reload reuses it in Milestone 7.
#[allow(dead_code)]
pub fn defaults() -> Config {
    build(RawConfig::default(), &default_paths()).expect("built-in defaults are valid")
}

/// Paths value used only to validate the built-in defaults, which reference
/// no filesystem paths.
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
                field: "read_paths",
                message: format!("read path must be absolute, got {value:?}"),
            });
        }
        if value.bytes().any(|byte| byte == 0) {
            return Err(Error::Invalid {
                field: "read_paths",
                message: "read path must not contain NUL".into(),
            });
        }
        let resolved = fs::canonicalize(value).map_err(|err| Error::Io {
            field: "read_paths",
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
                    field: "read_paths",
                    message: format!("read path {value:?} exposes the shbox {role}"),
                });
            }
        }
        if canonical.contains(&resolved) {
            return Err(Error::Invalid {
                field: "read_paths",
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
            field: "sandbox_env",
            message: format!("environment name {name:?} is not a POSIX identifier"),
        });
    }
    if RESERVED_ENV_NAMES.contains(&name) {
        return Err(Error::Invalid {
            field: "sandbox_env",
            message: format!("environment name {name:?} is managed by shbox and cannot be set"),
        });
    }
    if RESERVED_ENV_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Err(Error::Invalid {
            field: "sandbox_env",
            message: format!("environment name {name:?} uses a reserved prefix"),
        });
    }
    Ok(())
}

fn validate_env_value(name: &str, value: &str) -> Result<(), Error> {
    if value.bytes().any(|byte| byte == 0) {
        return Err(Error::Invalid {
            field: "sandbox_env",
            message: format!("environment value for {name:?} contains NUL"),
        });
    }
    if value.len() > MAX_ENV_VALUE_BYTES {
        return Err(Error::Invalid {
            field: "sandbox_env",
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
    "SHBOX_", "ARAPUCA_", "LD_", "DYLD_", "COR_", "CORECLR_", "DOTNET_", "COMPLUS_",
];

/// Sandbox network policy. Chosen on the command line at daemon start and
/// never reloaded; the `ValueEnum` words are the CLI spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, usage_rs::ValueEnum)]
pub enum NetworkMode {
    Disabled,
    Outbound,
}

/// Structured log verbosity. Chosen on the command line at daemon start and
/// never reloaded; the `ValueEnum` words are the CLI spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, usage_rs::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Resource limits for sandbox processes; `0` means "no limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_memory_mb: u64,
    pub cpu_timeout_secs: u64,
    pub max_file_size_mb: u64,
    pub max_open_files: u64,
    /// Linux-only cgroup settings; absent on macOS.
    pub linux: Option<LinuxLimits>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_memory_mb: 0,
            cpu_timeout_secs: 0,
            max_file_size_mb: 0,
            max_open_files: 1024,
            linux: default_linux_limits(),
        }
    }
}

/// Linux cgroup defaults exist only on Linux targets; the `[limits.linux]`
/// table is a schema error elsewhere.
#[cfg(target_os = "linux")]
fn default_linux_limits() -> Option<LinuxLimits> {
    Some(LinuxLimits::default())
}

#[cfg(not(target_os = "linux"))]
fn default_linux_limits() -> Option<LinuxLimits> {
    None
}

/// Linux-only cgroup limits (`[limits.linux]`); `0` means "no limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxLimits {
    pub max_cpu_pct: u32,
    pub max_pids: u32,
}

impl Default for LinuxLimits {
    fn default() -> LinuxLimits {
        LinuxLimits {
            max_cpu_pct: 0,
            max_pids: 256,
        }
    }
}

/// Concurrency caps; zero is forbidden for every field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub max_unauthenticated_connections: u32,
    pub max_connections: u32,
    pub max_channels_per_connection: u32,
    pub max_sandbox_processes: u32,
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
            max_sandbox_processes: 128,
            max_host_processes: 16,
            max_auth_attempts: 6,
            max_sandboxes: 1024,
            max_sandboxes_per_owner: 128,
            handshake_timeout_secs: 30,
        }
    }
}

/// Schema-level view of the TOML document. `listen`, `network`, and
/// `log_level` were removed in favor of CLI options; `deny_unknown_fields`
/// turns any leftover copy of them into an explicit configuration error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    sandbox_shell: Option<String>,
    read_paths: Option<Vec<String>>,
    sandbox_env: Option<BTreeMap<String, String>>,
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
        let raw: RawConfig =
            toml::from_str(text).map_err(|err| Error::Parse(err.message().to_string()))?;
        build(raw, &paths)
    }

    fn build_ok(text: &str) -> Config {
        build_toml(text).expect("valid config")
    }

    fn build_err(text: &str) -> String {
        build_toml(text).expect_err("invalid config").to_string()
    }

    #[test]
    fn missing_file_uses_builtin_defaults() {
        let (_home, paths) = test_paths();
        let config = Config::load_snapshot(&paths).expect("defaults");
        assert!(config.read_paths().is_empty());
        assert!(config.sandbox_env().is_empty());
        assert!(!config.loaded_from_file());
    }

    #[test]
    fn present_empty_file_uses_builtin_policy() {
        let (_home, paths) = test_paths();
        std::fs::write(paths.config_file(), "").expect("write empty config");
        let config = Config::load_snapshot(&paths).expect("empty config");
        assert!(config.loaded_from_file());
        assert!(config.read_paths().is_empty());
        assert!(config.sandbox_env().is_empty());
    }

    #[test]
    fn defaults_match_documented_values() {
        let limits = Limits::default();
        assert_eq!(limits.max_open_files, 1024);
        // The Linux cgroup table only exists on Linux targets.
        assert_eq!(limits.linux.is_some(), cfg!(target_os = "linux"));
        #[cfg(target_os = "linux")]
        assert_eq!(
            limits.linux,
            Some(LinuxLimits {
                max_cpu_pct: 0,
                max_pids: 256
            })
        );
        let caps = Caps::default();
        assert_eq!(caps.max_unauthenticated_connections, 32);
        assert_eq!(caps.max_connections, 128);
        assert_eq!(caps.max_channels_per_connection, 16);
        assert_eq!(caps.max_sandbox_processes, 128);
        assert_eq!(caps.max_host_processes, 16);
        assert_eq!(caps.max_auth_attempts, 6);
        assert_eq!(caps.max_sandboxes, 1024);
        assert_eq!(caps.max_sandboxes_per_owner, 128);
        assert_eq!(caps.handshake_timeout_secs, 30);
    }

    #[test]
    fn full_document_parses() {
        let config = build_ok(
            r#"
            sandbox_shell = "/bin/bash"
            read_paths = ["/usr/share/terminfo"]

            [sandbox_env]
            LANG = "C.UTF-8"
            EDITOR_DEFAULT = "vi"
            "#,
        );
        assert_eq!(config.read_paths().len(), 1);
        assert_eq!(
            config.sandbox_env().get("LANG").map(String::as_str),
            Some("C.UTF-8")
        );
    }

    #[test]
    fn rejects_operational_fields_moved_to_the_cli() {
        for text in [
            r#"listen = ["127.0.0.1:2222"]"#,
            r#"network = "outbound""#,
            r#"log_level = "debug""#,
        ] {
            let message = build_err(text);
            assert!(message.contains("unknown field"), "{text}: {message}");
        }
    }

    #[test]
    fn rejects_unknown_fields_and_bad_types() {
        let message = build_err("unknown_field = 1");
        assert!(message.contains("unknown field"), "{message}");
        for text in [
            "caps = { max_connections = 1 }",
            "limits = { max_memory_mb = 1 }",
        ] {
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
        assert!(toml::from_str::<RawConfig>("listen = [").is_err());
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(build_err(r#"sandbox_shell = "bin/bash""#).contains("absolute path"));
        assert!(build_err(r#"sandbox_shell = "~/bin/bash""#).contains("absolute path"));
        assert!(build_err(r#"read_paths = ["relative/path"]"#).contains("absolute"));
        assert!(build_err(r#"read_paths = [""]"#).contains("absolute"));
    }

    #[test]
    fn value_enum_words_match_the_cli_contract() {
        // The CLI spellings are part of the contract; keep the enum variants
        // mapped to the documented words.
        use usage_rs::spec::ValueEnum;
        assert_eq!(
            <NetworkMode as ValueEnum>::CHOICES,
            &["disabled", "outbound"]
        );
        assert_eq!(
            <LogLevel as ValueEnum>::CHOICES,
            &["error", "warn", "info", "debug", "trace"]
        );
    }

    #[test]
    fn read_paths_must_exist_and_stay_out_of_shbox_roots() {
        let (home, paths) = test_paths();
        let raw: RawConfig = toml::from_str(r#"read_paths = ["/definitely/not/here"]"#).unwrap();
        let message = build(raw, &paths).expect_err("missing path").to_string();
        assert!(message.contains("does not exist"), "{message}");

        let inside_data = paths.data_dir().join("exposed");
        std::fs::create_dir_all(&inside_data).expect("create");
        let raw: RawConfig =
            toml::from_str(&format!(r#"read_paths = [{:?}]"#, inside_data.display())).unwrap();
        let message = build(raw, &paths).expect_err("data root").to_string();
        assert!(message.contains("sandbox data root"), "{message}");

        let inside_state = paths.state_dir().join("exposed");
        std::fs::create_dir_all(&inside_state).expect("create");
        let raw: RawConfig =
            toml::from_str(&format!(r#"read_paths = [{:?}]"#, inside_state.display())).unwrap();
        let message = build(raw, &paths).expect_err("state root").to_string();
        assert!(message.contains("state root"), "{message}");

        // Duplicates are detected on canonical form for paths that are
        // otherwise acceptable.
        let allowed = home.path().join("extra");
        std::fs::create_dir_all(&allowed).expect("create");
        let raw: RawConfig = toml::from_str(&format!(
            r#"read_paths = [{:?}, {:?}]"#,
            allowed.display(),
            allowed.display()
        ))
        .unwrap();
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
            "ARAPUCA_X",
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
            let text = format!("[sandbox_env]\n{name} = \"x\"");
            let message = build_err(&text);
            assert!(
                message.contains("managed by shbox") || message.contains("reserved prefix"),
                "{name}: {message}"
            );
        }
    }

    #[test]
    fn sandbox_env_allows_path_and_lang_overrides() {
        let config = build_ok("[sandbox_env]\nPATH = \"/opt/bin\"\nLANG = \"ja_JP.UTF-8\"\n");
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
        assert!(build_err("[sandbox_env]\n\"1BAD\" = \"x\"").contains("POSIX identifier"));
        assert!(build_err("[sandbox_env]\n\"A B\" = \"x\"").contains("POSIX identifier"));
        assert!(build_err("[sandbox_env]\n\"WITH-NUL\" = \"a\\u0000b\"").contains("NUL"));
        let big = "x".repeat(MAX_ENV_VALUE_BYTES + 1);
        assert!(build_err(&format!("[sandbox_env]\nBIG = \"{big}\"")).contains("limit"));
        let ok = "x".repeat(MAX_ENV_VALUE_BYTES);
        assert!(
            build_ok(&format!("[sandbox_env]\nBIG = \"{ok}\""))
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
        let path = paths.config_file();
        std::fs::write(path, "listen = [\"127.0.0.1:0\"]").expect("write config");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        let message = match Config::load_snapshot(&paths) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("group writable config must be rejected"),
        };
        assert!(message.contains("group or world writable"), "{message}");
        // A missing config is still fine when nothing unsafe exists.
        std::fs::remove_file(path).expect("remove");
        Config::load_snapshot(&paths).expect("missing config");
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
            Config::load_snapshot(&paths),
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
