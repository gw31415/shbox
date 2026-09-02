//! Backend-neutral sandbox launch policy.
//!
//! This module is the single owner of "what shbox allows": the configured
//! shell, the network mode, the curated readable system paths, the per-launch
//! writable workspace, and the private per-launch temporary directory. It
//! deliberately contains no resource limits (CPU, memory, file size, open
//! files, PID counts) and no confinement-backend types: Linux maps this
//! snapshot into an explicit `shbox-sandbox` engine configuration, and no
//! backend detail leaks back through this interface.
//!
//! Every writable location is granted per launch, never in the base policy:
//! the sandbox workspace, `/dev/null` on Linux, and the launch temp
//! directory. A launch therefore cannot grant a sibling sandbox workspace or
//! a sibling launch temp by construction.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use shbox_sandbox::NetworkNamespacePolicy;
use shbox_sandbox::{
    FilesystemPolicy, Limit, NamespacePolicy, NetworkPolicy as SandboxNetwork, PathRule,
    ResourceLimits, SandboxConfig as EngineConfig,
};

use super::{LaunchError, LaunchOperation};
use crate::config::{Config, NetworkMode, SandboxResources};

/// Maximum remote command length accepted for `shell -c` execution.
pub(crate) const MAX_COMMAND_BYTES: usize = 32 * 1024;

/// Why a curated path is readable inside the sandbox.
///
/// The classification is part of the frozen contract tested below; it keeps
/// later policy edits from turning a deliberate list into an accumulation of
/// undocumented grants. The macOS build does not enumerate the list; the
/// allow is removed when the platform launchers consume the classification.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadPathClass {
    /// Executables, runtime libraries, and dynamic-loader data required to
    /// start and run the configured shell and ordinary commands.
    ExecutableRuntime,
    /// Read-only shared system data: TLS trust, name resolution, locale, and
    /// account databases.
    SystemData,
    /// Minimal terminal/device paths required by the platform. On Linux the
    /// controlling terminal `/dev/tty` must be openable by job-control code;
    /// granting it is session-scoped by the kernel, not a host-wide grant.
    TerminalDevice,
}

/// The curated default readable paths for Linux, frozen as (path, class).
///
/// Curated for the Linux Landlock policy:
/// system binaries and libraries, TLS trust stores, resolver/loader data,
/// locale and account databases, and the entropy devices. `/tmp` is
/// deliberately absent (host-shared; the per-launch temp directory replaces
/// it), `/proc` and `/sys` are deliberately absent, `/dev/pts` is deliberately
/// absent (it would expose every host pseudo-terminal), and `/dev/tty` is the
/// only terminal-device grant in the list.
#[cfg(target_os = "linux")]
pub(crate) const CURATED_READ_PATHS: &[(&str, ReadPathClass)] = &[
    ("/usr", ReadPathClass::ExecutableRuntime),
    ("/lib", ReadPathClass::ExecutableRuntime),
    ("/lib64", ReadPathClass::ExecutableRuntime),
    ("/bin", ReadPathClass::ExecutableRuntime),
    ("/sbin", ReadPathClass::ExecutableRuntime),
    ("/etc/ssl", ReadPathClass::SystemData),
    ("/etc/pki", ReadPathClass::SystemData),
    ("/etc/ca-certificates", ReadPathClass::SystemData),
    ("/etc/resolv.conf", ReadPathClass::SystemData),
    ("/etc/hosts", ReadPathClass::SystemData),
    ("/etc/host.conf", ReadPathClass::SystemData),
    ("/etc/nsswitch.conf", ReadPathClass::SystemData),
    ("/etc/ld.so.cache", ReadPathClass::SystemData),
    ("/etc/localtime", ReadPathClass::SystemData),
    ("/etc/passwd", ReadPathClass::SystemData),
    ("/etc/group", ReadPathClass::SystemData),
    ("/dev/zero", ReadPathClass::SystemData),
    ("/dev/urandom", ReadPathClass::SystemData),
    ("/dev/random", ReadPathClass::SystemData),
    ("/dev/tty", ReadPathClass::TerminalDevice),
];

/// Curated macOS runtime paths inherited from the audited Seatbelt backend.
///
/// These are read-only system/runtime dependencies, not host data grants.
/// Optional entries are filtered when absent. `/private/etc` is never granted
/// wholesale: only resolver/time/TLS inputs are named.
#[cfg(target_os = "macos")]
pub(crate) const CURATED_READ_PATHS: &[(&str, ReadPathClass)] = &[
    ("/usr", ReadPathClass::ExecutableRuntime),
    ("/bin", ReadPathClass::ExecutableRuntime),
    ("/sbin", ReadPathClass::ExecutableRuntime),
    ("/System", ReadPathClass::ExecutableRuntime),
    ("/Library/Frameworks", ReadPathClass::ExecutableRuntime),
    (
        "/Library/Apple/System/Library",
        ReadPathClass::ExecutableRuntime,
    ),
    ("/opt/homebrew", ReadPathClass::ExecutableRuntime),
    ("/private/var/select", ReadPathClass::SystemData),
    ("/private/var/db/timezone", ReadPathClass::SystemData),
    ("/private/etc/hosts", ReadPathClass::SystemData),
    ("/private/etc/resolv.conf", ReadPathClass::SystemData),
    ("/private/etc/localtime", ReadPathClass::SystemData),
    ("/private/etc/ssl", ReadPathClass::SystemData),
    ("/dev/zero", ReadPathClass::SystemData),
    ("/dev/urandom", ReadPathClass::SystemData),
    ("/dev/random", ReadPathClass::SystemData),
    ("/dev/fd", ReadPathClass::SystemData),
];

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) const CURATED_READ_PATHS: &[(&str, ReadPathClass)] = &[];

/// Curated writable device paths. Shell commands may discard output through
/// `/dev/null`; no broader `/dev` write grant is part of the policy.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const CURATED_WRITE_PATHS: &[&str] = &["/dev/null"];

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) const CURATED_WRITE_PATHS: &[&str] = &[];

/// The immutable, process-lifetime launch policy snapshot.
///
/// Built once at daemon bootstrap from the file-backed config and the
/// validated sandbox shell. Workspace and launch-temp grants stay
/// request-local: they are derived per launch by the platform backends, never
/// stored here.
#[derive(Clone)]
pub(crate) struct SandboxLaunchPolicy {
    shell: PathBuf,
    network: NetworkMode,
    read_paths: Vec<PathBuf>,
    sandbox_env: BTreeMap<String, String>,
    temp_root: PathBuf,
    resources: SandboxResources,
    cgroup_parent: Option<PathBuf>,
}

impl fmt::Debug for SandboxLaunchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxLaunchPolicy")
            .field("shell", &self.shell)
            .field("network", &self.network)
            .field("read_paths", &self.read_paths)
            .field(
                "sandbox_env_keys",
                &self.sandbox_env.keys().collect::<Vec<_>>(),
            )
            .field("temp_root", &self.temp_root)
            .field("resources", &self.resources)
            .field(
                "cgroup_parent",
                &self.cgroup_parent.as_deref().map(Path::display),
            )
            .finish()
    }
}

impl SandboxLaunchPolicy {
    /// Combine the file-backed config — including its `[sandbox] network`
    /// mode, which is process-lifetime — with the validated shell and the
    /// shbox runtime temp root into one immutable launch snapshot.
    pub(crate) fn from_config(
        config: &Config,
        shell: impl Into<PathBuf>,
        temp_root: impl Into<PathBuf>,
    ) -> Self {
        Self::from_parts(
            shell.into(),
            config.network(),
            config.read_paths().to_vec(),
            config.sandbox_env().clone(),
            temp_root.into(),
            *config.resources(),
            config.cgroup_parent().map(Path::to_path_buf),
        )
    }

    /// Assemble a policy from explicit parts. The production path is
    /// [`from_config`](Self::from_config); tests use this to construct
    /// policies without a TOML config fixture.
    pub(crate) fn from_parts(
        shell: PathBuf,
        network: NetworkMode,
        read_paths: Vec<PathBuf>,
        sandbox_env: BTreeMap<String, String>,
        temp_root: PathBuf,
        resources: SandboxResources,
        cgroup_parent: Option<PathBuf>,
    ) -> Self {
        Self {
            shell,
            network,
            read_paths,
            sandbox_env,
            temp_root,
            resources,
            cgroup_parent,
        }
    }

    pub(crate) fn shell(&self) -> &Path {
        &self.shell
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn network(&self) -> NetworkMode {
        self.network
    }

    /// The operator-configured per-sandbox resource limits.
    pub(crate) fn resources(&self) -> &crate::config::SandboxResources {
        &self.resources
    }

    /// The operator-specified cgroup v2 creation parent, if any.
    #[cfg(target_os = "linux")]
    pub(crate) fn cgroup_parent(&self) -> Option<&Path> {
        self.cgroup_parent.as_deref()
    }

    /// The shbox-owned runtime temp root; each launch creates a unique
    // Consumed by the Linux/macOS launchers (Milestones 3-4).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn temp_root(&self) -> &Path {
        &self.temp_root
    }

    /// Resolve readable paths into the engine's non-executable and executable
    /// tiers. Operator-configured read paths never gain execute permission;
    /// only curated runtime paths and the configured shell do.
    fn resolved_filesystem_paths(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut read_only = Vec::new();
        let mut execute = Vec::new();

        for (path, class) in CURATED_READ_PATHS {
            let target = match class {
                ReadPathClass::ExecutableRuntime => &mut execute,
                ReadPathClass::SystemData | ReadPathClass::TerminalDevice => &mut read_only,
            };
            target.push(PathBuf::from(path));
        }

        execute.push(self.shell.clone());
        if let Some(parent) = self.shell.parent() {
            execute.push(parent.to_path_buf());
        }
        read_only.extend(self.read_paths.iter().cloned());

        canonicalize_existing_paths(&mut read_only);
        canonicalize_existing_paths(&mut execute);
        (read_only, execute)
    }

    pub(crate) fn curated_write_paths(&self) -> Vec<PathBuf> {
        CURATED_WRITE_PATHS.iter().map(PathBuf::from).collect()
    }

    /// Build the engine sandbox configuration for one launch.
    ///
    /// This is the single place where shbox's own policy — the curated
    /// readable system paths, the per-launch writable workspace and temp
    /// directory, the operator's network mode, and the operator's resource
    /// limits — is resolved into an explicit
    /// [`shbox_sandbox::SandboxConfig`]. The engine crate itself ships no
    /// profiles: every restriction here is deliberate shbox policy.
    ///
    /// `is_pty` selects the process/session shape the terminal path needs
    /// (new session plus controlling terminal).
    pub(crate) fn engine_config(&self, workspace: &Path, launch_temp: &Path) -> EngineConfig {
        let (mut read_only, execute) = self.resolved_filesystem_paths();
        let mut read_write = self.curated_write_paths();
        read_write.push(workspace.to_path_buf());
        read_write.push(launch_temp.to_path_buf());
        // /dev/null is writable, not a read grant; keep the tiers disjoint.
        read_only.retain(|path| {
            !CURATED_WRITE_PATHS
                .iter()
                .any(|write| Path::new(write) == path)
        });

        EngineConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: read_only.into_iter().map(PathRule::new).collect(),
                read_write: read_write.into_iter().map(PathRule::new).collect(),
                execute: execute.into_iter().map(PathRule::new).collect(),
            },
            network: self.engine_network(),
            resources: self.engine_resources(),
            syscalls: shbox_sandbox::SyscallPolicy::Unrestricted,
            namespaces: self.engine_namespaces(),
            capabilities: shbox_sandbox::CapabilityPolicy::DropAll,
            inherited_fds: Vec::new(),
            cgroup_parent: self.cgroup_parent.clone(),
        }
    }

    /// Map the operator network mode onto the engine policy.
    ///
    /// Linux: `outbound` keeps the historical contract of unrestricted
    /// networking (Landlock cannot express connect-any-port allowlists).
    /// macOS: `outbound` maps to the client-only TCP tier the audited
    /// Seatbelt profile has always used.
    #[cfg(target_os = "linux")]
    fn engine_network(&self) -> SandboxNetwork {
        match self.network {
            NetworkMode::Disabled => SandboxNetwork::Disabled,
            NetworkMode::Outbound => SandboxNetwork::Unrestricted,
        }
    }

    /// Linux `network = "disabled"` is an all-network contract. Landlock
    /// mediates TCP bind/connect, while an unprivileged fresh network
    /// namespace removes the remaining host-network reachability (including
    /// UDP). The accompanying user namespace supplies the privilege required
    /// to create the network namespace without granting capabilities to the
    /// daemon in the host namespace.
    #[cfg(target_os = "linux")]
    fn engine_namespaces(&self) -> NamespacePolicy {
        let mut namespaces = NamespacePolicy::default();
        if self.network == NetworkMode::Disabled {
            namespaces.user = true;
            namespaces.network = NetworkNamespacePolicy::Isolated;
        }
        namespaces
    }

    #[cfg(not(target_os = "linux"))]
    fn engine_namespaces(&self) -> NamespacePolicy {
        NamespacePolicy::default()
    }

    #[cfg(target_os = "macos")]
    fn engine_network(&self) -> SandboxNetwork {
        match self.network {
            NetworkMode::Disabled => SandboxNetwork::Disabled,
            NetworkMode::Outbound => SandboxNetwork::OutboundTcp,
        }
    }

    /// Map the operator resource limits onto cgroup-backed engine limits.
    fn engine_resources(&self) -> ResourceLimits {
        let resources = &self.resources;
        ResourceLimits {
            memory_bytes: option_limit(resources.memory_bytes),
            swap_bytes: option_limit(resources.swap_bytes),
            pids: option_limit(resources.pids),
            cpu_max: option_limit(
                resources
                    .cpu_quota_micros
                    .map(|quota| shbox_sandbox::CpuMax {
                        quota_us: quota,
                        period_us: resources.cpu_period_micros.unwrap_or(100_000),
                    }),
            ),
        }
    }

    /// The environment for one sandbox process: workspace-scoped basics, the
    /// operator sandbox env, and the request-authoritative overrides.
    ///
    /// A `pty-req` is authoritative for `TERM`, and the launch temp directory
    /// is authoritative for `TMPDIR`; neither can be shadowed by an operator
    /// `sandbox.env` entry. Passing `None` for the temp directory is the
    /// callers that omit a launch temp leave `TMPDIR` untouched.
    pub(crate) fn environment_for(
        &self,
        workspace: &Path,
        term: Option<&str>,
        temp_dir: Option<&Path>,
    ) -> Vec<(String, String)> {
        let workspace = workspace.to_string_lossy().into_owned();
        let shell = self.shell.to_string_lossy().into_owned();
        let mut env = vec![
            ("HOME".to_string(), workspace.clone()),
            ("PWD".to_string(), workspace),
            ("SHELL".to_string(), shell),
        ];
        env.extend(
            self.sandbox_env
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        if let Some(term) = term {
            env.retain(|(name, _)| name != "TERM");
            env.push(("TERM".to_string(), term.to_string()));
        }
        if let Some(temp_dir) = temp_dir {
            env.retain(|(name, _)| name != "TMPDIR");
            env.push((
                "TMPDIR".to_string(),
                temp_dir.to_string_lossy().into_owned(),
            ));
        }
        env
    }

    /// Create the private per-launch temp directory used as `TMPDIR`.
    ///
    /// The directory is unique per launch, mode `0700`, and removed when the
    /// returned handle drops. Failure to remove an already-removed directory
    /// is not fatal; a failure is surfaced as a launch error only when the
    /// directory cannot be created at all.
    // Consumed by the Linux/macOS launchers (Milestones 3-4).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn create_launch_temp(&self) -> Result<LaunchTemp, LaunchError> {
        const RANDOM_BYTES: usize = 16;
        for _ in 0..32 {
            let random: [u8; RANDOM_BYTES] = rand::random();
            let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = self.temp_root.join(format!("launch-{hex}"));
            let created = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path)
            };
            match created {
                Ok(()) => {
                    // DirBuilder's mode is umask-masked; force the
                    // owner-only mode the policy promises.
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
                    if let Err(error) = crate::paths::validate_dir(&path) {
                        let _ = fs::remove_dir(&path);
                        return Err(LaunchError::new(format!(
                            "sandbox launch temp directory is not private: {error}"
                        )));
                    }
                    return Ok(LaunchTemp { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    return Err(LaunchError::new(
                        "sandbox launch temp directory could not be created",
                    ));
                }
            }
        }
        Err(LaunchError::new(
            "sandbox launch temp directory could not be allocated",
        ))
    }
}

fn canonicalize_existing_paths(paths: &mut Vec<PathBuf>) {
    paths.retain(|path| path.exists());
    *paths = paths
        .iter()
        .filter_map(|path| fs::canonicalize(path).ok())
        .collect();
    paths.sort();
    paths.dedup();
}

/// An optional configured value becomes an explicit `Value` limit; absent
/// stays `Inherit` (no contribution to the sandbox's shared resource domain).
fn option_limit<T>(value: Option<T>) -> Limit<T> {
    match value {
        Some(value) => Limit::Value(value),
        None => Limit::Inherit,
    }
}

/// An owned per-launch temp directory, removed on drop.
#[derive(Debug)]
pub(crate) struct LaunchTemp {
    path: PathBuf,
}

// The Linux and macOS launchers (Milestones 3-4) consume the temp handles;
// until then only tests construct them.
#[cfg_attr(not(test), allow(dead_code))]
impl LaunchTemp {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Best-effort recursive removal that tolerates an already-removed path
    /// but reports a still-owned tree that could not be deleted. The root is
    /// inspected without following symlinks before deletion, so a replaced
    /// launch-temp path cannot redirect cleanup into another tree.
    pub(crate) fn remove(self) -> Result<(), LaunchError> {
        let path = self.path.clone();
        let result = remove_launch_temp_tree(&path);
        // Avoid running Drop a second time after the explicit removal attempt.
        std::mem::forget(self);
        result.map_err(|error| {
            LaunchError::new(format!(
                "sandbox launch temp directory could not be removed: {error}"
            ))
        })
    }
}

impl Drop for LaunchTemp {
    fn drop(&mut self) {
        if let Err(error) = remove_launch_temp_tree(&self.path) {
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "could not remove launch temp directory"
            );
        }
    }
}

fn remove_launch_temp_tree(path: &Path) -> std::io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    }
}

/// Validate the remote command payload for `shell -c` execution.
///
/// The payload is an opaque SSH byte string: at most 32 KiB and no NUL
/// bytes, but not necessarily UTF-8. The exact bytes become the single
/// `-c` argument and quoting, encoding, and interpretation stay the
/// selected shell's responsibility. Shell operations return `None` and
/// keep the login-shell behavior of the caller.
pub(crate) fn validated_shell_command(
    operation: &LaunchOperation,
) -> Result<Option<std::ffi::OsString>, LaunchError> {
    use std::os::unix::ffi::OsStrExt;
    match operation {
        LaunchOperation::Shell => Ok(None),
        LaunchOperation::Exec(bytes) => {
            if bytes.len() > MAX_COMMAND_BYTES {
                return Err(LaunchError::new("sandbox command is too large"));
            }
            if bytes.contains(&0) {
                return Err(LaunchError::new("sandbox command contains NUL"));
            }
            Ok(Some(std::ffi::OsStr::from_bytes(bytes).to_os_string()))
        }
    }
}

/// OpenSSH-style login shell name: the `-<basename>` string the caller
/// installs as `argv[0]` so the shell starts in login mode without any
/// shell-specific option.
pub(crate) fn login_shell_argv0(shell: &Path) -> Result<std::ffi::OsString, LaunchError> {
    let name = shell
        .file_name()
        .ok_or_else(|| LaunchError::new("sandbox shell path has no file name"))?;
    let mut argv0 = std::ffi::OsString::from("-");
    argv0.push(name);
    Ok(argv0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(shell: &str) -> SandboxLaunchPolicy {
        let config = crate::config::defaults();
        SandboxLaunchPolicy::from_config(&config, shell, "/state/runtime")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn curated_linux_read_paths_are_frozen() {
        let expected = [
            ("/usr", ReadPathClass::ExecutableRuntime),
            ("/lib", ReadPathClass::ExecutableRuntime),
            ("/lib64", ReadPathClass::ExecutableRuntime),
            ("/bin", ReadPathClass::ExecutableRuntime),
            ("/sbin", ReadPathClass::ExecutableRuntime),
            ("/etc/ssl", ReadPathClass::SystemData),
            ("/etc/pki", ReadPathClass::SystemData),
            ("/etc/ca-certificates", ReadPathClass::SystemData),
            ("/etc/resolv.conf", ReadPathClass::SystemData),
            ("/etc/hosts", ReadPathClass::SystemData),
            ("/etc/host.conf", ReadPathClass::SystemData),
            ("/etc/nsswitch.conf", ReadPathClass::SystemData),
            ("/etc/ld.so.cache", ReadPathClass::SystemData),
            ("/etc/localtime", ReadPathClass::SystemData),
            ("/etc/passwd", ReadPathClass::SystemData),
            ("/etc/group", ReadPathClass::SystemData),
            ("/dev/zero", ReadPathClass::SystemData),
            ("/dev/urandom", ReadPathClass::SystemData),
            ("/dev/random", ReadPathClass::SystemData),
            ("/dev/tty", ReadPathClass::TerminalDevice),
        ];
        assert_eq!(CURATED_READ_PATHS, &expected[..]);

        // The deliberately absent broad grants stay absent.
        for path in ["/", "/tmp", "/dev", "/proc", "/sys", "/dev/pts", "/etc"] {
            assert!(
                !CURATED_READ_PATHS
                    .iter()
                    .any(|(granted, _)| *granted == path),
                "{path} must not be broadly granted"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn curated_linux_write_paths_are_only_dev_null() {
        assert_eq!(CURATED_WRITE_PATHS, &["/dev/null"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn curated_macos_paths_are_frozen_and_narrow() {
        let expected = [
            ("/usr", ReadPathClass::ExecutableRuntime),
            ("/bin", ReadPathClass::ExecutableRuntime),
            ("/sbin", ReadPathClass::ExecutableRuntime),
            ("/System", ReadPathClass::ExecutableRuntime),
            ("/Library/Frameworks", ReadPathClass::ExecutableRuntime),
            (
                "/Library/Apple/System/Library",
                ReadPathClass::ExecutableRuntime,
            ),
            ("/opt/homebrew", ReadPathClass::ExecutableRuntime),
            ("/private/var/select", ReadPathClass::SystemData),
            ("/private/var/db/timezone", ReadPathClass::SystemData),
            ("/private/etc/hosts", ReadPathClass::SystemData),
            ("/private/etc/resolv.conf", ReadPathClass::SystemData),
            ("/private/etc/localtime", ReadPathClass::SystemData),
            ("/private/etc/ssl", ReadPathClass::SystemData),
            ("/dev/zero", ReadPathClass::SystemData),
            ("/dev/urandom", ReadPathClass::SystemData),
            ("/dev/random", ReadPathClass::SystemData),
            ("/dev/fd", ReadPathClass::SystemData),
        ];
        assert_eq!(CURATED_READ_PATHS, &expected[..]);
        assert_eq!(CURATED_WRITE_PATHS, &["/dev/null"]);
        for broad in [
            "/",
            "/Users",
            "/private",
            "/private/etc",
            "/var",
            "/tmp",
            "/dev",
        ] {
            assert!(
                !CURATED_READ_PATHS
                    .iter()
                    .any(|(granted, _)| *granted == broad),
                "{broad} must not be broadly granted"
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn curated_paths_are_empty_on_unsupported_platforms() {
        assert!(CURATED_READ_PATHS.is_empty());
        assert!(CURATED_WRITE_PATHS.is_empty());
    }

    #[test]
    fn resolved_filesystem_paths_keep_operator_reads_non_executable() {
        let directory = tempfile::tempdir().expect("configured read root");
        let configured = directory.path().join("share");
        std::fs::create_dir(&configured).expect("configured dir");
        let policy = SandboxLaunchPolicy::from_parts(
            PathBuf::from("/bin/sh"),
            NetworkMode::Disabled,
            vec![configured],
            BTreeMap::new(),
            PathBuf::from("/state/runtime"),
            crate::config::SandboxResources::default(),
            None,
        );
        let (read_only, execute) = policy.resolved_filesystem_paths();
        let canonical_shell = std::fs::canonicalize("/bin/sh").expect("shell");
        assert!(execute.contains(&canonical_shell));
        assert!(!read_only.contains(&canonical_shell));
        let configured = std::fs::canonicalize(directory.path().join("share").as_path())
            .expect("canonical configured");
        assert!(read_only.contains(&configured));
        assert!(!execute.contains(&configured));

        for resolved in [&read_only, &execute] {
            let mut sorted = resolved.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(resolved, &sorted);
            assert!(resolved.iter().all(|path| path.is_absolute()));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disabled_network_uses_an_unprivileged_isolated_network_namespace() {
        let policy = test_policy("/bin/sh");
        let namespaces = policy.engine_namespaces();
        assert!(
            namespaces.user,
            "a user namespace is required to create the network namespace without host capabilities"
        );
        assert_eq!(namespaces.network, NetworkNamespacePolicy::Isolated);
    }

    #[test]
    fn policy_grants_no_workspace_and_no_resource_limits() {
        let directory = tempfile::tempdir().expect("workspace");
        let policy = test_policy("/bin/sh");
        // The base policy never names a workspace; workspace grants are
        // per-launch, so workspace A cannot accidentally grant workspace B.
        let debug = format!("{policy:?}");
        assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
        // No resource-limit field exists on the policy type; the debug
        // snapshot of every field must not carry limit-ish state either.
        assert!(!debug.contains("max_"));
        assert!(!debug.to_lowercase().contains("limit"));
    }

    /// The operator network mode maps onto the engine's network policy
    /// deterministically per platform (docs/platforms.md).
    #[test]
    fn network_mode_maps_deterministically_from_config() {
        let policy = test_policy("/bin/sh");
        assert_eq!(policy.engine_network(), SandboxNetwork::Disabled);
    }

    #[test]
    fn policy_debug_snapshot_carries_resource_state_openly() {
        let debug = format!("{:?}", test_policy("/bin/sh"));
        // Resource policy is operator configuration, not hidden global
        // state: the debug view shows it explicitly.
        assert!(debug.contains("resources"));
    }

    #[test]
    fn launch_temp_is_private_and_sibling_isolated() {
        let root = tempfile::tempdir().expect("temp root");
        let config = crate::config::defaults();
        let policy = SandboxLaunchPolicy::from_config(&config, "/bin/sh", root.path());
        assert_eq!(policy.temp_root(), root.path());
        let first = policy.create_launch_temp().expect("first launch temp");
        let second = policy.create_launch_temp().expect("second launch temp");
        assert_ne!(first.path(), second.path());

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(first.path())
            .expect("temp meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(first.path().starts_with(root.path()));

        // Removing one temp recursively removes child-created contents and
        // does not affect the sibling.
        let first_path = first.path().to_path_buf();
        fs::create_dir(first.path().join("nested")).expect("nested launch temp");
        fs::write(first.path().join("nested/file"), b"residue").expect("launch temp residue");
        first.remove().expect("remove first");
        assert!(!first_path.exists());
        assert!(second.path().exists());
    }

    #[test]
    fn environment_is_workspace_scoped_with_authoritative_overrides() {
        let mut sandbox_env = BTreeMap::new();
        sandbox_env.insert("TERM".to_string(), "operator-term".to_string());
        sandbox_env.insert("TMPDIR".to_string(), "/operator/tmp".to_string());
        let policy = SandboxLaunchPolicy::from_parts(
            PathBuf::from("/bin/sh"),
            NetworkMode::Disabled,
            Vec::new(),
            sandbox_env,
            PathBuf::from("/state/runtime"),
            crate::config::SandboxResources::default(),
            None,
        );
        let directory = tempfile::tempdir().expect("workspace");
        let temp = Path::new("/state/runtime/launch-abc");
        let env = policy.environment_for(directory.path(), Some("xterm-256color"), Some(temp));

        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "HOME")
                .map(|(_, value)| value.as_str()),
            Some(directory.path().to_string_lossy().as_ref())
        );
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "TMPDIR")
                .map(|(_, value)| value.as_str()),
            Some("/state/runtime/launch-abc")
        );
        assert_eq!(env.iter().filter(|(name, _)| name == "TERM").count(), 1);
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "TERM")
                .map(|(_, value)| value.as_str()),
            Some("xterm-256color")
        );

        // Without a temp dir, TMPDIR is untouched.
        let legacy = policy.environment_for(directory.path(), None, None);
        assert_eq!(
            legacy
                .iter()
                .find(|(name, _)| name == "TMPDIR")
                .map(|(_, value)| value.as_str()),
            Some("/operator/tmp")
        );
    }

    #[test]
    fn command_validation_rejects_oversized_and_nul_but_preserves_raw_bytes() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(
            validated_shell_command(&LaunchOperation::Shell).expect("shell"),
            None
        );
        let ok = LaunchOperation::Exec(b"echo hi".to_vec());
        assert_eq!(
            validated_shell_command(&ok)
                .expect("valid command")
                .expect("exec has a command")
                .as_os_str()
                .as_bytes(),
            b"echo hi"
        );
        // SSH exec carries an opaque byte string; non-UTF-8 payloads are
        // passed through byte-for-byte, never validated or transcoded.
        let non_utf8 = LaunchOperation::Exec(vec![b'x', 0xff, 0xfe, b'y']);
        assert_eq!(
            validated_shell_command(&non_utf8)
                .expect("raw bytes are valid")
                .expect("exec has a command")
                .as_os_str()
                .as_bytes(),
            &[b'x', 0xff, 0xfe, b'y']
        );
        let oversized = LaunchOperation::Exec(vec![b'a'; MAX_COMMAND_BYTES + 1]);
        assert_eq!(
            validated_shell_command(&oversized)
                .err()
                .map(|e| e.to_string()),
            Some("sandbox command is too large".to_string())
        );
        let with_nul = LaunchOperation::Exec(b"echo\0hi".to_vec());
        assert_eq!(
            validated_shell_command(&with_nul)
                .err()
                .map(|e| e.to_string()),
            Some("sandbox command contains NUL".to_string())
        );
    }

    #[test]
    fn login_shell_argv0_uses_the_leading_dash_basename_form() {
        use std::os::unix::ffi::OsStrExt;

        let argv0 = login_shell_argv0(Path::new("/bin/zsh")).expect("argv0");
        assert_eq!(argv0.as_os_str().as_bytes(), b"-zsh");
        let argv0 = login_shell_argv0(Path::new("/opt/homebrew/bin/fish")).expect("argv0");
        assert_eq!(argv0.as_os_str().as_bytes(), b"-fish");
        assert!(
            login_shell_argv0(Path::new("/")).is_err(),
            "a path with no file name has no login form"
        );
    }
}
