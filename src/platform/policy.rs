//! Backend-neutral sandbox launch policy.
//!
//! This module is the single owner of "what shbox allows": the configured
//! shell, the network mode, the curated readable system paths, the per-launch
//! writable workspace, and the private per-launch temporary directory. It
//! deliberately contains no resource limits (CPU, memory, file size, open
//! files, PID counts) and no confinement-backend types: Linux maps this
//! snapshot to `nono` capabilities and macOS to a generated Seatbelt profile,
//! and neither backend leaks back through this interface.
//!
//! Every writable location is granted per launch, never in the base policy:
//! the sandbox workspace, `/dev/null` on Linux, and the launch temp
//! directory. A launch therefore cannot grant a sibling sandbox workspace or
//! a sibling launch temp by construction.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use super::{LaunchError, LaunchOperation};
use crate::config::{Config, NetworkMode};

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
/// Inherited from the audited Arapuca defaults and re-approved for nono:
/// system binaries and libraries, TLS trust stores, resolver/loader data,
/// locale and account databases, and the entropy devices. `/tmp` is
/// deliberately absent (host-shared; the per-launch temp directory replaces
/// it), `/proc` and `/sys` are deliberately absent, `/dev/pts` is deliberately
/// absent (it would expose every host pseudo-terminal), and `/dev/tty` is the
/// only added grant beyond the Arapuca list.
#[cfg(target_os = "linux")]
pub(crate) const CURATED_READ_PATHS: &[(PathBuf, ReadPathClass)] = &[
    (PathBuf::from("/usr"), ReadPathClass::ExecutableRuntime),
    (PathBuf::from("/lib"), ReadPathClass::ExecutableRuntime),
    (PathBuf::from("/lib64"), ReadPathClass::ExecutableRuntime),
    (PathBuf::from("/bin"), ReadPathClass::ExecutableRuntime),
    (PathBuf::from("/sbin"), ReadPathClass::ExecutableRuntime),
    (PathBuf::from("/etc/ssl"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/pki"), ReadPathClass::SystemData),
    (
        PathBuf::from("/etc/ca-certificates"),
        ReadPathClass::SystemData,
    ),
    (PathBuf::from("/etc/resolv.conf"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/hosts"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/host.conf"), ReadPathClass::SystemData),
    (
        PathBuf::from("/etc/nsswitch.conf"),
        ReadPathClass::SystemData,
    ),
    (PathBuf::from("/etc/ld.so.cache"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/localtime"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/passwd"), ReadPathClass::SystemData),
    (PathBuf::from("/etc/group"), ReadPathClass::SystemData),
    (PathBuf::from("/dev/zero"), ReadPathClass::SystemData),
    (PathBuf::from("/dev/urandom"), ReadPathClass::SystemData),
    (PathBuf::from("/dev/random"), ReadPathClass::SystemData),
    (PathBuf::from("/dev/tty"), ReadPathClass::TerminalDevice),
];

/// macOS has no curated default read grants: the generated Seatbelt profile
/// enumerates the system paths the shell needs, and the profile is validated
/// in the macOS backend tests.
#[cfg(not(target_os = "linux"))]
pub(crate) const CURATED_READ_PATHS: &[(PathBuf, ReadPathClass)] = &[];

/// The curated writable device paths for Linux.
///
/// Shell commands commonly discard output through `/dev/null`. Keep this
/// single device writable without granting write access to the rest of
/// `/dev`. macOS handles `/dev/null` inside its Seatbelt profile instead.
#[cfg(target_os = "linux")]
pub(crate) const CURATED_WRITE_PATHS: &[PathBuf] = &[PathBuf::from("/dev/null")];

#[cfg(not(target_os = "linux"))]
pub(crate) const CURATED_WRITE_PATHS: &[PathBuf] = &[];

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
    ) -> Self {
        Self {
            shell,
            network,
            read_paths,
            sandbox_env,
            temp_root,
        }
    }

    pub(crate) fn shell(&self) -> &Path {
        &self.shell
    }

    pub(crate) fn network(&self) -> NetworkMode {
        self.network
    }

    /// The shbox-owned runtime temp root; each launch creates a unique
    // Consumed by the Linux/macOS launchers (Milestones 3-4).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn temp_root(&self) -> &Path {
        &self.temp_root
    }

    /// The final canonicalized readable path list for policy preparation:
    /// curated defaults (omitting absent entries), the validated shell plus
    /// its parent directory, and the operator-configured read paths.
    pub(crate) fn resolved_read_paths(&self) -> Vec<PathBuf> {
        let mut read_paths: Vec<PathBuf> = CURATED_READ_PATHS
            .iter()
            .map(|(path, _)| path.clone())
            .collect();
        read_paths.push(self.shell.clone());
        if let Some(parent) = self.shell.parent() {
            read_paths.push(parent.to_path_buf());
        }
        read_paths.extend(self.read_paths.iter().cloned());

        // Optional curated entries are omitted when absent, so filter before
        // canonicalization. Canonicalization can only fail for entries that
        // just disappeared between the existence check and the call; those
        // are dropped the same way as absent entries.
        read_paths.retain(|path| path.exists());
        let mut read_paths: Vec<PathBuf> = read_paths
            .iter()
            .filter_map(|path| fs::canonicalize(path).ok())
            .collect();
        read_paths.sort();
        read_paths.dedup();
        read_paths
    }

    pub(crate) fn curated_write_paths(&self) -> &[PathBuf] {
        CURATED_WRITE_PATHS
    }

    /// The environment for one sandbox process: workspace-scoped basics, the
    /// operator sandbox env, and the request-authoritative overrides.
    ///
    /// A `pty-req` is authoritative for `TERM`, and the launch temp directory
    /// is authoritative for `TMPDIR`; neither can be shadowed by an operator
    /// `sandbox.env` entry. Passing `None` for the temp directory is the
    /// transitional Arapuca behavior and leaves `TMPDIR` untouched.
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

    /// Best-effort removal that tolerates an already-removed directory but
    /// reports a still-owned directory that could not be deleted.
    pub(crate) fn remove(self) -> Result<(), LaunchError> {
        let path = self.path.clone();
        drop(self);
        match fs::remove_dir(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(LaunchError::new(format!(
                "sandbox launch temp directory could not be removed: {error}"
            ))),
        }
    }
}

impl Drop for LaunchTemp {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "could not remove launch temp directory"
            );
        }
    }
}

/// Validate the remote command payload for `shell -c` execution.
///
/// The contract is unchanged from the previous backend: at most 32 KiB, no
/// NUL bytes, and UTF-8 (the shell `-c` contract is UTF-8). Shell operations
/// return `None` and keep the login-shell behavior of the caller.
pub(crate) fn validated_shell_command(
    operation: &LaunchOperation,
) -> Result<Option<String>, LaunchError> {
    match operation {
        LaunchOperation::Shell => Ok(None),
        LaunchOperation::Exec(bytes) => {
            if bytes.len() > MAX_COMMAND_BYTES {
                return Err(LaunchError::new("sandbox command is too large"));
            }
            if bytes.contains(&0) {
                return Err(LaunchError::new("sandbox command contains NUL"));
            }
            Ok(Some(String::from_utf8(bytes.clone()).map_err(|_| {
                LaunchError::new("sandbox command is not valid UTF-8")
            })?))
        }
    }
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
        let expected: Vec<(PathBuf, ReadPathClass)> = [
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
        ]
        .into_iter()
        .map(|(path, class)| (PathBuf::from(path), class))
        .collect();
        assert_eq!(CURATED_READ_PATHS, &expected[..]);

        // The deliberately absent broad grants stay absent.
        for path in ["/", "/tmp", "/dev", "/proc", "/sys", "/dev/pts", "/etc"] {
            assert!(
                !CURATED_READ_PATHS
                    .iter()
                    .any(|(granted, _)| granted == Path::new(path)),
                "{path} must not be broadly granted"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn curated_linux_write_paths_are_only_dev_null() {
        assert_eq!(CURATED_WRITE_PATHS, &[PathBuf::from("/dev/null")]);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn curated_paths_are_empty_off_linux() {
        assert!(CURATED_READ_PATHS.is_empty());
        assert!(CURATED_WRITE_PATHS.is_empty());
    }

    #[test]
    fn resolved_read_paths_include_shell_and_configured_entries() {
        let directory = tempfile::tempdir().expect("configured read root");
        let configured = directory.path().join("share");
        std::fs::create_dir(&configured).expect("configured dir");
        let policy = SandboxLaunchPolicy::from_parts(
            PathBuf::from("/bin/sh"),
            NetworkMode::Disabled,
            vec![configured],
            BTreeMap::new(),
            PathBuf::from("/state/runtime"),
        );
        let resolved = policy.resolved_read_paths();
        let canonical_shell = std::fs::canonicalize("/bin/sh").expect("shell");
        assert!(resolved.contains(&canonical_shell));
        assert!(
            resolved.contains(
                &std::fs::canonicalize(directory.path().join("share").as_path())
                    .expect("canonical configured")
            )
        );
        // Sorted, deduplicated, absolute.
        let mut sorted = resolved.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(resolved, sorted);
        assert!(resolved.iter().all(|path| path.is_absolute()));
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

    #[test]
    fn network_mode_maps_deterministically_from_config() {
        assert_eq!(test_policy("/bin/sh").network(), NetworkMode::Disabled);
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

        // Removing one temp does not affect the sibling.
        let first_path = first.path().to_path_buf();
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

        // Without a temp dir (transitional Arapuca path) TMPDIR is untouched.
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
    fn command_validation_rejects_oversized_nul_and_non_utf8() {
        assert_eq!(
            validated_shell_command(&LaunchOperation::Shell).expect("shell"),
            None
        );
        let ok = LaunchOperation::Exec(b"echo hi".to_vec());
        assert_eq!(
            validated_shell_command(&ok).expect("valid command"),
            Some("echo hi".to_string())
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
        let non_utf8 = LaunchOperation::Exec(vec![0xff, 0xfe]);
        assert_eq!(
            validated_shell_command(&non_utf8)
                .err()
                .map(|e| e.to_string()),
            Some("sandbox command is not valid UTF-8".to_string())
        );
    }
}
