//! Policy validation (architecture Phase 11).
//!
//! Deciding how *strong* a sandbox should be is caller policy, but rejecting
//! configurations that cannot work is this crate's job. Validation runs in
//! the parent before any child exists and reports
//! [`SandboxError::InvalidPolicy`] with a field identifier; kernel/OS
//! shortfalls surface separately as [`SandboxError::Unsupported`] at spawn
//! time.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::command::{CommandSpec, Stdio};
use crate::error::SandboxError;
use crate::policy::{
    CapabilityPolicy, FilesystemPolicy, IdentityPolicy, Limit, PathRule, ResourceLimits,
    SandboxConfig, Syscall, SyscallPolicy,
};

/// Validate a config/command pair before any resource is allocated.
pub(crate) fn validate(config: &SandboxConfig, command: &CommandSpec) -> Result<(), SandboxError> {
    validate_command(command)?;
    validate_inherited_fds(config)?;
    validate_filesystem(&config.filesystem, command)?;
    validate_resources(&config.resources)?;
    validate_syscalls(&config.syscalls)?;
    validate_identity(config)?;
    Ok(())
}

/// Identity-policy invariants. Numeric checks are platform-neutral; the
/// Linux backend additionally rejects a `host_uid`/`host_gid` equal to its
/// own live credentials at spawn time.
fn validate_identity(config: &SandboxConfig) -> Result<(), SandboxError> {
    let IdentityPolicy::Isolated(identity) = config.identity else {
        return Ok(());
    };
    if identity.runtime_uid == 0 || identity.runtime_gid == 0 {
        return Err(SandboxError::invalid(
            "identity",
            "isolated identity must not map namespace UID/GID 0: no bootstrap identity may exist",
        ));
    }
    if identity.host_uid == 0 || identity.host_gid == 0 {
        return Err(SandboxError::invalid(
            "identity",
            "isolated identity must not map to host UID/GID 0 (root)",
        ));
    }
    if !config.namespaces.mount {
        return Err(SandboxError::invalid(
            "identity",
            "isolated identity requires a fresh mount namespace (NamespacePolicy::mount) for ID-mapped writable views",
        ));
    }
    if let CapabilityPolicy::Retain(retained) = &config.capabilities
        && !retained.is_empty()
    {
        return Err(SandboxError::invalid(
            "identity",
            "isolated identity is incompatible with retained capabilities: the runtime process must end with empty capability sets",
        ));
    }
    Ok(())
}

/// Command-level checks: C-string-safety and stream sources.
fn validate_command(command: &CommandSpec) -> Result<(), SandboxError> {
    if command.program.as_os_str().is_empty() {
        return Err(SandboxError::invalid("program", "program path is empty"));
    }
    // execve(2) does not search PATH; a relative program would resolve
    // against the child's (policy-restricted) view unpredictably.
    if !command.program.is_absolute() {
        return Err(SandboxError::invalid(
            "program",
            format!(
                "program path {} is not absolute (execve performs no PATH search)",
                command.program.display()
            ),
        ));
    }
    check_no_nul("program", &command.program)?;
    for arg in command.argv0.iter().chain(command.args.iter()) {
        check_no_nul("args", arg)?;
    }
    for (name, value) in &command.env {
        check_no_nul("env", name)?;
        check_no_nul("env", value)?;
        if name.is_empty() {
            return Err(SandboxError::invalid(
                "env",
                "environment variable name is empty",
            ));
        }
        if name.as_bytes().contains(&b'=') {
            return Err(SandboxError::invalid(
                "env",
                format!(
                    "environment variable name {:?} contains '='",
                    name.to_string_lossy()
                ),
            ));
        }
    }
    if let Some(cwd) = &command.cwd {
        check_no_nul("cwd", cwd)?;
        if !cwd.is_absolute() {
            return Err(SandboxError::invalid(
                "cwd",
                format!("working directory {} is not absolute", cwd.display()),
            ));
        }
    }
    for (field, stdio) in [
        ("stdin", command.stdin),
        ("stdout", command.stdout),
        ("stderr", command.stderr),
    ] {
        if let Stdio::Fd(fd) = stdio
            && fd < 0
        {
            return Err(SandboxError::invalid(
                field,
                format!("stdio source descriptor {fd} is negative"),
            ));
        }
    }
    Ok(())
}

fn check_no_nul(field: &'static str, value: impl AsRef<Path>) -> Result<(), SandboxError> {
    if value.as_ref().as_os_str().as_bytes().contains(&0) {
        return Err(SandboxError::invalid(
            field,
            "path contains a NUL byte and cannot be passed to the OS",
        ));
    }
    Ok(())
}

/// Inherited descriptors must be numbers >= 3, currently open, and listed
/// once. FDs 0..=2 belong to the standard streams by construction.
fn validate_inherited_fds(config: &SandboxConfig) -> Result<(), SandboxError> {
    let mut seen = BTreeSet::new();
    for &fd in &config.inherited_fds {
        if fd < 3 {
            return Err(SandboxError::invalid(
                "inherited_fds",
                format!(
                    "descriptor {fd} is a standard-stream slot; inherited descriptors must be >= 3"
                ),
            ));
        }
        if !seen.insert(fd) {
            return Err(SandboxError::invalid(
                "inherited_fds",
                format!("descriptor {fd} is listed more than once"),
            ));
        }
        // SAFETY: fcntl(F_GETFD) only reads descriptor flags of an integer.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(SandboxError::invalid(
                "inherited_fds",
                format!("descriptor {fd} is not open in the parent"),
            ));
        }
    }
    Ok(())
}

/// Filesystem policy checks: absolute rules and — as an early, best-effort
/// check — that the requested program and working directory are covered by
/// an execute/read grant when they can be resolved.
fn validate_filesystem(
    policy: &FilesystemPolicy,
    command: &CommandSpec,
) -> Result<(), SandboxError> {
    let FilesystemPolicy::Restricted {
        read_only,
        read_write,
        execute,
    } = policy
    else {
        return Ok(());
    };
    for (tier, rules) in [
        ("filesystem.read_only", read_only),
        ("filesystem.read_write", read_write),
        ("filesystem.execute", execute),
    ] {
        for rule in rules {
            if !rule.path.is_absolute() {
                return Err(SandboxError::invalid(
                    tier,
                    format!("rule path {} is not absolute", rule.path.display()),
                ));
            }
            check_no_nul("filesystem", &rule.path)?;
        }
    }

    // Early coverage diagnostics. Both sides are canonicalized the way the
    // spawn will resolve them; races can still make the child fail later
    // (fail closed at chdir/exec), so this only catches statically
    // contradictory policies.
    // The read tier grants no execute right, so only read_write and execute
    // rules can cover the program; every tier grants read, so any of them
    // can cover the working directory.
    let covered_by_grant =
        |path: &Path, rule: &PathRule| covered_by(path, canonical(&rule.path).as_ref());
    let mut executable_tiers = read_write.iter().chain(execute.iter());
    let mut readable_tiers = read_only
        .iter()
        .chain(read_write.iter())
        .chain(execute.iter());

    if let Ok(program) = std::fs::canonicalize(&command.program)
        && !executable_tiers.any(|rule| covered_by_grant(&program, rule))
    {
        return Err(SandboxError::invalid(
            "filesystem",
            format!(
                "program {} is not covered by any filesystem rule",
                program.display()
            ),
        ));
    }
    if let Some(cwd) = &command.cwd
        && let Ok(cwd) = std::fs::canonicalize(cwd)
        && !readable_tiers.any(|rule| covered_by_grant(&cwd, rule))
    {
        return Err(SandboxError::invalid(
            "filesystem.read_only",
            format!(
                "working directory {} is not covered by any filesystem rule",
                cwd.display()
            ),
        ));
    }
    Ok(())
}

/// The canonical form of `path`, or the path as-written when it cannot be
/// resolved — the fallback borrows the input instead of copying it.
fn canonical(path: &Path) -> Cow<'_, Path> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => Cow::Owned(canonical),
        Err(_) => Cow::Borrowed(path),
    }
}

/// Whether `path` equals or lies beneath `grant` (component-wise).
fn covered_by(path: &Path, grant: &Path) -> bool {
    path.starts_with(grant)
}

/// Resource-limit sanity.
pub(crate) fn validate_resources(resources: &ResourceLimits) -> Result<(), SandboxError> {
    if let Limit::Value(cpu) = resources.cpu_max {
        if cpu.quota_us == 0 {
            return Err(SandboxError::invalid(
                "resources.cpu_max",
                "CPU quota must be greater than zero",
            ));
        }
        if !(1000..=1_000_000).contains(&cpu.period_us) {
            return Err(SandboxError::invalid(
                "resources.cpu_max",
                format!(
                    "CPU period {} microseconds is outside the kernel range 1000..=1000000",
                    cpu.period_us
                ),
            ));
        }
    }
    if let Limit::Value(bytes) = resources.memory_bytes
        && bytes == 0
    {
        return Err(SandboxError::invalid(
            "resources.memory_bytes",
            "memory limit must be greater than zero (use Unlimited for no limit)",
        ));
    }
    if let Limit::Value(count) = resources.pids
        && count == 0
    {
        return Err(SandboxError::invalid(
            "resources.pids",
            "PID limit must be greater than zero (use Unlimited for no limit)",
        ));
    }
    Ok(())
}

/// Syscall policy sanity, including name resolution on Linux.
fn validate_syscalls(policy: &SyscallPolicy) -> Result<(), SandboxError> {
    let SyscallPolicy::Filter {
        default_action,
        matched_action,
        rules,
    } = policy
    else {
        return Ok(());
    };
    if default_action == matched_action {
        return Err(SandboxError::invalid(
            "syscalls",
            "default and matched actions are identical; the filter would be a no-op \
             (use SyscallPolicy::Unrestricted to install no filter)",
        ));
    }
    for rule in rules {
        match rule.syscall {
            Syscall::Named(name) => {
                #[cfg(target_os = "linux")]
                let known = crate::linux::syscall_number(name).is_some();
                #[cfg(not(target_os = "linux"))]
                let known = true;
                if !known {
                    return Err(SandboxError::invalid(
                        "syscalls.rules",
                        format!("unknown syscall name {name:?} for this architecture"),
                    ));
                }
            }
            Syscall::Number(number) => {
                if number < 0 {
                    return Err(SandboxError::invalid(
                        "syscalls.rules",
                        format!("syscall number {number} is negative"),
                    ));
                }
            }
        }
        for condition in &rule.conditions {
            if condition.arg > 5 {
                return Err(SandboxError::invalid(
                    "syscalls.rules",
                    format!(
                        "condition argument index {} is outside 0..=5",
                        condition.arg
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::policy::SyscallRule;
    use crate::policy::{
        Capability, CapabilityPolicy, CpuMax, IdentityPolicy, IsolatedIdentity, PathRule,
        SeccompAction,
    };
    use std::os::fd::AsRawFd;

    fn minimal_command() -> CommandSpec {
        CommandSpec::new("/bin/sh")
    }

    fn isolated_config(identity: IsolatedIdentity) -> SandboxConfig {
        let mut config = SandboxConfig::unrestricted();
        config.identity = IdentityPolicy::Isolated(identity);
        config.namespaces.mount = true;
        config
    }

    fn valid_identity() -> IsolatedIdentity {
        IsolatedIdentity {
            runtime_uid: 1000,
            runtime_gid: 1000,
            host_uid: 100_000,
            host_gid: 200_000,
        }
    }

    #[test]
    fn identity_defaults_to_host_and_caller_mapped_root_passes() {
        assert_eq!(SandboxConfig::unrestricted().identity, IdentityPolicy::Host);
        let mut config = SandboxConfig::unrestricted();
        config.identity = IdentityPolicy::CallerMappedRoot;
        assert!(validate(&config, &minimal_command()).is_ok());
    }

    #[test]
    fn isolated_identity_passes_validation_with_valid_ids() {
        assert!(validate(&isolated_config(valid_identity()), &minimal_command()).is_ok());
    }

    #[test]
    fn isolated_identity_rejects_zero_runtime_or_host_ids() {
        for mutate_zero in [
            IsolatedIdentity {
                runtime_uid: 0,
                ..valid_identity()
            },
            IsolatedIdentity {
                runtime_gid: 0,
                ..valid_identity()
            },
            IsolatedIdentity {
                host_uid: 0,
                ..valid_identity()
            },
            IsolatedIdentity {
                host_gid: 0,
                ..valid_identity()
            },
        ] {
            let error = validate(&isolated_config(mutate_zero), &minimal_command())
                .expect_err("zero id must be rejected");
            assert!(
                matches!(
                    error,
                    SandboxError::InvalidPolicy {
                        field: "identity",
                        ..
                    }
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn isolated_identity_requires_a_fresh_mount_namespace() {
        let mut config = isolated_config(valid_identity());
        config.namespaces.mount = false;
        let error = validate(&config, &minimal_command())
            .expect_err("isolated identity without mount namespace");
        assert!(
            matches!(
                error,
                SandboxError::InvalidPolicy {
                    field: "identity",
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn isolated_identity_rejects_retained_capabilities() {
        let mut config = isolated_config(valid_identity());
        config.capabilities = CapabilityPolicy::Retain(vec![
            Capability::from_number(1).expect("capability 1 (CAP_CHOWN) exists"),
        ]);
        let error = validate(&config, &minimal_command())
            .expect_err("isolated identity with retained capabilities");
        assert!(
            matches!(
                error,
                SandboxError::InvalidPolicy {
                    field: "identity",
                    ..
                }
            ),
            "{error}"
        );
        // An empty retain list is identical to dropping everything.
        config.capabilities = CapabilityPolicy::Retain(Vec::new());
        assert!(validate(&config, &minimal_command()).is_ok());
    }

    #[test]
    fn relative_program_is_rejected() {
        let error = validate(&SandboxConfig::unrestricted(), &CommandSpec::new("sh"))
            .expect_err("relative program");
        assert!(matches!(
            error,
            SandboxError::InvalidPolicy {
                field: "program",
                ..
            }
        ));
    }

    #[test]
    fn nul_in_argument_is_rejected() {
        use std::ffi::OsStr;
        let mut command = minimal_command();
        command
            .args
            .push(OsStr::from_bytes(b"bad\0arg").to_os_string());
        let error = validate(&SandboxConfig::unrestricted(), &command).expect_err("nul arg");
        assert!(matches!(
            error,
            SandboxError::InvalidPolicy { field: "args", .. }
        ));
    }

    #[test]
    fn env_name_with_equals_is_rejected() {
        let mut command = minimal_command();
        command.env.push(("A=B".into(), "v".into()));
        let error = validate(&SandboxConfig::unrestricted(), &command).expect_err("env =");
        assert!(matches!(
            error,
            SandboxError::InvalidPolicy { field: "env", .. }
        ));
    }

    #[test]
    fn inherited_fds_must_be_open_and_unique() {
        let mut config = SandboxConfig::unrestricted();
        config.inherited_fds.push(0);
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "inherited_fds",
                ..
            })
        ));

        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        let mut config = SandboxConfig::unrestricted();
        config.inherited_fds.push(file.as_raw_fd());
        config.inherited_fds.push(file.as_raw_fd());
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "inherited_fds",
                ..
            })
        ));

        let mut config = SandboxConfig::unrestricted();
        config.inherited_fds.push(909);
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "inherited_fds",
                ..
            })
        ));

        let mut config = SandboxConfig::unrestricted();
        config.inherited_fds.push(file.as_raw_fd());
        assert!(validate(&config, &minimal_command()).is_ok());
    }

    #[test]
    fn cpu_quota_bounds_are_enforced() {
        let mut config = SandboxConfig::unrestricted();
        config.resources.cpu_max = Limit::Value(CpuMax {
            quota_us: 0,
            period_us: 100_000,
        });
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "resources.cpu_max",
                ..
            })
        ));
        config.resources.cpu_max = Limit::Value(CpuMax {
            quota_us: 1_000,
            period_us: 100,
        });
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "resources.cpu_max",
                ..
            })
        ));
        config.resources.cpu_max = Limit::Value(CpuMax {
            quota_us: 1_000,
            period_us: 100_000,
        });
        assert!(validate(&config, &minimal_command()).is_ok());
    }

    #[test]
    fn identical_seccomp_actions_are_rejected() {
        let config = SandboxConfig {
            syscalls: SyscallPolicy::Filter {
                default_action: SeccompAction::Allow,
                matched_action: SeccompAction::Allow,
                rules: Vec::new(),
            },
            ..SandboxConfig::unrestricted()
        };
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "syscalls",
                ..
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_syscall_name_is_rejected() {
        let config = SandboxConfig {
            syscalls: SyscallPolicy::Filter {
                default_action: SeccompAction::Errno(libc::EPERM as u32),
                matched_action: SeccompAction::Allow,
                rules: vec![SyscallRule {
                    syscall: Syscall::Named("definitely_not_a_syscall"),
                    conditions: Vec::new(),
                }],
            },
            ..SandboxConfig::unrestricted()
        };
        assert!(matches!(
            validate(&config, &minimal_command()),
            Err(SandboxError::InvalidPolicy {
                field: "syscalls.rules",
                ..
            })
        ));
    }

    #[test]
    fn program_outside_all_grants_is_rejected() {
        let granted = tempfile::tempdir().expect("granted");
        let outside = tempfile::tempdir().expect("outside");
        let program = outside.path().join("tool");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("program");
        let config = SandboxConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: vec![PathRule::new(granted.path())],
                read_write: Vec::new(),
                execute: Vec::new(),
            },
            ..SandboxConfig::unrestricted()
        };
        let error = validate(&config, &CommandSpec::new(&program)).expect_err("uncovered program");
        assert!(
            matches!(
                error,
                SandboxError::InvalidPolicy {
                    field: "filesystem",
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn program_under_read_only_grant_is_rejected() {
        // The read tier grants no execute right, so a program covered only
        // by a read grant is a statically contradictory policy.
        let granted = tempfile::tempdir().expect("granted");
        let program = granted.path().join("tool");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("program");
        let config = SandboxConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: vec![PathRule::new(granted.path())],
                read_write: Vec::new(),
                execute: Vec::new(),
            },
            ..SandboxConfig::unrestricted()
        };
        let error = validate(&config, &CommandSpec::new(&program)).expect_err("uncovered program");
        assert!(
            matches!(
                error,
                SandboxError::InvalidPolicy {
                    field: "filesystem",
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn program_under_execute_grant_passes() {
        let granted = tempfile::tempdir().expect("granted");
        let program = granted.path().join("tool");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("program");
        let config = SandboxConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: Vec::new(),
                read_write: Vec::new(),
                execute: vec![PathRule::new(granted.path())],
            },
            ..SandboxConfig::unrestricted()
        };
        assert!(validate(&config, &CommandSpec::new(&program)).is_ok());
    }

    #[test]
    fn program_under_read_write_grant_passes() {
        let root = tempfile::tempdir().expect("root");
        let program = root.path().join("tool");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("program");
        let config = SandboxConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: Vec::new(),
                read_write: vec![PathRule::new(root.path())],
                execute: Vec::new(),
            },
            ..SandboxConfig::unrestricted()
        };
        assert!(validate(&config, &CommandSpec::new(&program)).is_ok());
    }

    #[test]
    fn cwd_outside_all_grants_is_rejected() {
        let mut command = minimal_command();
        command.cwd = Some(std::env::temp_dir());
        let config = SandboxConfig {
            filesystem: FilesystemPolicy::Restricted {
                read_only: vec![PathRule::new("/usr")],
                read_write: vec![PathRule::new("/bin")],
                execute: Vec::new(),
            },
            ..SandboxConfig::unrestricted()
        };
        let error = validate(&config, &command).expect_err("uncovered cwd");
        assert!(
            matches!(
                error,
                SandboxError::InvalidPolicy {
                    field: "filesystem.read_only",
                    ..
                }
            ),
            "{error}"
        );
    }
}
