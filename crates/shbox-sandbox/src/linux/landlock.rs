//! Landlock ruleset preparation (architecture Phase 6).
//!
//! Everything that can allocate — ruleset creation, path descriptors, rule
//! installation — happens in the parent. The child only enforces the
//! prepared ruleset with `landlock_restrict_self` (two raw syscalls).
//!
//! Access tiers map to Landlock rights as:
//!
//! * `read_only`  → `READ_FILE | READ_DIR`
//! * `read_write` → `READ_FILE | READ_DIR | EXECUTE` + the ABI's full
//!   write set
//! * `execute`    → `READ_FILE | READ_DIR | EXECUTE`
//!
//! Compatibility is fail-closed: handled access sets are derived from the
//! *probed* ABI and installed with `HardRequirement`, so a kernel that
//! cannot provide a requested right produces an error — never a silently
//! weaker ruleset. A kernel without Landlock at all is an explicit
//! [`SandboxError::Unsupported`], never a silent pass-through. Rights that a
//! given ABI simply does not model (e.g. `TRUNCATE` before ABI 3) are
//! omitted from the handled set, which is strictly more restrictive, never
//! less.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use landlock::{
    ABI, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr,
};

use crate::error::SandboxError;
use crate::policy::{FilesystemPolicy, NetworkPolicy};

/// A fully built ruleset awaiting child-side enforcement.
pub struct PreparedLandlock {
    ruleset_fd: OwnedFd,
}

impl PreparedLandlock {
    /// Enforce the ruleset on the calling thread. Runs in the child.
    ///
    /// Returns the raw errno on failure without constructing any error
    /// value: after `clone3` the child must not allocate.
    pub fn restrict_self_raw(&self) -> Result<(), i32> {
        // SAFETY: the ruleset fd was fully constructed in the parent and
        // remains open in this child until fd hygiene closes it before exec.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.ruleset_fd.as_raw_fd(),
                0_u32,
            )
        } == -1
        {
            Err(super::raw_errno())
        } else {
            Ok(())
        }
    }
}

/// Probe the running kernel's Landlock ABI version.
pub fn probe_abi() -> Option<u32> {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: the VERSION probe takes no pointers.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version < 0 {
        None
    } else {
        Some(version as u32)
    }
}

/// Build the ruleset for the requested filesystem and network policy.
///
/// Returns `Ok(None)` when both policies are unrestricted and nothing needs
/// to be enforced.
pub fn prepare(
    filesystem: &FilesystemPolicy,
    network: NetworkPolicy,
    abi_version: u32,
) -> Result<Option<PreparedLandlock>, SandboxError> {
    if matches!(filesystem, FilesystemPolicy::Unrestricted)
        && network == NetworkPolicy::Unrestricted
    {
        return Ok(None);
    }
    if abi_version == 0 {
        return Err(SandboxError::unsupported(
            "landlock",
            "the kernel does not support Landlock; a restricted filesystem or \
             network policy cannot be enforced",
        ));
    }
    let abi = ABI::from(abi_version as i32);

    if network != NetworkPolicy::Unrestricted {
        // Landlock network control needs ABI 4 (kernel 6.7). Restricting
        // networking on older kernels is the caller's job (e.g. via a
        // seccomp policy), not a silent downgrade here.
        if abi_version < 4 {
            return Err(SandboxError::unsupported(
                "landlock-network",
                "network restriction requires Landlock ABI 4 (kernel 6.7) or newer; \
                 express the restriction with a seccomp SyscallPolicy instead",
            ));
        }
        if network == NetworkPolicy::OutboundTcp {
            return Err(SandboxError::unsupported(
                "landlock-network",
                "outbound-only TCP cannot be expressed: Landlock network rules enumerate \
                 ports and cannot allow connect-to-any-port",
            ));
        }
    }

    let read_set = AccessFs::ReadFile | AccessFs::ReadDir;
    let write_set = AccessFs::from_write(abi);
    let execute_set = read_set | AccessFs::Execute;
    let read_write_set = execute_set | write_set;

    let FilesystemPolicy::Restricted {
        read_only,
        read_write,
        execute,
    } = filesystem
    else {
        // Network-only restriction: a ruleset handling network access with
        // no rules denies every Landlock-mediated network operation.
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(map_ruleset_error)?
            .create()
            .map_err(map_ruleset_error)?;
        return prepared_ruleset(ruleset).map(Some);
    };

    // Restricted is deny-by-default. Always handle every filesystem right
    // supported by the probed ABI; path rules below are the only grants.
    let handled_fs: BitFlags<AccessFs> = AccessFs::from_read(abi) | AccessFs::from_write(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs)
        .map_err(map_ruleset_error)?;
    if network != NetworkPolicy::Unrestricted {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(map_ruleset_error)?;
    }

    let ruleset = ruleset.create().map_err(map_ruleset_error)?;

    // Rules are built eagerly so an unopenable path is an error in the
    // parent, not a silently skipped grant. add_rules consumes Results.
    let mut rules: Vec<Result<PathBeneath<PathFd>, SandboxError>> = Vec::new();
    for (tier_rules, access) in [
        (read_only, read_set),
        (read_write, read_write_set),
        (execute, execute_set),
    ] {
        for rule in tier_rules {
            rules.push(Ok(path_rule(&rule.path, access)?));
        }
    }
    let ruleset = ruleset
        .add_rules(rules)
        .map_err(|error: SandboxError| error)?;
    prepared_ruleset(ruleset).map(Some)
}

fn prepared_ruleset(ruleset: RulesetCreated) -> Result<PreparedLandlock, SandboxError> {
    let ruleset_fd: Option<OwnedFd> = ruleset.into();
    let ruleset_fd = ruleset_fd.ok_or_else(|| {
        SandboxError::unsupported(
            "landlock",
            "a required Landlock ruleset was not materialized by the kernel",
        )
    })?;
    Ok(PreparedLandlock { ruleset_fd })
}

/// Build one path rule, narrowing the access mask to file-only rights when
/// the path resolves to a non-directory (the kernel rejects directory
/// access rights on non-directory descriptors).
fn path_rule(
    path: &std::path::Path,
    access: BitFlags<AccessFs>,
) -> Result<PathBeneath<PathFd>, SandboxError> {
    let fd = PathFd::new(path).map_err(|error| {
        SandboxError::invalid(
            "filesystem",
            format!(
                "rule path {} cannot be opened for Landlock: {}",
                path.display(),
                io::Error::other(error.to_string())
            ),
        )
    })?;
    // Decide dir-vs-file from the descriptor the rule actually pins, not a
    // second lookup by name that can race with a swap. A failed fstat keeps
    // the narrower file-only mask, which fails closed.
    let is_dir = fd_is_dir(&fd).unwrap_or(false);
    let effective = if is_dir {
        access
    } else {
        // Rights legitimate for non-directory files, computed at the newest
        // ABI so only genuinely directory-only rights are removed.
        access & AccessFs::from_file(ABI::V9)
    };
    Ok(PathBeneath::new(fd, effective))
}

/// fstat on the opened rule descriptor. Mirrors the check the landlock
/// crate itself runs on rule descriptors.
fn fd_is_dir(fd: &PathFd) -> Option<bool> {
    // SAFETY: `stat` is a C struct of integers and fixed-size arrays —
    // all-zero is a valid value, and fstat only writes to it.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open descriptor owned by the rule being built.
    if unsafe { libc::fstat(fd.as_fd().as_raw_fd(), &mut stat) } == -1 {
        return None;
    }
    Some((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

fn map_ruleset_error(error: impl std::error::Error) -> SandboxError {
    SandboxError::unsupported("landlock", format!("ruleset could not be built: {error}"))
}

/// Lets `add_rules` surface our error type directly.
impl From<landlock::RulesetError> for SandboxError {
    fn from(error: landlock::RulesetError) -> Self {
        map_ruleset_error(error)
    }
}
