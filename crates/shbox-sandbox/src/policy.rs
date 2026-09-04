//! Sandbox policy model.
//!
//! Every policy in this module is *explicit caller state*. The crate ships no
//! preset security levels (`Developer` / `Untrusted` / `Strict` / ...): the
//! strength of a sandbox is decided by the code that constructs these values,
//! which is expected to compose them from its own administrator/user/session
//! configuration before calling [`crate::Sandbox::spawn`].
//!
//! The crate itself only guarantees process-safety invariants that no policy
//! can weaken: `PR_SET_NO_NEW_PRIVS`, capability dropping before `exec`,
//! file-descriptor hygiene, and fail-closed setup (see the crate root docs).
//!
//! `Unlimited` / `Inherit` / explicit-value semantics are never conflated:
//! resource limits use [`Limit`], and access policies use enums whose
//! unrestricted variant must be chosen explicitly by the caller.

use std::fmt;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

/// A tri-state limit value.
///
/// * [`Limit::Inherit`] — preserve the parent's existing limit. The sandbox
///   does not set an rlimit or request a cgroup controller for this field.
/// * [`Limit::Unlimited`] — request no additional sandbox-local ceiling. On
///   Linux cgroup v2 this writes the controller's `max` token, but ancestor
///   cgroup limits still apply. On macOS an expressible rlimit requests
///   `RLIM_INFINITY`, which cannot raise a hard limit the process is not
///   permitted to raise.
/// * [`Limit::Value`] — apply an explicit restriction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Limit<T> {
    /// The default: keep whatever the parent provides.
    #[default]
    Inherit,
    /// Request the backend's local maximum without claiming to lift an
    /// ancestor/inherited hard ceiling.
    Unlimited,
    /// An explicit restriction value.
    Value(T),
}

impl<T> Limit<T> {
    /// Whether this field asks the Linux backend to create a dedicated
    /// cgroup controller for it. macOS has no cgroup backend and resolves its
    /// supported fields with `setrlimit` instead.
    pub fn requires_own_cgroup(&self) -> bool {
        !matches!(self, Limit::Inherit)
    }
}

impl<T: fmt::Display> fmt::Display for Limit<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Limit::Inherit => f.write_str("inherit"),
            Limit::Unlimited => f.write_str("unlimited"),
            Limit::Value(value) => write!(f, "value({value})"),
        }
    }
}

/// Filesystem access policy.
///
/// `Unrestricted` is an explicit opt-out of filesystem confinement; with
/// `Restricted`, nothing is accessible unless a rule grants it. There is
/// deliberately no `Default`: an unconfined sandbox must be written out,
/// never arrived at implicitly.
///
/// Rule tiers express caller intent. Both Seatbelt and Landlock preserve the
/// distinction between read-only data and executable runtime paths:
///
/// * `read_only`  — read files and list directories, but do not execute
/// * `read_write` — read, write, and execute using the ABI's full write set
/// * `execute`    — read and execute, but do not write
///
/// Granting is per *absolute* path; directories grant their whole subtree.
/// The backend resolves each rule to an open file descriptor before the
/// child exists, so rules are pinned to the opened object rather than to a
/// re-resolvable path name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemPolicy {
    /// No filesystem confinement is installed. The caller explicitly opts
    /// out; the crate never selects this implicitly.
    Unrestricted,
    /// Deny-by-default filesystem access with explicit grants.
    Restricted {
        /// Paths readable and listable, but not writable or executable.
        read_only: Vec<PathRule>,
        /// Paths readable, writable, and executable.
        read_write: Vec<PathRule>,
        /// Paths readable and executable, but not writable.
        execute: Vec<PathRule>,
    },
}

/// A single filesystem grant: an absolute path whose subtree receives the
/// tier's access rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// Absolute path whose subtree the rule covers.
    pub path: PathBuf,
}

impl PathRule {
    /// Build a rule for `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        PathRule { path: path.into() }
    }
}

/// An operator-provided cgroup directory to create sandbox cgroups under
/// (Linux only). Validated (writable cgroup v2 directory) at spawn time;
/// meaningless and ignored on the other backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupParent(PathBuf);

impl CgroupParent {
    /// Wrap an absolute cgroup v2 directory path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        CgroupParent(path.into())
    }

    /// The configured cgroup directory path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Network access policy.
///
/// This policy describes *access control within whatever network namespace
/// the sandbox runs in*; joining or isolating a network namespace is
/// [`NetworkNamespacePolicy`], a separate concept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No network restriction is installed.
    Unrestricted,
    /// Outbound TCP clients are allowed; listening sockets and other
    /// directions are denied.
    ///
    /// Linux implements this tier with Landlock TCP rules, which restrict
    /// `bind`/`connect` only. On Linux this variant is
    /// [unsupported](crate::SandboxError) because Landlock cannot express
    /// "connect to any port" without enumerating ports; callers that only
    /// need host-shared unrestricted networking should use [`Self::Unrestricted`].
    OutboundTcp,
    /// All Landlock-mediated networking (TCP bind/connect) is denied.
    #[default]
    Disabled,
}

/// Which network namespace the sandboxed process runs in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkNamespacePolicy {
    /// Share the host (or daemon) network namespace.
    #[default]
    Host,
    /// Run in a fresh, isolated network namespace (loopback only, and even
    /// loopback is down unless the sandboxed program brings it up).
    Isolated,
}

/// Per-launch process identity: *who the sandboxed process is* on the host,
/// independent of namespace topology ([`NamespacePolicy`]).
///
/// The engine offers only **fresh** user-namespace creation. Joining an
/// existing user namespace is deliberately absent: `setns()` into a user
/// namespace requires `CAP_SYS_ADMIN` in the target namespace, which an
/// unprivileged launcher does not hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IdentityPolicy {
    /// No user namespace: the process keeps the launcher's identity for its
    /// whole lifetime. This is **not** identity isolation.
    #[default]
    Host,
    /// Legacy engine behavior: create a user namespace and map namespace
    /// root (UID/GID 0) to the caller's effective UID/GID (the
    /// `unshare --map-root-user` model). Kept for compatibility and for
    /// namespace-topology use cases during the identity-isolation migration.
    /// The host-visible identity is still the launcher's, so this is also
    /// **not** identity isolation.
    CallerMappedRoot,
    /// Create a fresh user namespace for this launch. The child blocks at a
    /// parent mapping barrier; a parent-side mapper installs exactly the
    /// supplied delegated UID/GID entries before child setup continues.
    ///
    /// Requires a fresh mount namespace (`NamespacePolicy::mount`) so the
    /// writable views can be replaced with ID-mapped mounts, and rejects any
    /// retained capability: the runtime process must end with empty
    /// effective/permitted/inheritable/ambient sets.
    Isolated(IsolatedIdentity),
}

/// Numeric identity translation for [`IdentityPolicy::Isolated`].
///
/// Installed as exactly one `uid_map` and one `gid_map` entry
/// (`runtime <host> 1`). Namespace UID/GID 0 stay deliberately unmapped so
/// no bootstrap identity exists to regain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolatedIdentity {
    /// Namespace-visible runtime UID (1000 in shbox v1). Must be non-zero.
    pub runtime_uid: u32,
    /// Namespace-visible runtime GID (1000 in shbox v1). Must be non-zero.
    pub runtime_gid: u32,
    /// Host-side leased subordinate UID. Must be non-zero and must never be
    /// the daemon's own UID; validated against the launcher's live
    /// credentials at spawn time on Linux.
    pub host_uid: u32,
    /// Host-side leased subordinate GID. Must be non-zero and must never be
    /// the daemon's own GID.
    pub host_gid: u32,
}

/// Linux namespace topology selection. Combinations are the caller's choice;
/// the crate fixes no preset bundle. This says *which namespaces exist*, not
/// *who the process inside them is* — see [`IdentityPolicy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespacePolicy {
    /// Create a new PID namespace. The backend keeps an internal init/reaper
    /// as namespace PID 1 and runs the sandboxed program as its PID 2 child.
    pub pid: bool,
    /// Create a new mount namespace with recursive-private propagation so
    /// the sandbox's mounts cannot propagate back to the host.
    pub mount: bool,
    /// Create a new IPC namespace (System V IPC, POSIX IPC naming).
    pub ipc: bool,
    /// Create a new UTS namespace (hostname/domainname).
    pub uts: bool,
    /// Network namespace selection.
    pub network: NetworkNamespacePolicy,
}

/// Resource limits applied per sandbox.
///
/// Every field is independent and tri-state. A direct
/// [`Sandbox::spawn`](crate::Sandbox::spawn) requires a writable cgroup v2
/// hierarchy only when a field contributes a limit and uses a one-shot cgroup
/// whose lifetime follows that child. A [`ProcessDomain`](crate::ProcessDomain)
/// always owns a cgroup, including when every field is [`Limit::Inherit`], so
/// callers can enforce aggregate process ownership across multiple launches.
/// Linux children are created in their domain via `clone3(CLONE_INTO_CGROUP)`;
/// with a PID namespace, the internal PID 1 supervisor creates user PID 2 in
/// the same domain atomically. On macOS, `memory_bytes` maps to `RLIMIT_AS`
/// and `pids` maps to `RLIMIT_NPROC`; `swap_bytes` and `cpu_max` are
/// unsupported and fail closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Linux `memory.max`; macOS `RLIMIT_AS`: hard address-space ceiling in
    /// bytes.
    pub memory_bytes: Limit<u64>,
    /// Linux `memory.swap.max`: swap ceiling in bytes. Unsupported on macOS.
    pub swap_bytes: Limit<u64>,
    /// Linux `pids.max`; macOS `RLIMIT_NPROC`: maximum process count.
    pub pids: Limit<u32>,
    /// Linux `cpu.max`: CPU bandwidth quota per period. Unsupported on macOS.
    pub cpu_max: Limit<CpuMax>,
}

/// A cgroup v2 `cpu.max` quota: `quota_us` microseconds of CPU time per
/// `period_us` microseconds of wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    /// CPU-time budget per period, in microseconds. Must be non-zero.
    pub quota_us: u64,
    /// Period length in microseconds. The kernel accepts 1000..=1_000_000.
    pub period_us: u64,
}

impl ResourceLimits {
    /// Whether a direct spawn needs a dedicated resource cgroup.
    ///
    /// The public Linux process-domain adapter creates a cgroup regardless of
    /// this query; it is retained for direct one-shot engine spawns. The
    /// macOS backend does not use this query: its supported fields are applied
    /// with `setrlimit`.
    pub fn requires_cgroup(&self) -> bool {
        self.memory_bytes.requires_own_cgroup()
            || self.swap_bytes.requires_own_cgroup()
            || self.pids.requires_own_cgroup()
            || self.cpu_max.requires_own_cgroup()
    }
}

/// seccomp-BPF syscall policy.
///
/// The crate compiles exactly what the caller specifies: it provides no
/// "strict"/"development" profiles and no hidden syscall additions. A filter
/// is a default action plus per-syscall rules; the action applied when a
/// rule matches is uniform for the whole filter (the underlying BPF model).
///
/// An *allowlist* is `default_action: Errno(..)` with rules that match
/// allowed syscalls to `matched_action: Allow`; a *denylist* inverts the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallPolicy {
    /// Install no filter at all.
    Unrestricted,
    /// Install a filter with explicit default/matched actions and rules.
    Filter {
        /// Action for syscalls that match no rule ("mismatch" action).
        default_action: SeccompAction,
        /// Action for syscalls whose rule conditions match.
        matched_action: SeccompAction,
        /// Per-syscall rules; multiple rules for one syscall are OR-ed.
        rules: Vec<SyscallRule>,
    },
}

/// One syscall rule: the syscall plus optional argument conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallRule {
    /// Which syscall the rule applies to.
    pub syscall: Syscall,
    /// Argument conditions (AND-ed). Empty matches any invocation.
    pub conditions: Vec<SyscallCondition>,
}

/// A syscall identified by name or number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// Kernel syscall name (e.g. `"openat"`). Resolved to the current
    /// architecture's number; an unknown name is a policy error.
    Named(&'static str),
    /// Raw syscall number for the target architecture.
    Number(i64),
}

/// A seccomp argument condition: `op(value)` on argument `arg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallCondition {
    /// Argument index, 0..=5.
    pub arg: u8,
    /// Comparison width.
    pub len: ArgLen,
    /// Comparison operation.
    pub op: CmpOp,
    /// Value compared against.
    pub value: u64,
}

/// Comparison width for [`SyscallCondition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgLen {
    /// Compare the low 32 bits.
    Dword,
    /// Compare all 64 bits.
    Qword,
}

/// Comparison operation for [`SyscallCondition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    /// Argument equals `value`.
    Equal,
    /// Argument is greater than `value`.
    Greater,
    /// Argument is greater than or equal to `value`.
    GreaterEqual,
    /// Argument is less than `value`.
    Less,
    /// Argument is less than or equal to `value`.
    LessEqual,
    /// Masked-equality: `(arg & value) == value`.
    MaskedEqual,
    /// Argument is not equal to `value`.
    NotEqual,
}

/// seccomp filter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Permit the syscall.
    Allow,
    /// Fail the syscall with `errno` set to the given error number.
    Errno(u32),
    /// Kill the calling thread (`SECCOMP_RET_KILL_THREAD`).
    KillThread,
    /// Kill the calling process (`SECCOMP_RET_KILL_PROCESS`).
    KillProcess,
    /// Permit the syscall after logging it.
    Log,
    /// `SECCOMP_RET_TRACE`: notify a tracing process with the given value.
    Trace(u32),
    /// Send `SIGSYS` to the calling process.
    Trap,
}

/// Linux capability retention policy.
///
/// The crate always drops every capability before `exec` unless the caller
/// explicitly lists retained ones. Capabilities used for namespace or mount
/// setup never leak into the sandboxed program.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CapabilityPolicy {
    /// Drop all capabilities from effective, permitted, inheritable, and
    /// ambient sets. The bounding set is also narrowed when the launching
    /// thread has `CAP_SETPCAP`; otherwise `PR_SET_NO_NEW_PRIVS` prevents
    /// later `execve` from gaining capabilities from privilege-bearing files.
    #[default]
    DropAll,
    /// Keep the listed capabilities in effective, permitted, inheritable,
    /// and ambient sets. When `CAP_SETPCAP` is available, the bounding set is
    /// narrowed to the same list; otherwise the inherited bounding set is
    /// left unchanged under `PR_SET_NO_NEW_PRIVS`.
    Retain(Vec<Capability>),
}

/// A Linux capability.
///
/// Values follow `include/uapi/linux/capability.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(u8);

impl Capability {
    /// Construct from a raw capability number (0..=40).
    pub const fn from_number(number: u8) -> Option<Self> {
        if number <= CAP_LAST_NUMBER {
            Some(Capability(number))
        } else {
            None
        }
    }

    /// The raw capability number.
    pub const fn number(self) -> u8 {
        self.0
    }
}

/// Highest defined Linux capability number at the time of writing
/// (`CAP_CHECKPOINT_RESTORE`).
pub const CAP_LAST_NUMBER: u8 = 40;

macro_rules! capabilities {
    ($($(#[$doc:meta])* $name:ident = $value:expr),* $(,)?) => {
        impl Capability {
            $(
                $(#[$doc])*
                pub const $name: Capability = Capability($value);
            )*
        }
    };
}

capabilities! {
    /// `CAP_CHOWN`: change file ownership.
    CAP_CHOWN = 0,
    /// `CAP_DAC_OVERRIDE`: bypass file permission checks.
    CAP_DAC_OVERRIDE = 1,
    /// `CAP_DAC_READ_SEARCH`: bypass file read/search checks.
    CAP_DAC_READ_SEARCH = 2,
    /// `CAP_FOWNER`: bypass ownership checks.
    CAP_FOWNER = 3,
    /// `CAP_FSETID`: set setuid/setgid bits.
    CAP_FSETID = 4,
    /// `CAP_KILL`: signal arbitrary processes.
    CAP_KILL = 5,
    /// `CAP_SETGID`: set GIDs / drop supplementary groups.
    CAP_SETGID = 6,
    /// `CAP_SETUID`: set UIDs.
    CAP_SETUID = 7,
    /// `CAP_SETPCAP`: transfer capabilities.
    CAP_SETPCAP = 8,
    /// `CAP_LINUX_IMMUTABLE`: inode flags.
    CAP_LINUX_IMMUTABLE = 9,
    /// `CAP_NET_BIND_SERVICE`: bind ports below 1024.
    CAP_NET_BIND_SERVICE = 10,
    /// `CAP_NET_BROADCAST`: broadcast / listen multicast.
    CAP_NET_BROADCAST = 11,
    /// `CAP_NET_ADMIN`: interface/routing administration.
    CAP_NET_ADMIN = 12,
    /// `CAP_NET_RAW`: raw sockets.
    CAP_NET_RAW = 13,
    /// `CAP_IPC_LOCK`: lock memory.
    CAP_IPC_LOCK = 14,
    /// `CAP_IPC_OWNER`: bypass IPC checks.
    CAP_IPC_OWNER = 15,
    /// `CAP_SYS_MODULE`: load/unload kernel modules.
    CAP_SYS_MODULE = 16,
    /// `CAP_SYS_RAWIO`: raw I/O (`/dev/mem`, …).
    CAP_SYS_RAWIO = 17,
    /// `CAP_SYS_CHROOT`: `chroot`.
    CAP_SYS_CHROOT = 18,
    /// `CAP_SYS_PTRACE`: `ptrace`.
    CAP_SYS_PTRACE = 19,
    /// `CAP_SYS_PACCT`: process accounting.
    CAP_SYS_PACCT = 20,
    /// `CAP_SYS_ADMIN`: broad administration (mounts, namespaces, …).
    CAP_SYS_ADMIN = 21,
    /// `CAP_SYS_BOOT`: reboot.
    CAP_SYS_BOOT = 22,
    /// `CAP_SYS_NICE`: scheduling tweaks.
    CAP_SYS_NICE = 23,
    /// `CAP_SYS_RESOURCE`: raise resource limits.
    CAP_SYS_RESOURCE = 24,
    /// `CAP_SYS_TIME`: set system clock.
    CAP_SYS_TIME = 25,
    /// `CAP_SYS_TTY_CONFIG`: `vhangup` and tty config.
    CAP_SYS_TTY_CONFIG = 26,
    /// `CAP_MKNOD`: create device nodes.
    CAP_MKNOD = 27,
    /// `CAP_LEASE`: file leases.
    CAP_LEASE = 28,
    /// `CAP_AUDIT_WRITE`: write audit records.
    CAP_AUDIT_WRITE = 29,
    /// `CAP_AUDIT_CONTROL`: audit configuration.
    CAP_AUDIT_CONTROL = 30,
    /// `CAP_SETFCAP`: set file capabilities.
    CAP_SETFCAP = 31,
    /// `CAP_MAC_OVERRIDE`: override MAC policy.
    CAP_MAC_OVERRIDE = 32,
    /// `CAP_MAC_ADMIN`: MAC policy administration.
    CAP_MAC_ADMIN = 33,
    /// `CAP_SYSLOG`: `syslog`.
    CAP_SYSLOG = 34,
    /// `CAP_WAKE_ALARM`: trigger wake alarms.
    CAP_WAKE_ALARM = 35,
    /// `CAP_BLOCK_SUSPEND`: block suspend.
    CAP_BLOCK_SUSPEND = 36,
    /// `CAP_AUDIT_READ`: read audit records.
    CAP_AUDIT_READ = 37,
    /// `CAP_PERFMON`: performance monitoring.
    CAP_PERFMON = 38,
    /// `CAP_BPF`: privileged BPF.
    CAP_BPF = 39,
    /// `CAP_CHECKPOINT_RESTORE`: checkpoint/restore.
    CAP_CHECKPOINT_RESTORE = 40,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capability-{}", self.0)
    }
}

/// The complete sandbox configuration for one spawn.
///
/// Every field is explicit: there is no implicit merge with daemon globals,
/// and no `Default` — the fail-open policies (filesystem, syscalls) must be
/// written out or chosen through [`SandboxConfig::unrestricted`]. Callers
/// resolve their own administrator/user/session layers into this struct
/// before spawning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Filesystem confinement.
    pub filesystem: FilesystemPolicy,
    /// Network access within the sandbox's network namespace.
    pub network: NetworkPolicy,
    /// Resource limits (cgroup v2 on Linux; expressible rlimits on macOS).
    pub resources: ResourceLimits,
    /// Syscall filtering.
    pub syscalls: SyscallPolicy,
    /// Namespace topology selection.
    pub namespaces: NamespacePolicy,
    /// Process identity (user-namespace creation and UID/GID translation).
    pub identity: IdentityPolicy,
    /// Capability retention.
    pub capabilities: CapabilityPolicy,
    /// File descriptors (by number, `>= 3`) that survive the child-side
    /// close-everything hygiene step. They keep their exact numbers.
    pub inherited_fds: Vec<RawFd>,
    /// Overrides cgroup v2 auto-discovery with an explicit cgroup directory
    /// to create sandbox cgroups under (already delegated/writable).
    /// Ignored when no resource limit requires a cgroup. Linux only.
    pub cgroup_parent: Option<PathBuf>,
}

impl SandboxConfig {
    /// A configuration with every policy set to its unrestricted default and
    /// no cgroup usage. The process-safety invariants (no-new-privs,
    /// capability drop, FD hygiene) still apply.
    pub fn unrestricted() -> Self {
        SandboxConfig {
            filesystem: FilesystemPolicy::Unrestricted,
            network: NetworkPolicy::Unrestricted,
            resources: ResourceLimits::default(),
            syscalls: SyscallPolicy::Unrestricted,
            namespaces: NamespacePolicy::default(),
            identity: IdentityPolicy::default(),
            capabilities: CapabilityPolicy::default(),
            inherited_fds: Vec::new(),
            cgroup_parent: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkPolicy, SandboxConfig};

    #[test]
    fn unrestricted_config_leaves_network_unrestricted() {
        assert_eq!(
            SandboxConfig::unrestricted().network,
            NetworkPolicy::Unrestricted
        );
    }
}
