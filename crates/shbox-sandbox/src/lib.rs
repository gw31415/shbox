//! Process sandbox primitives for Linux and macOS.
//!
//! # What this crate is
//!
//! A pure-Rust, single-binary sandbox: it composes the OS confinement
//! primitives a caller selects into one race-free spawn path with a
//! pidfd-based lifecycle. On Linux the backing mechanisms are `clone3()`,
//! Landlock, seccomp-BPF, cgroup v2 (`CLONE_INTO_CGROUP`), namespaces,
//! `PR_SET_NO_NEW_PRIVS`, capability dropping, `close_range()` FD hygiene,
//! and pidfd supervision. On macOS the same API is backed by a generated
//! Seatbelt profile.
//!
//! # Responsibility split
//!
//! **The caller decides** (via [`SandboxConfig`] and [`CommandSpec`]):
//! filesystem access, network access, resource limits, syscall
//! restrictions, namespace usage, environment, working directory, the
//! command itself, and explicitly inherited file descriptors.
//!
//! **The crate always guarantees** (no policy can weaken these):
//!
//! * `PR_SET_NO_NEW_PRIVS` before `exec` — setuid binaries cannot recover
//!   privileges inside the sandbox;
//! * every Linux capability is dropped before `exec` unless the policy
//!   explicitly retains it — namespace/setup privileges never leak;
//! * file-descriptor hygiene — apart from the standard streams and the
//!   explicitly listed `inherited_fds`, nothing the parent had open
//!   survives into the child;
//! * the user command never executes before every requested sandbox
//!   mechanism is in place, and a failure at any stage aborts the child
//!   before `exec` (fail closed);
//! * the child is tracked by pidfd on Linux (no PID-reuse confusion), and
//!   dropping the [`SandboxChild`] handle tears the sandbox down instead of
//!   leaking processes or cgroups.
//!
//! The crate deliberately ships **no security profiles**: no
//! `SandboxLevel::Developer`, no "strict" preset. How restrictive a sandbox
//! should be is policy, and policy belongs to the embedding application.
//!
//! # Security boundary
//!
//! This is a kernel-sharing process sandbox. It is a strong constraint for
//! untrusted development workloads, but it is **not** a VM-equivalent
//! boundary against actively hostile multi-tenant workloads attempting
//! kernel exploits. For that threat model, run this sandbox inside a
//! VM/microVM as additional defense-in-depth.
//!
//! # Platform status
//!
//! * **Linux** is the production isolation target.
//! * **macOS** is best-effort local-development isolation: Seatbelt's
//!   public surface is deprecated and the backend invokes the OS-provided
//!   `/usr/bin/sandbox-exec` launcher with a parent-built profile. Linux-only
//!   policy fields are rejected explicitly on macOS — they are never
//!   silently ignored.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod command;
mod error;
mod policy;
mod validate;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::io;
use std::sync::Arc;

pub use command::{CommandSpec, SessionSetup, Stdio};
pub use error::{ChildStage, ExitStatus, SandboxError};
pub use policy::{
    ArgLen, CAP_LAST_NUMBER, Capability, CapabilityPolicy, CgroupParent, CmpOp, CpuMax,
    FilesystemPolicy, Limit, NamespacePolicy, NetworkNamespacePolicy, NetworkPolicy, PathRule,
    ResourceLimits, SandboxConfig, SeccompAction, Syscall, SyscallCondition, SyscallPolicy,
    SyscallRule,
};

#[cfg(target_os = "linux")]
pub use linux::{ProcessDomain, syscall_number};

/// Which backend a [`Sandbox`] resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux production backend.
    Linux,
    /// macOS best-effort Seatbelt backend.
    MacOs,
    /// No backend exists for this OS; every spawn fails closed.
    Unsupported,
}

/// Kernel/OS facilities detected at [`Sandbox::detect`] time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapabilities {
    /// The backend platform.
    pub platform: Platform,
    /// Landlock ABI version (Linux only). `None` when Landlock is absent.
    pub landlock_abi: Option<u32>,
    /// Discovered writable cgroup v2 parent for sandbox cgroups
    /// (Linux only). `None` when no usable hierarchy exists.
    pub cgroup_v2_root: Option<std::path::PathBuf>,
    /// Whether the macOS Seatbelt launcher is present (macOS only).
    pub seatbelt_available: bool,
}

/// The backend-specific child handle; see [`SandboxChild`].
pub(crate) trait BackendChild: Send {
    /// The engine-owned direct child's PID (diagnostic only; supervision
    /// never relies on it for identity). With a Linux PID namespace this is
    /// the internal PID 1 supervisor, not the logical user process.
    fn id(&self) -> u32;

    /// Signal the logical user process. Linux PID-namespace launches route
    /// this through the internal PID 1 supervisor.
    fn signal(&self, number: i32) -> io::Result<()>;

    /// Signal the child's whole process group (session). No-op-safe when the
    /// child is not a group leader.
    fn signal_process_group(&self, number: i32) -> io::Result<()>;

    /// Reap the child, blocking until it exits. Returns its status exactly
    /// once; subsequent calls return the same status.
    fn wait(&mut self) -> io::Result<ExitStatus>;

    /// Non-blocking reap.
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;

    /// Idempotent teardown: kill descendants, reap the direct child if
    /// possible, and release process-owned resource handles. A one-shot
    /// cgroup is removed when its final handle is released; a shared
    /// [`ProcessDomain`] outlives individual children until its owner
    /// explicitly removes it.
    fn teardown(&mut self);
}

/// A spawned, supervised sandbox process.
///
/// The handle owns the child's lifecycle: dropping it without a completed
/// [`wait`](SandboxChild::wait) tears the process down rather than leaking
/// it. One-shot resource handles are released with the process; durable
/// shared resource domains are released separately by their owner. Cleanup
/// is idempotent.
pub struct SandboxChild {
    child: Option<Box<dyn BackendChild>>,
    stdin: Option<std::fs::File>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
}

impl SandboxChild {
    /// The engine-owned direct child's PID, or `None` once the child has
    /// been reaped. Identity for supervision purposes is the internal pidfd
    /// on Linux; this value is diagnostic. With a Linux PID namespace it
    /// identifies the internal PID 1 supervisor.
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(|child| child.id())
    }

    /// Take the parent's stdin pipe writer, if `Stdio::Pipe` was requested.
    pub fn take_stdin(&mut self) -> Option<std::fs::File> {
        self.stdin.take()
    }

    /// Take the parent's stdout pipe reader, if `Stdio::Pipe` was requested.
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.stdout.take()
    }

    /// Take the parent's stderr pipe reader, if `Stdio::Pipe` was requested.
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.stderr.take()
    }

    /// Signal the logical user process.
    pub fn signal(&self, number: i32) -> io::Result<()> {
        self.child
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "child already reaped"))?
            .signal(number)
    }

    /// Signal the child's whole process group (its session, when spawned
    /// with [`SessionSetup::NewSession`]).
    pub fn signal_process_group(&self, number: i32) -> io::Result<()> {
        self.child
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "child already reaped"))?
            .signal_process_group(number)
    }

    /// Reap the child and finish its cleanup. Blocking.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "child already reaped"))?;
        let status = child.wait()?;
        child.teardown();
        Ok(status)
    }

    /// Non-blocking reap; `None` when the child still runs.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "child already reaped"))?;
        let status = child.try_wait()?;
        if status.is_some() {
            child.teardown();
        }
        Ok(status)
    }
}

impl Drop for SandboxChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            child.teardown();
        }
    }
}

impl std::fmt::Debug for SandboxChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxChild")
            .field("pid", &self.id())
            .field("has_stdin", &self.stdin.is_some())
            .field("has_stdout", &self.stdout.is_some())
            .field("has_stderr", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

impl SandboxChild {
    pub(crate) fn new(
        child: Box<dyn BackendChild>,
        stdin: Option<std::fs::File>,
        stdout: Option<std::fs::File>,
        stderr: Option<std::fs::File>,
    ) -> Self {
        SandboxChild {
            child: Some(child),
            stdin,
            stdout,
            stderr,
        }
    }
}

#[derive(Clone)]
enum Backend {
    #[cfg(target_os = "linux")]
    Linux(Arc<linux::LinuxBackend>),
    #[cfg(target_os = "macos")]
    MacOs(Arc<macos::MacosBackend>),
    #[allow(dead_code)]
    Unsupported,
}

/// A detected, immutable sandbox backend.
///
/// `detect()` probes the platform once (Landlock ABI, cgroup v2 hierarchy,
/// Seatbelt availability) and the resulting [`Sandbox`] is cheap to clone
/// and safe to share across threads.
#[derive(Clone)]
pub struct Sandbox {
    backend: Backend,
    capabilities: Arc<SandboxCapabilities>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl Sandbox {
    /// Probe the platform and construct the backend.
    ///
    /// Detection never fails for a supported OS: absence of specific
    /// facilities is recorded in [`capabilities`](Self::capabilities) and
    /// surfaces later as [`SandboxError::Unsupported`] when a spawn actually
    /// needs the missing primitive (fail closed, never silent fail-open).
    pub fn detect() -> Sandbox {
        Sandbox::detect_with(None)
    }

    /// Like [`detect`](Self::detect), with an explicit cgroup v2 parent
    /// (Linux only) overriding auto-discovery.
    #[cfg(target_os = "linux")]
    pub fn detect_with(cgroup_parent: Option<CgroupParent>) -> Sandbox {
        let capabilities = linux::detect_capabilities(cgroup_parent.as_ref());
        Sandbox {
            backend: Backend::Linux(Arc::new(linux::LinuxBackend::new(&capabilities))),
            capabilities: Arc::new(capabilities),
        }
    }

    /// Like [`detect`](Self::detect); the cgroup parent is meaningless on
    /// macOS and is ignored.
    #[cfg(target_os = "macos")]
    pub fn detect_with(_cgroup_parent: Option<CgroupParent>) -> Sandbox {
        let capabilities = macos::detect_capabilities();
        Sandbox {
            backend: Backend::MacOs(Arc::new(macos::MacosBackend::new(&capabilities))),
            capabilities: Arc::new(capabilities),
        }
    }

    /// Like [`detect`](Self::detect) on unsupported platforms: every spawn
    /// fails closed.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn detect_with(_cgroup_parent: Option<CgroupParent>) -> Sandbox {
        Sandbox {
            backend: Backend::Unsupported,
            capabilities: Arc::new(SandboxCapabilities {
                platform: Platform::Unsupported,
                landlock_abi: None,
                cgroup_v2_root: None,
                seatbelt_available: false,
            }),
        }
    }

    /// What this backend can do.
    pub fn capabilities(&self) -> &SandboxCapabilities {
        &self.capabilities
    }

    /// Create one Linux cgroup-backed process domain for a durable sandbox.
    ///
    /// Every child spawned through [`spawn_in_process_domain`](Self::spawn_in_process_domain)
    /// is born inside the domain's cgroup (`clone3(CLONE_INTO_CGROUP)`) and
    /// shares the same aggregate limits. Limits may be entirely `Inherit`:
    /// the domain still exists as the sandbox's process-containment boundary,
    /// it just leaves every controller file at the parent's policy. The
    /// caller owns the domain lifetime separately from any individual child
    /// and should remove it only after all sandbox processes are gone.
    #[cfg(target_os = "linux")]
    pub fn create_process_domain(
        &self,
        resources: ResourceLimits,
        cgroup_parent: Option<CgroupParent>,
    ) -> Result<ProcessDomain, SandboxError> {
        validate::validate_resources(&resources)?;
        match &self.backend {
            Backend::Linux(backend) => {
                backend.create_process_domain(resources, cgroup_parent.as_ref())
            }
            Backend::Unsupported => Err(SandboxError::unsupported(
                "backend",
                "no sandbox backend exists for this platform",
            )),
        }
    }

    /// Reconcile stale process domains left below a delegated cgroup parent.
    ///
    /// This removes only cgroups created by the durable process-domain API;
    /// one-shot resource cgroups and unrelated sibling cgroups are ignored.
    /// A daemon should call this before accepting new sandbox launches after
    /// a restart.
    #[cfg(target_os = "linux")]
    pub fn reconcile_stale_process_domains(
        &self,
        cgroup_parent: Option<CgroupParent>,
    ) -> Result<usize, SandboxError> {
        match &self.backend {
            Backend::Linux(backend) => {
                backend.reconcile_stale_process_domains(cgroup_parent.as_ref())
            }
            Backend::Unsupported => Err(SandboxError::unsupported(
                "backend",
                "no sandbox backend exists for this platform",
            )),
        }
    }

    /// Spawn a Linux child directly into an existing durable process domain.
    ///
    /// The config's resource limits must exactly match the domain's limits.
    /// Child teardown releases only the child's reference; it does not remove
    /// the shared cgroup.
    #[cfg(target_os = "linux")]
    pub fn spawn_in_process_domain(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
        domain: &ProcessDomain,
    ) -> Result<SandboxChild, SandboxError> {
        validate::validate(&config, &command)?;
        match &self.backend {
            Backend::Linux(backend) => backend.spawn_in_process_domain(command, config, domain),
            Backend::Unsupported => Err(SandboxError::unsupported(
                "backend",
                "no sandbox backend exists for this platform",
            )),
        }
    }

    /// Spawn `command` under `config`.
    ///
    /// Returns only after the child has either `exec`'d the requested
    /// program with every requested mechanism enforced, or failed setup
    /// (in which case [`SandboxError::Setup`] describes the stage and the
    /// child is already reaped and cleaned up). User code never runs before
    /// this function returns `Ok`.
    pub fn spawn(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
    ) -> Result<SandboxChild, SandboxError> {
        validate::validate(&config, &command)?;
        match &self.backend {
            #[cfg(target_os = "linux")]
            Backend::Linux(backend) => backend.spawn(command, config),
            #[cfg(target_os = "macos")]
            Backend::MacOs(backend) => backend.spawn(command, config),
            Backend::Unsupported => Err(SandboxError::unsupported(
                "backend",
                "no sandbox backend exists for this platform",
            )),
        }
    }
}
