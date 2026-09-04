//! Linux production backend.
//!
//! Spawn path (architecture Phase 2): every fallible, allocating step —
//! cgroup creation and limit writes, Landlock ruleset construction, seccomp
//! compilation, stdio pipes, argument/environment marshalling — happens in
//! the parent. A process-lifetime spawn-owner thread then creates the
//! engine-owned child with `clone3(CLONE_PIDFD | …)` and runs a fixed,
//! allocation-free setup chain before `execve`. Without a PID namespace that
//! clone also uses `CLONE_INTO_CGROUP` when limits are active. With a PID
//! namespace the direct clone is an internal PID 1 supervisor, which creates
//! the user PID 2 with a nested `clone3(CLONE_INTO_CGROUP)` when needed. There
//! is no fork-then-move fallback: unsupported kernel primitives fail closed.

pub mod caps;
pub mod cgroup;
pub mod child;
pub mod clone3;
pub mod landlock;
pub mod seccomp;
mod syscall_names;
pub use syscall_names::syscall_number;

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Error as IoError, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio as ProcessStdio};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use crate::ChildStage;
use crate::command::{CommandSpec, SessionSetup, Stdio};
use crate::error::{ExitStatus, SandboxError};
use crate::policy::{
    CgroupParent, IdentityPolicy, IsolatedIdentity, NetworkNamespacePolicy, ResourceLimits,
    SandboxConfig,
};
use crate::{BackendChild, Platform, SandboxCapabilities, SandboxChild};

use cgroup::{
    Cgroup, ResolvedParent, create_process_domain_cgroup, create_process_domain_cgroup_under,
    create_sandbox_cgroup, needed_controllers, reconcile_process_domain_cgroups,
    resolve_creation_parent,
};
use clone3::{
    CLONE_INTO_CGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CLONE_PIDFD, CLONE3_ARGS_SIZE_V1, CLONE3_ARGS_SIZE_V2, Clone3, Clone3Args,
    clone3, pidfd_send_signal, pidfd_wait,
};

/// Serializes descriptor-creating spawns across threads of this process so
/// that one spawn's child can never inherit another spawn's transient
/// (pre-`dup2`) descriptors.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// All Linux `clone3` calls run on one process-lifetime thread.
///
/// `PR_SET_PDEATHSIG` is tied to the thread that created a child, not merely
/// to the containing process. Callers such as Tokio may invoke `spawn()` from
/// short-lived blocking workers, so cloning on the caller thread can kill an
/// otherwise healthy sandbox as soon as that worker exits. This owner thread
/// intentionally lives for the process lifetime and serializes the actual
/// clone/setup hand-off.
static SPAWN_OWNER: OnceLock<Result<mpsc::Sender<SpawnRequest>, String>> = OnceLock::new();

struct SpawnRequest {
    landlock_abi: Option<u32>,
    identity_mapper: Option<Arc<dyn UidGidMapper>>,
    command: CommandSpec,
    config: SandboxConfig,
    sandbox_cgroup: Option<Arc<Cgroup>>,
    mounts: Option<PreparedMounts>,
    reply: mpsc::SyncSender<Result<SandboxChild, SandboxError>>,
}

/// An open `/proc/<pid>` directory descriptor addressing the
/// barrier-blocked child of an isolated launch. The descriptor is owned by
/// the engine; a mapper uses it (or `pid` when its helper cannot address a
/// descriptor) to install the UID/GID maps.
pub struct MapperTarget {
    /// Open `O_PATH|O_DIRECTORY` descriptor on `/proc/<pid>`.
    pub proc_dir_fd: OwnedFd,
    /// The child's PID in the launcher's PID namespace. The engine holds
    /// the child's pidfd for the whole handshake, so the PID cannot be
    /// recycled while `proc_dir_fd` is alive.
    pub pid: libc::pid_t,
}

/// Parent-side identity-mapping seam for isolated launches (the engine's
/// only route to subordinate-ID translation).
///
/// The engine calls `install` exactly once per isolated launch, after the
/// fresh `clone3(CLONE_NEWUSER)` child has signaled the mapping barrier and
/// before it is allowed to continue. The implementation must install
/// **exactly** the one-entry maps
///
/// ```text
/// uid_map: <runtime_uid> <host_uid> 1
/// gid_map: <runtime_gid> <host_gid> 1
/// ```
///
/// into the child's user namespace (shadow-utils `newuidmap`/`newgidmap`
/// with the proc-dir `fd:N` form is the intended production
/// implementation). The engine independently reads the maps back and fails
/// the launch unless they match exactly.
pub trait UidGidMapper: Send + Sync + 'static {
    /// Install the delegated one-entry UID/GID maps (see the trait docs).
    /// Returning `Err` aborts the launch before user code runs.
    fn install(&self, target: &MapperTarget, identity: &IsolatedIdentity) -> Result<(), IoError>;
}

/// Detached ID-mapped mounts prepared by a privileged broker and attached by
/// the sandbox child after its own user namespace mapping barrier.
///
/// All descriptors are owned by this value. The engine consumes the value for
/// one spawn; the parent copies are closed as soon as `clone3` succeeds and
/// the child closes its copies during setup/FD hygiene.
#[derive(Debug)]
pub struct PreparedMounts {
    workspace_mount: OwnedFd,
    workspace_target: OwnedFd,
    runtime_mount: OwnedFd,
    runtime_target: OwnedFd,
}

impl PreparedMounts {
    /// Construct the two writable views in stable workspace/runtime order.
    pub fn new(
        workspace_mount: OwnedFd,
        workspace_target: OwnedFd,
        runtime_mount: OwnedFd,
        runtime_target: OwnedFd,
    ) -> Self {
        Self {
            workspace_mount,
            workspace_target,
            runtime_mount,
            runtime_target,
        }
    }
}

/// Parent-side mapper backed by shadow-utils' `newuidmap` and `newgidmap`.
///
/// The helpers are invoked with the opened `/proc/<pid>` directory as an
/// inherited descriptor and the `fd:N` target form.  This keeps the mapping
/// operation tied to the object opened by the engine instead of reopening a
/// decimal PID after a possible PID reuse.  A helper that does not implement
/// the `fd:N` form fails the isolated launch; there is no PID-path fallback.
#[derive(Debug, Clone)]
pub struct ShadowUidGidMapper {
    uid_helper: PathBuf,
    gid_helper: PathBuf,
}

impl Default for ShadowUidGidMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowUidGidMapper {
    /// Use the standard shadow-utils helper names resolved through a fixed,
    /// administrator-owned PATH.
    pub fn new() -> Self {
        Self::with_helpers("newuidmap", "newgidmap")
    }

    /// Use explicit helper paths.  This is primarily useful for a packaged
    /// installation with helpers outside the usual system PATH and for
    /// deterministic integration-test fixtures.
    pub fn with_helpers(uid_helper: impl Into<PathBuf>, gid_helper: impl Into<PathBuf>) -> Self {
        Self {
            uid_helper: uid_helper.into(),
            gid_helper: gid_helper.into(),
        }
    }

    fn run_helper(
        &self,
        helper: &Path,
        target: &MapperTarget,
        inside: u32,
        outside: u32,
    ) -> Result<(), IoError> {
        let inherited = duplicate_without_cloexec(target.proc_dir_fd.as_raw_fd())?;
        let fd = inherited.as_raw_fd();
        let output = Command::new(helper)
            .arg(format!("fd:{fd}"))
            .arg(inside.to_string())
            .arg(outside.to_string())
            .arg("1")
            .env_clear()
            .env(
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
            )
            .stdin(ProcessStdio::null())
            .stdout(ProcessStdio::null())
            .stderr(ProcessStdio::piped())
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(IoError::other(format!(
            "{} failed with status {}{}",
            helper.display(),
            output.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )))
    }
}

impl UidGidMapper for ShadowUidGidMapper {
    fn install(&self, target: &MapperTarget, identity: &IsolatedIdentity) -> Result<(), IoError> {
        self.run_helper(
            &self.uid_helper,
            target,
            identity.runtime_uid,
            identity.host_uid,
        )?;
        self.run_helper(
            &self.gid_helper,
            target,
            identity.runtime_gid,
            identity.host_gid,
        )
    }
}

/// Create the auxiliary user namespace consumed by an ID-mapped mount.
///
/// The returned descriptor pins a fresh user namespace whose map is installed
/// by the same parent-side mapper used for runtime launches.  The temporary
/// keeper process is killed before this function returns; the namespace stays
/// alive because the returned namespace descriptor owns a kernel reference to
/// it.  `identity.runtime_uid`/`runtime_gid` are the IDs in the auxiliary
/// namespace (normally the daemon's effective IDs), while `host_uid`/
/// `host_gid` are the leased subordinate IDs.
pub fn create_mount_idmap_user_namespace(
    mapper: &dyn UidGidMapper,
    identity: IsolatedIdentity,
) -> Result<OwnedFd, SandboxError> {
    let _spawn_guard = SPAWN_LOCK
        .lock()
        .map_err(|_| SandboxError::Internal("spawn lock poisoned".to_string()))?;
    let (ready_read, ready_write) = make_pipe()?;
    let (installed_read, installed_write) = make_pipe()?;
    let parent_pid = unsafe { libc::getpid() };
    let mut args = Clone3Args {
        flags: CLONE_PIDFD | CLONE_NEWUSER,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };

    match unsafe { clone3(&mut args, CLONE3_ARGS_SIZE_V1) } {
        Ok(Clone3::Child) => unsafe {
            mount_idmap_keeper_child(
                ready_write.as_raw_fd(),
                installed_read.as_raw_fd(),
                parent_pid,
            )
        },
        Ok(Clone3::Parent { pid, pidfd }) => {
            drop(ready_write);
            drop(installed_read);
            let result = (|| {
                install_isolated_maps(pid, &identity, mapper, &ready_read, &installed_write)?;
                let path = CString::new(format!("/proc/{pid}/ns/user"))
                    .map_err(|_| SandboxError::Internal("PID contained NUL".to_string()))?;
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(SandboxError::Setup {
                        stage: ChildStage::MapBarrier,
                        detail: 15,
                        errno: Some(raw_errno()),
                    });
                }
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            })();
            drop(ready_read);
            drop(installed_write);
            match result {
                Ok(namespace) => {
                    kill_and_reap(&pidfd);
                    Ok(namespace)
                }
                Err(error) => {
                    kill_and_reap(&pidfd);
                    Err(error)
                }
            }
        }
        Err(error) => Err(SandboxError::unsupported(
            "user-namespace",
            format!("auxiliary mount ID-map namespace clone3 failed: {error}"),
        )),
    }
}

/// The auxiliary namespace keeper has no Rust-level cleanup path: it is a
/// post-clone helper that either waits for the parent release byte or exits.
///
/// # Safety
///
/// Called only in the child returned by `clone3`; all descriptors are valid
/// child copies and the function never returns to the cloned Rust stack.
unsafe fn mount_idmap_keeper_child(
    ready_write: RawFd,
    installed_read: RawFd,
    parent_pid: libc::pid_t,
) -> ! {
    if unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        )
    } == -1
        || unsafe { libc::syscall(libc::SYS_getppid) as libc::pid_t } != parent_pid
    {
        unsafe { libc::_exit(127) }
    }

    let byte = [child::MAP_READY];
    let mut written = 0_usize;
    while written < byte.len() {
        let count = unsafe {
            libc::write(
                ready_write,
                byte.as_ptr().add(written).cast(),
                byte.len() - written,
            )
        };
        if count > 0 {
            written += count as usize;
        } else if count < 0 && raw_errno() == libc::EINTR {
            continue;
        } else {
            unsafe { libc::_exit(127) }
        }
    }

    let mut release = [0_u8; 1];
    loop {
        let count = unsafe { libc::read(installed_read, release.as_mut_ptr().cast(), 1) };
        if count == 1 {
            break;
        }
        if count < 0 && raw_errno() == libc::EINTR {
            continue;
        }
        unsafe { libc::_exit(127) }
    }
    if release[0] != child::MAP_INSTALLED {
        unsafe { libc::_exit(127) }
    }

    loop {
        unsafe { libc::pause() };
    }
}

/// Duplicate a descriptor for a helper process while deliberately clearing
/// `FD_CLOEXEC`. `Command::output` inherits descriptors; the returned owner
/// closes the duplicate after the helper has exited.
fn duplicate_without_cloexec(fd: RawFd) -> Result<OwnedFd, IoError> {
    // SAFETY: `fd` is an open descriptor owned by the mapper target. F_DUPFD
    // creates an independent descriptor with the lowest number >= 3.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD, 3) };
    if duplicate < 0 {
        return Err(IoError::last_os_error());
    }
    // SAFETY: the duplicate is valid and owned by this function from here.
    let flags = unsafe { libc::fcntl(duplicate, libc::F_GETFD) };
    if flags < 0 {
        unsafe { libc::close(duplicate) };
        return Err(IoError::last_os_error());
    }
    if unsafe { libc::fcntl(duplicate, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        let error = IoError::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    // SAFETY: `duplicate` is a newly-created owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn spawn_owner() -> Result<&'static mpsc::Sender<SpawnRequest>, SandboxError> {
    match SPAWN_OWNER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<SpawnRequest>();
        std::thread::Builder::new()
            .name("shbox-sandbox-linux-spawn-owner".to_string())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let result = spawn_with_cgroup_on_owner(
                        request.landlock_abi,
                        request.identity_mapper,
                        request.command,
                        request.config,
                        request.sandbox_cgroup,
                        request.mounts,
                    );
                    let _ = request.reply.send(result);
                }
            })
            .map(|_| sender)
            .map_err(|error| error.to_string())
    }) {
        Ok(sender) => Ok(sender),
        Err(error) => Err(SandboxError::Internal(format!(
            "Linux sandbox spawn-owner thread is unavailable: {error}"
        ))),
    }
}

/// The kernel's errno for the calling thread.
pub(crate) fn raw_errno() -> i32 {
    // SAFETY: errno access is thread-local and valid on the calling thread.
    unsafe { *libc::__errno_location() }
}

/// Detect the platform's sandbox facilities.
///
/// The reported cgroup path is a **candidate**, not a validated parent:
/// writability, delegation, and controller availability are proven when a
/// parent is resolved for use ([`ProcessDomainScope::resolve`] or a spawn
/// with limits). An explicitly configured parent takes precedence over
/// auto-discovery so configuration actually overrides the environment.
pub fn detect_capabilities(explicit_parent: Option<&CgroupParent>) -> SandboxCapabilities {
    SandboxCapabilities {
        platform: Platform::Linux,
        landlock_abi: landlock::probe_abi(),
        cgroup_v2_root: explicit_parent
            .map(|parent| parent.path().to_path_buf())
            .or_else(cgroup::current_cgroup_path),
        seatbelt_available: false,
    }
}

/// A cgroup parent resolved once from immutable configuration, binding
/// process-domain creation and stale-domain reconciliation to one open
/// directory descriptor.
///
/// Resolving the parent independently per operation could select different
/// ancestors when auto-discovery walks toward the cgroup2 root (a nearer
/// writable candidate without the needed controllers versus a farther one
/// with them). One resolved scope makes that divergence impossible: every
/// domain created through the scope lives below the same descriptor that
/// reconciliation later enumerates.
///
/// A daemon should resolve exactly one scope for its resource policy at
/// startup, call [`reconcile_stale`](Self::reconcile_stale) before accepting
/// launches, and use [`create_domain`](Self::create_domain) for every
/// sandbox's durable process domain.
pub struct ProcessDomainScope {
    parent: ResolvedParent,
}

impl std::fmt::Debug for ProcessDomainScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessDomainScope")
            .field("parent", &self.parent.path().display().to_string())
            .finish()
    }
}

impl ProcessDomainScope {
    /// Resolve the delegated cgroup parent for `limits`' controller
    /// requirements. See [`detect_capabilities`] for detection semantics;
    /// this is the operation that actually validates writability and
    /// controllers.
    pub fn resolve(
        explicit_parent: Option<&CgroupParent>,
        limits: &ResourceLimits,
    ) -> Result<Self, SandboxError> {
        Ok(Self {
            parent: resolve_creation_parent(explicit_parent, &needed_controllers(limits))?,
        })
    }

    /// The resolved parent's path, for diagnostics and logging.
    pub fn parent_path(&self) -> &std::path::Path {
        self.parent.path()
    }

    /// Create one durable process domain below the resolved parent.
    ///
    /// Limits may be entirely `Inherit`: the domain still exists as the
    /// sandbox's process-containment boundary, leaving every controller file
    /// at the parent's policy.
    pub fn create_domain(&self, limits: &ResourceLimits) -> Result<ProcessDomain, SandboxError> {
        Ok(ProcessDomain {
            cgroup: Arc::new(create_process_domain_cgroup_under(
                &self.parent,
                limits,
                &random_suffix()?,
            )?),
            resources: *limits,
        })
    }

    /// Reclaim stale process domains left below this exact parent by a
    /// previous daemon instance. Only the reserved `shbox-domain-` prefix is
    /// considered owned; siblings and one-shot `sandbox-*` cgroups are never
    /// inspected or changed.
    pub fn reconcile_stale(&self) -> Result<usize, SandboxError> {
        reconcile_process_domain_cgroups(&self.parent)
    }
}

/// The immutable Linux backend state.
pub struct LinuxBackend {
    landlock_abi: Option<u32>,
    identity_mapper: Option<Arc<dyn UidGidMapper>>,
}

/// A durable Linux process domain shared by every process in one sandbox.
///
/// The domain owns one configured cgroup v2 directory: the authoritative
/// process-ownership boundary for the sandbox. Spawned children hold
/// references to that cgroup so a process teardown never removes containment
/// that still belongs to the durable sandbox. Resource limits are optional
/// dressing on the same cgroup; removing the domain is a separate lifecycle
/// operation performed after all sandbox processes are gone.
pub struct ProcessDomain {
    cgroup: Arc<Cgroup>,
    resources: ResourceLimits,
}

impl std::fmt::Debug for ProcessDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceDomain")
            .field("resources", &self.resources)
            .finish_non_exhaustive()
    }
}

impl ProcessDomain {
    /// Whether the domain's cgroup (or a descendant) still contains
    /// processes. This is the authoritative membership signal; Rust handle
    /// counts are not — a detached descendant keeps the domain populated
    /// long after every child handle is gone.
    pub fn is_populated(&self) -> Result<bool, SandboxError> {
        self.cgroup.is_populated().map_err(SandboxError::Io)
    }

    /// Block until the cgroup reports `populated 0` or `timeout` elapses.
    pub fn wait_until_empty(&self, timeout: Duration) -> Result<bool, SandboxError> {
        self.cgroup
            .wait_until_empty(timeout)
            .map_err(SandboxError::Io)
    }

    /// Kill every process in the domain (`cgroup.kill`).
    ///
    /// The only member-terminating operation, reserved for explicit
    /// lifecycle decisions: sandbox deletion, daemon shutdown, and
    /// defensive cleanup of an abandoned launch.
    pub fn kill_all(&self) -> Result<(), SandboxError> {
        self.cgroup.kill_all().map_err(SandboxError::Io)
    }

    /// Remove the domain's cgroup directory, refusing while processes
    /// remain. A failed removal leaves the domain intact so the caller can
    /// kill, wait, and retry without losing ownership of the cgroup.
    pub fn remove_empty(&self) -> Result<(), SandboxError> {
        self.cgroup.remove_empty().map_err(SandboxError::Io)
    }
}

impl LinuxBackend {
    pub(crate) fn new(
        capabilities: &SandboxCapabilities,
        identity_mapper: Option<Arc<dyn UidGidMapper>>,
    ) -> Self {
        LinuxBackend {
            landlock_abi: capabilities.landlock_abi,
            identity_mapper,
        }
    }

    pub(crate) fn create_mount_idmap_user_namespace(
        &self,
        identity: IsolatedIdentity,
    ) -> Result<OwnedFd, SandboxError> {
        let mapper = self.identity_mapper.as_deref().ok_or_else(|| {
            SandboxError::unsupported(
                "identity",
                "isolated identity requires a parent mapping helper for the mount map namespace",
            )
        })?;
        let daemon_identity = IsolatedIdentity {
            runtime_uid: unsafe { libc::geteuid() },
            runtime_gid: unsafe { libc::getegid() },
            host_uid: identity.host_uid,
            host_gid: identity.host_gid,
        };
        create_mount_idmap_user_namespace(mapper, daemon_identity)
    }

    pub(crate) fn spawn(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
    ) -> Result<SandboxChild, SandboxError> {
        let explicit_parent = config.cgroup_parent.as_deref().map(CgroupParent::new);
        let sandbox_cgroup = if config.resources.requires_cgroup() {
            Some(Arc::new(create_sandbox_cgroup(
                &config.resources,
                explicit_parent.as_ref(),
                &random_suffix()?,
            )?))
        } else {
            None
        };
        self.spawn_with_cgroup(command, config, sandbox_cgroup, None)
    }

    pub(crate) fn create_process_domain(
        &self,
        resources: ResourceLimits,
        explicit_parent: Option<&CgroupParent>,
    ) -> Result<ProcessDomain, SandboxError> {
        // All-`Inherit` limits are valid: the domain still owns one cgroup
        // for process containment, it simply leaves every controller file
        // at the creation parent's policy.
        Ok(ProcessDomain {
            cgroup: Arc::new(create_process_domain_cgroup(
                &resources,
                explicit_parent,
                &random_suffix()?,
            )?),
            resources,
        })
    }

    /// Reconcile with an independently resolved parent. Prefer
    /// [`ProcessDomainScope`], which binds creation and reconciliation to
    /// one resolved parent; this per-call form resolves with no controller
    /// requirements and is only correct when every domain was created below
    /// the same explicit parent.
    pub(crate) fn reconcile_stale_process_domains(
        &self,
        explicit_parent: Option<&CgroupParent>,
    ) -> Result<usize, SandboxError> {
        let parent = resolve_creation_parent(explicit_parent, &[])?;
        reconcile_process_domain_cgroups(&parent)
    }

    pub(crate) fn spawn_in_process_domain(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
        domain: &ProcessDomain,
    ) -> Result<SandboxChild, SandboxError> {
        if config.resources != domain.resources {
            return Err(SandboxError::invalid(
                "resources",
                "spawn resource limits do not match the resource domain",
            ));
        }
        self.spawn_with_cgroup(command, config, Some(Arc::clone(&domain.cgroup)), None)
    }

    pub(crate) fn spawn_in_process_domain_with_mounts(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
        domain: &ProcessDomain,
        mounts: PreparedMounts,
    ) -> Result<SandboxChild, SandboxError> {
        if config.resources != domain.resources {
            return Err(SandboxError::invalid(
                "resources",
                "spawn resource limits do not match the resource domain",
            ));
        }
        self.spawn_with_cgroup(
            command,
            config,
            Some(Arc::clone(&domain.cgroup)),
            Some(mounts),
        )
    }

    fn spawn_with_cgroup(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
        sandbox_cgroup: Option<Arc<Cgroup>>,
        mounts: Option<PreparedMounts>,
    ) -> Result<SandboxChild, SandboxError> {
        let (reply, response) = mpsc::sync_channel(1);
        spawn_owner()?
            .send(SpawnRequest {
                landlock_abi: self.landlock_abi,
                identity_mapper: self.identity_mapper.clone(),
                command,
                config,
                sandbox_cgroup,
                mounts,
                reply,
            })
            .map_err(|_| {
                SandboxError::Internal("Linux sandbox spawn-owner thread stopped".to_string())
            })?;
        response.recv().map_err(|_| {
            SandboxError::Internal(
                "Linux sandbox spawn-owner thread stopped before replying".to_string(),
            )
        })?
    }
}

fn spawn_with_cgroup_on_owner(
    landlock_abi: Option<u32>,
    identity_mapper: Option<Arc<dyn UidGidMapper>>,
    command: CommandSpec,
    config: SandboxConfig,
    sandbox_cgroup: Option<Arc<Cgroup>>,
    mounts: Option<PreparedMounts>,
) -> Result<SandboxChild, SandboxError> {
    // Serialize the descriptor-to-clone window against other spawns in
    // this process.
    let _spawn_guard = SPAWN_LOCK
        .lock()
        .map_err(|_| SandboxError::Internal("spawn lock poisoned".to_string()))?;

    // 2. Landlock ruleset (parent-side construction).
    let landlock_prepared = landlock::prepare(
        &config.filesystem,
        config.network,
        landlock_abi.unwrap_or(0),
    )?;

    // 3. seccomp program (parent-side compilation).
    let seccomp_program = seccomp::compile(&config.syscalls)?;

    // 4. stdio endpoints.
    let mut stdio = StdioFds::create(&command)?;

    // 5. status pipe.
    let (status_read, status_write) = make_pipe()?;

    // 5.5 Isolated identity: the mapping barrier pipe and the mapper seam.
    //    Both must exist before the child is cloned; an unconfigured mapper
    //    fails before any child exists.
    let isolated_launch = match config.identity {
        IdentityPolicy::Isolated(identity) => {
            let mapper = identity_mapper.clone().ok_or_else(|| {
                SandboxError::unsupported(
                    "identity",
                    "isolated identity requires a parent mapping helper (UidGidMapper) which was not configured",
                )
            })?;
            // Two one-direction pipes: the child signals readiness on
            // `ready`, the parent releases it on `installed`. After clone
            // the parent drops its copy of the readiness write end, so a
            // child that dies before signaling is observed as EOF instead
            // of a blocked read.
            let (ready_read, ready_write) = make_pipe()?;
            let (installed_read, installed_write) = make_pipe()?;
            Some((
                identity,
                mapper,
                ready_read,
                ready_write,
                installed_read,
                installed_write,
            ))
        }
        _ => None,
    };

    // A PID namespace needs a dedicated PID1 supervisor. The parent
    // sends logical user-process signals over a fixed-size seqpacket
    // channel, while PID1 returns the normalized PID2 exit status over a
    // separate pipe. Non-PID-namespace spawns allocate neither channel.
    let (
        supervisor_control_child,
        supervisor_control_parent,
        supervisor_exit_read,
        supervisor_exit_write,
    ) = if config.namespaces.pid {
        let (child, parent) = make_socketpair()?;
        let (read, write) = make_pipe()?;
        (Some(child), Some(parent), Some(read), Some(write))
    } else {
        (None, None, None, None)
    };

    // 6. A child in a new PID namespace sees getppid() == 0 because its
    // real parent is outside that namespace. Open the parent's pidfd
    // before clone so the child can perform the same race-safe liveness
    // check without relying on a namespace-local PID.
    let parent_pidfd = if config.namespaces.pid {
        Some(open_pidfd(unsafe { libc::getpid() }).map_err(|error| {
            SandboxError::unsupported(
                "pidfd",
                format!("parent-liveness pidfd_open failed: {error}"),
            )
        })?)
    } else {
        None
    };

    // 7. assemble the child setup.
    let mut setup = build_child_setup(
        command,
        &config,
        isolated_launch
            .as_ref()
            .map(|(_, _, _, ready_write, installed_read, _)| {
                (ready_write.as_raw_fd(), installed_read.as_raw_fd())
            }),
        stdio.sources(),
        status_write.as_raw_fd(),
        parent_pidfd.as_ref().map(AsRawFd::as_raw_fd),
        supervisor_control_child.as_ref().map(AsRawFd::as_raw_fd),
        supervisor_exit_write.as_ref().map(AsRawFd::as_raw_fd),
        if config.namespaces.pid {
            sandbox_cgroup.as_ref().map(|cgroup| cgroup.clone_fd())
        } else {
            None
        },
        mounts.as_ref().map(|mounts| child::MountSetup {
            workspace_mount: mounts.workspace_mount.as_raw_fd(),
            workspace_target: mounts.workspace_target.as_raw_fd(),
            runtime_mount: mounts.runtime_mount.as_raw_fd(),
            runtime_target: mounts.runtime_target.as_raw_fd(),
        }),
        landlock_prepared,
        seccomp_program,
    )?;

    // 8. clone3: namespaces, pidfd, and (when configured) the cgroup in
    //    one atomic child creation.
    let mut flags: u64 = CLONE_PIDFD | namespace_flags(&config);
    let mut args = Clone3Args {
        flags,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let mut size = CLONE3_ARGS_SIZE_V1;
    // When CLONE_NEWPID is active, the direct clone is the engine-owned
    // PID1 supervisor and intentionally stays outside the user resource
    // domain. PID1 atomically creates PID2 into this same cgroup via a
    // nested clone3(CLONE_INTO_CGROUP), so pids.max counts user processes
    // rather than implementation overhead.
    if !config.namespaces.pid
        && let Some(cgroup) = sandbox_cgroup.as_ref()
    {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = cgroup.clone_fd() as u64;
        size = CLONE3_ARGS_SIZE_V2;
    }
    flags = args.flags;

    match unsafe { clone3(&mut args, size) } {
        Ok(Clone3::Parent { pid, pidfd }) => {
            drop(parent_pidfd);
            // The child has its own descriptor-table view; drop the
            // parent's copies of child-side endpoints.
            drop(status_write);
            drop(supervisor_control_child);
            drop(supervisor_exit_write);
            drop(mounts);
            stdio.close_parent_copies();

            // 8.5 Isolated identity: run the parent side of the mapping
            //     barrier while the child is blocked. Any failure here kills
            //     the child through the pidfd path before user code can run.
            if let Some((
                identity,
                mapper,
                ready_read,
                ready_write,
                installed_read,
                installed_write,
            )) = isolated_launch
            {
                // The readiness write end must not outlive the child in the
                // parent, or a dead child could never be observed as EOF.
                drop(ready_write);
                drop(installed_read);
                let handshake = install_isolated_maps(
                    pid,
                    &identity,
                    mapper.as_ref(),
                    &ready_read,
                    &installed_write,
                );
                drop(ready_read);
                drop(installed_write);
                if let Err(error) = handshake {
                    kill_and_reap(&pidfd);
                    drop(sandbox_cgroup);
                    return Err(error);
                }
            }

            // 9. Confirm setup: EOF on the status pipe means the exec
            //    happened with every mechanism in place. Anything else
            //    aborts the launch, reaps the child, and removes the
            //    cgroup.
            let outcome = read_child_failure(&status_read);
            drop(status_read);
            let result = match outcome {
                Outcome::Clean => Ok(()),
                Outcome::Failed(failure) => Err(SandboxError::Setup {
                    stage: failure.stage,
                    detail: failure.detail,
                    errno: failure.errno,
                }),
                Outcome::Corrupt(message) => Err(SandboxError::Internal(message)),
            };
            if let Err(error) = result {
                kill_and_reap(&pidfd);
                drop(sandbox_cgroup);
                return Err(error);
            }

            let linux_child = LinuxChild {
                pid,
                pidfd,
                cgroup: sandbox_cgroup,
                status: None,
                torn_down: false,
                owns_process_group: !matches!(setup.session, SessionSetup::Inherit),
                pid_namespace_init: config.namespaces.pid,
                supervisor_control: supervisor_control_parent,
                supervisor_exit: supervisor_exit_read,
            };
            Ok(SandboxChild::new(
                Box::new(linux_child),
                stdio.take_stdin(),
                stdio.take_stdout(),
                stdio.take_stderr(),
            ))
        }
        Ok(Clone3::Child) => {
            // This thread is now the child; the setup chain consumes it
            // and never returns.
            unsafe { child::child_entry(&mut setup) }
        }
        Err(error) => {
            drop(status_read);
            drop(status_write);
            drop(sandbox_cgroup);
            let feature = match error.raw_os_error() {
                Some(libc::EINVAL) if flags & CLONE_INTO_CGROUP != 0 => "clone3-into-cgroup",
                Some(libc::EPERM) => "namespace",
                _ => "clone3",
            };
            Err(SandboxError::unsupported(
                feature,
                format!(
                    "clone3 with flags {flags:#x} failed: {error} \
                         (CLONE_PIDFD needs kernel 5.3+, CLONE_INTO_CGROUP 5.7+)"
                ),
            ))
        }
    }
}

fn namespace_flags(config: &SandboxConfig) -> u64 {
    let mut flags = 0_u64;
    // A user namespace exists for any non-host identity. Its UID/GID mapping
    // is identity policy, not topology: `CallerMappedRoot` self-maps in the
    // child, `Isolated` waits for the parent-side mapper.
    if matches!(
        config.identity,
        IdentityPolicy::CallerMappedRoot | IdentityPolicy::Isolated(_)
    ) {
        flags |= CLONE_NEWUSER;
    }
    if config.namespaces.pid {
        flags |= CLONE_NEWPID;
    }
    if config.namespaces.mount {
        flags |= CLONE_NEWNS;
    }
    if config.namespaces.ipc {
        flags |= CLONE_NEWIPC;
    }
    if config.namespaces.uts {
        flags |= CLONE_NEWUTS;
    }
    if config.namespaces.network == NetworkNamespacePolicy::Isolated {
        flags |= CLONE_NEWNET;
    }
    flags
}

/// Result of reading the child's setup status pipe.
enum Outcome {
    /// EOF before any record: the child reached `execve`.
    Clean,
    /// A well-formed failure record: the child never ran user code.
    Failed(child::ChildFailure),
    /// Unreadable or malformed status; fail closed.
    Corrupt(String),
}

/// Kill the direct child and reap it via the pidfd. Used on every failure
/// path after a successful clone.
fn kill_and_reap(pidfd: &OwnedFd) {
    let _ = pidfd_send_signal(pidfd, libc::SIGKILL);
    // The child may be mid-setup; waitid(P_PIDFD) blocks until it is gone.
    let _ = pidfd_wait(pidfd, false);
}

fn read_child_failure(fd: &OwnedFd) -> Outcome {
    let mut record = [0_u8; 12];
    let mut offset = 0_usize;
    while offset < record.len() {
        // SAFETY: fd is owned and the target is the initialized record.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                record[offset..].as_mut_ptr().cast(),
                record.len() - offset,
            )
        };
        if count == 0 {
            break;
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Outcome::Corrupt(format!("sandbox child status could not be read: {error}"));
        }
        offset += count as usize;
    }
    if offset == 0 {
        return Outcome::Clean;
    }
    if offset != record.len() {
        return Outcome::Corrupt("sandbox child returned a truncated setup status".to_string());
    }
    match child::parse_child_failure(record) {
        Some(failure) => Outcome::Failed(failure),
        None => Outcome::Corrupt("sandbox child returned an invalid setup status".to_string()),
    }
}

fn send_supervisor_signal(fd: &OwnedFd, kind: u32, number: i32) -> std::io::Result<()> {
    if !(0..=64).contains(&number) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid Linux signal number {number}"),
        ));
    }
    let mut record = [0_u8; child::SUPERVISOR_CONTROL_LEN];
    record[0..4].copy_from_slice(&kind.to_ne_bytes());
    record[4..8].copy_from_slice(&number.to_ne_bytes());
    // MSG_NOSIGNAL prevents a stale/closed supervisor socket from turning a
    // library-level signalling error into SIGPIPE against the daemon.
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            record.as_ptr().cast(),
            record.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if sent as usize != record.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short PID-namespace supervisor control write",
        ));
    }
    Ok(())
}

fn read_supervisor_exit(fd: &OwnedFd) -> std::io::Result<ExitStatus> {
    let mut record = [0_u8; child::SUPERVISOR_EXIT_LEN];
    let mut offset = 0_usize;
    while offset < record.len() {
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                record[offset..].as_mut_ptr().cast(),
                record.len() - offset,
            )
        };
        if count == 0 {
            break;
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        offset += count as usize;
    }
    if offset != record.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PID-namespace supervisor exited without a complete user status",
        ));
    }
    child::parse_supervisor_exit(record).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PID-namespace supervisor returned an invalid user status",
        )
    })
}

/// Parent side of the isolated-identity mapping barrier.
///
/// Runs after `clone3(CLONE_NEWUSER)` while the child blocks. The child
/// must announce `MAP_READY` first; the mapper then installs the delegated
/// maps, and the engine reads them back — an exact one-entry match is
/// mandatory, and `setgroups` must still read `allow` so the child can
/// clear its inherited supplementary groups. Only then is `MAP_INSTALLED`
/// sent.
fn install_isolated_maps(
    child_pid: libc::pid_t,
    identity: &IsolatedIdentity,
    mapper: &dyn UidGidMapper,
    ready_read: &OwnedFd,
    installed_write: &OwnedFd,
) -> Result<(), SandboxError> {
    // 1. Wait for the child's barrier announcement. EOF means it died
    //    before reaching the barrier.
    let mut ready = [0_u8; 1];
    let mut offset = 0_usize;
    while offset < ready.len() {
        // SAFETY: reads into valid writable stack storage.
        let read = unsafe {
            libc::read(
                ready_read.as_raw_fd(),
                ready.as_mut_ptr().add(offset).cast(),
                ready.len() - offset,
            )
        };
        if read > 0 {
            offset += read as usize;
        } else if read == 0 {
            return Err(SandboxError::Setup {
                stage: ChildStage::MapBarrier,
                detail: 10,
                errno: Some(libc::EPIPE),
            });
        } else if raw_errno() != libc::EINTR {
            return Err(SandboxError::Setup {
                stage: ChildStage::MapBarrier,
                detail: 11,
                errno: Some(raw_errno()),
            });
        }
    }
    if ready[0] != child::MAP_READY {
        return Err(SandboxError::Setup {
            stage: ChildStage::MapBarrier,
            detail: 12,
            errno: Some(libc::EPROTO),
        });
    }

    // 2. Address the child through /proc. The engine holds the child's
    //    pidfd (CLONE_PIDFD) for the whole handshake, so the PID cannot be
    //    recycled while this descriptor is open.
    let proc_path = CString::new(format!("/proc/{child_pid}"))
        .map_err(|_| SandboxError::Internal("PID contained NUL".to_string()))?;
    // SAFETY: open of a fixed-form path; a fresh descriptor on success.
    let proc_fd = unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if proc_fd < 0 {
        return Err(SandboxError::Setup {
            stage: ChildStage::MapBarrier,
            detail: 13,
            errno: Some(raw_errno()),
        });
    }
    // SAFETY: proc_fd is a fresh owned descriptor.
    let target = MapperTarget {
        proc_dir_fd: unsafe { OwnedFd::from_raw_fd(proc_fd) },
        pid: child_pid,
    };

    // 3. Install the delegated maps through the caller's seam.
    mapper
        .install(&target, identity)
        .map_err(SandboxError::Io)?;

    // 4. Read the maps back; an exact single-entry match is mandatory. The
    //    kernel pads the map columns, so entries compare field-wise.
    expect_map_entry(&target, c"uid_map", identity.runtime_uid, identity.host_uid)?;
    expect_map_entry(&target, c"gid_map", identity.runtime_gid, identity.host_gid)?;
    expect_proc_entry(&target, c"setgroups", b"allow\n")?;

    // 5. Release the child from the barrier.
    let installed = [child::MAP_INSTALLED];
    let mut offset = 0_usize;
    while offset < installed.len() {
        // SAFETY: writes from valid readable stack storage.
        let written = unsafe {
            libc::write(
                installed_write.as_raw_fd(),
                installed.as_ptr().add(offset).cast(),
                installed.len() - offset,
            )
        };
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && raw_errno() == libc::EINTR {
            continue;
        } else {
            return Err(SandboxError::Setup {
                stage: ChildStage::MapBarrier,
                detail: 14,
                errno: Some(raw_errno()),
            });
        }
    }
    Ok(())
}

/// Read a `/proc/<pid>` `uid_map`/`gid_map` entry relative to the barrier
/// target's directory descriptor and require exactly one mapping row with
/// the expected inside/outside IDs and length.
fn expect_map_entry(
    target: &MapperTarget,
    name: &CStr,
    inside: u32,
    outside: u32,
) -> Result<(), SandboxError> {
    let text = String::from_utf8_lossy(&read_proc_entry(target, name)?).into_owned();
    let fields: Vec<&str> = text.split_whitespace().collect();
    let expected = [inside.to_string(), outside.to_string(), "1".to_string()];
    let matched = fields.len() == 3
        && fields
            .iter()
            .zip(expected.iter())
            .all(|(found, wanted)| found == wanted);
    if !matched {
        return Err(SandboxError::Setup {
            stage: ChildStage::MapBarrier,
            detail: 23,
            errno: None,
        });
    }
    Ok(())
}

/// Read a `/proc/<pid>` entry relative to the barrier target's directory
/// descriptor and require an exact byte match.
fn expect_proc_entry(
    target: &MapperTarget,
    name: &CStr,
    expected: &[u8],
) -> Result<(), SandboxError> {
    let bytes = read_proc_entry(target, name)?;
    if bytes != expected {
        return Err(SandboxError::Setup {
            stage: ChildStage::MapBarrier,
            detail: 22,
            errno: None,
        });
    }
    Ok(())
}

/// Read a small `/proc/<pid>` entry relative to the barrier target's
/// directory descriptor.
fn read_proc_entry(target: &MapperTarget, name: &CStr) -> Result<Vec<u8>, SandboxError> {
    // SAFETY: openat relative to the owned /proc/<pid> descriptor.
    let fd = unsafe {
        libc::openat(
            target.proc_dir_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(SandboxError::Setup {
            stage: ChildStage::MapBarrier,
            detail: 20,
            errno: Some(raw_errno()),
        });
    }
    let mut buffer = [0_u8; 256];
    let mut len = 0_usize;
    loop {
        // SAFETY: reads into valid writable storage with room left.
        let read =
            unsafe { libc::read(fd, buffer.as_mut_ptr().add(len).cast(), buffer.len() - len) };
        if read > 0 {
            len += read as usize;
            if len == buffer.len() {
                break;
            }
        } else if read == 0 {
            break;
        } else if raw_errno() != libc::EINTR {
            // SAFETY: fd is owned by this function.
            unsafe { libc::close(fd) };
            return Err(SandboxError::Setup {
                stage: ChildStage::MapBarrier,
                detail: 21,
                errno: Some(raw_errno()),
            });
        }
    }
    // SAFETY: fd is owned by this function.
    unsafe { libc::close(fd) };
    Ok(buffer[..len].to_vec())
}

/// Build the complete child setup from validated inputs.
#[allow(clippy::too_many_arguments)]
fn build_child_setup(
    command: CommandSpec,
    config: &SandboxConfig,
    barrier_fds: Option<(RawFd, RawFd)>,
    stdio: [RawFd; 3],
    status_write: RawFd,
    parent_pidfd: Option<RawFd>,
    supervisor_control_fd: Option<RawFd>,
    supervisor_exit_fd: Option<RawFd>,
    user_cgroup_fd: Option<RawFd>,
    mounts: Option<child::MountSetup>,
    landlock_prepared: Option<landlock::PreparedLandlock>,
    seccomp_program: seccomp::CompiledSeccomp,
) -> Result<child::ChildSetup, SandboxError> {
    let program = to_cstring("program", &command.program)?;
    let mut argv_owned = Vec::with_capacity(command.args.len() + 2);
    argv_owned.push(to_cstring(
        "argv0",
        command
            .argv0
            .as_deref()
            .unwrap_or(command.program.as_os_str()),
    )?);
    for arg in &command.args {
        argv_owned.push(to_cstring("args", arg)?);
    }
    let mut envp_owned = Vec::with_capacity(command.env.len() + 1);
    for (name, value) in &command.env {
        let mut combined = std::ffi::OsString::new();
        combined.push(name);
        combined.push("=");
        combined.push(value);
        envp_owned.push(to_cstring("env", &combined)?);
    }
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // `config` is borrowed here; the fds are sorted/deduped locally, so the
    // clone is the copy the child setup needs.
    let mut inherited_fds = config.inherited_fds.clone();
    inherited_fds.sort_unstable();
    inherited_fds.dedup();
    if let Some(mounts) = mounts.as_ref() {
        let descriptors = mounts.descriptors();
        for (index, fd) in descriptors.into_iter().enumerate() {
            if fd < 3
                || inherited_fds.contains(&fd)
                || stdio.contains(&fd)
                || barrier_fds
                    .iter()
                    .flat_map(|(read, write)| [*read, *write])
                    .chain(parent_pidfd)
                    .chain(supervisor_control_fd)
                    .chain(supervisor_exit_fd)
                    .chain(user_cgroup_fd)
                    .any(|reserved| reserved == fd)
                || unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
            {
                return Err(SandboxError::invalid(
                    "mounts",
                    format!("prepared mount descriptor {index} is invalid or conflicts with setup"),
                ));
            }
        }
        if descriptors[0] == descriptors[1]
            || descriptors[0] == descriptors[2]
            || descriptors[0] == descriptors[3]
            || descriptors[1] == descriptors[2]
            || descriptors[1] == descriptors[3]
            || descriptors[2] == descriptors[3]
        {
            return Err(SandboxError::invalid(
                "mounts",
                "prepared mount descriptors must be distinct",
            ));
        }
    }
    let mut report_guard = inherited_fds.last().map_or(3, |fd| (fd + 1).max(3));
    for fd in barrier_fds
        .iter()
        .flat_map(|(read, write)| [*read, *write])
        .chain(parent_pidfd.iter().copied())
        .chain(supervisor_control_fd.iter().copied())
        .chain(supervisor_exit_fd.iter().copied())
        .chain(user_cgroup_fd.iter().copied())
        .chain(
            mounts
                .as_ref()
                .into_iter()
                .flat_map(|mounts| mounts.descriptors()),
        )
    {
        report_guard = report_guard.max(fd.saturating_add(1));
    }

    // User-namespace identity. `CallerMappedRoot` self-maps the launcher's
    // euid/egid to namespace root (the `unshare --map-root-user` model).
    // `Isolated` writes nothing from the child: a parent-side mapper
    // installs the delegated subordinate IDs across the mapping barrier
    // while the child blocks.
    let identity = match config.identity {
        IdentityPolicy::Host => child::ChildIdentity::Host,
        IdentityPolicy::CallerMappedRoot => {
            let (uid_map, uid_map_len) = format_identity_map(unsafe { libc::geteuid() } as u64);
            let (gid_map, gid_map_len) = format_identity_map(unsafe { libc::getegid() } as u64);
            child::ChildIdentity::CallerMappedRoot {
                uid_map,
                uid_map_len,
                gid_map,
                gid_map_len,
            }
        }
        IdentityPolicy::Isolated(identity) => {
            let euid = unsafe { libc::geteuid() };
            let egid = unsafe { libc::getegid() };
            if identity.host_uid == euid || identity.host_gid == egid {
                return Err(SandboxError::invalid(
                    "identity",
                    "isolated identity must use leased subordinate IDs, not the launcher's own UID/GID",
                ));
            }
            let (ready_write, installed_read) = barrier_fds.ok_or_else(|| {
                SandboxError::Internal(
                    "isolated launch is missing its mapping-barrier descriptors".to_string(),
                )
            })?;
            child::ChildIdentity::Isolated {
                runtime_uid: identity.runtime_uid,
                runtime_gid: identity.runtime_gid,
                ready_write,
                installed_read,
            }
        }
    };

    Ok(child::ChildSetup {
        stdin_fd: stdio[0],
        stdout_fd: stdio[1],
        stderr_fd: stdio[2],
        report_fd: status_write,
        report_guard,
        inherited_fds,
        session: command.session,
        parent_pid: unsafe { libc::getpid() },
        parent_pidfd,
        pid_namespace_supervisor: config.namespaces.pid,
        supervisor_control_fd,
        supervisor_exit_fd,
        user_cgroup_fd,
        cwd: command
            .cwd
            .as_deref()
            .map(|cwd| to_cstring("cwd", cwd))
            .transpose()?,
        identity,
        mounts,
        make_mounts_private: config.namespaces.mount,
        retain_mask: child::retained_mask(&config.capabilities),
        drop_capabilities: true,
        landlock: landlock_prepared,
        seccomp: seccomp_program,
        program,
        argv_owned,
        envp_owned,
        argv,
        envp,
    })
}

/// "0 <outer> 1\n" formatted into a fixed buffer without allocation.
fn format_identity_map(outer: u64) -> ([u8; 64], usize) {
    let mut buffer = [0_u8; 64];
    let mut len = 0;
    let mut push = |bytes: &[u8]| {
        buffer[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    push(b"0 ");
    let mut digits = [0_u8; 20];
    let mut used = 0;
    let mut value = outer;
    loop {
        digits[used] = b'0' + (value % 10) as u8;
        used += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for digit in digits[..used].iter().rev() {
        push(&[*digit]);
    }
    push(b" 1\n");
    (buffer, len)
}

fn to_cstring(field: &'static str, value: impl AsRef<OsStr>) -> Result<CString, SandboxError> {
    CString::new(value.as_ref().as_bytes()).map_err(|_| {
        SandboxError::invalid(field, "contains a NUL byte and cannot be passed to the OS")
    })
}

fn make_pipe() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two fresh descriptors and marks them
    // close-on-exec atomically.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: both descriptors are fresh and uniquely owned.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn make_socketpair() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0_i32; 2];
    // SOCK_SEQPACKET preserves one fixed-size signal command per recv, while
    // SOCK_CLOEXEC keeps both transient endpoints out of successful execs.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result == -1 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Open a pidfd for a process that must remain the sandbox child's parent.
fn open_pidfd(pid: libc::pid_t) -> std::io::Result<OwnedFd> {
    // SAFETY: pid is the current process ID and flags are zero as required by
    // pidfd_open(2) on kernels that provide this syscall.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: a non-negative pidfd_open result is a fresh owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn random_suffix() -> Result<String, SandboxError> {
    let mut bytes = [0_u8; 8];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| {
            SandboxError::unsupported(
                "cgroup-v2",
                format!("/dev/urandom is unavailable for cgroup naming: {error}"),
            )
        })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Parent-side stdio endpoint bookkeeping.
struct StdioFds {
    /// Descriptors to close in the parent after clone (child-side ends we
    /// own: pipe ends and the shared /dev/null descriptor).
    owned: Vec<OwnedFd>,
    /// Pipe ends kept for the parent.
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    /// The three source descriptors handed to the child.
    sources: [RawFd; 3],
}

impl StdioFds {
    fn create(command: &CommandSpec) -> Result<Self, SandboxError> {
        let specs = [command.stdin, command.stdout, command.stderr];
        let mut owned: Vec<OwnedFd> = Vec::new();
        let mut sources = [0_i32; 3];
        let mut parent_ends: [Option<File>; 3] = [None, None, None];

        for (index, spec) in specs.iter().enumerate() {
            match *spec {
                Stdio::Null => {
                    if !owned.iter().any(is_devnull) {
                        // SAFETY: open of a fixed device path; a fresh
                        // descriptor on success.
                        let fd = unsafe {
                            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
                        };
                        if fd == -1 {
                            return Err(SandboxError::Io(std::io::Error::last_os_error()));
                        }
                        // SAFETY: fresh descriptor from open.
                        owned.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                    sources[index] = owned
                        .iter()
                        .find(|fd| is_devnull(fd))
                        .map(|fd| fd.as_raw_fd())
                        .expect("devnull just opened");
                }
                Stdio::Fd(fd) => {
                    // Borrowed: validated pre-spawn, owned by the caller.
                    sources[index] = fd;
                }
                Stdio::Pipe => {
                    let (child_end, parent_end) = pipe_end(index)?;
                    sources[index] = child_end.as_raw_fd();
                    owned.push(child_end);
                    parent_ends[index] = Some(File::from(parent_end));
                }
            }
        }
        Ok(StdioFds {
            owned,
            stdin: parent_ends[0].take(),
            stdout: parent_ends[1].take(),
            stderr: parent_ends[2].take(),
            sources,
        })
    }

    fn sources(&self) -> [RawFd; 3] {
        self.sources
    }

    fn close_parent_copies(&mut self) {
        self.owned.clear();
    }

    fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }
    fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }
    fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }
}

/// Whether the descriptor is the shared `/dev/null` source. Distinguishing
/// by path keeps the reopen logic honest without extra state.
fn is_devnull(fd: &OwnedFd) -> bool {
    let mut target = [0_u8; 64];
    let path = format!("/proc/self/fd/{}\0", fd.as_raw_fd());
    // SAFETY: readlink into a fixed buffer from a NUL-terminated path.
    let len = unsafe {
        libc::readlink(
            path.as_bytes().as_ptr().cast::<libc::c_char>(),
            target.as_mut_ptr().cast::<libc::c_char>(),
            target.len(),
        )
    };
    len > 0 && &target[..len as usize] == b"/dev/null"
}

/// Create one pipe, oriented per stream direction. Returns (child_end,
/// parent_end).
fn pipe_end(index: usize) -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let (read_end, write_end) = make_pipe()?;
    // index 0 is stdin: the child reads; every other stream the child writes.
    if index == 0 {
        Ok((read_end, write_end))
    } else {
        Ok((write_end, read_end))
    }
}

/// The Linux child handle: pidfd-first lifecycle (architecture Phase 9).
struct LinuxChild {
    pid: i32,
    pidfd: OwnedFd,
    cgroup: Option<Arc<Cgroup>>,
    status: Option<ExitStatus>,
    torn_down: bool,
    /// Whether this spawn successfully created a process group of its own.
    /// `SessionSetup::Inherit` intentionally leaves this false: the daemon's
    /// group is not a sandbox-owned signalling target.
    owns_process_group: bool,
    /// A child created with CLONE_NEWPID is PID 1 in its new namespace.
    /// Killing that init process makes the kernel terminate the namespace's
    /// remaining processes as part of PID-namespace teardown.
    pid_namespace_init: bool,
    /// Parent endpoint used to ask PID1 to signal the logical user process.
    supervisor_control: Option<OwnedFd>,
    /// Parent endpoint carrying the logical user process's normalized exit.
    supervisor_exit: Option<OwnedFd>,
}

impl BackendChild for LinuxChild {
    fn id(&self) -> u32 {
        self.pid as u32
    }

    fn signal(&self, number: i32) -> std::io::Result<()> {
        if let Some(control) = self.supervisor_control.as_ref() {
            send_supervisor_signal(control, child::SUPERVISOR_SIGNAL_DIRECT, number)
        } else {
            pidfd_send_signal(&self.pidfd, number)
        }
    }

    fn signal_process_group(&self, number: i32) -> std::io::Result<()> {
        if !self.owns_process_group || self.pid <= 1 {
            return Ok(());
        }
        if let Some(control) = self.supervisor_control.as_ref() {
            return send_supervisor_signal(control, child::SUPERVISOR_SIGNAL_GROUP, number);
        }
        // SAFETY: negative pid addresses exactly one process group; the
        // child is its session-group leader under NewSession setups.
        let result = unsafe { libc::kill(-(self.pid as libc::pid_t), number) };
        if result == -1 && raw_errno() != libc::ESRCH {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // Normal completion reaps exactly the direct child. Descendants —
        // background jobs, `setsid()` escapees, daemons — belong to the
        // sandbox's process domain, not to this handle, and survive.
        let waited = pidfd_wait(&self.pidfd, false)?
            .map(|result| result.exit)
            .unwrap_or_else(|| ExitStatus::from_code(255));
        let status = if self.pid_namespace_init {
            let exit_fd = self.supervisor_exit.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing PID-namespace supervisor exit channel",
                )
            })?;
            read_supervisor_exit(exit_fd)?
        } else {
            waited
        };
        self.status = Some(status);
        Ok(status)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let Some(waited) = pidfd_wait(&self.pidfd, true)? else {
            return Ok(None);
        };
        let status = if self.pid_namespace_init {
            let exit_fd = self.supervisor_exit.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing PID-namespace supervisor exit channel",
                )
            })?;
            read_supervisor_exit(exit_fd)?
        } else {
            waited.exit
        };
        self.status = Some(status);
        Ok(Some(status))
    }

    fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        let was_running = self.status.is_none();
        if was_running {
            if self.pid_namespace_init {
                // The direct child is PID 1 in this namespace. A pidfd
                // SIGKILL to it is the safe descendant teardown operation;
                // the kernel terminates the rest of that PID namespace when
                // its init process exits.
                let _ = pidfd_send_signal(&self.pidfd, libc::SIGKILL);
            } else {
                if self.owns_process_group {
                    let _ = self.signal_process_group(libc::SIGKILL);
                }
                let _ = self.signal(libc::SIGKILL);
            }
            // Bounded reap: a wedged child must not hang a Drop path. An
            // unreaped remainder stays owned by PDEATHSIG + pidfd until the
            // daemon itself exits and init reaps it.
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline {
                match pidfd_wait(&self.pidfd, true) {
                    Ok(Some(waited)) => {
                        self.status = Some(waited.exit);
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        }
        if let Some(cgroup) = self.cgroup.take() {
            // Only a private one-shot cgroup may be killed as part of an
            // abandoned child handle. Its last Arc owner proves that no
            // durable process-domain owner remains. Shared process-domain
            // cgroups outlive individual children and are removed only by
            // their explicit owner; cgroup membership, not Arc counts, is
            // authoritative for their lifecycle.
            if was_running && Arc::strong_count(&cgroup) == 1 {
                let _ = cgroup.kill_all();
            }
            drop(cgroup);
        }
        self.supervisor_control.take();
        self.supervisor_exit.take();
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_map_formats_without_allocation() {
        let (buffer, len) = format_identity_map(1000);
        assert_eq!(&buffer[..len], b"0 1000 1\n");
        let (buffer, len) = format_identity_map(0);
        assert_eq!(&buffer[..len], b"0 0 1\n");
        let (buffer, len) = format_identity_map(u32::MAX as u64);
        assert_eq!(
            &buffer[..len],
            format!("0 {} 1\n", u32::MAX as u64).as_bytes()
        );
    }

    #[test]
    fn namespace_flags_follow_policy() {
        let mut config = SandboxConfig::unrestricted();
        assert_eq!(namespace_flags(&config), 0);
        config.identity = IdentityPolicy::CallerMappedRoot;
        assert_eq!(namespace_flags(&config), CLONE_NEWUSER);
        config.namespaces.network = NetworkNamespacePolicy::Isolated;
        config.namespaces.uts = true;
        assert_eq!(
            namespace_flags(&config),
            CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWUTS
        );
    }

    #[test]
    fn isolated_identity_requires_mount_namespace_and_zero_free_ids() {
        let identity = IdentityPolicy::Isolated(crate::policy::IsolatedIdentity {
            runtime_uid: 1000,
            runtime_gid: 1000,
            host_uid: 100_000,
            host_gid: 200_000,
        });
        let mut config = SandboxConfig::unrestricted();
        config.identity = identity;
        // Validation: a fresh mount namespace is part of the isolated
        // contract (ID-mapped writable views replace the inherited ones).
        let command = || CommandSpec::new("/bin/true");
        assert!(crate::validate::validate(&config, &command()).is_err());
        config.namespaces.mount = true;
        assert!(crate::validate::validate(&config, &command()).is_ok());
        // Flags: the fresh user namespace comes from the identity policy.
        assert_eq!(namespace_flags(&config), CLONE_NEWUSER | CLONE_NEWNS);
        // Construction: the child setup carries the isolated identity with
        // its barrier descriptors; the launcher's own credentials are
        // rejected as host IDs.
        let setup = build_child_setup(
            command(),
            &config,
            Some((10, 11)),
            [0, 1, 2],
            3,
            None,
            None,
            None,
            None,
            None,
            None,
            seccomp::compile(&crate::policy::SyscallPolicy::Unrestricted).expect("compile"),
        )
        .expect("isolated child setup");
        assert!(matches!(
            setup.identity,
            child::ChildIdentity::Isolated {
                runtime_uid: 1000,
                runtime_gid: 1000,
                ready_write: 10,
                installed_read: 11,
            }
        ));
        let own = IdentityPolicy::Isolated(crate::policy::IsolatedIdentity {
            host_uid: unsafe { libc::geteuid() },
            ..identity_or_default()
        });
        config.identity = own;
        let error = match build_child_setup(
            command(),
            &config,
            Some((10, 11)),
            [0, 1, 2],
            3,
            None,
            None,
            None,
            None,
            None,
            None,
            seccomp::compile(&crate::policy::SyscallPolicy::Unrestricted).expect("compile"),
        ) {
            Ok(_) => panic!("launcher's own UID must be rejected as a host ID"),
            Err(error) => error,
        };
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

    fn identity_or_default() -> crate::policy::IsolatedIdentity {
        crate::policy::IsolatedIdentity {
            runtime_uid: 1000,
            runtime_gid: 1000,
            host_uid: 100_000,
            host_gid: 200_000,
        }
    }
}
