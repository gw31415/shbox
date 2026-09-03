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

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use crate::command::{CommandSpec, SessionSetup, Stdio};
use crate::error::{ExitStatus, SandboxError};
use crate::policy::{CgroupParent, NetworkNamespacePolicy, ResourceLimits, SandboxConfig};
use crate::{BackendChild, Platform, SandboxCapabilities, SandboxChild};

use cgroup::{Cgroup, create_sandbox_cgroup};
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
    command: CommandSpec,
    config: SandboxConfig,
    sandbox_cgroup: Option<Arc<Cgroup>>,
    reply: mpsc::SyncSender<Result<SandboxChild, SandboxError>>,
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
                        request.command,
                        request.config,
                        request.sandbox_cgroup,
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
pub fn detect_capabilities(explicit_parent: Option<&CgroupParent>) -> SandboxCapabilities {
    SandboxCapabilities {
        platform: Platform::Linux,
        landlock_abi: landlock::probe_abi(),
        cgroup_v2_root: cgroup::current_cgroup_path()
            .or_else(|| explicit_parent.map(|parent| parent.path().to_path_buf())),
        seatbelt_available: false,
    }
}

/// The immutable Linux backend state.
pub struct LinuxBackend {
    landlock_abi: Option<u32>,
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
    pub(crate) fn new(capabilities: &SandboxCapabilities) -> Self {
        LinuxBackend {
            landlock_abi: capabilities.landlock_abi,
        }
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
        self.spawn_with_cgroup(command, config, sandbox_cgroup)
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
            cgroup: Arc::new(create_sandbox_cgroup(
                &resources,
                explicit_parent,
                &random_suffix()?,
            )?),
            resources,
        })
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
        self.spawn_with_cgroup(command, config, Some(Arc::clone(&domain.cgroup)))
    }

    fn spawn_with_cgroup(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
        sandbox_cgroup: Option<Arc<Cgroup>>,
    ) -> Result<SandboxChild, SandboxError> {
        let (reply, response) = mpsc::sync_channel(1);
        spawn_owner()?
            .send(SpawnRequest {
                landlock_abi: self.landlock_abi,
                command,
                config,
                sandbox_cgroup,
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
    command: CommandSpec,
    config: SandboxConfig,
    sandbox_cgroup: Option<Arc<Cgroup>>,
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
            stdio.close_parent_copies();

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
    if config.namespaces.user {
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

/// Observe whether the direct child has exited without reaping it.
///
/// Keeping an exited group leader unreaped until after the group signal closes
/// the small PID-reuse window that a raw process-group ID would otherwise
/// have after `waitid(WEXITED)` reaps the direct child.
fn pidfd_has_exited(pidfd: &OwnedFd, nohang: bool) -> std::io::Result<bool> {
    // SAFETY: `siginfo_t` is a C struct of integers, fixed-size arrays, and
    // raw pointers — all-zero is a valid value, and `waitid` only writes to
    // it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let mut options = libc::WEXITED | libc::WNOWAIT;
    if nohang {
        options |= libc::WNOHANG;
    }
    // SAFETY: `info` is initialized writable storage and the pidfd belongs to
    // this direct child. WNOWAIT observes the exit without consuming it.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD as libc::idtype_t,
            pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            options,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if nohang {
        // SAFETY: siginfo field access on an initialized structure.
        Ok(unsafe { info.si_pid() } != 0)
    } else {
        Ok(true)
    }
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

/// Build the complete child setup from validated inputs.
#[allow(clippy::too_many_arguments)]
fn build_child_setup(
    command: CommandSpec,
    config: &SandboxConfig,
    stdio: [RawFd; 3],
    status_write: RawFd,
    parent_pidfd: Option<RawFd>,
    supervisor_control_fd: Option<RawFd>,
    supervisor_exit_fd: Option<RawFd>,
    user_cgroup_fd: Option<RawFd>,
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
    let report_guard = inherited_fds.last().map_or(3, |fd| (fd + 1).max(3));

    // User-namespace identity mapping: outer euid/egid become uid/gid 0
    // inside the new namespace (the `unshare --map-root-user` model).
    let (uid_map, uid_map_len) = format_identity_map(unsafe { libc::geteuid() } as u64);
    let (gid_map, gid_map_len) = format_identity_map(unsafe { libc::getegid() } as u64);
    let with_userns = config.namespaces.user;

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
        uid_map: with_userns.then_some(uid_map),
        uid_map_len: if with_userns { uid_map_len } else { 0 },
        gid_map,
        gid_map_len: if with_userns { gid_map_len } else { 0 },
        deny_setgroups: with_userns,
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
                    // SAFETY: parent_end is a fresh owned descriptor.
                    parent_ends[index] = Some(unsafe { File::from_raw_fd(parent_end.as_raw_fd()) });
                    std::mem::forget(parent_end);
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
        if self.owns_process_group && !self.pid_namespace_init {
            // Observe without reaping so the direct child still reserves its
            // PID while the owned process group is cleaned up.
            pidfd_has_exited(&self.pidfd, false)?;
            let _ = self.signal_process_group(libc::SIGKILL);
        }
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
        if self.owns_process_group
            && !self.pid_namespace_init
            && !pidfd_has_exited(&self.pidfd, true)?
        {
            return Ok(None);
        }
        if self.owns_process_group && !self.pid_namespace_init {
            let _ = self.signal_process_group(libc::SIGKILL);
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
            // A per-launch cgroup (this handle is the last owner) that is
            // being abandoned still terminates its members: nobody else can.
            // Shared process-domain cgroups outlive individual children and
            // are removed only by the domain's explicit owner.
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
        config.namespaces.user = true;
        assert_eq!(namespace_flags(&config), CLONE_NEWUSER);
        config.namespaces.network = NetworkNamespacePolicy::Isolated;
        config.namespaces.uts = true;
        assert_eq!(
            namespace_flags(&config),
            CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWUTS
        );
    }
}
