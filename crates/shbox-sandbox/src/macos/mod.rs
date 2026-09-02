//! macOS best-effort backend (architecture Phase 10).
//!
//! The same public API as the Linux backend, backed by a generated Seatbelt
//! profile enforced through the OS-provided `/usr/bin/sandbox-exec`
//! launcher. macOS is *local development isolation*, not a production
//! security boundary: Seatbelt's in-process API is deprecated with no
//! stable replacement, and this backend deliberately uses the OS component
//! rather than guessing at private symbol signatures.
//!
//! Linux-only policy fields are rejected explicitly
//! ([`SandboxError::Unsupported`]) — never silently ignored:
//!
//! * any namespace,
//! * any seccomp filter,
//! * retained capabilities,
//! * cgroup-backed limits that `setrlimit` cannot express (`cpu.max`
//!   quotas, `memory.swap.max`).
//!
//! What macOS *can* express is mapped: filesystem and network policies to
//! Seatbelt rules, `memory_bytes` to `RLIMIT_AS`, and `pids` to
//! `RLIMIT_NPROC`.

mod seatbelt;

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::command::{CommandSpec, Stdio};
use crate::error::{ChildStage, ExitStatus, SandboxError};
use crate::policy::{CapabilityPolicy, Limit, SandboxConfig, SyscallPolicy};
use crate::{BackendChild, Platform, SandboxCapabilities, SandboxChild};

use seatbelt::build_profile;

/// The OS-provided Seatbelt launcher this backend execs.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// macOS lacks an atomic `pipe2(O_CLOEXEC)` in every libc surface this crate
/// targets, so descriptor creation and the fork are serialized process-wide
/// within the crate, mirroring the shbox-audited launcher.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// The kernel's errno for the calling thread.
fn raw_errno() -> i32 {
    // SAFETY: __error returns the calling thread's errno slot on Darwin.
    unsafe { *libc::__error() }
}

/// Detect Seatbelt availability.
pub fn detect_capabilities() -> SandboxCapabilities {
    SandboxCapabilities {
        platform: Platform::MacOs,
        landlock_abi: None,
        cgroup_v2_root: None,
        seatbelt_available: launcher_is_executable(),
    }
}

fn launcher_is_executable() -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(SANDBOX_EXEC)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The immutable macOS backend state.
pub struct MacosBackend {
    available: bool,
}

impl MacosBackend {
    pub(crate) fn new(capabilities: &SandboxCapabilities) -> Self {
        MacosBackend {
            available: capabilities.seatbelt_available,
        }
    }

    pub(crate) fn spawn(
        &self,
        command: CommandSpec,
        config: SandboxConfig,
    ) -> Result<SandboxChild, SandboxError> {
        if !self.available {
            return Err(SandboxError::unsupported(
                "seatbelt",
                format!("{SANDBOX_EXEC} is missing or not executable"),
            ));
        }
        reject_linux_only_policy(&config)?;
        let profile = build_profile(&config.filesystem, config.network, command.session)?;
        let resource_limits = resolve_resource_limits(&config)?;

        let _spawn_guard = SPAWN_LOCK
            .lock()
            .map_err(|_| SandboxError::Internal("spawn lock poisoned".to_string()))?;

        let mut stdio = StdioFds::create(&command)?;
        let (status_read, status_write) = make_pipe()?;

        // sandbox-exec argv: -p PROFILE [--] program args...
        let mut argv_owned = Vec::with_capacity(command.args.len() + 4);
        argv_owned.push(to_cstring("argv", SANDBOX_EXEC)?);
        argv_owned.push(to_cstring("argv", "-p")?);
        argv_owned.push(to_cstring_lossy(&profile)?);
        match &command.argv0 {
            Some(argv0) => {
                // sandbox-exec derives the child's argv[0] from the command
                // path, so an explicit argv[0] needs one /bin/sh exec hop;
                // `exec` keeps the same PID for supervision and signaling.
                // The hop takes a UTF-8 shell script string, so non-UTF-8
                // values are rejected rather than corrupted.
                let mut wrapper = String::from("exec -a ");
                wrapper.push_str(&seatbelt::sh_single_quote(utf8(
                    "argv0",
                    argv0.as_os_str(),
                )?));
                wrapper.push(' ');
                wrapper.push_str(&seatbelt::sh_single_quote(utf8(
                    "argv",
                    command.program.as_os_str(),
                )?));
                for arg in &command.args {
                    wrapper.push(' ');
                    wrapper.push_str(&seatbelt::sh_single_quote(utf8("argv", arg.as_os_str())?));
                }
                argv_owned.push(to_cstring("argv", "/bin/sh")?);
                argv_owned.push(to_cstring("argv", "-c")?);
                argv_owned.push(to_cstring("argv", &wrapper)?);
            }
            None => {
                argv_owned.push(to_cstring("argv", &command.program)?);
                for arg in &command.args {
                    argv_owned.push(to_cstring("argv", arg)?);
                }
            }
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

        let cwd = command
            .cwd
            .as_deref()
            .map(|cwd| to_cstring("cwd", cwd))
            .transpose()?;
        let mut inherited_fds = config.inherited_fds;
        inherited_fds.sort_unstable();
        inherited_fds.dedup();
        let report_guard = inherited_fds.last().map_or(3, |fd| (fd + 1).max(3));

        let mut setup = ChildSetup {
            stdin_fd: stdio.sources()[0],
            stdout_fd: stdio.sources()[1],
            stderr_fd: stdio.sources()[2],
            report_fd: status_write.as_raw_fd(),
            report_guard,
            inherited_fds,
            session: command.session,
            cwd,
            resource_limits,
            program: to_cstring("argv", SANDBOX_EXEC)?,
            argv_owned,
            envp_owned,
            argv,
            envp,
        };

        // SAFETY: the child setup runs between fork and exec and performs
        // only raw syscalls on parent-prepared values.
        let fork_result = unsafe { libc::fork() };
        if fork_result == -1 {
            drop(status_read);
            drop(status_write);
            return Err(SandboxError::Io(io::Error::last_os_error()));
        }
        if fork_result == 0 {
            unsafe { child_entry(&mut setup) }
        }
        let pid = fork_result;

        // The child has its own descriptor-table view; drop the parent's
        // copies of child-side endpoints.
        drop(status_write);
        stdio.close_parent_copies();

        // EOF on the status pipe means the Seatbelt launcher itself was
        // exec'd; confinement applies before the user program runs inside
        // it. A record means the pre-exec setup chain failed.
        let mut record = [0_u8; 12];
        let mut offset = 0_usize;
        let outcome: Result<Option<(u8, u8, i32)>, String> = loop {
            // SAFETY: status_read is owned and the record is initialized.
            let count = unsafe {
                libc::read(
                    status_read.as_raw_fd(),
                    record[offset..].as_mut_ptr().cast(),
                    record.len() - offset,
                )
            };
            if count == 0 {
                break Ok(None);
            }
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break Err(format!("sandbox child status could not be read: {error}"));
            }
            offset += count as usize;
            if offset == record.len() {
                if &record[0..4] != b"SBX1" {
                    break Err("sandbox child returned an invalid setup status".to_string());
                }
                let errno =
                    i32::from_ne_bytes(record[8..12].try_into().expect("fixed errno field"));
                break Ok(Some((record[4], record[5], errno)));
            }
        };
        drop(status_read);
        match outcome {
            Ok(None) => {}
            Ok(Some((stage_code, detail, errno))) => {
                kill_and_reap(pid);
                let stage = ChildStage::from_code(stage_code);
                return Err(match stage {
                    Some(stage) => SandboxError::Setup {
                        stage,
                        detail,
                        errno: Some(errno),
                    },
                    None => SandboxError::Internal(format!(
                        "sandbox child reported unknown stage {stage_code}"
                    )),
                });
            }
            Err(message) => {
                kill_and_reap(pid);
                return Err(SandboxError::Internal(message));
            }
        }

        let macos_child = MacosChild {
            pid,
            status: None,
            torn_down: false,
        };
        Ok(SandboxChild::new(
            Box::new(macos_child),
            stdio.take_stdin(),
            stdio.take_stdout(),
            stdio.take_stderr(),
        ))
    }
}

/// Reject policy the platform cannot express. Explicit failure, never
/// silent degradation.
fn reject_linux_only_policy(config: &SandboxConfig) -> Result<(), SandboxError> {
    let namespaces = &config.namespaces;
    if namespaces.user
        || namespaces.pid
        || namespaces.mount
        || namespaces.ipc
        || namespaces.uts
        || namespaces.network != crate::policy::NetworkNamespacePolicy::Host
    {
        return Err(SandboxError::unsupported(
            "namespace",
            "namespaces do not exist on macOS; the requested isolation cannot be provided",
        ));
    }
    if !matches!(config.syscalls, SyscallPolicy::Unrestricted) {
        return Err(SandboxError::unsupported(
            "seccomp",
            "syscall filtering is not available on macOS",
        ));
    }
    if let CapabilityPolicy::Retain(retained) = &config.capabilities
        && !retained.is_empty()
    {
        return Err(SandboxError::unsupported(
            "capabilities",
            "retaining Linux capabilities is meaningless on macOS",
        ));
    }
    if !matches!(config.resources.cpu_max, Limit::Inherit) {
        return Err(SandboxError::unsupported(
            "cpu-quota",
            "cgroup cpu.max quotas cannot be expressed on macOS",
        ));
    }
    if !matches!(config.resources.swap_bytes, Limit::Inherit) {
        return Err(SandboxError::unsupported(
            "swap-limit",
            "cgroup memory.swap.max cannot be expressed on macOS",
        ));
    }
    Ok(())
}

/// Map expressible limits to rlimits.
fn resolve_resource_limits(
    config: &SandboxConfig,
) -> Result<Vec<(i32, libc::rlimit)>, SandboxError> {
    let mut limits = Vec::new();
    let infinity = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    match config.resources.memory_bytes {
        Limit::Value(bytes) => limits.push((
            libc::RLIMIT_AS,
            libc::rlimit {
                rlim_cur: bytes.min(libc::RLIM_INFINITY) as libc::rlim_t,
                rlim_max: bytes.min(libc::RLIM_INFINITY) as libc::rlim_t,
            },
        )),
        Limit::Unlimited => limits.push((libc::RLIMIT_AS, infinity)),
        Limit::Inherit => {}
    }
    match config.resources.pids {
        Limit::Value(count) => limits.push((
            libc::RLIMIT_NPROC,
            libc::rlimit {
                rlim_cur: u64::from(count).min(libc::RLIM_INFINITY) as libc::rlim_t,
                rlim_max: u64::from(count).min(libc::RLIM_INFINITY) as libc::rlim_t,
            },
        )),
        Limit::Unlimited => limits.push((libc::RLIMIT_NPROC, infinity)),
        Limit::Inherit => {}
    }
    Ok(limits)
}

/// Everything the child needs, prepared by the parent.
struct ChildSetup {
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    report_fd: RawFd,
    report_guard: RawFd,
    inherited_fds: Vec<RawFd>,
    session: crate::command::SessionSetup,
    cwd: Option<CString>,
    resource_limits: Vec<(i32, libc::rlimit)>,
    program: CString,
    /// Owned argument strings; kept alive for the child's pointer array.
    #[expect(dead_code, reason = "the child reads the strings via `argv`")]
    argv_owned: Vec<CString>,
    /// Owned environment strings; kept alive for the child's pointer array.
    #[expect(dead_code, reason = "the child reads the strings via `envp`")]
    envp_owned: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
}

/// Duplicate all standard-stream sources before any standard slot is changed.
///
/// This is intentionally allocation-free: it runs after `fork`, and the
/// returned error contains only fixed-size scalar values. Every successful
/// duplicate is above fd 2, so a later `dup2` into fd 0, 1, or 2 cannot alter a
/// source that is still needed.
///
/// Runs in the child between `fork` and `execve`; every source must be an
/// open descriptor in this process (a stale one reports `(index, EBADF)`).
fn duplicate_stdio_sources(sources: [RawFd; 3]) -> Result<[RawFd; 3], (u8, i32)> {
    let mut duplicates = [-1_i32; 3];
    for (index, source) in sources.into_iter().enumerate() {
        // SAFETY: the caller guarantees that source is an open descriptor in
        // this process; F_DUPFD_CLOEXEC searches above the standard slots.
        let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate == -1 {
            let errno = raw_errno();
            for fd in duplicates.into_iter().take(index) {
                // SAFETY: every earlier entry is a descriptor duplicated by
                // this function and has not been handed to a target slot.
                unsafe { libc::close(fd) };
            }
            return Err((index as u8, errno));
        }
        duplicates[index] = duplicate;
    }
    Ok(duplicates)
}

/// The child-side setup chain: stdio, session, ctty, chdir, rlimits,
/// descriptor hygiene, execve. Raw syscalls only.
///
/// # Safety
///
/// Must run in the child between `fork` and `execve`.
unsafe fn child_entry(setup: &mut ChildSetup) -> ! {
    let report_fd = setup.report_fd;
    let fail_at = |report_fd: RawFd, stage: ChildStage, detail: u8, errno: i32| -> ! {
        let mut record = [0_u8; 12];
        record[0..4].copy_from_slice(b"SBX1");
        record[4] = stage.code();
        record[5] = detail;
        record[8..12].copy_from_slice(&errno.to_ne_bytes());
        let mut offset = 0_usize;
        while offset < record.len() {
            // SAFETY: the report fd is an inherited pipe endpoint; the
            // pointer stays inside the fixed stack record.
            let written = unsafe {
                libc::write(
                    report_fd,
                    record.as_ptr().add(offset).cast(),
                    record.len() - offset,
                )
            };
            if written > 0 {
                offset += written as usize;
            } else if written < 0 && raw_errno() == libc::EINTR {
                continue;
            } else {
                break;
            }
        }
        // SAFETY: post-fork failure path must not run Rust destructors.
        unsafe { libc::_exit(126) }
    };

    // Snapshot every source before changing any standard slot. A caller may
    // intentionally map standard descriptors in a cycle (for example,
    // stdin <- 1, stdout <- 2, stderr <- 0); sequential dup2 calls would
    // otherwise overwrite a source before it is consumed. The snapshots are
    // also separate descriptors when multiple streams intentionally alias
    // one source, so installing one target cannot affect another snapshot.
    let stdio_sources =
        match duplicate_stdio_sources([setup.stdin_fd, setup.stdout_fd, setup.stderr_fd]) {
            Ok(sources) => sources,
            Err((index, errno)) => fail_at(report_fd, ChildStage::Session, index, errno),
        };
    for (source, target) in stdio_sources.into_iter().zip(0..3) {
        // SAFETY: both descriptors belong to this process.
        if unsafe { libc::dup2(source, target) } == -1 {
            fail_at(report_fd, ChildStage::Session, 0, raw_errno());
        }
    }
    for source in stdio_sources {
        // SAFETY: each descriptor was duplicated immediately above.
        unsafe { libc::close(source) };
    }
    if !matches!(setup.session, crate::command::SessionSetup::Inherit) {
        // SAFETY: no-argument session creation.
        if unsafe { libc::setsid() } == -1 {
            fail_at(report_fd, ChildStage::Session, 1, raw_errno());
        }
        if matches!(
            setup.session,
            crate::command::SessionSetup::NewSessionWithControllingTerminal
        ) {
            // SAFETY: ioctl on the freshly installed standard input.
            if unsafe {
                libc::ioctl(
                    0,
                    libc::TIOCSCTTY as libc::c_ulong,
                    std::ptr::null_mut::<libc::c_void>(),
                )
            } == -1
            {
                fail_at(report_fd, ChildStage::ControllingTerminal, 0, raw_errno());
            }
        }
    }
    if let Some(cwd) = &setup.cwd {
        // SAFETY: the CString is inherited parent memory with a NUL.
        if unsafe { libc::chdir(cwd.as_ptr()) } == -1 {
            fail_at(report_fd, ChildStage::WorkingDirectory, 0, raw_errno());
        }
    }
    for (resource, limit) in &setup.resource_limits {
        // SAFETY: limit points at an inherited, initialized rlimit.
        if unsafe { libc::setrlimit(*resource, limit) } == -1 {
            fail_at(report_fd, ChildStage::ResourceLimits, 0, raw_errno());
        }
    }

    // Descriptor hygiene: move the report fd to its guard slot, mark it
    // close-on-exec (its closure at exec is the parent's success signal),
    // then close everything except stdio, the guard, and the explicitly
    // inherited descriptors. Darwin's F_MAXFD bounds the loop tightly.
    // SAFETY: dup2 within this process.
    if unsafe { libc::dup2(setup.report_fd, setup.report_guard) } == -1 {
        fail_at(report_fd, ChildStage::FdHygiene, 0, raw_errno());
    }
    let guard = setup.report_guard;
    // SAFETY: fcntl on the guard descriptor.
    if unsafe { libc::fcntl(guard, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        fail_at(report_fd, ChildStage::FdHygiene, 2, raw_errno());
    }
    // SAFETY: F_MAXFD probes the highest open descriptor number.
    // Darwin's F_MAXFD (41) reports the highest open descriptor number.
    const F_MAXFD: libc::c_int = 41;
    let max_fd = unsafe { libc::fcntl(0, F_MAXFD) };
    let limit = if max_fd >= 0 { max_fd } else { 1024 };
    for fd in 3..=limit {
        if fd == guard {
            continue;
        }
        if setup.inherited_fds.contains(&fd) {
            // Inherited descriptors must survive execve; clear any
            // close-on-exec flag the parent had set on them.
            // SAFETY: fcntl reads/updates flags of an open descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags != -1 {
                // SAFETY: fcntl updates only the close-on-exec bit.
                unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            }
            continue;
        }
        // SAFETY: closing a descriptor this process owns; EBADF is fine.
        unsafe { libc::close(fd) };
    }

    // SAFETY: program/argv/envp are inherited parent allocations with NUL
    // terminators and trailing null entries. A return means failure,
    // reported through the guard (the original report descriptor may
    // already have been closed by the loop above).
    unsafe {
        libc::execve(
            setup.program.as_ptr(),
            setup.argv.as_ptr(),
            setup.envp.as_ptr(),
        )
    };
    fail_at(guard, ChildStage::Exec, 0, raw_errno())
}

fn kill_and_reap(pid: i32) {
    // SAFETY: pid is our direct child from fork.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(pid as libc::pid_t, &mut status, 0) == -1 && raw_errno() == libc::EINTR
        {
        }
    }
}

fn to_cstring(field: &'static str, value: impl AsRef<OsStr>) -> Result<CString, SandboxError> {
    CString::new(value.as_ref().as_bytes()).map_err(|_| {
        SandboxError::invalid(field, "contains a NUL byte and cannot be passed to the OS")
    })
}

/// The argv[0] wrapper routes through `/bin/sh -c`, which takes a UTF-8
/// script string; unlike the raw exec path (bytes passed through), a
/// non-UTF-8 value is rejected rather than silently corrupted.
fn utf8<'a>(field: &'static str, value: &'a OsStr) -> Result<&'a str, SandboxError> {
    std::str::from_utf8(value.as_bytes()).map_err(|_| {
        SandboxError::invalid(
            field,
            "is not valid UTF-8; an argv0 override on macOS routes through /bin/sh",
        )
    })
}

fn to_cstring_lossy(value: impl AsRef<str>) -> Result<CString, SandboxError> {
    CString::new(value.as_ref().as_bytes())
        .map_err(|_| SandboxError::Internal("string contained NUL".to_string()))
}

/// Duplicate a caller-owned descriptor into a private descriptor above the
/// standard-stream slots. The caller retains ownership of the original.
fn duplicate_fd_above_stdio(fd: RawFd) -> Result<RawFd, SandboxError> {
    // SAFETY: fcntl duplicates the caller's open descriptor and sets
    // close-on-exec on the private copy.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate == -1 {
        Err(SandboxError::Io(io::Error::last_os_error()))
    } else {
        Ok(duplicate)
    }
}

/// Open one private `/dev/null` endpoint for a `Stdio::Null` stream.
fn open_dev_null() -> Result<OwnedFd, SandboxError> {
    // SAFETY: the path is a fixed NUL-terminated string and the resulting
    // descriptor is marked close-on-exec before the fork.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd == -1 {
        return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    if fd < 3 {
        let duplicate = duplicate_fd_above_stdio(fd);
        // SAFETY: fd is the fresh descriptor opened immediately above.
        unsafe { libc::close(fd) };
        return duplicate.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    }
    // SAFETY: fd is a fresh descriptor returned by open and is now owned.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn make_pipe() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0; 2];
    // SAFETY: pipe writes two fresh descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    // The report pipe must not occupy a standard slot: stdio remapping may
    // overwrite all of 0, 1, and 2 before setup failures are reported.
    // Normalize pipe endpoints here as well, since a caller may have closed
    // one of those slots before spawning.
    for index in 0..fds.len() {
        if fds[index] < 3 {
            let original = fds[index];
            let duplicate = match duplicate_fd_above_stdio(original) {
                Ok(duplicate) => duplicate,
                Err(error) => {
                    // SAFETY: both entries still identify the pipe endpoints;
                    // any endpoint already moved is stored in `fds`.
                    unsafe {
                        libc::close(fds[0]);
                        libc::close(fds[1]);
                    }
                    return Err(error);
                }
            };
            // SAFETY: original is the endpoint just duplicated.
            unsafe { libc::close(original) };
            fds[index] = duplicate;
        }
    }
    // Darwin has no atomic close-on-exec pipe creation in the supported
    // surface; set the flag on both ends while the spawn lock is held.
    for fd in fds {
        // SAFETY: fcntl reads flags of a fresh, valid descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1
            // SAFETY: fcntl updates only the close-on-exec bit.
            || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
        {
            let error = io::Error::last_os_error();
            // SAFETY: close both fresh descriptors on the failure path.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(SandboxError::Io(error));
        }
    }
    // SAFETY: both descriptors are fresh and uniquely owned.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Parent-side stdio endpoint bookkeeping.
struct StdioFds {
    owned: Vec<OwnedFd>,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
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
                    let null_fd = open_dev_null()?;
                    sources[index] = null_fd.as_raw_fd();
                    // Each Null stream gets its own fresh descriptor. It is
                    // never selected from the pipe endpoints in `owned`.
                    owned.push(null_fd);
                }
                Stdio::Fd(fd) => {
                    // Keep a private source copy for the whole fork window.
                    // Besides preserving a caller-supplied alias/cycle, this
                    // prevents a later internal fd allocation from ever
                    // reusing a source number if the caller closes its fd.
                    let source = duplicate_fd_above_stdio(fd)?;
                    sources[index] = source;
                    // SAFETY: source is a fresh descriptor returned by
                    // F_DUPFD_CLOEXEC and is now owned by this vector.
                    owned.push(unsafe { OwnedFd::from_raw_fd(source) });
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

fn pipe_end(index: usize) -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let (read_end, write_end) = make_pipe()?;
    if index == 0 {
        Ok((read_end, write_end))
    } else {
        Ok((write_end, read_end))
    }
}

/// The macOS child handle: waitpid-based lifecycle (pidfd does not exist on
/// Darwin; PID-reuse races are part of the documented best-effort posture).
struct MacosChild {
    pid: i32,
    status: Option<ExitStatus>,
    torn_down: bool,
}

impl MacosChild {
    fn waitpid(&self, nohang: bool) -> io::Result<Option<ExitStatus>> {
        let mut raw: libc::c_int = 0;
        let options = if nohang { libc::WNOHANG } else { 0 };
        // SAFETY: pid is our direct child and raw is initialized storage.
        let result = unsafe { libc::waitpid(self.pid, &mut raw, options) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return self.waitpid(nohang);
            }
            return Err(error);
        }
        if result == 0 {
            return Ok(None);
        }
        if libc::WIFEXITED(raw) {
            Ok(Some(ExitStatus::from_code(libc::WEXITSTATUS(raw))))
        } else if libc::WIFSIGNALED(raw) {
            Ok(Some(ExitStatus::from_signal(
                libc::WTERMSIG(raw),
                libc::WCOREDUMP(raw),
            )))
        } else {
            Ok(Some(ExitStatus::from_code(255)))
        }
    }
}

impl BackendChild for MacosChild {
    fn id(&self) -> u32 {
        self.pid as u32
    }

    fn signal(&self, number: i32) -> io::Result<()> {
        // SAFETY: signal to a pid we own.
        if unsafe { libc::kill(self.pid as libc::pid_t, number) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn signal_process_group(&self, number: i32) -> io::Result<()> {
        if self.pid <= 1 {
            return Ok(());
        }
        // SAFETY: negative pid addresses the child's process group; the
        // child called setsid before exec under NewSession setups.
        let result = unsafe { libc::kill(-(self.pid as libc::pid_t), number) };
        if result == -1 && raw_errno() != libc::ESRCH {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = self
            .waitpid(false)?
            .unwrap_or_else(|| ExitStatus::from_code(255));
        self.status = Some(status);
        Ok(status)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let Some(status) = self.waitpid(true)? else {
            return Ok(None);
        };
        self.status = Some(status);
        Ok(Some(status))
    }

    fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        if self.status.is_none() {
            let _ = self.signal_process_group(libc::SIGKILL);
            let _ = self.signal(libc::SIGKILL);
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline {
                match self.waitpid(true) {
                    Ok(Some(status)) => {
                        self.status = Some(status);
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        }
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn file_type(fd: RawFd) -> libc::mode_t {
        // SAFETY: the test passes an open descriptor owned by the test or by
        // the StdioFds value under inspection.
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        assert_eq!(unsafe { libc::fstat(fd, &mut metadata) }, 0);
        metadata.st_mode & libc::S_IFMT
    }

    #[test]
    fn null_stream_uses_a_private_dev_null_not_a_pipe_endpoint() {
        let mut command = CommandSpec::new("/bin/true");
        command.stdin = Stdio::Pipe;
        command.stdout = Stdio::Null;
        command.stderr = Stdio::Pipe;

        let stdio = StdioFds::create(&command).expect("stdio endpoints");
        let [stdin, stdout, stderr] = stdio.sources();
        assert_ne!(stdin, stdout);
        assert_ne!(stdout, stderr);
        assert_eq!(file_type(stdout), libc::S_IFCHR);
        assert_eq!(file_type(stdin), libc::S_IFIFO);
        assert_eq!(file_type(stderr), libc::S_IFIFO);
    }

    #[test]
    fn stdio_source_snapshot_keeps_aliases_as_distinct_safe_descriptors() {
        let (first, second) = UnixStream::pair().expect("socketpair");
        let snapshots =
            duplicate_stdio_sources([first.as_raw_fd(), second.as_raw_fd(), first.as_raw_fd()])
                .expect("source snapshots");

        assert!(snapshots.iter().all(|&fd| fd > 2));
        assert_ne!(snapshots[0], snapshots[2]);
        assert_eq!(file_identity(snapshots[0]), file_identity(snapshots[2]));

        for fd in snapshots {
            // SAFETY: each descriptor was returned by the snapshot helper.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }

    fn file_identity(fd: RawFd) -> (libc::dev_t, libc::ino_t, libc::mode_t) {
        // SAFETY: the test passes an open descriptor returned by the snapshot
        // helper.
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        assert_eq!(unsafe { libc::fstat(fd, &mut metadata) }, 0);
        (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode & libc::S_IFMT,
        )
    }
}
