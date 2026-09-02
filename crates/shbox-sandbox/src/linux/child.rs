//! The child-side setup chain (architecture Phases 2, 4, 5, 7, 8).
//!
//! Everything in this module runs between `clone3` and `execve`. The code
//! is a single-threaded copy of a multithreaded parent, so it must perform
//! **no allocation, no locking, no library buffering**: raw syscalls, fixed
//! buffers, and values fully prepared by the parent in [`ChildSetup`].
//!
//! Stage order (each stage assumes the previous ones succeeded):
//!
//! 1. `PR_SET_PDEATHSIG` + namespace-aware parent-liveness check
//! 2. user-namespace UID/GID map writes
//! 3. mount-namespace recursive-private propagation
//! 4. optional PID-namespace init/supervisor split
//! 5. standard-stream `dup2`, `setsid`, `TIOCSCTTY`, and `chdir`
//! 6. `PR_SET_NO_NEW_PRIVS`
//! 7. capability drop
//! 8. Landlock enforcement
//! 9. seccomp filter installation
//! 10. file-descriptor hygiene
//! 11. `execve`
//!
//! Failures are reported through a fixed-size record on the status pipe and
//! the child `_exit`s without running any user code.

use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

use seccompiler::BpfProgram;

use super::caps;
use super::clone3::{CLONE_INTO_CGROUP, CLONE3_ARGS_SIZE_V1, CLONE3_ARGS_SIZE_V2, Clone3Args};
use super::landlock::PreparedLandlock;
use crate::command::SessionSetup;
use crate::error::{ChildStage, ExitStatus};
use crate::policy::CapabilityPolicy;

/// Fixed child-failure exit code (matches the historical `sshd` convention
/// for "could not execute").
pub const CHILD_SETUP_EXIT: i32 = 126;

/// Magic prefix of the status record.
const STATUS_MAGIC: [u8; 4] = *b"SBX1";
/// Status record: magic(4) stage(1) detail(1) reserved(2) errno(4).
const STATUS_RECORD_LEN: usize = 12;

/// One fixed-size control packet sent by the parent to PID 1.
pub(super) const SUPERVISOR_CONTROL_LEN: usize = 8;
/// Forward a signal to the user command only.
pub(super) const SUPERVISOR_SIGNAL_DIRECT: u32 = 1;
/// Forward a signal to the user command's process group.
pub(super) const SUPERVISOR_SIGNAL_GROUP: u32 = 2;

const SUPERVISOR_EXIT_MAGIC: [u8; 4] = *b"SBXE";
pub(super) const SUPERVISOR_EXIT_LEN: usize = 12;

/// Everything the child needs, prepared by the parent.
pub struct ChildSetup {
    /// Standard-stream sources for fd 0/1/2 (`dup2` targets).
    pub stdin_fd: RawFd,
    /// Standard-output source for fd 1.
    pub stdout_fd: RawFd,
    /// Standard-error source for fd 2.
    pub stderr_fd: RawFd,
    /// Write end of the status pipe, still open in the parent.
    pub report_fd: RawFd,
    /// Slot the report fd is moved to before the hygiene pass.
    pub report_guard: RawFd,
    /// Descriptor numbers that survive hygiene, sorted ascending.
    pub inherited_fds: Vec<RawFd>,
    /// Session structure requested for the child.
    pub session: SessionSetup,
    /// The daemon's PID, for the post-clone parent-identity check when the
    /// child remains in the daemon's PID namespace.
    pub parent_pid: libc::pid_t,
    /// A pidfd for the daemon, opened before clone when the child enters a
    /// new PID namespace. It is polled before any setup can run and then
    /// closed in the child; it must never reach the exec'ed program.
    pub parent_pidfd: Option<RawFd>,
    /// Whether this clone is PID 1 and must supervise a separate user child.
    pub pid_namespace_supervisor: bool,
    /// Child endpoint of the parent↔PID1 control socket.
    pub supervisor_control_fd: Option<RawFd>,
    /// PID1 write endpoint carrying the user child's normalized exit status.
    pub supervisor_exit_fd: Option<RawFd>,
    /// Target cgroup fd for the user child. With a PID namespace the PID1
    /// supervisor stays outside this cgroup and atomically creates PID2 into
    /// it with `clone3(CLONE_INTO_CGROUP)`.
    pub user_cgroup_fd: Option<RawFd>,
    /// Working directory to `chdir` into before confinement.
    pub cwd: Option<CString>,
    /// Pre-formatted `uid_map` / `gid_map` contents (`None` skips the
    /// write; the contents end in a newline).
    pub uid_map: Option<[u8; 64]>,
    /// Valid length of `uid_map`.
    pub uid_map_len: usize,
    /// Pre-formatted `gid_map` content.
    pub gid_map: [u8; 64],
    /// Valid length of `gid_map`.
    pub gid_map_len: usize,
    /// Write `/proc/self/setgroups` = "deny" before `gid_map`.
    pub deny_setgroups: bool,
    /// Remount `/` recursive-private inside a new mount namespace.
    pub make_mounts_private: bool,
    /// Capability bit mask retained across the drop.
    pub retain_mask: u64,
    /// Whether the capability drop runs (crate invariant: always true).
    pub drop_capabilities: bool,
    /// The prepared Landlock ruleset to enforce, if any.
    pub landlock: Option<PreparedLandlock>,
    /// The compiled seccomp program to install, if any.
    pub seccomp: Option<BpfProgram>,
    /// The program path to `execve`.
    pub program: CString,
    /// Owned argument strings backing `argv` pointers. Read only by the
    /// child through the pointer array; kept alive here.
    #[expect(dead_code, reason = "the child reads the strings via `argv`")]
    pub argv_owned: Vec<CString>,
    /// Owned environment strings backing `envp` pointers. Read only by the
    /// child through the pointer array; kept alive here.
    #[expect(dead_code, reason = "the child reads the strings via `envp`")]
    pub envp_owned: Vec<CString>,
    /// `argv` pointer array with trailing null, pointing into
    /// `argv_owned`.
    pub argv: Vec<*const libc::c_char>,
    /// `envp` pointer array with trailing null, pointing into
    /// `envp_owned`.
    pub envp: Vec<*const libc::c_char>,
}

/// The report record the parent parses.
pub struct ChildFailure {
    /// The setup stage that failed.
    pub stage: ChildStage,
    /// Stage-specific detail byte.
    pub detail: u8,
    /// The failing syscall's errno, when applicable.
    pub errno: Option<i32>,
}

/// Report a failure and die. Runs in the child between `clone3` and
/// `execve`: raw write loop, then `_exit` without Rust destructors.
pub(super) fn child_fail(report_fd: RawFd, stage: ChildStage, detail: u8, errno: i32) -> ! {
    let mut record = [0_u8; STATUS_RECORD_LEN];
    record[0..4].copy_from_slice(&STATUS_MAGIC);
    record[4] = stage.code();
    record[5] = detail;
    record[8..12].copy_from_slice(&errno.to_ne_bytes());
    let mut offset = 0_usize;
    while offset < record.len() {
        // SAFETY: the report fd is an inherited pipe endpoint and the
        // pointer stays inside the fixed stack record.
        let written = unsafe {
            libc::syscall(
                libc::SYS_write,
                report_fd,
                record.as_ptr().add(offset),
                record.len() - offset,
            ) as isize
        };
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && super::raw_errno() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
    // SAFETY: post-clone failure path must not run Rust destructors.
    unsafe { libc::_exit(CHILD_SETUP_EXIT) }
}

/// The complete child setup chain; never returns on success (ends in
/// `execve`).
///
/// # Safety
///
/// Must be called immediately after `clone3` returned 0 in this process.
pub(super) unsafe fn child_entry(setup: &mut ChildSetup) -> ! {
    let report_fd = setup.report_fd;

    // 1. Parent-death signal. The liveness check closes the race where the
    //    parent died between clone and prctl. getppid() is not usable for a
    //    child that is PID 1 in a new namespace: its parent has no PID in
    //    that namespace and getppid() consequently returns zero.
    // SAFETY: scalar prctl and getpid/getppid.
    if unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        )
    } < 0
    {
        child_fail(report_fd, ChildStage::ParentDeath, 0, super::raw_errno());
    }
    if let Some(parent_pidfd) = setup.parent_pidfd {
        match unsafe { parent_pidfd_is_alive(parent_pidfd) } {
            Ok(true) => {
                // SAFETY: the pidfd was opened by the parent and inherited
                // solely for this check; it is not part of the exec fd set.
                unsafe { libc::close(parent_pidfd) };
            }
            Ok(false) => child_fail(report_fd, ChildStage::ParentDeath, 1, libc::ESRCH),
            Err(errno) => child_fail(report_fd, ChildStage::ParentDeath, 2, errno),
        }
    } else {
        // SAFETY: plain process identity query in the shared PID namespace.
        if unsafe { libc::syscall(libc::SYS_getppid) as libc::pid_t } != setup.parent_pid {
            child_fail(report_fd, ChildStage::ParentDeath, 1, libc::ESRCH);
        }
    }

    // 2. User-namespace mappings. The child owns its brand-new user
    //    namespace and holds CAP_SETUID/CAP_SETGID over it, so it may write
    //    its own single-entry maps (mapping only the parent's own ids).
    if setup.deny_setgroups {
        // SAFETY: runs in the child with parent-prepared buffers.
        unsafe {
            write_proc_file(
                report_fd,
                ChildStage::UserNamespace,
                c"/proc/self/setgroups",
                b"deny\n",
            )
        };
    }
    if let Some(uid_map) = setup.uid_map {
        // SAFETY: runs in the child with parent-prepared buffers.
        unsafe {
            write_proc_file(
                report_fd,
                ChildStage::UserNamespace,
                c"/proc/self/uid_map",
                &uid_map[..setup.uid_map_len],
            )
        };
    }
    if setup.gid_map_len > 0 {
        // SAFETY: runs in the child with parent-prepared buffers.
        unsafe {
            write_proc_file(
                report_fd,
                ChildStage::UserNamespace,
                c"/proc/self/gid_map",
                &setup.gid_map[..setup.gid_map_len],
            )
        };
    }

    // 3. Mount-namespace hygiene: stop mounts made inside the sandbox from
    //    propagating back to the host. Requires CAP_SYS_ADMIN in the
    //    namespace owning the mount namespace (granted when the user
    //    namespace was requested in the same clone).
    if setup.make_mounts_private {
        // SAFETY: remount-style propagation change with only flag
        // arguments; all pointers are null.
        if unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
                std::ptr::null(),
            )
        } == -1
        {
            child_fail(
                report_fd,
                ChildStage::MountPropagation,
                0,
                super::raw_errno(),
            );
        }
    }

    // 4. A process created with CLONE_NEWPID is namespace PID 1. Never exec
    //    arbitrary user code as PID 1: split off a PID 2 user child while PID 1
    //    remains an internal reaper/signal forwarder. This returns only in PID2.
    if setup.pid_namespace_supervisor {
        unsafe { enter_pid_namespace_user_process(setup, report_fd) };
    }

    // 5. Standard streams/session/cwd belong to the user process, not the
    // PID1 supervisor. dup2 first because TIOCSCTTY probes fd 0.
    unsafe { setup_user_process_environment(setup, report_fd) };

    // 6. No-new-privileges: from here on, setuid/file-capability execs can
    //    never regain privileges. Landlock and seccomp both require it for
    //    unprivileged enforcement.
    // SAFETY: scalar prctl.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        child_fail(report_fd, ChildStage::NoNewPrivs, 0, super::raw_errno());
    }

    // 7. Capabilities.
    if setup.drop_capabilities
        && let Err(errno) = caps::drop_capabilities(setup.retain_mask)
    {
        child_fail(report_fd, ChildStage::Capabilities, 0, errno);
    }

    // 8. Landlock.
    if let Some(landlock) = setup.landlock.as_mut()
        && let Err(errno) = landlock.restrict_self_raw()
    {
        child_fail(report_fd, ChildStage::Landlock, 0, errno);
    }

    // 9. seccomp.
    if let Some(program) = setup.seccomp.as_ref() {
        // SAFETY: program is inherited parent memory and stays live for the
        // duration of the prctl call.
        if let Err(errno) = super::seccomp::apply_raw(program) {
            child_fail(report_fd, ChildStage::Seccomp, 0, errno);
        }
    }

    // 10. File-descriptor hygiene. Stdio is already in place; move the
    //     report pipe to its guard slot, clear the top of the table, then
    //     close everything between 3 and the guard that is not explicitly
    //     inherited.
    // SAFETY: dup2 within this process.
    if unsafe { libc::dup2(setup.report_fd, setup.report_guard) } == -1 {
        child_fail(report_fd, ChildStage::FdHygiene, 0, super::raw_errno());
    }
    let guard = setup.report_guard;
    // SAFETY: close_range (raw syscall 436, kernel 5.9+) closes only
    // descriptors above the guard.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            (guard + 1) as libc::c_uint,
            u32::MAX as libc::c_uint,
            0_u32,
        )
    } == -1
    {
        child_fail(report_fd, ChildStage::FdHygiene, 1, super::raw_errno());
    }
    // Mark the guard close-on-exec: successful execve closes it, which the
    // parent observes as EOF (= user code reached). A failed exec reports
    // explicitly first.
    // SAFETY: fcntl on the guard descriptor.
    if unsafe { libc::fcntl(guard, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        child_fail(report_fd, ChildStage::FdHygiene, 2, super::raw_errno());
    }
    for fd in 3..guard {
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

    // 11. execve. From here the guard's close-on-exec is the success signal;
    //     a return means failure, reported through the guard (the original
    //     report descriptor may already have been closed by the loop above).
    let report_fd = guard;
    // SAFETY: program/argv/envp are inherited parent allocations with NUL
    // terminators and trailing null entries prepared by the parent.
    unsafe {
        libc::execve(
            setup.program.as_ptr(),
            setup.argv.as_ptr(),
            setup.envp.as_ptr(),
        )
    };
    child_fail(report_fd, ChildStage::Exec, 0, super::raw_errno())
}

/// Install stdio/session/cwd for the process that will exec user code.
///
/// # Safety
///
/// Runs only on the post-clone user-process path with parent-prepared fds and
/// C strings.
unsafe fn setup_user_process_environment(setup: &ChildSetup, report_fd: RawFd) {
    for (source, target) in [
        (setup.stdin_fd, 0),
        (setup.stdout_fd, 1),
        (setup.stderr_fd, 2),
    ] {
        if unsafe { libc::dup2(source, target) } == -1 {
            child_fail(report_fd, ChildStage::Session, 0, super::raw_errno());
        }
    }
    if !matches!(setup.session, SessionSetup::Inherit) {
        if unsafe { libc::syscall(libc::SYS_setsid) } == -1 {
            child_fail(report_fd, ChildStage::Session, 1, super::raw_errno());
        }
        if matches!(
            setup.session,
            SessionSetup::NewSessionWithControllingTerminal
        ) && unsafe {
            libc::ioctl(
                0,
                libc::TIOCSCTTY as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
            )
        } == -1
        {
            child_fail(
                report_fd,
                ChildStage::ControllingTerminal,
                0,
                super::raw_errno(),
            );
        }
    }
    if let Some(cwd) = &setup.cwd
        && unsafe { libc::syscall(libc::SYS_chdir, cwd.as_ptr()) } == -1
    {
        child_fail(
            report_fd,
            ChildStage::WorkingDirectory,
            0,
            super::raw_errno(),
        );
    }
}

/// Split PID1 into an internal supervisor and a separate user process.
/// Returns only in the user process; the PID1 branch never returns.
///
/// # Safety
///
/// Called after namespace-global setup and before any user policy seccomp is
/// installed. All descriptors and clone arguments were prepared by the
/// parent and this function performs no allocation or locking.
unsafe fn enter_pid_namespace_user_process(setup: &mut ChildSetup, report_fd: RawFd) {
    let control_fd = match setup.supervisor_control_fd {
        Some(fd) => fd,
        None => child_fail(report_fd, ChildStage::Supervisor, 1, libc::EBADF),
    };
    let exit_fd = match setup.supervisor_exit_fd {
        Some(fd) => fd,
        None => child_fail(report_fd, ChildStage::Supervisor, 2, libc::EBADF),
    };

    let mut args = Clone3Args {
        flags: 0,
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
    let size = if let Some(cgroup_fd) = setup.user_cgroup_fd {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = cgroup_fd as u64;
        CLONE3_ARGS_SIZE_V2
    } else {
        CLONE3_ARGS_SIZE_V1
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_mut(&mut args),
            size as libc::size_t,
        )
    };
    if result == -1 {
        child_fail(report_fd, ChildStage::Supervisor, 0, super::raw_errno());
    }

    if result == 0 {
        // PID2 must not retain the supervisor-only channels. The cgroup fd
        // has already served its purpose atomically in clone3.
        unsafe { libc::close(control_fd) };
        unsafe { libc::close(exit_fd) };
        if let Some(cgroup_fd) = setup.user_cgroup_fd {
            unsafe { libc::close(cgroup_fd) };
        }

        // The namespace init's death already causes kernel teardown, but a
        // child-local PDEATHSIG closes the smaller race before that teardown
        // is observed by this process.
        if unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL,
                0,
                0,
                0,
            )
        } < 0
        {
            child_fail(report_fd, ChildStage::ParentDeath, 3, super::raw_errno());
        }
        if unsafe { libc::syscall(libc::SYS_getppid) as libc::pid_t } != 1 {
            child_fail(report_fd, ChildStage::ParentDeath, 4, libc::ESRCH);
        }
        return;
    }

    let user_pid = result as libc::pid_t;

    // Harden PID1 independently of the user-requested seccomp policy. The
    // arbitrary user filter is intentionally not installed here because it
    // may deny the wait/poll/recv/kill syscalls required by the reaper.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        child_fail(report_fd, ChildStage::Supervisor, 3, super::raw_errno());
    }
    if let Err(errno) = caps::drop_capabilities(0) {
        child_fail(report_fd, ChildStage::Supervisor, 4, errno);
    }
    if let Some(landlock) = setup.landlock.as_mut()
        && let Err(errno) = landlock.restrict_self_raw()
    {
        child_fail(report_fd, ChildStage::Supervisor, 5, errno);
    }

    // Only PID2 keeps the exec-status writer. Closing PID1's copy makes the
    // parent's EOF observation track the user exec rather than supervisor
    // lifetime.
    unsafe { libc::close(report_fd) };
    if let Some(cgroup_fd) = setup.user_cgroup_fd {
        unsafe { libc::close(cgroup_fd) };
    }
    unsafe { close_all_except(control_fd, exit_fd) };
    unsafe { supervisor_loop(user_pid, control_fd, exit_fd) }
}

/// Close every fd >= 3 except two supervisor channels.
unsafe fn close_all_except(first: RawFd, second: RawFd) {
    let low = first.min(second);
    let high = first.max(second);
    unsafe { close_range_if_nonempty(3, i64::from(low - 1)) };
    unsafe { close_range_if_nonempty(low + 1, i64::from(high - 1)) };
    unsafe { close_range_if_nonempty(high + 1, u32::MAX as i64) };
}

unsafe fn close_range_if_nonempty(first: i32, last: i64) {
    if first < 0 || i64::from(first) > last {
        return;
    }
    let _ = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_uint,
            last as libc::c_uint,
            0_u32,
        )
    };
}

/// PID1 event loop: reap orphan descendants, forward parent control packets,
/// and report the main user process's exact termination status.
unsafe fn supervisor_loop(user_pid: libc::pid_t, control_fd: RawFd, exit_fd: RawFd) -> ! {
    loop {
        if let Some(status) = unsafe { reap_nonblocking(user_pid) } {
            unsafe { finish_supervisor(exit_fd, status) };
        }

        let mut pollfd = libc::pollfd {
            fd: control_fd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        let polled = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                std::ptr::from_mut(&mut pollfd),
                1_usize,
                std::ptr::from_ref(&timeout),
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<libc::sigset_t>(),
            )
        };
        if polled < 0 {
            if super::raw_errno() == libc::EINTR {
                continue;
            }
            unsafe { abort_supervisor() };
        }
        if polled == 0 {
            continue;
        }
        if pollfd.revents & libc::POLLIN != 0 {
            let mut record = [0_u8; SUPERVISOR_CONTROL_LEN];
            let received =
                unsafe { libc::recv(control_fd, record.as_mut_ptr().cast(), record.len(), 0) };
            if received == 0 {
                unsafe { abort_supervisor() };
            }
            if received < 0 {
                if super::raw_errno() == libc::EINTR {
                    continue;
                }
                unsafe { abort_supervisor() };
            }
            if received as usize != record.len() {
                continue;
            }
            let kind = u32::from_ne_bytes([record[0], record[1], record[2], record[3]]);
            let signal = i32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
            let target = match kind {
                SUPERVISOR_SIGNAL_DIRECT => user_pid,
                SUPERVISOR_SIGNAL_GROUP => -user_pid,
                _ => continue,
            };
            let result = unsafe { libc::kill(target, signal) };
            if result == -1 && super::raw_errno() != libc::ESRCH {
                // The API call already completed in the parent; a malformed
                // or no-longer-deliverable signal must not compromise PID1.
                continue;
            }
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            unsafe { abort_supervisor() };
        }
    }
}

/// Reap all currently waitable children and return the main child's raw wait
/// status once it exits. Orphan descendants are reaped while the main child
/// continues running.
unsafe fn reap_nonblocking(user_pid: libc::pid_t) -> Option<i32> {
    let mut main_status = None;
    loop {
        let mut status = 0_i32;
        let pid = unsafe { libc::waitpid(-1, std::ptr::from_mut(&mut status), libc::WNOHANG) };
        if pid > 0 {
            if pid == user_pid {
                main_status = Some(status);
            }
            continue;
        }
        if pid == 0 {
            return main_status;
        }
        match super::raw_errno() {
            libc::EINTR => continue,
            libc::ECHILD => return main_status,
            _ => unsafe { abort_supervisor() },
        }
    }
}

unsafe fn finish_supervisor(exit_fd: RawFd, status: i32) -> ! {
    // Kill every remaining process visible in this PID namespace, then reap
    // the whole namespace before exiting. A non-blocking sweep here races the
    // SIGKILL delivery: children killed microseconds earlier would survive
    // PID1 as zombies and be adopted by whatever init runs outside the
    // namespace, where nothing guarantees they are ever waited on.
    let _ = unsafe { libc::kill(-1, libc::SIGKILL) };
    unsafe { reap_all_descendants() };
    unsafe { write_supervisor_exit(exit_fd, status) };
    unsafe { libc::_exit(0) }
}

unsafe fn abort_supervisor() -> ! {
    let _ = unsafe { libc::kill(-1, libc::SIGKILL) };
    unsafe { reap_all_descendants() };
    unsafe { libc::_exit(CHILD_SETUP_EXIT) }
}

/// Block until every child in this PID namespace is reaped. The main child's
/// status is already saved by the caller, so these waits only collect
/// termination confirmations. PID1 owns every unreaped process here, and
/// signals it has no handler for are ignored by kernel PID1 semantics, so
/// the loop ends at `ECHILD` under normal operation.
unsafe fn reap_all_descendants() {
    loop {
        let mut ignored = 0_i32;
        // SAFETY: PID1 is the parent of every zombie in the namespace; the
        // status is deliberately discarded.
        let pid = unsafe { libc::waitpid(-1, std::ptr::from_mut(&mut ignored), 0) };
        if pid > 0 {
            continue;
        }
        match super::raw_errno() {
            libc::EINTR => continue,
            // ECHILD is the expected exit condition. Any other error cannot
            // be remedied inside PID1; the kernel namespace teardown that
            // follows PID1's own exit remains the final safety net.
            _ => return,
        }
    }
}

unsafe fn write_supervisor_exit(exit_fd: RawFd, status: i32) {
    let mut record = [0_u8; SUPERVISOR_EXIT_LEN];
    record[0..4].copy_from_slice(&SUPERVISOR_EXIT_MAGIC);
    let (kind, value, core) = if libc::WIFEXITED(status) {
        (0_u8, libc::WEXITSTATUS(status), 0_u8)
    } else if libc::WIFSIGNALED(status) {
        (
            1_u8,
            libc::WTERMSIG(status),
            u8::from(libc::WCOREDUMP(status)),
        )
    } else {
        (0_u8, 255, 0_u8)
    };
    record[4] = kind;
    record[5] = core;
    record[8..12].copy_from_slice(&value.to_ne_bytes());
    let mut offset = 0_usize;
    while offset < record.len() {
        let written = unsafe {
            libc::write(
                exit_fd,
                record.as_ptr().add(offset).cast(),
                record.len() - offset,
            )
        };
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && super::raw_errno() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
}

pub(super) fn parse_supervisor_exit(record: [u8; SUPERVISOR_EXIT_LEN]) -> Option<ExitStatus> {
    if record[0..4] != SUPERVISOR_EXIT_MAGIC {
        return None;
    }
    let value = i32::from_ne_bytes(record[8..12].try_into().expect("fixed exit field"));
    match record[4] {
        0 => Some(ExitStatus::from_code(value)),
        1 => Some(ExitStatus::from_signal(value, record[5] != 0)),
        _ => None,
    }
}

/// Check a pre-clone parent pidfd without allocating or blocking.
///
/// A pidfd becomes poll-readable when its process exits. Installing
/// `PDEATHSIG` first covers deaths after the check; polling the pidfd covers
/// the interval between `clone3` and `prctl`, including the case where the
/// child cannot observe its parent through `getppid()` because of
/// `CLONE_NEWPID`.
///
/// # Safety
///
/// `parent_pidfd` must be a valid pidfd inherited from the parent.
unsafe fn parent_pidfd_is_alive(parent_pidfd: RawFd) -> Result<bool, i32> {
    let mut pollfd = libc::pollfd {
        fd: parent_pidfd,
        events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        pollfd.revents = 0;
        // SAFETY: pollfd and timeout are initialized stack storage; the zero
        // timeout makes this a non-blocking liveness probe. ppoll is used
        // instead of poll because libc does not expose SYS_poll on every
        // supported Linux architecture.
        let result = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                std::ptr::from_mut(&mut pollfd),
                1_usize,
                std::ptr::from_ref(&timeout),
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<libc::sigset_t>(),
            )
        };
        if result >= 0 {
            if result == 0 {
                return Ok(true);
            }
            if pollfd.revents & libc::POLLNVAL != 0 {
                return Err(libc::EBADF);
            }
            if pollfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(false);
            }
            return Err(libc::EIO);
        }
        let errno = super::raw_errno();
        if errno == libc::EINTR {
            continue;
        }
        return Err(errno);
    }
}

/// Open/write/close a `/proc/self/*` control file. Post-fork safe.
///
/// # Safety
///
/// Must be called in the child; `content` must be initialized.
unsafe fn write_proc_file(report_fd: RawFd, stage: ChildStage, path: &CStr, content: &[u8]) {
    // SAFETY: open with a literal NUL-terminated path, write-only.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd == -1 {
        child_fail(report_fd, stage, 0, super::raw_errno());
    }
    let mut offset = 0_usize;
    while offset < content.len() {
        // SAFETY: the pointer stays inside the given slice for this call.
        let written = unsafe {
            libc::write(
                fd,
                content.as_ptr().add(offset).cast(),
                content.len() - offset,
            )
        };
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && super::raw_errno() == libc::EINTR {
            continue;
        } else {
            // SAFETY: fd is this child's descriptor.
            unsafe { libc::close(fd) };
            child_fail(report_fd, stage, 1, super::raw_errno());
        }
    }
    // SAFETY: fd is this child's descriptor.
    unsafe { libc::close(fd) };
}

/// Parse the fixed-size record the child may have written.
pub(super) fn parse_child_failure(record: [u8; STATUS_RECORD_LEN]) -> Option<ChildFailure> {
    if record[0..4] != STATUS_MAGIC {
        return None;
    }
    Some(ChildFailure {
        stage: ChildStage::from_code(record[4])?,
        detail: record[5],
        errno: Some(i32::from_ne_bytes(
            record[8..12].try_into().expect("fixed errno field"),
        )),
    })
}

/// Which capability bits survive the drop, per policy.
pub(super) fn retained_mask(policy: &CapabilityPolicy) -> u64 {
    match policy {
        CapabilityPolicy::DropAll => 0,
        CapabilityPolicy::Retain(list) => caps::retain_mask(list),
    }
}
