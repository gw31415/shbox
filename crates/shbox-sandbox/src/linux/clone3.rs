//! Raw `clone3()` wrapper.
//!
//! `clone3` is the only spawn primitive this backend uses. The outer clone
//! hands the parent a pidfd (`CLONE_PIDFD`, 5.3+) and creates requested
//! namespaces atomically. Without a PID namespace it can also start the user
//! process directly inside the target cgroup (`CLONE_INTO_CGROUP`, 5.7+).
//! With a PID namespace, the outer child is an internal PID 1 supervisor and
//! a nested `clone3(CLONE_INTO_CGROUP)` creates user PID 2 directly in the
//! target cgroup. There is deliberately no fork-then-move-to-cgroup path.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::io::FromRawFd;

/// `struct clone_args` as defined by the kernel UAPI. Field order is ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Clone3Args {
    /// Bit mask of `CLONE_*` flags.
    pub flags: u64,
    /// Where the kernel stores the pidfd (`CLONE_PIDFD`).
    pub pidfd: u64,
    /// Where the kernel stores the child TID in child memory.
    pub child_tid: u64,
    /// Where the kernel stores the child TID in parent memory.
    pub parent_tid: u64,
    /// Signal delivered to the parent on child exit.
    pub exit_signal: u64,
    /// Stack pointer when a custom stack is used.
    pub stack: u64,
    /// Stack size.
    pub stack_size: u64,
    /// TLS pointer.
    pub tls: u64,
    /// Pointer to a `pid_t` array (`set_tid`, 5.5+).
    pub set_tid: u64,
    /// Element count for `set_tid`.
    pub set_tid_size: u64,
    /// Cgroup file descriptor (`CLONE_INTO_CGROUP`, 5.7+).
    pub cgroup: u64,
}

/// `sizeof(struct clone_args)` through `tls` — the layout every kernel since
/// 5.3 knows. Used whenever `CLONE_INTO_CGROUP` is not requested, so spawn
/// works unchanged on kernels older than 5.7.
pub const CLONE3_ARGS_SIZE_V1: usize = 64;

/// `sizeof(struct clone_args)` including `set_tid` and `cgroup` (5.7+).
pub const CLONE3_ARGS_SIZE_V2: usize = 88;

// Flag values from the kernel UAPI; kept local so the crate does not depend
// on a minimum libc version having them.
pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_INTO_CGROUP: u64 = 0x0000_0002_0000_0000;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
#[allow(dead_code)]
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;

/// Outcome of a `clone3` call.
pub enum Clone3 {
    /// The caller is now the parent; the pidfd was stored.
    Parent { pid: i32, pidfd: OwnedFd },
    /// The caller is the child and must not return from its setup path.
    Child,
}

/// Issue `clone3`. `cgroup_fd` is stored in `args.cgroup` by the caller.
///
/// # Safety
///
/// On `Clone3::Child` the process is a single-threaded copy sharing nothing
/// live with the parent; the caller must immediately run a child entry that
/// ends in `execve` or `_exit` and performs no allocation, locking, or
/// library buffering.
pub unsafe fn clone3(args: &mut Clone3Args, size: usize) -> io::Result<Clone3> {
    let mut pidfd_storage: libc::c_int = -1;
    args.pidfd = std::ptr::from_mut(&mut pidfd_storage).addr() as u64;

    // SAFETY: `args` points to an initialized, correctly sized kernel
    // struct. With CLONE_PIDFD, args.pidfd points at writable c_int storage
    // where the kernel stores the new pidfd before clone3 returns.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            args as *mut Clone3Args,
            size as libc::size_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        Ok(Clone3::Child)
    } else {
        if pidfd_storage < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "clone3 succeeded without returning a pidfd",
            ));
        }
        // SAFETY: CLONE_PIDFD wrote a fresh, uniquely owned descriptor into
        // pidfd_storage on successful return in the parent.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_storage) };
        Ok(Clone3::Parent {
            pid: result as i32,
            pidfd,
        })
    }
}

/// `pidfd_send_signal(2)`.
pub fn pidfd_send_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: valid owned fd, NULL siginfo for plain signals.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd() as libc::c_int,
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `waitid(P_PIDFD, ...)` result for a reaped child.
pub struct PidfdWait {
    /// The collected exit status.
    pub exit: crate::error::ExitStatus,
}

/// Wait (optionally without blocking) on a pidfd.
///
/// Returns `Ok(None)` when `nohang` is set and the child has not exited.
pub fn pidfd_wait(pidfd: &OwnedFd, nohang: bool) -> io::Result<Option<PidfdWait>> {
    // SAFETY: `siginfo_t` is a C struct of integers, fixed-size arrays, and
    // raw pointers — all-zero is a valid value, and `waitid` only writes to
    // it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let mut options = libc::WEXITED;
    if nohang {
        options |= libc::WNOHANG;
    }
    // SAFETY: `info` is initialized writable storage; idtype P_PIDFD (3)
    // interprets `id` as a pidfd.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD as libc::idtype_t,
            pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            options,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: siginfo field access on an initialized structure.
    if nohang && unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let exit = siginfo_exit(&info).unwrap_or_else(|| crate::error::ExitStatus::from_code(255));
    // waitid(WEXITED) on a pidfd reaps the child; WNOWAIT is not used.
    Ok(Some(PidfdWait { exit }))
}

/// Translate a waitid `siginfo_t` into an [`ExitStatus`].
fn siginfo_exit(info: &libc::siginfo_t) -> Option<crate::error::ExitStatus> {
    let code = info.si_code;
    // SAFETY: siginfo field access on an initialized structure.
    let status = unsafe { info.si_status() };
    match code {
        libc::CLD_EXITED => Some(crate::error::ExitStatus::from_code(status)),
        libc::CLD_KILLED => Some(crate::error::ExitStatus::from_signal(status, false)),
        libc::CLD_DUMPED => Some(crate::error::ExitStatus::from_signal(status, true)),
        _ => None,
    }
}
