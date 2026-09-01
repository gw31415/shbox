//! Linux production launcher (nono confinement primitive).
//!
//! nono is a confinement primitive, not a process launcher: shbox owns the
//! PTY, Unix session, direct child, I/O, signaling, and cleanup. Every path
//! lookup and policy allocation happens in the parent. The post-fork child
//! only performs fixed/raw setup plus `PreparedLandlockSandbox::apply_raw()`
//! before `exec`.

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use nono::CapabilitySet;
use nono::capability::{AccessMode, IpcMode, NetworkMode as NonoNetworkMode, SignalMode};
use nono::sandbox::{
    DetectedAbi, PreparedLandlockSandbox, RawSandboxError, RawSandboxStage, SeccompNetFallback,
    SeccompOpts, detect_abi, prepare_seccomp_with_abi,
};

use super::policy::{LaunchTemp, SandboxLaunchPolicy, validated_shell_command};
use super::terminal::{ChildSetupStage, PtyIo, PtyPair, child_session_setup, duplicate_fd};
use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, RunningProcess,
};
use crate::config::NetworkMode;

const CHILD_SETUP_EXIT: i32 = 126;
const CHILD_FAILURE_MAGIC: [u8; 4] = *b"SHBX";
const PROCESS_GROUP_SETTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ChildFailureKind {
    ParentDeath = 1,
    Session = 2,
    ControllingTerminal = 3,
    WorkingDirectory = 4,
    Sandbox = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildFailure {
    kind: ChildFailureKind,
    detail: u8,
    errno: i32,
}

/// Linux launcher backed by a process-lifetime shbox policy snapshot and the
/// detected Landlock ABI. No nono process/supervisor abstraction is retained.
pub(crate) struct LinuxLauncher {
    policy: SandboxLaunchPolicy,
    abi: DetectedAbi,
}

impl fmt::Debug for LinuxLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxLauncher")
            .field("policy", &self.policy)
            .field("landlock_abi", &self.abi.version_string())
            .finish()
    }
}

impl LinuxLauncher {
    pub(crate) fn new(policy: SandboxLaunchPolicy) -> Result<Self, LaunchError> {
        let abi = detect_abi().map_err(|_| {
            LaunchError::new("sandbox process adapter unavailable: Landlock unsupported")
        })?;
        let seccomp_network_fallback =
            policy.network() == NetworkMode::Disabled && !abi.has_network();

        tracing::info!(
            kernel_release = %kernel_release(),
            landlock_abi = abi.version_string(),
            landlock_network = abi.has_network(),
            signal_scope = abi.has_scoping(),
            abstract_unix_socket_scope = abi.has_scoping(),
            seccomp_network_fallback,
            "Linux sandbox capabilities detected"
        );

        Ok(Self { policy, abi })
    }

    fn prepare_sandbox(
        &self,
        workspace: &Path,
        launch_temp: &Path,
    ) -> Result<PreparedLandlockSandbox, LaunchError> {
        let mut caps = CapabilitySet::new();
        for path in self.policy.resolved_read_paths() {
            caps = allow_existing(caps, &path, AccessMode::Read)?;
        }
        for path in self.policy.curated_write_paths() {
            caps = allow_existing(caps, &path, AccessMode::ReadWrite)?;
        }
        caps = caps
            .allow_path(workspace, AccessMode::ReadWrite)
            .map_err(|_| LaunchError::new("sandbox workspace policy could not be prepared"))?;
        caps = caps
            .allow_path(launch_temp, AccessMode::ReadWrite)
            .map_err(|_| LaunchError::new("sandbox temp policy could not be prepared"))?;
        caps = caps
            .set_network_mode(match self.policy.network() {
                NetworkMode::Disabled => NonoNetworkMode::Blocked,
                // Preserve the existing shbox `outbound` contract: the
                // Arapuca Baseline profile allowed ordinary client and bind
                // sockets while blocking escape-critical syscalls. Nono's
                // closest filesystem/network mapping is therefore AllowAll;
                // adding a port allowlist here would silently narrow the
                // established configuration semantics.
                NetworkMode::Outbound => NonoNetworkMode::AllowAll,
            })
            .set_signal_mode(SignalMode::Isolated)
            .set_ipc_mode(IpcMode::SharedMemoryOnly);

        let prepared = prepare_seccomp_with_abi(&caps, &self.abi, SeccompOpts::network_fallback())
            .map_err(|_| LaunchError::new("sandbox confinement policy could not be prepared"))?;
        if matches!(prepared.fallback(), SeccompNetFallback::ProxyOnly { .. }) {
            return Err(LaunchError::new(
                "sandbox confinement policy requested an unsupported network proxy",
            ));
        }
        Ok(prepared)
    }
}

impl ProcessLauncher for LinuxLauncher {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError> {
        // Everything that resolves paths or allocates confinement state happens
        // before a child exists.
        let workspace = fs::canonicalize(&request.workspace)
            .map_err(|_| LaunchError::new("sandbox workspace is unavailable"))?;
        if !workspace.is_dir() {
            return Err(LaunchError::new("sandbox workspace is unavailable"));
        }
        let launch_temp = self.policy.create_launch_temp()?;
        let prepared = self.prepare_sandbox(&workspace, launch_temp.path())?;
        let workspace_c = CString::new(workspace.as_os_str().as_bytes())
            .map_err(|_| LaunchError::new("sandbox workspace path contains NUL"))?;
        let command_arg = validated_shell_command(&request.operation)?;
        let environment = self.policy.environment_for(
            &workspace,
            request.pty.as_ref().map(|pty| pty.term.as_str()),
            Some(launch_temp.path()),
        );
        let parent_pid = unsafe { libc::getpid() };

        // PTY allocation is not atomically CLOEXEC on every supported libc,
        // so serialize this boundary with host-process and sandbox spawns.
        let _spawn_guard = super::process_spawn_lock()
            .lock()
            .map_err(|_| LaunchError::new("sandbox process adapter is unavailable"))?;

        let is_pty = request.pty.is_some();
        let mut pty_pair = if let Some(pty) = request.pty.as_ref() {
            Some(
                PtyPair::open(&pty.modes, pty.rows, pty.cols)
                    .map_err(|_| LaunchError::new("sandbox PTY allocation failed"))?,
            )
        } else {
            None
        };
        let setup_fd = if let Some(pair) = pty_pair.as_ref() {
            Some(
                pair.reserve_setup_fd()
                    .map_err(|_| LaunchError::new("sandbox PTY setup failed"))?,
            )
        } else {
            None
        };

        let (stdin_child, stdin_parent) = if is_pty {
            (None, None)
        } else {
            let (read, write) = make_pipe("sandbox stdin pipe creation failed")?;
            (Some(read), Some(write))
        };
        let (stdout_parent, stdout_child) = if is_pty {
            (None, None)
        } else {
            let (read, write) = make_pipe("sandbox stdout pipe creation failed")?;
            (Some(read), Some(write))
        };
        let (stderr_parent, stderr_child) = if is_pty {
            (None, None)
        } else {
            let (read, write) = make_pipe("sandbox stderr pipe creation failed")?;
            (Some(read), Some(write))
        };
        let (status_read, status_write) = make_pipe("sandbox status pipe creation failed")?;
        let status_fd = status_write.as_raw_fd();
        let setup_raw = setup_fd.as_ref().map(AsRawFd::as_raw_fd);

        let mut command = Command::new(self.policy.shell());
        match command_arg {
            Some(command_arg) => {
                command.arg("-c").arg(command_arg);
            }
            None => {
                command.arg("-l");
            }
        }
        command.env_clear();
        command.envs(environment.iter().map(|(name, value)| (name, value)));
        if !is_pty {
            command.stdin(Stdio::from(stdin_child.expect("non-PTY stdin child")));
            command.stdout(Stdio::from(stdout_child.expect("non-PTY stdout child")));
            command.stderr(Stdio::from(stderr_child.expect("non-PTY stderr child")));
        }

        // SAFETY: every captured value was fully prepared in the parent. The
        // closure only executes raw syscalls, the audited terminal helper, and
        // nono's allocation-free prepared policy application.
        unsafe {
            command.pre_exec(move || {
                child_set_parent_death(parent_pid, status_fd);
                if let Some(setup_raw) = setup_raw {
                    if let Err(error) = child_session_setup(setup_raw, true) {
                        let kind = match error.stage {
                            ChildSetupStage::Session => ChildFailureKind::Session,
                            ChildSetupStage::ControllingTerminal => {
                                ChildFailureKind::ControllingTerminal
                            }
                        };
                        child_fail(status_fd, kind, 0, error.errno);
                    }
                } else if libc::syscall(libc::SYS_setsid) < 0 {
                    child_fail(status_fd, ChildFailureKind::Session, 0, raw_errno());
                }
                if libc::syscall(libc::SYS_chdir, workspace_c.as_ptr()) < 0 {
                    child_fail(
                        status_fd,
                        ChildFailureKind::WorkingDirectory,
                        0,
                        raw_errno(),
                    );
                }
                if let Err(error) = prepared.apply_raw() {
                    child_fail(
                        status_fd,
                        ChildFailureKind::Sandbox,
                        sandbox_stage_code(error),
                        error.errno(),
                    );
                }
                Ok(())
            });
        }

        let mut child = command
            .spawn()
            .map_err(|_| LaunchError::new("sandbox process exec failed"))?;

        // Child has its own descriptor table now. Parent-side child-only copies
        // must close before waiting for the status pipe or exposing the PTY.
        drop(status_write);
        drop(setup_fd);
        match read_child_failure(status_read) {
            Ok(Some(failure)) => {
                // The child reports setup failure before exec. Kill the direct
                // PID rather than a process group because failure may have
                // happened before setsid() established the private group.
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!(
                    stage = ?failure.kind,
                    detail = failure.detail,
                    errno = failure.errno,
                    "sandbox child setup failed"
                );
                return Err(LaunchError::new("sandbox child setup failed"));
            }
            Err(error) => {
                // A malformed/unreadable setup status is fail-closed. The
                // direct child may be at any setup stage, so target only it.
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Ok(None) => {}
        }

        // Status EOF proves exec succeeded after setsid/confinement. From this
        // point onward any fallible parent-side PTY setup must tear down the
        // now-owned session if launch cannot be published to the runtime.
        let child = SpawnedChildGuard::new(child);
        let pid = child.pid();
        let (stdin, stdout, stderr, lifecycle_fd) = if let Some(pair) = pty_pair.take() {
            let master = pair.into_master();
            let read_fd = duplicate_fd(master.as_raw_fd())
                .map_err(|_| LaunchError::new("sandbox PTY read duplicate failed"))?;
            let write_fd = duplicate_fd(master.as_raw_fd())
                .map_err(|_| LaunchError::new("sandbox PTY write duplicate failed"))?;
            let stdin = PtyIo::new(write_fd)
                .map_err(|_| LaunchError::new("sandbox PTY writer could not be initialized"))?;
            let stdout = PtyIo::new(read_fd)
                .map_err(|_| LaunchError::new("sandbox PTY reader could not be initialized"))?;
            (
                Some(Box::new(stdin) as ProcessWriter),
                Some(Box::new(stdout) as ProcessReader),
                None,
                Some(master),
            )
        } else {
            (
                Some(async_writer(stdin_parent.expect("non-PTY stdin parent"))),
                Some(async_reader(stdout_parent.expect("non-PTY stdout parent"))),
                Some(async_reader(stderr_parent.expect("non-PTY stderr parent"))),
                None,
            )
        };

        let control = Arc::new(LinuxProcessControl::new(pid, lifecycle_fd));
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
        let wait_control = Arc::clone(&control);
        let child = child.into_child();
        let spawn_result = std::thread::Builder::new()
            .name("shbox-linux-sandbox-wait".to_string())
            .spawn(move || wait_process(child, wait_control, launch_temp, wait_tx));
        if spawn_result.is_err() {
            control.force_terminate();
            // The failed thread spawn drops the `Child` handle but the process
            // remains our direct child. Reap it explicitly by PID.
            unsafe {
                let mut status = 0;
                while libc::waitpid(pid as libc::pid_t, &mut status, 0) == -1
                    && raw_errno() == libc::EINTR
                {}
            }
            control.mark_cleanup_complete();
            return Err(LaunchError::new(
                "sandbox process waiter could not be started",
            ));
        }

        Ok(LaunchedProcess {
            control,
            stdin,
            stdout,
            stderr,
            window_revision: request.pty.as_ref().map_or(0, |pty| pty.window_revision),
            wait: wait_rx,
        })
    }
}

/// Own a successfully exec'd sandbox child until all fallible parent-side
/// launch setup has completed. Dropping this guard is a local launch failure,
/// so the complete private process group is killed and the direct child is
/// reaped before the error escapes.
struct SpawnedChildGuard {
    child: Option<Child>,
    pid: u32,
}

impl SpawnedChildGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
        }
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn into_child(mut self) -> Child {
        self.child.take().expect("spawned child guard")
    }
}

impl Drop for SpawnedChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        kill_process_group(self.pid, libc::SIGKILL);
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn allow_existing(
    caps: CapabilitySet,
    path: &Path,
    mode: AccessMode,
) -> Result<CapabilitySet, LaunchError> {
    let metadata = fs::metadata(path)
        .map_err(|_| LaunchError::new("sandbox confinement path became unavailable"))?;
    if metadata.is_dir() {
        caps.allow_path(path, mode)
    } else if metadata.is_file() || metadata.file_type().is_char_device() {
        caps.allow_file(path, mode)
    } else {
        return Err(LaunchError::new(
            "sandbox confinement path type is unsupported",
        ));
    }
    .map_err(|_| LaunchError::new("sandbox confinement path could not be prepared"))
}

fn make_pipe(message: &'static str) -> Result<(OwnedFd, OwnedFd), LaunchError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors to `fds` and atomically marks
    // them close-on-exec before a concurrent fork can observe them.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(LaunchError::new(message));
    }
    // SAFETY: pipe2 succeeded, so both returned descriptors are uniquely owned.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

unsafe fn child_set_parent_death(parent_pid: libc::pid_t, status_fd: RawFd) {
    // SAFETY: fixed raw syscalls only. The getppid check closes the race where
    // the parent dies between fork and PR_SET_PDEATHSIG installation.
    unsafe {
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) < 0
        {
            child_fail(status_fd, ChildFailureKind::ParentDeath, 0, raw_errno());
        }
        if libc::syscall(libc::SYS_getppid) as libc::pid_t != parent_pid {
            child_fail(status_fd, ChildFailureKind::ParentDeath, 1, libc::ESRCH);
        }
    }
}

unsafe fn child_fail(status_fd: RawFd, kind: ChildFailureKind, detail: u8, errno: i32) -> ! {
    let mut record = [0_u8; 12];
    record[0..4].copy_from_slice(&CHILD_FAILURE_MAGIC);
    record[4] = kind as u8;
    record[5] = detail;
    record[8..12].copy_from_slice(&errno.to_ne_bytes());
    let mut offset = 0_usize;
    while offset < record.len() {
        // SAFETY: the status fd is a live pipe endpoint inherited from the
        // parent and the pointer stays within the fixed stack record.
        let written = unsafe {
            libc::syscall(
                libc::SYS_write,
                status_fd,
                record.as_ptr().add(offset),
                record.len() - offset,
            ) as isize
        };
        if written > 0 {
            offset += written as usize;
            continue;
        }
        if written < 0 && raw_errno() == libc::EINTR {
            continue;
        }
        break;
    }
    // SAFETY: post-fork failure path must not execute Rust destructors.
    unsafe { libc::_exit(CHILD_SETUP_EXIT) }
}

fn sandbox_stage_code(error: RawSandboxError) -> u8 {
    match error.stage() {
        RawSandboxStage::NoNewPrivs => 1,
        RawSandboxStage::CreateRuleset => 2,
        RawSandboxStage::AddPathRule => 3,
        RawSandboxStage::AddNetRule => 4,
        RawSandboxStage::RestrictSelf => 5,
        RawSandboxStage::InstallStaticFilter => 6,
        RawSandboxStage::InstallNotifyFilter => 7,
        _ => 255,
    }
}

fn read_child_failure(fd: OwnedFd) -> Result<Option<ChildFailure>, LaunchError> {
    let mut record = [0_u8; 12];
    let mut offset = 0_usize;
    while offset < record.len() {
        // SAFETY: `fd` is owned and the target is the initialized stack buffer.
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
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LaunchError::new("sandbox child status could not be read"));
        }
        offset += count as usize;
    }
    if offset == 0 {
        return Ok(None);
    }
    if offset != record.len() || record[0..4] != CHILD_FAILURE_MAGIC {
        return Err(LaunchError::new(
            "sandbox child returned an invalid setup status",
        ));
    }
    let kind = match record[4] {
        1 => ChildFailureKind::ParentDeath,
        2 => ChildFailureKind::Session,
        3 => ChildFailureKind::ControllingTerminal,
        4 => ChildFailureKind::WorkingDirectory,
        5 => ChildFailureKind::Sandbox,
        _ => {
            return Err(LaunchError::new(
                "sandbox child returned an invalid setup stage",
            ));
        }
    };
    let errno = i32::from_ne_bytes(record[8..12].try_into().expect("fixed errno field"));
    Ok(Some(ChildFailure {
        kind,
        detail: record[5],
        errno,
    }))
}

fn raw_errno() -> i32 {
    // SAFETY: errno is thread-local and valid for the calling thread.
    unsafe { *libc::__errno_location() }
}

fn kernel_release() -> String {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is writable and remains live for the call.
    if unsafe { libc::uname(&mut uts) } == -1 {
        return "unknown".to_string();
    }
    // SAFETY: uname guarantees NUL-terminated fields.
    unsafe { CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn wait_process(
    mut child: Child,
    control: Arc<LinuxProcessControl>,
    launch_temp: LaunchTemp,
    wait_tx: tokio::sync::oneshot::Sender<Result<ProcessExit, LaunchError>>,
) {
    let result = match child.wait() {
        Ok(status) => {
            control.finished.store(true, Ordering::Release);
            kill_process_group(control.pid, libc::SIGKILL);
            wait_process_group_gone(control.pid, PROCESS_GROUP_SETTLE);
            let exit = if let Some(code) = status.code() {
                ProcessExit::Code(code)
            } else if let Some(number) = status.signal() {
                ProcessExit::Signal {
                    number,
                    core_dumped: status.core_dumped(),
                }
            } else {
                ProcessExit::Code(255)
            };
            Ok(exit)
        }
        Err(_) => {
            control.finished.store(true, Ordering::Release);
            kill_process_group(control.pid, libc::SIGKILL);
            wait_process_group_gone(control.pid, PROCESS_GROUP_SETTLE);
            Err(LaunchError::new("sandbox process wait failed"))
        }
    };
    drop(launch_temp);
    control.mark_cleanup_complete();
    let _ = wait_tx.send(result);
}

fn kill_process_group(pid: u32, signal: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: session leader PID is also its initial process-group ID.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

fn wait_process_group_gone(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // SAFETY: signal 0 performs existence/permission checking only.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        if result == -1 && raw_errno() == libc::ESRCH {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct LinuxProcessControl {
    pid: u32,
    finished: AtomicBool,
    termination_requested: AtomicBool,
    lifecycle_fd: Mutex<Option<OwnedFd>>,
    cleanup_complete: Mutex<bool>,
    cleanup_cv: Condvar,
}

impl fmt::Debug for LinuxProcessControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxProcessControl")
            .field("pid", &self.pid)
            .field("finished", &self.finished.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl LinuxProcessControl {
    fn new(pid: u32, lifecycle_fd: Option<OwnedFd>) -> Self {
        Self {
            pid,
            finished: AtomicBool::new(false),
            termination_requested: AtomicBool::new(false),
            lifecycle_fd: Mutex::new(lifecycle_fd),
            cleanup_complete: Mutex::new(false),
            cleanup_cv: Condvar::new(),
        }
    }

    fn mark_cleanup_complete(&self) {
        if let Ok(mut lifecycle_fd) = self.lifecycle_fd.lock() {
            lifecycle_fd.take();
        }
        if let Ok(mut complete) = self.cleanup_complete.lock() {
            *complete = true;
            self.cleanup_cv.notify_all();
        }
    }

    fn signal_target(&self, number: i32) {
        if self.pid <= 1 || self.finished.load(Ordering::Acquire) {
            return;
        }
        // In PTY mode forward user-requested signals to the current foreground
        // job when available; otherwise target the session leader's group.
        let foreground = self
            .lifecycle_fd
            .lock()
            .ok()
            .and_then(|fd| fd.as_ref().map(AsRawFd::as_raw_fd))
            .and_then(|fd| {
                // SAFETY: lifecycle fd owns the PTY master for this session.
                let group = unsafe { libc::tcgetpgrp(fd) };
                (group > 1).then_some(group)
            });
        let group = foreground.unwrap_or(self.pid as libc::pid_t);
        // SAFETY: negative PID addresses one process group.
        unsafe {
            libc::kill(-group, number);
        }
    }

    fn wait_for_cleanup_until(&self, deadline: Instant) -> bool {
        let Ok(mut complete) = self.cleanup_complete.lock() else {
            return false;
        };
        while !*complete {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let Ok((next, timeout)) = self.cleanup_cv.wait_timeout(complete, remaining) else {
                return false;
            };
            complete = next;
            if timeout.timed_out() && !*complete {
                return false;
            }
        }
        true
    }
}

impl RunningProcess for LinuxProcessControl {
    fn terminate(&self) {
        if self.termination_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        kill_process_group(self.pid, libc::SIGTERM);
    }

    fn force_terminate(&self) {
        self.termination_requested.store(true, Ordering::Release);
        kill_process_group(self.pid, libc::SIGKILL);
    }

    fn wait_for_cleanup(&self, timeout: Duration) -> bool {
        if self
            .cleanup_complete
            .lock()
            .map(|complete| *complete)
            .unwrap_or(false)
        {
            return true;
        }
        self.wait_for_cleanup_until(Instant::now() + timeout)
    }

    fn signal(&self, number: i32) {
        self.signal_target(number);
    }

    fn resize(&self, rows: u32, cols: u32) -> bool {
        if rows == 0 && cols == 0 {
            return true;
        }
        let Ok(fd) = self.lifecycle_fd.lock() else {
            return false;
        };
        let Some(fd) = fd.as_ref() else {
            return false;
        };
        super::terminal::apply_window_size(fd.as_raw_fd(), rows, cols).is_ok()
    }
}

fn async_reader(fd: OwnedFd) -> ProcessReader {
    let file: std::fs::File = fd.into();
    Box::new(tokio::fs::File::from_std(file))
}

fn async_writer(fd: OwnedFd) -> ProcessWriter {
    let file: std::fs::File = fd.into();
    Box::new(tokio::fs::File::from_std(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt;

    fn test_policy(root: &Path, network: NetworkMode) -> SandboxLaunchPolicy {
        SandboxLaunchPolicy::from_parts(
            "/bin/sh".into(),
            network,
            Vec::new(),
            BTreeMap::new(),
            root.into(),
        )
    }

    fn request(workspace: &Path, command: &str, pty: bool) -> LaunchRequest {
        LaunchRequest {
            sandbox_id: "linux-test".parse().expect("sandbox id"),
            workspace: workspace.into(),
            operation: super::super::LaunchOperation::Exec(command.as_bytes().to_vec()),
            pty: pty.then(|| super::super::PtySpec {
                term: "xterm-256color".to_string(),
                rows: 41,
                cols: 101,
                modes: vec![(russh::Pty::ECHO, 0)],
                window_revision: 7,
            }),
        }
    }

    #[test]
    fn pinned_nono_api_prepares_a_restricted_policy() {
        let workspace = tempfile::tempdir().expect("probe workspace");
        let caps = CapabilitySet::new()
            .allow_path("/usr", AccessMode::Read)
            .expect("usr read capability")
            .allow_file("/bin/sh", AccessMode::Read)
            .expect("shell read capability")
            .allow_path(workspace.path(), AccessMode::ReadWrite)
            .expect("workspace write capability")
            .set_network_mode(NonoNetworkMode::Blocked)
            .set_signal_mode(SignalMode::Isolated)
            .set_ipc_mode(IpcMode::SharedMemoryOnly);

        let abi = detect_abi().expect("landlock ABI detection");
        let prepared = prepare_seccomp_with_abi(&caps, &abi, SeccompOpts::network_fallback())
            .expect("policy preparation");
        let _fallback = prepared.fallback();

        let stage = RawSandboxStage::CreateRuleset;
        match stage {
            RawSandboxStage::CreateRuleset
            | RawSandboxStage::AddPathRule
            | RawSandboxStage::AddNetRule
            | RawSandboxStage::NoNewPrivs
            | RawSandboxStage::RestrictSelf
            | RawSandboxStage::InstallStaticFilter
            | RawSandboxStage::InstallNotifyFilter => {}
            _ => {}
        }
    }

    #[test]
    fn outbound_capability_set_prepares_without_network_handling() {
        let caps = CapabilitySet::new()
            .allow_path("/usr", AccessMode::Read)
            .expect("usr read capability")
            .set_network_mode(NonoNetworkMode::AllowAll);
        let abi = detect_abi().expect("landlock ABI detection");
        let prepared = prepare_seccomp_with_abi(&caps, &abi, SeccompOpts::network_fallback())
            .expect("policy preparation");
        assert!(matches!(prepared.fallback(), SeccompNetFallback::None));
    }

    #[tokio::test]
    async fn non_pty_launch_keeps_streams_separate_and_confines_filesystem() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let outside = tempfile::NamedTempFile::new().expect("outside secret");
        fs::write(outside.path(), b"SECRET").expect("write secret");
        assert!(
            Path::new("/etc/shadow").exists(),
            "Linux fixture needs /etc/shadow"
        );
        let command = format!(
            "printf OUT; printf ERR >&2; printf ok > inside; \
             if cat '{}' >/dev/null 2>&1; then exit 91; fi; \
             if (printf hacked > '{}') 2>/dev/null; then exit 92; fi; \
             if cat /etc/shadow >/dev/null 2>&1; then exit 93; fi",
            outside.path().display(),
            outside.path().display(),
        );
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let mut launched = launcher
            .launch(request(workspace.path(), &command, false))
            .expect("launch");
        drop(launched.stdin.take());
        let mut stdout = String::new();
        let mut stderr = String::new();
        launched
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .await
            .expect("read stdout");
        launched
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut stderr)
            .await
            .expect("read stderr");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        assert_eq!(stdout, "OUT");
        assert_eq!(stderr, "ERR");
        assert_eq!(
            fs::read(workspace.path().join("inside")).expect("inside"),
            b"ok"
        );
    }

    #[tokio::test]
    async fn pty_launch_uses_final_stdio_session_and_requested_terminal_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let command = "test -t 0 && test -t 1 && test -t 2 && printf 'PTY_OK '; stty size; stty -a | grep -q -- '-echo'";
        let mut launched = launcher
            .launch(request(workspace.path(), command, true))
            .expect("launch");
        assert!(launched.stderr.is_none());
        assert_eq!(launched.window_revision, 7);
        drop(launched.stdin.take());
        let mut output = String::new();
        launched
            .stdout
            .take()
            .expect("pty stdout")
            .read_to_string(&mut output)
            .await
            .expect("read pty");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        assert!(output.contains("PTY_OK 41 101"), "PTY output: {output:?}");
    }

    #[tokio::test]
    async fn terminate_targets_the_owned_session_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let launched = launcher
            .launch(request(workspace.path(), "sleep 30", false))
            .expect("launch");
        launched.control.terminate();
        let exit = tokio::time::timeout(Duration::from_secs(5), launched.wait)
            .await
            .expect("termination timeout")
            .expect("wait channel")
            .expect("wait");
        assert_eq!(
            exit,
            ProcessExit::Signal {
                number: libc::SIGTERM,
                core_dumped: false
            }
        );
        assert!(launched.control.wait_for_cleanup(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn outbound_network_allows_client_connect() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("probe listener");
        let port = listener.local_addr().expect("listener address").port();
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Outbound))
            .expect("linux launcher");
        let command = format!(
            "python3 -c 'import socket; s=socket.socket(); s.connect((\"127.0.0.1\", {port}))'"
        );
        let launched = launcher
            .launch(request(workspace.path(), &command, false))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
    }

    #[tokio::test]
    async fn signal_forwards_to_the_owned_process_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let command = "trap 'printf signaled > signal; exit 0' USR1; printf ready > ready; while :; do sleep 1; done";
        let launched = launcher
            .launch(request(workspace.path(), command, false))
            .expect("launch");
        let ready = workspace.path().join("ready");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "sandbox did not reach signal wait state");
        launched.control.signal(libc::SIGUSR1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), launched.wait)
                .await
                .expect("signal timeout")
                .expect("wait channel")
                .expect("wait"),
            ProcessExit::Code(0)
        );
        assert_eq!(
            fs::read(workspace.path().join("signal")).expect("signal marker"),
            b"signaled"
        );
    }

    #[tokio::test]
    async fn direct_child_exit_cleans_remaining_process_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let launched = launcher
            .launch(request(
                workspace.path(),
                "sleep 30 & printf '%s' $! > background-pid; exit 0",
                false,
            ))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        let pid: libc::pid_t = fs::read_to_string(workspace.path().join("background-pid"))
            .expect("background pid")
            .parse()
            .expect("numeric pid");
        // A descendant that is already a zombie has been killed and cannot
        // retain files or execute; only PID 1 can reap it after it has been
        // orphaned. Accept either an already-reaped PID or the zombie state so
        // this test does not depend on whether the surrounding container uses
        // an init process.
        // SAFETY: signal zero only checks whether this exact PID still exists.
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("descendant stat");
            let state = stat
                .rfind(')')
                .and_then(|end| stat.as_bytes().get(end + 2))
                .copied();
            assert_eq!(
                state,
                Some(b'Z'),
                "background descendant {pid} remained live"
            );
        } else {
            assert_eq!(raw_errno(), libc::ESRCH);
        }
    }

    #[test]
    fn child_failure_status_pipe_round_trips_fixed_stage_and_errno() {
        let (read, write) = make_pipe("status pipe").expect("status pipe");
        // SAFETY: the child performs only the allocation-free child_fail path
        // and exits with _exit; the parent owns the normal Rust-side cleanup.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                child_fail(
                    write.as_raw_fd(),
                    ChildFailureKind::WorkingDirectory,
                    9,
                    libc::ENOENT,
                )
            }
        }
        drop(write);
        let failure = read_child_failure(read)
            .expect("read child failure")
            .expect("child failure record");
        assert_eq!(failure.kind, ChildFailureKind::WorkingDirectory);
        assert_eq!(failure.detail, 9);
        assert_eq!(failure.errno, libc::ENOENT);
        let mut status = 0;
        // SAFETY: pid is the direct child returned by fork above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), CHILD_SETUP_EXIT);
    }

    #[tokio::test]
    async fn launch_temp_cleanup_removes_child_created_entries() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        let launched = launcher
            .launch(request(
                workspace.path(),
                r#"mkdir -p "$TMPDIR/nested"; printf residue > "$TMPDIR/nested/file""#,
                false,
            ))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        assert_eq!(
            fs::read_dir(root.path())
                .expect("runtime root listing")
                .count(),
            0,
            "per-launch temp directory leaked after child exit"
        );
    }

    #[tokio::test]
    async fn disabled_network_rejects_tcp_connect() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("probe listener");
        let port = listener.local_addr().expect("listener address").port();
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        // Landlock's network rules mediate bind/connect, not socket creation.
        // A real listener makes this red if confinement is absent: the
        // connection would otherwise succeed immediately on loopback.
        let command = format!(
            "python3 -c 'import socket; s=socket.socket(); s.connect((\"127.0.0.1\", {port}))' >/dev/null 2>&1 && exit 90 || exit 0"
        );
        let launched = launcher
            .launch(request(workspace.path(), &command, false))
            .expect("launch");
        let exit = launched.wait.await.expect("wait channel").expect("wait");
        assert_eq!(
            exit,
            ProcessExit::Code(0),
            "network block probe result: {exit:?}"
        );
    }
}
