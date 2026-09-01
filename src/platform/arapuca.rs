//! Production process adapter for the pinned Arapuca runtime.
//!
//! The rest of shbox deliberately knows only the private `ProcessLauncher`
//! seam in `platform::mod`.  This module owns the Arapuca-specific profile,
//! task-id, pipe, signal, and wait/cleanup details.  It is initialized once
//! during daemon bootstrap; a missing external wrapper or platform prerequisite
//! is a normal fail-closed state for sandbox launches, not a host-process
//! fallback. macOS arm64 can use shbox's embedded rlimit wrapper.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(any(target_os = "linux", test))]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Config, Limits, NetworkMode};
use crate::sandbox::SandboxId;

use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, PtyIo, RunningProcess, apply_terminal_modes, apply_window_size, duplicate_fd,
};

const TASK_RANDOM_BYTES: usize = 16;
const TASK_ID_ATTEMPTS: usize = 32;

/// The validated shbox policy captured by the process-lifetime adapter.
///
/// The backend-neutral snapshot lives in [`super::policy`]; this wrapper only
/// translates it into the pinned Arapuca profile for as long as Arapuca
/// drives production launch.
#[derive(Clone)]
pub(crate) struct ArapucaLaunchPolicy {
    inner: super::policy::SandboxLaunchPolicy,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxScope {
    private: PathBuf,
    restore: PathBuf,
    active_tasks: Option<Arc<Mutex<HashSet<String>>>>,
}

#[cfg(target_os = "linux")]
impl LinuxScope {
    fn retain_tasks(&mut self, active_tasks: Arc<Mutex<HashSet<String>>>) {
        self.active_tasks = Some(active_tasks);
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxScope {
    fn drop(&mut self) {
        let active = self
            .active_tasks
            .as_ref()
            .and_then(|tasks| tasks.lock().ok().map(|set| !set.is_empty()))
            .unwrap_or(false);
        if active {
            tracing::warn!(
                scope = %self.private.display(),
                "leaving private sandbox cgroup in place while tasks are active"
            );
            return;
        }

        let pid = std::process::id().to_string();
        if let Err(error) = fs::write(self.restore.join("cgroup.procs"), &pid) {
            tracing::warn!(
                scope = %self.private.display(),
                error = %error,
                "could not restore daemon cgroup"
            );
            return;
        }
        if let Err(error) = fs::remove_dir(&self.private) {
            tracing::debug!(
                scope = %self.private.display(),
                error = %error,
                "could not remove private sandbox cgroup"
            );
        }
    }
}

impl ArapucaLaunchPolicy {
    /// Combine the file-backed config — including its `[sandbox] network`
    /// mode, which is process-lifetime — with the validated shell and the
    /// shbox runtime temp root into the neutral launch snapshot.
    pub(crate) fn from_config(
        config: &Config,
        shell: impl Into<PathBuf>,
        temp_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            inner: super::policy::SandboxLaunchPolicy::from_config(config, shell, temp_root),
        }
    }

    fn profile_for(&self, workspace: &Path) -> ::arapuca::Profile {
        // The curated defaults, the validated shell, and the configured read
        // paths are resolved by the neutral policy module.
        let read_paths = self.inner.resolved_read_paths();

        let limits = Limits::default();
        let (max_cpu_pct, max_pids) = limits
            .linux
            .map(|limits| (limits.max_cpu_pct, limits.max_pids))
            .unwrap_or((0, 0));

        let mut write_paths = vec![workspace.to_path_buf()];
        write_paths.extend(self.inner.curated_write_paths());

        let seccomp_profile = match self.inner.network() {
            NetworkMode::Disabled => ::arapuca::SeccompProfile::Strict,
            NetworkMode::Outbound => ::arapuca::SeccompProfile::Baseline,
        };
        ::arapuca::Profile {
            isolation: ::arapuca::Isolation::Process,
            read_paths,
            write_paths,
            max_memory_mb: limits.max_memory_mb,
            max_cpu_pct,
            max_pids,
            cgroup_policy: ::arapuca::CgroupPolicy::Required,
            cpu_timeout_secs: limits.cpu_timeout_secs,
            max_file_size_mb: limits.max_file_size_mb,
            max_open_files: limits.max_open_files,
            allow_exec: true,
            use_netns: false,
            use_pidns: false,
            dns_capture: false,
            seccomp_profile,
            audit_file_access: false,
            audit_network: false,
            seccomp_debug: false,
            allow_proxy_env: false,
            allow_keychain: false,
            ..Default::default()
        }
    }

    fn environment_for(&self, workspace: &Path, term: Option<&str>) -> Vec<(String, String)> {
        // Transitional Arapuca launches set no TMPDIR; the temp directory
        // becomes authoritative when the shbox-owned launchers take over.
        self.inner.environment_for(workspace, term, None)
    }
}

/// A process-lifetime Arapuca adapter.
pub(crate) struct ArapucaLauncher {
    backend: Box<dyn ::arapuca::platform::Sandbox>,
    policy: ArapucaLaunchPolicy,
    active_tasks: Arc<Mutex<HashSet<String>>>,
    #[cfg(target_os = "linux")]
    // The leading underscore documents that this is an owned lifetime guard:
    // its Drop implementation restores the daemon cgroup and removes the
    // private child after all task leases have drained.
    _linux_scope: LinuxScope,
}

impl fmt::Debug for ArapucaLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArapucaLauncher")
            .field("backend", &"pinned arapuca platform")
            .field(
                "active_task_count",
                &self.active_tasks.lock().map(|set| set.len()).ok(),
            )
            .finish_non_exhaustive()
    }
}

impl ArapucaLauncher {
    /// Construct the one shared backend after checking prerequisites that
    /// otherwise could mutate a shared cgroup during Arapuca initialization.
    /// The launch policy is fixed at construction: it is a process-lifetime
    /// snapshot of the boot-time config, cloned per launch.
    pub(crate) fn new(policy: ArapucaLaunchPolicy) -> Result<Self, LaunchError> {
        #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
        {
            let _ = &policy;
            return Err(LaunchError::new(
                "sandbox process adapter unavailable on this platform",
            ));
        }

        let wrapper = resolve_wrapper()?;
        ensure_executable_file(&wrapper)?;

        #[cfg(target_os = "linux")]
        let mut linux_scope = linux_scope_preflight()?;

        let backend = ::arapuca::platform::new_boxed()
            .map_err(|_| LaunchError::new("sandbox process adapter initialization failed"))?;
        backend
            .available()
            .map_err(|_| LaunchError::new("sandbox platform is unavailable"))?;

        #[cfg(target_os = "linux")]
        {
            if !backend.cgroups_available() {
                return Err(LaunchError::new(
                    "sandbox process adapter unavailable: cgroups are not available",
                ));
            }
            verify_linux_scope(&linux_scope.private, true)?;
        }

        // Keep the lookup above as an explicit startup assertion. Arapuca
        // resolves the wrapper again at launch, so a replacement/removal
        // after startup still fails closed instead of falling back.
        let active_tasks = Arc::new(Mutex::new(HashSet::new()));
        #[cfg(target_os = "linux")]
        linux_scope.retain_tasks(Arc::clone(&active_tasks));
        Ok(Self {
            backend,
            policy,
            active_tasks,
            #[cfg(target_os = "linux")]
            _linux_scope: linux_scope,
        })
    }

    fn acquire_task(&self, sandbox_id: &SandboxId) -> Result<TaskLease, LaunchError> {
        for _ in 0..TASK_ID_ATTEMPTS {
            let random: [u8; TASK_RANDOM_BYTES] = rand::random();
            let task_id = format!("{}-{}", sandbox_id, hex_lower(&random));
            if ::arapuca::sanitize_task_id(&task_id).is_err() {
                continue;
            }
            let mut active = self
                .active_tasks
                .lock()
                .map_err(|_| LaunchError::new("sandbox task registry is unavailable"))?;
            if active.insert(task_id.clone()) {
                return Ok(TaskLease {
                    task_id,
                    active_tasks: Arc::clone(&self.active_tasks),
                });
            }
        }
        Err(LaunchError::new(
            "sandbox process adapter could not allocate a unique task ID",
        ))
    }

    fn build_config(
        policy: &ArapucaLaunchPolicy,
        task_id: &str,
        workspace: &Path,
        stdio: (Option<RawFd>, Option<RawFd>, Option<RawFd>),
        tty: bool,
        term: Option<&str>,
    ) -> ::arapuca::Config {
        let (stdin, stdout, stderr) = stdio;
        ::arapuca::Config {
            profile: policy.profile_for(workspace),
            socket_dir: PathBuf::new(),
            task_id: task_id.to_string(),
            phase: "ssh".to_string(),
            work_dir: Some(workspace.to_path_buf()),
            stdin,
            stdout,
            stderr,
            extra_fds: Vec::new(),
            tty,
            network_proxy_socket: None,
            #[cfg(target_os = "linux")]
            allowed_hosts: Vec::new(),
            env: policy.environment_for(workspace, term),
            audit_sink: None,
            audit_verbosity: ::arapuca::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        }
    }
}

/// Owns an Arapuca process while post-spawn PTY setup is still fallible. If a
/// descriptor duplicate or ioctl fails, the process must be terminated and
/// reaped before the launch error is returned; dropping Arapuca alone does not
/// remove macOS descendants from the process group.
struct ProcessSetupGuard {
    process: Option<::arapuca::Process>,
    pid: u32,
}

impl ProcessSetupGuard {
    fn new(process: ::arapuca::Process) -> ProcessSetupGuard {
        let pid = process.pid();
        ProcessSetupGuard {
            process: Some(process),
            pid,
        }
    }

    fn process(&self) -> &::arapuca::Process {
        self.process.as_ref().expect("process setup guard")
    }

    fn into_process(mut self) -> ::arapuca::Process {
        self.process.take().expect("process setup guard")
    }
}

impl Drop for ProcessSetupGuard {
    fn drop(&mut self) {
        let Some(process) = self.process.take() else {
            return;
        };
        let pid = self.pid;
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::Builder::new()
            .name("shbox-sandbox-setup-cleanup".to_string())
            .spawn(move || {
                let mut process = process;
                let _ = process.wait();
                process.cleanup();
                let _ = done_tx.send(());
            });
        let Ok(worker) = worker else {
            signal_process_group(pid, libc::SIGKILL);
            return;
        };
        signal_process_group(pid, libc::SIGTERM);
        if done_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            signal_process_group(pid, libc::SIGKILL);
            let _ = done_rx.recv_timeout(Duration::from_secs(5));
        }
        let _ = worker.join();
    }
}

impl ProcessLauncher for ArapucaLauncher {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError> {
        let _launch_guard = crate::platform::process_spawn_lock()
            .lock()
            .map_err(|_| LaunchError::new("sandbox process adapter is unavailable"))?;
        let policy = self.policy.clone();
        let task = self.acquire_task(&request.sandbox_id)?;
        let workspace = fs::canonicalize(&request.workspace)
            .map_err(|_| LaunchError::new("sandbox workspace is unavailable"))?;
        if !workspace.is_dir() {
            return Err(LaunchError::new("sandbox workspace is unavailable"));
        }

        let is_pty = request.pty.is_some();
        let (stdin_child, stdin_parent): (Option<OwnedFd>, Option<OwnedFd>) = if is_pty {
            (None, None)
        } else {
            let (child, parent) = make_pipe()?;
            (Some(child), Some(parent))
        };
        let (stdout_parent, stdout_child): (Option<OwnedFd>, Option<OwnedFd>) = if is_pty {
            (None, None)
        } else {
            let (parent, child) = make_pipe()?;
            (Some(parent), Some(child))
        };
        let (stderr_parent, stderr_child): (Option<OwnedFd>, Option<OwnedFd>) = if is_pty {
            (None, None)
        } else {
            let (parent, child) = make_pipe()?;
            (Some(parent), Some(child))
        };

        let command = policy
            .inner
            .shell()
            .to_str()
            .ok_or_else(|| LaunchError::new("sandbox shell path is not valid UTF-8"))?;
        let command_arg = super::policy::validated_shell_command(&request.operation)?;
        let args_storage = match command_arg {
            Some(command) => vec!["-c".to_string(), command],
            None => vec!["-l".to_string()],
        };
        let args: Vec<&str> = args_storage.iter().map(String::as_str).collect();

        let config = Self::build_config(
            &policy,
            &task.task_id,
            &workspace,
            (
                stdin_child.as_ref().map(|fd| fd.as_raw_fd()),
                stdout_child.as_ref().map(|fd| fd.as_raw_fd()),
                stderr_child.as_ref().map(|fd| fd.as_raw_fd()),
            ),
            is_pty,
            request.pty.as_ref().map(|pty| pty.term.as_str()),
        );
        let process = self
            .backend
            .launch(&config, command, &args)
            .map_err(|_| LaunchError::new("sandbox process launch failed"))?;
        let process = ProcessSetupGuard::new(process);

        // Arapuca has synchronously forked and duplicated the configured
        // descriptors. No child-side FD is needed after launch returns.
        drop(stdin_child);
        drop(stdout_child);
        drop(stderr_child);

        let (pty_stdin, pty_stdout, lifecycle_fd) = if let Some(pty) = request.pty.as_ref() {
            let master = process
                .process()
                .pty_master()
                .ok_or_else(|| LaunchError::new("sandbox PTY master was not returned"))?;
            let master_fd = master.as_raw_fd();
            let read_fd = duplicate_fd(master_fd)
                .map_err(|_| LaunchError::new("sandbox PTY read duplicate failed"))?;
            let write_fd = duplicate_fd(master_fd)
                .map_err(|_| LaunchError::new("sandbox PTY write duplicate failed"))?;
            let lifecycle_fd = duplicate_fd(master_fd)
                .map_err(|_| LaunchError::new("sandbox PTY lifecycle duplicate failed"))?;

            apply_window_size(lifecycle_fd.as_raw_fd(), pty.rows, pty.cols)
                .map_err(|_| LaunchError::new("sandbox PTY window size could not be applied"))?;
            apply_terminal_modes(lifecycle_fd.as_raw_fd(), &pty.modes)
                .map_err(|_| LaunchError::new("sandbox PTY terminal modes could not be applied"))?;

            let stdin = PtyIo::new(write_fd)
                .map_err(|_| LaunchError::new("sandbox PTY writer could not be initialized"))?;
            let stdout = PtyIo::new(read_fd)
                .map_err(|_| LaunchError::new("sandbox PTY reader could not be initialized"))?;
            (
                Some(Box::new(stdin) as ProcessWriter),
                Some(Box::new(stdout) as ProcessReader),
                Some(lifecycle_fd),
            )
        } else {
            (None, None, None)
        };

        let pid = process.process().pid();
        let control = Arc::new(ArapucaProcessControl::new(pid, lifecycle_fd));
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
        let wait_control = Arc::clone(&control);
        let wait_task = task;
        let process = process;
        let spawn_result = std::thread::Builder::new()
            .name("shbox-sandbox-wait".to_string())
            .spawn(move || wait_process(process.into_process(), wait_control, wait_task, wait_tx));
        if spawn_result.is_err() {
            // Dropping Process is Arapuca's force-cleanup path. It kills and
            // reaps before removing its private temp/cgroup state.
            return Err(LaunchError::new(
                "sandbox process waiter could not be started",
            ));
        }

        let (stdin, stdout, stderr) = if is_pty {
            (pty_stdin, pty_stdout, None)
        } else {
            (
                Some(async_writer(stdin_parent.expect("non-PTY stdin parent"))),
                Some(async_reader(stdout_parent.expect("non-PTY stdout parent"))),
                Some(async_reader(stderr_parent.expect("non-PTY stderr parent"))),
            )
        };
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

fn wait_process(
    mut process: ::arapuca::Process,
    control: Arc<ArapucaProcessControl>,
    _task: TaskLease,
    wait_tx: tokio::sync::oneshot::Sender<Result<ProcessExit, LaunchError>>,
) {
    let pid = process.pid();
    let result = match process.wait() {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
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
            // Once wait has returned, the direct PID is no longer safe to
            // target. Keep late signal requests away while descendants and
            // Arapuca-owned resources are being cleaned up.
            control.finished.store(true, Ordering::Release);
            kill_descendants_after_wait(pid);
            // `cleanup` consumes Process and must happen after wait. Keeping
            // it in this same thread makes the wait-channel completion mean
            // both reaping and Arapuca-owned resource cleanup are finished.
            process.cleanup();
            control.mark_cleanup_complete();
            Ok(exit)
        }
        Err(_) => {
            kill_process_group(pid);
            // Dropping Process is Arapuca's force-cleanup path when wait
            // itself fails. Publish completion only after that owner has been
            // dropped, so delete never races workspace removal with cleanup.
            drop(process);
            control.mark_cleanup_complete();
            Err(LaunchError::new("sandbox process wait failed"))
        }
    };
    let _ = wait_tx.send(result);
}

#[cfg(not(target_os = "linux"))]
fn kill_descendants_after_wait(pid: u32) {
    // The pinned Arapuca wait path performs this cleanup on Linux.  Its
    // non-Linux process wait reaps the direct child but does not own a cgroup,
    // so the adapter closes the same setsid-created process group before
    // publishing completion.
    kill_process_group(pid);
}

#[cfg(target_os = "linux")]
fn kill_descendants_after_wait(_pid: u32) {}

fn signal_process_group(pid: u32, signal: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: Arapuca creates a new session for the launched process, making
    // its PID the process-group ID. ESRCH simply means the group is gone.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

fn kill_process_group(pid: u32) {
    signal_process_group(pid, libc::SIGKILL);
}

#[derive(Debug)]
struct TaskLease {
    task_id: String,
    active_tasks: Arc<Mutex<HashSet<String>>>,
}

impl Drop for TaskLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_tasks.lock() {
            active.remove(&self.task_id);
        }
    }
}

#[derive(Debug)]
struct ArapucaProcessControl {
    pid: u32,
    finished: AtomicBool,
    termination_requested: AtomicBool,
    lifecycle_fd: Mutex<Option<OwnedFd>>,
    cleanup_complete: Mutex<bool>,
    cleanup_cv: Condvar,
}

impl ArapucaProcessControl {
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
        self.finished.store(true, Ordering::Release);
        if let Ok(mut lifecycle_fd) = self.lifecycle_fd.lock() {
            lifecycle_fd.take();
        }
        if let Ok(mut complete) = self.cleanup_complete.lock() {
            *complete = true;
            self.cleanup_cv.notify_all();
        }
    }

    fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
            .lock()
            .map(|complete| *complete)
            .unwrap_or(false)
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

    fn signal_group(&self, signal: i32) {
        if self.pid <= 1 || self.finished.load(Ordering::Acquire) {
            return;
        }
        // Arapuca's Unix launch path calls setsid(), so its returned process
        // is the process-group leader.
        let group = -(self.pid as libc::pid_t);
        // SAFETY: `group` is a process-group target derived from the owned
        // Arapuca process PID and `signal` is supplied by the validated SSH
        // signal mapping or the fixed teardown signal.
        unsafe {
            libc::kill(group, signal);
        }
    }
}

impl RunningProcess for ArapucaProcessControl {
    fn terminate(&self) {
        if self.termination_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        self.signal_group(libc::SIGTERM);
    }

    fn force_terminate(&self) {
        self.termination_requested.store(true, Ordering::Release);
        self.signal_group(libc::SIGKILL);
    }

    fn wait_for_cleanup(&self, timeout: Duration) -> bool {
        if self.cleanup_complete() {
            return true;
        }
        self.wait_for_cleanup_until(Instant::now() + timeout)
    }

    fn signal(&self, number: i32) {
        self.signal_group(number);
    }

    fn resize(&self, rows: u32, cols: u32) -> bool {
        if rows == 0 && cols == 0 {
            return true;
        }
        let Ok(lifecycle_fd) = self.lifecycle_fd.lock() else {
            return false;
        };
        let Some(fd) = lifecycle_fd.as_ref() else {
            return false;
        };
        apply_window_size(fd.as_raw_fd(), rows, cols).is_ok()
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

#[cfg(target_os = "linux")]
fn make_pipe() -> Result<(OwnedFd, OwnedFd), LaunchError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two owned descriptors to the valid array. The
    // O_CLOEXEC flag is applied atomically before any concurrent fork can
    // observe either endpoint.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(LaunchError::new("sandbox stdio pipe creation failed"));
    }
    // SAFETY: pipe2 succeeded, so both descriptors are newly owned here.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}

#[cfg(not(target_os = "linux"))]
fn make_pipe() -> Result<(OwnedFd, OwnedFd), LaunchError> {
    let (read, write) =
        nix::unistd::pipe().map_err(|_| LaunchError::new("sandbox stdio pipe creation failed"))?;
    set_cloexec(&read)?;
    set_cloexec(&write)?;
    Ok((read, write))
}

#[cfg(not(target_os = "linux"))]
fn set_cloexec(fd: &OwnedFd) -> Result<(), LaunchError> {
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl is called for an owned, valid descriptor.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags == -1 {
        return Err(LaunchError::new("sandbox stdio pipe setup failed"));
    }
    // SAFETY: fcntl updates only the close-on-exec bit on the owned fd.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(LaunchError::new("sandbox stdio pipe setup failed"));
    }
    Ok(())
}

fn ensure_executable_file(path: &Path) -> Result<(), LaunchError> {
    let metadata = fs::metadata(path)
        .map_err(|_| LaunchError::new("sandbox process adapter unavailable: invalid wrapper"))?;
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LaunchError::new(
            "sandbox process adapter unavailable: invalid wrapper",
        ));
    }
    Ok(())
}

fn resolve_wrapper() -> Result<PathBuf, LaunchError> {
    if let Some(wrapper) = ::arapuca::env::wrapper_path() {
        return Ok(wrapper);
    }

    // Darwin's Seatbelt backend needs only the rlimit part of the standalone
    // wrapper. The daemon handles that boundary before exec and asks Arapuca
    // to resolve the current executable for subsequent launches.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        ::arapuca::selfexec::enable_selfexec_mode();
        if let Some(wrapper) = ::arapuca::env::wrapper_path() {
            return Ok(wrapper);
        }
    }

    Err(LaunchError::new(
        "sandbox process adapter unavailable: arapuca wrapper is missing",
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(target_os = "linux")]
fn linux_scope_preflight() -> Result<LinuxScope, LaunchError> {
    let restore = current_linux_cgroup_path()?;
    let parent = restore
        .parent()
        .filter(|path| *path != Path::new("/sys/fs/cgroup"))
        .map(Path::to_path_buf)
        .ok_or_else(|| LaunchError::new("sandbox cgroup scope has no delegated parent"))?;
    verify_linux_parent_scope(&parent)?;

    let pid = std::process::id().to_string();
    for _ in 0..TASK_ID_ATTEMPTS {
        let random: u64 = rand::random();
        let private = parent.join(format!("shbox-{pid}-{random:016x}"));
        match fs::create_dir(&private) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(LaunchError::new(
                    "sandbox cgroup scope cannot create a private child",
                ));
            }
        }

        if let Err(error) = fs::write(private.join("cgroup.procs"), &pid) {
            let _ = fs::remove_dir(&private);
            return Err(LaunchError::new(format!(
                "sandbox cgroup scope cannot isolate daemon: {error}"
            )));
        }

        if let Err(error) = verify_linux_scope(&private, false) {
            let _ = fs::write(restore.join("cgroup.procs"), &pid);
            let _ = fs::remove_dir(&private);
            return Err(error);
        }

        // Arapuca will discover this path through /proc/self/cgroup and may
        // create its own `leaf` below it.  Only this daemon is moved into the
        // child, so Arapuca's stale `arapuca-*` cleanup cannot touch sibling
        // workloads in a shared service/session scope.
        return Ok(LinuxScope {
            private,
            restore,
            active_tasks: None,
        });
    }
    Err(LaunchError::new(
        "sandbox cgroup scope cannot allocate a private child",
    ))
}

#[cfg(target_os = "linux")]
fn verify_linux_scope(path: &Path, require_subtree: bool) -> Result<(), LaunchError> {
    verify_linux_controllers(path, require_subtree)?;

    // Arapuca's cgroup manager may move the daemon into its `leaf` child
    // while enabling subtree control. Before that happens, and after it
    // happens, the private scope may contain only this daemon.
    let current_pid = std::process::id().to_string();
    let mut members = read_cgroup_members(&path.join("cgroup.procs"))?;
    let leaf = path.join("leaf");
    if leaf.is_dir() {
        members.extend(read_cgroup_members(&leaf.join("cgroup.procs"))?);
    }
    if members.iter().any(|pid| pid != &current_pid) {
        return Err(LaunchError::new(
            "sandbox cgroup scope contains unrelated processes",
        ));
    }
    if members.is_empty() {
        return Err(LaunchError::new(
            "sandbox cgroup scope has no daemon process",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_linux_parent_scope(path: &Path) -> Result<(), LaunchError> {
    let controllers = read_words(&path.join("cgroup.controllers"))?;
    for required in ["cpu", "cpuset", "memory", "pids"] {
        if !controllers.iter().any(|controller| controller == required) {
            return Err(LaunchError::new(
                "sandbox cgroup scope does not delegate required controllers",
            ));
        }
    }
    let subtree = read_words(&path.join("cgroup.subtree_control"))?;
    for required in ["cpu", "cpuset", "memory", "pids"] {
        if !subtree.iter().any(|controller| controller == required) {
            return Err(LaunchError::new(
                "sandbox cgroup scope does not pre-delegate required controllers",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_linux_controllers(path: &Path, require_subtree: bool) -> Result<(), LaunchError> {
    let controllers = read_words(&path.join("cgroup.controllers"))?;
    for required in ["cpu", "cpuset", "memory", "pids"] {
        if !controllers.iter().any(|controller| controller == required) {
            return Err(LaunchError::new(
                "sandbox cgroup scope does not delegate required controllers",
            ));
        }
    }

    if require_subtree {
        let subtree = read_words(&path.join("cgroup.subtree_control"))?;
        for required in ["cpu", "memory", "pids"] {
            if !subtree.iter().any(|controller| controller == required) {
                return Err(LaunchError::new(
                    "sandbox cgroup scope does not enable required controllers",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_linux_cgroup_path() -> Result<PathBuf, LaunchError> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| LaunchError::new("sandbox cgroup scope is unavailable"))?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|path| !path.is_empty() && *path != "/")
        .ok_or_else(|| LaunchError::new("sandbox cgroup scope is unavailable"))?;
    let relative = relative.trim_start_matches('/');
    let relative_path = Path::new(relative);
    if !relative_path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(LaunchError::new("sandbox cgroup scope is invalid"));
    }
    let path = PathBuf::from("/sys/fs/cgroup").join(relative_path);
    if !path.is_dir() {
        return Err(LaunchError::new("sandbox cgroup scope is unavailable"));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn read_words(path: &Path) -> Result<Vec<String>, LaunchError> {
    let content = fs::read_to_string(path)
        .map_err(|_| LaunchError::new("sandbox cgroup scope is unreadable"))?;
    Ok(content.split_whitespace().map(str::to_string).collect())
}

#[cfg(target_os = "linux")]
fn read_cgroup_members(path: &Path) -> Result<Vec<String>, LaunchError> {
    let content = fs::read_to_string(path)
        .map_err(|_| LaunchError::new("sandbox cgroup scope is unreadable"))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_maps_the_shbox_policy_without_exposing_arapuca_options() {
        let config = crate::config::defaults();
        let policy = ArapucaLaunchPolicy::from_config(&config, "/bin/sh", "/state/runtime");
        let directory = tempfile::tempdir().expect("workspace");
        let profile = policy.profile_for(directory.path());

        assert!(profile.allow_exec);
        #[cfg(target_os = "linux")]
        assert_eq!(
            profile.write_paths,
            vec![directory.path().to_path_buf(), PathBuf::from("/dev/null")]
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(profile.write_paths, vec![directory.path().to_path_buf()]);
        assert_eq!(profile.max_open_files, 1024);
        assert_eq!(profile.seccomp_profile, ::arapuca::SeccompProfile::Strict);
        let shell = std::fs::canonicalize("/bin/sh").expect("canonical shell");
        assert!(
            profile.read_paths.iter().any(|path| path == &shell),
            "canonical shell {shell:?} is not readable: {:?}",
            profile.read_paths
        );
    }

    #[test]
    fn outbound_network_uses_the_baseline_profile() {
        // `network` rides the config snapshot; the defaults carry `disabled`,
        // so this test builds the policy directly to exercise the other mode.
        let policy = ArapucaLaunchPolicy {
            inner: crate::platform::policy::SandboxLaunchPolicy::from_parts(
                PathBuf::from("/bin/sh"),
                NetworkMode::Outbound,
                Vec::new(),
                BTreeMap::new(),
                PathBuf::from("/state/runtime"),
            ),
        };
        let directory = tempfile::tempdir().expect("workspace");
        let profile = policy.profile_for(directory.path());

        assert_eq!(profile.seccomp_profile, ::arapuca::SeccompProfile::Baseline);
    }

    #[test]
    fn environment_is_workspace_scoped_and_deterministic() {
        let config = crate::config::defaults();
        let policy = ArapucaLaunchPolicy::from_config(&config, "/bin/sh", "/state/runtime");
        let directory = tempfile::tempdir().expect("workspace");
        let env = policy.environment_for(directory.path(), None);
        assert_eq!(
            env[0],
            ("HOME".into(), directory.path().display().to_string())
        );
        assert_eq!(
            env[1],
            ("PWD".into(), directory.path().display().to_string())
        );
        assert_eq!(env[2], ("SHELL".into(), "/bin/sh".into()));
    }

    #[test]
    fn requested_pty_term_overrides_the_operator_environment() {
        let mut sandbox_env = BTreeMap::new();
        sandbox_env.insert("TERM".to_string(), "operator-term".to_string());
        let policy = ArapucaLaunchPolicy {
            inner: crate::platform::policy::SandboxLaunchPolicy::from_parts(
                PathBuf::from("/bin/sh"),
                NetworkMode::Disabled,
                Vec::new(),
                sandbox_env,
                PathBuf::from("/state/runtime"),
            ),
        };
        let directory = tempfile::tempdir().expect("workspace");
        let env = policy.environment_for(directory.path(), Some("xterm-256color"));
        assert_eq!(env.iter().filter(|(name, _)| name == "TERM").count(), 1);
        assert_eq!(
            env.iter()
                .find(|(name, _)| name == "TERM")
                .map(|(_, value)| value.as_str()),
            Some("xterm-256color")
        );
    }

    #[test]
    fn task_id_shape_is_the_external_id_plus_128_bits() {
        let id = SandboxId::parse("dev").expect("sandbox id");
        let task_id = format!("{id}-{}", hex_lower(&[0xab; TASK_RANDOM_BYTES]));
        assert_eq!(task_id, "dev-abababababababababababababababab");
        assert!(::arapuca::sanitize_task_id(&task_id).is_ok());
        assert!(task_id.len() <= 128);
    }

    #[test]
    fn invalid_cgroup_relative_components_are_not_accepted() {
        let path = Path::new("a/../b");
        assert!(
            !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        );
    }
}
