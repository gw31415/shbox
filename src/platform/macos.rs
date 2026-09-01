//! macOS production launcher using shbox-owned process/PTY lifecycle and Seatbelt.
//!
//! The Seatbelt profile is generated completely in the parent. The post-fork
//! child performs only the fixed terminal/session and chdir operations before
//! exec'ing `/usr/bin/sandbox-exec`; no allocating sandbox API is called there.

#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::policy::{LaunchTemp, SandboxLaunchPolicy, validated_shell_command};
use super::terminal::{PtyIo, PtyPair, child_session_setup, duplicate_fd};
use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, RunningProcess,
};
use crate::config::NetworkMode;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const PROCESS_GROUP_SETTLE: Duration = Duration::from_secs(1);

/// Process-lifetime macOS launcher. Seatbelt is only the confinement layer;
/// shbox owns every process and terminal resource around it.
pub(crate) struct MacosLauncher {
    policy: SandboxLaunchPolicy,
}

impl fmt::Debug for MacosLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosLauncher")
            .field("policy", &self.policy)
            .field("wrapper", &SANDBOX_EXEC)
            .finish()
    }
}

impl MacosLauncher {
    pub(crate) fn new(policy: SandboxLaunchPolicy) -> Result<Self, LaunchError> {
        let metadata = fs::metadata(SANDBOX_EXEC).map_err(|_| {
            LaunchError::new("sandbox process adapter unavailable: sandbox-exec is missing")
        })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: sandbox-exec is not executable",
            ));
        }
        Ok(Self { policy })
    }

    fn profile_for(
        &self,
        workspace: &Path,
        launch_temp: &Path,
        pty: bool,
    ) -> Result<String, LaunchError> {
        build_seatbelt_profile(&self.policy, workspace, launch_temp, pty)
    }
}

impl ProcessLauncher for MacosLauncher {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError> {
        let workspace = fs::canonicalize(&request.workspace)
            .map_err(|_| LaunchError::new("sandbox workspace is unavailable"))?;
        if !workspace.is_dir() {
            return Err(LaunchError::new("sandbox workspace is unavailable"));
        }

        let launch_temp = self.policy.create_launch_temp()?;
        let launch_temp_path = fs::canonicalize(launch_temp.path())
            .map_err(|_| LaunchError::new("sandbox launch temp directory became unavailable"))?;
        let is_pty = request.pty.is_some();
        let profile = self.profile_for(&workspace, &launch_temp_path, is_pty)?;
        let workspace_c = std::ffi::CString::new(workspace.as_os_str().as_bytes())
            .map_err(|_| LaunchError::new("sandbox workspace path contains NUL"))?;
        let command_arg = validated_shell_command(&request.operation)?;
        let environment = self.policy.environment_for(
            &workspace,
            request.pty.as_ref().map(|pty| pty.term.as_str()),
            Some(&launch_temp_path),
        );

        // Darwin lacks pipe2(O_CLOEXEC). Hold the process-wide spawn lock from
        // descriptor creation through fork/exec so no concurrent child can
        // inherit the short-lived pipe/PTY descriptors.
        let _spawn_guard = super::process_spawn_lock()
            .lock()
            .map_err(|_| LaunchError::new("sandbox process adapter is unavailable"))?;

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
        let setup_raw = setup_fd.as_ref().map(AsRawFd::as_raw_fd);

        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-p").arg(profile).arg(self.policy.shell());
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

        // SAFETY: all captured values were allocated in the parent. The child
        // only performs fixed raw syscalls plus the audited terminal helper;
        // Seatbelt itself is applied by sandbox-exec after exec.
        unsafe {
            command.pre_exec(move || {
                if let Some(setup_raw) = setup_raw {
                    child_session_setup(setup_raw, true)
                        .map_err(|error| io::Error::from_raw_os_error(error.errno))?;
                } else if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(workspace_c.as_ptr()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|_| LaunchError::new("sandbox process launch failed"))?;
        let pid = child.id();

        // fork completed; child-only descriptor copies are no longer needed in
        // the daemon. Production PTY ownership retains only the master.
        drop(setup_fd);
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

        let control = Arc::new(MacosProcessControl::new(pid, lifecycle_fd));
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
        let wait_control = Arc::clone(&control);
        let spawn_result = std::thread::Builder::new()
            .name("shbox-macos-sandbox-wait".to_string())
            .spawn(move || wait_process(child, wait_control, launch_temp, wait_tx));
        if spawn_result.is_err() {
            control.force_terminate();
            // The failed thread spawn dropped the Child handle, but the direct
            // process is still ours. Reap it explicitly by PID.
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

fn build_seatbelt_profile(
    policy: &SandboxLaunchPolicy,
    workspace: &Path,
    launch_temp: &Path,
    pty: bool,
) -> Result<String, LaunchError> {
    let read_paths = policy.resolved_read_paths();
    let mut write_paths = policy.curated_write_paths();
    write_paths.push(workspace.to_path_buf());
    write_paths.push(launch_temp.to_path_buf());

    let mut profile = String::with_capacity(8192);
    writeln!(&mut profile, "(version 1)").expect("write profile");
    writeln!(&mut profile, "(deny default)").expect("write profile");

    // Process/session behavior mirrors nono 0.74's macOS policy: fork/exec,
    // self + same-sandbox process inspection, and same-sandbox signaling.
    writeln!(&mut profile, "(allow process-fork)").expect("write profile");
    writeln!(&mut profile, "(allow process-info* (target self))").expect("write profile");
    writeln!(&mut profile, "(allow process-info* (target same-sandbox))").expect("write profile");
    writeln!(&mut profile, "(allow signal (target self))").expect("write profile");
    writeln!(&mut profile, "(allow signal (target same-sandbox))").expect("write profile");

    writeln!(&mut profile, "(allow sysctl-read)").expect("write profile");
    writeln!(&mut profile, "(allow system-fsctl)").expect("write profile");
    writeln!(&mut profile, "(allow system-info)").expect("write profile");

    // Basic macOS Mach/IPC services required by ordinary command runtimes.
    // Keep the compatibility-oriented lookup baseline from nono, but deny the
    // credential-bearing security services explicitly.
    writeln!(&mut profile, "(allow mach-lookup)").expect("write profile");
    for service in [
        "com.apple.SecurityServer",
        "com.apple.securityd",
        "com.apple.security.keychaind",
        "com.apple.secd",
        "com.apple.security.agent",
    ] {
        writeln!(
            &mut profile,
            "(deny mach-lookup (global-name \"{}\"))",
            service
        )
        .expect("write profile");
    }
    writeln!(&mut profile, "(allow mach-per-user-lookup)").expect("write profile");
    writeln!(&mut profile, "(allow mach-task-name)").expect("write profile");
    writeln!(&mut profile, "(deny mach-priv*)").expect("write profile");

    writeln!(&mut profile, "(allow ipc-posix-shm-read-data)").expect("write profile");
    writeln!(&mut profile, "(allow ipc-posix-shm-write-data)").expect("write profile");
    writeln!(&mut profile, "(allow ipc-posix-shm-write-create)").expect("write profile");

    // dyld/path traversal needs root metadata plus every ancestor of an
    // explicitly granted path. Ancestors receive metadata only.
    writeln!(&mut profile, "(allow file-read* (literal \"/\"))").expect("write profile");
    let mut ancestors = BTreeSet::new();
    for path in read_paths.iter().chain(write_paths.iter()) {
        let mut current = path.parent();
        while let Some(parent) = current {
            if parent == Path::new("/") || parent.as_os_str().is_empty() {
                break;
            }
            ancestors.insert(parent.to_path_buf());
            current = parent.parent();
        }
    }
    for ancestor in ancestors {
        append_path_filter_rule(&mut profile, "file-read-metadata", "literal", &ancestor)?;
    }

    for path in &read_paths {
        append_existing_path_rule(&mut profile, "file-read*", path)?;
        append_existing_path_rule(&mut profile, "file-map-executable", path)?;
        append_existing_path_rule(&mut profile, "process-exec*", path)?;
    }
    for path in &write_paths {
        append_existing_path_rule(&mut profile, "file-read*", path)?;
        append_existing_path_rule(&mut profile, "file-write*", path)?;
        append_existing_path_rule(&mut profile, "file-map-executable", path)?;
        append_existing_path_rule(&mut profile, "process-exec*", path)?;
    }

    if pty {
        writeln!(&mut profile, "(allow pseudo-tty)").expect("write profile");
        writeln!(&mut profile, "(allow file-read* (literal \"/dev/tty\"))").expect("write profile");
        writeln!(&mut profile, "(allow file-write* (literal \"/dev/tty\"))")
            .expect("write profile");
        writeln!(&mut profile, "(allow file-ioctl (literal \"/dev/tty\"))").expect("write profile");
        writeln!(
            &mut profile,
            "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))"
        )
        .expect("write profile");
        writeln!(
            &mut profile,
            "(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))"
        )
        .expect("write profile");
    }

    match policy.network() {
        NetworkMode::Disabled => {}
        NetworkMode::Outbound => append_outbound_network_profile(&mut profile)?,
    }

    Ok(profile)
}

fn append_outbound_network_profile(profile: &mut String) -> Result<(), LaunchError> {
    // Client-only TCP: no network-bind/network-inbound rule is emitted.
    writeln!(
        profile,
        "(allow system-socket (socket-domain AF_INET) (socket-type SOCK_STREAM))"
    )
    .expect("write profile");
    writeln!(
        profile,
        "(allow system-socket (socket-domain AF_INET6) (socket-type SOCK_STREAM))"
    )
    .expect("write profile");
    writeln!(
        profile,
        "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))"
    )
    .expect("write profile");
    writeln!(profile, "(allow network-outbound (remote tcp))").expect("write profile");
    writeln!(
        profile,
        "(allow network-outbound (path \"/private/var/run/mDNSResponder\"))"
    )
    .expect("write profile");
    writeln!(
        profile,
        "(allow network-outbound (path \"/var/run/mDNSResponder\"))"
    )
    .expect("write profile");

    // Network.framework / CFNetwork consult these files on current macOS.
    for path in [
        Path::new("/Library/Preferences/com.apple.networkd.plist"),
        Path::new("/private/var/db/nsurlstoraged/dafsaData.bin"),
    ] {
        if path.exists() {
            append_existing_path_rule(profile, "file-read*", path)?;
        }
    }
    Ok(())
}

fn append_existing_path_rule(
    profile: &mut String,
    operation: &str,
    path: &Path,
) -> Result<(), LaunchError> {
    let metadata = fs::metadata(path)
        .map_err(|_| LaunchError::new("sandbox Seatbelt path became unavailable"))?;
    let filter = if metadata.is_dir() {
        "subpath"
    } else {
        "literal"
    };
    append_path_filter_rule(profile, operation, filter, path)
}

fn append_path_filter_rule(
    profile: &mut String,
    operation: &str,
    filter: &str,
    path: &Path,
) -> Result<(), LaunchError> {
    let escaped = seatbelt_escape_path(path)?;
    writeln!(
        profile,
        "(allow {} ({} \"{}\"))",
        operation, filter, escaped
    )
    .expect("write profile");
    Ok(())
}

fn seatbelt_escape_path(path: &Path) -> Result<String, LaunchError> {
    let value = path
        .to_str()
        .ok_or_else(|| LaunchError::new("sandbox path is not valid UTF-8 for Seatbelt"))?;
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                return Err(LaunchError::new(
                    "sandbox path contains a control character unsupported by Seatbelt",
                ));
            }
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

fn make_pipe(message: &'static str) -> Result<(OwnedFd, OwnedFd), LaunchError> {
    let (read, write) = nix::unistd::pipe().map_err(|_| LaunchError::new(message))?;
    set_cloexec(&read, message)?;
    set_cloexec(&write, message)?;
    Ok((read, write))
}

fn set_cloexec(fd: &OwnedFd, message: &'static str) -> Result<(), LaunchError> {
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl operates on the owned descriptor and only changes FD flags.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags == -1 {
        return Err(LaunchError::new(message));
    }
    // SAFETY: raw is still owned and valid for this call.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(LaunchError::new(message));
    }
    Ok(())
}

fn wait_process(
    mut child: Child,
    control: Arc<MacosProcessControl>,
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
    // SAFETY: child calls setsid before exec, so its PID is its process-group ID.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

fn wait_process_group_gone(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // SAFETY: signal zero only probes group existence/permission.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        if result == -1 && raw_errno() == libc::ESRCH {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn raw_errno() -> i32 {
    // SAFETY: __error returns the calling thread's errno slot on Darwin.
    unsafe { *libc::__error() }
}

struct MacosProcessControl {
    pid: u32,
    finished: AtomicBool,
    termination_requested: AtomicBool,
    lifecycle_fd: Mutex<Option<OwnedFd>>,
    cleanup_complete: Mutex<bool>,
    cleanup_cv: Condvar,
}

impl fmt::Debug for MacosProcessControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosProcessControl")
            .field("pid", &self.pid)
            .field("finished", &self.finished.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl MacosProcessControl {
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
        let foreground = self
            .lifecycle_fd
            .lock()
            .ok()
            .and_then(|fd| fd.as_ref().map(AsRawFd::as_raw_fd))
            .and_then(|fd| {
                // SAFETY: lifecycle fd owns this launch's PTY master.
                let group = unsafe { libc::tcgetpgrp(fd) };
                (group > 1).then_some(group)
            });
        let group = foreground.unwrap_or(self.pid as libc::pid_t);
        // SAFETY: negative pid targets exactly one process group.
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

impl RunningProcess for MacosProcessControl {
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
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt;

    fn test_policy(root: &Path, network: NetworkMode) -> SandboxLaunchPolicy {
        SandboxLaunchPolicy::from_parts(
            PathBuf::from("/bin/sh"),
            network,
            Vec::new(),
            BTreeMap::new(),
            root.to_path_buf(),
        )
    }

    fn request(workspace: &Path, command: &str, pty: bool) -> LaunchRequest {
        LaunchRequest {
            sandbox_id: "macos-test".parse().expect("sandbox id"),
            workspace: workspace.to_path_buf(),
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
    fn profile_is_deny_default_and_scopes_write_and_network() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let temp = tempfile::tempdir().expect("launch temp");
        let disabled = build_seatbelt_profile(
            &test_policy(root.path(), NetworkMode::Disabled),
            workspace.path(),
            temp.path(),
            true,
        )
        .expect("disabled profile");
        assert!(disabled.contains("(deny default)"));
        assert!(disabled.contains("(allow pseudo-tty)"));
        assert!(disabled.contains("(allow signal (target same-sandbox))"));
        assert!(!disabled.contains("(allow file-write* (subpath \"/\"))"));
        assert!(!disabled.contains("(allow network-outbound (remote tcp))"));

        let outbound = build_seatbelt_profile(
            &test_policy(root.path(), NetworkMode::Outbound),
            workspace.path(),
            temp.path(),
            false,
        )
        .expect("outbound profile");
        assert!(outbound.contains("(allow network-outbound (remote tcp))"));
        assert!(!outbound.contains("(allow network-bind)"));
        assert!(!outbound.contains("(allow network-inbound)"));
    }

    #[test]
    fn seatbelt_path_escaping_cannot_inject_a_rule() {
        let escaped =
            seatbelt_escape_path(Path::new("/tmp/x\"\n(allow default)")).expect("escaped path");
        assert!(escaped.contains("\\\""), "escaped path: {escaped:?}");
        assert!(escaped.contains("\\n"), "escaped path: {escaped:?}");
        assert!(
            !escaped.contains('\n'),
            "escaped path contains a raw newline"
        );
    }

    #[tokio::test]
    async fn non_pty_launch_keeps_streams_separate_and_confines_filesystem() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let outside_dir = tempfile::tempdir().expect("outside dir");
        let outside = outside_dir.path().join("secret");
        fs::write(&outside, b"SECRET").expect("outside secret");
        let command = format!(
            "printf OUT; printf ERR >&2; printf ok > inside; if cat '{}' >/dev/null 2>&1; then exit 91; fi; if printf bad > '{}' 2>/dev/null; then exit 92; fi",
            outside.display(),
            outside.display()
        );
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
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
        assert!(stderr.starts_with("ERR"), "stderr: {stderr:?}");
        assert!(
            stderr.contains("Operation not permitted"),
            "sandbox denial was not reported: {stderr:?}"
        );
        assert_eq!(
            fs::read(workspace.path().join("inside")).expect("inside"),
            b"ok"
        );
        assert_eq!(fs::read(&outside).expect("outside remains"), b"SECRET");
    }

    #[tokio::test]
    async fn pty_launch_uses_final_stdio_session_and_terminal_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
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
    async fn disabled_network_rejects_tcp_connect() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("listener address").port();
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
        let command =
            format!("/usr/bin/nc -z 127.0.0.1 {port} >/dev/null 2>&1 && exit 90 || exit 0");
        let launched = launcher
            .launch(request(workspace.path(), &command, false))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
    }

    #[tokio::test]
    async fn outbound_network_allows_client_connect_without_bind_grant() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("listener address").port();
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Outbound))
            .expect("macos launcher");
        let command = format!("/usr/bin/nc -z 127.0.0.1 {port}");
        let launched = launcher
            .launch(request(workspace.path(), &command, false))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
    }

    #[tokio::test]
    async fn signal_forwards_to_owned_process_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
        let launched = launcher
            .launch(request(
                workspace.path(),
                "trap 'printf signaled > signal; exit 0' USR1; printf ready > ready; while :; do sleep 1; done",
                false,
            ))
            .expect("launch");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !workspace.path().join("ready").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            workspace.path().join("ready").exists(),
            "child never became ready"
        );
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
    async fn launch_temp_cleanup_removes_child_created_entries() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
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
            0
        );
    }

    #[tokio::test]
    async fn terminate_reaps_direct_child_and_process_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
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
    async fn force_terminate_reaps_direct_child_and_process_group() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
        let launched = launcher
            .launch(request(workspace.path(), "sleep 30", false))
            .expect("launch");
        launched.control.force_terminate();
        let exit = tokio::time::timeout(Duration::from_secs(5), launched.wait)
            .await
            .expect("force termination timeout")
            .expect("wait channel")
            .expect("wait");
        assert_eq!(
            exit,
            ProcessExit::Signal {
                number: libc::SIGKILL,
                core_dumped: false
            }
        );
        assert!(launched.control.wait_for_cleanup(Duration::from_secs(1)));
    }

    #[test]
    fn wrapper_is_fixed_to_system_sandbox_exec() {
        assert_eq!(SANDBOX_EXEC, "/usr/bin/sandbox-exec");
        assert!(Path::new(SANDBOX_EXEC).is_absolute());
    }
}
