//! macOS production launcher: shbox policy on the `shbox-sandbox` engine.
//!
//! The engine crate owns the Seatbelt profile generation and the
//! fork/exec/hygiene chain; this adapter owns the SSH-facing lifecycle
//! (PTY, session, I/O plumbing, waiter thread) exactly like the Linux one.
//! macOS is best-effort development isolation: see the engine crate docs
//! for the platform's security posture.

#![cfg(target_os = "macos")]

use std::fmt;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use shbox_sandbox::{
    CommandSpec, Sandbox, SandboxConfig as EngineConfig, SandboxError, SessionSetup, Stdio,
};

use super::policy::{
    CURATED_READ_PATHS, LaunchTemp, ReadPathClass, SandboxLaunchPolicy, login_shell_argv0,
    validated_shell_command,
};
use super::terminal::{PtyIo, PtyPair, duplicate_fd};
use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, RunningProcess,
};
#[cfg(test)]
use crate::config::NetworkMode;
#[cfg(test)]
use crate::config::SandboxResources;

const PROCESS_GROUP_SETTLE: Duration = Duration::from_secs(1);

/// macOS launcher backed by the engine's Seatbelt backend and the
/// process-lifetime shbox policy snapshot.
pub(crate) struct MacosLauncher {
    policy: SandboxLaunchPolicy,
    engine: Sandbox,
}

impl fmt::Debug for MacosLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosLauncher")
            .field("policy", &self.policy)
            .field("capabilities", self.engine.capabilities())
            .finish()
    }
}

impl MacosLauncher {
    pub(crate) fn new(policy: SandboxLaunchPolicy) -> Result<Self, LaunchError> {
        let engine = Sandbox::detect();
        if !engine.capabilities().seatbelt_available {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: /usr/bin/sandbox-exec is missing",
            ));
        }
        if policy.resources().cpu_quota_micros.is_some() {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: CPU quota cannot be enforced on macOS",
            ));
        }
        if policy.resources().swap_bytes.is_some() {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: swap limit cannot be enforced on macOS",
            ));
        }
        Ok(Self { policy, engine })
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
        // Resolve through symlinks once: the confinement rules and the
        // TMPDIR the child sees must name the same canonical directory.
        let launch_temp_path = fs::canonicalize(launch_temp.path())
            .map_err(|_| LaunchError::new("sandbox launch temp directory became unavailable"))?;
        let mut config: EngineConfig = self.policy.engine_config(&workspace, &launch_temp_path);
        promote_runtime_grants(&mut config, &self.policy);

        let mut command = CommandSpec::new(self.policy.shell());
        match validated_shell_command(&request.operation)? {
            Some(command_arg) => {
                // The raw command bytes are the single `-c` argument; this is
                // not a login shell.
                command = command.arg("-c").arg(command_arg);
            }
            None => {
                // Login mode without a shell-specific option: sshd's leading
                // `-` argv[0] convention.
                command.argv0 = Some(login_shell_argv0(self.policy.shell())?);
            }
        }
        let env = self
            .policy
            .environment_for(
                &workspace,
                request.pty.as_ref().map(|pty| pty.term.as_str()),
                Some(&launch_temp_path),
            )
            .into_iter()
            .map(|(name, value)| {
                (
                    std::ffi::OsString::from(name),
                    std::ffi::OsString::from(value),
                )
            })
            .collect();
        command.cwd = Some(workspace);
        command.env = env;

        // Darwin lacks an atomic pipe2(O_CLOEXEC) surface; hold the
        // process-wide spawn lock from descriptor creation through fork.
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

        if let Some(setup) = setup_fd.as_ref() {
            command.stdin = Stdio::Fd(setup.as_raw_fd());
            command.stdout = Stdio::Fd(setup.as_raw_fd());
            command.stderr = Stdio::Fd(setup.as_raw_fd());
            command.session = SessionSetup::NewSessionWithControllingTerminal;
        } else {
            command.stdin = Stdio::Pipe;
            command.stdout = Stdio::Pipe;
            command.stderr = Stdio::Pipe;
            command.session = SessionSetup::NewSession;
        }

        // The engine returns only after the Seatbelt launcher exec'd with
        // the profile applied; failures already cleaned up.
        let mut child = self
            .engine
            .spawn(command, config)
            .map_err(|error| LaunchError::new(describe_engine_error(&error)))?;
        // `None` would mean the child was already reaped — a pid of 0 must
        // never reach the group-signaling control (`kill(0, ..)` would
        // signal the daemon's own process group).
        let pid = child
            .id()
            .ok_or_else(|| LaunchError::new("sandbox child vanished before launch completion"))?;

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
                child.take_stdin().map(async_writer),
                child.take_stdout().map(async_reader),
                child.take_stderr().map(async_reader),
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

/// The engine keeps filesystem tiers distinct on macOS. Promote only the
/// shell and curated executable/runtime paths from the policy adapter's
/// read-only list; operator-provided data paths remain read-only.
fn promote_runtime_grants(config: &mut EngineConfig, policy: &SandboxLaunchPolicy) {
    let shbox_sandbox::FilesystemPolicy::Restricted {
        read_only, execute, ..
    } = &mut config.filesystem
    else {
        return;
    };

    let shell = fs::canonicalize(policy.shell()).unwrap_or_else(|_| policy.shell().to_path_buf());
    let read_rules = std::mem::take(read_only);
    for rule in read_rules {
        let is_runtime = rule.path == shell
            || CURATED_READ_PATHS.iter().any(|(path, class)| {
                *class == ReadPathClass::ExecutableRuntime
                    && fs::canonicalize(path).is_ok_and(|runtime| runtime == rule.path)
            });
        if is_runtime {
            execute.push(rule);
        } else {
            read_only.push(rule);
        }
    }
}

/// Render an engine failure for the SSH-facing launch error.
fn describe_engine_error(error: &SandboxError) -> String {
    match error {
        SandboxError::Setup {
            stage,
            detail,
            errno,
        } => format!(
            "sandbox child setup failed at {stage:?} (detail {detail}, errno {})",
            errno
                .map(|errno| errno.to_string())
                .unwrap_or_else(|| "n/a".into())
        ),
        other => format!("sandbox launch failed: {other}"),
    }
}

fn wait_process(
    mut child: shbox_sandbox::SandboxChild,
    control: Arc<MacosProcessControl>,
    launch_temp: LaunchTemp,
    wait_tx: tokio::sync::oneshot::Sender<Result<ProcessExit, LaunchError>>,
) {
    let result = match child.wait() {
        Ok(status) => Ok(if let Some(code) = status.code() {
            ProcessExit::Code(code)
        } else if let Some(number) = status.signal() {
            ProcessExit::Signal {
                number,
                core_dumped: status.core_dumped(),
            }
        } else {
            ProcessExit::Code(255)
        }),
        Err(_) => Err(LaunchError::new("sandbox process wait failed")),
    };
    kill_process_group(control.pid, libc::SIGKILL);
    wait_process_group_gone(control.pid, PROCESS_GROUP_SETTLE);
    drop(launch_temp);
    control.mark_cleanup_complete();
    let _ = wait_tx.send(result);
}

fn kill_process_group(pid: u32, signal: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: child calls setsid before exec, so its PID is its
    // process-group ID.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

fn wait_process_group_gone(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // SAFETY: signal zero only probes group existence/permission.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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

    fn detach_transport(&self) {
        // Close this channel's PTY master; kernel hangup semantics decide
        // what ends and what survives. No daemon-side signal is sent.
        if let Ok(mut lifecycle_fd) = self.lifecycle_fd.lock() {
            lifecycle_fd.take();
        }
    }
}

fn async_reader(file: std::fs::File) -> ProcessReader {
    Box::new(tokio::fs::File::from_std(file))
}

fn async_writer(file: std::fs::File) -> ProcessWriter {
    Box::new(tokio::fs::File::from_std(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;
    use tokio::io::AsyncReadExt;

    fn test_policy(root: &Path, network: NetworkMode) -> SandboxLaunchPolicy {
        test_policy_with_resources(root, network, SandboxResources::default())
    }

    fn test_policy_with_resources(
        root: &Path,
        network: NetworkMode,
        resources: SandboxResources,
    ) -> SandboxLaunchPolicy {
        SandboxLaunchPolicy::from_parts(
            "/bin/sh".into(),
            network,
            Vec::new(),
            BTreeMap::new(),
            root.to_path_buf(),
            resources,
            None,
        )
    }

    #[test]
    fn supported_rlimit_resources_are_accepted_by_launcher() {
        let root = tempfile::tempdir().expect("runtime root");
        let resources = SandboxResources {
            memory_bytes: Some(2 * 1024 * 1024 * 1024),
            pids: Some(64),
            ..SandboxResources::default()
        };
        MacosLauncher::new(test_policy_with_resources(
            root.path(),
            NetworkMode::Disabled,
            resources,
        ))
        .expect("memory and PID RLIMITs are supported on macOS");
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

    /// The exec payload is an opaque byte string: a non-UTF-8 command must
    /// reach the shell byte-for-byte as the single `-c` argument instead of
    /// being rejected by a UTF-8 conversion (docs/ssh-protocol.md §5).
    #[tokio::test]
    async fn exec_preserves_non_utf8_command_bytes() {
        use tokio::io::AsyncReadExt;

        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let mut command = b"printf %s 'x".to_vec();
        command.push(0xff);
        command.push(0xfe);
        command.extend_from_slice(b"y'");
        let request = LaunchRequest {
            sandbox_id: "macos-test".parse().expect("sandbox id"),
            workspace: workspace.path().to_path_buf(),
            operation: super::super::LaunchOperation::Exec(command),
            pty: None,
        };
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
        let mut launched = launcher.launch(request).expect("launch");
        drop(launched.stdin.take());
        let mut output = Vec::new();
        launched
            .stdout
            .take()
            .expect("stdout")
            .read_to_end(&mut output)
            .await
            .expect("read stdout");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        assert_eq!(output, b"x\xff\xfey", "command bytes must survive exactly");
    }

    /// A sandbox shell request starts the configured shell in login mode
    /// through the leading-`-` argv[0], with no shell-specific option
    /// (docs/ssh-protocol.md §4.1).
    #[tokio::test]
    async fn shell_request_starts_a_login_argv0_shell() {
        use tokio::io::AsyncWriteExt;

        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let request = LaunchRequest {
            sandbox_id: "macos-test".parse().expect("sandbox id"),
            workspace: workspace.path().to_path_buf(),
            operation: super::super::LaunchOperation::Shell,
            pty: None,
        };
        let launcher = MacosLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("macos launcher");
        let mut launched = launcher.launch(request).expect("launch");
        let mut stdin = launched.stdin.take().expect("stdin");
        stdin
            .write_all(b"printf 'argv0=%s\\n' \"$0\"\n")
            .await
            .expect("write probe");
        drop(stdin);
        let mut output = Vec::new();
        launched
            .stdout
            .take()
            .expect("stdout")
            .read_to_end(&mut output)
            .await
            .expect("read stdout");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("argv0=-sh"),
            "shell must observe login argv[0]: {output:?}"
        );
    }
}
