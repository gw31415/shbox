//! Linux production launcher: shbox policy on the `shbox-sandbox` engine.
//!
//! The engine crate owns the spawn path (`clone3` + pidfd, Landlock,
//! seccomp, cgroup v2, capability drop, FD hygiene); this adapter owns the
//! SSH-facing process lifecycle: the PTY, the session, I/O plumbing, the
//! waiter thread, and mapping [`SandboxLaunchPolicy`] (shbox's own curated
//! profile) into an explicit engine `SandboxConfig` per launch.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use shbox_sandbox::{
    CommandSpec, ResourceDomain, Sandbox, SandboxConfig as EngineConfig, SandboxError,
    SessionSetup, Stdio,
};

use super::policy::{LaunchTemp, SandboxLaunchPolicy, login_shell_argv0, validated_shell_command};
use super::terminal::{PtyIo, PtyPair, duplicate_fd};
use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, RunningProcess,
};
use crate::config::NetworkMode;
use crate::sandbox::SandboxId;

const PROCESS_GROUP_SETTLE: Duration = Duration::from_secs(1);

/// Linux launcher backed by the detected engine capabilities and the
/// process-lifetime shbox policy snapshot.
pub(crate) struct LinuxLauncher {
    policy: SandboxLaunchPolicy,
    engine: Sandbox,
    resource_domains: Mutex<HashMap<SandboxId, Arc<ResourceDomain>>>,
}

impl fmt::Debug for LinuxLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxLauncher")
            .field("policy", &self.policy)
            .field("capabilities", self.engine.capabilities())
            .field(
                "resource_domains",
                &self
                    .resource_domains
                    .lock()
                    .map(|domains| domains.len())
                    .unwrap_or_default(),
            )
            .finish()
    }
}

impl LinuxLauncher {
    pub(crate) fn new(policy: SandboxLaunchPolicy) -> Result<Self, LaunchError> {
        let engine =
            Sandbox::detect_with(policy.cgroup_parent().map(shbox_sandbox::CgroupParent::new));
        let capabilities = engine.capabilities();

        // Landlock is the filesystem confinement layer; without it the
        // curated profile cannot be enforced and launches must fail closed.
        let landlock_abi = capabilities.landlock_abi.ok_or_else(|| {
            LaunchError::new("sandbox process adapter unavailable: Landlock unsupported")
        })?;

        // The disabled-network contract is enforced by a fresh user+network
        // namespace, which blocks host/external reachability for all socket
        // families. Landlock ABI 4 TCP mediation is an additional required
        // defense-in-depth layer; fail closed if it is unavailable.
        if policy.network() == NetworkMode::Disabled && landlock_abi < 4 {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: network restriction requires \
                 Landlock ABI 4 (kernel 6.7+)",
            ));
        }

        if let Some(root) = &capabilities.cgroup_v2_root {
            tracing::info!(
                cgroup_v2_root = %root.display(),
                "sandbox engine detected a cgroup v2 hierarchy"
            );
        } else if policy.resources().wants_cgroup() {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: resource limits are configured \
                 but no cgroup v2 hierarchy is usable",
            ));
        }

        tracing::info!(
            kernel_release = %kernel_release(),
            landlock_abi = landlock_abi,
            "Linux sandbox engine capabilities detected"
        );

        Ok(Self {
            policy,
            engine,
            resource_domains: Mutex::new(HashMap::new()),
        })
    }

    fn command_spec(
        &self,
        request: &LaunchRequest,
        workspace: &Path,
    ) -> Result<CommandSpec, LaunchError> {
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
        command.cwd = Some(workspace.to_path_buf());
        Ok(command)
    }

    fn resource_domain(
        &self,
        sandbox_id: &SandboxId,
        config: &EngineConfig,
    ) -> Result<Option<Arc<ResourceDomain>>, LaunchError> {
        if !config.resources.requires_cgroup() {
            return Ok(None);
        }

        let mut domains = self
            .resource_domains
            .lock()
            .map_err(|_| LaunchError::new("sandbox resource registry is unavailable"))?;
        if let Some(domain) = domains.get(sandbox_id) {
            return Ok(Some(Arc::clone(domain)));
        }

        let parent = config
            .cgroup_parent
            .as_deref()
            .map(shbox_sandbox::CgroupParent::new);
        let domain = Arc::new(
            self.engine
                .create_resource_domain(config.resources, parent)
                .map_err(|error| LaunchError::new(describe_engine_error(&error)))?,
        );
        domains.insert(sandbox_id.clone(), Arc::clone(&domain));
        Ok(Some(domain))
    }
}

impl ProcessLauncher for LinuxLauncher {
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
        let config: EngineConfig = self.policy.engine_config(&workspace, &launch_temp_path);
        let resource_domain = self.resource_domain(&request.sandbox_id, &config)?;

        let mut command = self.command_spec(&request, &workspace)?;
        command.env = self
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

        // PTY allocation is not atomically CLOEXEC on every supported libc,
        // so serialize this boundary with host-process and sandbox spawns.
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

        // The engine returns only after exec is confirmed with every
        // confinement mechanism in place; failures already cleaned up.
        let mut child = match resource_domain.as_deref() {
            Some(domain) => self
                .engine
                .spawn_in_resource_domain(command, config, domain),
            None => self.engine.spawn(command, config),
        }
        .map_err(|error| LaunchError::new(describe_engine_error(&error)))?;
        let pid = child.id();

        // From here any fallible parent-side PTY setup must tear the
        // now-owned session down if the launch cannot be published to the
        // runtime.
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

        let control = Arc::new(LinuxProcessControl::new(pid, lifecycle_fd));
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
        let wait_control = Arc::clone(&control);
        let spawn_result = std::thread::Builder::new()
            .name("shbox-linux-sandbox-wait".to_string())
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

    fn release_sandbox_resources(&self, sandbox_id: &SandboxId) -> Result<(), LaunchError> {
        let mut domains = self
            .resource_domains
            .lock()
            .map_err(|_| LaunchError::new("sandbox resource registry is unavailable"))?;
        let Some(domain) = domains.remove(sandbox_id) else {
            return Ok(());
        };
        if Arc::strong_count(&domain) != 1 || domain.is_in_use() {
            domains.insert(sandbox_id.clone(), domain);
            return Err(LaunchError::new(
                "sandbox resource domain is still in use after process cleanup",
            ));
        }
        let mut domain = match Arc::try_unwrap(domain) {
            Ok(domain) => domain,
            Err(domain) => {
                domains.insert(sandbox_id.clone(), domain);
                return Err(LaunchError::new(
                    "sandbox resource domain is still referenced after process cleanup",
                ));
            }
        };
        match domain.remove() {
            Ok(()) => Ok(()),
            Err(error) => {
                domains.insert(sandbox_id.clone(), Arc::new(domain));
                Err(LaunchError::new(describe_engine_error(&error)))
            }
        }
    }
}

/// Render an engine failure for the SSH-facing launch error. Setup-stage
/// failures mean the user command never executed.
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

fn kernel_release() -> String {
    // SAFETY: `utsname` is a C struct of fixed-size char arrays only —
    // all-zero is a valid value, and `uname` only writes to it.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is writable and remains live for the call.
    if unsafe { libc::uname(&mut uts) } == -1 {
        return "unknown".to_string();
    }
    // SAFETY: uname guarantees NUL-terminated fields.
    unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn wait_process(
    mut child: shbox_sandbox::SandboxChild,
    control: Arc<LinuxProcessControl>,
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
    // The engine reaped the direct child. A one-shot engine spawn may have
    // cleaned its cgroup; shbox resource-domain cgroups deliberately outlive
    // individual children and are released only when the durable sandbox is
    // deleted. Remaining descendants still belong to the owned session group.
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
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
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
    use tokio::io::AsyncReadExt;

    fn test_policy(root: &Path, network: NetworkMode) -> SandboxLaunchPolicy {
        test_policy_with_resources(root, network, crate::config::SandboxResources::default())
    }

    fn test_policy_with_resources(
        root: &Path,
        network: NetworkMode,
        resources: crate::config::SandboxResources,
    ) -> SandboxLaunchPolicy {
        SandboxLaunchPolicy::from_parts(
            "/bin/sh".into(),
            network,
            Vec::new(),
            BTreeMap::new(),
            root.into(),
            resources,
            None,
        )
    }

    fn request(workspace: &Path, command: &str, pty: bool) -> LaunchRequest {
        request_for("linux-test", workspace, command, pty)
    }

    fn request_for(sandbox_id: &str, workspace: &Path, command: &str, pty: bool) -> LaunchRequest {
        LaunchRequest {
            sandbox_id: sandbox_id.parse().expect("sandbox id"),
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

    #[tokio::test]
    async fn resource_limits_are_shared_by_sandbox_id_and_independent_between_ids() {
        let root = tempfile::tempdir().expect("runtime root");
        let first_workspace = tempfile::tempdir().expect("first workspace");
        let second_workspace = tempfile::tempdir().expect("second workspace");
        let resources = crate::config::SandboxResources {
            pids: Some(1),
            ..crate::config::SandboxResources::default()
        };
        let launcher = LinuxLauncher::new(test_policy_with_resources(
            root.path(),
            NetworkMode::Disabled,
            resources,
        ))
        .expect("linux launcher");

        // The native platform gate intentionally does not require cgroup
        // delegation. Resource limits still fail closed in production, but
        // this limit-specific test should self-skip when the host cannot
        // provide a writable cgroup v2 parent, matching the engine-level
        // integration tests.
        let probe_config = launcher
            .policy
            .engine_config(first_workspace.path(), root.path());
        let cgroup_parent = probe_config
            .cgroup_parent
            .as_deref()
            .map(shbox_sandbox::CgroupParent::new);
        match launcher
            .engine
            .create_resource_domain(probe_config.resources, cgroup_parent)
        {
            Ok(domain) => drop(domain),
            Err(SandboxError::Unsupported {
                feature: feature @ ("cgroup-v2" | "clone3-into-cgroup"),
                reason,
            }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected resource-domain probe error: {error}"),
        }

        let first = launcher
            .launch(request_for(
                "first",
                first_workspace.path(),
                "exec sleep 30",
                false,
            ))
            .expect("first launch");

        let same_sandbox =
            launcher.launch(request_for("first", first_workspace.path(), "true", false));
        assert!(
            same_sandbox.is_err(),
            "same sandbox must share one pids.max=1 resource domain"
        );

        let independent = launcher
            .launch(request_for(
                "second",
                second_workspace.path(),
                "true",
                false,
            ))
            .expect("different sandbox must get an independent resource domain");
        assert_eq!(
            independent
                .wait
                .await
                .expect("independent wait channel")
                .expect("independent wait"),
            ProcessExit::Code(0)
        );

        first.control.force_terminate();
        assert_eq!(
            first
                .wait
                .await
                .expect("first wait channel")
                .expect("first wait"),
            ProcessExit::Signal {
                number: libc::SIGKILL,
                core_dumped: false,
            }
        );

        let reused = launcher
            .launch(request_for("first", first_workspace.path(), "true", false))
            .expect("sandbox resource domain must survive child exit");
        assert_eq!(
            reused
                .wait
                .await
                .expect("reused wait channel")
                .expect("reused wait"),
            ProcessExit::Code(0)
        );

        launcher
            .release_sandbox_resources(&"first".parse().expect("first id"))
            .expect("release first resource domain");
        launcher
            .release_sandbox_resources(&"second".parse().expect("second id"))
            .expect("release second resource domain");
    }

    /// Real kernel probe of the engine's confinement stack; failure is
    /// blocking for the Linux platform gate.
    #[test]
    fn engine_capability_probe() {
        let engine = Sandbox::detect();
        let capabilities = engine.capabilities();
        let abi = capabilities
            .landlock_abi
            .expect("Linux gate requires Landlock");
        assert!(abi >= 4, "network restriction requires Landlock ABI 4");
        if std::env::var_os("SHBOX_PLATFORM_DIAGNOSTICS").is_some() {
            eprintln!(
                "shbox Linux sandbox engine: landlock_abi={} cgroup_v2_root={:?}",
                abi, capabilities.cgroup_v2_root
            );
        }

        // The exact engine API this launcher pins: a restricted policy
        // prepares, spawns, and enforces against the running kernel.
        let workspace = tempfile::tempdir().expect("probe workspace");
        let outside = tempfile::NamedTempFile::new().expect("outside secret");
        fs::write(outside.path(), b"SECRET").expect("write secret");
        let mut command = CommandSpec::new("/bin/sh");
        command = command
            .arg("-c")
            .arg(format!(
                "printf ok > inside; if cat '{}' >/dev/null 2>&1; then exit 91; fi; exit 0",
                outside.path().display()
            ))
            .cwd(workspace.path())
            .env([("PATH", "/bin:/usr/bin")]);
        command.stdout = Stdio::Pipe;
        let config = test_policy(workspace.path(), NetworkMode::Disabled)
            .engine_config(workspace.path(), workspace.path());
        let mut child = engine.spawn(command, config).expect("engine spawn");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0), "probe did not confine reads");
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
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
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
            sandbox_id: "linux-test".parse().expect("sandbox id"),
            workspace: workspace.path().to_path_buf(),
            operation: super::super::LaunchOperation::Exec(command),
            pty: None,
        };
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
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
            sandbox_id: "linux-test".parse().expect("sandbox id"),
            workspace: workspace.path().to_path_buf(),
            operation: super::super::LaunchOperation::Shell,
            pty: None,
        };
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
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
