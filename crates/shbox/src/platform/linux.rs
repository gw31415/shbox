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
    CommandSpec, ProcessDomain, Sandbox, SandboxConfig as EngineConfig, SandboxError, SessionSetup,
    Stdio,
};

use super::policy::{LaunchTemp, SandboxLaunchPolicy, login_shell_argv0, validated_shell_command};
use super::terminal::{PtyIo, PtyPair, duplicate_fd};
use super::{
    LaunchError, LaunchRequest, LaunchedProcess, ProcessExit, ProcessLauncher, ProcessReader,
    ProcessWriter, RunningProcess,
};
use crate::config::NetworkMode;
use crate::sandbox::SandboxId;

/// Deadline for a killed process domain to report `populated 0`.
const DOMAIN_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// One sandbox's runtime-domain state (plan M5).
///
/// ```text
/// Idle (absent)  -- first launch -->  Active  -- populated=0 && in_flight=0 -->  Idle
/// Active/Idle    -- delete -->        Deleting  -- reject launches, wait in-flight,
///                                             kill/remove the domain, then gone
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DomainPhase {
    /// No domain exists; the slot is absent from the registry.
    #[default]
    Idle,
    /// A domain exists and launches may join it.
    Active,
    /// Removal is in progress; launches are rejected.
    Deleting,
}

/// The registry entry behind [`DomainPhase::Active`].
#[derive(Debug, Default)]
struct DomainSlot {
    phase: DomainPhase,
    /// Bumped each time a domain is removed; names the runtime generation.
    generation: u64,
    /// Launches between "domain acquired" and "waiter finished".
    in_flight: usize,
    domain: Option<Arc<ProcessDomain>>,
}

/// Shared per-sandbox domain registry: the state machine guarding the
/// launch / empty-cleanup / delete races.
#[derive(Debug, Default)]
struct DomainRegistry {
    slots: Mutex<HashMap<SandboxId, DomainSlot>>,
    changed: Condvar,
}

impl DomainRegistry {
    /// A launch's in-flight accounting handle. Dropping it decrements the
    /// count and performs the empty-cleanup transition when the domain has
    /// drained.
    fn launch_finished(&self, sandbox_id: &SandboxId) {
        let Ok(mut slots) = self.slots.lock() else {
            return;
        };
        let Some(slot) = slots.get_mut(sandbox_id) else {
            return;
        };
        slot.in_flight = slot.in_flight.saturating_sub(1);
        // Empty cleanup is only allowed when everything agrees the domain is
        // unused: no in-flight launch (this lock serializes new launches'
        // increments), no member processes (so nothing can fork into it),
        // and the slot is still Active — not mid-deletion.
        if slot.phase == DomainPhase::Active
            && slot.in_flight == 0
            && slot
                .domain
                .as_ref()
                .is_some_and(|domain| !domain.is_populated().unwrap_or(true))
            && let Some(domain) = slot.domain.take()
            && domain.remove_empty().is_ok()
        {
            slot.generation += 1;
            slots.remove(sandbox_id);
        }
        self.changed.notify_all();
    }
}

/// Owned in-flight registration for one launch against its sandbox domain.
struct DomainLease {
    registry: Arc<DomainRegistry>,
    sandbox_id: SandboxId,
}

impl Drop for DomainLease {
    fn drop(&mut self) {
        self.registry.launch_finished(&self.sandbox_id);
    }
}

/// Linux launcher backed by the detected engine capabilities and the
/// process-lifetime shbox policy snapshot.
pub(crate) struct LinuxLauncher {
    policy: SandboxLaunchPolicy,
    engine: Sandbox,
    registry: Arc<DomainRegistry>,
}

impl fmt::Debug for LinuxLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxLauncher")
            .field("policy", &self.policy)
            .field("capabilities", self.engine.capabilities())
            .field(
                "process_domains",
                &self
                    .registry
                    .slots
                    .lock()
                    .map(|slots| slots.len())
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

        // The sandbox cgroup is the mandatory process-ownership boundary
        // (docs/lifecycle.md §1): without a cgroup v2 hierarchy there is no
        // reliable containment, so launches fail closed.
        let Some(root) = &capabilities.cgroup_v2_root else {
            return Err(LaunchError::new(
                "sandbox process adapter unavailable: process containment requires \
                 a cgroup v2 hierarchy",
            ));
        };
        tracing::info!(
            cgroup_v2_root = %root.display(),
            "sandbox engine detected a cgroup v2 hierarchy"
        );

        tracing::info!(
            kernel_release = %kernel_release(),
            landlock_abi = landlock_abi,
            "Linux sandbox engine capabilities detected"
        );

        Ok(Self {
            policy,
            engine,
            registry: Arc::new(DomainRegistry::default()),
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

    /// Whether this host can currently provide the mandatory per-sandbox
    /// process domain. Test seams use this to self-skip on hosts without a
    /// delegated cgroup v2 parent, mirroring the engine's contract.
    #[cfg(test)]
    pub(crate) fn process_domain_ready(&self, workspace: &Path) -> bool {
        let config = self.policy.engine_config(workspace, workspace);
        let parent = config
            .cgroup_parent
            .as_deref()
            .map(shbox_sandbox::CgroupParent::new);
        match self.engine.create_process_domain(config.resources, parent) {
            Ok(domain) => {
                let _ = domain.remove_empty();
                true
            }
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                false
            }
            Err(error) => panic!("unexpected process-domain probe error: {error}"),
        }
    }

    /// Join (or lazily create) the sandbox's process domain and register one
    /// in-flight launch against it. The returned lease decrements the
    /// in-flight count on drop, so every exit path — success, failure, or a
    /// panicking waiter — keeps the registry exact.
    fn process_domain(
        &self,
        sandbox_id: &SandboxId,
        config: &EngineConfig,
    ) -> Result<(Arc<ProcessDomain>, DomainLease), LaunchError> {
        let mut slots = self
            .registry
            .slots
            .lock()
            .map_err(|_| LaunchError::new("sandbox process registry is unavailable"))?;
        let slot = slots.entry(sandbox_id.clone()).or_default();
        if slot.phase == DomainPhase::Deleting {
            return Err(LaunchError::new(
                "sandbox process domain is being deleted; new launches are rejected",
            ));
        }
        if slot.domain.is_none() {
            let parent = config
                .cgroup_parent
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new);
            let domain = Arc::new(
                self.engine
                    .create_process_domain(config.resources, parent)
                    .map_err(|error| LaunchError::new(describe_engine_error(&error)))?,
            );
            slot.domain = Some(domain);
            slot.phase = DomainPhase::Active;
        }
        slot.in_flight += 1;
        let domain = Arc::clone(slot.domain.as_ref().expect("domain just ensured"));
        let lease = DomainLease {
            registry: Arc::clone(&self.registry),
            sandbox_id: sandbox_id.clone(),
        };
        Ok((domain, lease))
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
        let (process_domain, domain_lease) = self.process_domain(&request.sandbox_id, &config)?;

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
        // Every launch joins the sandbox's shared process domain: limits or
        // no limits, containment is not optional.
        let mut child = self
            .engine
            .spawn_in_process_domain(command, config, &process_domain)
            .map_err(|error| LaunchError::new(describe_engine_error(&error)))?;
        // `None` would mean the child was already reaped — a pid of 0 must
        // never reach the group-signaling control (`kill(0, ..)` would
        // signal the daemon's own process group).
        let pid = child
            .id()
            .ok_or_else(|| LaunchError::new("sandbox child vanished before launch completion"))?;

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
            .spawn(move || wait_process(child, wait_control, launch_temp, wait_tx, domain_lease));
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
        // Deleting transition: reject new launches first, then wait out the
        // in-flight barrier before touching the cgroup (plan M5).
        let domain = {
            let mut slots = self
                .registry
                .slots
                .lock()
                .map_err(|_| LaunchError::new("sandbox process registry is unavailable"))?;
            match slots.get_mut(sandbox_id) {
                None => return Ok(()),
                Some(slot) if slot.phase == DomainPhase::Deleting => {
                    return Err(LaunchError::new(
                        "sandbox process domain deletion is already in progress",
                    ));
                }
                Some(slot) => {
                    slot.phase = DomainPhase::Deleting;
                    // Kill every member now: still-running launches keep an
                    // in-flight waiter that only finishes once its process
                    // dies, so the barrier below could never drain otherwise.
                    // Graceful termination already happened above this seam
                    // (the manager's TERM pass); this is the hard boundary.
                    if let Some(domain) = slot.domain.as_ref() {
                        let _ = domain.kill_all();
                    }
                }
            }
            let deadline = Instant::now() + DOMAIN_TEARDOWN_TIMEOUT;
            loop {
                let in_flight = slots.get(sandbox_id).map_or(0, |slot| slot.in_flight);
                if in_flight == 0 {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok((guard, timeout)) = self.registry.changed.wait_timeout(slots, remaining)
                else {
                    return Err(LaunchError::new("sandbox process registry is unavailable"));
                };
                slots = guard;
                if timeout.timed_out() {
                    if let Some(slot) = slots.get_mut(sandbox_id) {
                        slot.phase = DomainPhase::Active;
                    }
                    return Err(LaunchError::new(
                        "sandbox launch barrier did not drain before deletion",
                    ));
                }
            }
            slots
                .get_mut(sandbox_id)
                .and_then(|slot| slot.domain.take())
        };
        // Cgroup-authoritative teardown outside the registry lock: kill every
        // member (including detached `setsid()`/double-fork descendants no
        // process group can reach), wait for the kernel to agree the domain
        // is empty, then remove the directory.
        let teardown = || -> Result<(), LaunchError> {
            let Some(domain) = domain.as_ref() else {
                return Ok(());
            };
            domain
                .kill_all()
                .map_err(|error| LaunchError::new(describe_engine_error(&error)))?;
            if !domain
                .wait_until_empty(DOMAIN_TEARDOWN_TIMEOUT)
                .map_err(|error| LaunchError::new(describe_engine_error(&error)))?
            {
                return Err(LaunchError::new(
                    "sandbox process domain still contains processes after kill",
                ));
            }
            domain
                .remove_empty()
                .map_err(|error| LaunchError::new(describe_engine_error(&error)))
        };
        match teardown() {
            Ok(()) => {
                let Ok(mut slots) = self.registry.slots.lock() else {
                    return Ok(());
                };
                if let Some(slot) = slots.get_mut(sandbox_id) {
                    // A launch cannot have recreated a domain: Deleting
                    // rejects them. Bump the generation for the next runtime.
                    slot.generation += 1;
                    slot.phase = DomainPhase::Idle;
                    slots.remove(sandbox_id);
                }
                self.registry.changed.notify_all();
                Ok(())
            }
            Err(error) => {
                // Deletion failed: restore the slot so the cgroup stays
                // owned and the caller can retry.
                if let Ok(mut slots) = self.registry.slots.lock() {
                    if let Some(slot) = slots.get_mut(sandbox_id) {
                        slot.domain = domain;
                        slot.phase = DomainPhase::Active;
                    }
                    self.registry.changed.notify_all();
                }
                Err(error)
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
    // Held for the waiter's lifetime: dropping it after the launch completes
    // decrements the domain's in-flight count and may retire an empty
    // domain (the M5 empty-cleanup transition).
    _domain_lease: DomainLease,
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
    // The engine reaped the direct child; descendants deliberately survive
    // (docs/lifecycle.md §2.1). They stay owned by the sandbox process
    // domain, which is released only by sandbox deletion or daemon
    // shutdown — never by the direct child's exit.
    drop(launch_temp);
    control.mark_cleanup_complete();
    let _ = wait_tx.send(result);
}

/// Signal one launch's session process group. Reserved for job-control
/// semantics (user-requested signals, terminate paths) — never for normal
/// completion, where descendants must survive (docs/lifecycle.md §3).
fn kill_process_group(pid: u32, signal: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: session leader PID is also its initial process-group ID.
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
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

    fn detach_transport(&self) {
        // Close this channel's PTY master. The kernel sends SIGHUP to the
        // terminal's foreground process group, so an interactive shell ends
        // by normal terminal semantics while a `nohup`/`setsid()` process
        // survives — no daemon-side signal decides either way. After the
        // close, resize and foreground-group lookups naturally fail.
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
            // A delegated cgroup v2 parent for hosts whose session
            // ancestors are root-owned; without it, cgroup-backed tests
            // self-skip inside the launcher.
            std::env::var_os("SHBOX_SANDBOX_TEST_CGROUP_PARENT").map(std::path::PathBuf::from),
        )
    }

    fn request(workspace: &Path, command: &str, pty: bool) -> LaunchRequest {
        request_for("linux-test", workspace, command, pty)
    }

    /// Whether this host can currently provide the launcher's mandatory
    /// per-sandbox process domain. Every launch joins one cgroup (plan M4),
    /// so on hosts without a delegated cgroup v2 parent the launcher-level
    /// tests self-skip with the engine's diagnostic — the same contract as
    /// the engine integration tests.
    fn process_domain_available(launcher: &LinuxLauncher, workspace: &Path) -> bool {
        launcher.process_domain_ready(workspace)
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
        // this limit-specific test self-skips when the host cannot provide a
        // writable cgroup v2 parent, matching the engine-level tests.
        if !process_domain_available(&launcher, first_workspace.path()) {
            return;
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

    /// Plans M4+M5: every launch of one sandbox joins the same process
    /// domain — limits or no limits — while the domain holds members; once
    /// the domain drains (no processes, no in-flight launches) it is retired
    /// and the next launch starts a fresh generation. Different sandbox IDs
    /// never share a domain.
    #[tokio::test]
    async fn launches_without_limits_share_one_domain_per_sandbox() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        // /proc is readable so the probe command can observe its own cgroup.
        let policy = SandboxLaunchPolicy::from_parts(
            "/bin/sh".into(),
            NetworkMode::Disabled,
            vec!["/proc".into()],
            BTreeMap::new(),
            root.path().into(),
            crate::config::SandboxResources::default(),
            std::env::var_os("SHBOX_SANDBOX_TEST_CGROUP_PARENT").map(std::path::PathBuf::from),
        );
        let launcher = LinuxLauncher::new(policy).expect("linux launcher");
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }

        let read_cgroup = read_own_cgroup;

        // A detached descendant keeps the domain populated across launch
        // boundaries (docs/lifecycle.md §2.1).
        let keeper = launcher
            .launch(request(
                workspace.path(),
                "setsid sh -c 'printf ok > keeper-ready; exec sleep 30' & B=$!; \
                 until [ -f keeper-ready ]; do sleep 0.01; done; \
                 printf '%s' $B > keeper-pid; exit 0",
                false,
            ))
            .expect("keeper launch");
        assert_eq!(
            keeper.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );

        let first_cgroup = read_cgroup(&launcher, "linux-test", workspace.path()).await;
        assert!(
            first_cgroup.contains("sandbox-"),
            "launch must join a dedicated cgroup even without limits: {first_cgroup}"
        );
        let second_cgroup = read_cgroup(&launcher, "linux-test", workspace.path()).await;
        assert_eq!(
            first_cgroup, second_cgroup,
            "launches of one sandbox must share one domain while it is populated"
        );

        let other_workspace = tempfile::tempdir().expect("other workspace");
        let other_cgroup = read_cgroup(&launcher, "other-sandbox", other_workspace.path()).await;
        assert_ne!(
            first_cgroup, other_cgroup,
            "different sandbox IDs must use separate process domains"
        );

        // Drain the keeper: the next launch joins the same (now idle-domain)
        // cgroup, and its completion retires the domain; the launch after
        // that must start a fresh generation.
        let keeper_pid: libc::pid_t = fs::read_to_string(workspace.path().join("keeper-pid"))
            .expect("keeper pid")
            .trim()
            .parse()
            .expect("numeric keeper pid");
        kill_test_process(keeper_pid);
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_alive(keeper_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let drained_cgroup = read_cgroup(&launcher, "linux-test", workspace.path()).await;
        assert_eq!(
            drained_cgroup, first_cgroup,
            "the drained domain stays until a launch-finished transition"
        );
        let fresh_cgroup = read_cgroup(&launcher, "linux-test", workspace.path()).await;
        assert_ne!(
            fresh_cgroup, first_cgroup,
            "after the domain drains, the next launch must start a fresh generation"
        );

        launcher
            .release_sandbox_resources(&"linux-test".parse().expect("sandbox id"))
            .expect("release first domain");
        launcher
            .release_sandbox_resources(&"other-sandbox".parse().expect("sandbox id"))
            .expect("release other domain");
    }

    /// `docs/lifecycle.md` §2.1: a normally-exiting shell must not terminate
    /// the background process it started.
    /// Plan M5 stress: concurrent launches, empty-cleanup transitions, and a
    /// racing delete must never lose a process or wedge the domain state
    /// machine. Delegated-host only (self-skips otherwise).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn domain_state_machine_survives_launch_cleanup_and_delete_races() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = Arc::new(
            LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
                .expect("linux launcher"),
        );
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
        let sandbox: SandboxId = "stress".parse().expect("sandbox id");

        // Repeated empty → launch → empty cycles: each burst drains the
        // domain, its completion retires the cgroup, and the next burst
        // lazily creates a fresh generation.
        for _round in 0..5 {
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let launcher = Arc::clone(&launcher);
                let workspace = workspace.path().to_path_buf();
                tasks.push(tokio::spawn(async move {
                    let launched = launcher
                        .launch(request_for("stress", &workspace, "exit 0", false))
                        .expect("burst launch");
                    assert_eq!(
                        launched.wait.await.expect("wait channel").expect("wait"),
                        ProcessExit::Code(0)
                    );
                }));
            }
            for task in tasks {
                task.await.expect("burst task");
            }
        }

        // Launch vs delete: the launch either joins the doomed domain and is
        // killed by the release teardown, or is rejected while Deleting.
        let long_launch = tokio::spawn({
            let launcher = Arc::clone(&launcher);
            let workspace = workspace.path().to_path_buf();
            async move {
                let launched = launcher
                    .launch(request_for("stress", &workspace, "exec sleep 30", false))
                    .expect("long launch");
                launched.wait.await.expect("long wait channel")
            }
        });
        // Give the launch a moment to join the domain, then race the delete.
        tokio::time::sleep(Duration::from_millis(200)).await;
        launcher
            .release_sandbox_resources(&sandbox)
            .expect("stress release");
        let long_exit = long_launch.await.expect("long launch task");
        assert!(
            matches!(
                long_exit,
                Ok(ProcessExit::Signal { .. }) | Ok(ProcessExit::Code(_))
            ),
            "the racing launch must exit, not hang: {long_exit:?}"
        );

        // The state machine must be reusable: a fresh launch and a clean
        // release after the race.
        let fresh = launcher
            .launch(request_for("stress", workspace.path(), "exit 0", false))
            .expect("post-race launch");
        assert_eq!(
            fresh.wait.await.expect("post-race wait").expect("wait"),
            ProcessExit::Code(0)
        );
        launcher
            .release_sandbox_resources(&sandbox)
            .expect("post-race release");
    }

    #[tokio::test]
    async fn background_process_survives_shell_exit() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
        let launched = launcher
            .launch(request(
                workspace.path(),
                "sleep 30 >/dev/null 2>&1 & printf '%s' $! > background-pid; exit 0",
                false,
            ))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        let pid: libc::pid_t = fs::read_to_string(workspace.path().join("background-pid"))
            .expect("background pid")
            .trim()
            .parse()
            .expect("numeric pid");
        assert!(
            process_alive(pid),
            "background process {pid} must survive the shell's normal exit"
        );
        // Test cleanup: the contract under test leaves this process running,
        // so the test itself owns its disposal.
        kill_test_process(pid);
    }

    /// `docs/lifecycle.md` §2.4: releasing a sandbox's resources (the
    /// launcher seam under sandbox delete) must remove every sandbox process,
    /// including a `setsid()` descendant no process group signal can reach.
    #[tokio::test]
    async fn sandbox_release_kills_detached_descendants() {
        let root = tempfile::tempdir().expect("runtime root");
        let workspace = tempfile::tempdir().expect("workspace");
        let launcher = LinuxLauncher::new(test_policy(root.path(), NetworkMode::Disabled))
            .expect("linux launcher");
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
        let launched = launcher
            .launch(request(
                workspace.path(),
                "setsid sh -c 'printf ok > detached-ready; exec sleep 30' & B=$!; \
                 until [ -f detached-ready ]; do sleep 0.01; done; \
                 printf '%s' $B > detached-pid; exit 0",
                false,
            ))
            .expect("launch");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        let pid: libc::pid_t = fs::read_to_string(workspace.path().join("detached-pid"))
            .expect("detached pid")
            .trim()
            .parse()
            .expect("numeric pid");
        assert!(process_alive(pid), "detached process must start alive");
        launcher
            .release_sandbox_resources(&"linux-test".parse().expect("sandbox id"))
            .expect("release sandbox resources");
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process_alive(pid),
            "sandbox release must kill the detached descendant {pid}"
        );
    }

    /// Launch one probe command that prints its own cgroup and collect it.
    async fn read_own_cgroup(launcher: &LinuxLauncher, sandbox: &str, workspace: &Path) -> String {
        use tokio::io::AsyncReadExt;

        let mut launched = launcher
            .launch(request_for(
                sandbox,
                workspace,
                "cat /proc/self/cgroup",
                false,
            ))
            .expect("launch");
        drop(launched.stdin.take());
        let mut cgroup = String::new();
        launched
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut cgroup)
            .await
            .expect("read cgroup");
        assert_eq!(
            launched.wait.await.expect("wait channel").expect("wait"),
            ProcessExit::Code(0)
        );
        cgroup.trim().to_string()
    }

    /// Whether `pid` exists and is not a zombie.
    fn process_alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal zero performs existence/permission checking only.
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 {
            fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    stat.rfind(')')
                        .and_then(|end| stat.as_bytes().get(end + 2).copied())
                })
                .is_none_or(|state| state != b'Z')
        } else {
            false
        }
    }

    /// Direct test-side disposal of a process the lifecycle contract
    /// deliberately leaves running.
    fn kill_test_process(pid: libc::pid_t) {
        // SAFETY: signal delivery to a process the test spawned.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
        if !process_domain_available(&launcher, workspace.path()) {
            return;
        }
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
