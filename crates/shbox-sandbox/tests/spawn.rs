//! Behavioral integration tests for the sandbox crate.
//!
//! Tests that need kernel features this host may lack (Landlock, cgroup
//! delegation, unprivileged user namespaces, seccomp) self-skip with a
//! diagnostic when the backend reports the primitive unsupported — the
//! fail-closed *error* itself is asserted where it is the contract.

use std::io::Read;
#[cfg(target_os = "macos")]
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use shbox_sandbox::{
    CommandSpec, FilesystemPolicy, Limit, NetworkPolicy, PathRule, Sandbox, SandboxConfig,
    SandboxError, SeccompAction, SessionSetup, Stdio, Syscall, SyscallPolicy, SyscallRule,
};

/// Run `/bin/sh -c <script>` under `config`, wait, and collect
/// (exit status code/signal, stdout, stderr).
fn run_sh(script: &str, config: SandboxConfig) -> (Option<i32>, Option<i32>, String, String) {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command
        .arg("-c")
        .arg(script)
        .env([("PATH", "/bin:/usr/bin:/usr/sbin:/sbin")]);
    command.stdin = Stdio::Null;
    command.stdout = Stdio::Pipe;
    command.stderr = Stdio::Pipe;
    let mut child = sandbox.spawn(command, config).expect("spawn");
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.take_stdout() {
        pipe.read_to_string(&mut stdout).expect("read stdout");
    }
    if let Some(mut pipe) = child.take_stderr() {
        pipe.read_to_string(&mut stderr).expect("read stderr");
    }
    let status = child.wait().expect("wait");
    (status.code(), status.signal(), stdout, stderr)
}

fn unrestricted() -> SandboxConfig {
    SandboxConfig::unrestricted()
}

fn restricted_to(workspace: &std::path::Path) -> SandboxConfig {
    SandboxConfig {
        filesystem: FilesystemPolicy::Restricted {
            read_only: system_data_paths(),
            read_write: vec![PathRule::new(workspace)],
            // Runtime needed to start /bin/sh and ordinary commands; on
            // Linux /bin and /lib* resolve beneath /usr on merged systems.
            execute: system_execute_paths(),
        },
        network: NetworkPolicy::Disabled,
        cgroup_parent: delegated_cgroup_parent(),
        ..SandboxConfig::unrestricted()
    }
}

/// A cgroup v2 creation parent delegated to this test user, if the
/// environment provides one. Auto-discovery walks the daemon's own cgroup
/// ancestors, which on a developer session are root-owned; a delegated
/// subtree (systemd `user@.service`, `systemd-run --scope -p Delegate=…`)
/// is where sandbox cgroups can actually live.
fn delegated_cgroup_parent() -> Option<std::path::PathBuf> {
    std::env::var_os("SHBOX_SANDBOX_TEST_CGROUP_PARENT").map(std::path::PathBuf::from)
}

fn existing_paths(candidates: &[&str]) -> Vec<PathRule> {
    candidates
        .iter()
        .filter(|path| std::path::Path::new(path).exists())
        .map(PathRule::new)
        .collect()
}

fn system_execute_paths() -> Vec<PathRule> {
    let candidates = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/System"];
    existing_paths(&candidates)
}

fn system_data_paths() -> Vec<PathRule> {
    // /proc is included so lifecycle tests can observe their own cgroup
    // membership (`/proc/self/cgroup`) under the restricted fixture.
    let candidates = ["/private/etc", "/etc", "/dev", "/proc"];
    existing_paths(&candidates)
}

#[test]
fn unrestricted_spawn_runs_and_reports_the_exit_code() {
    let (code, signal, stdout, stderr) = run_sh("printf ok; exit 7", unrestricted());
    assert_eq!((code, signal), (Some(7), None));
    assert_eq!(stdout, "ok");
    assert_eq!(stderr, "");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_null_stdio_does_not_alias_a_pipe_endpoint() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command
        .arg("-c")
        .arg("printf ok || { printf null-stdio-broken >&2; exit 91; }");
    command.stdin = Stdio::Pipe;
    command.stdout = Stdio::Null;
    command.stderr = Stdio::Pipe;

    let mut child = sandbox
        .spawn(command, SandboxConfig::unrestricted())
        .expect("spawn");
    drop(child.take_stdin());
    let mut stderr = String::new();
    child
        .take_stderr()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0), "stderr: {stderr:?}");
    assert!(stderr.is_empty(), "stderr: {stderr:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_stdio_fd_cycles_preserve_all_three_sources() {
    use std::sync::Mutex;

    static STDIO_LOCK: Mutex<()> = Mutex::new(());
    let _stdio_lock = STDIO_LOCK.lock().expect("stdio test lock");
    let (input_parent, input_child) = UnixStream::pair().expect("input socketpair");
    let (mut stdout_parent, stdout_child) = UnixStream::pair().expect("stdout socketpair");
    let (mut stderr_parent, stderr_child) = UnixStream::pair().expect("stderr socketpair");

    struct StandardFdGuard {
        saved: [i32; 3],
    }

    impl StandardFdGuard {
        fn install(sources: [i32; 3]) -> Self {
            let mut saved = [0_i32; 3];
            for (slot, saved_fd) in saved.iter_mut().enumerate() {
                let duplicate = unsafe { libc::fcntl(slot as i32, libc::F_DUPFD_CLOEXEC, 10) };
                assert!(duplicate >= 0, "save stdio fd {slot}");
                *saved_fd = duplicate;
            }
            let guard = Self { saved };
            for (source, target) in sources.into_iter().zip(0_i32..3) {
                assert_eq!(unsafe { libc::dup2(source, target) }, target);
            }
            guard
        }
    }

    impl Drop for StandardFdGuard {
        fn drop(&mut self) {
            for (saved, target) in self.saved.into_iter().zip(0_i32..3) {
                unsafe {
                    libc::dup2(saved, target);
                    libc::close(saved);
                }
            }
        }
    }

    // fd 1 -> stdin, fd 2 -> stdout, fd 0 -> stderr is a cycle through the
    // three standard slots. Each source is a different socket endpoint so a
    // sequential dup2 implementation cannot accidentally pass this test.
    let guard = StandardFdGuard::install([
        stderr_child.as_raw_fd(),
        input_child.as_raw_fd(),
        stdout_child.as_raw_fd(),
    ]);
    let mut command = CommandSpec::new("/bin/sh");
    command = command.arg("-c").arg("printf out; printf err >&2");
    command.stdin = Stdio::Fd(1);
    command.stdout = Stdio::Fd(2);
    command.stderr = Stdio::Fd(0);
    let spawn_result = Sandbox::detect().spawn(command, SandboxConfig::unrestricted());
    drop(guard);
    drop(input_child);
    drop(stdout_child);
    drop(stderr_child);
    let mut child = spawn_result.expect("spawn");

    input_parent
        .shutdown(Shutdown::Write)
        .expect("close input write side");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    stdout_parent.read_to_end(&mut stdout).expect("read stdout");
    stderr_parent.read_to_end(&mut stderr).expect("read stderr");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(stdout, b"out");
    assert_eq!(stderr, b"err");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_supported_resource_fields_use_rlimits() {
    let mut command = CommandSpec::new("/bin/sh");
    command = command.arg("-c").arg("printf '%s\\n' \"$(ulimit -u)\"");
    command.stdout = Stdio::Pipe;

    let mut config = SandboxConfig::unrestricted();
    config.resources.pids = Limit::Value(1024);
    let mut child = Sandbox::detect().spawn(command, config).expect("spawn");
    let mut stdout = String::new();
    child
        .take_stdout()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(stdout.lines().collect::<Vec<_>>(), ["1024"]);
}

#[test]
fn environment_is_exact_and_cwd_applies() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut config = unrestricted();
    let _ = &mut config;
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command
        .arg("-c")
        .arg("printf '%s\\n' \"$SANDBOX_MARKER\"; printf '%s\\n' \"${UNSET_VAR:-unset}\"; pwd")
        .env([("SANDBOX_MARKER", "exact")])
        .cwd(workspace.path());
    command.stdout = Stdio::Pipe;
    let mut child = sandbox.spawn(command, unrestricted()).expect("spawn");
    let mut stdout = String::new();
    child
        .take_stdout()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
    let canonical = std::fs::canonicalize(workspace.path()).expect("canonical cwd");
    assert_eq!(stdout, format!("exact\nunset\n{}\n", canonical.display()));
}

#[test]
fn argv0_override_reaches_the_program() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command.argv0 = Some("-mine".into());
    command = command.arg("-c").arg("printf '%s' \"$0\"");
    command.stdout = Stdio::Pipe;
    let mut child = sandbox.spawn(command, unrestricted()).expect("spawn");
    let mut stdout = String::new();
    child
        .take_stdout()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read");
    assert_eq!(status_code(&mut child), Some(0));
    assert_eq!(stdout, "-mine");
}

#[test]
#[cfg(target_os = "macos")]
fn non_utf8_argv0_is_rejected_on_macos() {
    use std::os::unix::ffi::OsStrExt;

    // The macOS argv[0] override routes through `/bin/sh -c`, which takes a
    // UTF-8 script string: a non-UTF-8 override must be rejected up front,
    // not corrupted by lossy conversion.
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command.argv0 = Some(std::ffi::OsStr::from_bytes(b"\xff\xfe-bad").to_os_string());
    let error = sandbox
        .spawn(command, unrestricted())
        .expect_err("non-UTF-8 argv0 must be rejected");
    assert!(
        matches!(
            error,
            shbox_sandbox::SandboxError::InvalidPolicy { field: "argv0", .. }
        ),
        "{error}"
    );
}

fn status_code(child: &mut shbox_sandbox::SandboxChild) -> Option<i32> {
    child.wait().expect("wait").code()
}

#[test]
fn filesystem_policy_denies_outside_and_permits_inside() {
    let root = tempfile::tempdir().expect("root");
    let workspace = root.path().join("ws");
    std::fs::create_dir(&workspace).expect("workspace");
    let secret = root.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET").expect("secret");

    let script = format!(
        "printf inside > inside.txt; if cat '{}' >/dev/null 2>&1; then exit 91; fi; \
         if printf x > '{}' 2>/dev/null; then exit 92; fi; exit 0",
        secret.display(),
        secret.display()
    );
    // The shell must run inside the workspace; a missing cwd grant would
    // itself be a (different) confinement failure.
    let mut command = CommandSpec::new("/bin/sh");
    command = command
        .arg("-c")
        .arg(script)
        .env([("PATH", "/bin:/usr/bin:/usr/sbin:/sbin")])
        .cwd(&workspace);
    let sandbox = Sandbox::detect();
    let mut child = sandbox
        .spawn(command, restricted_to(&workspace))
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(0),
        "sandbox did not confine filesystem access"
    );
    assert_eq!(
        std::fs::read(workspace.join("inside.txt")).expect("inside"),
        b"inside"
    );
    assert_eq!(std::fs::read(&secret).expect("secret intact"), b"SECRET");
}

#[test]
fn missing_program_fails_closed_at_the_exec_stage() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/definitely/not/a/program");
    command.stderr = Stdio::Pipe;

    #[cfg(target_os = "linux")]
    {
        let error = sandbox
            .spawn(command, unrestricted())
            .expect_err("Linux spawn must fail closed before returning a child");
        assert!(
            matches!(
                error,
                SandboxError::Setup {
                    stage: shbox_sandbox::ChildStage::Exec,
                    ..
                }
            ),
            "unexpected missing-program error: {error}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    let mut child = sandbox
        .spawn(command, unrestricted())
        .expect("launcher spawn succeeds; the launcher reports exec failure");
    #[cfg(not(target_os = "linux"))]
    let mut stderr = String::new();
    #[cfg(not(target_os = "linux"))]
    if let Some(mut pipe) = child.take_stderr() {
        pipe.read_to_string(&mut stderr).expect("read stderr");
    }
    #[cfg(not(target_os = "linux"))]
    let status = child.wait().expect("wait");
    #[cfg(not(target_os = "linux"))]
    {
        // On macOS the OS Seatbelt launcher is the direct child; it reports the
        // exec failure with its own nonzero exit code and stderr message.
        assert!(
            status.code().is_some_and(|code| code != 0),
            "status: {status:?}"
        );
        assert!(!stderr.is_empty(), "launcher must explain the failure");
    }
}

#[test]
fn inherited_socket_survives_with_its_exact_fd_number() {
    let (mut parent_end, child_end) = UnixStream::pair().expect("socketpair");
    let inherited = child_end.as_raw_fd();
    let mut config = unrestricted();
    config.inherited_fds = vec![inherited];

    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command
        .arg("-c")
        .arg(format!("printf socket-ok >&{inherited}"));
    let mut child = sandbox.spawn(command, config).expect("spawn");
    assert_eq!(status_code(&mut child), Some(0));

    let mut buffer = [0_u8; 16];
    parent_end
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let read = parent_end.read(&mut buffer).expect("read socket");
    assert_eq!(&buffer[..read], b"socket-ok");
    drop(child_end);
}

#[test]
fn descriptor_hygiene_leaves_only_expected_fds() {
    // A deliberately leaky parent: open files and a socket that must not
    // survive into the child.
    let leaky_file = tempfile::tempfile().expect("leaky file");
    let (_leaky_socket_b, leaky_socket_a) = UnixStream::pair().expect("leaky socket");
    let _ = leaky_file.as_raw_fd();
    let _ = leaky_socket_a.as_raw_fd();

    let script = if cfg!(target_os = "linux") {
        "ls /proc/self/fd"
    } else {
        "ls /dev/fd"
    };
    let (_, _, stdout, _) = run_sh(script, unrestricted());
    let fds: Vec<i32> = stdout
        .split_whitespace()
        .filter_map(|entry| entry.trim().parse::<i32>().ok())
        .collect();
    assert!(!fds.is_empty(), "fd listing was empty");
    for fd in fds {
        // 0-2 are stdio (null here), and `ls` itself uses one directory
        // descriptor. Everything beyond that would be a leak.
        assert!(
            fd <= 4,
            "unexpected inherited descriptor {fd}; listing: {stdout:?}"
        );
    }
}

#[test]
fn terminate_signals_the_session_and_wait_reports_the_signal() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command.arg("-c").arg("trap '' TERM; sleep 30");
    command.session = shbox_sandbox::SessionSetup::NewSession;
    let mut child = sandbox.spawn(command, unrestricted()).expect("spawn");
    let pid = child.id().expect("child present");
    child.signal_process_group(libc::SIGKILL).expect("signal");
    let status = child.wait().expect("wait");
    assert_eq!(status.signal(), Some(9), "status: {status:?}");
    // The process group is torn down once the kernel no longer reports a
    // live member: kill(-pid, 0) fails with ESRCH, or on Linux the only
    // remaining members are zombies.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: signal zero only probes group existence.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        // A killed-but-unreaped descendant lingers as a zombie inside the
        // group when the surrounding container's init never waits on adopted
        // orphans; a zombie holds no address space and cannot run, so it
        // does not count against the teardown.
        #[cfg(target_os = "linux")]
        let zombie_only = !process_group_has_live_members(pid);
        #[cfg(not(target_os = "linux"))]
        let zombie_only = false;
        let gone = (result == -1 && errno_is_esrch()) || zombie_only;
        if gone {
            break;
        }
        assert!(Instant::now() < deadline, "process group {pid} survived");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Scan `/proc` for members of the given process group that are not zombies.
#[cfg(target_os = "linux")]
fn process_group_has_live_members(pgroup: u32) -> bool {
    let target = pgroup.to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // Without /proc the scan cannot prove liveness either way; keep the
        // caller waiting on the plain kill() probe instead.
        return true;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{name}/stat")) else {
            continue;
        };
        // The comm field is parenthesized and may contain spaces; the
        // interesting fields follow the final closing parenthesis: state,
        // ppid, pgrp.
        let Some((_, tail)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = tail.split_whitespace();
        let (Some(state), Some(_ppid), Some(pgrp)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if pgrp == target && state != "Z" {
            return true;
        }
    }
    false
}

fn errno_is_esrch() -> bool {
    std::io::Error::last_os_error().raw_os_error() == Some(3)
}

#[test]
fn dropping_the_handle_tears_down_descendants() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command.arg("-c").arg("sleep 30 & sleep 30 & wait");
    let child = sandbox.spawn(command, unrestricted()).expect("spawn");
    let pid = child.id().expect("child present");
    drop(child);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // SAFETY: signal zero only probes the direct child's existence.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        let gone = result == -1 && errno_is_esrch();
        // A zombie counts as torn down: it was killed and cannot retain
        // resources; only the init process can reap an orphaned zombie.
        let zombie = cfg!(target_os = "linux")
            && result == 0
            && std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    stat.rfind(')')
                        .and_then(|end| stat.as_bytes().get(end + 2).copied())
                })
                == Some(b'Z');
        if gone || zombie {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "descendants of {pid} survived drop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn double_teardown_is_idempotent() {
    let sandbox = Sandbox::detect();
    let mut command = CommandSpec::new("/bin/sh");
    command = command.arg("-c").arg("exit 0");
    let mut child = sandbox.spawn(command, unrestricted()).expect("spawn");
    assert_eq!(status_code(&mut child), Some(0));
    // wait() already ran teardown; drop() runs it again.
    drop(child);
}

// ---------------------------------------------------------------------------
// Platform-specific confinement tests
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_denies_network_when_disabled() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = listener.local_addr().expect("addr").port();
    let script = format!("/usr/bin/nc -z 127.0.0.1 {port} >/dev/null 2>&1 && exit 90 || exit 0");
    let (code, _, _, _) = run_sh(
        &script,
        restricted_to(tempfile::tempdir().expect("ws").path()),
    );
    assert_eq!(code, Some(0), "network was not denied by Seatbelt");
}

#[cfg(target_os = "macos")]
#[test]
fn linux_only_policies_fail_closed_on_macos() {
    let sandbox = Sandbox::detect();
    let mut config = unrestricted();
    config.syscalls = SyscallPolicy::Filter {
        default_action: SeccompAction::Allow,
        matched_action: SeccompAction::Errno(1),
        rules: vec![SyscallRule {
            syscall: Syscall::Named("ioctl"),
            conditions: Vec::new(),
        }],
    };
    let error = sandbox
        .spawn(CommandSpec::new("/bin/true"), config)
        .expect_err("seccomp on macOS must fail");
    assert!(
        matches!(
            error,
            SandboxError::Unsupported {
                feature: "seccomp",
                ..
            }
        ),
        "{error}"
    );

    let mut config = unrestricted();
    config.namespaces.user = true;
    let error = sandbox
        .spawn(CommandSpec::new("/bin/true"), config)
        .expect_err("namespaces on macOS must fail");
    assert!(
        matches!(
            error,
            SandboxError::Unsupported {
                feature: "namespace",
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn inexpressible_resource_limits_fail_closed() {
    let sandbox = Sandbox::detect();
    let mut config = unrestricted();
    config.resources.cpu_max = Limit::Value(shbox_sandbox::CpuMax {
        quota_us: 10_000,
        period_us: 100_000,
    });
    let error = sandbox
        .spawn(CommandSpec::new("/bin/true"), config)
        .expect_err("cpu quota on macOS must fail");
    assert!(
        matches!(
            error,
            SandboxError::Unsupported {
                feature: "cpu-quota",
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn unlimited_inexpressible_resource_limits_are_not_silently_ignored() {
    let sandbox = Sandbox::detect();

    let mut cpu = unrestricted();
    cpu.resources.cpu_max = Limit::Unlimited;
    let error = sandbox
        .spawn(CommandSpec::new("/bin/true"), cpu)
        .expect_err("unlimited CPU quota on macOS must fail");
    assert!(
        matches!(
            error,
            SandboxError::Unsupported {
                feature: "cpu-quota",
                ..
            }
        ),
        "{error}"
    );

    let mut swap = unrestricted();
    swap.resources.swap_bytes = Limit::Unlimited;
    let error = sandbox
        .spawn(CommandSpec::new("/bin/true"), swap)
        .expect_err("unlimited swap limit on macOS must fail");
    assert!(
        matches!(
            error,
            SandboxError::Unsupported {
                feature: "swap-limit",
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
mod linux_only {
    use super::*;
    use shbox_sandbox::ResourceLimits;

    fn landlock_ready() -> bool {
        Sandbox::detect().capabilities().landlock_abi.unwrap_or(0) >= 1
    }

    /// Whether `pid` exists and is not a zombie: the lifecycle contract's
    /// definition of "still running" for a detached descendant.
    fn process_is_alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal zero performs existence/permission checking only.
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 {
            process_state(pid as u32).is_none_or(|state| state != b'Z')
        } else {
            false
        }
    }

    /// Direct test-side disposal of a process the lifecycle contract
    /// deliberately leaves running.
    fn kill_process(pid: libc::pid_t) {
        // SAFETY: signal delivery to a process the test spawned.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }

    fn process_state(pid: u32) -> Option<u8> {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rfind(')')
                    .and_then(|end| stat.as_bytes().get(end + 2).copied())
            })
    }

    fn wait_for_process_state(pid: u32, expected: u8, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while process_state(pid) != Some(expected) {
            assert!(
                Instant::now() < deadline,
                "process {pid} did not enter state {expected:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_descendant(pid: u32, timeout: Duration) -> u32 {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(children) =
                std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                && let Some(child) = children
                    .split_whitespace()
                    .find_map(|entry| entry.parse::<u32>().ok())
            {
                return child;
            }
            assert!(
                Instant::now() < deadline,
                "process {pid} did not create a descendant"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn process_is_gone_or_zombie(pid: u32) -> bool {
        matches!(process_state(pid), None | Some(b'Z'))
    }

    #[test]
    fn inherited_session_never_signals_the_daemon_process_group() {
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("sleep 30");
        let mut child = Sandbox::detect()
            .spawn(command, unrestricted())
            .expect("spawn");
        let pid = child.id().expect("child present");

        child.signal(libc::SIGSTOP).expect("stop direct child");
        wait_for_process_state(pid, b'T', Duration::from_secs(1));
        child
            .signal_process_group(libc::SIGCONT)
            .expect("inherited process-group signal is a safe no-op");
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(
            process_state(pid),
            Some(b'T'),
            "SessionSetup::Inherit must not resume the daemon's process group"
        );

        child.signal(libc::SIGKILL).expect("kill direct child");
        assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn child_survives_the_thread_that_requested_spawn() {
        let spawned = std::thread::spawn(|| {
            let mut command = CommandSpec::new("/bin/sh");
            command = command.arg("-c").arg("sleep 0.05; exit 17");
            Sandbox::detect().spawn(command, unrestricted())
        })
        .join()
        .expect("spawn request thread");

        let mut child = match spawned {
            Ok(child) => child,
            Err(SandboxError::Unsupported {
                feature: "clone3",
                reason,
            }) => {
                eprintln!("skipping: clone3 unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("sandbox spawn failed unexpectedly: {error}"),
        };

        assert_eq!(
            child.wait().expect("wait").code(),
            Some(17),
            "PDEATHSIG must be owned by the process-lifetime spawn thread, not the caller thread"
        );
    }

    #[test]
    fn normal_completion_cleans_owned_process_group_descendants() {
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("sleep 30 & read ignored; exit 0");
        command.stdin = Stdio::Pipe;
        command.session = shbox_sandbox::SessionSetup::NewSession;
        let mut child = Sandbox::detect()
            .spawn(command, unrestricted())
            .expect("spawn");
        let pid = child.id().expect("child present");
        let descendant = wait_for_descendant(pid, Duration::from_secs(1));
        drop(child.take_stdin().expect("stdin pipe"));
        assert_eq!(child.wait().expect("wait").code(), Some(0));

        let deadline = Instant::now() + Duration::from_secs(2);
        while !process_is_gone_or_zombie(descendant) {
            assert!(
                Instant::now() < deadline,
                "owned process-group descendant {descendant} survived normal completion"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn pid_namespace_runs_user_command_below_init_supervisor() {
        let mut config = unrestricted();
        config.namespaces.user = true;
        config.namespaces.pid = true;
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("printf '%s %s' \"$$\" \"$PPID\"");
        command.stdout = Stdio::Pipe;

        let spawn_result = Sandbox::detect().spawn(command, config);
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("PID namespace setup failed unexpectedly: {error}"),
        };
        let mut stdout = String::new();
        child
            .take_stdout()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .expect("read stdout");
        assert_eq!(child.wait().expect("wait").code(), Some(0));
        assert_eq!(
            stdout, "2 1",
            "user command must run below the PID 1 init supervisor"
        );
    }

    #[test]
    fn pid_namespace_supervisor_forwards_direct_signals_to_user() {
        let mut config = unrestricted();
        config.namespaces.user = true;
        config.namespaces.pid = true;
        let mut command = CommandSpec::new("/bin/sh");
        command = command
            .arg("-c")
            .arg("trap 'printf term; exit 23' TERM; printf ready; read ignored");
        command.stdin = Stdio::Pipe;
        command.stdout = Stdio::Pipe;

        let spawn_result = Sandbox::detect().spawn(command, config);
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("PID namespace setup failed unexpectedly: {error}"),
        };
        let mut stdout = child.take_stdout().expect("stdout");
        let mut ready = [0_u8; 5];
        stdout
            .read_exact(&mut ready)
            .expect("read readiness marker");
        assert_eq!(&ready, b"ready");

        child.signal(libc::SIGTERM).expect("signal user command");
        // Closing stdin is only a fail-fast unblock for a lost signal: an EOF
        // that reaches `read` before the forwarded TERM ends the script with
        // `read`'s status instead of running the trap. Wait for the trap
        // output first and release stdin only when the signal evidently never
        // arrived, so the assertions below report that failure.
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut rest = String::new();
            let _ = stdout.read_to_string(&mut rest);
            let _ = sent.send(rest);
        });
        let rest = match received.recv_timeout(Duration::from_secs(2)) {
            Ok(rest) => rest,
            Err(_) => {
                drop(child.take_stdin());
                received
                    .recv()
                    .expect("stdin release ended the blocked script")
            }
        };
        drop(child.take_stdin());
        let _ = reader.join();
        assert_eq!(child.wait().expect("wait").code(), Some(23));
        assert_eq!(rest, "term");
    }

    #[test]
    fn pid_namespace_init_teardown_kills_descendants() {
        let mut config = unrestricted();
        config.namespaces.user = true;
        config.namespaces.pid = true;
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("sleep 30 & wait");

        let spawn_result = Sandbox::detect().spawn(command, config);
        let child = match spawn_result {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("PID namespace setup failed unexpectedly: {error}"),
        };
        let pid = child.id().expect("child present");
        let descendant = wait_for_descendant(pid, Duration::from_secs(1));
        drop(child);

        let deadline = Instant::now() + Duration::from_secs(2);
        while !process_is_gone_or_zombie(descendant) {
            assert!(
                Instant::now() < deadline,
                "PID namespace descendant {descendant} survived init teardown"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn landlock_denies_reads_outside_grants() {
        if !landlock_ready() {
            eprintln!("skipping: kernel has no Landlock");
            return;
        }
        let root = tempfile::tempdir().expect("root");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let secret = root.path().join("secret.txt");
        std::fs::write(&secret, b"SECRET").expect("secret");
        let script = format!(
            "printf inside > inside.txt; if cat '{}' >/dev/null 2>&1; then exit 91; fi; \
             if printf x > '{}' 2>/dev/null; then exit 92; fi; exit 0",
            secret.display(),
            secret.display()
        );
        let (code, _, _, _) = run_sh(&script, restricted_to(&workspace));
        assert_eq!(code, Some(0), "Landlock did not confine filesystem access");
    }

    #[test]
    fn seccomp_filter_blocks_the_configured_syscall() {
        if !landlock_ready() {
            eprintln!("skipping: kernel has no Landlock");
            return;
        }
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.syscalls = SyscallPolicy::Filter {
            default_action: SeccompAction::Allow,
            matched_action: SeccompAction::Errno(libc::EPERM as u32),
            rules: vec![SyscallRule {
                // `unlinkat` exists on both supported Linux architectures;
                // aarch64 has no legacy `unlink` syscall.
                syscall: Syscall::Named("unlinkat"),
                conditions: Vec::new(),
            }],
        };
        let script = format!(
            "cd '{}' || exit 92; printf keep > target; rm target 2>&- || true; \
             test -f target && printf present || printf gone",
            workspace.path().display()
        );
        let (code, _, stdout, stderr) = run_sh(&script, config);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        // With unlink denied, the file must still exist and the probe must
        // print `present`.
        assert_eq!(stdout, "present", "stderr: {stderr}");
    }

    #[test]
    fn user_namespace_maps_caller_to_root() {
        if !landlock_ready() {
            eprintln!("skipping: kernel has no Landlock");
            return;
        }
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.namespaces.user = true;
        config.namespaces.mount = true;
        let sandbox = Sandbox::detect();
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("id -u; touch made-by-sandbox");
        command.cwd = Some(workspace.path().to_path_buf());
        command.stdout = Stdio::Pipe;
        let spawn_result = sandbox.spawn(command, config);
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(SandboxError::Unsupported {
                feature: feature @ ("cgroup-v2" | "clone3-into-cgroup"),
                reason,
            }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected spawn error: {error}"),
        };
        let mut stdout = String::new();
        child
            .take_stdout()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .expect("read");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0), "stdout: {stdout}");
        assert_eq!(stdout.trim(), "0", "userns must map the caller to uid 0");
        assert!(workspace.path().join("made-by-sandbox").exists());
    }

    #[test]
    fn cgroup_limits_spawn_into_a_dedicated_cgroup() {
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.resources = ResourceLimits {
            pids: Limit::Value(16),
            ..ResourceLimits::default()
        };
        let sandbox = Sandbox::detect();
        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("cat /proc/self/cgroup; exit 0");
        command.stdout = Stdio::Pipe;
        let spawn_result = sandbox.spawn(command, config);
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected spawn error: {error}"),
        };
        let mut stdout = String::new();
        child
            .take_stdout()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .expect("read");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0), "stdout: {stdout}");
        assert!(
            stdout.contains("sandbox-"),
            "child did not run in a dedicated cgroup: {stdout}"
        );
    }

    /// `plan-cgroup.md` M1: a process domain is the sandbox's containment
    /// boundary first and its resource-limit carrier second. All-`Inherit`
    /// limits must still yield a dedicated cgroup that children are born
    /// into, and separate domains must never share it.
    #[test]
    fn process_domain_with_all_inherit_limits_contains_children() {
        let workspace = tempfile::tempdir().expect("workspace");
        let config = restricted_to(workspace.path());
        assert!(
            !config.resources.requires_cgroup(),
            "fixture must be the all-Inherit case"
        );
        let sandbox = Sandbox::detect();
        let domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("all-Inherit process domain must be creatable: {error}"),
        };
        let other_domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(error) => panic!("second process domain could not be created: {error}"),
        };

        let read_cgroup = |label: &str| {
            let mut command = CommandSpec::new("/bin/sh");
            command = command.arg("-c").arg("cat /proc/self/cgroup");
            command.stdin = Stdio::Null;
            command.stdout = Stdio::Pipe;
            command.stderr = Stdio::Null;
            let mut child =
                match sandbox.spawn_in_process_domain(command, config.clone(), &domain) {
                    Ok(child) => child,
                    Err(SandboxError::Unsupported { feature, reason }) => {
                        eprintln!("skipping: {feature} unsupported here: {reason}");
                        return None;
                    }
                    Err(error) => panic!("unexpected {label} spawn error: {error}"),
                };
            let mut stdout = String::new();
            if let Some(mut pipe) = child.take_stdout() {
                pipe.read_to_string(&mut stdout).expect("read stdout");
            }
            let status = child.wait().expect("wait");
            assert_eq!(status.code(), Some(0), "{label} stdout: {stdout}");
            Some(stdout.trim().to_string())
        };

        let first = read_cgroup("first").expect("first cgroup reading");
        assert!(
            first.contains("sandbox-"),
            "child must be born inside the dedicated cgroup: {first}"
        );
        let second = read_cgroup("second").expect("second cgroup reading");
        assert_eq!(
            first, second,
            "every launch in one sandbox must share the same process domain"
        );

        let mut command = CommandSpec::new("/bin/sh");
        command = command.arg("-c").arg("cat /proc/self/cgroup");
        command.stdin = Stdio::Null;
        command.stdout = Stdio::Pipe;
        command.stderr = Stdio::Null;
        let mut independent = sandbox
            .spawn_in_process_domain(command, config.clone(), &other_domain)
            .expect("independent domain spawn");
        let mut independent_stdout = String::new();
        if let Some(mut pipe) = independent.take_stdout() {
            pipe.read_to_string(&mut independent_stdout).expect("read");
        }
        assert_eq!(independent.wait().expect("wait").code(), Some(0));
        let independent_cgroup = independent_stdout.trim();
        assert_ne!(
            first, independent_cgroup,
            "different sandbox IDs must never share a process domain"
        );

        domain.remove_empty().expect("remove first process domain");
        other_domain
            .remove_empty()
            .expect("remove independent process domain");
    }

    #[test]
    fn process_domain_remove_is_retryable_and_child_exit_preserves_domain() {
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.resources = ResourceLimits {
            pids: Limit::Value(4),
            ..ResourceLimits::default()
        };
        let sandbox = Sandbox::detect();
        let domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected resource-domain error: {error}"),
        };

        let mut first_command = CommandSpec::new("/bin/sleep");
        first_command = first_command.arg("30");
        let mut first = match sandbox.spawn_in_process_domain(first_command, config.clone(), &domain)
        {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected first domain spawn error: {error}"),
        };

        // A populated domain refuses removal: the live child is the kernel's
        // authoritative membership, not the Rust handle count.
        let error = domain
            .remove_empty()
            .expect_err("a populated domain must refuse removal");
        assert!(
            matches!(error, SandboxError::Io(_)),
            "unexpected removal error: {error}"
        );

        first.signal(libc::SIGKILL).expect("kill first child");
        let _ = first.wait().expect("wait first child");
        assert!(
            domain
                .wait_until_empty(Duration::from_secs(2))
                .expect("wait for the killed child to leave the cgroup"),
            "domain must drain after its only child is killed"
        );

        let mut second = sandbox
            .spawn_in_process_domain(CommandSpec::new("/bin/true"), config, &domain)
            .expect("resource domain must remain reusable after child cleanup");
        assert_eq!(second.wait().expect("wait second child").code(), Some(0));
        domain.remove_empty().expect("remove idle resource domain");
    }


    /// `docs/lifecycle.md` §2.1: a normally-exiting direct child must not
    /// terminate its descendants. This is the engine-level contract test for
    /// the background (same process group) case; it is expected to fail until
    /// the engine stops killing the owned process group on wait.
    #[test]
    fn background_descendant_survives_direct_child_exit() {
        let workspace = tempfile::tempdir().expect("workspace");
        let config = restricted_to(workspace.path());
        let sandbox = Sandbox::detect();
        let mut command = CommandSpec::new("/bin/sh");
        command = command
            .arg("-c")
            .arg("sleep 30 & printf '%s' $! > descendant.pid; exit 0");
        command.cwd = Some(workspace.path().to_path_buf());
        command.stdin = Stdio::Null;
        command.stdout = Stdio::Null;
        command.stderr = Stdio::Null;
        // The launcher path always creates a session per launch; the engine
        // contract must hold for that shape, where the owned process group
        // exists and could be (wrongly) cleaned up on wait.
        command.session = SessionSetup::NewSession;
        let mut child = sandbox.spawn(command, config).expect("spawn");
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0));
        let pid: libc::pid_t = std::fs::read_to_string(workspace.path().join("descendant.pid"))
            .expect("descendant pid marker")
            .trim()
            .parse()
            .expect("numeric descendant pid");
        // A process-group kill lands within microseconds of `wait()`
        // returning; letting that window pass makes "still alive" a settled
        // fact rather than a race with signal delivery.
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            process_is_alive(pid),
            "background descendant {pid} must survive the direct child's normal exit"
        );
        // Test cleanup: the contract under test deliberately leaves this
        // process running, so the test itself owns its disposal.
        kill_process(pid);
    }

    /// `docs/lifecycle.md` §2.1: a `setsid()` descendant leaves the owned
    /// process group but stays inside the sandbox resource domain. Its
    /// survival after the direct child exits — and after the child handle is
    /// dropped — is the cgroup-ownership contract.
    #[test]
    fn setsid_descendant_survives_direct_child_exit_in_domain() {
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.resources = ResourceLimits {
            pids: Limit::Value(8),
            ..ResourceLimits::default()
        };
        let sandbox = Sandbox::detect();
        let domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected resource-domain error: {error}"),
        };
        let mut command = CommandSpec::new("/bin/sh");
        command = command
            .arg("-c")
            .arg("setsid sh -c 'printf ok > setsid-ready; exec sleep 30' & B=$!; until [ -f setsid-ready ]; do sleep 0.01; done; printf '%s' $B > setsid.pid; exit 0");
        command.cwd = Some(workspace.path().to_path_buf());
        command.env = vec![(
            std::ffi::OsString::from("PATH"),
            std::ffi::OsString::from("/bin:/usr/bin"),
        )];
        command.stdin = Stdio::Null;
        command.stdout = Stdio::Null;
        command.stderr = Stdio::Null;
        command.session = SessionSetup::NewSession;
        let mut child = match sandbox.spawn_in_process_domain(command, config.clone(), &domain) {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected domain spawn error: {error}"),
        };
        assert_eq!(child.wait().expect("wait").code(), Some(0));
        let pid: libc::pid_t = std::fs::read_to_string(workspace.path().join("setsid.pid"))
            .expect("setsid pid marker")
            .trim()
            .parse()
            .expect("numeric setsid pid");
        // The readiness marker is written from inside the new session, so
        // the descendant's `setsid()` is complete before the shell exits and
        // the survival assertion cannot race session establishment.
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            process_is_alive(pid),
            "setsid descendant {pid} must survive the direct child's normal exit"
        );
        // Dropping the child handle must not affect surviving descendants
        // either; only the durable domain owner may decide their fate.
        drop(child);
        assert!(
            process_is_alive(pid),
            "setsid descendant {pid} must survive the direct child handle being dropped"
        );
        // With the child handle gone, only the detached descendant keeps the
        // domain populated — and removal must refuse rather than kill it.
        assert!(
            domain.is_populated().expect("domain population"),
            "the setsid descendant must keep the domain populated after every \
             direct child handle is gone"
        );
        assert!(
            domain.remove_empty().is_err(),
            "a populated domain must refuse removal instead of killing members"
        );
        assert!(
            process_is_alive(pid),
            "a refused removal must leave the descendant untouched"
        );

        // Explicit teardown: kill_all reaches even the detached descendant,
        // the domain drains, and only then can the cgroup be removed.
        domain.kill_all().expect("kill all domain members");
        assert!(
            domain
                .wait_until_empty(Duration::from_secs(2))
                .expect("wait for domain to drain"),
            "domain must drain after kill_all"
        );
        assert!(!process_is_alive(pid));
        domain.remove_empty().expect("remove drained domain");
    }

    #[test]
    fn process_domain_pids_limit_is_shared_across_spawns() {
        if !landlock_ready() {
            eprintln!("skipping: kernel has no Landlock");
            return;
        }
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.resources = ResourceLimits {
            pids: Limit::Value(1),
            ..ResourceLimits::default()
        };
        let sandbox = Sandbox::detect();
        let domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected resource-domain error: {error}"),
        };
        let other_domain = match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
            Ok(domain) => domain,
            Err(error) => panic!("second resource domain could not be created: {error}"),
        };

        let mut first_command = CommandSpec::new("/bin/sleep");
        first_command = first_command.arg("30");
        let mut first =
            match sandbox.spawn_in_process_domain(first_command, config.clone(), &domain) {
                Ok(child) => child,
                Err(SandboxError::Unsupported { feature, reason }) => {
                    eprintln!("skipping: {feature} unsupported here: {reason}");
                    return;
                }
                Err(error) => panic!("unexpected first spawn error: {error}"),
            };

        let same_domain = sandbox.spawn_in_process_domain(
            CommandSpec::new("/bin/true"),
            config.clone(),
            &domain,
        );
        assert!(
            same_domain.is_err(),
            "a second process in the same pids.max=1 domain must be rejected"
        );

        let mut independent = sandbox
            .spawn_in_process_domain(CommandSpec::new("/bin/true"), config.clone(), &other_domain)
            .expect("a different resource domain must have an independent pids budget");
        assert_eq!(
            independent.wait().expect("wait independent child").code(),
            Some(0)
        );

        first.signal(libc::SIGKILL).expect("kill first child");
        let _ = first.wait().expect("wait first child");
        let mut reused = sandbox
            .spawn_in_process_domain(CommandSpec::new("/bin/true"), config, &domain)
            .expect("the same resource domain must be reusable after its child exits");
        assert_eq!(reused.wait().expect("wait reused child").code(), Some(0));

        domain.remove_empty().expect("remove first resource domain");
        other_domain
            .remove_empty()
            .expect("remove independent resource domain");
    }

    /// `plan-cgroup.md` M2: `cgroup.events` `populated` is the membership
    /// authority; `kill_all` is the only terminating operation and an empty
    /// domain's removal must not disturb processes in other domains.
    #[test]
    fn process_domain_populated_kill_and_remove_are_separate_operations() {
        let workspace = tempfile::tempdir().expect("workspace");
        let mut config = restricted_to(workspace.path());
        config.resources = ResourceLimits {
            pids: Limit::Value(8),
            ..ResourceLimits::default()
        };
        let sandbox = Sandbox::detect();
        let make_domain = || {
            match sandbox.create_process_domain(
            config.resources,
            delegated_cgroup_parent()
                .as_deref()
                .map(shbox_sandbox::CgroupParent::new),
        ) {
                Ok(domain) => Some(domain),
                Err(SandboxError::Unsupported { feature, reason }) => {
                    eprintln!("skipping: {feature} unsupported here: {reason}");
                    None
                }
                Err(error) => panic!("unexpected process-domain error: {error}"),
            }
        };
        let Some(domain) = make_domain() else {
            return;
        };
        let Some(other) = make_domain() else {
            return;
        };

        let mut witness_command = CommandSpec::new("/bin/sleep");
        witness_command = witness_command.arg("30");
        let mut witness = match sandbox.spawn_in_process_domain(
            witness_command,
            config.clone(),
            &other,
        ) {
            Ok(child) => child,
            Err(SandboxError::Unsupported { feature, reason }) => {
                eprintln!("skipping: {feature} unsupported here: {reason}");
                return;
            }
            Err(error) => panic!("unexpected witness spawn error: {error}"),
        };

        // An empty domain removes cleanly and does not touch other domains.
        assert!(!domain.is_populated().expect("empty domain population"));
        domain.remove_empty().expect("remove empty domain");
        assert!(
            other.is_populated().expect("witness domain population"),
            "removing an empty domain must not disturb a populated sibling"
        );

        // The witness domain drains only through its own kill_all, and that
        // kill reaches exactly this domain's members.
        other.kill_all().expect("kill witness domain");
        assert!(
            other
                .wait_until_empty(Duration::from_secs(2))
                .expect("witness drain"),
            "witness domain must drain after its own kill_all"
        );
        other.remove_empty().expect("remove drained witness domain");
        let _ = witness.wait();
    }
}
