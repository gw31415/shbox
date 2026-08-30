//! OpenSSH integration harness for the public-key server and the admin host
//! route and the SandboxManager management operations (PLANS.md Milestones
//! 2-7).
//!
//! Every test starts a real daemon binary with a temporary XDG tree and its
//! own listener, then drives it with the real `ssh` client. Tests share
//! nothing and are run serially (`--test-threads=1`).

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// One test daemon: process handle plus the paths and keys it was given.
struct TestDaemon {
    child: std::process::Child,
    port: u16,
    _root: TempDir,
    admin_key: KeyPair,
    normal_key: KeyPair,
    ssh_config: PathBuf,
    config_path: PathBuf,
}

struct KeyPair {
    private: PathBuf,
    public: PathBuf,
    fingerprint: String,
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn generated_key(dir: &Path, name: &str) -> KeyPair {
    let private = dir.join(name);
    let public = dir.join(format!("{name}.pub"));
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-f",
            private.to_str().expect("utf8 path"),
        ])
        .status()
        .expect("ssh-keygen runs");
    assert!(status.success(), "ssh-keygen failed");
    let output = Command::new("ssh-keygen")
        .args(["-lf", public.to_str().expect("utf8 path")])
        .output()
        .expect("ssh-keygen -lf runs");
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    // `3072 SHA256:... name (ED25519)` - the digest is the second field.
    let fingerprint = text
        .split_whitespace()
        .nth(1)
        .expect("fingerprint")
        .to_string();
    KeyPair {
        private,
        public,
        fingerprint,
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind :0");
    let address = listener.local_addr().expect("local addr");
    drop(listener);
    address.port()
}

fn daemon_binary() -> PathBuf {
    // cargo test builds the bin alongside the tests.
    let mut path = std::env::current_exe().expect("current exe");
    path.pop(); // deps
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("shbox");
    assert!(
        path.is_file(),
        "daemon binary missing at {}",
        path.display()
    );
    path
}

impl TestDaemon {
    fn start(admin_keys: &[&str]) -> TestDaemon {
        let root = TempDir::new().expect("temp root");
        let config_dir = root.path().join("config/shbox");
        let data_dir = root.path().join("data/shbox");
        let state_dir = root.path().join("state/shbox");
        let keys_dir = root.path().join("keys");
        for dir in [&config_dir, &data_dir, &state_dir, &keys_dir] {
            std::fs::create_dir_all(dir).expect("create dirs");
        }

        let admin_key = generated_key(&keys_dir, "admin");
        let normal_key = generated_key(&keys_dir, "normal");

        // The authorized-keys file carries both keys; only the admin key is
        // configured as admin.
        let authorized_keys = config_dir.join("authorized_keys");
        std::fs::write(
            &authorized_keys,
            format!(
                "# test authorized keys\n{}\n{}\n",
                std::fs::read_to_string(&admin_key.public)
                    .expect("admin pub")
                    .trim(),
                std::fs::read_to_string(&normal_key.public)
                    .expect("normal pub")
                    .trim(),
            ),
        )
        .expect("write authorized_keys");

        let admin_list: Vec<String> = admin_keys
            .iter()
            .filter(|name| **name == "admin")
            .map(|_| admin_key.fingerprint.clone())
            .collect();
        let mut config = String::new();
        let port = free_port();
        config.push_str(&format!("listen = [\"127.0.0.1:{port}\"]\n"));
        config.push_str(&format!(
            "authorized_keys = {:?}\n",
            authorized_keys.display().to_string()
        ));
        config.push_str(&format!("admin_keys = {admin_list:?}\n"));
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, config).expect("write config");

        let ssh_config = keys_dir.join("ssh_config");
        std::fs::write(
            &ssh_config,
            "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n  IdentitiesOnly yes\n  BatchMode yes\n",
        )
        .expect("write ssh_config");

        let child = Command::new(daemon_binary())
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon starts");

        let daemon = TestDaemon {
            child,
            port,
            _root: root,
            admin_key,
            normal_key,
            ssh_config,
            config_path,
        };
        daemon.wait_ready();
        daemon
    }

    /// Replace only the admin-key line in the fixture's config file.
    fn set_admin_keys(&self, admin_keys: &[&str]) {
        let current = std::fs::read_to_string(&self.config_path).expect("read config");
        let replacement = format!("admin_keys = {admin_keys:?}\n");
        let mut updated = String::with_capacity(current.len());
        let mut replaced = false;
        for line in current.lines() {
            if line.starts_with("admin_keys = ") {
                updated.push_str(&replacement);
                replaced = true;
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        assert!(replaced, "fixture config has no admin_keys line");
        std::fs::write(&self.config_path, updated).expect("write config");
    }

    /// Replace the listener address without changing the live socket.
    fn set_listen(&self, port: u16) {
        let current = std::fs::read_to_string(&self.config_path).expect("read config");
        let replacement = format!("listen = [\"127.0.0.1:{port}\"]\n");
        let mut updated = String::with_capacity(current.len());
        let mut replaced = false;
        for line in current.lines() {
            if line.starts_with("listen = ") {
                updated.push_str(&replacement);
                replaced = true;
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        assert!(replaced, "fixture config has no listen line");
        std::fs::write(&self.config_path, updated).expect("write config");
    }

    /// Send a signal to the child owned by this harness.
    fn send_signal(&self, signal: libc::c_int) {
        let pid = i32::try_from(self.child.id()).expect("daemon pid fits pid_t");
        // SAFETY: the pid comes from the child process owned by this test
        // daemon, and the caller keeps that child alive for the operation.
        let result = unsafe { libc::kill(pid, signal) };
        assert_eq!(result, 0, "sending signal {signal} to daemon pid {pid}");
    }

    /// Ask this daemon to reload its configuration from the fixture path.
    fn reload(&self) {
        self.send_signal(libc::SIGHUP);
    }

    /// Wait until the listener accepts TCP connections.
    fn wait_ready(&self) {
        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(address).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("daemon did not become reachable on {address}");
    }

    /// Run the real OpenSSH client against this daemon.
    fn ssh(&self, key: &KeyPair, username: &str, command: &str, extra: &[&str]) -> SshResult {
        let output = Command::new("ssh")
            .arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .args(extra)
            .arg(format!("{username}@127.0.0.1"))
            .arg(command)
            .output()
            .expect("ssh runs");
        SshResult {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Run a command over an explicit OpenSSH ControlMaster connection.
    fn ssh_with_control(
        &self,
        key: &KeyPair,
        username: &str,
        command: &str,
        control_path: &Path,
        control_master: &str,
    ) -> std::process::Output {
        Command::new("ssh")
            .arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .args(["-o", "ControlPersist=30"])
            .arg("-o")
            .arg(format!("ControlPath={}", control_path.display()))
            .arg("-o")
            .arg(format!("ControlMaster={control_master}"))
            .arg(format!("{username}@127.0.0.1"))
            .arg(command)
            .output()
            .expect("ssh runs")
    }

    /// Query or close an existing OpenSSH ControlMaster without opening a
    /// fallback connection.
    fn control_operation(
        &self,
        key: &KeyPair,
        username: &str,
        control_path: &Path,
        operation: &str,
    ) -> std::process::Output {
        Command::new("ssh")
            .arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .args(["-o", "ControlPersist=30"])
            .arg("-o")
            .arg(format!("ControlPath={}", control_path.display()))
            .arg("-O")
            .arg(operation)
            .arg(format!("{username}@127.0.0.1"))
            .output()
            .expect("ssh runs")
    }
}

#[derive(Debug)]
struct SshResult {
    status: i32,
    stdout: String,
    stderr: String,
}

impl SshResult {
    fn ok(&self) -> bool {
        self.status == 0
    }
}

const RELOAD_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Wait for an observable post-reload state without retrying indefinitely.
fn retry_until<T>(description: &str, mut attempt: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + RELOAD_RETRY_TIMEOUT;
    loop {
        if let Some(value) = attempt() {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("{description} did not settle within {RELOAD_RETRY_TIMEOUT:?}");
        }
        std::thread::sleep(RELOAD_RETRY_DELAY);
    }
}

fn run_ssh_command(
    config: PathBuf,
    key: PathBuf,
    port: u16,
    username: &str,
    command: &str,
) -> std::process::Output {
    Command::new("ssh")
        .arg("-F")
        .arg(config)
        .arg("-i")
        .arg(key)
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{username}@127.0.0.1"))
        .arg(command)
        .output()
        .expect("ssh runs")
}

/// Real Arapuca execution is an explicit environment-gated acceptance test.
/// Ordinary CI and developer runs must prove the fail-closed path when the
/// wrapper/delegated cgroup is not provisioned; a successful branch is never
/// accepted merely because the adapter happened to be unavailable.
fn arapuca_integration_enabled() -> bool {
    std::env::var_os("SHBOX_RUN_ARAPUCA_INTEGRATION").is_some()
}

/// The `_` host route runs the daemon account's login shell and command.
#[test]
fn admin_host_exec_works() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.admin_key, "_", "printf host-ok", &["-T"]);
    assert!(result.ok(), "admin exec failed: {result:?}");
    assert_eq!(result.stdout, "host-ok");
}

/// A long-running host request does not stop the listener from accepting and
/// serving an independent SSH connection.
#[test]
fn independent_connections_are_served_concurrently() {
    let daemon = TestDaemon::start(&["admin"]);
    let first_config = daemon.ssh_config.clone();
    let first_key = daemon.admin_key.private.clone();
    let first_port = daemon.port;
    let first = std::thread::spawn(move || {
        run_ssh_command(
            first_config,
            first_key,
            first_port,
            "_",
            "sleep 2; printf slow-ok",
        )
    });
    std::thread::sleep(Duration::from_millis(250));

    let began = Instant::now();
    let fast = run_ssh_command(
        daemon.ssh_config.clone(),
        daemon.admin_key.private.clone(),
        daemon.port,
        "_",
        "printf fast-ok",
    );
    let elapsed = began.elapsed();
    assert!(fast.status.success(), "fast connection failed: {fast:?}");
    assert_eq!(fast.stdout, b"fast-ok");
    assert!(
        elapsed < Duration::from_millis(1500),
        "listener serialized the fast request for {elapsed:?}"
    );

    let slow = first.join().expect("slow ssh thread");
    assert!(slow.status.success(), "slow connection failed: {slow:?}");
    assert_eq!(slow.stdout, b"slow-ok");
}

/// stdout and stderr are separate streams and the remote exit status is
/// reported faithfully.
#[test]
fn admin_host_exec_reports_streams_and_status() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(
        &daemon.admin_key,
        "_",
        "printf out; printf err >&2; exit 7",
        &["-T"],
    );
    assert_eq!(
        result.status, 7,
        "remote exit status must surface: {result:?}"
    );
    assert_eq!(result.stdout, "out");
    assert_eq!(result.stderr, "err");
}

/// The PTY route works for host exec (`ssh -tt`).
#[test]
fn admin_host_exec_with_pty() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.admin_key, "_", "printf pty-ok", &["-tt"]);
    assert!(result.ok(), "pty exec failed: {result:?}");
    assert!(
        result.stdout.contains("pty-ok"),
        "pty output: {:?}",
        result.stdout
    );
}

/// A normal key cannot use the reserved `_` selector; the failure is the
/// generic publickey denial with no role or key-set information.
#[test]
fn normal_key_cannot_use_host_selector() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.normal_key, "_", "printf nope", &["-T"]);
    assert!(!result.ok(), "normal key must not reach host mode");
    assert_eq!(result.status, 255, "transport/auth failure expected");
    assert!(
        result.stderr.contains("Permission denied"),
        "generic denial expected: {:?}",
        result.stderr
    );
    assert!(
        result.stderr.contains("publickey"),
        "method list must not leak roles: {:?}",
        result.stderr
    );
    assert!(!result.stdout.contains("nope"));
}

/// Unknown keys are rejected; `none`/password/keyboard-interactive methods
/// are not offered or fail without revealing the key set.
#[test]
fn unregistered_key_and_non_publickey_methods_are_refused() {
    let daemon = TestDaemon::start(&["admin"]);

    // A key that is not in authorized_keys at all.
    let root = TempDir::new().expect("tempdir");
    let foreign = generated_key(root.path(), "foreign");
    let result = daemon.ssh(&foreign, "_", "printf nope", &["-T"]);
    assert!(!result.ok());
    assert!(
        result.stderr.contains("Permission denied"),
        "{:?}",
        result.stderr
    );

    // Password-only authentication must fail for an otherwise valid key.
    let output = Command::new("ssh")
        .arg("-F")
        .arg(&daemon.ssh_config)
        .arg("-i")
        .arg(&daemon.admin_key.private)
        .arg("-p")
        .arg(daemon.port.to_string())
        .args([
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
            "-o",
            "NumberOfPasswordPrompts=0",
        ])
        .arg("_@127.0.0.1")
        .arg("printf nope")
        .output()
        .expect("ssh runs");
    assert!(!output.status.success(), "password auth must not succeed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Permission denied"), "{stderr}");
}

/// Sandbox launches fail closed by default. A real-platform harness opts in
/// explicitly with SHBOX_RUN_ARAPUCA_INTEGRATION and must then observe a real
/// successful launch.
#[test]
fn sandbox_requests_execute_or_fail_closed() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.normal_key, "dev", "printf nope", &["-T"]);
    if arapuca_integration_enabled() {
        assert_eq!(result.status, 0, "real Arapuca launch failed: {result:?}");
        assert_eq!(result.stdout, "nope");
    } else {
        assert_eq!(result.status, 111, "sandbox must fail closed: {result:?}");
        assert!(result.stderr.contains("request cannot be completed"));
        assert!(!result.stdout.contains("nope"));
    }
}

/// The real OpenSSH subsystem reaches the manager for owner-filtered and
/// admin-wide list, then performs an idempotent delete.
#[test]
fn sandbox_list_and_delete_are_wired_to_the_manager() {
    let daemon = TestDaemon::start(&["admin"]);

    // The request exercises lazy first-owner claim. The real-platform suite
    // opts in explicitly; the default path proves unavailable is fail-closed.
    let claim = daemon.ssh(&daemon.normal_key, "dev", "printf ignored", &["-T"]);
    if arapuca_integration_enabled() {
        assert!(claim.ok(), "real Arapuca launch failed: {claim:?}");
        assert_eq!(claim.stdout, "ignored");
    } else {
        assert_eq!(claim.status, 111, "sandbox must fail closed: {claim:?}");
        assert!(claim.stderr.contains("request cannot be completed"));
    }

    // The list username is only connection context; owner filtering uses the
    // authenticated fingerprint, so it need not itself be a SandboxId.
    let owner_list = daemon.ssh(&daemon.normal_key, "list-user", "list", &["-T", "-s"]);
    assert!(owner_list.ok(), "owner list failed: {owner_list:?}");
    assert_eq!(owner_list.stdout, "dev\n");
    assert!(owner_list.stderr.is_empty(), "list stderr: {owner_list:?}");

    let admin_list = daemon.ssh(&daemon.admin_key, "_", "list", &["-T", "-s"]);
    assert!(admin_list.ok(), "admin list failed: {admin_list:?}");
    assert_eq!(admin_list.stdout, "dev\n");

    let delete = daemon.ssh(&daemon.normal_key, "dev", "delete", &["-T", "-s"]);
    assert!(delete.ok(), "delete failed: {delete:?}");
    assert!(delete.stdout.is_empty(), "delete stdout: {delete:?}");
    assert!(delete.stderr.is_empty(), "delete stderr: {delete:?}");

    let absent = daemon.ssh(&daemon.normal_key, "dev", "delete", &["-T", "-s"]);
    assert!(absent.ok(), "absent delete must be a no-op: {absent:?}");
    assert!(absent.stdout.is_empty());
    assert!(absent.stderr.is_empty());

    let empty = daemon.ssh(&daemon.admin_key, "_", "list", &["-T", "-s"]);
    assert!(empty.ok(), "post-delete list failed: {empty:?}");
    assert!(empty.stdout.is_empty());
}

/// Client `env` requests are rejected but never kill the connection; an
/// existing authenticated connection keeps working across multiple channels.
#[test]
fn env_requests_are_rejected_and_connections_stay_usable() {
    let daemon = TestDaemon::start(&["admin"]);
    // OpenSSH sends env requests by default (LANG, LC_*); assert an explicit
    // SendEnv works and a second exec on the same connection still succeeds
    // through ControlMaster multiplexing (two channels on one connection).
    // ControlPath must stay under the 104-byte unix socket limit, so it
    // lives directly in /tmp (serial tests, unique per process).
    let control_path = std::env::temp_dir()
        .join(format!("shbox-ctl-{}", std::process::id()))
        .to_str()
        .expect("utf8")
        .to_string();
    let _ = std::fs::remove_file(&control_path);
    let base = [
        "-F",
        daemon.ssh_config.to_str().expect("utf8"),
        "-i",
        daemon.admin_key.private.to_str().expect("utf8"),
        "-p",
        &daemon.port.to_string(),
        "-o",
        "ControlMaster=auto",
        "-o",
        &format!("ControlPath={control_path}"),
        "-o",
        "ControlPersist=10",
        "-o",
        "SendEnv=SHBOX_TEST_ENV",
    ];
    let first = Command::new("ssh")
        .args(base)
        .env("SHBOX_TEST_ENV", "must-not-reach-host")
        .arg("_@127.0.0.1")
        .arg("test -z \"${SHBOX_TEST_ENV+x}\" && printf first-ok")
        .output()
        .expect("ssh runs");
    assert!(first.status.success(), "{:?}", first);
    assert_eq!(String::from_utf8_lossy(&first.stdout), "first-ok");
    let second = Command::new("ssh")
        .args(base)
        .env("SHBOX_TEST_ENV", "must-not-reach-host")
        .arg("_@127.0.0.1")
        .arg("test -z \"${SHBOX_TEST_ENV+x}\" && printf second-ok")
        .output()
        .expect("ssh runs");
    assert!(second.status.success(), "{:?}", second);
    assert_eq!(String::from_utf8_lossy(&second.stdout), "second-ok");
    let _ = std::fs::remove_file(control_path);
}

/// A malformed SIGHUP snapshot is rejected without changing the current
/// authentication snapshot used by subsequent connections.
#[test]
fn invalid_sighup_reload_keeps_previous_auth_snapshot() {
    let daemon = TestDaemon::start(&["admin"]);
    std::fs::write(&daemon.config_path, "admin_keys = [\n").expect("write invalid config");
    daemon.reload();

    let result = retry_until("admin access after invalid SIGHUP", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf old-snapshot", &["-T"]);
        (result.ok() && result.stdout == "old-snapshot").then_some(result)
    });
    assert_eq!(result.stdout, "old-snapshot");
}

/// SIGHUP changes roles only for new connections: removing the last admin,
/// retaining an already authenticated admin connection, and restoring the
/// key all use the real OpenSSH client path.
#[test]
fn sighup_admin_keys_update_new_connections_and_preserve_existing_role() {
    let daemon = TestDaemon::start(&["admin"]);
    let control_path = std::env::temp_dir().join(format!("shbox-hup-{}", std::process::id()));
    let _ = std::fs::remove_file(&control_path);

    let first = daemon.ssh_with_control(
        &daemon.admin_key,
        "_",
        "printf existing-before",
        &control_path,
        "yes",
    );
    assert!(first.status.success(), "control master failed: {first:?}");
    assert_eq!(first.stdout, b"existing-before");
    let _ = retry_until("ControlMaster readiness", || {
        let check = daemon.control_operation(&daemon.admin_key, "_", &control_path, "check");
        check.status.success().then_some(check)
    });

    daemon.set_admin_keys(&[]);
    daemon.reload();

    let denied = retry_until("new admin connection after admin removal", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf should-not-run", &["-T"]);
        (result.status == 255 && result.stderr.contains("Permission denied")).then_some(result)
    });
    assert!(
        !denied.ok(),
        "new connection must lose admin role: {denied:?}"
    );

    let existing = retry_until("existing admin connection after admin removal", || {
        let check = daemon.control_operation(&daemon.admin_key, "_", &control_path, "check");
        if !check.status.success() {
            return None;
        }
        let result = daemon.ssh_with_control(
            &daemon.admin_key,
            "_",
            "printf existing-after",
            &control_path,
            "no",
        );
        (result.status.success() && result.stdout == b"existing-after").then_some(result)
    });
    assert_eq!(existing.stdout, b"existing-after");

    daemon.set_admin_keys(&[daemon.admin_key.fingerprint.as_str()]);
    daemon.reload();

    let restored = retry_until("new admin connection after admin restore", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf restored", &["-T"]);
        (result.ok() && result.stdout == "restored").then_some(result)
    });
    assert_eq!(restored.stdout, "restored");

    let _ = daemon.control_operation(&daemon.admin_key, "_", &control_path, "exit");
    let _ = std::fs::remove_file(control_path);
}

/// A restart-only listener change rejects the whole reload, preserving the
/// prior auth snapshot instead of applying only the other changed fields.
#[test]
fn sighup_listener_change_is_rejected_atomically() {
    let daemon = TestDaemon::start(&["admin"]);
    daemon.set_listen(free_port());
    daemon.set_admin_keys(&[]);
    daemon.reload();

    let result = retry_until("admin access after restart-only reload", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf old-listener", &["-T"]);
        (result.ok() && result.stdout == "old-listener").then_some(result)
    });
    assert_eq!(result.stdout, "old-listener");
}

/// The daemon exits cleanly on SIGTERM.
#[test]
fn daemon_shuts_down_on_sigterm() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.admin_key, "_", "printf alive", &["-T"]);
    assert!(result.ok(), "{result:?}");
    daemon.send_signal(libc::SIGTERM);
    let status = daemon.child.wait().expect("wait");
    assert!(status.success(), "graceful exit expected, got {status}");
}

/// Shutdown closes an active host channel and eventually kills a process that
/// ignores the graceful TERM. The PID check makes the cleanup contract
/// observable beyond the SSH transport disconnect.
#[test]
fn daemon_shutdown_cleans_up_an_active_host_process() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let pid_path = std::env::temp_dir().join(format!("shbox-host-pid-{}", std::process::id()));
    let descendant_path =
        std::env::temp_dir().join(format!("shbox-host-descendant-pid-{}", std::process::id()));
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&descendant_path);
    let config = daemon.ssh_config.clone();
    let key = daemon.admin_key.private.clone();
    let port = daemon.port;
    let command_pid_path = pid_path.clone();
    let command_descendant_path = descendant_path.clone();
    let client = std::thread::spawn(move || {
        run_ssh_command(
            config,
            key,
            port,
            "_",
            &format!(
                "printf '%s' \"$$\" > {}; trap '' TERM; sleep 30 & child=$!; printf '%s' \"$child\" > {}; wait",
                command_pid_path.display(),
                command_descendant_path.display(),
            ),
        )
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    let (host_pid, descendant_pid) = loop {
        if let (Ok(host), Ok(descendant)) = (
            std::fs::read_to_string(&pid_path),
            std::fs::read_to_string(&descendant_path),
        ) {
            break (
                host.parse::<i32>().expect("host pid"),
                descendant.parse::<i32>().expect("descendant pid"),
            );
        }
        assert!(Instant::now() < deadline, "host process did not start");
        std::thread::sleep(Duration::from_millis(50));
    };

    daemon.send_signal(libc::SIGTERM);
    let daemon_status = daemon.child.wait().expect("daemon wait");
    assert!(
        daemon_status.success(),
        "graceful exit expected: {daemon_status}"
    );
    let client_status = client.join().expect("ssh client join");
    assert!(
        !client_status.status.success(),
        "shutdown must close ssh client"
    );

    for (label, pid) in [("host process", host_pid), ("descendant", descendant_pid)] {
        let deadline = Instant::now() + Duration::from_secs(7);
        loop {
            // SAFETY: the PID was written by the host process created by this
            // fixture; kill(pid, 0) only probes its existence.
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            assert!(Instant::now() < deadline, "{label} {pid} survived shutdown");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let _ = std::fs::remove_file(pid_path);
    let _ = std::fs::remove_file(descendant_path);
}

/// A second shutdown signal takes the force path instead of waiting for the
/// first graceful deadline or for the client connection to drain.
#[test]
fn second_shutdown_signal_force_stops_host_process() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let pid_path =
        std::env::temp_dir().join(format!("shbox-second-signal-pid-{}", std::process::id()));
    let _ = std::fs::remove_file(&pid_path);
    let config = daemon.ssh_config.clone();
    let key = daemon.admin_key.private.clone();
    let port = daemon.port;
    let command_pid_path = pid_path.clone();
    let client = std::thread::spawn(move || {
        run_ssh_command(
            config,
            key,
            port,
            "_",
            &format!(
                "printf '%s' \"$$\" > {}; trap '' TERM; sleep 30",
                command_pid_path.display()
            ),
        )
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    let host_pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_path) {
            break text.parse::<i32>().expect("host pid");
        }
        assert!(Instant::now() < deadline, "host process did not start");
        std::thread::sleep(Duration::from_millis(50));
    };

    daemon.send_signal(libc::SIGTERM);
    std::thread::sleep(Duration::from_millis(100));
    daemon.send_signal(libc::SIGTERM);
    let started = Instant::now();
    let status = daemon.child.wait().expect("daemon wait");
    assert!(status.success(), "graceful exit expected, got {status}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "second signal did not force a prompt exit"
    );
    let _ = client.join();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // SAFETY: the PID was written by the host process created by this
        // fixture; kill(pid, 0) only probes its existence.
        let result = unsafe { libc::kill(host_pid, 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "host process {host_pid} survived second shutdown signal"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(pid_path);
}

/// Linux's parent-death guard prevents a daemon crash from orphaning a host
/// child. This is intentionally target-gated because macOS has no equivalent
/// prctl contract; its native process-group behavior remains a release-gate
/// observation.
#[cfg(target_os = "linux")]
#[test]
fn daemon_crash_does_not_orphan_an_active_host_process() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let pid_path = std::env::temp_dir().join(format!("shbox-crash-pid-{}", std::process::id()));
    let _ = std::fs::remove_file(&pid_path);
    let config = daemon.ssh_config.clone();
    let key = daemon.admin_key.private.clone();
    let port = daemon.port;
    let command_pid_path = pid_path.clone();
    let client = std::thread::spawn(move || {
        run_ssh_command(
            config,
            key,
            port,
            "_",
            &format!(
                "printf '%s' \"$$\" > {}; sleep 30",
                command_pid_path.display()
            ),
        )
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    let child_pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_path) {
            break text.parse::<i32>().expect("host pid");
        }
        assert!(Instant::now() < deadline, "host process did not start");
        std::thread::sleep(Duration::from_millis(50));
    };

    daemon.send_signal(libc::SIGKILL);
    let _ = daemon.child.wait();
    let _ = client.join();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // SAFETY: the PID was written by the host process created by this
        // fixture; kill(pid, 0) only probes its existence.
        let result = unsafe { libc::kill(child_pid, 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "host process {child_pid} survived daemon crash"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(pid_path);
}
