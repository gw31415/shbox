//! OpenSSH integration harness for the public-key server and the admin host
//! route (PLANS.md Milestone 2).
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
        };
        daemon.wait_ready();
        daemon
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

/// A normal key with a valid sandbox selector reaches the intentional
/// unavailable placeholder (Milestones 3-4), which is a generic non-zero
/// completion rather than a crash or an authorization leak.
#[test]
fn sandbox_requests_are_currently_unavailable() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.normal_key, "dev", "printf nope", &["-T"]);
    assert!(!result.ok(), "sandbox route is not implemented yet");
    assert_eq!(result.status, 111, "generic unavailable status");
    assert!(!result.stdout.contains("nope"));
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

/// The daemon exits cleanly on SIGTERM.
#[test]
fn daemon_shuts_down_on_sigterm() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.admin_key, "_", "printf alive", &["-T"]);
    assert!(result.ok(), "{result:?}");
    let pid = daemon.child.id() as i32;
    // SAFETY: kill(2) with SIGTERM on the daemon we spawned.
    unsafe {
        libc_kill(pid);
    }
    let status = daemon.child.wait().expect("wait");
    assert!(status.success(), "graceful exit expected, got {status}");
}

// SAFETY wrapper so the test body does not repeat the unsafe block.
unsafe fn libc_kill(pid: i32) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    assert_eq!(unsafe { kill(pid, 15) }, 0);
}
