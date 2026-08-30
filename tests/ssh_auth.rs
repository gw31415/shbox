//! OpenSSH integration harness for the public-key server and the admin host
//! route and the SandboxManager management operations (PLANS.md Milestones
//! 2-8).
//!
//! Every test starts a real daemon binary with a temporary XDG tree and its
//! own listener, then drives it with the real `ssh` client. Tests share
//! nothing and are run serially (`--test-threads=1`).

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
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

/// Keep daemon fixtures below the crate workspace instead of the usual
/// world-writable `/tmp`: shbox validates every authorized_keys ancestor.
fn ssh_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix(".shbox-ssh-test-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("tempdir")
}

impl TestDaemon {
    fn start(admin_keys: &[&str]) -> TestDaemon {
        Self::start_with_config(admin_keys, "")
    }

    fn start_with_config(admin_keys: &[&str], extra_config: &str) -> TestDaemon {
        let root = ssh_tempdir();
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
        if !extra_config.is_empty() {
            config.push_str(extra_config);
            if !extra_config.ends_with('\n') {
                config.push('\n');
            }
        }
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

    fn sandbox_workspace(&self, id: &str) -> PathBuf {
        self._root
            .path()
            .join("data/shbox/sandboxes")
            .join(id)
            .join("workspace")
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

    /// Run OpenSSH with one explicit client-only environment variable. The
    /// server still receives that value only through an SSH env request, so a
    /// test can prove that the request is rejected before the sandbox launch.
    fn ssh_with_client_env(
        &self,
        key: &KeyPair,
        username: &str,
        command: &str,
        extra: &[&str],
        name: &str,
        value: &str,
    ) -> SshResult {
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
            .env(name, value)
            .output()
            .expect("ssh runs");
        SshResult {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Spawn OpenSSH with pipes so the test can explicitly close client
    /// stdin after sending a bounded input sequence.
    fn spawn_ssh(
        &self,
        key: &KeyPair,
        username: &str,
        command: &str,
        extra: &[&str],
    ) -> std::process::Child {
        Command::new("ssh")
            .arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .args(extra)
            .arg(format!("{username}@127.0.0.1"))
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ssh starts")
    }

    /// Spawn OpenSSH on a local PTY. OpenSSH then sends the local PTY's
    /// dimensions and terminal modes in its real `pty-req`, and a SIGWINCH
    /// can be used to drive a real SSH `window-change` request.
    fn spawn_ssh_pty(
        &self,
        key: &KeyPair,
        username: &str,
        command: &str,
        rows: u16,
        cols: u16,
    ) -> OpenSshPty {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pair = nix::pty::openpty(Some(&size), None).expect("open local pty");
        let master: File = pair.master.into();
        let slave: File = pair.slave.into();
        configure_local_pty(slave.as_raw_fd());
        let stdout = slave.try_clone().expect("clone local pty stdout");
        let stderr = slave.try_clone().expect("clone local pty stderr");

        let child = Command::new("ssh")
            .arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-tt")
            .args(["-o", "EscapeChar=none"])
            .arg(format!("{username}@127.0.0.1"))
            .arg(command)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("ssh starts on local pty");

        OpenSshPty {
            child,
            master,
            pending: Vec::new(),
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

/// A real OpenSSH client attached to a local PTY. The master is kept in the
/// harness so tests can send bytes, resize the client terminal, and observe
/// the resulting remote PTY behavior without relying on an operator terminal.
struct OpenSshPty {
    child: std::process::Child,
    master: File,
    pending: Vec<u8>,
}

impl OpenSshPty {
    fn send(&mut self, data: &[u8]) {
        self.master.write_all(data).expect("write local pty");
        self.master.flush().expect("flush local pty");
    }

    fn read_until(&mut self, marker: &[u8], timeout: Duration) -> Vec<u8> {
        assert!(!marker.is_empty(), "PTY marker must not be empty");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(start) = find_subslice(&self.pending, marker) {
                let end = start + marker.len();
                return self.pending.drain(..end).collect();
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                panic!(
                    "PTY output did not contain {:?} within {timeout:?}; output={:?}",
                    String::from_utf8_lossy(marker),
                    String::from_utf8_lossy(&self.pending)
                );
            };
            let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd and the
            // master fd remains owned by this session for the call.
            let polled = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if polled == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                panic!("poll local pty: {error}");
            }
            if polled == 0 {
                panic!(
                    "PTY output did not contain {:?} within {timeout:?}; output={:?}",
                    String::from_utf8_lossy(marker),
                    String::from_utf8_lossy(&self.pending)
                );
            }

            let mut buffer = [0u8; 4096];
            match self.master.read(&mut buffer) {
                Ok(0) => panic!(
                    "local PTY closed before {:?}; output={:?}",
                    String::from_utf8_lossy(marker),
                    String::from_utf8_lossy(&self.pending)
                ),
                Ok(count) => self.pending.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => panic!(
                    "local PTY returned EIO before {:?}; output={:?}",
                    String::from_utf8_lossy(marker),
                    String::from_utf8_lossy(&self.pending)
                ),
                Err(error) => panic!("read local pty: {error}"),
            }
        }
    }

    fn resize(&self, rows: u16, cols: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the master is an open PTY and size points to an initialized
        // winsize owned by this stack frame.
        let result = unsafe {
            libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ,
                &size as *const libc::winsize,
            )
        };
        assert_eq!(result, 0, "resize local pty");

        let pid = i32::try_from(self.child.id()).expect("ssh pid fits pid_t");
        // SAFETY: the pid belongs to the OpenSSH child created by this
        // session; SIGWINCH asks it to send a protocol window-change.
        let result = unsafe { libc::kill(pid, libc::SIGWINCH) };
        assert_eq!(result, 0, "send SIGWINCH to OpenSSH client");
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll ssh child") {
                return status;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                panic!("OpenSSH child did not exit within {timeout:?}");
            };
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }
}

impl Drop for OpenSshPty {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn configure_local_pty(fd: std::os::fd::RawFd) {
    let mut state = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: fd is the slave side of the local PTY held by the caller.
    assert_eq!(
        unsafe { libc::tcgetattr(fd, &mut state) },
        0,
        "read local pty modes"
    );
    // Keep ISIG enabled so OpenSSH includes a real VINTR/ISIG request while
    // disabling canonical buffering and local echo for byte-level probes.
    state.c_lflag &= !(libc::ICANON | libc::ECHO);
    state.c_lflag |= libc::ISIG;
    state.c_cc[libc::VMIN] = 1;
    state.c_cc[libc::VTIME] = 0;
    // SAFETY: state was read from this PTY and remains fully initialized.
    assert_eq!(
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &state) },
        0,
        "set local pty modes"
    );
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn between_markers<'a>(output: &'a [u8], start: &[u8], end: &[u8]) -> &'a [u8] {
    let start_index = find_subslice(output, start).expect("start marker");
    let content = &output[start_index + start.len()..];
    let end = find_subslice(content, end).expect("end marker");
    &content[..end]
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

/// Real Arapuca execution is an explicit environment-gated acceptance test on
/// Linux. macOS arm64 has an embedded rlimit wrapper, so its normal OpenSSH
/// harness exercises the real Seatbelt path without a separately installed
/// `arapuca` binary.
fn arapuca_integration_enabled() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
        || std::env::var_os("SHBOX_RUN_ARAPUCA_INTEGRATION").is_some()
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
    let root = ssh_tempdir();
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

/// The real Arapuca path keeps non-PTY stdout/stderr separate and forwards a
/// non-zero shell exit status through the OpenSSH client.
#[test]
fn arapuca_sandbox_non_pty_exec_reports_streams_and_status() {
    if !arapuca_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(
        &daemon.normal_key,
        "m8-streams",
        "printf out; printf err >&2; exit 17",
        &["-T"],
    );
    assert_eq!(result.status, 17, "sandbox exit status: {result:?}");
    assert_eq!(result.stdout, "out");
    assert_eq!(result.stderr, "err");
}

/// The real PTY path exposes the requested terminal modes and size, supports
/// raw byte input, and applies a later OpenSSH window-change request.
#[test]
fn arapuca_sandbox_pty_applies_modes_and_resize() {
    if !arapuca_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let command = concat!(
        "printf '__M8_TERM_%s__' \"$TERM\"; ",
        "printf '__M8_PTY_READY__'; ",
        "dd bs=1 count=1 >/dev/null 2>/dev/null; ",
        "printf '__M8_MODES_BEGIN__'; stty -a; printf '__M8_MODES_END__'; ",
        "stty raw -echo; ",
        "printf '__M8_RAW_BEGIN__'; stty -a; printf '__M8_RAW_END__'; ",
        "printf '__M8_INITIAL_BEGIN__'; stty size; printf '__M8_INITIAL_END__'; ",
        "printf '__M8_RESIZE_READY__'; ",
        "dd bs=1 count=1 >/dev/null 2>/dev/null; ",
        "printf '__M8_RESIZED_BEGIN__'; stty size; printf '__M8_RESIZED_END__'"
    );
    let mut session = daemon.spawn_ssh_pty(&daemon.normal_key, "m8-pty", command, 24, 80);

    let ready = session.read_until(b"__M8_PTY_READY__", Duration::from_secs(5));
    assert!(
        String::from_utf8_lossy(&ready).contains("__M8_TERM_xterm-256color__"),
        "TERM was not negotiated through pty-req: {ready:?}"
    );
    // A single byte must pass the requested non-canonical mode before the
    // remote command can emit the mode and size probes.
    session.send(b"A");
    let first = session.read_until(b"__M8_RESIZE_READY__", Duration::from_secs(5));
    let first_text = String::from_utf8_lossy(&first);
    let modes = between_markers(&first, b"__M8_MODES_BEGIN__", b"__M8_MODES_END__");
    let modes_text = String::from_utf8_lossy(modes);
    assert!(
        modes_text.contains("-icanon"),
        "canonical mode remained enabled: {modes_text}"
    );
    assert!(
        modes_text.contains("-echo"),
        "echo mode remained enabled: {modes_text}"
    );
    assert!(
        modes_text.contains("isig") && !modes_text.contains("-isig"),
        "signal mode was not enabled: {modes_text}"
    );
    let mode_start = first_text
        .find("__M8_MODES_BEGIN__")
        .expect("mode marker in PTY output");
    assert!(
        !first_text[..mode_start].contains('A'),
        "input was echoed despite the requested echo mode: {first_text}"
    );

    let raw = between_markers(&first, b"__M8_RAW_BEGIN__", b"__M8_RAW_END__");
    let raw_text = String::from_utf8_lossy(raw);
    assert!(
        raw_text.contains("-icanon"),
        "stty raw did not disable canonical mode"
    );
    assert!(
        raw_text.contains("-echo"),
        "stty raw -echo did not disable echo"
    );

    let initial = between_markers(&first, b"__M8_INITIAL_BEGIN__", b"__M8_INITIAL_END__");
    assert!(
        String::from_utf8_lossy(initial).contains("24 80"),
        "initial PTY size was not applied: {initial:?}"
    );

    session.resize(41, 117);
    std::thread::sleep(Duration::from_millis(250));
    session.send(b"R");
    let resized = session.read_until(b"__M8_RESIZED_END__", Duration::from_secs(5));
    let resized_size = between_markers(&resized, b"__M8_RESIZED_BEGIN__", b"__M8_RESIZED_END__");
    assert!(
        String::from_utf8_lossy(resized_size).contains("41 117"),
        "window-change was not applied: {resized:?}"
    );
    assert!(
        session.wait_for_exit(Duration::from_secs(5)).success(),
        "PTY probe did not exit successfully"
    );
}

/// The real launch maps HOME/PWD to the durable workspace, injects only the
/// configured sandbox environment, and keeps a client env request out.
#[test]
fn arapuca_sandbox_maps_environment_and_workspace() {
    if !arapuca_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start_with_config(
        &["admin"],
        "[sandbox_env]\nM8_SANDBOX_TOKEN = \"configured-token\"\n",
    );
    let id = "m8-environment";
    let marker = daemon.sandbox_workspace(id).join("m8-workspace-marker");
    let result = daemon.ssh_with_client_env(
        &daemon.normal_key,
        id,
        r#"test "$M8_SANDBOX_TOKEN" = "configured-token" && test -z "${M8_CLIENT_INJECTION+x}" && test "$HOME" = "$PWD" && test "$(pwd)" = "$PWD" && printf workspace-ok > "$HOME/m8-workspace-marker" && printf '%s\n%s\n%s\n' "$HOME" "$PWD" "$(pwd)""#,
        &["-T", "-o", "SendEnv=M8_CLIENT_INJECTION"],
        "M8_CLIENT_INJECTION",
        "must-not-reach-sandbox",
    );
    assert!(result.ok(), "sandbox environment probe failed: {result:?}");
    let expected =
        std::fs::canonicalize(daemon.sandbox_workspace(id)).expect("canonical sandbox workspace");
    let lines = result.stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "sandbox HOME/PWD output: {result:?}");
    assert_eq!(lines[0], lines[1], "HOME and PWD differ: {result:?}");
    for path in lines {
        assert_eq!(
            std::fs::canonicalize(path).expect("canonical sandbox environment path"),
            expected,
            "sandbox path escaped its workspace: {result:?}"
        );
    }
    assert!(
        result.stderr.is_empty(),
        "sandbox environment stderr: {result:?}"
    );
    assert_eq!(
        std::fs::read_to_string(marker).expect("sandbox workspace marker"),
        "workspace-ok"
    );
}

/// Client EOF closes a non-PTY stdin and still permits output/status delivery;
/// PTY EOF does not inject a VEOF byte into the sandbox child.
#[test]
fn arapuca_sandbox_eof_behavior_is_transport_correct() {
    if !arapuca_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let mut non_pty = daemon.spawn_ssh(
        &daemon.normal_key,
        "m8-non-pty-eof",
        "cat; printf __M8_NON_PTY_EOF__; exit 19",
        &["-T"],
    );
    let mut input = non_pty.stdin.take().expect("non-PTY ssh stdin");
    input.write_all(b"eof-input").expect("write non-PTY input");
    drop(input);
    let output = non_pty.wait_with_output().expect("wait for non-PTY EOF");
    assert_eq!(
        output.status.code(),
        Some(19),
        "non-PTY EOF status: {output:?}"
    );
    assert_eq!(
        output.stdout, b"eof-input__M8_NON_PTY_EOF__",
        "non-PTY output after EOF: {output:?}"
    );
    assert!(output.stderr.is_empty(), "non-PTY EOF stderr: {output:?}");

    let mut pty = daemon.spawn_ssh(
        &daemon.normal_key,
        "m8-pty-eof",
        "printf '__M8_PTY_EOF_READY__\\n'; read -r line; printf __M8_SYNTHETIC_VEOF__",
        &["-tt"],
    );
    let stdout = pty.stdout.take().expect("PTY ssh stdout");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let _ = ready_tx.send(result.map(|_| line));
        let mut tail = Vec::new();
        let tail_result = reader.read_to_end(&mut tail);
        (tail_result, tail)
    });
    let ready = match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => {
            let _ = pty.kill();
            let _ = pty.wait_with_output();
            let _ = reader.join();
            panic!("read PTY EOF ready marker: {error}");
        }
        Err(error) => {
            let _ = pty.kill();
            let _ = pty.wait_with_output();
            let _ = reader.join();
            panic!("PTY EOF ready marker did not arrive: {error}");
        }
    };
    if !ready.contains("__M8_PTY_EOF_READY__") {
        let _ = pty.kill();
        let _ = pty.wait_with_output();
        let _ = reader.join();
        panic!("PTY EOF ready output: {ready:?}");
    }
    let input = pty.stdin.take().expect("PTY ssh stdin");
    drop(input);
    let deadline = Instant::now() + Duration::from_millis(750);
    let exited = loop {
        if let Some(status) = pty.try_wait().expect("poll PTY ssh child") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let pty_output = if exited.is_none() {
        let _ = pty.kill();
        pty.wait_with_output().expect("wait for PTY EOF cleanup")
    } else {
        pty.wait_with_output().expect("collect PTY EOF output")
    };
    let (tail_result, tail) = reader.join().expect("PTY EOF stdout reader");
    tail_result.expect("read PTY EOF output");
    assert!(
        exited.is_none(),
        "PTY child exited after client EOF, likely from synthetic VEOF: {pty_output:?}"
    );
    assert!(
        !String::from_utf8_lossy(&tail).contains("__M8_SYNTHETIC_VEOF__"),
        "PTY child observed synthetic VEOF: {tail:?}"
    );
}

/// A terminal VINTR byte reaches the sandbox process group and is surfaced by
/// the real PTY exec as the command's handled interrupt exit.
#[test]
fn arapuca_sandbox_pty_forwards_terminal_signal() {
    if !arapuca_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let mut session = daemon.spawn_ssh_pty(
        &daemon.normal_key,
        "m8-signal",
        "printf __M8_SIGNAL_READY__; trap 'printf __M8_SIGNAL_HANDLED__; exit 23' INT; while :; do read -r line; done",
        24,
        80,
    );
    session.read_until(b"__M8_SIGNAL_READY__", Duration::from_secs(5));
    session.send(&[0x03]);
    session.read_until(b"__M8_SIGNAL_HANDLED__", Duration::from_secs(5));
    let status = session.wait_for_exit(Duration::from_secs(5));
    assert_eq!(
        status.code(),
        Some(23),
        "handled terminal signal status: {status}"
    );
}

/// A real sandbox shutdown removes both the direct process and an ignored-TERM
/// descendant from the sandbox runtime before the daemon exits.
#[test]
fn arapuca_sandbox_shutdown_cleans_up_descendants() {
    if !arapuca_integration_enabled() {
        return;
    }

    let mut daemon = TestDaemon::start(&["admin"]);
    let id = "m8-cleanup";
    let workspace = daemon.sandbox_workspace(id);
    let parent_path = workspace.join("m8-parent.pid");
    let descendant_path = workspace.join("m8-descendant.pid");
    let config = daemon.ssh_config.clone();
    let key = daemon.normal_key.private.clone();
    let port = daemon.port;
    let client = std::thread::spawn(move || {
        run_ssh_command(
            config,
            key,
            port,
            id,
            r#"printf '%s' "$$" > "$HOME/m8-parent.pid"; trap '' TERM; sleep 30 & child=$!; printf '%s' "$child" > "$HOME/m8-descendant.pid"; wait"#,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let (parent_pid, descendant_pid) = loop {
        if let (Ok(parent), Ok(descendant)) = (
            std::fs::read_to_string(&parent_path),
            std::fs::read_to_string(&descendant_path),
        ) {
            break (
                parent.trim().parse::<i32>().expect("sandbox parent pid"),
                descendant
                    .trim()
                    .parse::<i32>()
                    .expect("sandbox descendant pid"),
            );
        }
        assert!(
            Instant::now() < deadline,
            "sandbox descendant fixture did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    daemon.send_signal(libc::SIGTERM);
    let daemon_status = daemon.child.wait().expect("daemon wait");
    assert!(
        daemon_status.success(),
        "graceful sandbox shutdown expected: {daemon_status}"
    );
    let _ = client.join().expect("sandbox ssh client join");

    for (label, pid) in [
        ("sandbox parent", parent_pid),
        ("sandbox descendant", descendant_pid),
    ] {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: each PID was written by the sandbox process created by
            // this fixture; kill(pid, 0) only probes its existence.
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{label} {pid} survived sandbox shutdown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
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
