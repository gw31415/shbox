//! OpenSSH integration harness for the public-key server and the admin host
//! route and the SandboxManager management operations (Milestones 2-8).
//!
//! Every test starts a real daemon binary with a temporary XDG tree and its
//! own listener, then drives it with the real `ssh` client. Tests share
//! nothing and are run serially (`--test-threads=1`). The harness speaks
//! plain TCP SSH, so it only applies to `tcp` builds.

#![cfg(feature = "tcp")]

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
    stderr_reader: Option<std::thread::JoinHandle<String>>,
    port: u16,
    _root: TempDir,
    admin_key: KeyPair,
    normal_key: KeyPair,
    ssh_config: PathBuf,
    config_path: PathBuf,
    host_authorized_keys: PathBuf,
    sandbox_allowed_keys: PathBuf,
}

struct KeyPair {
    private: PathBuf,
    public: PathBuf,
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.read_stderr();
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
    KeyPair { private, public }
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
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix(".shbox-ssh-test-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("tempdir");
    // The fixture root is an ancestor of every key source the daemon
    // validates; make it private regardless of the ambient umask.
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("fixture root must be private");
    root
}

impl TestDaemon {
    fn start(admin_keys: &[&str]) -> TestDaemon {
        Self::start_with_config(admin_keys, "")
    }

    fn start_with_config(admin_keys: &[&str], extra_config: &str) -> TestDaemon {
        use std::os::unix::fs::PermissionsExt;
        let root = ssh_tempdir();
        let home_dir = root.path().join("home");
        let ssh_dir = home_dir.join(".ssh");
        let config_dir = root.path().join("config/shbox");
        let data_dir = root.path().join("data/shbox");
        let state_dir = root.path().join("state/shbox");
        let keys_dir = root.path().join("keys");
        for dir in [
            &home_dir,
            &ssh_dir,
            &config_dir,
            &data_dir,
            &state_dir,
            &keys_dir,
            // Intermediate directories created by create_dir_all must be
            // private too: the daemon walks the whole ancestor chain of
            // every key source, and default modes are umask-dependent.
            &root.path().join("config"),
            &root.path().join("data"),
            &root.path().join("state"),
        ] {
            std::fs::create_dir_all(dir).expect("create dirs");
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod 0700");
        }

        let admin_key = generated_key(&keys_dir, "admin");
        let normal_key = generated_key(&keys_dir, "normal");

        let host_authorized_keys = ssh_dir.join("authorized_keys");
        let sandbox_allowed_keys = config_dir.join("allowed_keys");

        let mut host_content = String::new();
        if admin_keys.contains(&"admin") {
            host_content.push_str(
                std::fs::read_to_string(&admin_key.public)
                    .expect("admin pub")
                    .trim(),
            );
            host_content.push('\n');
        }
        std::fs::write(&host_authorized_keys, &host_content).expect("write host authorized_keys");
        std::fs::set_permissions(
            &host_authorized_keys,
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod host authorized_keys");

        let allowed_content = format!(
            "{}\n",
            std::fs::read_to_string(&normal_key.public)
                .expect("normal pub")
                .trim()
        );
        std::fs::write(&sandbox_allowed_keys, &allowed_content)
            .expect("write sandbox allowed_keys");
        std::fs::set_permissions(
            &sandbox_allowed_keys,
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod sandbox allowed_keys");

        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, extra_config).expect("write config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");

        let ssh_config = keys_dir.join("ssh_config");
        std::fs::write(
            &ssh_config,
            "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n  IdentitiesOnly yes\n  BatchMode yes\n",
        )
        .expect("write ssh_config");

        let port = free_port();
        let mut daemon_command = Command::new(daemon_binary());
        daemon_command
            .env("HOME", &home_dir)
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .arg("--listen")
            .arg(format!("tcp://127.0.0.1:{port}"));
        let mut child = daemon_command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("daemon starts");
        let mut daemon_stderr = child.stderr.take().expect("daemon stderr pipe");
        let stderr_reader = std::thread::spawn(move || {
            let mut output = String::new();
            daemon_stderr
                .read_to_string(&mut output)
                .expect("read daemon stderr");
            output
        });

        let mut daemon = TestDaemon {
            child,
            stderr_reader: Some(stderr_reader),
            port,
            _root: root,
            admin_key,
            normal_key,
            ssh_config,
            config_path,
            host_authorized_keys,
            sandbox_allowed_keys,
        };
        daemon.wait_ready();
        daemon
    }

    fn read_stderr(&mut self) -> String {
        let Some(stderr_reader) = self.stderr_reader.take() else {
            return String::new();
        };
        stderr_reader.join().expect("stderr reader thread")
    }

    /// Stop the daemon cleanly and return everything it wrote to stderr.
    /// The stderr pipe is read to EOF, so this only completes after exit.
    fn stop_and_collect_stderr(&mut self) -> String {
        self.send_signal(libc::SIGTERM);
        self.child.wait().expect("wait for daemon exit");
        self.read_stderr()
    }

    fn sandbox_workspace(&self, id: &str) -> PathBuf {
        self._root
            .path()
            .join("data/shbox/sandboxes")
            .join(id)
            .join("workspace")
    }

    fn set_host_keys(&self, content: &str) {
        write_key_source(&self.host_authorized_keys, content, "host keys");
    }

    fn set_allowed_keys(&self, content: &str) {
        write_key_source(&self.sandbox_allowed_keys, content, "allowed keys");
    }

    /// Replace the whole config file content with a complete new document.
    fn set_config(&self, content: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&self.config_path, content).expect("write config");
        std::fs::set_permissions(&self.config_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod config");
    }

    /// Send a signal to the child owned by this harness.
    fn send_signal(&self, signal: libc::c_int) {
        let pid = i32::try_from(self.child.id()).expect("daemon pid fits pid_t");
        // SAFETY: the pid comes from the child process owned by this test
        // daemon, and the caller keeps that child alive for the operation.
        let result = unsafe { libc::kill(pid, signal) };
        assert_eq!(result, 0, "sending signal {signal} to daemon pid {pid}");
    }

    /// Send SIGHUP: the daemon invalidates its cached key-file identities so
    /// the next authentication request re-validates both key sources. The
    /// config file is never re-read; applying a config change needs a restart.
    fn sighup(&self) {
        self.send_signal(libc::SIGHUP);
    }

    /// Wait until the listener accepts TCP connections.
    fn wait_ready(&mut self) {
        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(address).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let status = self.child.try_wait().expect("poll daemon status");
        let stderr = if status.is_some() {
            self.read_stderr()
        } else {
            String::new()
        };
        panic!("daemon did not become reachable on {address}; status={status:?}; stderr={stderr}");
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
        self.spawn_ssh_pty_inner(key, username, Some(command), rows, cols, false)
    }

    /// Spawn a genuine SSH shell request instead of an exec request. The local
    /// terminal starts in sane canonical mode so OpenSSH forwards ordinary
    /// job-control characters (VINTR/VSUSP) in the initial `pty-req`.
    fn spawn_ssh_interactive_pty(
        &self,
        key: &KeyPair,
        username: &str,
        rows: u16,
        cols: u16,
    ) -> OpenSshPty {
        self.spawn_ssh_pty_inner(key, username, None, rows, cols, true)
    }

    fn spawn_ssh_pty_inner(
        &self,
        key: &KeyPair,
        username: &str,
        remote_command: Option<&str>,
        rows: u16,
        cols: u16,
        interactive: bool,
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
        if interactive {
            configure_interactive_local_pty(slave.as_raw_fd());
        } else {
            configure_local_pty(slave.as_raw_fd());
        }
        let stdout = slave.try_clone().expect("clone local pty stdout");
        let stderr = slave.try_clone().expect("clone local pty stderr");

        let mut ssh = Command::new("ssh");
        ssh.arg("-F")
            .arg(&self.ssh_config)
            .arg("-i")
            .arg(&key.private)
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-tt")
            .args(["-o", "EscapeChar=none"])
            .arg(format!("{username}@127.0.0.1"));
        if let Some(remote_command) = remote_command {
            ssh.arg(remote_command);
        }
        let child = ssh
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

fn write_key_source(path: &Path, content: &str, label: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content).expect("write key source");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|_| panic!("chmod {label}"));
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

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn kill_client(&mut self) {
        if self.is_running() {
            self.child.kill().expect("kill OpenSSH client");
        }
        let _ = self.child.wait();
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

fn configure_interactive_local_pty(fd: std::os::fd::RawFd) {
    let mut state = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: fd is the local PTY slave owned by the harness.
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut state) }, 0);
    state.c_lflag |= libc::ICANON | libc::ECHO | libc::ISIG;
    state.c_cc[libc::VINTR] = 0x03;
    state.c_cc[libc::VSUSP] = 0x1a;
    state.c_cc[libc::VEOF] = 0x04;
    // SAFETY: state came from this PTY and remains initialized.
    assert_eq!(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &state) }, 0);
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

#[derive(Debug)]
struct TtyProbe {
    tty_bits: String,
    tty_device: u64,
    sid: i64,
    terminal_sid: i64,
    process_group: i64,
    foreground_group: i64,
}

fn build_tty_probe(workspace: &Path) -> PathBuf {
    let source = workspace.join("m6-tty-probe.c");
    let binary = workspace.join("m6-tty-probe");
    std::fs::write(
        &source,
        r#"#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

int main(void) {
    pid_t sid = getsid(0);
    pid_t terminal_sid = tcgetsid(STDIN_FILENO);
    pid_t process_group = getpgrp();
    pid_t foreground_group = tcgetpgrp(STDIN_FILENO);
    struct stat terminal_stat;
    if (fstat(STDIN_FILENO, &terminal_stat) != 0) return 2;
    printf("__M6_TTY_PROBE__ %d%d%d %llu %ld %ld %ld %ld\n",
           isatty(STDIN_FILENO), isatty(STDOUT_FILENO), isatty(STDERR_FILENO),
           (unsigned long long)terminal_stat.st_rdev, (long)sid, (long)terminal_sid,
           (long)process_group, (long)foreground_group);
    fflush(stdout);
    return 0;
}
"#,
    )
    .expect("write tty probe source");
    let status = Command::new("cc")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .status()
        .expect("C compiler runs for tty probe");
    assert!(status.success(), "compile tty probe: {status}");
    binary
}

fn parse_tty_probe(output: &[u8]) -> TtyProbe {
    let text = String::from_utf8_lossy(output);
    let line = text
        .lines()
        .find(|line| line.contains("__M6_TTY_PROBE__"))
        .unwrap_or_else(|| panic!("tty probe marker missing: {text:?}"));
    let fields = line
        .split("__M6_TTY_PROBE__")
        .nth(1)
        .expect("tty probe payload")
        .split_whitespace()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 6, "tty probe fields: {line:?}");
    TtyProbe {
        tty_bits: fields[0].to_string(),
        tty_device: fields[1].parse().expect("tty probe device"),
        sid: fields[2].parse().expect("tty probe sid"),
        terminal_sid: fields[3].parse().expect("tty probe terminal sid"),
        process_group: fields[4].parse().expect("tty probe process group"),
        foreground_group: fields[5].parse().expect("tty probe foreground group"),
    }
}

fn wait_for_pid_gone(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pid_is_terminated(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// A fixture PID counts as terminated when the kernel forgot it entirely or
/// when it is dead-but-unreaped. On Linux an orphan is reparented to the
/// surrounding init, and a container whose PID 1 never waits keeps it as a
/// zombie that still answers `kill(pid, 0)`. A zombie holds no address space
/// and cannot run again, so the cleanup contract is satisfied either way; a
/// live state (`S`, `R`, …) keeps counting as present.
fn pid_is_terminated(pid: libc::pid_t) -> bool {
    // SAFETY: signal zero performs existence/permission checking only.
    let result = unsafe { libc::kill(pid, 0) };
    if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if linux_process_state(pid).as_deref() == Some("Z") {
        return true;
    }
    false
}

/// Read the scheduler state field of `/proc/<pid>/stat`. The comm field is
/// parenthesized and may itself contain spaces, so parsing starts after the
/// final closing parenthesis.
#[cfg(target_os = "linux")]
fn linux_process_state(pid: libc::pid_t) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1;
    tail.split_whitespace().next().map(str::to_owned)
}

#[derive(Debug, Clone)]
struct DaemonFdSnapshot {
    total: usize,
    slave_ttys: Vec<String>,
}

#[cfg(target_os = "linux")]
fn daemon_fd_snapshot(pid: u32) -> DaemonFdSnapshot {
    let directory =
        std::fs::read_dir(format!("/proc/{pid}/fd")).expect("daemon /proc fd directory");
    let mut targets = Vec::new();
    for entry in directory {
        let entry = entry.expect("daemon fd entry");
        if let Ok(target) = std::fs::read_link(entry.path()) {
            targets.push(target.to_string_lossy().into_owned());
        }
    }
    let mut slave_ttys = targets
        .iter()
        .filter(|target| target.starts_with("/dev/pts/") && target.as_str() != "/dev/pts/ptmx")
        .cloned()
        .collect::<Vec<_>>();
    slave_ttys.sort();
    DaemonFdSnapshot {
        total: targets.len(),
        slave_ttys,
    }
}

#[cfg(target_os = "macos")]
fn daemon_fd_snapshot(pid: u32) -> DaemonFdSnapshot {
    let output = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-Fn"])
        .output()
        .expect("lsof daemon descriptors");
    assert!(output.status.success(), "lsof failed: {output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut descriptors = Vec::<Option<String>>::new();
    let mut current: Option<usize> = None;
    for line in text.lines() {
        if let Some(field) = line.strip_prefix('f') {
            current = field
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
                .then(|| {
                    descriptors.push(None);
                    descriptors.len() - 1
                });
        } else if let (Some(index), Some(name)) = (current, line.strip_prefix('n')) {
            descriptors[index] = Some(name.to_string());
        }
    }
    let mut slave_ttys = descriptors
        .iter()
        .filter_map(|target| target.as_ref())
        .filter(|target| target.starts_with("/dev/ttys"))
        .cloned()
        .collect::<Vec<_>>();
    slave_ttys.sort();
    DaemonFdSnapshot {
        total: descriptors.len(),
        slave_ttys,
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

/// Linux and macOS have a native production sandbox launcher. Unsupported
/// targets retain the fail-closed path used by generic protocol tests.
fn native_sandbox_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        if cfg!(target_os = "linux") {
            #[cfg(target_os = "linux")]
            {
                return linux_process_domain_supported();
            }
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("guarded by cfg!(target_os = \"linux\")")
            }
        }
        cfg!(target_os = "macos")
    })
}

/// Every sandbox launch joins a mandatory per-sandbox cgroup (plan M4), so
/// a Linux host without a usable delegated cgroup v2 parent cannot run the
/// native-launch acceptance path. Probe with the engine's own discovery.
#[cfg(target_os = "linux")]
fn linux_process_domain_supported() -> bool {
    match shbox_sandbox::Sandbox::detect()
        .create_process_domain(shbox_sandbox::ResourceLimits::default(), None)
    {
        Ok(domain) => {
            let _ = domain.remove_empty();
            true
        }
        Err(error) => {
            eprintln!("skipping native sandbox acceptance: {error}");
            false
        }
    }
}

/// Blocking real-platform sandbox/PTTY acceptance is explicit. Platform gate
/// scripts set this variable so a missing capability cannot be mistaken for a
/// skipped success path.
fn sandbox_integration_enabled() -> bool {
    let enabled = std::env::var_os("SHBOX_RUN_SANDBOX_INTEGRATION").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    if enabled {
        assert!(
            native_sandbox_supported(),
            "SHBOX_RUN_SANDBOX_INTEGRATION=1 requires a supported native sandbox platform"
        );
    }
    enabled
}

/// Supported platforms execute the real sandbox path. Unsupported targets may
/// authenticate successfully but must fail the sandbox request generically.
fn sandbox_request_accepted(result: &SshResult, expected_stdout: &str) -> bool {
    if native_sandbox_supported() {
        result.ok() && result.stdout == expected_stdout
    } else {
        sandbox_request_failed_closed(result)
    }
}

/// OpenSSH may render a server-side channel failure instead of forwarding the
/// daemon's generic unavailable message. Both forms prove that no sandbox
/// process ran and that the request failed closed.
fn sandbox_request_failed_closed(result: &SshResult) -> bool {
    result.status == 255
        && result.stdout.is_empty()
        && (result.stderr.contains("request cannot be completed")
            || result.stderr.contains("exec request failed on channel"))
}

fn assert_sandbox_request_accepted(result: &SshResult, expected_stdout: &str, context: &str) {
    assert!(
        sandbox_request_accepted(result, expected_stdout),
        "{context}: {result:?}"
    );
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

/// A key present in both ~/.ssh/authorized_keys and allowed_keys is accepted
/// with the Admin role.
#[test]
fn key_present_in_both_files_receives_admin_role() {
    let daemon = TestDaemon::start(&["admin"]);
    let admin_pub = std::fs::read_to_string(&daemon.admin_key.public).expect("admin pub");
    let normal_pub = std::fs::read_to_string(&daemon.normal_key.public).expect("normal pub");
    daemon.set_allowed_keys(&format!("{normal_pub}\n{admin_pub}\n"));

    let result = retry_until("overlap admin key access", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf host-access", &["-T"]);
        (result.ok() && result.stdout == "host-access").then_some(result)
    });
    assert!(
        result.ok(),
        "overlap key did not authenticate as admin: {result:?}"
    );
    assert_eq!(result.stdout, "host-access");
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
/// explicitly with native production sandbox launcher and must then observe a real
/// successful launch.
#[test]
fn sandbox_requests_execute_or_fail_closed() {
    let daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.normal_key, "dev", "printf nope", &["-T"]);
    if native_sandbox_supported() {
        assert_eq!(result.status, 0, "real sandbox launch failed: {result:?}");
        assert_eq!(result.stdout, "nope");
    } else {
        assert!(
            sandbox_request_failed_closed(&result),
            "sandbox must fail closed: {result:?}"
        );
    }
}

/// The real OpenSSH subsystem reaches the manager for owner-filtered and
/// admin-wide list, then performs an idempotent delete.
#[test]
fn sandbox_list_and_delete_are_wired_to_the_manager() {
    if !native_sandbox_supported() {
        // The manager stays unavailable when startup cannot reconcile the
        // mandatory process-domain backend. The fail-closed launch path is
        // covered by sandbox_requests_execute_or_fail_closed; list/delete
        // acceptance requires the native backend below.
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);

    // The request exercises lazy first-owner claim on the real platform.
    let claim = daemon.ssh(&daemon.normal_key, "dev", "printf ignored", &["-T"]);
    assert!(claim.ok(), "real sandbox launch failed: {claim:?}");
    assert_eq!(claim.stdout, "ignored");

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

/// The real sandbox path keeps non-PTY stdout/stderr separate and forwards a
/// non-zero shell exit status through the OpenSSH client.
#[test]
fn sandbox_non_pty_exec_reports_streams_and_status() {
    if !sandbox_integration_enabled() {
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
fn sandbox_pty_applies_modes_and_resize() {
    if !sandbox_integration_enabled() {
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

/// The real OpenSSH PTY owns all three standard descriptors, creates a fresh
/// session, acquires the requested controlling terminal, and exposes the
/// foreground process group through the terminal itself.
#[test]
fn sandbox_pty_has_controlling_terminal_and_foreground_group() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let id = "m6-tty-identity";
    let claim = daemon.ssh(&daemon.normal_key, id, "printf claim", &["-T"]);
    assert!(claim.ok(), "create probe workspace: {claim:?}");
    let workspace = daemon.sandbox_workspace(id);
    let probe = build_tty_probe(&workspace);
    assert_eq!(probe, workspace.join("m6-tty-probe"));

    let daemon_sid =
        unsafe { libc::getsid(i32::try_from(daemon.child.id()).expect("daemon pid fits pid_t")) };
    assert!(daemon_sid > 0, "daemon session id must be observable");

    let mut session = daemon.spawn_ssh_pty(&daemon.normal_key, id, "./m6-tty-probe", 33, 109);
    let mut combined = session.read_until(b"__M6_TTY_PROBE__", Duration::from_secs(5));
    let tail = session.read_until(b"\n", Duration::from_secs(5));
    combined.extend_from_slice(&tail);
    let probe = parse_tty_probe(&combined);
    assert_eq!(probe.tty_bits, "111", "fd 0/1/2 must all be TTYs");
    assert_ne!(
        probe.sid,
        i64::from(daemon_sid),
        "sandbox reused daemon session"
    );
    assert_eq!(
        probe.sid, probe.terminal_sid,
        "controlling terminal session"
    );
    assert_eq!(
        probe.process_group, probe.foreground_group,
        "probe process group must own the terminal foreground"
    );
    assert!(session.wait_for_exit(Duration::from_secs(5)).success());
}

/// A genuine SSH shell request must support ordinary interactive job control,
/// not merely look interactive because stdout is attached to a PTY.
#[test]
fn sandbox_interactive_pty_supports_job_control_and_mode_restore() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start_with_config(&["admin"], "[sandbox]\nshell = \"/bin/bash\"\n");
    let mut session =
        daemon.spawn_ssh_interactive_pty(&daemon.normal_key, "m6-interactive", 29, 103);

    // Make the prompt deterministic, then prove command -> prompt exchange on
    // a shell request (no remote exec command was supplied to OpenSSH).
    session.send(b"PS1='__M6_'PROMPT'__ '\n");
    session.read_until(b"__M6_PROMPT__ ", Duration::from_secs(5));
    session.send(b"printf '__M6_%s__\\n' SHELL_READY\n");
    session.read_until(b"__M6_SHELL_READY__", Duration::from_secs(5));
    session.read_until(b"__M6_PROMPT__ ", Duration::from_secs(5));
    session.send(b"stty -a; printf '__M6_%s__\\n' STTY_END\n");
    let initial_modes = session.read_until(b"__M6_STTY_END__", Duration::from_secs(5));
    let initial_modes_text = String::from_utf8_lossy(&initial_modes).to_lowercase();
    assert!(
        initial_modes_text.contains("susp = ^z"),
        "remote PTY did not receive VSUSP=^Z: {initial_modes_text}"
    );

    // A foreground job receives terminal VINTR while the shell survives and
    // accepts the next command.
    session.send(b"sleep 30\n");
    std::thread::sleep(Duration::from_millis(200));
    session.send(&[0x03]);
    session.send(b"printf '__M6_%s__\\n' AFTER_INT\n");
    session.read_until(b"__M6_AFTER_INT__", Duration::from_secs(5));

    // VSUSP must stop the foreground job and return control to bash. `jobs`
    // then exposes the stopped job rather than losing it in the launcher.
    session.send(b"sleep 30\n");
    std::thread::sleep(Duration::from_millis(200));
    session.send(&[0x1a]);
    session.send(b"jobs; printf '__M6_%s__\\n' JOBS_END\n");
    let jobs = session.read_until(b"__M6_JOBS_END__", Duration::from_secs(5));
    let jobs_text = String::from_utf8_lossy(&jobs).to_lowercase();
    assert!(
        jobs_text.contains("sleep 30"),
        "stopped job missing: {jobs_text}"
    );
    assert!(
        jobs_text.contains("stopped") || jobs_text.contains("suspended"),
        "foreground job was not stopped: {jobs_text}"
    );

    // `bg` and `fg` must preserve the same job-control relationship. Resume in
    // background, verify it is running, return it to foreground, then interrupt.
    session.send(b"bg; jobs; printf '__M6_%s__\\n' BG_END\n");
    let background = session.read_until(b"__M6_BG_END__", Duration::from_secs(5));
    let background_text = String::from_utf8_lossy(&background).to_lowercase();
    assert!(
        background_text.contains("running"),
        "bg did not resume job: {background_text}"
    );
    session.send(b"fg\n");
    std::thread::sleep(Duration::from_millis(200));
    session.send(&[0x03]);
    session.send(b"printf '__M6_%s__\\n' AFTER_FG\n");
    session.read_until(b"__M6_AFTER_FG__", Duration::from_secs(5));

    // A nested foreground process group receives the terminal-generated INT;
    // the outer interactive shell remains alive afterward.
    session.send(
        b"/bin/sh -c 'trap \"printf \"__M6_%s__\" NESTED_INT; exit 31\" INT; printf \"__M6_%s__\" NESTED_READY; while :; do sleep 1; done'\n",
    );
    session.read_until(b"__M6_NESTED_READY__", Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(100));
    session.send(&[0x03]);
    session.read_until(b"__M6_NESTED_INT__", Duration::from_secs(5));
    session.send(b"printf '__M6_%s__\\n' OUTER_ALIVE\n");
    session.read_until(b"__M6_OUTER_ALIVE__", Duration::from_secs(5));

    // A small raw-mode fixture changes the remote terminal and restores the
    // exact termios encoding before returning to the shell.
    session.send(
        b"saved=$(stty -g); stty raw -echo; raw=$(stty -g); stty \"$saved\"; after=$(stty -g); if [ \"$saved\" = \"$after\" ] && [ \"$raw\" != \"$after\" ]; then printf '__M6_%s__\\n' RAW_RESTORED; else printf '__M6_%s__\\n' RAW_BAD; fi\n",
    );
    let raw = session.read_until(b"__M6_RAW_RESTORED__", Duration::from_secs(5));
    assert!(
        !String::from_utf8_lossy(&raw).contains("__M6_RAW_BAD__"),
        "raw mode was not restored"
    );

    session.send(b"jobs -p; printf '__M6_%s__\\n' FINAL_JOBS_END\n");
    let final_jobs = session.read_until(b"__M6_FINAL_JOBS_END__", Duration::from_secs(5));
    let final_jobs_text = String::from_utf8_lossy(&final_jobs);
    assert!(
        !final_jobs_text
            .lines()
            .any(|line| line.trim().parse::<u32>().is_ok()),
        "interactive shell retained a job: {final_jobs_text:?}"
    );
    session.read_until(b"__M6_PROMPT__ ", Duration::from_secs(5));
    session.send(b"printf '__M6_%s__\\n' EXITING; exit 0\n");
    session.read_until(b"__M6_EXITING__", Duration::from_secs(5));
    assert!(session.wait_for_exit(Duration::from_secs(5)).success());
}

/// The real launch maps HOME/PWD to the durable workspace, injects only the
/// configured sandbox environment, and keeps a client env request out.
#[test]
fn sandbox_maps_environment_and_workspace() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start_with_config(
        &["admin"],
        "[sandbox.env]\nM8_SANDBOX_TOKEN = \"configured-token\"\n",
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
fn sandbox_eof_behavior_is_transport_correct() {
    if !sandbox_integration_enabled() {
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
fn sandbox_pty_forwards_terminal_signal() {
    if !sandbox_integration_enabled() {
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
fn sandbox_shutdown_cleans_up_descendants() {
    if !sandbox_integration_enabled() {
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
        assert!(
            wait_for_pid_gone(pid, Duration::from_secs(10)),
            "{label} {pid} survived sandbox shutdown"
        );
    }
}

/// Killing the OpenSSH client closes the channel/connection. A published
/// sandbox launch must detach its transport without terminating a descendant
/// that deliberately left the PTY session. The cgroup remains authoritative:
/// an explicit delete below still removes that descendant.
#[test]
fn sandbox_pty_disconnect_preserves_detached_process_until_delete() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start_with_config(&["admin"], "[sandbox]\nshell = \"/bin/bash\"\n");
    let id = "m6-disconnect";
    let pid_path = daemon.sandbox_workspace(id).join("m6-disconnect.pid");
    let mut session = daemon.spawn_ssh_pty(
        &daemon.normal_key,
        id,
        r#"setsid sh -c 'printf "%s" "$$" > "$HOME/m6-disconnect.pid"; trap "" HUP; while :; do sleep 1; done' & until test -s "$HOME/m6-disconnect.pid"; do sleep 0.01; done; printf __M6_DISCONNECT_READY__; while :; do sleep 1; done"#,
        24,
        80,
    );
    session.read_until(b"__M6_DISCONNECT_READY__", Duration::from_secs(5));
    let pid = retry_until("sandbox PTY pid file", || {
        std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|value| value.trim().parse::<libc::pid_t>().ok())
    });
    session.kill_client();
    retry_until("detached sandbox process survives transport loss", || {
        (!pid_is_terminated(pid)).then_some(())
    });

    let delete = daemon.ssh(&daemon.normal_key, id, "delete", &["-T", "-s"]);
    assert!(delete.ok(), "sandbox delete failed: {delete:?}");
    if !wait_for_pid_gone(pid, Duration::from_secs(12)) {
        let ps = Command::new("ps")
            .args([
                "-o",
                "pid,ppid,pgid,sid,state,etime,command",
                "-p",
                &pid.to_string(),
            ])
            .output()
            .expect("ps remote shell");
        panic!(
            "sandbox detached process {pid} survived sandbox delete: {}",
            String::from_utf8_lossy(&ps.stdout)
        );
    }
}

/// M12: the real mise-provided tssh client must complete ordinary TCP SSH
/// compatibility against the sandbox listener.
#[test]
fn tssh_tcp_compatibility_runs_inside_the_sandbox_process_domain() {
    if Command::new("tssh").arg("--version").output().is_err() {
        eprintln!("skipping tssh acceptance: tssh is unavailable");
        return;
    }
    if !sandbox_integration_enabled() {
        return;
    }

    let mut daemon = TestDaemon::start_with_config(
        &["admin"],
        "[sandbox]\nnetwork = \"outbound\"\nread_paths = [\"/proc\"]\n",
    );
    let tssh = Command::new("timeout")
        .args(["20s", "tssh"])
        .args(["-F", daemon.ssh_config.to_str().expect("ssh config path")])
        .args(["-i", daemon.normal_key.private.to_str().expect("key path")])
        .args(["-p", &daemon.port.to_string(), "-4", "--tcp"])
        .arg("m12-tssh@127.0.0.1")
        .arg("printf __M12_TSSH_BEGIN__; cat /proc/self/cgroup; printf __M12_TSSH_END__")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("timeout/tssh starts");
    let output = tssh.wait_with_output().expect("timeout/tssh waits");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let daemon_stderr = daemon.stop_and_collect_stderr();
    assert!(
        output.status.success(),
        "tssh TCP acceptance failed: status={:?}, stdout={stdout:?}, stderr={stderr:?}, daemon_stderr={daemon_stderr:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("__M12_TSSH_BEGIN__") && stdout.contains("__M12_TSSH_END__"),
        "tssh did not return the remote command output: stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(
        stdout.contains("shbox-domain-"),
        "tssh session escaped the durable sandbox process domain: stdout={stdout:?}"
    );
}

/// M12 external acceptance: the real tssh client can replace the bootstrap
/// SSH transport with tsshd's UDP transport when the host permits loopback
/// UDP delivery. This host binds tsshd successfully but returns ECONNREFUSED
/// before any authentication packet reaches it, so keep this probe available
/// for explicitly provisioned UDP-capable environments without making the
/// default workspace test suite depend on that external condition.
#[test]
#[ignore = "requires host loopback UDP delivery to the tsshd child"]
fn tssh_udp_bootstrap_runs_inside_the_sandbox_process_domain() {
    if Command::new("tssh").arg("--version").output().is_err() {
        eprintln!("skipping tssh acceptance: tssh is unavailable");
        return;
    }
    if !sandbox_integration_enabled() {
        return;
    }

    let mut daemon = TestDaemon::start_with_config(
        &["admin"],
        "[sandbox]\nnetwork = \"outbound\"\nread_paths = [\"/proc\"]\n",
    );
    let tssh = Command::new("timeout")
        .args(["20s", "tssh"])
        .args(["-F", daemon.ssh_config.to_str().expect("ssh config path")])
        .args(["-i", daemon.normal_key.private.to_str().expect("key path")])
        .args(["-p", &daemon.port.to_string(), "-4", "--udp"])
        .args(["--tsshd-path", "/usr/bin/tsshd"])
        .arg("--debug")
        .arg("m12-tssh@127.0.0.1")
        .arg("printf __M12_TSSH_BEGIN__; cat /proc/self/cgroup; printf __M12_TSSH_END__")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("timeout/tssh starts");
    let output = tssh.wait_with_output().expect("timeout/tssh waits");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let daemon_stderr = daemon.stop_and_collect_stderr();
    assert!(
        output.status.success(),
        "tssh UDP acceptance failed: status={:?}, stdout={stdout:?}, stderr={stderr:?}, daemon_stderr={daemon_stderr:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("__M12_TSSH_BEGIN__") && stdout.contains("__M12_TSSH_END__"),
        "tssh did not return the remote command output: stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(
        stdout.contains("shbox-domain-"),
        "tssh session escaped the durable sandbox process domain: stdout={stdout:?}"
    );
}

/// PTY allocation must not leak the slave into the daemon, and repeated real
/// OpenSSH PTY sessions must return the daemon descriptor table to baseline.
#[test]
fn repeated_sandbox_ptys_do_not_leak_slave_or_daemon_fds() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start(&["admin"]);
    let warmup = daemon.ssh(&daemon.normal_key, "m6-fd", "printf warm", &["-tt"]);
    assert!(warmup.ok(), "PTY warmup failed: {warmup:?}");
    let baseline = daemon_fd_snapshot(daemon.child.id());
    assert!(
        baseline.slave_ttys.is_empty(),
        "daemon baseline unexpectedly owns PTY slaves: {baseline:?}"
    );

    let mut live = daemon.spawn_ssh_pty(
        &daemon.normal_key,
        "m6-fd",
        "printf __M6_FD_READY__; sleep 30",
        24,
        80,
    );
    live.read_until(b"__M6_FD_READY__", Duration::from_secs(5));
    let during = daemon_fd_snapshot(daemon.child.id());
    assert!(
        during.slave_ttys.is_empty(),
        "daemon retained a PTY slave after launch: {during:?}"
    );
    live.kill_client();

    for index in 0..16 {
        let result = daemon.ssh(
            &daemon.normal_key,
            "m6-fd",
            &format!("printf pty-{index}"),
            &["-tt"],
        );
        assert!(result.ok(), "PTY iteration {index} failed: {result:?}");
    }

    let settled = retry_until("daemon PTY fd table returned to baseline", || {
        let snapshot = daemon_fd_snapshot(daemon.child.id());
        (snapshot.total <= baseline.total && snapshot.slave_ttys == baseline.slave_ttys)
            .then_some(snapshot)
    });
    assert!(
        settled.total <= baseline.total,
        "daemon fd count grew: baseline={baseline:?} settled={settled:?}"
    );
}

/// Concurrent PTY channels must own distinct terminals. A resize and terminal
/// signal applied to one session must neither resize nor terminate the other.
#[test]
fn concurrent_sandbox_ptys_isolate_terminal_state_and_signals() {
    if !sandbox_integration_enabled() {
        return;
    }

    let daemon = TestDaemon::start_with_config(&["admin"], "[sandbox]\nshell = \"/bin/bash\"\n");
    for id in ["m6-concurrent-a", "m6-concurrent-b"] {
        let claim = daemon.ssh(&daemon.normal_key, id, "printf claim", &["-T"]);
        assert!(claim.ok(), "create concurrent probe workspace: {claim:?}");
        build_tty_probe(&daemon.sandbox_workspace(id));
    }
    let command_a = r#"./m6-tty-probe; exec /bin/sh -c 'trap "printf __M6_A_WINCH__" WINCH; trap "printf __M6_A_INT__; exit 41" INT; printf __M6_A_READY__; while :; do if IFS= read -r line; then case "$line" in size) printf __M6_A_SIZE__; stty size; printf __M6_A_SIZE_END__;; alive) printf __M6_A_ALIVE__;; esac; fi; done'"#;
    let command_b = r#"./m6-tty-probe; exec /bin/sh -c 'trap "printf __M6_B_WINCH__" WINCH; trap "printf __M6_B_INT__; exit 42" INT; printf __M6_B_READY__; while :; do if IFS= read -r line; then case "$line" in size) printf __M6_B_SIZE__; stty size; printf __M6_B_SIZE_END__;; alive) printf __M6_B_ALIVE__;; esac; fi; done'"#;
    let mut first = daemon.spawn_ssh_pty(&daemon.normal_key, "m6-concurrent-a", command_a, 24, 80);
    let mut second = daemon.spawn_ssh_pty(&daemon.normal_key, "m6-concurrent-b", command_b, 24, 80);
    let first_ready = first.read_until(b"__M6_A_READY__", Duration::from_secs(5));
    let second_ready = second.read_until(b"__M6_B_READY__", Duration::from_secs(5));
    let first_probe = parse_tty_probe(&first_ready);
    let second_probe = parse_tty_probe(&second_ready);
    assert_eq!(first_probe.tty_bits, "111");
    assert_eq!(second_probe.tty_bits, "111");
    assert_ne!(
        first_probe.tty_device, second_probe.tty_device,
        "concurrent sessions shared a controlling TTY device"
    );
    assert_ne!(
        first_probe.sid, second_probe.sid,
        "concurrent sessions shared a SID"
    );

    first.resize(37, 111);
    first.read_until(b"__M6_A_WINCH__", Duration::from_secs(5));
    second.send(b"size\n");
    let second_size = second.read_until(b"__M6_B_SIZE_END__", Duration::from_secs(5));
    let second_size = String::from_utf8_lossy(between_markers(
        &second_size,
        b"__M6_B_SIZE__",
        b"__M6_B_SIZE_END__",
    ));
    assert!(
        second_size.contains("24 80"),
        "first session resize leaked into second: {second_size:?}"
    );

    first.send(&[0x03]);
    first.read_until(b"__M6_A_INT__", Duration::from_secs(5));
    assert_eq!(
        first.wait_for_exit(Duration::from_secs(5)).code(),
        Some(41),
        "first terminal signal did not reach its process group"
    );
    assert!(
        second.is_running(),
        "first terminal signal killed second SSH session"
    );
    second.send(b"alive\n");
    second.read_until(b"__M6_B_ALIVE__", Duration::from_secs(5));
    second.kill_client();
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

/// A key added to a key file is accepted by the very next authentication
/// request, with no signal of any kind.
#[test]
fn key_file_change_applies_on_the_next_auth_without_a_signal() {
    let daemon = TestDaemon::start(&["admin"]);
    let extra_home = ssh_tempdir();
    let added = generated_key(extra_home.path(), "added");

    // Before the file change the minted key is unknown.
    let before = daemon.ssh(&added, "dev", "printf added", &["-T"]);
    assert!(!before.ok(), "unknown key must be refused: {before:?}");

    // Append it to allowed_keys. No signal is sent from here on.
    let normal_pub = std::fs::read_to_string(&daemon.normal_key.public).expect("normal pub");
    let added_pub = std::fs::read_to_string(&added.public).expect("added pub");
    daemon.set_allowed_keys(&format!("{normal_pub}\n{added_pub}\n"));

    let after = retry_until("added key accepted without a signal", || {
        let result = daemon.ssh(&added, "dev", "printf added", &["-T"]);
        sandbox_request_accepted(&result, "added").then_some(result)
    });
    assert_sandbox_request_accepted(&after, "added", "added key authentication");

    // The same applies to the host source: writing the added key into
    // authorized_keys promotes it to Admin on the next request, no signal.
    daemon.set_host_keys(&format!("{added_pub}\n"));
    let promoted = retry_until("added key promoted to admin without a signal", || {
        let result = daemon.ssh(&added, "_", "printf promoted", &["-T"]);
        (result.ok() && result.stdout == "promoted").then_some(result)
    });
    assert_eq!(promoted.stdout, "promoted");

    // Replacing the host file also revokes the previous admin key on the
    // next request, with no signal.
    let admin = daemon.ssh(&daemon.admin_key, "_", "printf host-ok", &["-T"]);
    assert!(
        !admin.ok(),
        "replacing the host file must revoke the previous admin key: {admin:?}"
    );
}

/// A key removed from its file is refused by the next authentication request
/// while an already authenticated connection keeps its fixed principal.
#[test]
fn removed_key_is_rejected_on_the_next_auth() {
    let daemon = TestDaemon::start(&["admin"]);
    let first = daemon.ssh(&daemon.normal_key, "dev", "printf before", &["-T"]);
    assert_sandbox_request_accepted(&first, "before", "normal key before removal");

    let control_path = std::env::temp_dir().join(format!("shbox-keyrm-{}", std::process::id()));
    let _ = std::fs::remove_file(&control_path);
    let master = daemon.ssh_with_control(
        &daemon.admin_key,
        "_",
        "printf existing-before",
        &control_path,
        "yes",
    );
    assert!(master.status.success(), "control master failed: {master:?}");
    assert_eq!(master.stdout, b"existing-before");
    let _ = retry_until("ControlMaster readiness", || {
        let check = daemon.control_operation(&daemon.admin_key, "_", &control_path, "check");
        check.status.success().then_some(check)
    });

    // Empty allowed_keys removes the normal key; no signal is sent.
    daemon.set_allowed_keys("");
    let denied = retry_until("normal key denied after file removal", || {
        let result = daemon.ssh(&daemon.normal_key, "dev", "printf should-not-run", &["-T"]);
        (result.status == 255 && result.stderr.contains("Permission denied")).then_some(result)
    });
    assert!(
        !denied.ok(),
        "removed key must lose access on the next auth: {denied:?}"
    );

    // The existing admin connection keeps the principal it authenticated with.
    let existing = retry_until("existing admin connection after key removal", || {
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
    let _ = daemon.control_operation(&daemon.admin_key, "_", &control_path, "exit");
    let _ = std::fs::remove_file(control_path);

    // Writing the key back applies again on the next attempt.
    let normal_pub = std::fs::read_to_string(&daemon.normal_key.public).expect("normal pub");
    daemon.set_allowed_keys(&format!("{normal_pub}\n"));
    let restored = retry_until("normal key restored after rewrite", || {
        let result = daemon.ssh(&daemon.normal_key, "dev", "printf restored", &["-T"]);
        sandbox_request_accepted(&result, "restored").then_some(result)
    });
    assert_sandbox_request_accepted(&restored, "restored", "restored key authentication");
}

/// A malformed key file is parsed once, rejected, and logged; the previous
/// snapshot keeps serving until the file is fixed, and fixing it applies on
/// the next attempt.
#[test]
fn malformed_key_file_keeps_previous_snapshot_and_recovers() {
    let mut daemon = TestDaemon::start(&["admin"]);
    daemon.set_allowed_keys("not-a-valid-ssh-ed25519-key\n");

    // The rejected refresh keeps the previous snapshot live.
    let stale = daemon.ssh(&daemon.normal_key, "dev", "printf old-auth", &["-T"]);
    assert_sandbox_request_accepted(&stale, "old-auth", "previous snapshot");
    // A stable broken file costs one rejected parse, not one per request.
    let again = daemon.ssh(&daemon.normal_key, "dev", "printf old-auth", &["-T"]);
    assert_sandbox_request_accepted(&again, "old-auth", "previous snapshot retry");

    let normal_pub = std::fs::read_to_string(&daemon.normal_key.public).expect("normal pub");
    daemon.set_allowed_keys(&format!("{normal_pub}\n"));
    let recovered = retry_until("malformed allowed_keys recovered", || {
        let result = daemon.ssh(&daemon.normal_key, "dev", "printf new-auth", &["-T"]);
        sandbox_request_accepted(&result, "new-auth").then_some(result)
    });
    assert_sandbox_request_accepted(&recovered, "new-auth", "recovered key authentication");

    // Across the whole run the broken state was parsed and logged once.
    let stderr = daemon.stop_and_collect_stderr();
    assert!(
        stderr.contains("key source refresh rejected"),
        "rejected refresh must be logged: {stderr}"
    );
    assert_eq!(
        stderr.matches("key source refresh rejected").count(),
        1,
        "a stable broken file must be parsed once: {stderr}"
    );
}

/// SIGHUP forces a revalidation even when both stat identities are unchanged:
/// an ancestor-directory permission drift, invisible to the per-request
/// identity check, is caught by the forced re-read and logged while the
/// previous snapshot keeps serving.
#[test]
fn sighup_forces_revalidation_of_unchanged_identities() {
    use std::os::unix::fs::PermissionsExt;
    let mut daemon = TestDaemon::start(&["admin"]);
    let ssh_dir = daemon
        .host_authorized_keys
        .parent()
        .expect("ssh dir")
        .to_path_buf();

    // Make the ancestor unsafe without touching either key file.
    std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o770))
        .expect("chmod ssh dir");
    let stale = daemon.ssh(&daemon.admin_key, "_", "printf previous-snapshot", &["-T"]);
    assert!(
        stale.ok(),
        "unchanged identities must keep serving: {stale:?}"
    );

    daemon.sighup();
    // The forced revalidation rejects the unsafe ancestor and keeps the
    // previous snapshot serving.
    let after = daemon.ssh(&daemon.admin_key, "_", "printf forced", &["-T"]);
    assert!(after.ok(), "rejected refresh must keep serving: {after:?}");

    // Restoring the mode applies on the next forced revalidation.
    std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore ssh dir");
    daemon.sighup();
    let restored = retry_until("clean revalidation after mode restore", || {
        let result = daemon.ssh(&daemon.admin_key, "_", "printf restored", &["-T"]);
        (result.ok() && result.stdout == "restored").then_some(result)
    });
    assert_eq!(restored.stdout, "restored");

    // The forced re-read is observable in the log: it rejected the unsafe
    // ancestor before the mode was restored.
    let stderr = daemon.stop_and_collect_stderr();
    assert!(
        stderr.contains("parent is group or world writable"),
        "forced revalidation must report the unsafe ancestor: {stderr}"
    );
}

/// The config file is restart-only: neither SIGHUP nor an authentication
/// request re-reads it, so edits — invalid or valid — stay inert until a
/// restart.
#[test]
fn config_toml_edit_is_ignored_until_restart() {
    let mut daemon = TestDaemon::start(&["admin"]);
    // A broken config file is never re-read: SIGHUP and the next auth both
    // keep working, and nothing reports a reload failure.
    daemon.set_config("admin_keys = [\n");
    daemon.sighup();
    let result = daemon.ssh(&daemon.admin_key, "_", "printf alive", &["-T"]);
    assert!(
        result.ok(),
        "auth broke after invalid config edit: {result:?}"
    );

    // A valid but different document is equally inert: its sandbox network
    // mode and env never reach a launched process without a restart.
    daemon.set_config(
        "[sandbox]\nnetwork = \"outbound\"\n\n[sandbox.env]\nSHBOX_CONFIG_EDIT = \"applied\"\n",
    );
    daemon.sighup();
    let env_probe = daemon.ssh(
        &daemon.normal_key,
        "dev",
        "printf env=${SHBOX_CONFIG_EDIT-unset}",
        &["-T"],
    );
    assert_sandbox_request_accepted(
        &env_probe,
        "env=unset",
        "config edit must not alter sandbox authentication",
    );

    let stderr = daemon.stop_and_collect_stderr();
    assert!(
        !stderr.contains("reloaded"),
        "nothing may log a reload: {stderr}"
    );
    assert!(
        !stderr.contains("sandbox.network"),
        "no reload may re-evaluate the network mode: {stderr}"
    );
}

/// The daemon exits cleanly on SIGTERM.
#[test]
fn daemon_shuts_down_on_sigterm() {
    let mut daemon = TestDaemon::start(&["admin"]);
    let result = daemon.ssh(&daemon.admin_key, "_", "printf alive", &["-T"]);
    assert!(result.ok(), "{result:?}");
    daemon.send_signal(libc::SIGTERM);
    let status = daemon.child.wait().expect("wait");
    let daemon_stderr = daemon.read_stderr();
    assert!(status.success(), "graceful exit expected, got {status}");
    assert!(
        !daemon_stderr.contains("JoinHandle polled after completion"),
        "daemon polled a completed Tokio task during shutdown:\n{daemon_stderr}"
    );
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
    let daemon_stderr = daemon.read_stderr();
    assert!(
        daemon_status.success(),
        "graceful exit expected: {daemon_status}"
    );
    assert!(
        !daemon_stderr.contains("JoinHandle polled after completion"),
        "daemon polled a completed Tokio task during shutdown:\n{daemon_stderr}"
    );
    let client_status = client.join().expect("ssh client join");
    assert!(
        !client_status.status.success(),
        "shutdown must close ssh client"
    );

    for (label, pid) in [("host process", host_pid), ("descendant", descendant_pid)] {
        assert!(
            wait_for_pid_gone(pid, Duration::from_secs(7)),
            "{label} {pid} survived shutdown"
        );
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

    assert!(
        wait_for_pid_gone(host_pid, Duration::from_secs(3)),
        "host process {host_pid} survived second shutdown signal"
    );
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

    assert!(
        wait_for_pid_gone(child_pid, Duration::from_secs(3)),
        "host process {child_pid} survived daemon crash"
    );
    let _ = std::fs::remove_file(pid_path);
}

/// SSH `signal` requests reach the managed process group and never take the
/// channel or connection down by themselves (docs/ssh-protocol.md §13). The
/// OpenSSH CLI cannot issue a `signal` request, so this drives the daemon
/// with the same russh protocol stack the server uses.
#[tokio::test]
async fn ssh_signal_requests_forward_and_keep_the_channel_alive() {
    use std::sync::Arc as StdArc;

    use russh::client::{self, Handle};
    use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key};
    use russh::{ChannelMsg, Disconnect, Sig};

    struct TrustAll;
    impl client::Handler for TrustAll {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    let daemon = TestDaemon::start(&["admin"]);
    let secret =
        StdArc::new(load_secret_key(&daemon.admin_key.private, None).expect("load admin key"));
    let config = StdArc::new(client::Config::default());
    let mut handle: Handle<TrustAll> = client::connect(
        config,
        (std::net::IpAddr::from([127, 0, 0, 1]), daemon.port),
        TrustAll,
    )
    .await
    .expect("russh client connect");
    let auth = handle
        .authenticate_publickey(
            "_",
            PrivateKeyWithHashAlg::new(StdArc::clone(&secret), None),
        )
        .await
        .expect("auth round trip");
    assert!(
        matches!(auth, russh::client::AuthResult::Success),
        "admin key must authenticate: {auth:?}"
    );

    let mut channel = handle.channel_open_session().await.expect("open session");
    channel.exec(true, "sleep 30").await.expect("exec sent");
    match channel.wait().await.expect("exec reply") {
        ChannelMsg::Success => {}
        other => panic!("exec was not acknowledged: {other:?}"),
    }

    // An unrecognized signal name is refused without touching the channel,
    // and a known signal reaches the process group: `sleep` dies by SIGINT
    // and the bridge reports exit-signal INT followed by an orderly close.
    channel
        .signal(Sig::Custom("NOSUCH".to_string()))
        .await
        .expect("unknown signal sent");
    channel.signal(Sig::INT).await.expect("signal sent");
    let mut saw_exit_signal = false;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(10), channel.wait())
            .await
            .expect("channel completion timeout")
            .expect("channel message");
        match message {
            ChannelMsg::ExitSignal { signal_name, .. } => {
                assert_eq!(
                    format!("{signal_name:?}"),
                    "INT",
                    "sleep must die by SIGINT"
                );
                saw_exit_signal = true;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                panic!("signaled death must not report exit-status {exit_status}");
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    assert!(saw_exit_signal, "exit-signal INT must precede close");

    // The connection itself is unaffected: a fresh channel still runs.
    let mut followup = handle.channel_open_session().await.expect("second session");
    followup
        .exec(false, "printf alive")
        .await
        .expect("second exec sent");
    followup.eof().await.expect("client eof");
    let mut saw_output = false;
    while let Ok(Some(message)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), followup.wait()).await
    {
        match message {
            ChannelMsg::Data { data } if data.as_ref() == b"alive" => saw_output = true,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    assert!(saw_output, "second channel must run after signal teardown");

    let _ = handle
        .disconnect(Disconnect::ByApplication, "done", "en")
        .await;
}
