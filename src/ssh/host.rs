//! Host-mode process handling for the admin `_` selector.
//!
//! Host processes are not sandboxed: they run as the daemon uid/gid with the
//! daemon account's login shell, its home as the working directory, and the
//! full daemon service environment inherited (`HOME` included). Interactive
//! shells run in login mode (`argv[0] = "-<basename>"`); remote commands run
//! the same shell with `-c` and are not login shells.

use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use tokio::io::AsyncWriteExt;

/// A `pty-req` captured before the operation starts.
#[derive(Debug, Clone)]
pub struct PtyRequest {
    pub term: String,
    pub rows: u32,
    pub cols: u32,
}

/// Fallback terminal size when the client sends a zero dimension.
const DEFAULT_ROWS: u32 = 24;
const DEFAULT_COLS: u32 = 80;

fn dimension_or_default(value: u32) -> libc::c_ushort {
    let value = if value == 0 { DEFAULT_COLS } else { value };
    value.clamp(1, u16::MAX as u32) as libc::c_ushort
}

impl PtyRequest {
    /// Initial window size with the RFC 4254 zero-dimension rule: a zero
    /// dimension falls back to the 24x80 default instead of a 0x0 terminal.
    pub fn window_size(&self) -> libc::winsize {
        libc::winsize {
            ws_row: if self.rows == 0 {
                DEFAULT_ROWS as libc::c_ushort
            } else {
                dimension_or_default(self.rows)
            },
            ws_col: dimension_or_default(self.cols),
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

/// Everything needed to start one host-mode process.
#[derive(Debug, Clone)]
pub struct HostRequest {
    pub shell: PathBuf,
    pub home: PathBuf,
    /// Raw remote command bytes; `None` starts an interactive login shell.
    pub command: Option<Vec<u8>>,
    pub pty: Option<PtyRequest>,
}

/// The parent-side ends of a running host process. The child itself lives in
/// the [`HostWaiter`], so the bridge can keep writing input while the waiter
/// blocks on the exit status.
pub struct HostProcess {
    pid: libc::pid_t,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    /// PTY master: one duplicate for reading (handed to the output pump),
    /// one for writing (dropped on client EOF).
    master_read: Option<tokio::io::unix::AsyncFd<std::fs::File>>,
    master_write: Option<tokio::io::unix::AsyncFd<std::fs::File>>,
    /// Last desired PTY size. This remains available after the read end is
    /// handed to the output pump, so window-change can still issue ioctl on
    /// the write duplicate.
    pty_size: Option<libc::winsize>,
}

/// Owns the child and reports its exit exactly once.
pub struct HostWaiter {
    task: tokio::task::JoinHandle<Result<Exit, io::Error>>,
}

impl HostWaiter {
    /// Await the child exit off the async runtime's hot path.
    pub async fn exit(self) -> Result<Exit, io::Error> {
        self.task
            .await
            .unwrap_or_else(|err| Err(io::Error::other(err)))
    }
}

/// A process exit as observed by the waiter.
#[derive(Debug, Clone, Copy)]
pub enum Exit {
    Code(i32),
    Signal { number: i32, core_dumped: bool },
}

impl HostProcess {
    /// Start the host process described by `request`.
    pub fn spawn(request: &HostRequest) -> Result<(HostProcess, HostWaiter), SpawnError> {
        let mut command = tokio::process::Command::new(&request.shell);
        match &request.command {
            Some(bytes) => {
                // Remote command: the raw byte string is passed verbatim as
                // the single `-c` argument; this is not a login shell.
                let text = command_bytes(bytes)?;
                command.arg("-c").arg(text);
            }
            None => {
                // Interactive shell: login mode via a leading `-` on argv[0].
                let name = request
                    .shell
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "sh".to_string());
                command.arg0(format!("-{name}"));
            }
        }
        command.current_dir(&request.home);
        // A requested PTY also fixes the child's TERM; client environment is
        // otherwise never forwarded. An empty TERM is a valid request value
        // and is still intentionally explicit.
        if let Some(pty) = &request.pty {
            command.env("TERM", &pty.term);
        }
        // Host mode intentionally inherits the whole daemon service
        // environment, `HOME` included; shbox does not filter it here.
        if request.pty.is_none() {
            // Without a PTY the cleanup path targets a dedicated process
            // group. The PTY path must not call setpgid first: setsid in the
            // child would then fail with EPERM for a process-group leader.
            command.process_group(0);
        }
        // Keep the child kill-on-drop until it is owned by the waiter. This
        // also covers the narrow error window after fork but before the PTY
        // AsyncFd wrappers have been fully constructed.
        command.kill_on_drop(true);

        let mut pty_master: Option<std::fs::File> = None;
        let mut child = match &request.pty {
            None => {
                command
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                command.spawn().map_err(SpawnError::Exec)?
            }
            Some(pty) => {
                let size = pty.window_size();
                let pty_pair = nix::pty::openpty(Some(&size), None)
                    .map_err(|err| SpawnError::Pty(io::Error::other(err.to_string())))?;
                let slave: std::fs::File = pty_pair.slave.into();
                let slave_in = slave.try_clone().map_err(SpawnError::Pty)?;
                let slave_out = slave.try_clone().map_err(SpawnError::Pty)?;
                command
                    .stdin(std::process::Stdio::from(slave_in))
                    .stdout(std::process::Stdio::from(slave_out))
                    .stderr(std::process::Stdio::from(slave));
                // SAFETY: pre_exec callbacks run between fork and exec in the
                // child; setsid detaches the child from our session and the
                // ioctl makes the already-dup2'ed slave (fd 0) its controlling
                // terminal. An error here aborts the spawn before exec.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::ioctl(0, TIOCSCTTY, 0) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                pty_master = Some(pty_pair.master.into());
                command.spawn().map_err(SpawnError::Exec)?
            }
        };

        let pid = child.id().unwrap_or(0) as libc::pid_t;
        let (master_read, master_write) = match pty_master {
            Some(master) => {
                let write_dup = master.try_clone().map_err(SpawnError::Pty)?;
                set_nonblocking(&master).map_err(SpawnError::Pty)?;
                set_nonblocking(&write_dup).map_err(SpawnError::Pty)?;
                let read = tokio::io::unix::AsyncFd::new(master).map_err(SpawnError::Pty)?;
                let write = tokio::io::unix::AsyncFd::new(write_dup).map_err(SpawnError::Pty)?;
                (Some(read), Some(write))
            }
            None => (None, None),
        };
        if pid == 0 {
            return Err(SpawnError::Exec(io::Error::other(
                "child exited before it could be tracked",
            )));
        }
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let process = HostProcess {
            pid,
            stdin,
            stdout,
            stderr,
            master_read,
            master_write,
            pty_size: request.pty.as_ref().map(PtyRequest::window_size),
        };
        // The waiter task owns the child from here on; the parent interacts
        // with the process group by pid only.
        let task = tokio::task::spawn(async move {
            use std::os::unix::process::ExitStatusExt;
            let mut child = child;
            let status = child.wait().await?;
            if let Some(number) = status.signal() {
                Ok(Exit::Signal {
                    number,
                    core_dumped: status.core_dumped(),
                })
            } else {
                Ok(Exit::Code(status.code().unwrap_or(255)))
            }
        });
        Ok((process, HostWaiter { task }))
    }

    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.stderr.take()
    }

    /// Hand the PTY master read end to the output pump.
    pub fn take_master_read(&mut self) -> Option<tokio::io::unix::AsyncFd<std::fs::File>> {
        self.master_read.take()
    }

    /// Write client bytes to the process input.
    pub async fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(master) = self.master_write.as_mut() {
            write_all_fd(master, data).await
        } else if let Some(stdin) = self.stdin.as_mut() {
            stdin.write_all(data).await
        } else {
            // The write end is already closed after client EOF; no new input
            // is forwarded past EOF.
            Ok(())
        }
    }

    /// Client EOF: a non-PTY child observes stdin EOF; for a PTY only the
    /// write duplicate is closed, and the child is never forced to observe
    /// EOF or a synthetic `VEOF`.
    pub fn client_eof(&mut self) {
        self.stdin = None;
        self.master_write = None;
    }

    /// Resize the PTY window; a zero dimension leaves that dimension alone.
    pub fn resize(&mut self, rows: u32, cols: u32) {
        let Some(size) = self.pty_size.as_mut() else {
            return;
        };
        if rows != 0 {
            size.ws_row = rows.clamp(1, u16::MAX as u32) as libc::c_ushort;
        }
        if cols != 0 {
            size.ws_col = cols.clamp(1, u16::MAX as u32) as libc::c_ushort;
        }
        if rows == 0 && cols == 0 {
            return;
        }
        let Some(master) = self.master_write.as_ref() else {
            return;
        };
        // SAFETY: TIOCSWINSZ with a valid winsize pointer on an owned fd.
        unsafe {
            libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, size);
        }
    }

    /// Send a signal to the whole process group.
    pub fn signal_group(&self, signal: i32) -> bool {
        if self.pid <= 0 {
            return false;
        }
        // SAFETY: kill(2) with the negative pid targets the process group.
        unsafe { libc::kill(-self.pid, signal) == 0 }
    }
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        // If the owner drops the process without an orderly teardown, make
        // sure the process group does not outlive shbox silently.
        self.signal_group(libc::SIGTERM);
    }
}

/// Maximum exec command payload accepted from the wire.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024;

/// Validate and convert raw command bytes to the `-c` argument.
fn command_bytes(bytes: &[u8]) -> Result<std::ffi::OsString, SpawnError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(SpawnError::CommandTooLarge(bytes.len()));
    }
    if bytes.contains(&0) {
        return Err(SpawnError::CommandContainsNul);
    }
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::OsStr::from_bytes(bytes).to_os_string())
}

/// Set O_NONBLOCK before wrapping a PTY master in `AsyncFd`. `AsyncFd` relies
/// on readiness notifications; a blocking descriptor can stall the runtime
/// despite the surrounding async API.
fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: fcntl is called with an owned, valid descriptor and the flags
    // returned by F_GETFL are passed back with only O_NONBLOCK added.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// TIOCSCTTY is not exported by the libc crate on Linux.
#[cfg(target_os = "linux")]
const TIOCSCTTY: libc::c_ulong = 0x540E;
#[cfg(target_os = "macos")]
const TIOCSCTTY: libc::c_ulong = 0x20007461;

/// Write the whole buffer to an `AsyncFd`-wrapped file.
pub async fn write_all_fd(
    fd: &mut tokio::io::unix::AsyncFd<std::fs::File>,
    mut data: &[u8],
) -> io::Result<()> {
    while !data.is_empty() {
        let mut guard = fd.writable().await?;
        let written = match guard.try_io(|inner| {
            // SAFETY: plain write(2) on an owned fd.
            let result =
                unsafe { libc::write(inner.as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }) {
            Ok(result) => result?,
            Err(_would_block) => continue,
        };
        if written == 0 {
            return Err(io::Error::other("pty master write returned 0"));
        }
        data = &data[written..];
    }
    Ok(())
}

/// Read once from an `AsyncFd`-wrapped file into `buffer`, awaiting
/// readability first. Returns `Ok(0)` at end of stream.
pub async fn read_some_fd(
    fd: &mut tokio::io::unix::AsyncFd<std::fs::File>,
    buffer: &mut [u8],
) -> io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| {
            // SAFETY: plain read(2) on an owned fd with a valid buffer.
            let result =
                unsafe { libc::read(inner.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Spawn failures; the caller cleans up any partially started process.
#[derive(Debug)]
pub enum SpawnError {
    Exec(io::Error),
    Pty(io::Error),
    CommandTooLarge(usize),
    CommandContainsNul,
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Exec(source) => write!(f, "cannot start host process: {source}"),
            SpawnError::Pty(source) => write!(f, "pty allocation failed: {source}"),
            SpawnError::CommandTooLarge(size) => {
                write!(
                    f,
                    "command payload of {size} bytes exceeds the 32 KiB limit"
                )
            }
            SpawnError::CommandContainsNul => write!(f, "command payload contains NUL"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// Map an SSH signal name to the libc signal number. Only the RFC 4254 set
/// the spec accepts is allowed; everything else is rejected by the caller.
pub fn signal_from_name(name: &str) -> Option<i32> {
    let number = match name {
        "ABRT" => libc::SIGABRT,
        "ALRM" => libc::SIGALRM,
        "FPE" => libc::SIGFPE,
        "HUP" => libc::SIGHUP,
        "ILL" => libc::SIGILL,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "PIPE" => libc::SIGPIPE,
        "QUIT" => libc::SIGQUIT,
        "SEGV" => libc::SIGSEGV,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => return None,
    };
    Some(number)
}

/// Map a libc signal number back to the SSH signal name for exit-signal.
pub fn name_from_signal(number: i32) -> Option<&'static str> {
    match number {
        libc::SIGABRT => Some("ABRT"),
        libc::SIGALRM => Some("ALRM"),
        libc::SIGFPE => Some("FPE"),
        libc::SIGHUP => Some("HUP"),
        libc::SIGILL => Some("ILL"),
        libc::SIGINT => Some("INT"),
        libc::SIGKILL => Some("KILL"),
        libc::SIGPIPE => Some("PIPE"),
        libc::SIGQUIT => Some("QUIT"),
        libc::SIGSEGV => Some("SEGV"),
        libc::SIGTERM => Some("TERM"),
        libc::SIGUSR1 => Some("USR1"),
        libc::SIGUSR2 => Some("USR2"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_zero_dimensions_use_a_nonzero_default() {
        let size = PtyRequest {
            term: "xterm".into(),
            rows: 0,
            cols: 0,
        }
        .window_size();
        assert_eq!(size.ws_row, 24);
        assert_eq!(size.ws_col, 80);
    }

    #[test]
    fn command_bytes_preserve_unix_bytes_and_reject_nul() {
        use std::os::unix::ffi::OsStrExt;

        let command = command_bytes(&[b'p', 0xff, b'r']).expect("raw command");
        assert_eq!(command.as_bytes(), b"p\xffr");
        assert!(matches!(
            command_bytes(b"printf\0bad"),
            Err(SpawnError::CommandContainsNul)
        ));
    }

    #[test]
    fn supported_signal_names_round_trip() {
        for (name, number) in [
            ("ABRT", libc::SIGABRT),
            ("TERM", libc::SIGTERM),
            ("USR1", libc::SIGUSR1),
            ("USR2", libc::SIGUSR2),
        ] {
            assert_eq!(signal_from_name(name), Some(number));
            assert_eq!(name_from_signal(number), Some(name));
        }
        assert_eq!(signal_from_name("SIGTERM"), None);
    }
}
