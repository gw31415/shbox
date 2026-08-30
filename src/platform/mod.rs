//! Private process-launch seam.
//!
//! The production adapter wraps the pinned Arapuca revision
//! `c94802c4d8b6b880334c0d643b16b7326ec7f039` (package version 0.2.7). Tests
//! get a deterministic fake launcher with barriers and failure injection;
//! nothing here is a configurable backend, and no Arapuca type leaks into the
//! configuration or SSH surfaces. The dependency is pinned in `Cargo.toml` so
//! `Cargo.lock` records the exact revision from the first commit on.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sandbox::SandboxId;

#[cfg(unix)]
mod arapuca;
#[cfg(unix)]
mod terminal;

#[cfg(unix)]
pub(crate) use self::arapuca::{ArapucaLaunchPolicy, ArapucaLauncher};
#[cfg(unix)]
pub(crate) use self::terminal::{PtyIo, apply_terminal_modes, apply_window_size, duplicate_fd};

/// Serialize every daemon-owned process spawn with adapter pipe creation.
///
/// macOS has no `pipe2(O_CLOEXEC)` equivalent exposed by the supported libc
/// surface. Holding this process-wide lock across pipe creation and the
/// subsequent fork/exec prevents host and sandbox launches from creating a
/// child while an endpoint is still being marked close-on-exec. Linux also
/// uses the lock for one uniform spawn boundary, even though it has an
/// atomic pipe primitive.
static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn process_spawn_lock() -> &'static Mutex<()> {
    &PROCESS_SPAWN_LOCK
}

/// The operation a sandbox process must perform.  This is deliberately a
/// protocol-neutral value: the SSH layer never passes an Arapuca type across
/// the manager boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LaunchOperation {
    Shell,
    Exec(Vec<u8>),
}

/// PTY settings captured before launch.  The revision is a channel-local
/// desired-window sequence number; it lets the bridge discard stale
/// window-change events that were queued while a process was launching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PtySpec {
    pub(crate) term: String,
    pub(crate) rows: u32,
    pub(crate) cols: u32,
    pub(crate) modes: Vec<(russh::Pty, u32)>,
    pub(crate) window_revision: u64,
}

/// The private request passed from SandboxManager to a process adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchRequest {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) workspace: PathBuf,
    pub(crate) operation: LaunchOperation,
    pub(crate) pty: Option<PtySpec>,
}

/// A process handle owned by the runtime registry.  The adapter owns the
/// process lifetime while the channel bridge owns the I/O endpoints.
pub(crate) trait RunningProcess: fmt::Debug + Send + Sync {
    fn terminate(&self);

    /// Force-stop after the graceful termination deadline. Keeping this as a
    /// separate seam lets cleanup preserve a real TERM grace period.
    fn force_terminate(&self) {
        self.terminate();
    }

    /// Wait until the adapter has reaped the process and released all
    /// platform-owned resources. Delete uses this before removing a
    /// workspace, so termination is not merely an asynchronous signal.
    fn wait_for_cleanup(&self, timeout: Duration) -> bool;

    /// Forward a validated SSH signal.  The production implementation maps
    /// this to its process group; the default keeps older adapters harmless.
    fn signal(&self, _number: i32) {}

    /// Apply a desired PTY size.  A process adapter may ignore this until its
    /// PTY has been created; the channel state remains authoritative.
    fn resize(&self, _rows: u32, _cols: u32) -> bool {
        true
    }
}

/// Normalized process exit used by the channel bridge.  The manager does not
/// expose raw wait status or platform-specific process types.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessExit {
    Code(i32),
    Signal { number: i32, core_dumped: bool },
}

pub(crate) type ProcessReader = Box<dyn tokio::io::AsyncRead + Send + Unpin>;
pub(crate) type ProcessWriter = Box<dyn tokio::io::AsyncWrite + Send + Unpin>;

/// Everything needed by one channel bridge after a successful launch.
pub(crate) struct LaunchedProcess {
    pub(crate) control: Arc<dyn RunningProcess>,
    pub(crate) stdin: Option<ProcessWriter>,
    pub(crate) stdout: Option<ProcessReader>,
    pub(crate) stderr: Option<ProcessReader>,
    pub(crate) window_revision: u64,
    /// In PTY mode `stdout` is already the merged terminal stream and
    /// `stderr` is `None`.  The write duplicate is represented by `stdin` and
    /// is dropped on client EOF.
    pub(crate) wait: tokio::sync::oneshot::Receiver<Result<ProcessExit, LaunchError>>,
}

impl fmt::Debug for LaunchedProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchedProcess")
            .field("control", &self.control)
            .field("has_stdin", &self.stdin.is_some())
            .field("has_stdout", &self.stdout.is_some())
            .field("has_stderr", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

/// Private production/test seam. It is not a configurable backend surface.
pub(crate) trait ProcessLauncher: fmt::Debug + Send + Sync {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError>;
}

/// Adapter-level launch failure, intentionally free of platform-specific
/// fields at the manager boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchError {
    message: String,
}

impl LaunchError {
    #[allow(dead_code)]
    pub(crate) fn new(message: impl Into<String>) -> LaunchError {
        LaunchError {
            message: message.into(),
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LaunchError {}

/// Fallback used when the process-lifetime Arapuca adapter could not be
/// initialized. Sandbox requests fail closed after the durable claim. This
/// adapter is deliberately not selectable through config or SSH.
#[derive(Debug, Default)]
pub(crate) struct UnavailableLauncher;

impl ProcessLauncher for UnavailableLauncher {
    fn launch(&self, _request: LaunchRequest) -> Result<LaunchedProcess, LaunchError> {
        Err(LaunchError::new("sandbox process adapter is unavailable"))
    }
}

/// Deterministic fake adapter used by lifecycle and bridge tests. The barrier
/// is optional and is deliberately controlled by the test, not by user config.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeLauncher {
    state: Arc<std::sync::Mutex<FakeState>>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct FakeState {
    fail_next: bool,
    launches: usize,
    barrier: Option<Arc<std::sync::Barrier>>,
    last_request: Option<LaunchRequest>,
    last_process: Option<Arc<FakeProcess>>,
}

#[cfg(test)]
impl FakeLauncher {
    pub(crate) fn fail_next(&self) {
        self.state.lock().expect("fake launcher").fail_next = true;
    }

    pub(crate) fn set_barrier(&self, barrier: Arc<std::sync::Barrier>) {
        self.state.lock().expect("fake launcher").barrier = Some(barrier);
    }

    pub(crate) fn launch_count(&self) -> usize {
        self.state.lock().expect("fake launcher").launches
    }

    pub(crate) fn last_request(&self) -> Option<LaunchRequest> {
        self.state
            .lock()
            .expect("fake launcher")
            .last_request
            .clone()
    }

    pub(crate) fn last_process(&self) -> Option<Arc<FakeProcess>> {
        self.state
            .lock()
            .expect("fake launcher")
            .last_process
            .clone()
    }
}

#[cfg(test)]
impl ProcessLauncher for FakeLauncher {
    fn launch(&self, request: LaunchRequest) -> Result<LaunchedProcess, LaunchError> {
        let barrier = {
            let mut state = self.state.lock().expect("fake launcher");
            state.launches += 1;
            state.last_request = Some(request.clone());
            if state.fail_next {
                state.fail_next = false;
                return Err(LaunchError::new("injected fake launch failure"));
            }
            state.barrier.clone()
        };
        if let Some(barrier) = barrier {
            barrier.wait();
        }

        let (service_stdin, fake_stdin) = tokio::io::duplex(64 * 1024);
        let (stdout_tx, stdout_rx) = tokio::sync::mpsc::channel(32);
        let (stderr_tx, stderr_rx) = tokio::sync::mpsc::channel(32);
        let (pty_tx, pty_rx) = tokio::sync::mpsc::channel(32);
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
        let pty_mode = request.pty.is_some();
        let process = Arc::new(FakeProcess::new(
            fake_stdin, stdout_tx, stderr_tx, pty_tx, wait_tx,
        ));
        self.state.lock().expect("fake launcher").last_process = Some(Arc::clone(&process));
        Ok(LaunchedProcess {
            control: process,
            stdin: Some(Box::new(service_stdin)),
            stdout: Some(Box::new(FakeReader::new(if pty_mode {
                pty_rx
            } else {
                stdout_rx
            }))),
            stderr: (!pty_mode).then(|| Box::new(FakeReader::new(stderr_rx)) as ProcessReader),
            window_revision: request.pty.as_ref().map_or(0, |pty| pty.window_revision),
            wait: wait_rx,
        })
    }
}

#[cfg(test)]
pub(crate) struct FakeProcess {
    terminated: std::sync::atomic::AtomicBool,
    cleanup_complete: std::sync::atomic::AtomicBool,
    signals: std::sync::Mutex<Vec<i32>>,
    resizes: std::sync::Mutex<Vec<(u32, u32)>>,
    stdin: tokio::sync::Mutex<tokio::io::DuplexStream>,
    channels: std::sync::Mutex<FakeChannels>,
}

#[cfg(test)]
struct FakeChannels {
    stdout: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    stderr: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    pty: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    wait: Option<tokio::sync::oneshot::Sender<Result<ProcessExit, LaunchError>>>,
}

#[cfg(test)]
struct FakeReader {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

#[cfg(test)]
impl FakeReader {
    fn new(receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> FakeReader {
        FakeReader {
            receiver,
            current: Vec::new(),
            offset: 0,
        }
    }
}

#[cfg(test)]
impl tokio::io::AsyncRead for FakeReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let available = &self.current[self.offset..];
                let count = available.len().min(buffer.remaining());
                buffer.put_slice(&available[..count]);
                self.offset += count;
                return std::task::Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut self.receiver).poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Some(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
impl fmt::Debug for FakeProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeProcess")
            .field(
                "terminated",
                &self.terminated.load(std::sync::atomic::Ordering::Acquire),
            )
            .field("signals", &self.signals)
            .field("resizes", &self.resizes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl FakeProcess {
    fn new(
        stdin: tokio::io::DuplexStream,
        stdout: tokio::sync::mpsc::Sender<Vec<u8>>,
        stderr: tokio::sync::mpsc::Sender<Vec<u8>>,
        pty: tokio::sync::mpsc::Sender<Vec<u8>>,
        wait: tokio::sync::oneshot::Sender<Result<ProcessExit, LaunchError>>,
    ) -> FakeProcess {
        FakeProcess {
            terminated: std::sync::atomic::AtomicBool::new(false),
            cleanup_complete: std::sync::atomic::AtomicBool::new(false),
            signals: std::sync::Mutex::new(Vec::new()),
            resizes: std::sync::Mutex::new(Vec::new()),
            stdin: tokio::sync::Mutex::new(stdin),
            channels: std::sync::Mutex::new(FakeChannels {
                stdout: Some(stdout),
                stderr: Some(stderr),
                pty: Some(pty),
                wait: Some(wait),
            }),
        }
    }

    pub(crate) fn terminated(&self) -> bool {
        self.terminated.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn mark_clean_for_test(&self) {
        self.cleanup_complete
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn signals(&self) -> Vec<i32> {
        self.signals.lock().expect("fake signals").clone()
    }

    pub(crate) fn resizes(&self) -> Vec<(u32, u32)> {
        self.resizes.lock().expect("fake resizes").clone()
    }

    async fn send_output(&self, stream: FakeOutput, data: &[u8]) -> std::io::Result<()> {
        let sender = {
            let channels = self.channels.lock().expect("fake channels");
            match stream {
                FakeOutput::Stdout => channels.stdout.clone(),
                FakeOutput::Stderr => channels.stderr.clone(),
                FakeOutput::Pty => channels.pty.clone(),
            }
        };
        let Some(sender) = sender else {
            return Ok(());
        };
        sender
            .send(data.to_vec())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "fake output closed"))
    }

    pub(crate) async fn send_stdout(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_output(FakeOutput::Stdout, data).await
    }

    pub(crate) async fn send_stderr(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_output(FakeOutput::Stderr, data).await
    }

    pub(crate) async fn send_pty(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_output(FakeOutput::Pty, data).await
    }

    pub(crate) async fn read_stdin(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.stdin.lock().await.read(buffer).await
    }

    pub(crate) async fn finish(&self, exit: ProcessExit) {
        let wait = {
            let mut channels = self.channels.lock().expect("fake channels");
            channels.stdout = None;
            channels.stderr = None;
            channels.pty = None;
            channels.wait.take()
        };
        if let Some(wait) = wait {
            let _ = wait.send(Ok(exit));
        }
        self.cleanup_complete
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn terminate_now(&self) {
        self.terminated
            .store(true, std::sync::atomic::Ordering::Release);
        let wait = {
            let mut channels = self.channels.lock().expect("fake channels");
            channels.stdout = None;
            channels.stderr = None;
            channels.pty = None;
            channels.wait.take()
        };
        if let Some(wait) = wait {
            let _ = wait.send(Ok(ProcessExit::Code(143)));
        }
        self.cleanup_complete
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum FakeOutput {
    Stdout,
    Stderr,
    Pty,
}

#[cfg(test)]
impl RunningProcess for FakeProcess {
    fn terminate(&self) {
        self.terminate_now();
    }

    fn wait_for_cleanup(&self, _timeout: Duration) -> bool {
        self.cleanup_complete
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn signal(&self, number: i32) {
        self.signals.lock().expect("fake signals").push(number);
    }

    fn resize(&self, rows: u32, cols: u32) -> bool {
        self.resizes
            .lock()
            .expect("fake resizes")
            .push((rows, cols));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_request(pty: Option<PtySpec>) -> LaunchRequest {
        LaunchRequest {
            sandbox_id: SandboxId::parse("dev").expect("sandbox id"),
            workspace: PathBuf::from("/tmp/shbox-dev"),
            operation: LaunchOperation::Exec(b"printf fake".to_vec()),
            pty,
        }
    }

    #[test]
    fn fake_records_the_complete_launch_request() {
        let launcher = FakeLauncher::default();
        let request = launch_request(Some(PtySpec {
            term: "xterm".into(),
            rows: 40,
            cols: 120,
            modes: Vec::new(),
            window_revision: 0,
        }));
        let _process = launcher.launch(request.clone()).expect("fake launch");
        assert_eq!(launcher.last_request(), Some(request));
    }

    #[tokio::test]
    async fn fake_non_pty_keeps_stdout_stderr_and_stdin_separate() {
        use tokio::io::AsyncReadExt;

        let launcher = FakeLauncher::default();
        let launched = launcher.launch(launch_request(None)).expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let mut stdout = launched.stdout.expect("stdout");
        let mut stderr = launched.stderr.expect("stderr");

        fake.send_stdout(b"out").await.expect("stdout write");
        fake.send_stderr(b"err").await.expect("stderr write");
        let mut out = [0; 3];
        let mut err = [0; 3];
        stdout.read_exact(&mut out).await.expect("stdout read");
        stderr.read_exact(&mut err).await.expect("stderr read");
        assert_eq!(&out, b"out");
        assert_eq!(&err, b"err");
    }

    #[tokio::test]
    async fn fake_pty_exposes_merged_output_without_stderr() {
        use tokio::io::AsyncReadExt;

        let launcher = FakeLauncher::default();
        let launched = launcher
            .launch(launch_request(Some(PtySpec {
                term: "xterm".into(),
                rows: 24,
                cols: 80,
                modes: Vec::new(),
                window_revision: 0,
            })))
            .expect("fake launch");
        assert!(launched.stderr.is_none());
        let fake = launcher.last_process().expect("fake process");
        let mut stdout = launched.stdout.expect("merged pty output");
        fake.send_pty(b"terminal").await.expect("pty write");
        let mut output = [0; 8];
        stdout.read_exact(&mut output).await.expect("pty read");
        assert_eq!(&output, b"terminal");
    }

    #[tokio::test]
    async fn terminate_closes_output_and_resolves_wait() {
        let launcher = FakeLauncher::default();
        let launched = launcher.launch(launch_request(None)).expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let control = Arc::clone(&launched.control);
        let wait = launched.wait;
        control.terminate();
        assert!(fake.terminated());
        assert_eq!(
            wait.await.expect("wait channel").expect("exit"),
            ProcessExit::Code(143)
        );
    }

    #[test]
    fn signal_and_resize_are_recorded() {
        let launcher = FakeLauncher::default();
        let launched = launcher.launch(launch_request(None)).expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        launched.control.signal(libc::SIGINT);
        launched.control.resize(30, 100);
        assert_eq!(fake.signals(), vec![libc::SIGINT]);
        assert_eq!(fake.resizes(), vec![(30, 100)]);
    }

    /// Compile-time probe of the pinned Arapuca public API. Building the
    /// production adapter on top of an unverified abstraction is the risk the
    /// plan calls out; this keeps the surface compiling from Milestone 1 on.
    #[test]
    fn pinned_arapuca_public_api_compiles() {
        let profile = ::arapuca::Profile::default();
        assert_eq!(profile.max_open_files, 0);
        assert_eq!(profile.seccomp_profile, ::arapuca::SeccompProfile::Strict);

        let task_id = "dev-0123456789abcdef0123456789abcdef";
        assert_eq!(
            ::arapuca::sanitize_task_id(task_id).expect("valid task id"),
            task_id
        );
        assert!(::arapuca::sanitize_task_id("bad_task").is_err());

        fn implements_sandbox_trait<T: ::arapuca::platform::Sandbox>() {}
        #[cfg(target_os = "linux")]
        implements_sandbox_trait::<::arapuca::platform::Linux>();
        #[cfg(target_os = "macos")]
        implements_sandbox_trait::<::arapuca::platform::Darwin>();
    }
}
