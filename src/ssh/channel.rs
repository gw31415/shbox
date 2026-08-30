//! Per-channel request state and the host-channel bridge task.
//!
//! Each session channel owns exactly one terminal operation. Client input is
//! routed into a bounded mailbox so a slow reader can never grow daemon
//! memory without limit; process output is forwarded through the russh
//! channel window, which applies the SSH flow-control backpressure.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use russh::ChannelId;
use russh::server::Handle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::platform;

use super::host::{self, HostRequest};

/// Bound for the per-channel mailbox of client events.
const MAILBOX_CAPACITY: usize = 64;

type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>>;

/// Small output sink used by the generic sandbox bridge.  Keeping this
/// boundary independent of russh makes stream ordering and cleanup tests
/// deterministic without exposing a fake transport to production code.
pub(crate) trait ChannelSink: Send + Sync {
    fn data<'a>(&'a self, id: ChannelId, data: Vec<u8>) -> SinkFuture<'a>;
    fn extended_data<'a>(&'a self, id: ChannelId, ext: u32, data: Vec<u8>) -> SinkFuture<'a>;
    fn eof<'a>(&'a self, id: ChannelId) -> SinkFuture<'a>;
    fn exit_status<'a>(&'a self, id: ChannelId, status: u32) -> SinkFuture<'a>;
    fn exit_signal<'a>(
        &'a self,
        id: ChannelId,
        name: &'static str,
        core_dumped: bool,
    ) -> SinkFuture<'a>;
    fn close<'a>(&'a self, id: ChannelId) -> SinkFuture<'a>;
}

impl ChannelSink for Handle {
    fn data<'a>(&'a self, id: ChannelId, data: Vec<u8>) -> SinkFuture<'a> {
        Box::pin(async move { self.data(id, data).await.map_err(|_| ()) })
    }

    fn extended_data<'a>(&'a self, id: ChannelId, ext: u32, data: Vec<u8>) -> SinkFuture<'a> {
        Box::pin(async move { self.extended_data(id, ext, data).await.map_err(|_| ()) })
    }

    fn eof<'a>(&'a self, id: ChannelId) -> SinkFuture<'a> {
        Box::pin(async move { self.eof(id).await })
    }

    fn exit_status<'a>(&'a self, id: ChannelId, status: u32) -> SinkFuture<'a> {
        Box::pin(async move { self.exit_status_request(id, status).await })
    }

    fn exit_signal<'a>(
        &'a self,
        id: ChannelId,
        name: &'static str,
        core_dumped: bool,
    ) -> SinkFuture<'a> {
        Box::pin(async move {
            self.exit_signal_request(
                id,
                signal_name_to_sig(name),
                core_dumped,
                String::new(),
                String::new(),
            )
            .await
        })
    }

    fn close<'a>(&'a self, id: ChannelId) -> SinkFuture<'a> {
        Box::pin(async move { self.close(id).await })
    }
}

/// Client-originated events routed to a channel task.
#[derive(Debug)]
pub(crate) enum ChannelEvent {
    Data(Vec<u8>),
    Eof,
    Close,
    Signal(i32),
    WindowChange { rows: u32, cols: u32, revision: u64 },
}

/// Everything the connection handler remembers about one channel.
#[derive(Debug, Default)]
pub(crate) struct ChannelState {
    pub pty: Option<host::PtyRequest>,
    pub window_revision: u64,
    /// Set once shell/exec/subsystem started; further terminal operations on
    /// the same channel are refused.
    pub started: bool,
    pub eof_from_client: bool,
    /// Client-event mailbox, created at channel open. The receiver is taken
    /// by the bridge task when an operation starts.
    mailbox: Option<mpsc::Sender<ChannelEvent>>,
    mailbox_rx: Option<mpsc::Receiver<ChannelEvent>>,
}

/// Channel registry shared between the connection handler and channel tasks.
#[derive(Debug, Default)]
pub(crate) struct ChannelRegistry {
    channels: std::sync::Mutex<HashMap<ChannelId, ChannelState>>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.channels.lock().expect("channel registry").len()
    }

    /// Register a fresh channel with its bounded event mailbox.
    #[cfg(test)]
    pub fn open(&self, id: ChannelId) {
        let (tx, rx) = mpsc::channel(MAILBOX_CAPACITY);
        let mut channels = self.channels.lock().expect("channel registry");
        channels.insert(
            id,
            ChannelState {
                mailbox: Some(tx),
                mailbox_rx: Some(rx),
                ..Default::default()
            },
        );
    }

    /// Atomically enforce the per-connection channel cap and register the
    /// channel.  The admission check and insertion share one lock so two
    /// concurrent channel-open callbacks cannot cross the configured limit.
    pub fn try_open(&self, id: ChannelId, cap: usize) -> bool {
        let (tx, rx) = mpsc::channel(MAILBOX_CAPACITY);
        let mut channels = self.channels.lock().expect("channel registry");
        if channels.len() >= cap {
            return false;
        }
        channels.insert(
            id,
            ChannelState {
                mailbox: Some(tx),
                mailbox_rx: Some(rx),
                ..Default::default()
            },
        );
        true
    }

    pub fn remove(&self, id: ChannelId) {
        self.channels.lock().expect("channel registry").remove(&id);
    }

    /// Atomically mark a channel as running and take its event receiver.
    ///
    /// Keeping these two changes under one lock prevents a second terminal
    /// request from observing a receiver that was taken but a channel that was
    /// not yet marked started.
    pub fn start(&self, id: ChannelId) -> Option<mpsc::Receiver<ChannelEvent>> {
        let mut channels = self.channels.lock().expect("channel registry");
        let state = channels.get_mut(&id)?;
        if state.started {
            return None;
        }
        state.started = true;
        state.mailbox_rx.take()
    }

    /// Return the currently requested PTY, if the channel still exists.
    pub fn pty(&self, id: ChannelId) -> Option<host::PtyRequest> {
        self.with_state(id, |state| state.pty.clone())
            .unwrap_or(None)
    }

    /// Return the PTY request and its desired-window revision as one snapshot.
    /// The revision lets a bridge discard resize events queued before a newer
    /// size was applied during process launch.
    pub fn pty_snapshot(&self, id: ChannelId) -> Option<(host::PtyRequest, u64)> {
        self.with_state(id, |state| {
            state.pty.clone().map(|pty| (pty, state.window_revision))
        })
        .unwrap_or(None)
    }

    /// Update only non-zero PTY dimensions. The zero value means "ignore this
    /// dimension" in RFC 4254, so a resize can never turn a known dimension
    /// into zero or overwrite the other dimension with a default.
    pub fn update_window(&self, id: ChannelId, rows: u32, cols: u32) -> Option<u64> {
        self.with_state(id, |state| {
            let pty = state.pty.as_mut()?;
            if rows == 0 && cols == 0 {
                return Some(state.window_revision);
            }
            let revision = state.window_revision.checked_add(1)?;
            if rows != 0 {
                pty.rows = rows;
            }
            if cols != 0 {
                pty.cols = cols;
            }
            state.window_revision = revision;
            Some(revision)
        })
        .unwrap_or(None)
    }

    /// Run `body` against the channel state; the lock is held only for the
    /// in-memory update, never across an await.
    pub fn with_state<R>(
        &self,
        id: ChannelId,
        body: impl FnOnce(&mut ChannelState) -> R,
    ) -> Option<R> {
        let mut channels = self.channels.lock().expect("channel registry");
        channels.get_mut(&id).map(body)
    }

    /// Try to enqueue an event without ever blocking the protocol loop.
    pub fn try_send(&self, id: ChannelId, event: ChannelEvent) -> bool {
        self.with_state(id, |state| match state.mailbox.as_ref() {
            Some(mailbox) => mailbox.try_send(event).is_ok(),
            None => false,
        })
        .unwrap_or(false)
    }
}

/// Outcome of a completed channel task.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChannelResult {
    /// The operation ran; the exit was forwarded to the client.
    Completed,
    /// The operation never produced a process (spawn failed).
    Failed,
    /// The channel was torn down (close/disconnect/backpressure).
    Aborted,
}

/// Normalized process exit forwarded as exit-status or exit-signal.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExitStatus {
    Code(u32),
    Signal {
        name: &'static str,
        core_dumped: bool,
    },
}

/// Size of one output chunk handed to the SSH channel.
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
/// Number of buffered output chunks per channel (bounded memory).
const OUTPUT_QUEUE_CHUNKS: usize = 8;
/// Grace period between SIGTERM and SIGKILL on teardown.
const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Allocate and start a host process away from the async runtime's hot path.
/// The SSH handler uses this future before acknowledging shell/exec so a
/// successful request always corresponds to a process that really started.
pub(crate) async fn spawn_host_process(
    request: HostRequest,
) -> Result<(host::HostProcess, host::HostWaiter), host::SpawnError> {
    // Spawn on the blocking pool: PTY allocation and fork/exec block.
    tokio::task::spawn_blocking(move || {
        // Keep host fork/exec serialized with the sandbox adapter's
        // non-atomic macOS pipe-CLOEXEC setup. Otherwise a host child could
        // inherit an endpoint between pipe() and fcntl(FD_CLOEXEC).
        let _spawn_guard = crate::platform::process_spawn_lock()
            .lock()
            .expect("process spawn lock");
        host::HostProcess::spawn(&request)
    })
    .await
    .expect("spawn_blocking join")
}

/// Wait for an adapter's reap/cleanup owner after an abnormal channel
/// teardown. Persistent workspace deletion must not race this boundary.
pub(crate) async fn wait_for_process_cleanup(control: Arc<dyn platform::RunningProcess>) {
    let _ = tokio::task::spawn_blocking(move || {
        control.terminate();
        if !control.wait_for_cleanup(TEARDOWN_GRACE) {
            control.force_terminate();
            let _ = control.wait_for_cleanup(TEARDOWN_GRACE);
        }
    })
    .await;
}

/// Tear down a host process before a request can be acknowledged. The waiter
/// remains owned until the child has been reaped, and only a timeout escalates
/// from the process-group TERM to KILL path.
pub(crate) async fn terminate_host_process(
    mut process: host::HostProcess,
    mut waiter: host::HostWaiter,
) {
    process.client_eof();
    process.signal_group(libc::SIGTERM);
    let graceful = matches!(
        tokio::time::timeout(TEARDOWN_GRACE, waiter.wait()).await,
        Ok(Ok(_))
    );
    if !graceful {
        process.signal_group(libc::SIGKILL);
        if !matches!(
            tokio::time::timeout(TEARDOWN_GRACE, waiter.wait()).await,
            Ok(Ok(_))
        ) {
            waiter.abort();
        }
    }
}

/// Re-apply the latest channel window before a sandbox bridge is published.
/// A resize can arrive while the blocking adapter launch is in progress; the
/// loop observes the state revision after each ioctl and repeats until stable.
pub(crate) fn synchronize_sandbox_window(
    registry: &ChannelRegistry,
    id: ChannelId,
    control: &dyn platform::RunningProcess,
) -> Option<u64> {
    let Some((mut pty, mut revision)) = registry.pty_snapshot(id) else {
        return Some(0);
    };
    loop {
        if !control.resize(pty.rows, pty.cols) {
            return None;
        }
        let (latest, latest_revision) = registry.pty_snapshot(id)?;
        if latest_revision == revision {
            return Some(revision);
        }
        pty = latest;
        revision = latest_revision;
    }
}

/// The host adapter has the same launch race, but owns a mutable process
/// rather than a platform control trait object.
pub(crate) fn synchronize_host_window(
    registry: &ChannelRegistry,
    id: ChannelId,
    process: &mut host::HostProcess,
) -> Option<u64> {
    let Some((mut pty, mut revision)) = registry.pty_snapshot(id) else {
        return Some(0);
    };
    loop {
        if !process.resize(pty.rows, pty.cols) {
            return None;
        }
        let (latest, latest_revision) = registry.pty_snapshot(id)?;
        if latest_revision == revision {
            return Some(revision);
        }
        pty = latest;
        revision = latest_revision;
    }
}

/// Bridge an already-started host process to one SSH channel.
pub(crate) struct HostProcessRun {
    pub(crate) id: ChannelId,
    pub(crate) handle: Handle,
    pub(crate) process: host::HostProcess,
    pub(crate) waiter: host::HostWaiter,
    pub(crate) events: mpsc::Receiver<ChannelEvent>,
    pub(crate) initial_window_revision: u64,
    pub(crate) host_slot: crate::server::HostProcessSlot,
    pub(crate) shutdown: tokio::sync::watch::Receiver<bool>,
}

pub(crate) async fn run_host_process(run: HostProcessRun) -> ChannelResult {
    let HostProcessRun {
        id,
        handle,
        mut process,
        waiter,
        mut events,
        initial_window_revision,
        host_slot: _host_slot,
        mut shutdown,
    } = run;
    // Bounded queue of output chunks; the pumps block when full, so the child
    // blocks on its pipe once the daemon-side buffer is exhausted.
    let (output_tx, mut output_rx) = mpsc::channel::<OutputChunk>(OUTPUT_QUEUE_CHUNKS);
    let mut pumps: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(stdout) = process.take_stdout() {
        pumps.push(spawn_pipe_pump(stdout, None, output_tx.clone()));
    }
    if let Some(stderr) = process.take_stderr() {
        pumps.push(spawn_pipe_pump(stderr, Some(1), output_tx.clone()));
    }
    if let Some(master_read) = process.take_master_read() {
        // The PTY master merges stdout and stderr into one terminal stream.
        pumps.push(spawn_pty_pump(master_read, output_tx.clone()));
    }
    drop(output_tx);

    let (exit_tx, mut exit_rx) = mpsc::channel::<ExitStatus>(1);
    let mut waiter_task = tokio::task::spawn(async move {
        let exit = match waiter.exit().await {
            Ok(host::Exit::Code(code)) => ExitStatus::Code(code.clamp(0, i32::MAX) as u32),
            Ok(host::Exit::Signal {
                number,
                core_dumped,
            }) => ExitStatus::Signal {
                name: host::name_from_signal(number).unwrap_or("TERM"),
                core_dumped,
            },
            Err(err) => {
                tracing::warn!("host process wait failed: {err}");
                ExitStatus::Code(255)
            }
        };
        let _ = exit_tx.send(exit).await;
    });

    let mut client_eof = false;
    let mut applied_window_revision = initial_window_revision;
    let mut exit_status: Option<ExitStatus> = None;
    let mut output_done = pumps.is_empty();
    let result: ChannelResult = loop {
        tokio::select! {
            _ = shutdown.changed() => break ChannelResult::Aborted,
            event = events.recv() => {
                match event {
                    Some(ChannelEvent::Data(data)) => {
                        if client_eof {
                            // Input after client EOF is dropped; the remaining
                            // output and the exit still flow.
                            continue;
                        }
                        if process.write_input(&data).await.is_err() {
                            break ChannelResult::Aborted;
                        }
                    }
                    Some(ChannelEvent::Eof) => {
                        client_eof = true;
                        process.client_eof();
                    }
                    Some(ChannelEvent::Close) => break ChannelResult::Aborted,
                    Some(ChannelEvent::Signal(number)) => {
                        process.signal_group(number);
                    }
                    Some(ChannelEvent::WindowChange { rows, cols, revision }) => {
                        if revision > applied_window_revision {
                            if !process.resize(rows, cols) {
                                break ChannelResult::Aborted;
                            }
                            applied_window_revision = revision;
                        }
                    }
                    // The registry dropped the mailbox: the connection is
                    // gone; tear this channel down.
                    None => break ChannelResult::Aborted,
                }
            }
            chunk = output_rx.recv(), if !output_done => {
                match chunk {
                    Some(chunk) => {
                        if chunk.failed {
                            break ChannelResult::Aborted;
                        }
                        let sent = match chunk.ext {
                            None => handle.data(id, chunk.data).await,
                            Some(ext) => handle.extended_data(id, ext, chunk.data).await,
                        };
                        if sent.is_err() {
                            break ChannelResult::Aborted;
                        }
                    }
                    None => output_done = true,
                }
            }
            status = exit_rx.recv(), if exit_status.is_none() => {
                exit_status = Some(status.unwrap_or(ExitStatus::Code(255)));
            }
        }
        if exit_status.is_some() && output_done {
            break ChannelResult::Completed;
        }
    };
    if result != ChannelResult::Completed {
        // Teardown: no new input, give the waiter a graceful window, then
        // force the process group and join every pump before returning.
        process.client_eof();
        process.signal_group(libc::SIGTERM);
        let graceful = matches!(
            tokio::time::timeout(TEARDOWN_GRACE, &mut waiter_task).await,
            Ok(Ok(()))
        );
        if !graceful {
            process.signal_group(libc::SIGKILL);
            let _ = tokio::time::timeout(TEARDOWN_GRACE, &mut waiter_task).await;
        }
        if !waiter_task.is_finished() {
            waiter_task.abort();
        }
        let _ = waiter_task.await;
        for pump in pumps {
            pump.abort();
            let _ = pump.await;
        }
        let _ = handle.close(id).await;
        return result;
    }

    drop(waiter_task);

    // Order the completion the SSH protocol expects: output, EOF, exit,
    // close.
    let _ = handle.eof(id).await;
    match exit_status.expect("exit collected") {
        ExitStatus::Code(code) => {
            let _ = handle.exit_status_request(id, code).await;
        }
        ExitStatus::Signal { name, core_dumped } => {
            let _ = handle
                .exit_signal_request(
                    id,
                    signal_name_to_sig(name),
                    core_dumped,
                    String::new(),
                    String::new(),
                )
                .await;
        }
    }
    let _ = handle.close(id).await;
    result
}

/// Bridge a sandbox adapter's process endpoints to one SSH channel.  The
/// adapter supplies bounded/owned streams, while this function owns the
/// protocol ordering and channel-local event semantics.
pub(crate) async fn run_sandbox_process(
    id: ChannelId,
    sink: &dyn ChannelSink,
    mut process: platform::LaunchedProcess,
    mut events: mpsc::Receiver<ChannelEvent>,
) -> ChannelResult {
    let (output_tx, mut output_rx) = mpsc::channel::<OutputChunk>(OUTPUT_QUEUE_CHUNKS);
    let mut pumps: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(stdout) = process.stdout.take() {
        pumps.push(spawn_pipe_pump(stdout, None, output_tx.clone()));
    }
    if let Some(stderr) = process.stderr.take() {
        pumps.push(spawn_pipe_pump(stderr, Some(1), output_tx.clone()));
    }
    // In PTY mode the adapter places the merged terminal stream in `stdout`
    // and leaves `stderr` empty, so the same pump handles both modes.
    drop(output_tx);

    let mut wait = process.wait;
    let mut client_eof = false;
    let mut exit_status: Option<ExitStatus> = None;
    let mut output_done = pumps.is_empty();
    let result: ChannelResult = loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(ChannelEvent::Data(data)) => {
                        if client_eof {
                            continue;
                        }
                        let Some(stdin) = process.stdin.as_mut() else {
                            break ChannelResult::Aborted;
                        };
                        if stdin.write_all(&data).await.is_err() {
                            break ChannelResult::Aborted;
                        }
                    }
                    Some(ChannelEvent::Eof) => {
                        client_eof = true;
                        // Dropping the adapter's write endpoint models a
                        // non-PTY stdin EOF and a PTY write-duplicate close;
                        // it never synthesizes VEOF or 0x04.
                        process.stdin = None;
                    }
                    Some(ChannelEvent::Close) => break ChannelResult::Aborted,
                    Some(ChannelEvent::Signal(number)) => {
                        process.control.signal(number);
                    }
                    Some(ChannelEvent::WindowChange { rows, cols, revision }) => {
                        if revision > process.window_revision {
                            if !process.control.resize(rows, cols) {
                                break ChannelResult::Aborted;
                            }
                            process.window_revision = revision;
                        }
                    }
                    None => break ChannelResult::Aborted,
                }
            }
            chunk = output_rx.recv(), if !output_done => {
                match chunk {
                    Some(chunk) => {
                        if chunk.failed {
                            break ChannelResult::Aborted;
                        }
                        let sent = match chunk.ext {
                            None => sink.data(id, chunk.data).await,
                            Some(ext) => sink.extended_data(id, ext, chunk.data).await,
                        };
                        if sent.is_err() {
                            break ChannelResult::Aborted;
                        }
                    }
                    None => output_done = true,
                }
            }
            status = &mut wait, if exit_status.is_none() => {
                exit_status = Some(normalize_sandbox_exit(status));
            }
        }
        if exit_status.is_some() && output_done {
            break ChannelResult::Completed;
        }
    };

    if result != ChannelResult::Completed {
        let control = Arc::clone(&process.control);
        for pump in pumps {
            pump.abort();
        }
        wait_for_process_cleanup(control).await;
        let _ = sink.close(id).await;
        return result;
    }

    let _ = sink.eof(id).await;
    match exit_status.expect("exit collected") {
        ExitStatus::Code(code) => {
            let _ = sink.exit_status(id, code).await;
        }
        ExitStatus::Signal { name, core_dumped } => {
            let _ = sink.exit_signal(id, name, core_dumped).await;
        }
    }
    let _ = sink.close(id).await;
    result
}

fn normalize_sandbox_exit(
    result: Result<
        Result<platform::ProcessExit, platform::LaunchError>,
        tokio::sync::oneshot::error::RecvError,
    >,
) -> ExitStatus {
    match result {
        Ok(Ok(platform::ProcessExit::Code(code))) => {
            ExitStatus::Code(code.clamp(0, i32::MAX) as u32)
        }
        Ok(Ok(platform::ProcessExit::Signal {
            number,
            core_dumped,
        })) => ExitStatus::Signal {
            name: host::name_from_signal(number).unwrap_or("TERM"),
            core_dumped,
        },
        Ok(Err(error)) => {
            tracing::warn!("sandbox process wait failed: {error}");
            ExitStatus::Code(255)
        }
        Err(error) => {
            tracing::warn!("sandbox process wait channel failed: {error}");
            ExitStatus::Code(255)
        }
    }
}

/// A failed channel still completes: generic stderr, EOF, non-zero status,
/// close, so the client never waits on a channel that quietly stops.
pub(crate) async fn finish_failed(id: ChannelId, sink: &dyn ChannelSink) -> ChannelResult {
    let _ = sink
        .extended_data(id, 1, b"shbox: request cannot be completed\r\n".to_vec())
        .await;
    let _ = sink.eof(id).await;
    let _ = sink.exit_status(id, 111).await;
    let _ = sink.close(id).await;
    ChannelResult::Failed
}

#[derive(Debug)]
struct OutputChunk {
    data: Vec<u8>,
    ext: Option<u32>,
    failed: bool,
}

/// Read one child pipe to EOF and forward bounded chunks.
fn spawn_pipe_pump(
    mut reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    ext: Option<u32>,
    tx: mpsc::Sender<OutputChunk>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Err(_) => {
                    let _ = tx
                        .send(OutputChunk {
                            data: Vec::new(),
                            ext,
                            failed: true,
                        })
                        .await;
                    break;
                }
                Ok(count) => {
                    let chunk = OutputChunk {
                        data: buffer[..count].to_vec(),
                        ext,
                        failed: false,
                    };
                    if tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Read the PTY master to EOF and forward bounded chunks.
fn spawn_pty_pump(
    mut master: tokio::io::unix::AsyncFd<std::fs::File>,
    tx: mpsc::Sender<OutputChunk>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
        loop {
            match host::read_some_fd(&mut master, &mut buffer).await {
                Ok(0) => break,
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(_) => {
                    let _ = tx
                        .send(OutputChunk {
                            data: Vec::new(),
                            ext: None,
                            failed: true,
                        })
                        .await;
                    break;
                }
                Ok(count) => {
                    let chunk = OutputChunk {
                        data: buffer[..count].to_vec(),
                        ext: None,
                        failed: false,
                    };
                    if tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// The russh `Sig` enum carries the wire name for exit-signal requests.
fn signal_name_to_sig(name: &'static str) -> russh::Sig {
    match name {
        "ABRT" => russh::Sig::ABRT,
        "ALRM" => russh::Sig::ALRM,
        "FPE" => russh::Sig::FPE,
        "HUP" => russh::Sig::HUP,
        "ILL" => russh::Sig::ILL,
        "INT" => russh::Sig::INT,
        "KILL" => russh::Sig::KILL,
        "PIPE" => russh::Sig::PIPE,
        "QUIT" => russh::Sig::QUIT,
        "SEGV" => russh::Sig::SEGV,
        "TERM" => russh::Sig::TERM,
        "USR1" => russh::Sig::USR1,
        // russh 0.63.1 represents USR2 as a custom RFC signal name.
        "USR2" => russh::Sig::Custom("USR2".to_string()),
        _ => russh::Sig::TERM,
    }
}

/// The single terminal operation approved for a channel.
#[derive(Debug, Clone)]
pub(crate) enum ChannelOperation {
    Shell,
    Exec { command: Vec<u8> },
}

/// Build the host request for an approved operation.
pub(crate) fn host_request(
    operation: &ChannelOperation,
    shell: &std::path::Path,
    home: &std::path::Path,
    pty: Option<host::PtyRequest>,
) -> HostRequest {
    HostRequest {
        shell: shell.to_path_buf(),
        home: home.to_path_buf(),
        command: match operation {
            ChannelOperation::Shell => None,
            ChannelOperation::Exec { command } => Some(command.clone()),
        },
        pty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        FakeLauncher, LaunchOperation, LaunchRequest, ProcessExit, ProcessLauncher, PtySpec,
    };
    use ssh_encoding::Decode;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum SinkEvent {
        Data(Vec<u8>),
        Extended(u32, Vec<u8>),
        Eof,
        ExitStatus(u32),
        ExitSignal(&'static str, bool),
        Close,
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingSink {
        events: std::sync::Arc<std::sync::Mutex<Vec<SinkEvent>>>,
        fail_data: std::sync::Arc<AtomicBool>,
    }

    impl RecordingSink {
        fn events(&self) -> Vec<SinkEvent> {
            self.events.lock().expect("sink events").clone()
        }

        fn record(&self, event: SinkEvent) {
            self.events.lock().expect("sink events").push(event);
        }

        fn ready<'a>() -> SinkFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    impl ChannelSink for RecordingSink {
        fn data<'a>(&'a self, _id: ChannelId, data: Vec<u8>) -> SinkFuture<'a> {
            self.record(SinkEvent::Data(data));
            if self.fail_data.load(Ordering::Acquire) {
                Box::pin(async { Err(()) })
            } else {
                Self::ready()
            }
        }

        fn extended_data<'a>(&'a self, _id: ChannelId, ext: u32, data: Vec<u8>) -> SinkFuture<'a> {
            self.record(SinkEvent::Extended(ext, data));
            Self::ready()
        }

        fn eof<'a>(&'a self, _id: ChannelId) -> SinkFuture<'a> {
            self.record(SinkEvent::Eof);
            Self::ready()
        }

        fn exit_status<'a>(&'a self, _id: ChannelId, status: u32) -> SinkFuture<'a> {
            self.record(SinkEvent::ExitStatus(status));
            Self::ready()
        }

        fn exit_signal<'a>(
            &'a self,
            _id: ChannelId,
            name: &'static str,
            core_dumped: bool,
        ) -> SinkFuture<'a> {
            self.record(SinkEvent::ExitSignal(name, core_dumped));
            Self::ready()
        }

        fn close<'a>(&'a self, _id: ChannelId) -> SinkFuture<'a> {
            self.record(SinkEvent::Close);
            Self::ready()
        }
    }

    fn channel_id(number: u32) -> ChannelId {
        let bytes = number.to_be_bytes();
        ChannelId::decode(&mut &bytes[..]).expect("valid channel id")
    }

    fn request(pty: Option<PtySpec>) -> LaunchRequest {
        LaunchRequest {
            sandbox_id: crate::sandbox::SandboxId::parse("dev").expect("sandbox id"),
            workspace: std::path::PathBuf::from("/tmp/shbox-dev"),
            operation: LaunchOperation::Exec(b"fake command".to_vec()),
            pty,
        }
    }

    #[test]
    fn registry_open_is_atomic_with_the_channel_cap() {
        let registry = ChannelRegistry::new();
        let first = channel_id(1);
        let second = channel_id(2);
        assert!(registry.try_open(first, 1));
        assert!(!registry.try_open(second, 1));
        assert_eq!(registry.count(), 1);
        registry.remove(first);
        registry.open(second);
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn window_revision_preserves_zero_dimensions_and_ignores_non_pty_channels() {
        let registry = ChannelRegistry::new();
        let id = channel_id(10);
        let no_pty = channel_id(11);
        registry.open(id);
        registry.open(no_pty);
        registry.with_state(id, |state| {
            state.pty = Some(host::PtyRequest {
                term: "xterm".into(),
                rows: 24,
                cols: 80,
                modes: Vec::new(),
            });
        });

        assert_eq!(registry.update_window(id, 0, 0), Some(0));
        assert_eq!(registry.update_window(id, 40, 0), Some(1));
        assert_eq!(registry.update_window(id, 0, 120), Some(2));
        let (pty, revision) = registry.pty_snapshot(id).expect("pty snapshot");
        assert_eq!((pty.rows, pty.cols, revision), (40, 120, 2));
        assert_eq!(registry.update_window(no_pty, 50, 150), None);
        assert_eq!(registry.pty_snapshot(no_pty), None);
    }

    #[tokio::test]
    async fn sandbox_bridge_keeps_streams_separate_and_finishes_in_order() {
        let launcher = FakeLauncher::default();
        let launched = launcher.launch(request(None)).expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let sink = RecordingSink::default();
        let (events_tx, events_rx) = mpsc::channel(16);
        let id = channel_id(1);
        let bridge_sink = sink.clone();
        let bridge = tokio::spawn(async move {
            run_sandbox_process(id, &bridge_sink, launched, events_rx).await
        });

        events_tx
            .send(ChannelEvent::Data(b"input".to_vec()))
            .await
            .expect("input event");
        let mut input = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fake.read_stdin(&mut input),
        )
        .await
        .expect("input forwarded")
        .expect("stdin read");
        assert_eq!(&input, b"input");

        events_tx
            .send(ChannelEvent::Signal(libc::SIGINT))
            .await
            .expect("signal event");
        events_tx
            .send(ChannelEvent::WindowChange {
                rows: 30,
                cols: 100,
                revision: 1,
            })
            .await
            .expect("resize event");
        events_tx.send(ChannelEvent::Eof).await.expect("eof event");
        events_tx
            .send(ChannelEvent::Data(vec![0x04]))
            .await
            .expect("post-eof data event");
        let mut after_eof = [0; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fake.read_stdin(&mut after_eof),
        )
        .await
        .expect("stdin closes after EOF")
        .expect("stdin read after EOF");
        assert_eq!(read, 0, "EOF must not synthesize a VEOF byte");

        fake.send_stdout(b"out").await.expect("stdout");
        fake.send_stderr(b"err").await.expect("stderr");
        fake.finish(ProcessExit::Code(7)).await;
        assert_eq!(bridge.await.expect("bridge join"), ChannelResult::Completed);

        let events = sink.events();
        assert!(events.contains(&SinkEvent::Data(b"out".to_vec())));
        assert!(events.contains(&SinkEvent::Extended(1, b"err".to_vec())));
        assert_eq!(
            &events[events.len() - 3..],
            [SinkEvent::Eof, SinkEvent::ExitStatus(7), SinkEvent::Close,]
        );
        assert_eq!(fake.signals(), vec![libc::SIGINT]);
        assert_eq!(fake.resizes(), vec![(30, 100)]);
    }

    #[tokio::test]
    async fn sandbox_bridge_merges_pty_output_and_reports_exit_signal() {
        let launcher = FakeLauncher::default();
        let launched = launcher
            .launch(request(Some(PtySpec {
                term: "xterm".into(),
                rows: 24,
                cols: 80,
                modes: Vec::new(),
                window_revision: 0,
            })))
            .expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let sink = RecordingSink::default();
        let (events_tx, events_rx) = mpsc::channel(4);
        let id = channel_id(2);
        let bridge_sink = sink.clone();
        let bridge = tokio::spawn(async move {
            run_sandbox_process(id, &bridge_sink, launched, events_rx).await
        });

        fake.send_pty(b"terminal").await.expect("pty output");
        fake.finish(ProcessExit::Signal {
            number: libc::SIGTERM,
            core_dumped: false,
        })
        .await;
        assert_eq!(bridge.await.expect("bridge join"), ChannelResult::Completed);
        let events = sink.events();
        assert!(events.contains(&SinkEvent::Data(b"terminal".to_vec())));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SinkEvent::Extended(..)))
        );
        assert_eq!(
            &events[events.len() - 3..],
            [
                SinkEvent::Eof,
                SinkEvent::ExitSignal("TERM", false),
                SinkEvent::Close,
            ]
        );
        let _ = events_tx;
    }

    #[tokio::test]
    async fn sandbox_bridge_discards_resize_events_older_than_launch_snapshot() {
        let launcher = FakeLauncher::default();
        let launched = launcher
            .launch(request(Some(PtySpec {
                term: "xterm".into(),
                rows: 24,
                cols: 80,
                modes: Vec::new(),
                window_revision: 2,
            })))
            .expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let sink = RecordingSink::default();
        let (events_tx, events_rx) = mpsc::channel(4);
        let id = channel_id(12);
        let bridge_sink = sink.clone();
        let bridge = tokio::spawn(async move {
            run_sandbox_process(id, &bridge_sink, launched, events_rx).await
        });

        events_tx
            .send(ChannelEvent::WindowChange {
                rows: 30,
                cols: 100,
                revision: 1,
            })
            .await
            .expect("stale resize");
        events_tx
            .send(ChannelEvent::WindowChange {
                rows: 40,
                cols: 120,
                revision: 3,
            })
            .await
            .expect("new resize");
        fake.finish(ProcessExit::Code(0)).await;
        assert_eq!(bridge.await.expect("bridge join"), ChannelResult::Completed);
        assert_eq!(fake.resizes(), vec![(40, 120)]);
    }

    #[tokio::test]
    async fn sink_failure_terminates_only_the_bridge_process() {
        let launcher = FakeLauncher::default();
        let launched = launcher.launch(request(None)).expect("fake launch");
        let fake = launcher.last_process().expect("fake process");
        let sink = RecordingSink::default();
        sink.fail_data.store(true, Ordering::Release);
        let (_events_tx, events_rx) = mpsc::channel(4);
        let id = channel_id(3);
        let bridge_sink = sink.clone();
        let bridge = tokio::spawn(async move {
            run_sandbox_process(id, &bridge_sink, launched, events_rx).await
        });
        fake.send_stdout(b"blocked").await.expect("stdout");
        assert_eq!(bridge.await.expect("bridge join"), ChannelResult::Aborted);
        assert!(fake.terminated());
        assert_eq!(sink.events().last(), Some(&SinkEvent::Close));
    }
}
