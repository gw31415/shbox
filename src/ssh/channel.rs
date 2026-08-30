//! Per-channel request state and the host-channel bridge task.
//!
//! Each session channel owns exactly one terminal operation. Client input is
//! routed into a bounded mailbox so a slow reader can never grow daemon
//! memory without limit; process output is forwarded through the russh
//! channel window, which applies the SSH flow-control backpressure.

use std::collections::HashMap;

use russh::ChannelId;
use russh::server::Handle;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::host::{self, HostRequest};

/// Bound for the per-channel mailbox of client events.
const MAILBOX_CAPACITY: usize = 64;

/// Client-originated events routed to a channel task.
#[derive(Debug)]
pub(crate) enum ChannelEvent {
    Data(Vec<u8>),
    Eof,
    Close,
    Signal(i32),
    WindowChange { rows: u32, cols: u32 },
}

/// Everything the connection handler remembers about one channel.
#[derive(Debug, Default)]
pub(crate) struct ChannelState {
    pub pty: Option<host::PtyRequest>,
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

    pub fn count(&self) -> usize {
        self.channels.lock().expect("channel registry").len()
    }

    /// Register a fresh channel with its bounded event mailbox.
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

    /// Update only non-zero PTY dimensions. The zero value means "ignore this
    /// dimension" in RFC 4254, so a resize can never turn a known dimension
    /// into zero or overwrite the other dimension with a default.
    pub fn update_window(&self, id: ChannelId, rows: u32, cols: u32) -> bool {
        self.with_state(id, |state| {
            let Some(pty) = state.pty.as_mut() else {
                return false;
            };
            if rows != 0 {
                pty.rows = rows;
            }
            if cols != 0 {
                pty.cols = cols;
            }
            true
        })
        .unwrap_or(false)
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
    tokio::task::spawn_blocking(move || host::HostProcess::spawn(&request))
        .await
        .expect("spawn_blocking join")
}

/// Bridge an already-started host process to one SSH channel.
pub(crate) async fn run_host_process(
    id: ChannelId,
    handle: Handle,
    mut process: host::HostProcess,
    waiter: host::HostWaiter,
    mut events: mpsc::Receiver<ChannelEvent>,
) -> ChannelResult {
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
    let waiter_task = tokio::task::spawn(async move {
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
    let mut exit_status: Option<ExitStatus> = None;
    let mut output_done = pumps.is_empty();
    let result: ChannelResult = loop {
        tokio::select! {
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
                    Some(ChannelEvent::WindowChange { rows, cols }) => {
                        process.resize(rows, cols);
                    }
                    // The registry dropped the mailbox: the connection is
                    // gone; tear this channel down.
                    None => break ChannelResult::Aborted,
                }
            }
            chunk = output_rx.recv(), if !output_done => {
                match chunk {
                    Some(chunk) => {
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
    drop(waiter_task);

    if result != ChannelResult::Completed {
        // Teardown: no new input, then make sure the group dies.
        process.client_eof();
        process.signal_group(libc::SIGTERM);
        tokio::time::sleep(TEARDOWN_GRACE).await;
        process.signal_group(libc::SIGKILL);
        let _ = handle.close(id).await;
        return result;
    }

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

/// A failed channel still completes: generic stderr, EOF, non-zero status,
/// close, so the client never waits on a channel that quietly stops.
pub(crate) async fn finish_failed(id: ChannelId, handle: &Handle) -> ChannelResult {
    let _ = handle
        .extended_data(id, 1, b"shbox: request cannot be completed\r\n".to_vec())
        .await;
    let _ = handle.eof(id).await;
    let _ = handle.exit_status_request(id, 111).await;
    let _ = handle.close(id).await;
    ChannelResult::Failed
}

#[derive(Debug)]
struct OutputChunk {
    data: Vec<u8>,
    ext: Option<u32>,
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
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let chunk = OutputChunk {
                        data: buffer[..count].to_vec(),
                        ext,
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
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let chunk = OutputChunk {
                        data: buffer[..count].to_vec(),
                        ext: None,
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
    HostShell,
    HostExec { command: Vec<u8> },
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
            ChannelOperation::HostShell => None,
            ChannelOperation::HostExec { command } => Some(command.clone()),
        },
        pty,
    }
}
