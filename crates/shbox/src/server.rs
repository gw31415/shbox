//! Listener binding, connection admission, and session supervision.
//!
//! Binding is all-or-nothing: either every configured address binds or
//! startup fails, and a failing bind never falls back to another port. Each
//! accepted TCP connection gets a handshake deadline that ends as soon as
//! authentication succeeds; authenticated connections have no idle timeout.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use russh::server::{self, Config};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

use crate::config::Caps;
use crate::endpoint::ListenEndpoint;
use russh::{MethodKind, MethodSet};

use crate::ssh::ConnHandler;

/// Handler failures are russh transport failures; operational errors are
/// handled inside the handlers and never reach this type.
pub type HandlerError = russh::Error;

/// Connection admission counters for the built-in caps.
#[derive(Debug)]
pub struct Limiter {
    caps: Caps,
    unauthenticated: AtomicUsize,
    total: AtomicUsize,
}

impl Limiter {
    pub fn new(caps: &Caps) -> Limiter {
        Limiter {
            caps: *caps,
            unauthenticated: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
        }
    }

    /// Reserve a connection slot, enforcing both caps atomically enough for
    /// the admission decision: a slot is only granted under both limits.
    pub fn admit(self: &Arc<Self>) -> Option<Arc<LimiterSlot>> {
        let caps = self.caps;
        if !try_acquire(&self.total, caps.max_connections as usize) {
            return None;
        }
        if !try_acquire(
            &self.unauthenticated,
            caps.max_unauthenticated_connections as usize,
        ) {
            self.release_connection();
            return None;
        }
        Some(Arc::new(LimiterSlot {
            limiter: self.clone(),
            unauthenticated: AtomicBool::new(true),
        }))
    }

    fn release_unauthenticated(&self) {
        self.unauthenticated.fetch_sub(1, Ordering::AcqRel);
    }

    fn release_connection(&self) {
        self.total.fetch_sub(1, Ordering::AcqRel);
    }

    /// Current bucket sizes (ops diagnostics; asserted by the tests).
    #[allow(dead_code)]
    pub fn in_flight(&self) -> (usize, usize) {
        (
            self.unauthenticated.load(Ordering::Acquire),
            self.total.load(Ordering::Acquire),
        )
    }
}

/// Increment a bounded counter without ever publishing a value above its
/// limit. A fetch-add followed by rollback briefly exceeds the cap under
/// contention and can admit too many simultaneous connections.
fn try_acquire(counter: &AtomicUsize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// One reserved connection slot; dropped when the connection ends.
#[derive(Debug)]
pub struct LimiterSlot {
    limiter: Arc<Limiter>,
    unauthenticated: AtomicBool,
}

/// Built-in cap for host processes. The slot is held by exactly one host
/// bridge, so a connection can open several independent channels without
/// allowing the aggregate host-process count to exceed the process default.
#[derive(Debug)]
pub(crate) struct HostProcessLimiter {
    cap: usize,
    in_flight: AtomicUsize,
}

impl HostProcessLimiter {
    pub(crate) fn new(caps: &Caps) -> HostProcessLimiter {
        HostProcessLimiter {
            cap: caps.max_host_processes as usize,
            in_flight: AtomicUsize::new(0),
        }
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Option<HostProcessSlot> {
        if !try_acquire(&self.in_flight, self.cap) {
            return None;
        }
        Some(HostProcessSlot {
            limiter: Arc::clone(self),
        })
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }
}

/// RAII admission slot for one running host process.
#[derive(Debug)]
pub(crate) struct HostProcessSlot {
    limiter: Arc<HostProcessLimiter>,
}

impl Drop for HostProcessSlot {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A boxed host-bridge future handed to [`HostTaskRegistry::track`].
pub(crate) type HostTaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Owns the join handles for host bridges that are spawned from russh handler
/// callbacks. Keeping the handles outside the connection task prevents a
/// daemon shutdown from dropping the Tokio runtime while a host process is
/// still in its TERM/KILL/reap sequence.
///
/// Tracking does not spawn a completion-wrapper task: the tracked bridge
/// carries a [`HostTaskGuard`] that removes its registry entry when the
/// bridge itself finishes, so one host process costs exactly one task.
#[derive(Debug, Default)]
pub(crate) struct HostTaskRegistry {
    tasks: std::sync::Mutex<HashMap<u64, HostTaskEntry>>,
    next_id: AtomicU64,
    closed: AtomicBool,
}

#[derive(Debug)]
struct HostTaskEntry {
    task: tokio::task::JoinHandle<()>,
    control: Arc<crate::ssh::host::HostProcessControl>,
}

/// Registry-entry cleanup embedded in the tracked bridge's own lifecycle.
struct HostTaskGuard {
    registry: std::sync::Weak<HostTaskRegistry>,
    id: u64,
}

impl Drop for HostTaskGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.complete(self.id);
        }
    }
}

impl HostTaskRegistry {
    pub(crate) fn track(
        self: &Arc<Self>,
        task: HostTaskFuture,
        control: Arc<crate::ssh::host::HostProcessControl>,
    ) -> Result<(), (HostTaskFuture, Arc<crate::ssh::host::HostProcessControl>)> {
        let mut tasks = self.tasks.lock().expect("host task registry");
        if self.closed.load(Ordering::Acquire) {
            return Err((task, control));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let guard = HostTaskGuard {
            registry: Arc::downgrade(self),
            id,
        };
        // Spawn while the registry lock is held: a bridge that finishes
        // immediately removes its entry through this same mutex, so the
        // insert below always happens before that removal can observe it.
        let task_handle = tokio::spawn(async move {
            task.await;
            drop(guard);
        });
        tasks.insert(
            id,
            HostTaskEntry {
                task: task_handle,
                control,
            },
        );
        Ok(())
    }

    fn complete(&self, id: u64) {
        self.tasks.lock().expect("host task registry").remove(&id);
    }

    pub(crate) fn close(&self) {
        let _tasks = self.tasks.lock().expect("host task registry");
        self.closed.store(true, Ordering::Release);
    }

    pub(crate) fn force_stop(&self) {
        let tasks = self.tasks.lock().expect("host task registry");
        for task in tasks.values() {
            task.control.force_terminate();
        }
    }

    pub(crate) async fn join_all(&self) {
        self.close();
        loop {
            let tasks = {
                let mut tasks = self.tasks.lock().expect("host task registry");
                tasks
                    .drain()
                    .map(|(_, entry)| entry.task)
                    .collect::<Vec<_>>()
            };
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }
}

impl LimiterSlot {
    /// The connection authenticated: it leaves the unauthenticated bucket but
    /// keeps occupying the total connection cap.
    pub fn authenticated(&self) {
        if self.unauthenticated.swap(false, Ordering::AcqRel) {
            self.limiter.release_unauthenticated();
        }
    }
}

impl Drop for LimiterSlot {
    fn drop(&mut self) {
        if self.unauthenticated.swap(false, Ordering::AcqRel) {
            self.limiter.release_unauthenticated();
        }
        self.limiter.release_connection();
    }
}

/// The running SSH server.
pub struct SshServer {
    shared: crate::ssh::Shared,
    /// Transport configuration, identical for every connection: built once
    /// here so each accepted connection shares one `Arc` instead of
    /// re-copying the host key.
    transport: Arc<Config>,
    limiter: Arc<Limiter>,
    host_process_limiter: Arc<HostProcessLimiter>,
    host_tasks: Arc<HostTaskRegistry>,
    caps: Caps,
}

impl SshServer {
    /// Build the server: the russh transport configuration derives from the
    /// host key and the built-in caps. The shared state is fixed for the
    /// process lifetime; the accepted-key set updates itself inside
    /// [`crate::auth::KeyStore`] at authentication time.
    pub fn new(shared: crate::ssh::Shared, host_key: russh::keys::PrivateKey) -> SshServer {
        let caps = Caps::default();
        let mut methods = MethodSet::empty();
        // Public-key only: none/password/keyboard-interactive and everything
        // else are refused before they can even be attempted.
        methods.push(MethodKind::PublicKey);
        let transport = Arc::new(Config {
            methods,
            keys: vec![host_key],
            max_auth_attempts: caps.max_auth_attempts as usize,
            // No idle timeout: authenticated connections may sit idle.
            inactivity_timeout: None,
            // Fail visibly when a rejected client idles through the
            // handshake window; the rejection delay applies per attempt.
            auth_rejection_time: Duration::from_millis(250),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            ..Default::default()
        });
        SshServer {
            shared,
            transport,
            limiter: Arc::new(Limiter::new(&caps)),
            host_process_limiter: Arc::new(HostProcessLimiter::new(&caps)),
            host_tasks: Arc::new(HostTaskRegistry::default()),
            caps,
        }
    }

    /// Force-kill host process groups when a second shutdown signal bypasses
    /// the normal server task. The bridge/waiter tasks may still be detached,
    /// but no host process is allowed to continue running after this call.
    pub(crate) fn force_stop_host_tasks(&self) {
        self.host_tasks.close();
        self.host_tasks.force_stop();
    }

    /// Serve until the shutdown signal fires. `listeners` are already bound,
    /// all-or-nothing, by [`bind_all`]. Every transport feeds the same SSH
    /// session handling path; authentication and sandbox selection never
    /// depend on the transport a connection arrived over.
    pub async fn serve(
        self: Arc<Self>,
        listeners: Vec<BoundListener>,
        shutdown: watch::Receiver<bool>,
    ) {
        let mut listener_tasks = tokio::task::JoinSet::new();
        for listener in listeners {
            let server = self.clone();
            let mut shutdown_rx = shutdown.clone();
            listener_tasks.spawn(async move {
                let mut connection_tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        accepted = listener.accept() => match accepted {
                            Ok((stream, peer, local)) => {
                                if *shutdown_rx.borrow() {
                                    drop(stream);
                                    break;
                                }
                                let connection_server = server.clone();
                                let connection_shutdown = shutdown_rx.clone();
                                connection_tasks.spawn(async move {
                                    connection_server
                                        .handle_connection(stream, peer, local, connection_shutdown)
                                        .await;
                                });
                            }
                            Err(err) => {
                                // Transient failures (EMFILE/ENFILE under fd
                                // pressure, ECONNABORTED from a client that
                                // vanished mid-handshake) must not silently
                                // kill this transport while the daemon keeps
                                // running. Pause briefly and keep accepting;
                                // only shutdown ends the loop.
                                tracing::warn!(error = %err, "listener accept failed");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        },
                    }
                }
                while connection_tasks.join_next().await.is_some() {}
            });
        }
        let mut shutdown_rx = shutdown.clone();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    self.host_tasks.close();
                    // Stop sandbox processes before waiting for connection
                    // tasks. Their channel bridges may otherwise be waiting
                    // on a child that no longer has a client transport.
                    let manager = Arc::clone(&self.shared.sandbox);
                    let _ = tokio::task::spawn_blocking(move || manager.shutdown_runtime()).await;
                    while listener_tasks.join_next().await.is_some() {}
                    break;
                }
                joined = listener_tasks.join_next() => {
                    if joined.is_none() {
                        break;
                    }
                }
            }
        }
        self.host_tasks.join_all().await;
    }

    /// Admit, supervise, and run one connection over any transport's byte
    /// stream; TCP and WebSocket connections are indistinguishable from here
    /// on.
    async fn handle_connection<S>(
        self: Arc<Self>,
        stream: S,
        peer: Option<std::net::SocketAddr>,
        local: Option<std::net::SocketAddr>,
        mut shutdown: watch::Receiver<bool>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if *shutdown.borrow() {
            return;
        }
        let shared = self.shared.clone();
        let Some(slot) = self.limiter.admit() else {
            tracing::debug!(?peer, "connection cap reached; refusing connection");
            return; // Dropping the stream is the resource-exhaustion refusal.
        };
        let caps = self.caps;
        let conn = Arc::new(crate::ssh::ConnState {
            principal: std::sync::Mutex::new(None),
            connection_environment: crate::ssh::connection_environment(peer, local),
            authenticated: Arc::new(Notify::new()),
            registry: crate::ssh::channel::ChannelRegistry::new(),
            host_process_limiter: Arc::clone(&self.host_process_limiter),
            host_tasks: Arc::clone(&self.host_tasks),
            shutdown: shutdown.clone(),
            unauth_slot: slot,
        });
        let handler = ConnHandler::new(shared, conn.clone());
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(caps.handshake_timeout_secs as u64);
        let transport_config = Arc::clone(&self.transport);
        let session = tokio::select! {
            result = tokio::time::timeout_at(
                deadline,
                server::run_stream(transport_config, stream, handler),
            ) => match result {
                Ok(Ok(session)) => session,
                Ok(Err(err)) => {
                    tracing::debug!(?peer, "connection setup failed: {err}");
                    return;
                }
                Err(_) => {
                    tracing::debug!(?peer, "handshake timed out");
                    return;
                }
            },
            _ = shutdown.changed() => {
                return;
            }
        };
        let mut session = std::pin::pin!(session);
        // Supervise the handshake window; it ends at the first successful
        // authentication. Authenticated connections are never idle-kicked.
        let mut authenticated = conn.principal().is_some();
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::debug!(?peer, "shutdown: disconnecting SSH session");
                    let _ = session
                        .handle()
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "server shutting down".into(),
                            String::new(),
                        )
                        .await;
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut session).await;
                    break;
                }
                _ = conn.authenticated.notified(), if !authenticated => {
                    authenticated = true;
                }
                _ = tokio::time::sleep_until(deadline), if !authenticated => {
                    if conn.principal().is_none() {
                        tracing::debug!(?peer, "handshake timeout; disconnecting");
                        let _ = session
                            .handle()
                            .disconnect(
                                russh::Disconnect::ByApplication,
                                "handshake timeout".into(),
                                String::new(),
                            )
                            .await;
                        // Give the session a moment to deliver the message.
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            &mut session,
                        )
                        .await;
                    }
                    break;
                }
                _ = &mut session => break,
            }
        }
    }
}

/// One bound listener. Each transport adapts its accepted TCP connection
/// into the shared boxed SSH byte stream before session handling.
pub enum BoundListener {
    #[cfg(feature = "tcp")]
    Tcp(TcpListener),

    #[cfg(feature = "ws")]
    WebSocket { listener: TcpListener, path: String },
}

impl std::fmt::Debug for BoundListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundListener")
            .field("local_addr", &self.local_addr())
            .finish()
    }
}

/// The byte stream every transport hands to the SSH engine.
pub type SshStream = Box<dyn AsyncReadWrite>;

/// Object-safe alias for the stream contract `russh::server::run_stream`
/// accepts.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

impl BoundListener {
    /// Accept one connection and adapt it to the shared SSH byte stream.
    /// WebSocket connections complete their upgrade here; a failed upgrade
    /// is logged and surfaces as an accept error for that one connection.
    pub async fn accept(
        &self,
    ) -> std::io::Result<(
        SshStream,
        Option<std::net::SocketAddr>,
        Option<std::net::SocketAddr>,
    )> {
        match self {
            #[cfg(feature = "tcp")]
            BoundListener::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                let local = stream.local_addr().ok();
                Ok((Box::new(stream), Some(peer), local))
            }
            #[cfg(feature = "ws")]
            BoundListener::WebSocket { listener, path } => {
                // A refused upgrade (probe, wrong path, missing subprotocol)
                // ends that one connection; the listener itself keeps
                // serving.
                loop {
                    let (stream, peer) = listener.accept().await?;
                    let local = stream.local_addr().ok();
                    match crate::ws::upgrade(stream, path, Some(peer)).await {
                        Ok(stream) => {
                            return Ok((Box::new(stream), Some(peer), local));
                        }
                        Err(_) => continue,
                    }
                }
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("no transport feature"),
        }
    }

    /// The bound local address, for startup logging.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            #[cfg(feature = "tcp")]
            BoundListener::Tcp(listener) => listener.local_addr(),
            #[cfg(feature = "ws")]
            BoundListener::WebSocket { listener, .. } => listener.local_addr(),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no transport feature"),
        }
    }
}

/// Bind every configured endpoint or none of them.
pub async fn bind_all(endpoints: &[ListenEndpoint]) -> Result<Vec<BoundListener>, Error> {
    let mut bound = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let address = endpoint.address();
        match TcpListener::bind(address).await {
            Ok(listener) => {
                let bound_listener = match endpoint {
                    #[cfg(feature = "tcp")]
                    ListenEndpoint::Tcp { .. } => BoundListener::Tcp(listener),
                    #[cfg(feature = "ws")]
                    ListenEndpoint::WebSocket { path, .. } => BoundListener::WebSocket {
                        listener,
                        path: path.clone(),
                    },
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("no transport feature"),
                };
                bound.push(bound_listener);
            }
            Err(source) => {
                // All-or-nothing: drop what already bound and report.
                drop(bound);
                return Err(Error::Bind { address, source });
            }
        }
    }
    Ok(bound)
}

/// Listener errors.
#[derive(Debug)]
pub enum Error {
    Bind {
        address: std::net::SocketAddr,
        source: std::io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bind { address, source } => {
                write!(f, "cannot bind listen address {address}: {source}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Bind { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Caps;
    #[cfg(feature = "tcp")]
    use std::net::SocketAddr;

    fn limiter(caps: &Caps) -> Arc<Limiter> {
        Arc::new(Limiter::new(caps))
    }

    #[test]
    fn admits_up_to_the_connection_cap() {
        let caps = Caps {
            max_connections: 2,
            max_unauthenticated_connections: 8,
            ..Caps::default()
        };
        let limiter = limiter(&caps);
        let _a = limiter.admit().expect("first");
        let _b = limiter.admit().expect("second");
        assert!(limiter.admit().is_none(), "third must hit the cap");
        drop(_a);
        assert!(limiter.admit().is_some(), "released slot is reusable");
    }

    #[test]
    fn admits_up_to_the_unauthenticated_cap() {
        let caps = Caps {
            max_connections: 8,
            max_unauthenticated_connections: 2,
            ..Caps::default()
        };
        let limiter = limiter(&caps);
        let _a = limiter.admit().expect("first");
        let _b = limiter.admit().expect("second");
        assert!(limiter.admit().is_none(), "unauth cap hit");
        _a.authenticated();
        // Authenticated connections leave the unauth bucket but keep their
        // total slot; the freed unauth slot admits a new connection.
        assert!(limiter.admit().is_some());
    }

    #[test]
    fn slots_release_both_buckets_on_drop() {
        let caps = Caps::default();
        let limiter = limiter(&caps);
        let slot = limiter.admit().expect("admit");
        drop(slot);
        let (unauth, total) = limiter.in_flight();
        assert_eq!((unauth, total), (0, 0));
    }

    #[test]
    fn host_process_cap_is_bounded_without_evicting_existing_slots() {
        let caps = Caps {
            max_host_processes: 2,
            ..Caps::default()
        };
        let limiter = Arc::new(HostProcessLimiter::new(&caps));
        let first = limiter.admit().expect("first host process");
        let second = limiter.admit().expect("second host process");
        assert!(limiter.admit().is_none(), "host cap must be enforced");
        assert_eq!(limiter.in_flight(), 2);
        drop(first);
        assert_eq!(limiter.in_flight(), 1);
        assert!(limiter.admit().is_some(), "released slot is reusable");
        drop(second);
    }

    #[test]
    fn bind_all_is_all_or_nothing() {
        #[cfg(feature = "tcp")]
        {
            let holder =
                std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("holder");
            let occupied = holder.local_addr().expect("addr");
            let endpoints = [
                ListenEndpoint::Tcp {
                    address: SocketAddr::from(([127, 0, 0, 1], 0)),
                },
                ListenEndpoint::Tcp { address: occupied },
            ];
            let err = tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(async { bind_all(&endpoints).await.expect_err("occupied address") });
            let Error::Bind { address, .. } = &err;
            assert_eq!(address, &occupied);
        }
    }

    // ---- Performance baseline (M1) ----

    /// Tracking one host bridge must not multiply Tokio tasks: the bridge
    /// removes its own registry entry through an embedded guard, so one
    /// tracked task costs exactly one task (M6).
    #[tokio::test]
    async fn tracked_host_task_cost_is_one_task() {
        let registry = Arc::new(HostTaskRegistry::default());
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let control = Arc::new(crate::ssh::host::HostProcessControl::for_tests());
        let before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let tracked = registry.track(
            Box::pin(async move {
                let _ = gate_rx.await;
            }),
            Arc::clone(&control),
        );
        assert!(tracked.is_ok(), "tracking must succeed before close");
        let after = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        println!(
            "tracked host task cost: {} tokio tasks per tracked task",
            after - before
        );
        assert_eq!(
            after - before,
            1,
            "tracking must not spawn a completion-wrapper task"
        );

        drop(gate_tx);
        registry.join_all().await;
        let settled = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(
            settled, before,
            "completion removes the tracked entry and its task"
        );
    }

    /// A bridge tracked after the registry closed still runs to completion:
    /// `track` hands the future back and the caller drives it, so shutdown
    /// cannot leak a half-cleaned host process.
    #[tokio::test]
    async fn track_after_close_returns_the_future_for_the_caller_to_run() {
        let registry = Arc::new(HostTaskRegistry::default());
        let control = Arc::new(crate::ssh::host::HostProcessControl::for_tests());
        registry.close();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let task: HostTaskFuture = Box::pin(async move {
            let _ = done_tx.send("ran");
        });
        let Err((mut task, control)) = registry.track(task, control) else {
            panic!("closed registry must refuse tracking");
        };
        control.force_terminate();
        task.as_mut().await;
        assert_eq!(done_rx.await.expect("bridge ran"), "ran");
    }
}
