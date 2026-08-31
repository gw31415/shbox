//! Listener binding, connection admission, and session supervision.
//!
//! Binding is all-or-nothing: either every configured address binds or
//! startup fails, and a failing bind never falls back to another port. Each
//! accepted TCP connection gets a handshake deadline that ends as soon as
//! authentication succeeds; authenticated connections have no idle timeout.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use russh::server::{self, Config};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

use crate::config::Caps;
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

/// Owns the join handles for host bridges that are spawned from russh handler
/// callbacks. Keeping the handles outside the connection task prevents a
/// daemon shutdown from dropping the Tokio runtime while a host process is
/// still in its TERM/KILL/reap sequence.
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

impl HostTaskRegistry {
    pub(crate) fn track(
        self: &Arc<Self>,
        task: tokio::task::JoinHandle<()>,
        control: Arc<crate::ssh::host::HostProcessControl>,
    ) -> Result<
        (),
        (
            tokio::task::JoinHandle<()>,
            Arc<crate::ssh::host::HostProcessControl>,
        ),
    > {
        let mut tasks = self.tasks.lock().expect("host task registry");
        if self.closed.load(Ordering::Acquire) {
            return Err((task, control));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let registry = Arc::clone(self);
        let wrapper = tokio::spawn(async move {
            let _ = task.await;
            registry.complete(id);
        });
        tasks.insert(
            id,
            HostTaskEntry {
                task: wrapper,
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
    shared: RwLock<crate::ssh::Shared>,
    host_key: russh::keys::PrivateKey,
    limiter: Arc<Limiter>,
    host_process_limiter: Arc<HostProcessLimiter>,
    host_tasks: Arc<HostTaskRegistry>,
    caps: Caps,
}

impl SshServer {
    /// Build the server: the russh transport configuration derives from the
    /// host key and the built-in caps.
    pub fn new(shared: crate::ssh::Shared, host_key: russh::keys::PrivateKey) -> SshServer {
        let caps = Caps::default();
        SshServer {
            shared: RwLock::new(shared),
            host_key,
            limiter: Arc::new(Limiter::new(&caps)),
            host_process_limiter: Arc::new(HostProcessLimiter::new(&caps)),
            host_tasks: Arc::new(HostTaskRegistry::default()),
            caps,
        }
    }

    /// Publish an all-or-nothing runtime snapshot for future connections.
    /// Existing handlers already own a clone of the previous `Shared` value.
    pub(crate) fn reload(&self, shared: crate::ssh::Shared) {
        let mut current = self.shared.write().expect("server shared state");
        *current = shared;
    }

    /// Force-kill host process groups when a second shutdown signal bypasses
    /// the normal server task. The bridge/waiter tasks may still be detached,
    /// but no host process is allowed to continue running after this call.
    pub(crate) fn force_stop_host_tasks(&self) {
        self.host_tasks.close();
        self.host_tasks.force_stop();
    }

    fn transport_config(&self, caps: &Caps) -> Arc<Config> {
        let mut methods = MethodSet::empty();
        // Public-key only: none/password/keyboard-interactive and everything
        // else are refused before they can even be attempted.
        methods.push(MethodKind::PublicKey);
        Arc::new(Config {
            methods,
            keys: vec![self.host_key.clone()],
            max_auth_attempts: caps.max_auth_attempts as usize,
            // No idle timeout: authenticated connections may sit idle.
            inactivity_timeout: None,
            // Fail visibly when a rejected client idles through the
            // handshake window; the rejection delay applies per attempt.
            auth_rejection_time: Duration::from_millis(250),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            ..Default::default()
        })
    }

    /// Serve until the shutdown signal fires. `sockets` are already bound,
    /// all-or-nothing, by [`bind_all`].
    pub async fn serve(
        self: Arc<Self>,
        sockets: Vec<TcpListener>,
        shutdown: watch::Receiver<bool>,
    ) {
        let mut listener_tasks = tokio::task::JoinSet::new();
        for socket in sockets {
            let server = self.clone();
            let mut shutdown_rx = shutdown.clone();
            listener_tasks.spawn(async move {
                let mut connection_tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        accepted = socket.accept() => match accepted {
                            Ok((stream, peer)) => {
                                if *shutdown_rx.borrow() {
                                    drop(stream);
                                    break;
                                }
                                let connection_server = server.clone();
                                let connection_shutdown = shutdown_rx.clone();
                                connection_tasks.spawn(async move {
                                    connection_server
                                        .handle_connection(stream, Some(peer), connection_shutdown)
                                        .await;
                                });
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "listener accept failed");
                                break;
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
                    let manager = self
                        .shared
                        .read()
                        .expect("server shared state")
                        .sandbox
                        .clone();
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

    /// Admit, supervise, and run one connection.
    async fn handle_connection(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
        peer: Option<std::net::SocketAddr>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        if *shutdown.borrow() {
            return;
        }
        let (shared, slot) = {
            let shared_guard = self.shared.read().expect("server shared state");
            let Some(slot) = self.limiter.admit() else {
                tracing::debug!(?peer, "connection cap reached; refusing connection");
                return; // Dropping the stream is the resource-exhaustion refusal.
            };
            (shared_guard.clone(), slot)
        };
        let caps = self.caps;
        let conn = Arc::new(crate::ssh::ConnState {
            principal: std::sync::Mutex::new(None),
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
        let transport_config = self.transport_config(&caps);
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

/// Bind every configured address or none of them.
pub async fn bind_all(addresses: &[std::net::SocketAddr]) -> Result<Vec<TcpListener>, Error> {
    let mut bound = Vec::with_capacity(addresses.len());
    for address in addresses {
        match TcpListener::bind(*address).await {
            Ok(listener) => bound.push(listener),
            Err(source) => {
                // All-or-nothing: drop what already bound and report.
                drop(bound);
                return Err(Error::Bind {
                    address: *address,
                    source,
                });
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
        let holder =
            std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("holder");
        let occupied = holder.local_addr().expect("addr");
        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                bind_all(&[SocketAddr::from(([127, 0, 0, 1], 0)), occupied])
                    .await
                    .expect_err("occupied address")
            });
        let Error::Bind { address, .. } = &err;
        assert_eq!(address, &occupied);
    }
}
