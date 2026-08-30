//! Per-connection and per-channel SSH handling.
//!
//! The connection handler implements the small russh surface shbox accepts:
//! public-key authentication only, session channels only, one terminal
//! operation per channel, and an explicit rejection for every request the
//! v0.1 contract does not implement (forwarding, agent, X11, `env`, SFTP,
//! unknown subsystems).

pub(crate) mod channel;
pub(crate) mod host;

use std::sync::Arc;

use russh::server::{Auth, Session};
use russh::{ChannelId, Pty};

use crate::account::Account;
use crate::auth::{AuthSnapshot, Principal, Role};
use crate::config::Config;
use crate::sandbox::SandboxId;

use channel::{ChannelEvent, ChannelOperation, ChannelRegistry};

/// Immutable state shared by all connections, captured per connection so a
/// later reload can only affect new connections.
#[derive(Debug, Clone)]
pub(crate) struct Shared {
    pub auth: Arc<AuthSnapshot>,
    pub config: Arc<Config>,
    pub account: Arc<Account>,
}

/// Per-connection state; the authenticated principal is fixed once set.
#[derive(Debug)]
pub(crate) struct ConnState {
    pub principal: std::sync::Mutex<Option<Principal>>,
    /// Fired exactly when authentication succeeds; the listener watchdog
    /// stops the handshake timer on this.
    pub authenticated: Arc<tokio::sync::Notify>,
    pub registry: ChannelRegistry,
    /// Tracks the connection in the unauthenticated bucket until auth.
    pub unauth_slot: std::sync::Arc<crate::server::LimiterSlot>,
}

impl ConnState {
    pub fn principal(&self) -> Option<Principal> {
        self.principal.lock().expect("principal mutex").clone()
    }
}

/// The russh connection handler.
pub(crate) struct ConnHandler {
    pub shared: Shared,
    pub conn: Arc<ConnState>,
    /// The username presented at authentication time (selector context).
    pub username: Option<String>,
}

/// Where an approved selector routes.
enum Route {
    Host,
    Sandbox(SandboxId),
}

/// Why a selector route is refused. The client always sees the same generic
/// failure; nothing about roles or existence is revealed.
#[derive(Debug)]
enum RouteRejection {
    NotAuthorized,
    InvalidSelector,
}

impl ConnHandler {
    pub fn new(shared: Shared, conn: Arc<ConnState>) -> ConnHandler {
        ConnHandler {
            shared,
            conn,
            username: None,
        }
    }

    /// Classify the username into a route for terminal operations.
    fn route(&self, username: &str) -> Result<Route, RouteRejection> {
        let Some(principal) = self.conn.principal() else {
            return Err(RouteRejection::NotAuthorized);
        };
        if username == "_" {
            if principal.role == Role::Admin {
                Ok(Route::Host)
            } else {
                Err(RouteRejection::NotAuthorized)
            }
        } else {
            match SandboxId::parse(username) {
                Ok(id) => Ok(Route::Sandbox(id)),
                Err(_) => Err(RouteRejection::InvalidSelector),
            }
        }
    }

    /// The sandbox placeholder response until Milestones 3-4 wire sandbox
    /// operations: the channel completes with a generic non-zero exit.
    async fn sandbox_unavailable(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), crate::server::HandlerError> {
        let _ = session.extended_data(channel, 1, format!("{}\r\n", UNAVAILABLE_MESSAGE));
        let _ = session.eof(channel);
        let _ = session.exit_status_request(channel, UNAVAILABLE_EXIT);
        let _ = session.close(channel);
        self.conn.registry.remove(channel);
        Ok(())
    }

    /// Complete a validated but not-yet-implemented operation without
    /// acknowledging a second operation on the same channel.
    async fn start_sandbox_unavailable(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), crate::server::HandlerError> {
        if self.conn.registry.pty(channel).is_some() || self.conn.registry.start(channel).is_none()
        {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        self.sandbox_unavailable(channel, session).await
    }

    /// Approve the single terminal operation for a channel and dispatch it.
    async fn start_operation(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        operation: ChannelOperation,
    ) -> Result<(), crate::server::HandlerError> {
        let username = self.username.clone().unwrap_or_default();
        match self.route(&username) {
            Err(rejection) => {
                tracing::debug!(?rejection, "route refused");
                let _ = session.channel_failure(channel);
                Ok(())
            }
            Ok(Route::Host) => {
                let pty = self
                    .conn
                    .registry
                    .with_state(channel, |state| state.pty.clone())
                    .unwrap_or(None);
                let request = channel::host_request(
                    &operation,
                    &self.shared.account.host_shell(),
                    &self.shared.account.home,
                    pty,
                );
                self.dispatch_host_channel(channel, session, request).await
            }
            Ok(Route::Sandbox(_id)) => {
                // A validated sandbox selector: intentionally unavailable
                // until the SandboxManager exists (Milestones 3-4).
                self.start_sandbox_unavailable(channel, session).await
            }
        }
    }

    /// Mark the channel started, confirm the request, and hand the channel
    /// to the bridge task.
    async fn dispatch_host_channel(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        request: host::HostRequest,
    ) -> Result<(), crate::server::HandlerError> {
        let Some(events) = self.conn.registry.start(channel) else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        // Do not acknowledge the request until fork/exec and PTY setup have
        // completed. A client-visible success must never be followed by a
        // spawn failure that was already known to the daemon.
        let (process, waiter) = match channel::spawn_host_process(request).await {
            Ok(process) => process,
            Err(err) => {
                tracing::warn!("host process spawn failed: {err}");
                let handle = session.handle();
                let _ = channel::finish_failed(channel, &handle).await;
                self.conn.registry.remove(channel);
                return Ok(());
            }
        };
        if session.channel_success(channel).is_err() {
            // The transport is already unavailable; stop the process rather
            // than leaving a waiter-owned child behind.
            process.signal_group(libc::SIGTERM);
            process.signal_group(libc::SIGKILL);
            drop(waiter);
            self.conn.registry.remove(channel);
            return Ok(());
        }
        let handle = session.handle();
        let conn = Arc::clone(&self.conn);
        tokio::spawn(async move {
            // The bridge task owns the channel end to end; the handler only
            // routes further client events into the mailbox.
            channel::run_host_process(channel, handle, process, waiter, events).await;
            conn.registry.remove(channel);
        });
        Ok(())
    }
}

impl russh::server::Handler for ConnHandler {
    type Error = crate::server::HandlerError;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Role assignment happens only here, after russh verified the
        // signature; offered-key probes never touch this state.
        let Some(principal) = self.shared.auth.authenticate(public_key) else {
            return Ok(Auth::reject());
        };
        if user == "_" && principal.role != Role::Admin {
            // The host selector is reserved for admin keys.
            return Ok(Auth::reject());
        }
        tracing::info!(
            fingerprint = %principal.fingerprint,
            role = ?principal.role,
            user = %user,
            "authenticated"
        );
        self.username = Some(user.to_string());
        *self.conn.principal.lock().expect("principal mutex") = Some(principal);
        self.conn.unauth_slot.authenticated();
        self.conn.authenticated.notify_one();
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cap = self.shared.config.caps().max_channels_per_connection as usize;
        if self.conn.registry.count() >= cap {
            let _ = reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        let id = channel.id();
        self.conn.registry.open(id);
        reply.accept().await;
        // The channel object is dropped on purpose: incoming client data is
        // delivered to the `data` callback, and the internal queue stays
        // empty so no unbounded buffering can accumulate there.
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _socket_path: &str,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if term.len() > MAX_TERM_BYTES || term.contains('\0') {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        let accepted = self.conn.registry.with_state(channel, |state| {
            if state.started || state.pty.is_some() {
                return false;
            }
            state.pty = Some(host::PtyRequest {
                term: term.to_string(),
                rows: row_height,
                cols: col_width,
            });
            true
        });
        if accepted == Some(true) {
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start_operation(channel, session, ChannelOperation::HostShell)
            .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.len() > host::MAX_COMMAND_BYTES {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        self.start_operation(
            channel,
            session,
            ChannelOperation::HostExec {
                command: data.to_vec(),
            },
        )
        .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name.len() > MAX_SUBSYSTEM_BYTES {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        match name {
            "list" => {
                // The SandboxManager arrives in Milestones 3-4; the route is
                // still validated and the channel is consumed exactly once.
                if self.conn.principal().is_none() {
                    let _ = session.channel_failure(channel);
                    return Ok(());
                }
                self.start_sandbox_unavailable(channel, session).await
            }
            "delete" => {
                // `_` is a host context, never a delete target. Other
                // selectors must be valid SandboxIds before they can reach
                // the later manager implementation.
                let username = self.username.clone().unwrap_or_default();
                if username == "_" || SandboxId::parse(&username).is_err() {
                    let _ = session.channel_failure(channel);
                    return Ok(());
                }
                self.start_sandbox_unavailable(channel, session).await
            }
            _ => {
                // SFTP and every unknown subsystem are rejected explicitly.
                let _ = session.channel_failure(channel);
                Ok(())
            }
        }
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client environment is never injected into host or sandbox
        // processes.
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // RFC 4254: normally want_reply=false, so no success/failure reply.
        // Without a PTY request the change is ignored without side effects.
        if self
            .conn
            .registry
            .update_window(channel, row_height, col_width)
        {
            self.conn.registry.try_send(
                channel,
                ChannelEvent::WindowChange {
                    rows: row_height,
                    cols: col_width,
                },
            );
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let name = sig_name(&signal);
        match host::signal_from_name(&name) {
            Some(number) => {
                self.conn
                    .registry
                    .try_send(channel, ChannelEvent::Signal(number));
                Ok(())
            }
            None => {
                // Unrecognized signal names are refused, never forwarded.
                Ok(())
            }
        }
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The SSH receive window supplies the normal flow-control boundary;
        // the local bounded mailbox is a final memory guard.
        if !self
            .conn
            .registry
            .try_send(channel, ChannelEvent::Data(data.to_vec()))
        {
            // The mailbox is deliberately bounded. Once it is full, closing
            // is safer than silently dropping user input or allowing memory
            // to grow without limit; normal traffic remains flow-controlled
            // by russh's receive window.
            let _ = session.close(channel);
            self.conn.registry.remove(channel);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let accepted = self.conn.registry.try_send(channel, ChannelEvent::Eof);
        if accepted {
            self.conn
                .registry
                .with_state(channel, |state| state.eof_from_client = true);
        } else {
            // A full mailbox must not lose the EOF silently.
            let _ = session.close(channel);
            self.conn.registry.remove(channel);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let started = self
            .conn
            .registry
            .with_state(channel, |state| state.started)
            .unwrap_or(false);
        if started {
            if !self.conn.registry.try_send(channel, ChannelEvent::Close) {
                // A full mailbox must not make channel close dependent on an
                // event that can never be delivered. Dropping the sender
                // wakes the bridge with `None` and triggers teardown.
                self.conn.registry.remove(channel);
            }
        } else {
            // A channel closed before its operation began has no bridge task
            // to perform this cleanup.
            self.conn.registry.remove(channel);
        }
        let _ = session;
        Ok(())
    }
}

/// Wire name for a received signal request.
fn sig_name(signal: &russh::Sig) -> String {
    match signal {
        russh::Sig::ABRT => "ABRT".into(),
        russh::Sig::ALRM => "ALRM".into(),
        russh::Sig::FPE => "FPE".into(),
        russh::Sig::HUP => "HUP".into(),
        russh::Sig::ILL => "ILL".into(),
        russh::Sig::INT => "INT".into(),
        russh::Sig::KILL => "KILL".into(),
        russh::Sig::PIPE => "PIPE".into(),
        russh::Sig::QUIT => "QUIT".into(),
        russh::Sig::SEGV => "SEGV".into(),
        russh::Sig::TERM => "TERM".into(),
        russh::Sig::USR1 => "USR1".into(),
        russh::Sig::Custom(name) => name.clone(),
    }
}

/// Maximum terminal type string accepted in `pty-req`.
const MAX_TERM_BYTES: usize = 256;
/// Maximum subsystem name length accepted.
const MAX_SUBSYSTEM_BYTES: usize = 64;
/// Generic stderr line used for unavailable operations.
const UNAVAILABLE_MESSAGE: &str = "shbox: request cannot be completed";
/// Generic non-zero exit status for unavailable operations.
const UNAVAILABLE_EXIT: u32 = 111;
