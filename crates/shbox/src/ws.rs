//! SSH-over-WebSocket transport adapter (`ws` feature).
//!
//! The WebSocket endpoint is only a byte pipe for the SSH stream: the client
//! must request the `ssh` subprotocol, frames are binary only, and there is
//! no second application protocol. Request paths must match the configured
//! listener path exactly; query parameters are never interpreted.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async};

/// The subprotocol token every client must request.
pub const SUBPROTOCOL: &str = "ssh";

/// Cap on one outbound WebSocket message; SSH writes larger than this are
/// split across messages. Receivers concatenate payloads in order.
const MAX_OUTBOUND_CHUNK: usize = 256 * 1024;

/// Perform the server side of the WebSocket upgrade on an accepted TCP
/// stream, enforcing the configured path and the `ssh` subprotocol, and
/// return the upgraded stream as a byte pipe.
// The handshake `Err` type's size is fixed by the tungstenite API.
#[allow(clippy::result_large_err)]
pub async fn upgrade(
    stream: TcpStream,
    expected_path: &str,
    peer: Option<std::net::SocketAddr>,
) -> std::io::Result<WsSshStream> {
    let path = expected_path.to_string();
    let callback =
        move |request: &Request, response: Response| validate_upgrade(request, response, &path);
    match accept_hdr_async(stream, callback).await {
        Ok(ws) => Ok(WsSshStream::new(ws)),
        Err(err) => {
            tracing::debug!(?peer, "websocket upgrade failed: {err}");
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("websocket upgrade failed: {err}"),
            ))
        }
    }
}

/// Check the request path and subprotocol, then confirm `ssh` in the
/// response headers so the client sees the selected subprotocol.
#[allow(clippy::result_large_err)]
fn validate_upgrade(
    request: &Request,
    mut response: Response,
    expected_path: &str,
) -> Result<Response, ErrorResponse> {
    let reject = |message: &str| -> ErrorResponse {
        let mut denied = Response::builder()
            .status(400)
            .body(Some(message.to_string()))
            .expect("static error response");
        denied.headers_mut().insert(
            "x-shbox-websocket-error",
            HeaderValue::from_str(message).unwrap_or(HeaderValue::from_static("rejected")),
        );
        denied
    };
    let request_path = request.uri().path();
    if request_path != expected_path {
        return Err(reject(
            "websocket path does not match the configured listener",
        ));
    }
    let offered = request
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let selects_ssh = offered
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(SUBPROTOCOL));
    if !selects_ssh {
        return Err(reject("websocket upgrade requires the \"ssh\" subprotocol"));
    }
    response.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(response)
}

/// A WebSocket stream presenting the raw SSH byte stream. Binary message
/// payloads are the received bytes in order; text frames are rejected, since
/// the SSH transport is not text.
pub struct WsSshStream {
    ws: WebSocketStream<TcpStream>,
    inbound: Vec<u8>,
}

impl WsSshStream {
    fn new(ws: WebSocketStream<TcpStream>) -> WsSshStream {
        WsSshStream {
            ws,
            inbound: Vec::new(),
        }
    }
}

impl AsyncRead for WsSshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.inbound.is_empty() {
                let copy = self.inbound.len().min(buf.remaining());
                let (head, tail) = self.inbound.split_at(copy);
                buf.put_slice(head);
                self.inbound = tail.to_vec();
                return Poll::Ready(Ok(()));
            }
            match self.ws.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err,
                    )));
                }
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(payload) => self.inbound.extend_from_slice(&payload),
                    Message::Text(_) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "websocket text frames are not part of the SSH transport",
                        )));
                    }
                    // Close/Ping/Pong are transport-level frames; Close ends
                    // the stream and control frames are handled by the
                    // protocol layer below.
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                },
            }
        }
    }
}

impl AsyncWrite for WsSshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(MAX_OUTBOUND_CHUNK);
        match self.ws.poll_ready_unpin(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(ws_io_error(err))),
            Poll::Ready(Ok(())) => {}
        }
        let frame = Message::Binary(buf[..len].to_vec().into());
        self.ws.start_send_unpin(frame).map_err(ws_io_error)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.ws.poll_flush_unpin(cx).map_err(ws_io_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.ws.poll_close_unpin(cx).map_err(ws_io_error)
    }
}

fn ws_io_error(err: WsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::http::Uri;

    fn upgrade_request(path: &str, protocols: Option<&str>) -> Request {
        let uri: Uri = path.parse().expect("uri");
        let mut builder = Request::builder().uri(uri);
        if let Some(protocols) = protocols {
            builder = builder.header("sec-websocket-protocol", protocols);
        }
        builder.body(()).expect("request")
    }

    #[test]
    fn upgrade_selects_the_ssh_subprotocol() {
        let request = upgrade_request("/ssh", Some("ssh"));
        let response =
            validate_upgrade(&request, Response::new(()), "/ssh").expect("upgrade allowed");
        assert_eq!(
            response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok()),
            Some("ssh")
        );
    }

    #[test]
    fn upgrade_accepts_ssh_among_other_tokens_case_insensitively() {
        for offered in ["ssh", "SSH, binary", "other, ssh"] {
            let request = upgrade_request("/ssh", Some(offered));
            assert!(
                validate_upgrade(&request, Response::new(()), "/ssh").is_ok(),
                "{offered}"
            );
        }
    }

    #[test]
    fn upgrade_rejects_wrong_path_or_missing_subprotocol() {
        // Wrong path, with the right subprotocol.
        let request = upgrade_request("/other", Some("ssh"));
        assert!(validate_upgrade(&request, Response::new(()), "/ssh").is_err());
        // Right path, no subprotocol offered.
        let request = upgrade_request("/ssh", None);
        assert!(validate_upgrade(&request, Response::new(()), "/ssh").is_err());
        // Right path, unrelated subprotocols only.
        let request = upgrade_request("/ssh", Some("chatv2, binary"));
        assert!(validate_upgrade(&request, Response::new(()), "/ssh").is_err());
    }
}
