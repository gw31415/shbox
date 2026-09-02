//! Transport-qualified listen endpoints (`tcp://…`, `ws://…`).
//!
//! `listen` configuration is a list of endpoint URIs rather than raw socket
//! addresses. Parsing is feature-aware and fail-closed: an endpoint whose
//! transport was not compiled in is an explicit error, never a silent
//! fallback to another transport. The URI never carries application
//! semantics — sandbox selection lives entirely in the SSH username.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// One configured listener endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListenEndpoint {
    #[cfg(feature = "tcp")]
    Tcp { address: SocketAddr },

    #[cfg(feature = "ws")]
    WebSocket { address: SocketAddr, path: String },
}

impl ListenEndpoint {
    /// The socket address every transport variant binds.
    pub fn address(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "tcp")]
            ListenEndpoint::Tcp { address } => *address,
            #[cfg(feature = "ws")]
            ListenEndpoint::WebSocket { address, .. } => *address,
            // Unreachable in transport-less builds, which fail to compile.
            #[allow(unreachable_patterns)]
            _ => unreachable!("no transport feature"),
        }
    }
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "tcp")]
            ListenEndpoint::Tcp { address } => write!(f, "tcp://{address}"),
            #[cfg(feature = "ws")]
            ListenEndpoint::WebSocket { address, path } => write!(f, "ws://{address}{path}"),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no transport feature"),
        }
    }
}

/// Parse failures carry an operator-facing diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointError(pub String);

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EndpointError {}

impl FromStr for ListenEndpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = value.split_once("://").ok_or_else(|| {
            EndpointError(format!(
                "listen endpoint {value:?} must be a transport URI like tcp://0.0.0.0:22 or ws://0.0.0.0:8080/ssh"
            ))
        })?;
        match scheme {
            "tcp" => parse_tcp(rest, value),
            "ws" => parse_ws(rest, value),
            "wss" => Err(EndpointError(format!(
                "listen endpoint {value:?}: wss:// is not supported; terminate TLS at a reverse proxy and use ws://"
            ))),
            other => Err(EndpointError(format!(
                "listen endpoint {value:?}: unknown transport scheme {other:?} (expected tcp or ws)"
            ))),
        }
    }
}

fn bad_address(value: &str, rest: &str) -> EndpointError {
    EndpointError(format!(
        "listen endpoint {value:?}: {rest:?} is not a valid host:port socket address"
    ))
}

#[cfg(feature = "tcp")]
fn parse_tcp(rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    if rest.contains('/') {
        return Err(EndpointError(format!(
            "listen endpoint {value:?}: tcp endpoints carry no path"
        )));
    }
    let address = SocketAddr::from_str(rest).map_err(|_| bad_address(value, rest))?;
    Ok(ListenEndpoint::Tcp { address })
}

#[cfg(not(feature = "tcp"))]
fn parse_tcp(_rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    Err(EndpointError(format!(
        "listen endpoint {value:?} uses tcp transport, but shbox was built without the `tcp` feature"
    )))
}

#[cfg(feature = "ws")]
fn parse_ws(rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(bad_address(value, rest));
    }
    if path.contains('?') {
        return Err(EndpointError(format!(
            "listen endpoint {value:?}: query parameters are not part of the WebSocket transport"
        )));
    }
    if path.contains('#') || path.bytes().any(|byte| byte == 0) {
        return Err(EndpointError(format!(
            "listen endpoint {value:?}: invalid WebSocket path"
        )));
    }
    if path != "/" && (!path.starts_with('/') || path.split('/').any(|segment| segment == "..")) {
        return Err(EndpointError(format!(
            "listen endpoint {value:?}: invalid WebSocket path {path:?}"
        )));
    }
    let address = SocketAddr::from_str(authority).map_err(|_| bad_address(value, rest))?;
    Ok(ListenEndpoint::WebSocket { address, path })
}

#[cfg(not(feature = "ws"))]
fn parse_ws(_rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    Err(EndpointError(format!(
        "listen endpoint {value:?} uses ws transport, but shbox was built without the `ws` feature"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> Result<ListenEndpoint, String> {
        ListenEndpoint::from_str(value).map_err(|err| err.0)
    }

    #[test]
    fn tcp_endpoints_parse() {
        #[cfg(feature = "tcp")]
        {
            let endpoint = parse("tcp://127.0.0.1:2222").expect("tcp parses");
            assert_eq!(
                endpoint,
                ListenEndpoint::Tcp {
                    address: SocketAddr::from(([127, 0, 0, 1], 2222))
                }
            );
            assert_eq!(endpoint.to_string(), "tcp://127.0.0.1:2222");
            assert!(parse("tcp://[::1]:22").is_ok());
        }
        #[cfg(not(feature = "tcp"))]
        {
            let message = parse("tcp://127.0.0.1:2222").expect_err("tcp not compiled in");
            assert!(message.contains("without the `tcp` feature"), "{message}");
        }
    }

    #[test]
    fn ws_endpoints_parse() {
        #[cfg(feature = "ws")]
        {
            let endpoint = parse("ws://127.0.0.1:8080/ssh").expect("ws parses");
            assert_eq!(
                endpoint,
                ListenEndpoint::WebSocket {
                    address: SocketAddr::from(([127, 0, 0, 1], 8080)),
                    path: "/ssh".to_string(),
                }
            );
            assert_eq!(endpoint.to_string(), "ws://127.0.0.1:8080/ssh");
            // No path means the endpoint root; query parameters are refused.
            assert_eq!(
                parse("ws://127.0.0.1:8080").expect("root"),
                ListenEndpoint::WebSocket {
                    address: SocketAddr::from(([127, 0, 0, 1], 8080)),
                    path: "/".to_string(),
                }
            );
            for bad in [
                "ws://127.0.0.1:8080/ssh?sandbox=x",
                "ws://127.0.0.1:8080/../etc",
                "ws://127.0.0.1:8080/\u{0}",
            ] {
                assert!(parse(bad).is_err(), "{bad}");
            }
        }
        #[cfg(not(feature = "ws"))]
        {
            let message = parse("ws://127.0.0.1:8080/ssh").expect_err("ws not compiled in");
            assert!(message.contains("without the `ws` feature"), "{message}");
        }
    }

    #[test]
    fn malformed_and_unknown_schemes_are_rejected() {
        for bad in [
            "127.0.0.1:2222",
            "unix:///tmp/sock",
            "wss://example.com/ssh",
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:2222/extra",
            "ws://not-an-address/ssh",
            "",
            "tcp://",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
