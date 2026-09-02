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

/// The failure class of an endpoint parse. Each variant keeps the input text
/// so diagnostics survive, while callers can still distinguish classes —
/// e.g. a feature-not-compiled failure is a build problem, not a config typo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// No `scheme://` prefix at all.
    MissingScheme { input: String },
    /// The transport parsed but the address or path portion is malformed.
    Malformed { input: String, detail: String },
    /// The scheme names a transport that was not compiled in. Only
    /// constructible in builds missing the feature, hence the allow.
    #[allow(dead_code)]
    FeatureNotCompiled { input: String, scheme: String },
    /// The scheme is not a transport shbox knows.
    UnknownScheme { input: String, scheme: String },
    /// `wss://` is intentionally not supported.
    WssRefused { input: String },
}

impl EndpointError {
    fn missing_scheme(input: impl Into<String>) -> Self {
        EndpointError::MissingScheme {
            input: input.into(),
        }
    }

    fn malformed(input: impl Into<String>, detail: impl Into<String>) -> Self {
        EndpointError::Malformed {
            input: input.into(),
            detail: detail.into(),
        }
    }

    #[allow(dead_code)]
    fn feature_not_compiled(input: impl Into<String>, scheme: impl Into<String>) -> Self {
        EndpointError::FeatureNotCompiled {
            input: input.into(),
            scheme: scheme.into(),
        }
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointError::MissingScheme { input } => write!(
                f,
                "listen endpoint {input:?} must be a transport URI like \
                 tcp://0.0.0.0:22 or ws://0.0.0.0:8080/ssh"
            ),
            EndpointError::Malformed { input, detail } => {
                write!(f, "listen endpoint {input:?}: {detail}")
            }
            EndpointError::FeatureNotCompiled { input, scheme } => write!(
                f,
                "listen endpoint {input:?} uses {scheme} transport, but shbox was \
                 built without the `{scheme}` feature"
            ),
            EndpointError::UnknownScheme { input, scheme } => write!(
                f,
                "listen endpoint {input:?}: unknown transport scheme {scheme:?} \
                 (expected tcp or ws)"
            ),
            EndpointError::WssRefused { input } => write!(
                f,
                "listen endpoint {input:?}: wss:// is not supported; terminate TLS \
                 at a reverse proxy and use ws://"
            ),
        }
    }
}

impl std::error::Error for EndpointError {}

impl FromStr for ListenEndpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = value
            .split_once("://")
            .ok_or_else(|| EndpointError::missing_scheme(value))?;
        match scheme {
            "tcp" => parse_tcp(rest, value),
            "ws" => parse_ws(rest, value),
            "wss" => Err(EndpointError::WssRefused {
                input: value.to_string(),
            }),
            other => Err(EndpointError::UnknownScheme {
                input: value.to_string(),
                scheme: other.to_string(),
            }),
        }
    }
}

fn bad_address(value: &str, rest: &str) -> EndpointError {
    EndpointError::malformed(
        value,
        format!("{rest:?} is not a valid host:port socket address"),
    )
}

#[cfg(feature = "tcp")]
fn parse_tcp(rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    if rest.contains('/') {
        return Err(EndpointError::malformed(
            value,
            "tcp endpoints carry no path",
        ));
    }
    let address = SocketAddr::from_str(rest).map_err(|_| bad_address(value, rest))?;
    Ok(ListenEndpoint::Tcp { address })
}

#[cfg(not(feature = "tcp"))]
fn parse_tcp(_rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    Err(EndpointError::feature_not_compiled(value, "tcp"))
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
        return Err(EndpointError::malformed(
            value,
            "query parameters are not part of the WebSocket transport",
        ));
    }
    if path.contains('#') || path.bytes().any(|byte| byte == 0) {
        return Err(EndpointError::malformed(value, "invalid WebSocket path"));
    }
    if path != "/" && (!path.starts_with('/') || path.split('/').any(|segment| segment == "..")) {
        return Err(EndpointError::malformed(
            value,
            format!("invalid WebSocket path {path:?}"),
        ));
    }
    let address = SocketAddr::from_str(authority).map_err(|_| bad_address(value, rest))?;
    Ok(ListenEndpoint::WebSocket { address, path })
}

#[cfg(not(feature = "ws"))]
fn parse_ws(_rest: &str, value: &str) -> Result<ListenEndpoint, EndpointError> {
    Err(EndpointError::feature_not_compiled(value, "ws"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_endpoints_parse() {
        #[cfg(feature = "tcp")]
        {
            let endpoint = ListenEndpoint::from_str("tcp://127.0.0.1:2222").expect("tcp parses");
            assert_eq!(
                endpoint,
                ListenEndpoint::Tcp {
                    address: SocketAddr::from(([127, 0, 0, 1], 2222))
                }
            );
            assert_eq!(endpoint.to_string(), "tcp://127.0.0.1:2222");
            assert!(ListenEndpoint::from_str("tcp://[::1]:22").is_ok());
        }
        #[cfg(not(feature = "tcp"))]
        {
            let err =
                ListenEndpoint::from_str("tcp://127.0.0.1:2222").expect_err("tcp not compiled in");
            assert!(
                matches!(err, EndpointError::FeatureNotCompiled { .. }),
                "{err}"
            );
        }
    }

    #[test]
    fn ws_endpoints_parse() {
        #[cfg(feature = "ws")]
        {
            let endpoint = ListenEndpoint::from_str("ws://127.0.0.1:8080/ssh").expect("ws parses");
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
                ListenEndpoint::from_str("ws://127.0.0.1:8080").expect("root"),
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
                assert!(ListenEndpoint::from_str(bad).is_err(), "{bad}");
            }
        }
        #[cfg(not(feature = "ws"))]
        {
            let err = ListenEndpoint::from_str("ws://127.0.0.1:8080/ssh")
                .expect_err("ws not compiled in");
            assert!(
                matches!(err, EndpointError::FeatureNotCompiled { .. }),
                "{err}"
            );
        }
    }

    #[test]
    fn malformed_and_unknown_schemes_are_rejected() {
        let missing_scheme = ListenEndpoint::from_str("127.0.0.1:2222").expect_err("no scheme");
        assert!(matches!(
            missing_scheme,
            EndpointError::MissingScheme { .. }
        ));
        let unknown = ListenEndpoint::from_str("unix:///tmp/sock").expect_err("unknown scheme");
        assert!(matches!(unknown, EndpointError::UnknownScheme { scheme, .. } if scheme == "unix"));
        let wss = ListenEndpoint::from_str("wss://example.com/ssh").expect_err("wss refused");
        assert!(matches!(wss, EndpointError::WssRefused { .. }));
        for bad in [
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:2222/extra",
            "ws://not-an-address/ssh",
            "",
            "tcp://",
        ] {
            assert!(ListenEndpoint::from_str(bad).is_err(), "{bad}");
        }
    }
}
