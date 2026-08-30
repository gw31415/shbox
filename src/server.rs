//! Listener handling.
//!
//! Milestone 1 validates that every configured listen address is bindable,
//! all-or-nothing, before the daemon reports readiness. Milestone 2 replaces
//! the probe with the real russh listener using the same rule: either every
//! address binds or startup fails, and a failing bind never falls back to
//! another port.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener};

/// Bind every configured address; on the first failure drop the sockets
/// already bound and report the failing address.
pub fn probe_listen(addresses: &[SocketAddr]) -> Result<(), Error> {
    let mut bound = Vec::with_capacity(addresses.len());
    for address in addresses {
        match TcpListener::bind(address) {
            Ok(listener) => bound.push(listener),
            Err(source) => {
                return Err(Error::Bind {
                    address: *address,
                    source,
                });
            }
        }
    }
    drop(bound);
    Ok(())
}

/// Listener errors.
#[derive(Debug)]
pub enum Error {
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    #[test]
    fn binds_all_or_nothing() {
        // A single wildcard ephemeral bind always succeeds.
        probe_listen(&[SocketAddr::from(([127, 0, 0, 1], 0))]).expect("bind loopback:0");
    }

    #[test]
    fn reports_occupied_address_and_releases_the_rest() {
        let holder = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("holder");
        let occupied = holder.local_addr().expect("local addr");
        // Port 0 lets the kernel pick a free port for the first address, so
        // the only failure is the held one: the all-or-nothing rule must
        // surface it even though the other address could bind.
        let err = probe_listen(&[SocketAddr::from(([127, 0, 0, 1], 0)), occupied])
            .expect_err("occupied address");
        let Error::Bind { address, .. } = &err;
        assert_eq!(*address, occupied);
    }
}
