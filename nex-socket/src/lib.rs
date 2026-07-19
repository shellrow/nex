//! Cross-platform low-level socket APIs for TCP, UDP and ICMP.
//!
//! `nex-socket` focuses on predictable, low-level behavior and platform-aware
//! socket option control.
//!
//! TCP, UDP, and ICMP use an infallible configuration value followed by a
//! fallible socket constructor. Synchronous constructors create blocking
//! sockets unless their TCP configuration explicitly requests nonblocking
//! operation. Asynchronous constructors always register a nonblocking socket
//! with Tokio. Address-family mismatches are rejected by configuration
//! validation or returned by the operating system for per-operation targets.
//!
//! Raw TCP and ICMP sockets normally require root/`CAP_NET_RAW` on Unix and an
//! elevated process on Windows. Unprivileged UDP and TCP stream sockets do not.

pub mod icmp;
pub mod tcp;
pub mod udp;

use std::net::{IpAddr, SocketAddr};

/// Represents the socket address family (IPv4 or IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketFamily {
    IPV4,
    IPV6,
}

impl SocketFamily {
    /// Returns the socket family of the IP address.
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => SocketFamily::IPV4,
            IpAddr::V6(_) => SocketFamily::IPV6,
        }
    }

    /// Returns the socket family of the socket address.
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => SocketFamily::IPV4,
            SocketAddr::V6(_) => SocketFamily::IPV6,
        }
    }

    /// Returns true if the socket family is IPv4.
    pub fn is_v4(&self) -> bool {
        matches!(self, SocketFamily::IPV4)
    }

    /// Returns true if the socket family is IPv6.
    pub fn is_v6(&self) -> bool {
        matches!(self, SocketFamily::IPV6)
    }

    /// Converts the socket family to a `socket2::Domain`.
    pub(crate) fn to_domain(self) -> socket2::Domain {
        match self {
            SocketFamily::IPV4 => socket2::Domain::IPV4,
            SocketFamily::IPV6 => socket2::Domain::IPV6,
        }
    }
}
