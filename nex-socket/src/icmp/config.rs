use socket2::Type as SockType;
use std::{io, net::SocketAddr, time::Duration};

use crate::SocketFamily;

/// ICMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    V4,
    V6,
}

/// ICMP socket type, either DGRAM or RAW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpSocketType {
    Dgram,
    Raw,
}

impl IcmpSocketType {
    /// Returns true if the socket type is DGRAM.
    pub fn is_dgram(&self) -> bool {
        matches!(self, IcmpSocketType::Dgram)
    }

    /// Returns true if the socket type is RAW.
    pub fn is_raw(&self) -> bool {
        matches!(self, IcmpSocketType::Raw)
    }

    /// Converts the ICMP socket type from a `socket2::Type`.
    pub(crate) fn try_from_sock_type(sock_type: SockType) -> io::Result<Self> {
        match sock_type {
            SockType::DGRAM => Ok(IcmpSocketType::Dgram),
            SockType::RAW => Ok(IcmpSocketType::Raw),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ICMP socket type",
            )),
        }
    }

    /// Converts the ICMP socket type to a `socket2::Type`.
    pub(crate) fn to_sock_type(&self) -> SockType {
        match self {
            IcmpSocketType::Dgram => SockType::DGRAM,
            IcmpSocketType::Raw => SockType::RAW,
        }
    }
}

/// Configuration for an ICMP socket.
#[derive(Debug, Clone)]
pub struct IcmpConfig {
    /// The socket family.
    pub socket_family: SocketFamily,
    /// Optional bind address for the socket.
    pub bind: Option<SocketAddr>,
    /// Time-to-live for IPv4 packets.
    pub ttl: Option<u32>,
    /// Hop limit for IPv6 packets.
    pub hoplimit: Option<u32>,
    /// Read timeout for the socket.
    pub read_timeout: Option<Duration>,
    /// Write timeout for the socket.
    pub write_timeout: Option<Duration>,
    /// Network interface to use for the socket.
    pub interface: Option<String>,
    /// Socket type hint, DGRAM preferred on Linux, RAW fallback on macOS/Windows.
    pub sock_type_hint: IcmpSocketType,
    /// FreeBSD only: optional FIB (Forwarding Information Base) support.
    pub fib: Option<u32>,
}

impl IcmpConfig {
    /// Creates a new ICMP configuration with the specified kind.
    pub fn new(kind: IcmpKind) -> Self {
        Self {
            socket_family: match kind {
                IcmpKind::V4 => SocketFamily::IPV4,
                IcmpKind::V6 => SocketFamily::IPV6,
            },
            bind: None,
            ttl: None,
            hoplimit: None,
            read_timeout: None,
            write_timeout: None,
            interface: None,
            sock_type_hint: IcmpSocketType::Dgram,
            fib: None,
        }
    }

    /// Creates a new ICMP configuration from a socket family.
    pub fn from_family(socket_family: SocketFamily) -> Self {
        Self {
            socket_family,
            ..Self::new(match socket_family {
                SocketFamily::IPV4 => IcmpKind::V4,
                SocketFamily::IPV6 => IcmpKind::V6,
            })
        }
    }

    /// Set bind address for the socket.
    pub fn with_bind(mut self, addr: SocketAddr) -> Self {
        self.bind = Some(addr);
        self
    }

    /// Set the time-to-live for IPv4 packets.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the hop limit for IPv6 packets.
    pub fn with_hoplimit(mut self, hops: u32) -> Self {
        self.hoplimit = Some(hops);
        self
    }

    /// Set the hop limit for IPv6 packets.
    pub fn with_hop_limit(self, hops: u32) -> Self {
        self.with_hoplimit(hops)
    }

    /// Set the read timeout for the socket.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Set the write timeout for the socket.
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    /// Set the network interface to use for the socket.
    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    /// Set the socket type hint. (DGRAM or RAW)
    pub fn with_sock_type(mut self, ty: IcmpSocketType) -> Self {
        self.sock_type_hint = ty;
        self
    }

    /// Set the FIB (Forwarding Information Base) for FreeBSD.
    pub fn with_fib(mut self, fib: u32) -> Self {
        self.fib = Some(fib);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_config_builders() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = IcmpConfig::new(IcmpKind::V4)
            .with_bind(addr)
            .with_ttl(4)
            .with_interface("eth0")
            .with_sock_type(IcmpSocketType::Raw);
        assert_eq!(cfg.socket_family, SocketFamily::IPV4);
        assert_eq!(cfg.bind, Some(addr));
        assert_eq!(cfg.ttl, Some(4));
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.sock_type_hint, IcmpSocketType::Raw);
    }

    #[test]
    fn from_family_sets_expected_kind() {
        let v4 = IcmpConfig::from_family(SocketFamily::IPV4);
        let v6 = IcmpConfig::from_family(SocketFamily::IPV6);
        assert_eq!(v4.socket_family, SocketFamily::IPV4);
        assert_eq!(v6.socket_family, SocketFamily::IPV6);
    }
}
