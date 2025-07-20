use socket2::Type as SockType;
use std::{net::SocketAddr, time::Duration};

use crate::SocketFamily;

/// ICMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    V4,
    V6,
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
    pub sock_type_hint: SockType,
    /// FreeBSD only: optional FIB (Forwarding Information Base) support.
    pub fib: Option<u32>,
}

impl IcmpConfig {
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
            sock_type_hint: SockType::DGRAM,
            fib: None,
        }
    }

    pub fn with_bind(mut self, addr: SocketAddr) -> Self {
        self.bind = Some(addr);
        self
    }

    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn with_hoplimit(mut self, hops: u32) -> Self {
        self.hoplimit = Some(hops);
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    pub fn with_sock_type(mut self, ty: SockType) -> Self {
        self.sock_type_hint = ty;
        self
    }

    pub fn with_fib(mut self, fib: u32) -> Self {
        self.fib = Some(fib);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::Type;
    #[test]
    fn icmp_config_builders() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = IcmpConfig::new(IcmpKind::V4)
            .with_bind(addr)
            .with_ttl(4)
            .with_interface("eth0")
            .with_sock_type(Type::RAW);
        assert_eq!(cfg.socket_family, SocketFamily::IPV4);
        assert_eq!(cfg.bind, Some(addr));
        assert_eq!(cfg.ttl, Some(4));
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.sock_type_hint, Type::RAW);
    }
}
