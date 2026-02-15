use socket2::Type as SockType;
use std::net::SocketAddr;
use std::time::Duration;

use crate::SocketFamily;

/// TCP socket type, either STREAM or RAW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketType {
    Stream,
    Raw,
}

impl TcpSocketType {
    /// Returns true if the socket type is STREAM.
    pub fn is_stream(&self) -> bool {
        matches!(self, TcpSocketType::Stream)
    }

    /// Returns true if the socket type is RAW.
    pub fn is_raw(&self) -> bool {
        matches!(self, TcpSocketType::Raw)
    }

    /// Converts the TCP socket type to a `socket2::Type`.
    pub(crate) fn to_sock_type(&self) -> SockType {
        match self {
            TcpSocketType::Stream => SockType::STREAM,
            TcpSocketType::Raw => SockType::RAW,
        }
    }
}

/// Configuration options for a TCP socket.
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// The socket family, either IPv4 or IPv6.
    pub socket_family: SocketFamily,
    /// The type of TCP socket, either STREAM or RAW.
    pub socket_type: TcpSocketType,
    /// Optional address to bind the socket to.
    pub bind_addr: Option<SocketAddr>,
    /// Whether the socket should be non-blocking.
    pub nonblocking: bool,
    /// Whether to allow address reuse.
    pub reuseaddr: Option<bool>,
    /// Whether to allow port reuse (`SO_REUSEPORT`) where supported.
    pub reuseport: Option<bool>,
    /// Whether to disable Nagle's algorithm (TCP_NODELAY).
    pub nodelay: Option<bool>,
    /// Optional linger duration for the socket.
    pub linger: Option<Duration>,
    /// Optional Time-To-Live (TTL) for the socket.
    pub ttl: Option<u32>,
    /// Optional Hop Limit for the socket (IPv6).
    pub hoplimit: Option<u32>,
    /// Optional read timeout for the socket.
    pub read_timeout: Option<Duration>,
    /// Optional write timeout for the socket.
    pub write_timeout: Option<Duration>,
    /// Optional receive buffer size in bytes.
    pub recv_buffer_size: Option<usize>,
    /// Optional send buffer size in bytes.
    pub send_buffer_size: Option<usize>,
    /// Optional IPv4 TOS / DSCP field value.
    pub tos: Option<u32>,
    /// Optional IPv6 traffic class value (`IPV6_TCLASS`) where supported.
    pub tclass_v6: Option<u32>,
    /// Whether to force IPv6-only behavior on dual-stack sockets.
    pub only_v6: Option<bool>,
    /// Optional device to bind the socket to.
    pub bind_device: Option<String>,
    /// Whether to enable TCP keepalive.
    pub keepalive: Option<bool>,
}

impl TcpConfig {
    /// Create a STREAM socket for the specified family.
    pub fn new(socket_family: SocketFamily) -> Self {
        match socket_family {
            SocketFamily::IPV4 => Self::v4_stream(),
            SocketFamily::IPV6 => Self::v6_stream(),
        }
    }

    /// Create a STREAM socket for IPv4.
    pub fn v4_stream() -> Self {
        Self {
            socket_family: SocketFamily::IPV4,
            socket_type: TcpSocketType::Stream,
            bind_addr: None,
            nonblocking: false,
            reuseaddr: None,
            reuseport: None,
            nodelay: None,
            linger: None,
            ttl: None,
            hoplimit: None,
            read_timeout: None,
            write_timeout: None,
            recv_buffer_size: None,
            send_buffer_size: None,
            tos: None,
            tclass_v6: None,
            only_v6: None,
            bind_device: None,
            keepalive: None,
        }
    }

    /// Create a RAW socket. Requires administrator privileges.
    pub fn raw_v4() -> Self {
        Self {
            socket_family: SocketFamily::IPV4,
            socket_type: TcpSocketType::Raw,
            ..Self::v4_stream()
        }
    }

    /// Create a STREAM socket for IPv6.
    pub fn v6_stream() -> Self {
        Self {
            socket_family: SocketFamily::IPV6,
            socket_type: TcpSocketType::Stream,
            ..Self::v4_stream()
        }
    }

    /// Create a RAW socket for IPv6. Requires administrator privileges.
    pub fn raw_v6() -> Self {
        Self {
            socket_family: SocketFamily::IPV6,
            socket_type: TcpSocketType::Raw,
            ..Self::v4_stream()
        }
    }

    // --- chainable modifiers ---

    pub fn with_bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    pub fn with_bind_addr(self, addr: SocketAddr) -> Self {
        self.with_bind(addr)
    }

    pub fn with_nonblocking(mut self, flag: bool) -> Self {
        self.nonblocking = flag;
        self
    }

    pub fn with_reuseaddr(mut self, flag: bool) -> Self {
        self.reuseaddr = Some(flag);
        self
    }

    pub fn with_reuseport(mut self, flag: bool) -> Self {
        self.reuseport = Some(flag);
        self
    }

    pub fn with_nodelay(mut self, flag: bool) -> Self {
        self.nodelay = Some(flag);
        self
    }

    pub fn with_linger(mut self, dur: Duration) -> Self {
        self.linger = Some(dur);
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

    pub fn with_hop_limit(self, hops: u32) -> Self {
        self.with_hoplimit(hops)
    }

    pub fn with_keepalive(mut self, on: bool) -> Self {
        self.keepalive = Some(on);
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

    pub fn with_recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    pub fn with_send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    pub fn with_tos(mut self, tos: u32) -> Self {
        self.tos = Some(tos);
        self
    }

    pub fn with_tclass_v6(mut self, tclass: u32) -> Self {
        self.tclass_v6 = Some(tclass);
        self
    }

    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = Some(only_v6);
        self
    }

    pub fn with_bind_device(mut self, iface: impl Into<String>) -> Self {
        self.bind_device = Some(iface.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_config_builders() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let cfg = TcpConfig::new(SocketFamily::IPV4)
            .with_bind_addr(addr)
            .with_nonblocking(true)
            .with_reuseaddr(true)
            .with_reuseport(true)
            .with_nodelay(true)
            .with_ttl(10)
            .with_recv_buffer_size(8192)
            .with_send_buffer_size(8192)
            .with_tos(0x10)
            .with_tclass_v6(0x20);

        assert_eq!(cfg.socket_family, SocketFamily::IPV4);
        assert_eq!(cfg.socket_type, TcpSocketType::Stream);
        assert_eq!(cfg.bind_addr, Some(addr));
        assert!(cfg.nonblocking);
        assert_eq!(cfg.reuseaddr, Some(true));
        assert_eq!(cfg.reuseport, Some(true));
        assert_eq!(cfg.nodelay, Some(true));
        assert_eq!(cfg.ttl, Some(10));
        assert_eq!(cfg.recv_buffer_size, Some(8192));
        assert_eq!(cfg.send_buffer_size, Some(8192));
        assert_eq!(cfg.tos, Some(0x10));
        assert_eq!(cfg.tclass_v6, Some(0x20));
    }

    #[test]
    fn new_with_ipv6_family_creates_v6_stream() {
        let cfg = TcpConfig::new(SocketFamily::IPV6);
        assert_eq!(cfg.socket_family, SocketFamily::IPV6);
        assert_eq!(cfg.socket_type, TcpSocketType::Stream);
    }
}
