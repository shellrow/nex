use socket2::{Domain, Type as SockType};
use std::net::SocketAddr;
use std::time::Duration;

/// Configuration options for a TCP socket.
#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub domain: Domain,
    pub sock_type: SockType,
    pub bind_addr: Option<SocketAddr>,
    pub nonblocking: bool,
    pub reuseaddr: Option<bool>,
    pub nodelay: Option<bool>,
    pub linger: Option<Duration>,
    pub ttl: Option<u32>,
    pub bind_device: Option<String>,
}

impl TcpConfig {
    /// Create a STREAM socket for IPv4.
    pub fn v4_stream() -> Self {
        Self {
            domain: Domain::IPV4,
            sock_type: SockType::STREAM,
            bind_addr: None,
            nonblocking: false,
            reuseaddr: None,
            nodelay: None,
            linger: None,
            ttl: None,
            bind_device: None,
        }
    }

    /// Create a RAW socket. Requires administrator privileges.
    pub fn raw_v4() -> Self {
        Self {
            domain: Domain::IPV4,
            sock_type: SockType::RAW,
            ..Self::v4_stream()
        }
    }

    /// Create a STREAM socket for IPv6.
    pub fn v6_stream() -> Self {
        Self {
            domain: Domain::IPV6,
            sock_type: SockType::STREAM,
            ..Self::v4_stream()
        }
    }

    /// Create a RAW socket for IPv6. Requires administrator privileges.
    pub fn raw_v6() -> Self {
        Self {
            domain: Domain::IPV6,
            sock_type: SockType::RAW,
            ..Self::v4_stream()
        }
    }

    // --- chainable modifiers ---

    pub fn with_bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    pub fn with_nonblocking(mut self, flag: bool) -> Self {
        self.nonblocking = flag;
        self
    }

    pub fn with_reuseaddr(mut self, flag: bool) -> Self {
        self.reuseaddr = Some(flag);
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
        let cfg = TcpConfig::v4_stream()
            .with_bind(addr)
            .with_nonblocking(true)
            .with_reuseaddr(true)
            .with_nodelay(true)
            .with_ttl(10);

        assert_eq!(cfg.domain, Domain::IPV4);
        assert_eq!(cfg.sock_type, SockType::STREAM);
        assert_eq!(cfg.bind_addr, Some(addr));
        assert!(cfg.nonblocking);
        assert_eq!(cfg.reuseaddr, Some(true));
        assert_eq!(cfg.nodelay, Some(true));
        assert_eq!(cfg.ttl, Some(10));
    }
}
