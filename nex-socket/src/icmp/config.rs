use std::net::SocketAddr;
use socket2::Type as SockType;

/// ICMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    V4,
    V6,
}

/// Configuration for an ICMP socket.
#[derive(Debug, Clone)]
pub struct IcmpConfig {
    pub kind: IcmpKind,
    pub bind: Option<SocketAddr>,
    pub ttl: Option<u32>,
    pub interface: Option<String>,
    pub sock_type_hint: SockType,
    pub fib: Option<u32>,
}

impl IcmpConfig {
    pub fn new(kind: IcmpKind) -> Self {
        Self {
            kind,
            bind: None,
            ttl: None,
            interface: None,
            sock_type_hint: SockType::DGRAM, // DGRAM preferred on Linux, RAW fallback on macOS/Windows
            fib: None, // FreeBSD only
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
        assert_eq!(cfg.kind, IcmpKind::V4);
        assert_eq!(cfg.bind, Some(addr));
        assert_eq!(cfg.ttl, Some(4));
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.sock_type_hint, Type::RAW);
    }
}

