use std::{net::SocketAddr, time::Duration};

use socket2::Type as SockType;

use crate::SocketFamily;

/// UDP socket type, either DGRAM or RAW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketType {
    Dgram,
    Raw,
}

impl UdpSocketType {
    /// Returns true if the socket type is DGRAM.
    pub fn is_dgram(&self) -> bool {
        matches!(self, UdpSocketType::Dgram)
    }

    /// Returns true if the socket type is RAW.
    pub fn is_raw(&self) -> bool {
        matches!(self, UdpSocketType::Raw)
    }

    /// Converts the UDP socket type to a `socket2::Type`.
    pub(crate) fn to_sock_type(&self) -> SockType {
        match self {
            UdpSocketType::Dgram => SockType::DGRAM,
            UdpSocketType::Raw => SockType::RAW,
        }
    }
}

/// Configuration options for a UDP socket.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// The socket family.
    pub socket_family: SocketFamily,
    /// The socket type (DGRAM or RAW).
    pub socket_type: UdpSocketType,
    /// Address to bind. If `None`, the operating system chooses the address.
    pub bind_addr: Option<SocketAddr>,
    /// Enable address reuse (`SO_REUSEADDR`).
    pub reuseaddr: Option<bool>,
    /// Allow broadcast (`SO_BROADCAST`).
    pub broadcast: Option<bool>,
    /// Time to live value.
    pub ttl: Option<u32>,
    /// Hop limit value.
    pub hoplimit: Option<u32>,
    /// Read timeout for the socket.
    pub read_timeout: Option<Duration>,
    /// Write timeout for the socket.
    pub write_timeout: Option<Duration>,
    /// Bind to a specific interface (Linux only).
    pub bind_device: Option<String>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            socket_family: SocketFamily::IPV4,
            socket_type: UdpSocketType::Dgram,
            bind_addr: None,
            reuseaddr: None,
            broadcast: None,
            ttl: None,
            hoplimit: None,
            read_timeout: None,
            write_timeout: None,
            bind_device: None,
        }
    }
}

impl UdpConfig {
    /// Create a new UDP configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bind address.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Enable address reuse.
    pub fn with_reuseaddr(mut self, on: bool) -> Self {
        self.reuseaddr = Some(on);
        self
    }

    /// Allow broadcast.
    pub fn with_broadcast(mut self, on: bool) -> Self {
        self.broadcast = Some(on);
        self
    }

    /// Set the time to live value.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the hop limit value.
    pub fn with_hoplimit(mut self, hops: u32) -> Self {
        self.hoplimit = Some(hops);
        self
    }

    /// Set the read timeout.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Set the write timeout.
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    /// Bind to a specific interface (Linux only).
    pub fn with_bind_device(mut self, iface: impl Into<String>) -> Self {
        self.bind_device = Some(iface.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_config_default_values() {
        let cfg = UdpConfig::default();
        assert!(cfg.bind_addr.is_none());
        assert!(cfg.reuseaddr.is_none());
        assert!(cfg.broadcast.is_none());
        assert!(cfg.ttl.is_none());
        assert!(cfg.bind_device.is_none());
    }
}
