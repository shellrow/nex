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
    /// Whether to allow port reuse (`SO_REUSEPORT`) where supported.
    pub reuseport: Option<bool>,
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
    /// Optional receive buffer size in bytes.
    pub recv_buffer_size: Option<usize>,
    /// Optional send buffer size in bytes.
    pub send_buffer_size: Option<usize>,
    /// Optional IPv4 TOS / DSCP field value.
    pub tos: Option<u32>,
    /// Optional IPv6 traffic class value (`IPV6_TCLASS`) where supported.
    pub tclass_v6: Option<u32>,
    /// Enable receiving packet info ancillary data (`IP_PKTINFO` / `IPV6_RECVPKTINFO`) where supported.
    pub recv_pktinfo: Option<bool>,
    /// Whether to force IPv6-only behavior on dual-stack sockets.
    pub only_v6: Option<bool>,
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
            reuseport: None,
            broadcast: None,
            ttl: None,
            hoplimit: None,
            read_timeout: None,
            write_timeout: None,
            recv_buffer_size: None,
            send_buffer_size: None,
            tos: None,
            tclass_v6: None,
            recv_pktinfo: None,
            only_v6: None,
            bind_device: None,
        }
    }
}

impl UdpConfig {
    /// Create a new UDP configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new UDP configuration for a specific socket family.
    pub fn new_with_family(socket_family: SocketFamily) -> Self {
        Self {
            socket_family,
            ..Self::default()
        }
    }

    /// Set the socket family.
    pub fn with_socket_family(mut self, socket_family: SocketFamily) -> Self {
        self.socket_family = socket_family;
        self
    }

    /// Set the bind address.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Set the bind address.
    pub fn with_bind(self, addr: SocketAddr) -> Self {
        self.with_bind_addr(addr)
    }

    /// Enable address reuse.
    pub fn with_reuseaddr(mut self, on: bool) -> Self {
        self.reuseaddr = Some(on);
        self
    }

    /// Enable port reuse.
    pub fn with_reuseport(mut self, on: bool) -> Self {
        self.reuseport = Some(on);
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

    /// Set the hop limit value.
    pub fn with_hop_limit(self, hops: u32) -> Self {
        self.with_hoplimit(hops)
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

    /// Set the receive buffer size.
    pub fn with_recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set the send buffer size.
    pub fn with_send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Set the IPv4 TOS / DSCP field value.
    pub fn with_tos(mut self, tos: u32) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set the IPv6 traffic class value.
    pub fn with_tclass_v6(mut self, tclass: u32) -> Self {
        self.tclass_v6 = Some(tclass);
        self
    }

    /// Enable packet-info ancillary data receiving.
    pub fn with_recv_pktinfo(mut self, on: bool) -> Self {
        self.recv_pktinfo = Some(on);
        self
    }

    /// Set whether the socket is IPv6 only.
    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = Some(only_v6);
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
        assert!(cfg.reuseport.is_none());
        assert!(cfg.broadcast.is_none());
        assert!(cfg.ttl.is_none());
        assert!(cfg.recv_buffer_size.is_none());
        assert!(cfg.send_buffer_size.is_none());
        assert!(cfg.tos.is_none());
        assert!(cfg.tclass_v6.is_none());
        assert!(cfg.recv_pktinfo.is_none());
        assert!(cfg.only_v6.is_none());
        assert!(cfg.bind_device.is_none());
    }

    #[test]
    fn udp_config_with_family_builder() {
        let cfg =
            UdpConfig::new_with_family(SocketFamily::IPV6).with_bind("[::1]:0".parse().unwrap());
        assert_eq!(cfg.socket_family, SocketFamily::IPV6);
        assert!(cfg.bind_addr.is_some());
    }
}
