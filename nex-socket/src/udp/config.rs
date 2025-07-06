use std::net::SocketAddr;

/// Configuration options for a UDP socket.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Address to bind. If `None`, the operating system chooses the address.
    pub bind_addr: Option<SocketAddr>,

    /// Enable address reuse (`SO_REUSEADDR`).
    pub reuseaddr: Option<bool>,

    /// Allow broadcast (`SO_BROADCAST`).
    pub broadcast: Option<bool>,

    /// Time to live value.
    pub ttl: Option<u32>,

    /// Bind to a specific interface (Linux only).
    pub bind_device: Option<String>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            reuseaddr: None,
            broadcast: None,
            ttl: None,
            bind_device: None,
        }
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
