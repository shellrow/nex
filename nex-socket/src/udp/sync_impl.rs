use crate::udp::UdpConfig;
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

/// Synchronous low level UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: Socket,
}

impl UdpSocket {
    /// Create a socket from the provided configuration.
    pub fn from_config(config: &UdpConfig) -> io::Result<Self> {
        let socket = Socket::new(
            config.socket_family.to_domain(),
            config.socket_type.to_sock_type(),
            Some(Protocol::UDP),
        )?;

        socket.set_nonblocking(false)?;

        // Set socket options based on configuration
        if let Some(flag) = config.reuseaddr {
            socket.set_reuse_address(flag)?;
        }
        if let Some(flag) = config.broadcast {
            socket.set_broadcast(flag)?;
        }
        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(hoplimit) = config.hoplimit {
            socket.set_unicast_hops_v6(hoplimit)?;
        }
        if let Some(timeout) = config.read_timeout {
            socket.set_read_timeout(Some(timeout))?;
        }
        if let Some(timeout) = config.write_timeout {
            socket.set_write_timeout(Some(timeout))?;
        }

        // Linux: optional interface name
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        if let Some(iface) = &config.bind_device {
            socket.bind_device(Some(iface.as_bytes()))?;
        }

        // bind to the specified address if provided
        if let Some(addr) = config.bind_addr {
            socket.bind(&addr.into())?;
        }

        Ok(Self { socket })
    }

    /// Create a socket of arbitrary type (DGRAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::UDP))?;
        socket.set_nonblocking(false)?;
        Ok(Self { socket })
    }

    /// Convenience constructor for IPv4 DGRAM.
    pub fn v4_dgram() -> io::Result<Self> {
        Self::new(Domain::IPV4, SockType::DGRAM)
    }

    /// Convenience constructor for IPv6 DGRAM.
    pub fn v6_dgram() -> io::Result<Self> {
        Self::new(Domain::IPV6, SockType::DGRAM)
    }

    /// IPv4 RAW UDP. Requires administrator privileges.
    pub fn raw_v4() -> io::Result<Self> {
        Self::new(Domain::IPV4, SockType::RAW)
    }

    /// IPv6 RAW UDP. Requires administrator privileges.
    pub fn raw_v6() -> io::Result<Self> {
        Self::new(Domain::IPV6, SockType::RAW)
    }

    /// Send data.
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, &target.into())
    }

    /// Receive data.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Safety: `MaybeUninit<u8>` has the same layout as `u8`.
        let buf_maybe = unsafe {
            std::slice::from_raw_parts_mut(
                buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
                buf.len(),
            )
        };

        let (n, addr) = self.socket.recv_from(buf_maybe)?;
        let addr = addr
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid address format"))?;

        Ok((n, addr))
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl(ttl)
    }

    pub fn set_hoplimit(&self, hops: u32) -> io::Result<()> {
        self.socket.set_unicast_hops_v6(hops)
    }

    pub fn set_keepalive(&self, on: bool) -> io::Result<()> {
        self.socket.set_keepalive(on)
    }

    /// Retrieve the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get socket address"))
    }

    /// Convert into a raw `std::net::UdpSocket`.
    pub fn to_std(self) -> io::Result<StdUdpSocket> {
        Ok(self.socket.into())
    }

    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }

    #[cfg(windows)]
    pub fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket.as_raw_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_v4_socket() {
        let sock = UdpSocket::v4_dgram().expect("create socket");
        let addr = sock.local_addr().expect("addr");
        assert!(addr.is_ipv4());
    }
}
