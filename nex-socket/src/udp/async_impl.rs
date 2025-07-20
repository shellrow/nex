use crate::udp::UdpConfig;
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;

/// Asynchronous UDP socket built on top of Tokio.
#[derive(Debug)]
pub struct AsyncUdpSocket {
    inner: UdpSocket,
}

impl AsyncUdpSocket {
    /// Create an asynchronous UDP socket from the given configuration.
    pub fn from_config(config: &UdpConfig) -> io::Result<Self> {
        let socket = Socket::new(config.socket_family.to_domain(), config.socket_type.to_sock_type(), Some(Protocol::UDP))?;

        socket.set_nonblocking(true)?;
        
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

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        if let Some(iface) = &config.bind_device {
            socket.bind_device(Some(iface.as_bytes()))?;
        }

        if let Some(addr) = config.bind_addr {
            socket.bind(&addr.into())?;
        }

        #[cfg(windows)]
        let std_socket = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            StdUdpSocket::from_raw_socket(socket.into_raw_socket())
        };
        #[cfg(unix)]
        let std_socket = unsafe {
            use std::os::fd::{FromRawFd, IntoRawFd};
            StdUdpSocket::from_raw_fd(socket.into_raw_fd())
        };

        let inner = UdpSocket::from_std(std_socket)?;

        Ok(Self { inner })
    }

    /// Create a socket of arbitrary type (DGRAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;

        #[cfg(windows)]
        let std_socket = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            StdUdpSocket::from_raw_socket(socket.into_raw_socket())
        };
        #[cfg(unix)]
        let std_socket = unsafe {
            use std::os::fd::{FromRawFd, IntoRawFd};
            StdUdpSocket::from_raw_fd(socket.into_raw_fd())
        };

        let inner = UdpSocket::from_std(std_socket)?;

        Ok(Self { inner })
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

    /// Send data asynchronously.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    /// Receive data asynchronously.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    /// Retrieve the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn into_tokio_socket(self) -> io::Result<UdpSocket> {
        Ok(self.inner)
    }

    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::fd::AsRawFd;
        self.inner.as_raw_fd()
    }

    #[cfg(windows)]
    pub fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.inner.as_raw_socket()
    }
}
