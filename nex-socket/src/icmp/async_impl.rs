use crate::icmp::{IcmpConfig, IcmpKind};
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;

/// Asynchronous ICMP socket built on Tokio.
#[derive(Debug)]
pub struct AsyncIcmpSocket {
    inner: UdpSocket,
    sock_type: SockType,
    kind: IcmpKind,
}

impl AsyncIcmpSocket {
    /// Create a new asynchronous ICMP socket.
    pub async fn new(config: &IcmpConfig) -> io::Result<Self> {
        let (domain, proto) = match config.kind {
            IcmpKind::V4 => (Domain::IPV4, Some(Protocol::ICMPV4)),
            IcmpKind::V6 => (Domain::IPV6, Some(Protocol::ICMPV6)),
        };

        // Build the socket with DGRAM preferred and RAW as a fallback
        let socket = match Socket::new(domain, config.sock_type_hint, proto) {
            Ok(s) => s,
            Err(_) => {
                let alt_type = if config.sock_type_hint == SockType::DGRAM {
                    SockType::RAW
                } else {
                    SockType::DGRAM
                };
                Socket::new(domain, alt_type, proto)?
            }
        };

        socket.set_nonblocking(true)?;

        // bind
        if let Some(addr) = &config.bind {
            socket.bind(&(*addr).into())?;
        }

        // Linux: optional interface name
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        if let Some(interface) = &config.interface {
            socket.bind_device(Some(interface.as_bytes()))?;
        }

        // TTL
        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }

        // FreeBSD only: optional FIB support
        #[cfg(target_os = "freebsd")]
        if let Some(fib) = config.fib {
            socket.set_fib(fib)?;
        }

        let socket_type = socket.r#type()?;

        // Convert socket2::Socket into std::net::UdpSocket
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

        // std → tokio::net::UdpSocket
        let inner = UdpSocket::from_std(std_socket)?;

        Ok(Self {
            inner,
            sock_type: socket_type,
            kind: config.kind,
        })
    }

    /// Send a packet asynchronously.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    /// Receive a packet asynchronously.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    /// Retrieve the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Return the socket type (DGRAM or RAW).
    pub fn sock_type(&self) -> SockType {
        self.sock_type
    }

    /// Return the ICMP version.
    pub fn kind(&self) -> IcmpKind {
        self.kind
    }

    /// Access the native socket for low level operations.
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
