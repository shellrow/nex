use crate::icmp::{IcmpConfig, IcmpKind};
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Synchronous ICMP socket.
#[derive(Debug)]
pub struct IcmpSocket {
    inner: UdpSocket,
    sock_type: SockType,
    kind: IcmpKind,
}

impl IcmpSocket {
    /// Create a new synchronous ICMP socket.
    pub fn new(config: &IcmpConfig) -> io::Result<Self> {
        let (domain, proto) = match config.kind {
            IcmpKind::V4 => (Domain::IPV4, Some(Protocol::ICMPV4)),
            IcmpKind::V6 => (Domain::IPV6, Some(Protocol::ICMPV6)),
        };

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

        socket.set_nonblocking(false)?; // blocking mode for sync usage

        if let Some(addr) = &config.bind {
            socket.bind(&(*addr).into())?;
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        if let Some(interface) = &config.interface {
            socket.bind_device(Some(interface.as_bytes()))?;
        }

        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }

        #[cfg(target_os = "freebsd")]
        if let Some(fib) = config.fib {
            socket.set_fib(fib)?;
        }

        // Convert socket2::Socket into std::net::UdpSocket
        let std_socket: UdpSocket = socket.into();

        Ok(Self {
            inner: std_socket,
            sock_type: config.sock_type_hint,
            kind: config.kind,
        })
    }

    /// Send a packet.
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, target)
    }

    /// Receive a packet.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    /// Retrieve the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Return the socket type.
    pub fn sock_type(&self) -> SockType {
        self.sock_type
    }

    /// Return the ICMP variant.
    pub fn kind(&self) -> IcmpKind {
        self.kind
    }

    /// Access the underlying socket.
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
