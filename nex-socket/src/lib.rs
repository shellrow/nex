#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

use async_io::Async;
use socket2::{Domain, SockAddr, Socket as SystemSocket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nex_packet::ip::IpNextLevelProtocol;

/// IP version. IPv4 or IPv6.
#[derive(Clone, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// IP Version number as u8.
    pub fn version_u8(&self) -> u8 {
        match self {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        }
    }
    /// Return true if IP version is IPv4.
    pub fn is_ipv4(&self) -> bool {
        match self {
            IpVersion::V4 => true,
            IpVersion::V6 => false,
        }
    }
    /// Return true if IP version is IPv6.
    pub fn is_ipv6(&self) -> bool {
        match self {
            IpVersion::V4 => false,
            IpVersion::V6 => true,
        }
    }
    pub(crate) fn to_domain(&self) -> Domain {
        match self {
            IpVersion::V4 => Domain::IPV4,
            IpVersion::V6 => Domain::IPV6,
        }
    }
}

/// Socket type
#[derive(Clone, Debug)]
pub enum SocketType {
    /// Raw socket
    Raw,
    /// Datagram socket. Usualy used for UDP.
    Datagram,
    /// Stream socket. Used for TCP.
    Stream,
}

impl SocketType {
    pub(crate) fn to_type(&self) -> Type {
        match self {
            SocketType::Raw => Type::RAW,
            SocketType::Datagram => Type::DGRAM,
            SocketType::Stream => Type::STREAM,
        }
    }
}

/// Socket option.
#[derive(Clone, Debug)]
pub struct SocketOption {
    /// IP version
    pub ip_version: IpVersion,
    /// Socket type
    pub socket_type: SocketType,
    /// Protocol. TCP, UDP, ICMP, etc.
    pub protocol: Option<IpNextLevelProtocol>,
    /// Timeout
    pub timeout: Option<u64>,
    /// TTL or Hop Limit
    pub ttl: Option<u32>,
    /// Non-blocking mode
    pub non_blocking: bool,
}

impl SocketOption {
    /// Constructs a new SocketOption.
    pub fn new(
        ip_version: IpVersion,
        socket_type: SocketType,
        protocol: Option<IpNextLevelProtocol>,
    ) -> SocketOption {
        SocketOption {
            ip_version,
            socket_type,
            protocol,
            timeout: None,
            ttl: None,
            non_blocking: false,
        }
    }
    /// Check socket option.
    /// Return Ok(()) if socket option is valid.
    pub fn is_valid(&self) -> Result<(), String> {
        check_socket_option(self.clone())
    }
}

/// Async socket. Provides cross-platform async adapter for system’s socket.
#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<Async<SystemSocket>>,
}

impl AsyncSocket {
    /// Constructs a new AsyncSocket.
    pub fn new(socket_option: SocketOption) -> io::Result<AsyncSocket> {
        let socket: SystemSocket = if let Some(protocol) = socket_option.protocol {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                Some(to_socket_protocol(protocol)),
            )?
        } else {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                None,
            )?
        };
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Send packet.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self.inner.write_with(|inner| inner.send(buf)).await {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    /// Send packet to target.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target: SockAddr = SockAddr::from(target);
        loop {
            self.inner.writable().await?;
            match self
                .inner
                .write_with(|inner| inner.send_to(buf, &target))
                .await
            {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    /// Receive packet.
    pub async fn receive(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv(recv_buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    /// Receive packet with sender address.
    pub async fn receive_from(&self, buf: &mut Vec<u8>) -> io::Result<(usize, SocketAddr)> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self
                .inner
                .read_with(|inner| inner.recv_from(recv_buf))
                .await
            {
                Ok(result) => {
                    let (n, addr) = result;
                    match addr.as_socket() {
                        Some(addr) => return Ok((n, addr)),
                        None => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    }
    /// Write data to the socket and send to the target.
    /// Return how many bytes were written.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self.inner.write_with(|inner| inner.send(buf)).await {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    /// Read data from the socket.
    /// Return how many bytes were read.
    pub async fn read(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv(recv_buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    /// Bind socket to address.
    pub async fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.bind(&addr)).await
    }
    /// Set receive timeout.
    pub async fn set_receive_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_read_timeout(timeout))
            .await
    }
    /// Set TTL or Hop Limit.
    pub async fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        self.inner.writable().await?;
        match ip_version {
            IpVersion::V4 => self.inner.write_with(|inner| inner.set_ttl(ttl)).await,
            IpVersion::V6 => {
                self.inner
                    .write_with(|inner| inner.set_unicast_hops_v6(ttl))
                    .await
            }
        }
    }
    /// Initiate TCP connection.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.connect(&addr)).await
    }
    /// Shutdown TCP connection.
    pub async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.shutdown(how)).await
    }
    /// Listen TCP connection.
    pub async fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.listen(backlog)).await
    }
    /// Accept TCP connection.
    pub async fn accept(&self) -> io::Result<(AsyncSocket, SocketAddr)> {
        self.inner.readable().await?;
        match self.inner.read_with(|inner| inner.accept()).await {
            Ok((socket, addr)) => {
                let socket = AsyncSocket {
                    inner: Arc::new(Async::new(socket)?),
                };
                Ok((socket, addr.as_socket().unwrap()))
            }
            Err(e) => Err(e),
        }
    }
    /// Get peer address.
    pub async fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.writable().await?;
        match self.inner.read_with(|inner| inner.peer_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get local address.
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.writable().await?;
        match self.inner.read_with(|inner| inner.local_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Initiate a connection on this socket to the specified address, only only waiting for a certain period of time for the connection to be established.
    /// The non-blocking state of the socket is overridden by this function.
    pub async fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.connect_timeout(&addr, timeout))
            .await
    }
    /// Set the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast address.
    pub async fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_nonblocking(nonblocking))
            .await
    }
    /// Set the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast address.
    pub async fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_broadcast(broadcast))
            .await
    }
    /// Get the value of the `SO_ERROR` option on this socket.
    pub async fn get_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.readable().await?;
        self.inner.read_with(|inner| inner.take_error()).await
    }
    /// Set value for the `SO_KEEPALIVE` option on this socket.
    ///
    /// Enable sending of keep-alive messages on connection-oriented sockets.
    pub async fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_keepalive(keepalive))
            .await
    }
    /// Set value for the `SO_RCVBUF` option on this socket.
    ///
    /// Changes the size of the operating system's receive buffer associated with the socket.
    pub async fn set_receive_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_recv_buffer_size(size))
            .await
    }
    /// Set value for the `SO_REUSEADDR` option on this socket.
    ///
    /// This indicates that futher calls to `bind` may allow reuse of local addresses.
    pub async fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_reuse_address(reuse))
            .await
    }
    /// Set value for the `SO_SNDBUF` option on this socket.
    ///
    /// Changes the size of the operating system's send buffer associated with the socket.
    pub async fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_send_buffer_size(size))
            .await
    }
    /// Set value for the `SO_SNDTIMEO` option on this socket.
    ///
    /// If `timeout` is `None`, then `write` and `send` calls will block indefinitely.
    pub async fn set_send_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_write_timeout(duration))
            .await
    }
    /// Set the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, segments are always sent as soon as possible, even if there is only a small amount of data.
    pub async fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_nodelay(nodelay))
            .await
    }
}

/// Socket. Provides cross-platform adapter for system’s socket.
#[derive(Clone, Debug)]
pub struct Socket {
    inner: Arc<SystemSocket>,
}

impl Socket {
    /// Constructs a new Socket.
    pub fn new(socket_option: SocketOption) -> io::Result<Socket> {
        let socket: SystemSocket = if let Some(protocol) = socket_option.protocol {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                Some(to_socket_protocol(protocol)),
            )?
        } else {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                None,
            )?
        };
        if socket_option.non_blocking {
            socket.set_nonblocking(true)?;
        }
        Ok(Socket {
            inner: Arc::new(socket),
        })
    }
    /// Send packet to target.
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target: SockAddr = SockAddr::from(target);
        match self.inner.send_to(buf, &target) {
            Ok(n) => Ok(n),
            Err(e) => Err(e),
        }
    }
    /// Receive packet.
    pub fn receive(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match self.inner.recv(recv_buf) {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }
    /// Receive packet with sender address.
    pub fn receive_from(&self, buf: &mut Vec<u8>) -> io::Result<(usize, SocketAddr)> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match self.inner.recv_from(recv_buf) {
            Ok(result) => {
                let (n, addr) = result;
                match addr.as_socket() {
                    Some(addr) => return Ok((n, addr)),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Invalid socket address",
                        ))
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
    /// Write data to the socket and send to the target.
    /// Return how many bytes were written.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.send(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(e),
        }
    }
    /// Read data from the socket.
    /// Return how many bytes were read.
    pub fn read(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match self.inner.recv(recv_buf) {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }
    /// Bind socket to address.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.bind(&addr)
    }
    /// Set receive timeout.
    pub fn set_receive_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
    /// Set TTL or Hop Limit.
    pub fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        match ip_version {
            IpVersion::V4 => self.inner.set_ttl(ttl),
            IpVersion::V6 => self.inner.set_unicast_hops_v6(ttl),
        }
    }
    /// Initiate TCP connection.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.connect(&addr)
    }
    /// Shutdown TCP connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
    /// Listen TCP connection.
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.listen(backlog)
    }
    /// Accept TCP connection.
    pub fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        match self.inner.accept() {
            Ok((socket, addr)) => Ok((
                Socket {
                    inner: Arc::new(socket),
                },
                addr.as_socket().unwrap(),
            )),
            Err(e) => Err(e),
        }
    }
    /// Get peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.peer_addr() {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.local_addr() {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Initiate a connection on this socket to the specified address, only only waiting for a certain period of time for the connection to be established.
    /// The non-blocking state of the socket is overridden by this function.
    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner.connect_timeout(&addr, timeout)
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
    /// Set the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast address.
    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.inner.set_broadcast(broadcast)
    }
    /// Get the value of the `SO_ERROR` option on this socket.
    pub fn get_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }
    /// Set value for the `SO_KEEPALIVE` option on this socket.
    ///
    /// Enable sending of keep-alive messages on connection-oriented sockets.
    pub fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.inner.set_keepalive(keepalive)
    }
    /// Set value for the `SO_RCVBUF` option on this socket.
    ///
    /// Changes the size of the operating system's receive buffer associated with the socket.
    pub fn set_receive_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_recv_buffer_size(size)
    }
    /// Set value for the `SO_REUSEADDR` option on this socket.
    ///
    /// This indicates that futher calls to `bind` may allow reuse of local addresses.
    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.inner.set_reuse_address(reuse)
    }
    /// Set value for the `SO_SNDBUF` option on this socket.
    ///
    /// Changes the size of the operating system's send buffer associated with the socket.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_send_buffer_size(size)
    }
    /// Set value for the `SO_SNDTIMEO` option on this socket.
    ///
    /// If `timeout` is `None`, then `write` and `send` calls will block indefinitely.
    pub fn set_send_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(duration)
    }
    /// Set the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, segments are always sent as soon as possible, even if there is only a small amount of data.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

fn to_socket_protocol(protocol: IpNextLevelProtocol) -> socket2::Protocol {
    match protocol {
        IpNextLevelProtocol::Tcp => socket2::Protocol::TCP,
        IpNextLevelProtocol::Udp => socket2::Protocol::UDP,
        IpNextLevelProtocol::Icmp => socket2::Protocol::ICMPV4,
        IpNextLevelProtocol::Icmpv6 => socket2::Protocol::ICMPV6,
        _ => socket2::Protocol::TCP,
    }
}
