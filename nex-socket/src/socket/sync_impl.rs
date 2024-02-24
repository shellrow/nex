use socket2::{SockAddr, Socket as SystemSocket};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use crate::socket::{IpVersion, SocketOption};
use crate::socket::to_socket_protocol;

/// Socket. Provides cross-platform adapter for system socket.
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
    /// Bind socket to address.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.bind(&addr)
    }
    /// Send packet.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.send(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(e),
        }
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
    /// Get TTL or Hop Limit.
    pub fn ttl(&self, ip_version: IpVersion) -> io::Result<u32> {
        match ip_version {
            IpVersion::V4 => self.inner.ttl(),
            IpVersion::V6 => self.inner.unicast_hops_v6(),
        }
    }
    /// Set TTL or Hop Limit.
    pub fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        match ip_version {
            IpVersion::V4 => self.inner.set_ttl(ttl),
            IpVersion::V6 => self.inner.set_unicast_hops_v6(ttl),
        }
    }
    /// Get the value of the IP_TOS option for this socket.
    pub fn tos(&self) -> io::Result<u32> {
        self.inner.tos()
    }
    /// Set the value of the IP_TOS option for this socket.
    pub fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.inner.set_tos(tos)
    }
    /// Get the value of the IP_RECVTOS option for this socket.
    pub fn receive_tos(&self) -> io::Result<bool> {
        self.inner.recv_tos()
    }
    /// Set the value of the IP_RECVTOS option for this socket.
    pub fn set_receive_tos(&self, receive_tos: bool) -> io::Result<()> {
        self.inner.set_recv_tos(receive_tos)
    }
    /// Initiate TCP connection.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.connect(&addr)
    }
    /// Initiate a connection on this socket to the specified address, only only waiting for a certain period of time for the connection to be established.
    /// The non-blocking state of the socket is overridden by this function.
    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner.connect_timeout(&addr, timeout)
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
    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.local_addr() {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
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
    /// Get type of the socket.
    pub fn socket_type(&self) -> io::Result<crate::socket::SocketType> {
        match self.inner.r#type() {
            Ok(socktype) => Ok(crate::socket::SocketType::from_type(socktype)),
            Err(e) => Err(e),
        }
    }
    /// Create a new socket with the same configuration and bound to the same address.
    pub fn try_clone(&self) -> io::Result<Socket> {
        match self.inner.try_clone() {
            Ok(socket) => Ok(Socket {
                inner: Arc::new(socket),
            }),
            Err(e) => Err(e),
        }
    }
    /// Returns true if this socket is set to nonblocking mode, false otherwise.
    #[cfg(not(target_os = "windows"))]
    pub fn is_nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }
    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
    /// Shutdown TCP connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
    /// Get the value of the SO_BROADCAST option for this socket.
    pub fn is_broadcast(&self) -> io::Result<bool> {
        self.inner.broadcast()
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
    /// Get the value of the `SO_KEEPALIVE` option on this socket.
    pub fn keepalive(&self) -> io::Result<bool> {
        self.inner.keepalive()
    }
    /// Set value for the `SO_KEEPALIVE` option on this socket.
    ///
    /// Enable sending of keep-alive messages on connection-oriented sockets.
    pub fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.inner.set_keepalive(keepalive)
    }
    /// Get the value of the SO_LINGER option on this socket.
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        self.inner.linger()
    }
    /// Set value for the SO_LINGER option on this socket.
    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_linger(dur)
    }
    /// Get the value of the `SO_RCVBUF` option on this socket.
    pub fn receive_buffer_size(&self) -> io::Result<usize> {
        self.inner.recv_buffer_size()
    }
    /// Set value for the `SO_RCVBUF` option on this socket.
    ///
    /// Changes the size of the operating system's receive buffer associated with the socket.
    pub fn set_receive_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_recv_buffer_size(size)
    }
    /// Get value for the SO_RCVTIMEO option on this socket.
    pub fn receive_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }
    /// Set value for the `SO_RCVTIMEO` option on this socket.
    pub fn set_receive_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(duration)
    }
    /// Get value for the `SO_REUSEADDR` option on this socket.
    pub fn reuse_address(&self) -> io::Result<bool> {
        self.inner.reuse_address()
    }
    /// Set value for the `SO_REUSEADDR` option on this socket.
    ///
    /// This indicates that futher calls to `bind` may allow reuse of local addresses.
    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.inner.set_reuse_address(reuse)
    }
    /// Get value for the `SO_SNDBUF` option on this socket.
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.inner.send_buffer_size()
    }
    /// Set value for the `SO_SNDBUF` option on this socket.
    ///
    /// Changes the size of the operating system's send buffer associated with the socket.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner.set_send_buffer_size(size)
    }
    /// Get value for the `SO_SNDTIMEO` option on this socket.
    pub fn send_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.write_timeout()
    }
    /// Set value for the `SO_SNDTIMEO` option on this socket.
    ///
    /// If `timeout` is `None`, then `write` and `send` calls will block indefinitely.
    pub fn set_send_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(duration)
    }
    /// Get the value of the IP_HDRINCL option on this socket.
    pub fn is_ip_header_included(&self) -> io::Result<bool> {
        self.inner.header_included()
    }
    /// Set the value of the `IP_HDRINCL` option on this socket.
    pub fn set_ip_header_included(&self, include: bool) -> io::Result<()> {
        self.inner.set_header_included(include)
    }
    /// Get the value of the TCP_NODELAY option on this socket.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }
    /// Set the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, segments are always sent as soon as possible, even if there is only a small amount of data.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
    /// Get TCP Stream
    /// This function will consume the socket and return a new std::net::TcpStream.
    pub fn into_tcp_stream(self) -> io::Result<TcpStream> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket.into()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to unwrap socket",
            )),
        }
    }
    /// Get TCP Listener
    /// This function will consume the socket and return a new std::net::TcpListener.
    pub fn into_tcp_listener(self) -> io::Result<TcpListener> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket.into()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to unwrap socket",
            )),
        }
    }
    /// Get UDP Socket
    /// This function will consume the socket and return a new std::net::UdpSocket.
    pub fn into_udp_socket(self) -> io::Result<UdpSocket> {
        match Arc::try_unwrap(self.inner) {
            Ok(socket) => Ok(socket.into()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to unwrap socket",
            )),
        }
    }
}
