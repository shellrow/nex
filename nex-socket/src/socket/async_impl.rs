use crate::socket::to_socket_protocol;
use crate::socket::{IpVersion, SocketOption};
use async_io::{Async, Timer};
use futures_lite::future::FutureExt;
use socket2::{SockAddr, Socket as SystemSocket};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// Async socket. Provides cross-platform async adapter for system socket.
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
    /// Constructs a new AsyncSocket with async non-blocking TCP connect.
    pub async fn new_with_async_connect(addr: &SocketAddr) -> io::Result<AsyncSocket> {
        let stream = Async::<TcpStream>::connect(*addr).await?;
        // Once the connection is established, we can turn it into a SystemSocket(socket2::Socket).
        // And then we can turn it into a AsyncSocket for the rest of the operations.
        let socket = SystemSocket::from(stream.into_inner()?);
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket with async non-blocking TCP connect and timeout.
    pub async fn new_with_async_connect_timeout(
        addr: &SocketAddr,
        timeout: Duration,
    ) -> io::Result<AsyncSocket> {
        let stream = Async::<TcpStream>::connect(*addr)
            .or(async {
                Timer::after(timeout).await;
                Err(io::ErrorKind::TimedOut.into())
            })
            .await?;
        // Once the connection is established, we can turn it into a SystemSocket(socket2::Socket).
        // And then we can turn it into a AsyncSocket for the rest of the operations.
        let socket = SystemSocket::from(stream.into_inner()?);
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket with TCP connect.
    /// If you want to async non-blocking connect, use `new_with_async_connect` instead.
    pub fn new_with_connect(
        socket_option: SocketOption,
        addr: &SocketAddr,
    ) -> io::Result<AsyncSocket> {
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
        let addr: SockAddr = SockAddr::from(*addr);
        socket.connect(&addr)?;
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket with TCP connect and timeout.
    /// If you want to async non-blocking connect, use `new_with_async_connect_timeout` instead.
    pub fn new_with_connect_timeout(
        socket_option: SocketOption,
        addr: &SocketAddr,
        timeout: Duration,
    ) -> io::Result<AsyncSocket> {
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
        let addr: SockAddr = SockAddr::from(*addr);
        socket.connect_timeout(&addr, timeout)?;
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket with listener.
    pub fn new_with_listener(
        socket_option: SocketOption,
        addr: &SocketAddr,
    ) -> io::Result<AsyncSocket> {
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
        let addr: SockAddr = SockAddr::from(*addr);
        socket.bind(&addr)?;
        socket.listen(1024)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket with bind.
    pub fn new_with_bind(
        socket_option: SocketOption,
        addr: &SocketAddr,
    ) -> io::Result<AsyncSocket> {
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
        let addr: SockAddr = SockAddr::from(*addr);
        socket.bind(&addr)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket from TcpStream.
    /// Async Socket does not support non-blocking connect. Use TCP Stream to connect to the target.
    pub fn from_tcp_stream(tcp_stream: TcpStream) -> io::Result<AsyncSocket> {
        let socket = SystemSocket::from(tcp_stream);
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket from TcpListener.
    pub fn from_tcp_listener(tcp_listener: TcpListener) -> io::Result<AsyncSocket> {
        let socket = SystemSocket::from(tcp_listener);
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Constructs a new AsyncSocket from UdpSocket.
    pub fn from_udp_socket(udp_socket: UdpSocket) -> io::Result<AsyncSocket> {
        let socket = SystemSocket::from(udp_socket);
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Bind socket to address.
    pub async fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        //self.inner.writable().await?;
        self.inner.write_with(|inner| inner.bind(&addr)).await
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
    /// Write data with timeout.
    /// Return how many bytes were written.
    pub async fn write_timeout(&self, buf: &[u8], timeout: Duration) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self
                .inner
                .write_with(|inner| {
                    match inner.set_write_timeout(Some(timeout)) {
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                    inner.send(buf)
                })
                .await
            {
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
    /// Read data with timeout.
    /// Return how many bytes were read.
    pub async fn read_timeout(&self, buf: &mut Vec<u8>, timeout: Duration) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self
                .inner
                .read_with(|inner| {
                    match inner.set_read_timeout(Some(timeout)) {
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                    inner.recv(recv_buf)
                })
                .await
            {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    /// Get TTL or Hop Limit.
    pub async fn ttl(&self, ip_version: IpVersion) -> io::Result<u32> {
        match ip_version {
            IpVersion::V4 => self.inner.read_with(|inner| inner.ttl()).await,
            IpVersion::V6 => self.inner.read_with(|inner| inner.unicast_hops_v6()).await,
        }
    }
    /// Set TTL or Hop Limit.
    pub async fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        match ip_version {
            IpVersion::V4 => self.inner.write_with(|inner| inner.set_ttl(ttl)).await,
            IpVersion::V6 => {
                self.inner
                    .write_with(|inner| inner.set_unicast_hops_v6(ttl))
                    .await
            }
        }
    }
    /// Get the value of the IP_TOS option for this socket.
    pub async fn tos(&self) -> io::Result<u32> {
        self.inner.read_with(|inner| inner.tos()).await
    }
    /// Set the value of the IP_TOS option for this socket.
    pub async fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.inner.write_with(|inner| inner.set_tos(tos)).await
    }
    /// Get the value of the IP_RECVTOS option for this socket.
    pub async fn receive_tos(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.recv_tos()).await
    }
    /// Set the value of the IP_RECVTOS option for this socket.
    pub async fn set_receive_tos(&self, receive_tos: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_recv_tos(receive_tos))
            .await
    }
    /// Initiate TCP connection.
    pub async fn connect(&mut self, addr: &SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner.write_with(|inner| inner.connect(&addr)).await
    }
    /// Initiate a connection on this socket to the specified address, only only waiting for a certain period of time for the connection to be established.
    /// The non-blocking state of the socket is overridden by this function.
    pub async fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner
            .write_with(|inner| inner.connect_timeout(&addr, timeout))
            .await
    }
    /// Listen TCP connection.
    pub async fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.write_with(|inner| inner.listen(backlog)).await
    }
    /// Accept TCP connection.
    pub async fn accept(&self) -> io::Result<(AsyncSocket, SocketAddr)> {
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
    /// Get local address.
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.read_with(|inner| inner.local_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get peer address.
    pub async fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.read_with(|inner| inner.peer_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get type of the socket.
    pub async fn socket_type(&self) -> io::Result<crate::socket::SocketType> {
        match self.inner.read_with(|inner| inner.r#type()).await {
            Ok(socktype) => Ok(crate::socket::SocketType::from_type(socktype)),
            Err(e) => Err(e),
        }
    }
    /// Create a new socket with the same configuration and bound to the same address.
    pub async fn try_clone(&self) -> io::Result<AsyncSocket> {
        match self.inner.read_with(|inner| inner.try_clone()).await {
            Ok(socket) => Ok(AsyncSocket {
                inner: Arc::new(Async::new(socket)?),
            }),
            Err(e) => Err(e),
        }
    }

    /// Returns true if this socket is set to nonblocking mode, false otherwise.
    #[cfg(not(target_os = "windows"))]
    pub async fn is_nonblocking(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.nonblocking()).await
    }
    /// Set non-blocking mode.
    pub async fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_nonblocking(nonblocking))
            .await
    }
    /// Shutdown TCP connection.
    pub async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.write_with(|inner| inner.shutdown(how)).await
    }
    /// Get the value of the SO_BROADCAST option for this socket.
    pub async fn is_broadcast(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.broadcast()).await
    }
    /// Set the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast address.
    pub async fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_broadcast(broadcast))
            .await
    }
    /// Get the value of the `SO_ERROR` option on this socket.
    pub async fn get_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.read_with(|inner| inner.take_error()).await
    }
    /// Get the value of the `SO_KEEPALIVE` option on this socket.
    pub async fn is_keepalive(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.keepalive()).await
    }
    /// Set value for the `SO_KEEPALIVE` option on this socket.
    ///
    /// Enable sending of keep-alive messages on connection-oriented sockets.
    pub async fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_keepalive(keepalive))
            .await
    }
    /// Get the value of the SO_LINGER option on this socket.
    pub async fn linger(&self) -> io::Result<Option<Duration>> {
        self.inner.read_with(|inner| inner.linger()).await
    }
    /// Set value for the SO_LINGER option on this socket.
    pub async fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.write_with(|inner| inner.set_linger(dur)).await
    }
    /// Get the value of the `SO_RCVBUF` option on this socket.
    pub async fn receive_buffer_size(&self) -> io::Result<usize> {
        self.inner.read_with(|inner| inner.recv_buffer_size()).await
    }
    /// Set value for the `SO_RCVBUF` option on this socket.
    ///
    /// Changes the size of the operating system's receive buffer associated with the socket.
    pub async fn set_receive_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_recv_buffer_size(size))
            .await
    }
    /// Get value for the SO_RCVTIMEO option on this socket.
    pub async fn receive_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_with(|inner| inner.read_timeout()).await
    }
    /// Set value for the `SO_RCVTIMEO` option on this socket.
    pub async fn set_receive_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_read_timeout(duration))
            .await
    }
    /// Get value for the `SO_REUSEADDR` option on this socket.
    pub async fn reuse_address(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.reuse_address()).await
    }
    /// Set value for the `SO_REUSEADDR` option on this socket.
    ///
    /// This indicates that futher calls to `bind` may allow reuse of local addresses.
    pub async fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_reuse_address(reuse))
            .await
    }
    /// Get value for the `SO_SNDBUF` option on this socket.
    pub async fn send_buffer_size(&self) -> io::Result<usize> {
        self.inner.read_with(|inner| inner.send_buffer_size()).await
    }
    /// Set value for the `SO_SNDBUF` option on this socket.
    ///
    /// Changes the size of the operating system's send buffer associated with the socket.
    pub async fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_send_buffer_size(size))
            .await
    }
    /// Get value for the `SO_SNDTIMEO` option on this socket.
    pub async fn send_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_with(|inner| inner.write_timeout()).await
    }
    /// Set value for the `SO_SNDTIMEO` option on this socket.
    ///
    /// If `timeout` is `None`, then `write` and `send` calls will block indefinitely.
    pub async fn set_send_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_write_timeout(duration))
            .await
    }
    /// Get the value of the IP_HDRINCL option on this socket.
    pub async fn is_ip_header_included(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.header_included_v4()).await
    }
    /// Set the value of the `IP_HDRINCL` option on this socket.
    pub async fn set_ip_header_included(&self, include: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_header_included_v4(include))
            .await
    }
    /// Get the value of the TCP_NODELAY option on this socket.
    pub async fn is_nodelay(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.nodelay()).await
    }
    /// Set the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, segments are always sent as soon as possible, even if there is only a small amount of data.
    pub async fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_nodelay(nodelay))
            .await
    }
    /// Get TCP Stream
    /// This function will consume the socket and return a new std::net::TcpStream.
    pub fn into_tcp_stream(&self) -> io::Result<TcpStream> {
        let socket = Arc::try_unwrap(self.inner.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to unwrap Arc"))?
            .into_inner()?;
        let tcp_stream = TcpStream::from(socket);
        Ok(tcp_stream)
    }
    /// Get TCP Listener
    /// This function will consume the socket and return a new std::net::TcpListener.
    pub fn into_tcp_listener(&self) -> io::Result<TcpListener> {
        let socket = Arc::try_unwrap(self.inner.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to unwrap Arc"))?
            .into_inner()?;
        let tcp_listener = TcpListener::from(socket);
        Ok(tcp_listener)
    }
    /// Get UDP Socket
    /// This function will consume the socket and return a new std::net::UdpSocket.
    pub fn into_udp_socket(&self) -> io::Result<UdpSocket> {
        let socket = Arc::try_unwrap(self.inner.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to unwrap Arc"))?
            .into_inner()?;
        let udp_socket = UdpSocket::from(socket);
        Ok(udp_socket)
    }
}

/// Async TCP Stream.
#[derive(Clone, Debug)]
pub struct AsyncTcpStream {
    inner: Arc<Async<TcpStream>>,
}

impl AsyncTcpStream {
    /// Connect to a remote address.
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = Async::<TcpStream>::connect(addr).await?;
        Ok(AsyncTcpStream {
            inner: Arc::new(stream),
        })
    }

    /// Connect to a remote address with timeout.
    pub async fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = Async::<TcpStream>::connect(*addr)
            .or(async {
                Timer::after(timeout).await;
                Err(std::io::ErrorKind::TimedOut.into())
            })
            .await?;
        Ok(AsyncTcpStream {
            inner: Arc::new(stream),
        })
    }

    /// Get local address.
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.read_with(|inner| inner.local_addr()).await
    }

    /// Get peer address.
    pub async fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.read_with(|inner| inner.peer_addr()).await
    }

    /// Write data to the socket.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_with(|mut inner| inner.write(buf)).await
    }

    /// Attempts to write an entire buffer into this writer.
    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.inner
            .write_with(|mut inner| inner.write_all(buf))
            .await
    }

    /// Read data from the socket.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_with(|mut inner| inner.read(buf)).await
    }

    /// Read all bytes until EOF in this source, placing them into buf.
    pub async fn read_to_end(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.inner
            .read_with(|mut inner| inner.read_to_end(buf))
            .await
    }

    /// Read all bytes until EOF in this source, placing them into buf.
    /// This ignore io::Error on read_to_end because it is expected when reading response.
    /// If no response is received, and io::Error is occurred, return Err.
    pub async fn read_to_end_timeout(
        &self,
        buf: &mut Vec<u8>,
        timeout: Duration,
    ) -> io::Result<usize> {
        let mut io_error: io::Error = io::Error::new(io::ErrorKind::Other, "No response");
        match self
            .read_to_end(buf)
            .or(async {
                Timer::after(timeout).await;
                Err(std::io::ErrorKind::TimedOut.into())
            })
            .await
        {
            Ok(_) => {}
            Err(e) => {
                io_error = e;
            }
        }
        if buf.is_empty() {
            Err(io_error)
        } else {
            Ok(buf.len())
        }
    }

    /// Shutdown the socket.
    pub async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.write_with(|inner| inner.shutdown(how)).await
    }

    /// Get the value of the `SO_ERROR` option on this socket.
    pub async fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.read_with(|inner| inner.take_error()).await
    }
    /// Creates a new independently owned handle to the underlying socket.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let stream = self.inner.read_with(|inner| inner.try_clone()).await?;
        Ok(AsyncTcpStream {
            inner: Arc::new(Async::new(stream)?),
        })
    }

    /// Sets the read timeout to the timeout specified.
    pub async fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_read_timeout(dur))
            .await
    }

    /// Sets the write timeout to the timeout specified.
    pub async fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_write_timeout(dur))
            .await
    }

    /// Gets the read timeout of this socket.
    pub async fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_with(|inner| inner.read_timeout()).await
    }

    /// Gets the write timeout of this socket.
    pub async fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_with(|inner| inner.write_timeout()).await
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    pub async fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_nodelay(nodelay))
            .await
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    pub async fn nodelay(&self) -> io::Result<bool> {
        self.inner.read_with(|inner| inner.nodelay()).await
    }

    /// Sets the value for the IP_TTL option on this socket.
    pub async fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.write_with(|inner| inner.set_ttl(ttl)).await
    }

    /// Gets the value of the IP_TTL option on this socket.
    pub async fn ttl(&self) -> io::Result<u32> {
        self.inner.read_with(|inner| inner.ttl()).await
    }

    /// Moves this TCP stream into or out of nonblocking mode.
    pub async fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner
            .write_with(|inner| inner.set_nonblocking(nonblocking))
            .await
    }
}
