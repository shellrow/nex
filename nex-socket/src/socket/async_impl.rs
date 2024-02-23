use async_io::Async;
use socket2::{SockAddr, Socket as SystemSocket};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use crate::socket::{IpVersion, SocketOption};
use crate::socket::to_socket_protocol;

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
    /// Bind socket to address.
    pub async fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.writable().await?;
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
    /// Initiate a connection on this socket to the specified address, only only waiting for a certain period of time for the connection to be established.
    /// The non-blocking state of the socket is overridden by this function.
    pub async fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(*addr);
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.connect_timeout(&addr, timeout))
            .await
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
    /// Get local address.
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.writable().await?;
        match self.inner.read_with(|inner| inner.local_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
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
    /// Shutdown TCP connection.
    pub async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.shutdown(how)).await
    }
    /// Set non-blocking mode.
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
