use crate::tcp::TcpConfig;
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Asynchronous TCP socket built on top of Tokio.
#[derive(Debug)]
pub struct AsyncTcpSocket {
    socket: Socket,
}

impl AsyncTcpSocket {
    /// Create a socket from the given configuration without connecting.
    pub fn from_config(config: &TcpConfig) -> io::Result<Self> {
        let socket = Socket::new(config.socket_family.to_domain(), config.socket_type.to_sock_type(), Some(Protocol::TCP))?;

        socket.set_nonblocking(true)?;
        
        if let Some(flag) = config.reuseaddr {
            socket.set_reuse_address(flag)?;
        }
        if let Some(flag) = config.nodelay {
            socket.set_nodelay(flag)?;
        }
        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(hoplimit) = config.hoplimit {
            socket.set_unicast_hops_v6(hoplimit)?;
        }
        if let Some(keepalive) = config.keepalive {
            socket.set_keepalive(keepalive)?;
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

        Ok(Self { socket })
    }

    /// Create a socket of arbitrary type (STREAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Convenience constructor for an IPv4 STREAM socket.
    pub fn v4_stream() -> io::Result<Self> {
        Self::new(Domain::IPV4, SockType::STREAM)
    }

    /// Convenience constructor for an IPv6 STREAM socket.
    pub fn v6_stream() -> io::Result<Self> {
        Self::new(Domain::IPV6, SockType::STREAM)
    }

    /// IPv4 RAW TCP. Requires administrator privileges.
    pub fn raw_v4() -> io::Result<Self> {
        Self::new(Domain::IPV4, SockType::RAW)
    }

    /// IPv6 RAW TCP. Requires administrator privileges.
    pub fn raw_v6() -> io::Result<Self> {
        Self::new(Domain::IPV6, SockType::RAW)
    }

    /// Connect to the target asynchronously.
    pub async fn connect(self, target: SocketAddr) -> io::Result<TcpStream> {
        // call connect
        match self.socket.connect(&target.into()) {
            Ok(_) => {
                // connection completed immediately (rare case)
                let std_stream: StdTcpStream = self.socket.into();
                return TcpStream::from_std(std_stream);
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::EINPROGRESS) =>
            {
                // wait until writable
                let std_stream: StdTcpStream = self.socket.into();
                let stream = TcpStream::from_std(std_stream)?;
                stream.writable().await?;

                // check the final connection state with SO_ERROR
                if let Some(err) = stream.take_error()? {
                    return Err(err);
                }

                return Ok(stream);
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                return Err(e);
            }
        }
    }

    /// Connect with a timeout to the target address.
    pub async fn connect_timeout(
        self,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        match tokio::time::timeout(timeout, self.connect(target)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection timed out",
            )),
        }
    }

    /// Start listening for incoming connections.
    pub fn listen(self, backlog: i32) -> io::Result<TcpListener> {
        self.socket.listen(backlog)?;

        let std_listener: StdTcpListener = self.socket.into();
        TcpListener::from_std(std_listener)
    }

    /// Send a raw TCP packet. Requires `SockType::RAW`.
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, &target.into())
    }

    /// Receive a raw TCP packet. Requires `SockType::RAW`.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Safety: `MaybeUninit<u8>` has the same memory layout as `u8`.
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

    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    // --- option helpers ---

    pub fn set_reuseaddr(&self, on: bool) -> io::Result<()> {
        self.socket.set_reuse_address(on)
    }

    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.socket.set_nodelay(on)
    }

    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_linger(dur)
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

    pub fn set_bind_device(&self, iface: &str) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        return self.socket.bind_device(Some(iface.as_bytes()));

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "fuchsia")))]
        {
            let _ = iface;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bind_device not supported on this OS",
            ))
        }
    }

    /// Retrieve the local address of the socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get socket address"))
    }

    /// Convert the internal socket into a Tokio `TcpStream`.
    pub fn into_tokio_stream(self) -> io::Result<TcpStream> {
        let std_stream: StdTcpStream = self.socket.into();
        TcpStream::from_std(std_stream)
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
