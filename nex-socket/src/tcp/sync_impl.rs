use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::tcp::TcpConfig;

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags};

/// Low level synchronous TCP socket.
#[derive(Debug)]
pub struct TcpSocket {
    socket: Socket,
}

impl TcpSocket {
    /// Build a socket according to `TcpSocketConfig`.
    pub fn from_config(config: &TcpConfig) -> io::Result<Self> {
        let socket = Socket::new(
            config.socket_family.to_domain(),
            config.socket_type.to_sock_type(),
            Some(Protocol::TCP),
        )?;

        socket.set_nonblocking(config.nonblocking)?;

        // Set socket options based on configuration
        if let Some(flag) = config.reuseaddr {
            socket.set_reuse_address(flag)?;
        }
        if let Some(flag) = config.nodelay {
            socket.set_nodelay(flag)?;
        }
        if let Some(dur) = config.linger {
            socket.set_linger(Some(dur))?;
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

    /// Create a socket of arbitrary type (STREAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::TCP))?;
        socket.set_nonblocking(false)?;
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

    /// Bind the socket to a specific address.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.bind(&addr.into())
    }

    /// Connect to a remote address.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(&addr.into())
    }

    /// Connect to the target address with a timeout.
    #[cfg(unix)]
    pub fn connect_timeout(&self, target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let raw_fd = self.socket.as_raw_fd();
        self.socket.set_nonblocking(true)?;

        // Try to connect first
        match self.socket.connect(&target.into()) {
            Ok(_) => { /* succeeded immediately */ }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.raw_os_error() == Some(libc::EINPROGRESS) =>
            {
                // Continue waiting
            }
            Err(e) => return Err(e),
        }

        // Wait for the connection using poll
        let timeout_ms = timeout.as_millis() as i32;
        use std::os::unix::io::BorrowedFd;
        // Safety: raw_fd is valid for the lifetime of this scope
        let mut fds = [PollFd::new(
            unsafe { BorrowedFd::borrow_raw(raw_fd) },
            PollFlags::POLLOUT,
        )];
        let n = poll(&mut fds, Some(timeout_ms as u16))?;

        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
        }

        // Check the result with `SO_ERROR`
        let err: i32 = self
            .socket
            .take_error()?
            .map(|e| e.raw_os_error().unwrap_or(0))
            .unwrap_or(0);
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }

        self.socket.set_nonblocking(false)?;

        match self.socket.try_clone() {
            Ok(cloned_socket) => {
                // Convert the socket into a `std::net::TcpStream`
                let std_stream: TcpStream = cloned_socket.into();
                Ok(std_stream)
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(windows)]
    pub fn connect_timeout(&self, target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        use std::mem::size_of;
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            getsockopt, WSAPoll, POLLWRNORM, SOCKET, SOCKET_ERROR, SOL_SOCKET, SO_ERROR, WSAPOLLFD,
        };

        let sock = self.socket.as_raw_socket() as SOCKET;
        self.socket.set_nonblocking(true)?;

        // Start connect
        match self.socket.connect(&target.into()) {
            Ok(_) => { /* connection succeeded immediately */ }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(10035) /* WSAEWOULDBLOCK */ => {}
            Err(e) => return Err(e),
        }

        // Wait using WSAPoll until writable
        let mut fds = [WSAPOLLFD {
            fd: sock,
            events: POLLWRNORM,
            revents: 0,
        }];

        let timeout_ms = timeout.as_millis().clamp(0, i32::MAX as u128) as i32;
        let result = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, timeout_ms) };
        if result == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        } else if result == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
        }

        // Check for errors via `SO_ERROR`
        let mut so_error: i32 = 0;
        let mut optlen = size_of::<i32>() as i32;
        let ret = unsafe {
            getsockopt(
                sock,
                SOL_SOCKET as i32,
                SO_ERROR as i32,
                &mut so_error as *mut _ as *mut _,
                &mut optlen,
            )
        };

        if ret == SOCKET_ERROR || so_error != 0 {
            return Err(io::Error::from_raw_os_error(so_error));
        }

        self.socket.set_nonblocking(false)?;

        let std_stream: TcpStream = self.socket.try_clone()?.into();
        Ok(std_stream)
    }

    /// Start listening for incoming connections.
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        self.socket.listen(backlog)
    }

    /// Accept an incoming connection.
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.socket.accept()?;
        Ok((stream.into(), addr.as_socket().unwrap()))
    }

    /// Convert the socket into a `TcpStream`.
    pub fn to_tcp_stream(self) -> io::Result<TcpStream> {
        Ok(self.socket.into())
    }

    /// Convert the socket into a `TcpListener`.
    pub fn to_tcp_listener(self) -> io::Result<TcpListener> {
        Ok(self.socket.into())
    }

    /// Send a raw packet (for RAW TCP use).
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, &target.into())
    }

    /// Receive a raw packet (for RAW TCP use).
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Safety: `MaybeUninit<u8>` is layout-compatible with `u8`.
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

    /// Shutdown the socket.
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    /// Set the socket to reuse the address.
    pub fn set_reuseaddr(&self, on: bool) -> io::Result<()> {
        self.socket.set_reuse_address(on)
    }

    /// Set the socket to not delay packets.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.socket.set_nodelay(on)
    }

    /// Set the linger option for the socket.
    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_linger(dur)
    }

    /// Set the time-to-live for IPv4 packets.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl(ttl)
    }

    /// Set the hop limit for IPv6 packets.
    pub fn set_hoplimit(&self, hops: u32) -> io::Result<()> {
        self.socket.set_unicast_hops_v6(hops)
    }

    /// Set the keepalive option for the socket.
    pub fn set_keepalive(&self, on: bool) -> io::Result<()> {
        self.socket.set_keepalive(on)
    }

    /// Set the bind device for the socket (Linux specific).
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to retrieve local address"))
    }

    /// Extract the RAW file descriptor for Unix.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }

    /// Extract the RAW socket handle for Windows.
    #[cfg(windows)]
    pub fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket.as_raw_socket()
    }
}
