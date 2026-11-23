use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::tcp::TcpConfig;

#[cfg(all(test, unix))]
use std::os::fd::AsRawFd;

/// Low level synchronous TCP socket.
#[derive(Debug)]
pub struct TcpSocket {
    socket: Socket,
    #[cfg(windows)]
    nonblocking: bool,
}

impl TcpSocket {
    /// Build a socket according to `TcpSocketConfig`.
    pub fn from_config(config: &TcpConfig) -> io::Result<Self> {
        config.validate()?;

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
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ))]
        if let Some(flag) = config.reuseport {
            socket.set_reuse_port(flag)?;
        }
        if let Some(flag) = config.nodelay {
            socket.set_tcp_nodelay(flag)?;
        }
        if let Some(dur) = config.linger {
            socket.set_linger(Some(dur))?;
        }
        if let Some(ttl) = config.ttl {
            socket.set_ttl_v4(ttl)?;
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
        if let Some(size) = config.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = config.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(tos) = config.tos {
            socket.set_tos_v4(tos)?;
        }
        crate::apply_tclass_v6(&socket, config.tclass_v6)?;
        if let Some(only_v6) = config.only_v6 {
            socket.set_only_v6(only_v6)?;
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

        Ok(Self {
            socket,
            #[cfg(windows)]
            nonblocking: config.nonblocking,
        })
    }

    /// Create a socket of arbitrary type (STREAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::TCP))?;
        socket.set_nonblocking(false)?;
        Ok(Self {
            socket,
            #[cfg(windows)]
            nonblocking: false,
        })
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

    /// Connect to the target address with a timeout and return the connected stream.
    ///
    /// The returned `TcpStream` must be used for subsequent I/O.
    pub fn connect_timeout(&self, target: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        #[cfg(unix)]
        let nonblocking = self.socket.nonblocking()?;
        #[cfg(windows)]
        let nonblocking = self.nonblocking;

        let result = self.socket.connect_timeout(&target.into(), timeout);
        // Cloned handles share the socket mode. Restore it on failure as well.
        self.socket.set_nonblocking(nonblocking)?;
        result?;
        Ok(self.socket.try_clone()?.into())
    }

    /// Start listening for incoming connections.
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        self.socket.listen(backlog)
    }

    /// Accept an incoming connection.
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.socket.accept()?;
        let address = addr.as_socket().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "accepted peer did not provide an IP socket address",
            )
        })?;
        Ok((stream.into(), address))
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
        // SAFETY: `MaybeUninit<u8>` is layout-compatible with `u8`, and the
        // slice preserves the original buffer's length and lifetime.
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

    /// Get the socket address reuse option.
    pub fn reuseaddr(&self) -> io::Result<bool> {
        self.socket.reuse_address()
    }

    /// Set the socket port reuse option where supported.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    pub fn set_reuseport(&self, on: bool) -> io::Result<()> {
        self.socket.set_reuse_port(on)
    }

    /// Get the socket port reuse option where supported.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    pub fn reuseport(&self) -> io::Result<bool> {
        self.socket.reuse_port()
    }

    /// Set the socket to not delay packets.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.socket.set_tcp_nodelay(on)
    }

    /// Get the no delay option.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.socket.tcp_nodelay()
    }

    /// Set the linger option for the socket.
    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_linger(dur)
    }

    /// Set the time-to-live for IPv4 packets.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl_v4(ttl)
    }

    /// Get the time-to-live for IPv4 packets.
    pub fn ttl(&self) -> io::Result<u32> {
        self.socket.ttl_v4()
    }

    /// Set the hop limit for IPv6 packets.
    pub fn set_hoplimit(&self, hops: u32) -> io::Result<()> {
        self.socket.set_unicast_hops_v6(hops)
    }

    /// Get the hop limit for IPv6 packets.
    pub fn hoplimit(&self) -> io::Result<u32> {
        self.socket.unicast_hops_v6()
    }

    /// Set the keepalive option for the socket.
    pub fn set_keepalive(&self, on: bool) -> io::Result<()> {
        self.socket.set_keepalive(on)
    }

    /// Get the keepalive option.
    pub fn keepalive(&self) -> io::Result<bool> {
        self.socket.keepalive()
    }

    /// Set the receive buffer size.
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.socket.set_recv_buffer_size(size)
    }

    /// Get the receive buffer size.
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        self.socket.recv_buffer_size()
    }

    /// Set the send buffer size.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.socket.set_send_buffer_size(size)
    }

    /// Get the send buffer size.
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.socket.send_buffer_size()
    }

    /// Set IPv4 TOS / DSCP.
    pub fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.socket.set_tos_v4(tos)
    }

    /// Get IPv4 TOS / DSCP.
    pub fn tos(&self) -> io::Result<u32> {
        self.socket.tos_v4()
    }

    /// Set IPv6 traffic class where supported.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub fn set_tclass_v6(&self, tclass: u32) -> io::Result<()> {
        self.socket.set_tclass_v6(tclass)
    }

    /// Get IPv6 traffic class where supported.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub fn tclass_v6(&self) -> io::Result<u32> {
        self.socket.tclass_v6()
    }

    /// Set whether this socket is IPv6 only.
    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        self.socket.set_only_v6(only_v6)
    }

    /// Get whether this socket is IPv6 only.
    pub fn only_v6(&self) -> io::Result<bool> {
        self.socket.only_v6()
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
                "bind_device is not supported on this platform",
            ))
        }
    }

    /// Retrieve the local address of the socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("failed to retrieve local address"))
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

    /// Construct from a raw `socket2::Socket`. On Windows, `connect_timeout`
    /// restores blocking mode for externally supplied sockets.
    pub fn from_socket(socket: Socket) -> Self {
        Self {
            socket,
            // `socket2::Socket` does not expose a portable getter for the current
            // blocking mode, so externally supplied sockets default to blocking
            // expectations in this synchronous wrapper.
            #[cfg(windows)]
            nonblocking: false,
        }
    }

    /// Borrow the inner `socket2::Socket`.
    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    /// Consume and return the inner `socket2::Socket`.
    pub fn into_socket(self) -> Socket {
        self.socket
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use libc::{F_GETFL, O_NONBLOCK, fcntl};
    #[cfg(unix)]
    use std::net::TcpListener as StdTcpListener;

    #[cfg(unix)]
    fn socket_is_nonblocking(socket: &Socket) -> bool {
        // SAFETY: The descriptor belongs to the borrowed live socket and F_GETFL
        // neither takes ownership nor retains pointers.
        let flags = unsafe { fcntl(socket.as_raw_fd(), F_GETFL) };
        assert!(flags >= 0, "F_GETFL failed: {}", io::Error::last_os_error());
        (flags & O_NONBLOCK) != 0
    }

    #[cfg(unix)]
    #[test]
    fn connect_timeout_does_not_mutate_original_nonblocking_state_after_invalid_input() {
        let sock = TcpSocket::v4_stream().expect("socket");
        let target = "[::1]:80".parse().unwrap();
        assert!(
            sock.connect_timeout(target, Duration::from_secs(1))
                .is_err()
        );
        assert!(!socket_is_nonblocking(&sock.socket));
        sock.socket.set_nonblocking(true).expect("set nonblocking");

        let result = sock.connect_timeout("[::1]:80".parse().unwrap(), Duration::from_secs(1));
        assert!(result.is_err());
        assert!(socket_is_nonblocking(&sock.socket));
    }

    #[cfg(unix)]
    #[test]
    fn connect_timeout_does_not_mutate_original_blocking_state_after_success() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || listener.accept().expect("accept"));

        let sock = TcpSocket::v4_stream().expect("socket");
        sock.socket.set_nonblocking(false).expect("set blocking");
        let _stream = sock
            .connect_timeout(addr, Duration::from_secs(1))
            .expect("connect");

        assert!(!socket_is_nonblocking(&sock.socket));
        let _ = handle.join();
    }
}
