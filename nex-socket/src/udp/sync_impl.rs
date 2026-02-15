use crate::udp::UdpConfig;
use socket2::{Domain, Protocol, Socket, Type as SockType};
use std::io;
use std::net::IpAddr;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

/// Synchronous low level UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: Socket,
}

/// Metadata returned from `recv_msg`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpRecvMeta {
    /// Number of bytes received into the data buffer.
    pub bytes_read: usize,
    /// Source address of the datagram.
    pub source_addr: SocketAddr,
    /// Destination address that received the datagram, if provided by ancillary data.
    pub destination_addr: Option<IpAddr>,
    /// Interface index on which the datagram was received, if provided.
    pub interface_index: Option<u32>,
}

/// Optional metadata used by `send_msg`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UdpSendMeta {
    /// Explicit source IP address to use for transmission when supported.
    pub source_addr: Option<IpAddr>,
    /// Explicit outgoing interface index when supported.
    pub interface_index: Option<u32>,
}

impl UdpSocket {
    /// Create a socket from the provided configuration.
    pub fn from_config(config: &UdpConfig) -> io::Result<Self> {
        let socket = Socket::new(
            config.socket_family.to_domain(),
            config.socket_type.to_sock_type(),
            Some(Protocol::UDP),
        )?;

        socket.set_nonblocking(false)?;

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
        if let Some(size) = config.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = config.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(tos) = config.tos {
            socket.set_tos(tos)?;
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
        if let Some(tclass) = config.tclass_v6 {
            socket.set_tclass_v6(tclass)?;
        }
        if let Some(only_v6) = config.only_v6 {
            socket.set_only_v6(only_v6)?;
        }
        if let Some(on) = config.recv_pktinfo {
            crate::udp::set_recv_pktinfo(&socket, config.socket_family, on)?;
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

    /// Create a socket of arbitrary type (DGRAM or RAW).
    pub fn new(domain: Domain, sock_type: SockType) -> io::Result<Self> {
        let socket = Socket::new(domain, sock_type, Some(Protocol::UDP))?;
        socket.set_nonblocking(false)?;
        Ok(Self { socket })
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

    /// Send data.
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, &target.into())
    }

    /// Send data with ancillary metadata (`sendmsg` on Unix).
    ///
    /// When supported by the current OS, source address and interface index are
    /// propagated using packet-info control messages.
    #[cfg(unix)]
    pub fn send_msg(
        &self,
        buf: &[u8],
        target: SocketAddr,
        meta: Option<&UdpSendMeta>,
    ) -> io::Result<usize> {
        use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn, SockaddrIn6, sendmsg};
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;

        let iov = [IoSlice::new(buf)];
        let raw_fd = self.socket.as_raw_fd();

        match target {
            SocketAddr::V4(addr) => {
                let sockaddr = SockaddrIn::from(addr);
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "netbsd",
                    target_vendor = "apple"
                ))]
                {
                    if let Some(meta) = meta {
                        if meta.source_addr.is_some() || meta.interface_index.is_some() {
                            if let Some(src) = meta.source_addr {
                                if !src.is_ipv4() {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "source_addr family does not match target",
                                    ));
                                }
                            }
                            let mut pktinfo: libc::in_pktinfo = unsafe { std::mem::zeroed() };
                            if let Some(src) = meta.source_addr.and_then(|ip| match ip {
                                IpAddr::V4(v4) => Some(v4),
                                IpAddr::V6(_) => None,
                            }) {
                                pktinfo.ipi_spec_dst.s_addr = u32::from_ne_bytes(src.octets());
                            }
                            if let Some(ifindex) = meta.interface_index {
                                pktinfo.ipi_ifindex = ifindex.try_into().map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "interface_index is out of range for this platform",
                                    )
                                })?;
                            }
                            let cmsgs = [ControlMessage::Ipv4PacketInfo(&pktinfo)];
                            return sendmsg(
                                raw_fd,
                                &iov,
                                &cmsgs,
                                MsgFlags::empty(),
                                Some(&sockaddr),
                            )
                            .map_err(|e| io::Error::from_raw_os_error(e as i32));
                        }
                    }
                }
                if let Some(meta) = meta {
                    if meta.source_addr.is_some() || meta.interface_index.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "send_msg packet-info metadata is not supported on this platform",
                        ));
                    }
                }
                sendmsg(raw_fd, &iov, &[], MsgFlags::empty(), Some(&sockaddr))
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))
            }
            SocketAddr::V6(addr) => {
                let sockaddr = SockaddrIn6::from(addr);
                #[cfg(any(
                    target_os = "android",
                    target_os = "freebsd",
                    target_os = "linux",
                    target_os = "netbsd",
                    target_vendor = "apple"
                ))]
                {
                    if let Some(meta) = meta {
                        if meta.source_addr.is_some() || meta.interface_index.is_some() {
                            if let Some(src) = meta.source_addr {
                                if !src.is_ipv6() {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "source_addr family does not match target",
                                    ));
                                }
                            }
                            let mut pktinfo: libc::in6_pktinfo = unsafe { std::mem::zeroed() };
                            if let Some(src) = meta.source_addr.and_then(|ip| match ip {
                                IpAddr::V4(_) => None,
                                IpAddr::V6(v6) => Some(v6),
                            }) {
                                pktinfo.ipi6_addr.s6_addr = src.octets();
                            }
                            if let Some(ifindex) = meta.interface_index {
                                pktinfo.ipi6_ifindex = ifindex.try_into().map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "interface_index is out of range for this platform",
                                    )
                                })?;
                            }
                            let cmsgs = [ControlMessage::Ipv6PacketInfo(&pktinfo)];
                            return sendmsg(
                                raw_fd,
                                &iov,
                                &cmsgs,
                                MsgFlags::empty(),
                                Some(&sockaddr),
                            )
                            .map_err(|e| io::Error::from_raw_os_error(e as i32));
                        }
                    }
                }
                if let Some(meta) = meta {
                    if meta.source_addr.is_some() || meta.interface_index.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "send_msg packet-info metadata is not supported on this platform",
                        ));
                    }
                }
                sendmsg(raw_fd, &iov, &[], MsgFlags::empty(), Some(&sockaddr))
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))
            }
        }
    }

    /// Send data with ancillary metadata (`sendmsg` is not available on this platform build).
    #[cfg(not(unix))]
    pub fn send_msg(
        &self,
        _buf: &[u8],
        _target: SocketAddr,
        _meta: Option<&UdpSendMeta>,
    ) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "send_msg is only supported on Unix",
        ))
    }

    /// Receive data.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Safety: `MaybeUninit<u8>` has the same layout as `u8`.
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

    /// Receive data with ancillary metadata (`recvmsg` on Unix).
    ///
    /// This allows extracting packet-info control messages such as destination
    /// address and incoming interface index when enabled with
    /// `set_recv_pktinfo_v4` / `set_recv_pktinfo_v6`.
    #[cfg(unix)]
    pub fn recv_msg(&self, buf: &mut [u8]) -> io::Result<UdpRecvMeta> {
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
        use std::io::IoSliceMut;
        use std::os::fd::AsRawFd;

        let mut iov = [IoSliceMut::new(buf)];
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_vendor = "apple",
            target_os = "netbsd"
        ))]
        let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo);
        #[cfg(all(
            not(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux",
                target_vendor = "apple",
                target_os = "netbsd"
            )),
            any(target_os = "freebsd", target_os = "openbsd")
        ))]
        let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);
        #[cfg(all(
            not(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux",
                target_vendor = "apple",
                target_os = "netbsd"
            )),
            not(any(target_os = "freebsd", target_os = "openbsd"))
        ))]
        let mut cmsgspace = nix::cmsg_space!(libc::c_int);
        let msg = recvmsg::<SockaddrStorage>(
            self.socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsgspace),
            MsgFlags::empty(),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

        let source_addr = msg
            .address
            .and_then(|addr: SockaddrStorage| {
                if let Some(v4) = addr.as_sockaddr_in() {
                    return Some(SocketAddr::from(*v4));
                }
                if let Some(v6) = addr.as_sockaddr_in6() {
                    return Some(SocketAddr::from(*v6));
                }
                None
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid source address"))?;

        let mut destination_addr = None;
        let mut interface_index = None;

        if let Ok(cmsgs) = msg.cmsgs() {
            for cmsg in cmsgs {
                match cmsg {
                    #[cfg(any(
                        target_os = "android",
                        target_os = "fuchsia",
                        target_os = "linux",
                        target_vendor = "apple",
                        target_os = "netbsd"
                    ))]
                    ControlMessageOwned::Ipv4PacketInfo(info) => {
                        destination_addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(
                            info.ipi_addr.s_addr.to_ne_bytes(),
                        )));
                        interface_index = Some(info.ipi_ifindex.try_into().map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "received invalid interface index",
                            )
                        })?);
                    }
                    #[cfg(any(
                        target_os = "android",
                        target_os = "freebsd",
                        target_os = "linux",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "tvos",
                        target_os = "visionos",
                        target_os = "watchos",
                        target_os = "netbsd",
                        target_os = "openbsd"
                    ))]
                    ControlMessageOwned::Ipv6PacketInfo(info) => {
                        destination_addr =
                            Some(IpAddr::V6(std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                        interface_index = Some(info.ipi6_ifindex.try_into().map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "received invalid interface index",
                            )
                        })?);
                    }
                    _ => {}
                }
            }
        }

        Ok(UdpRecvMeta {
            bytes_read: msg.bytes,
            source_addr,
            destination_addr,
            interface_index,
        })
    }

    /// Receive data with ancillary metadata (`recvmsg` is not available on this platform build).
    #[cfg(not(unix))]
    pub fn recv_msg(&self, _buf: &mut [u8]) -> io::Result<UdpRecvMeta> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "recv_msg is only supported on Unix",
        ))
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl(ttl)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        self.socket.ttl()
    }

    pub fn set_hoplimit(&self, hops: u32) -> io::Result<()> {
        self.socket.set_unicast_hops_v6(hops)
    }

    pub fn hoplimit(&self) -> io::Result<u32> {
        self.socket.unicast_hops_v6()
    }

    pub fn set_reuseaddr(&self, on: bool) -> io::Result<()> {
        self.socket.set_reuse_address(on)
    }

    pub fn reuseaddr(&self) -> io::Result<bool> {
        self.socket.reuse_address()
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
    pub fn set_reuseport(&self, on: bool) -> io::Result<()> {
        self.socket.set_reuse_port(on)
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
    pub fn reuseport(&self) -> io::Result<bool> {
        self.socket.reuse_port()
    }

    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.socket.set_broadcast(on)
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        self.socket.broadcast()
    }

    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.socket.set_recv_buffer_size(size)
    }

    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        self.socket.recv_buffer_size()
    }

    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.socket.set_send_buffer_size(size)
    }

    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.socket.send_buffer_size()
    }

    pub fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.socket.set_tos(tos)
    }

    pub fn tos(&self) -> io::Result<u32> {
        self.socket.tos()
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
    pub fn set_tclass_v6(&self, tclass: u32) -> io::Result<()> {
        self.socket.set_tclass_v6(tclass)
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
    pub fn tclass_v6(&self) -> io::Result<u32> {
        self.socket.tclass_v6()
    }

    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        self.socket.set_only_v6(only_v6)
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        self.socket.only_v6()
    }

    pub fn set_keepalive(&self, on: bool) -> io::Result<()> {
        self.socket.set_keepalive(on)
    }

    pub fn keepalive(&self) -> io::Result<bool> {
        self.socket.keepalive()
    }

    /// Enable IPv4 packet-info ancillary data receiving (`IP_PKTINFO`) where supported.
    pub fn set_recv_pktinfo_v4(&self, on: bool) -> io::Result<()> {
        crate::udp::set_recv_pktinfo_v4(&self.socket, on)
    }

    /// Enable IPv6 packet-info ancillary data receiving (`IPV6_RECVPKTINFO`) where supported.
    pub fn set_recv_pktinfo_v6(&self, on: bool) -> io::Result<()> {
        crate::udp::set_recv_pktinfo_v6(&self.socket, on)
    }

    /// Query whether IPv4 packet-info ancillary data receiving is enabled.
    pub fn recv_pktinfo_v4(&self) -> io::Result<bool> {
        crate::udp::recv_pktinfo_v4(&self.socket)
    }

    /// Query whether IPv6 packet-info ancillary data receiving is enabled.
    pub fn recv_pktinfo_v6(&self) -> io::Result<bool> {
        crate::udp::recv_pktinfo_v6(&self.socket)
    }

    /// Retrieve the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to retrieve local address"))
    }

    /// Convert into a raw `std::net::UdpSocket`.
    pub fn to_std(self) -> io::Result<StdUdpSocket> {
        Ok(self.socket.into())
    }

    /// Construct from a raw `socket2::Socket`.
    pub fn from_socket(socket: Socket) -> Self {
        Self { socket }
    }

    /// Borrow the inner `socket2::Socket`.
    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    /// Consume and return the inner `socket2::Socket`.
    pub fn into_socket(self) -> Socket {
        self.socket
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_v4_socket() {
        let sock = UdpSocket::v4_dgram().expect("create socket");
        let addr = sock.local_addr().expect("addr");
        assert!(addr.is_ipv4());
    }
}
