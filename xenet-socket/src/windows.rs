use socket2::SockAddr;
use std::cmp::min;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{SocketAddr, UdpSocket};
use std::ptr;
use std::sync::Once;
use std::time::Duration;

#[allow(non_camel_case_types)]
type c_int = i32;

#[allow(non_camel_case_types)]
type c_long = i32;

type DWORD = u32;
use windows_sys::Win32::Networking::WinSock::SIO_RCVALL;
use windows_sys::Win32::System::Threading::INFINITE;

#[allow(non_camel_case_types)]
type u_long = u32;

use windows_sys::Win32::Networking::WinSock::{self as sock, SOCKET, WSA_FLAG_NO_HANDLE_INHERIT};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP,
    IPPROTO_UDP,
};

pub(crate) const NO_INHERIT: c_int = 1 << (c_int::BITS - 1);
pub(crate) const MAX_BUF_LEN: usize = <c_int>::max_value() as usize;

use super::{IpVersion, SocketOption, SocketType};
use xenet_packet::ip::IpNextLevelProtocol;

pub fn check_socket_option(socket_option: SocketOption) -> Result<(), String> {
    match socket_option.ip_version {
        IpVersion::V4 => {
            match socket_option.socket_type {
                SocketType::Raw => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Icmp) => Ok(()),
                        Some(IpNextLevelProtocol::Tcp) => Err(String::from("TCP is not supported on IPv4 raw socket on Windows(Due to Winsock2 limitation))")),
                        Some(IpNextLevelProtocol::Udp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Datagram => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Icmp) => Ok(()),
                        Some(IpNextLevelProtocol::Udp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Stream => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Tcp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
            }
        }
        IpVersion::V6 => {
            match socket_option.socket_type {
                SocketType::Raw => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Icmpv6) => Ok(()),
                        Some(IpNextLevelProtocol::Tcp) => Err(String::from("TCP is not supported on IPv6 raw socket on Windows(Due to Winsock2 limitation))")),
                        Some(IpNextLevelProtocol::Udp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Datagram => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Icmpv6) => Ok(()),
                        Some(IpNextLevelProtocol::Udp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Stream => {
                    match socket_option.protocol {
                        Some(IpNextLevelProtocol::Tcp) => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
            }
        }
    }
}

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

pub(crate) fn init_socket() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = UdpSocket::bind("127.0.0.1:34254");
    });
}

pub(crate) fn ioctlsocket(socket: SOCKET, cmd: c_long, payload: &mut u_long) -> io::Result<()> {
    syscall!(
        ioctlsocket(socket, cmd, payload),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

pub(crate) fn create_socket(family: c_int, mut ty: c_int, protocol: c_int) -> io::Result<SOCKET> {
    init_socket();
    let flags = if ty & NO_INHERIT != 0 {
        ty = ty & !NO_INHERIT;
        WSA_FLAG_NO_HANDLE_INHERIT
    } else {
        0
    };
    syscall!(
        WSASocketW(
            family,
            ty,
            protocol,
            ptr::null_mut(),
            0,
            sock::WSA_FLAG_OVERLAPPED | flags,
        ),
        PartialEq::eq,
        sock::INVALID_SOCKET
    )
}

pub(crate) fn bind(socket: SOCKET, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(socket, addr.as_ptr(), addr.len()), PartialEq::ne, 0).map(|_| ())
}

#[allow(dead_code)]
pub(crate) fn set_nonblocking(socket: SOCKET, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as u_long;
    ioctlsocket(socket, sock::FIONBIO, &mut nonblocking)
}

pub(crate) fn set_promiscuous(socket: SOCKET, promiscuous: bool) -> io::Result<()> {
    let mut promiscuous = promiscuous as u_long;
    ioctlsocket(socket, SIO_RCVALL as i32, &mut promiscuous)
}

pub(crate) unsafe fn setsockopt<T>(
    socket: SOCKET,
    level: c_int,
    optname: i32,
    optval: T,
) -> io::Result<()> {
    syscall!(
        setsockopt(
            socket,
            level as i32,
            optname,
            (&optval as *const T).cast(),
            mem::size_of::<T>() as c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

pub(crate) fn into_ms(duration: Option<Duration>) -> DWORD {
    duration
        .map(|duration| min(duration.as_millis(), INFINITE as u128) as DWORD)
        .unwrap_or(0)
}

pub(crate) fn set_timeout_opt(
    fd: SOCKET,
    level: c_int,
    optname: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_ms(duration);
    unsafe { setsockopt(fd, level, optname, duration) }
}

pub(crate) fn recv_from(
    socket: SOCKET,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    unsafe {
        SockAddr::try_init(|storage, addrlen| {
            let res = syscall!(
                recvfrom(
                    socket,
                    buf.as_mut_ptr().cast(),
                    min(buf.len(), MAX_BUF_LEN) as c_int,
                    flags,
                    storage.cast(),
                    addrlen,
                ),
                PartialEq::eq,
                sock::SOCKET_ERROR
            );
            match res {
                Ok(n) => Ok(n as usize),
                Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => Ok(0),
                Err(err) => Err(err),
            }
        })
    }
}

/// Receive all IPv4 or IPv6 packets passing through a network interface.
pub struct ListenerSocket {
    inner: SOCKET,
}

impl ListenerSocket {
    pub fn new(
        socket_addr: SocketAddr,
        ip_version: IpVersion,
        protocol: Option<IpNextLevelProtocol>,
        timeout: Option<Duration>,
    ) -> io::Result<ListenerSocket> {
        let socket = match ip_version {
            IpVersion::V4 => match protocol {
                Some(IpNextLevelProtocol::Icmp) => {
                    create_socket(AF_INET as i32, sock::SOCK_RAW, IPPROTO_ICMP)?
                }
                Some(IpNextLevelProtocol::Tcp) => {
                    create_socket(AF_INET as i32, sock::SOCK_RAW, IPPROTO_TCP)?
                }
                Some(IpNextLevelProtocol::Udp) => {
                    create_socket(AF_INET as i32, sock::SOCK_RAW, IPPROTO_UDP)?
                }
                _ => create_socket(AF_INET as i32, sock::SOCK_RAW, IPPROTO_IP)?,
            },
            IpVersion::V6 => match protocol {
                Some(IpNextLevelProtocol::Icmpv6) => {
                    create_socket(AF_INET6 as i32, sock::SOCK_RAW, IPPROTO_ICMPV6)?
                }
                Some(IpNextLevelProtocol::Tcp) => {
                    create_socket(AF_INET6 as i32, sock::SOCK_RAW, IPPROTO_TCP)?
                }
                Some(IpNextLevelProtocol::Udp) => {
                    create_socket(AF_INET6 as i32, sock::SOCK_RAW, IPPROTO_UDP)?
                }
                _ => create_socket(AF_INET6 as i32, sock::SOCK_RAW, IPPROTO_IPV6)?,
            },
        };
        let sock_addr = SockAddr::from(socket_addr);
        bind(socket, &sock_addr)?;
        set_promiscuous(socket, true)?;
        set_timeout_opt(socket, sock::SOL_SOCKET, sock::SO_RCVTIMEO, timeout)?;
        Ok(ListenerSocket { inner: socket })
    }
    pub fn bind(&self, addr: &SockAddr) -> io::Result<()> {
        bind(self.inner, addr)
    }
    pub fn receive_from(&self, buf: &mut Vec<u8>) -> io::Result<(usize, SocketAddr)> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match recv_from(self.inner, recv_buf, 0) {
            Ok((n, addr)) => match addr.as_socket() {
                Some(socket_addr) => {
                    return Ok((n, socket_addr));
                }
                None => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid socket address",
                )),
            },
            Err(e) => Err(e),
        }
    }
}
