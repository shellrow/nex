//! UDP socket.
//!
//! Provides synchronous and asynchronous UDP APIs along with
//! configuration utilities for common socket options.
mod async_impl;
mod config;
mod sync_impl;

use std::io;

use socket2::Socket;

use crate::SocketFamily;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn set_bool_sockopt(
    socket: &Socket,
    level: libc::c_int,
    optname: libc::c_int,
    on: bool,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let value: libc::c_int = if on { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn get_bool_sockopt(socket: &Socket, level: libc::c_int, optname: libc::c_int) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if ret == 0 {
        Ok(value != 0)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn set_recv_pktinfo(socket: &Socket, family: SocketFamily, on: bool) -> io::Result<()> {
    match family {
        SocketFamily::IPV4 => set_recv_pktinfo_v4(socket, on),
        SocketFamily::IPV6 => set_recv_pktinfo_v6(socket, on),
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) fn set_recv_pktinfo_v4(socket: &Socket, on: bool) -> io::Result<()> {
    set_bool_sockopt(socket, libc::IPPROTO_IP, libc::IP_PKTINFO, on)
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
pub(crate) fn set_recv_pktinfo_v4(_socket: &Socket, _on: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IP_PKTINFO is not supported on this platform",
    ))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) fn set_recv_pktinfo_v6(socket: &Socket, on: bool) -> io::Result<()> {
    set_bool_sockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, on)
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
pub(crate) fn set_recv_pktinfo_v6(_socket: &Socket, _on: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPV6_RECVPKTINFO is not supported on this platform",
    ))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) fn recv_pktinfo_v4(socket: &Socket) -> io::Result<bool> {
    get_bool_sockopt(socket, libc::IPPROTO_IP, libc::IP_PKTINFO)
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
pub(crate) fn recv_pktinfo_v4(_socket: &Socket) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IP_PKTINFO is not supported on this platform",
    ))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) fn recv_pktinfo_v6(socket: &Socket) -> io::Result<bool> {
    get_bool_sockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
pub(crate) fn recv_pktinfo_v6(_socket: &Socket) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPV6_RECVPKTINFO is not supported on this platform",
    ))
}

pub use async_impl::*;
pub use config::*;
pub use sync_impl::*;
