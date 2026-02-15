use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

pub type CSocket = libc::c_int;
pub type Buf = *const libc::c_void;
pub type MutBuf = *mut libc::c_void;
pub type BufLen = libc::size_t;
pub type CouldFail = libc::ssize_t;
pub type SockLen = libc::socklen_t;
pub type MutSockLen = *mut libc::socklen_t;
pub type SockAddr = libc::sockaddr;
pub type SockAddrIn = libc::sockaddr_in;
pub type SockAddrIn6 = libc::sockaddr_in6;
pub type SockAddrStorage = libc::sockaddr_storage;
pub type SockAddrFamily = libc::sa_family_t;
pub type SockAddrFamily6 = libc::sa_family_t;
pub type InAddr = libc::in_addr;
pub type In6Addr = libc::in6_addr;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "netbsd")))]
pub type TvUsecType = libc::c_long;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "netbsd"))]
pub type TvUsecType = libc::c_int;

pub const AF_INET: libc::c_int = libc::AF_INET;
pub const AF_INET6: libc::c_int = libc::AF_INET6;

pub use libc::{IFF_BROADCAST, IFF_LOOPBACK, IFF_MULTICAST, IFF_POINTOPOINT, IFF_UP};

pub unsafe fn close(sock: CSocket) {
    unsafe {
        let _ = libc::close(sock);
    }
}

fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

pub fn sockaddr_to_addr(storage: &SockAddrStorage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        AF_INET => {
            assert!(len as usize >= mem::size_of::<SockAddrIn>());
            let storage: &SockAddrIn = unsafe { mem::transmute(storage) };
            let ip = ipv4_addr_int(storage.sin_addr);
            // octets
            let o1 = (ip >> 24) as u8;
            let o2 = (ip >> 16) as u8;
            let o3 = (ip >> 8) as u8;
            let o4 = ip as u8;
            let sockaddrv4 =
                SocketAddrV4::new(Ipv4Addr::new(o1, o2, o3, o4), ntohs(storage.sin_port));
            Ok(SocketAddr::V4(sockaddrv4))
        }
        AF_INET6 => {
            assert!(len as usize >= mem::size_of::<SockAddrIn6>());
            let storage: &SockAddrIn6 = unsafe { mem::transmute(storage) };
            let arr: [u16; 8] = unsafe { mem::transmute(storage.sin6_addr.s6_addr) };
            // hextets
            let h1 = ntohs(arr[0]);
            let h2 = ntohs(arr[1]);
            let h3 = ntohs(arr[2]);
            let h4 = ntohs(arr[3]);
            let h5 = ntohs(arr[4]);
            let h6 = ntohs(arr[5]);
            let h7 = ntohs(arr[6]);
            let h8 = ntohs(arr[7]);
            let ip = Ipv6Addr::new(h1, h2, h3, h4, h5, h6, h7, h8);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                ntohs(storage.sin6_port),
                u32::from_be(storage.sin6_flowinfo),
                storage.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Not supported")),
    }
}

#[inline(always)]
pub fn ipv4_addr_int(addr: InAddr) -> u32 {
    (addr.s_addr as u32).to_be()
}

/// Convert a platform specific `timeval` into a Duration.
pub fn timeval_to_duration(tv: libc::timeval) -> Duration {
    Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000)
}

/// Convert a Duration into a platform specific `timeval`.
pub fn duration_to_timeval(dur: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_usec: dur.subsec_micros() as TvUsecType,
    }
}

/// Convert a platform specific `timespec` into a Duration.
pub fn timespec_to_duration(ts: libc::timespec) -> Duration {
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Convert a Duration into a platform specific `timespec`.
pub fn duration_to_timespec(dur: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_nsec: (dur.subsec_nanos() as TvUsecType).into(),
    }
}

pub unsafe fn sendto(
    socket: CSocket,
    buf: Buf,
    len: BufLen,
    flags: libc::c_int,
    addr: *const SockAddr,
    addrlen: SockLen,
) -> CouldFail {
    unsafe { libc::sendto(socket, buf, len, flags, addr, addrlen) }
}

pub unsafe fn recvfrom(
    socket: CSocket,
    buf: MutBuf,
    len: BufLen,
    flags: libc::c_int,
    addr: *mut SockAddr,
    addrlen: *mut SockLen,
) -> CouldFail {
    unsafe { libc::recvfrom(socket, buf, len, flags, addr, addrlen) }
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::ssize_t
where
    F: FnMut() -> libc::ssize_t,
{
    loop {
        let ret = f();
        if ret != -1 || errno() as isize != libc::EINTR as isize {
            return ret;
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_timeval_round_trip() {
        let dur = Duration::new(1, 500_000_000);
        let tv = duration_to_timeval(dur);
        assert_eq!(timeval_to_duration(tv), dur);
    }

    #[test]
    fn test_timespec_round_trip() {
        let dur = Duration::new(2, 123_456_789);
        let ts = duration_to_timespec(dur);
        assert_eq!(timespec_to_duration(ts), dur);
    }

    #[test]
    fn test_ipv4_addr_int() {
        let addr = InAddr {
            s_addr: u32::from_be(0x7f000001),
        };
        assert_eq!(ipv4_addr_int(addr), 0x7f000001);
    }
}
