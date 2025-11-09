use windows_sys::Win32::Networking::WinSock as ws;

pub const IFF_UP: u32 = ws::IFF_UP;
pub const IFF_BROADCAST: u32 = ws::IFF_BROADCAST;
pub const IFF_LOOPBACK: u32 = ws::IFF_LOOPBACK;
pub const IFF_POINTOPOINT: u32 = ws::IFF_POINTTOPOINT;
pub const IFF_MULTICAST: u32 = ws::IFF_MULTICAST;

pub type CSocket = ws::SOCKET;
pub type Buf = *const libc::c_void;
pub type MutBuf = *mut libc::c_char;
pub type BufLen = libc::c_int;
pub type CouldFail = libc::c_int;
pub type SockLen = libc::c_int;
pub type MutSockLen = *mut libc::c_int;
pub type SockAddr = ws::SOCKADDR;
pub type SockAddrIn = ws::SOCKADDR_IN;
pub type SockAddrIn6 = ws::SOCKADDR_IN6;
pub type SockAddrStorage = ws::SOCKADDR_STORAGE;
pub type SockAddrFamily = ws::ADDRESS_FAMILY;
pub type SockAddrFamily6 = ws::ADDRESS_FAMILY;
pub type InAddr = ws::IN_ADDR;
pub type In6Addr = ws::IN6_ADDR;

pub unsafe fn close(sock: CSocket) {
    unsafe {
        let _ = ws::closesocket(sock);
    }
}

pub unsafe fn sendto(
    socket: CSocket,
    buf: Buf,
    len: BufLen,
    flags: libc::c_int,
    to: *const SockAddr,
    tolen: SockLen,
) -> CouldFail {
    unsafe { ws::sendto(socket, buf as *const u8, len, flags, to, tolen) }
}

pub unsafe fn recvfrom(
    socket: CSocket,
    buf: MutBuf,
    len: BufLen,
    flags: libc::c_int,
    addr: *mut SockAddr,
    addrlen: *mut SockLen,
) -> CouldFail {
    unsafe { ws::recvfrom(socket, buf as *mut u8, len, flags, addr, addrlen) }
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::c_int
where
    F: FnMut() -> libc::c_int,
{
    loop {
        let ret = f();
        if ret != -1 || errno() as isize != ws::WSAEINTR as isize {
            return ret;
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}
