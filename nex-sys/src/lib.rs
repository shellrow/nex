#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

/// Any file descriptor on unix, only sockets on Windows.
pub struct FileDesc {
    pub fd: CSocket,
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

pub fn send_to(
    socket: CSocket,
    buffer: &[u8],
    dst: *const SockAddr,
    slen: SockLen,
) -> std::io::Result<usize> {
    let send_len = retry(&mut || unsafe {
        sendto(
            socket,
            buffer.as_ptr() as Buf,
            buffer.len() as BufLen,
            0,
            dst,
            slen,
        )
    });

    if send_len < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(send_len as usize)
    }
}

pub fn recv_from(
    socket: CSocket,
    buffer: &mut [u8],
    caddr: *mut SockAddrStorage,
) -> std::io::Result<usize> {
    let mut caddrlen = std::mem::size_of::<SockAddrStorage>() as SockLen;
    let len = retry(&mut || unsafe {
        recvfrom(
            socket,
            buffer.as_ptr() as MutBuf,
            buffer.len() as BufLen,
            0,
            caddr as *mut SockAddr,
            &mut caddrlen,
        )
    });

    if len < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}