//! Cross-platform system helpers and low-level wrappers used by the nex crates.
//!
//! # Stability
//!
//! This crate is an implementation detail of the `nex` workspace. Its public
//! items exist so sibling crates can share platform bindings; they do not carry
//! the semver guarantees of the high-level `nex` API. Applications should use
//! `nex-core`, `nex-datalink`, `nex-packet`, or `nex-socket` instead.

#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

/// An owned Unix file descriptor or Windows socket.
#[derive(Debug)]
pub struct FileDesc {
    fd: CSocket,
}

impl FileDesc {
    /// Takes ownership of a raw descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open descriptor that the caller owns exclusively.
    /// After calling this function, no other code may close `fd`, and the caller
    /// must not construct another owning wrapper for it.
    pub unsafe fn from_raw(fd: CSocket) -> Self {
        Self { fd }
    }

    /// Returns the wrapped descriptor without transferring ownership.
    pub fn as_raw(&self) -> CSocket {
        self.fd
    }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        // SAFETY: `from_raw` requires exclusive ownership, and `drop` runs once
        // for this wrapper, so the descriptor is still owned and open here.
        unsafe {
            close(self.fd);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn socket_buffer_len(len: usize) -> std::io::Result<BufLen> {
    Ok(len)
}

#[cfg(target_os = "windows")]
fn socket_buffer_len(len: usize) -> std::io::Result<BufLen> {
    len.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer length exceeds the platform socket API limit",
        )
    })
}

/// Sends data to a socket, returning the number of bytes sent.
///
/// # Safety
///
/// `dst` must point to a socket address that is valid for reads of `slen`
/// bytes for the duration of the call.
pub unsafe fn send_to(
    socket: CSocket,
    buffer: &[u8],
    dst: *const SockAddr,
    slen: SockLen,
) -> std::io::Result<usize> {
    let buffer_len = socket_buffer_len(buffer.len())?;
    // SAFETY: The slice supplies a readable buffer of `buffer_len` bytes.
    // The caller guarantees that `dst` is readable for `slen` bytes.
    let send_len =
        retry(&mut || unsafe { sendto(socket, buffer.as_ptr() as Buf, buffer_len, 0, dst, slen) });

    if send_len < 0 {
        Err(last_socket_error())
    } else {
        Ok(send_len as usize)
    }
}

/// Receives data from a socket, returning the number of bytes read.
///
/// # Safety
///
/// `caddr` must point to writable storage for a `SockAddrStorage` value and
/// remain valid for the duration of the call.
pub unsafe fn recv_from(
    socket: CSocket,
    buffer: &mut [u8],
    caddr: *mut SockAddrStorage,
) -> std::io::Result<usize> {
    let buffer_len = socket_buffer_len(buffer.len())?;
    let mut caddrlen = std::mem::size_of::<SockAddrStorage>() as SockLen;
    // SAFETY: The mutable slice supplies writable storage for `buffer_len`
    // bytes, and the caller guarantees that `caddr` is valid writable storage.
    let len = retry(&mut || unsafe {
        recvfrom(
            socket,
            buffer.as_mut_ptr() as MutBuf,
            buffer_len,
            0,
            caddr as *mut SockAddr,
            &mut caddrlen,
        )
    });

    if len < 0 {
        Err(last_socket_error())
    } else {
        Ok(len as usize)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::FileDesc;
    use std::io::{self, Read};
    use std::os::{fd::IntoRawFd, unix::net::UnixStream};

    fn socket_pair() -> (FileDesc, UnixStream) {
        let (socket, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        // SAFETY: into_raw_fd transfers exclusive ownership of the open socket.
        (unsafe { FileDesc::from_raw(socket.into_raw_fd()) }, peer)
    }

    #[test]
    fn file_desc_closes_owned_descriptor_on_drop() {
        let (owned, mut peer) = socket_pair();
        drop(owned);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn file_desc_closes_owned_descriptor_on_early_error() {
        fn fail_after_ownership_transfer(_owned: FileDesc) -> io::Result<()> {
            Err(io::Error::other("injected setup failure"))
        }

        let (owned, mut peer) = socket_pair();
        assert!(fail_after_ownership_transfer(owned).is_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
