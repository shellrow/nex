//! Asynchronous raw datalink support for BSD BPF devices.

use crate::Config;
use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::bpf;
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use nex_sys;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const ETHERNET_HEADER_SIZE: usize = 14;
const ETHERNET_NULL_HEADER_SIZE: usize = 4;

#[derive(Debug)]
struct Inner {
    fd: RawFd,
    loopback: bool,
    buffer_offset: usize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe { nex_sys::close(self.fd) };
    }
}

/// Sender half of an asynchronous BPF socket.
#[derive(Clone, Debug)]
pub struct AsyncBpfSocketSender {
    inner: Arc<Inner>,
}

impl AsyncRawSender for AsyncBpfSocketSender {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        let offset = if self.inner.loopback {
            ETHERNET_HEADER_SIZE
        } else {
            0
        };
        let ret = unsafe {
            libc::write(
                self.inner.fd,
                packet[offset..].as_ptr() as *const libc::c_void,
                (packet.len() - offset) as libc::size_t,
            )
        };
        if ret >= 0 {
            return Poll::Ready(Ok(()));
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            let mut pfd = libc::pollfd {
                fd: self.inner.fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            unsafe { libc::poll(&mut pfd, 1, 0) };
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Err(err))
        }
    }
}

/// Receiver half of an asynchronous BPF socket.
#[derive(Debug)]
pub struct AsyncBpfSocketReceiver {
    inner: Arc<Inner>,
    read_buffer: Vec<u8>,
    packets: VecDeque<(usize, usize)>,
}

impl Stream for AsyncBpfSocketReceiver {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        let header_size = if me.inner.loopback {
            ETHERNET_NULL_HEADER_SIZE
        } else {
            0
        };
        if me.packets.is_empty() {
            let buffer = &mut me.read_buffer[me.inner.buffer_offset..];
            let ret = unsafe {
                libc::read(
                    me.inner.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len() as libc::size_t,
                )
            };
            if ret >= 0 {
                let buflen = ret as usize;
                let mut ptr = buffer.as_mut_ptr();
                let end = unsafe { buffer.as_ptr().add(buflen) };
                while (ptr as *const u8) < end {
                    unsafe {
                        let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                        let start =
                            ptr as isize + (*packet).bh_hdrlen as isize - buffer.as_ptr() as isize;
                        me.packets.push_back((
                            start as usize + header_size,
                            (*packet).bh_caplen as usize - header_size,
                        ));
                        let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                        ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                    }
                }
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    let mut pfd = libc::pollfd {
                        fd: me.inner.fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 0) };
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                } else {
                    return Poll::Ready(Some(Err(err)));
                }
            }
        }
        if let Some((mut start, mut len)) = me.packets.pop_front() {
            len += me.inner.buffer_offset;
            if me.inner.loopback {
                let padding = ETHERNET_HEADER_SIZE - me.inner.buffer_offset;
                start -= padding;
            }
            for i in (&mut me.read_buffer[start..start + me.inner.buffer_offset]).iter_mut() {
                *i = 0;
            }
            let pkt = me.read_buffer[start..start + len].to_vec();
            Poll::Ready(Some(Ok(pkt)))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Create a new asynchronous BPF socket channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "openbsd"))]
    fn get_fd(attempts: usize) -> io::Result<RawFd> {
        for i in 0..attempts {
            let file_name = format!("/dev/bpf{}", i);
            let c_file_name = CString::new(file_name).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid bpf device path")
            })?;
            let fd = unsafe { libc::open(c_file_name.as_ptr(), libc::O_RDWR, 0) };
            if fd != -1 {
                return Ok(fd);
            }
        }
        Err(io::Error::last_os_error())
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))]
    fn get_fd(_attempts: usize) -> io::Result<RawFd> {
        let c_file_name = CString::new("/dev/bpf")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid bpf device path"))?;
        let fd = unsafe { libc::open(c_file_name.as_ptr(), libc::O_RDWR, 0) };
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    let fd = get_fd(config.bpf_fd_attempts)?;

    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    for (i, c) in network_interface.name.bytes().enumerate() {
        iface.ifr_name[i] = c as libc::c_char;
    }

    let buflen = config.read_buffer_size as libc::c_uint;
    if unsafe { bpf::ioctl(fd, bpf::BIOCSBLEN, &buflen) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    if unsafe { bpf::ioctl(fd, bpf::BIOCSETIF, &iface) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &1) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    let mut dlt: libc::c_uint = 0;
    if unsafe { bpf::ioctl(fd, bpf::BIOCGDLT, &mut dlt) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    let mut loopback = false;
    let mut buffer_offset = 0usize;
    let mut read_buffer_size = config.read_buffer_size;
    if dlt == bpf::DLT_NULL {
        loopback = true;
        let align = mem::align_of::<bpf::bpf_hdr>();
        buffer_offset = (ETHERNET_HEADER_SIZE - ETHERNET_NULL_HEADER_SIZE).next_multiple_of(align);
        read_buffer_size += buffer_offset;
    } else {
        if unsafe { bpf::ioctl(fd, bpf::BIOCSHDRCMPLT, &1) } == -1 {
            let err = io::Error::last_os_error();
            unsafe {
                nex_sys::close(fd);
            }
            return Err(err);
        }
    }

    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    let read_buffer = vec![0u8; read_buffer_size];

    let inner = Arc::new(Inner {
        fd,
        loopback,
        buffer_offset,
    });
    let tx = AsyncBpfSocketSender {
        inner: inner.clone(),
    };
    let rx = AsyncBpfSocketReceiver {
        inner,
        read_buffer,
        packets: VecDeque::with_capacity(read_buffer_size / 64),
    };
    Ok(AsyncChannel::Ethernet(Box::new(tx), Box::new(rx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;

    #[test]
    #[ignore]
    fn async_raw_send() {
        let iface = Interface::default().expect("no default interface");
        let AsyncChannel::Ethernet(mut tx, _rx) =
            channel(&iface, Config::default()).expect("socket");
        let packet = [0u8; 42];
        futures::executor::block_on(async {
            let _ = poll_fn(|cx| tx.poll_send(cx, &packet)).await;
        });
    }
}
