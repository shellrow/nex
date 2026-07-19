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
    fd: nex_sys::FileDesc,
    loopback: bool,
    buffer_offset: usize,
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
        if packet.len() < offset {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "loopback packets must include an Ethernet header",
            )));
        }
        // SAFETY: The descriptor is owned by `inner`; the packet slice remains
        // readable for the duration of `write`.
        let ret = unsafe {
            libc::write(
                self.inner.fd.as_raw(),
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
                fd: self.inner.fd.as_raw(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: `pfd` points to one initialized poll descriptor.
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
            // SAFETY: The descriptor is open and `buffer` is writable for its
            // full reported length.
            let ret = unsafe {
                libc::read(
                    me.inner.fd.as_raw(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len() as libc::size_t,
                )
            };
            if ret >= 0 {
                let buflen = ret as usize;
                let mut cursor = 0usize;
                while cursor < buflen {
                    let remaining = buflen - cursor;
                    if remaining < mem::size_of::<bpf::bpf_hdr>() {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated BPF record header",
                        ))));
                    }
                    // SAFETY: The size check proves the complete header is
                    // in-bounds. `read_unaligned` handles Vec<u8>'s alignment.
                    let packet = unsafe {
                        std::ptr::read_unaligned(buffer.as_ptr().add(cursor) as *const bpf::bpf_hdr)
                    };
                    let header_len = packet.bh_hdrlen as usize;
                    let captured_len = packet.bh_caplen as usize;
                    let Some(record_len) = header_len.checked_add(captured_len) else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BPF record length overflow",
                        ))));
                    };
                    if header_len < mem::size_of::<bpf::bpf_hdr>()
                        || captured_len < header_size
                        || record_len > remaining
                    {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid BPF record lengths",
                        ))));
                    }
                    me.packets.push_back((
                        cursor + header_len + header_size,
                        captured_len - header_size,
                    ));
                    let Ok(record_len) = isize::try_from(record_len) else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BPF record exceeds platform pointer range",
                        ))));
                    };
                    let Some(next) = cursor.checked_add(bpf::BPF_WORDALIGN(record_len) as usize)
                    else {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BPF record offset overflow",
                        ))));
                    };
                    cursor = next;
                }
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    let mut pfd = libc::pollfd {
                        fd: me.inner.fd.as_raw(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: `pfd` points to one initialized poll descriptor.
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
            for i in me.read_buffer[start..start + me.inner.buffer_offset].iter_mut() {
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
            // SAFETY: `c_file_name` is a live, NUL-terminated path and the
            // selected flags require no variadic mode argument.
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
        // SAFETY: `c_file_name` is a live, NUL-terminated path and the selected
        // flags require no variadic mode argument.
        let fd = unsafe { libc::open(c_file_name.as_ptr(), libc::O_RDWR, 0) };
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    let raw_fd = get_fd(config.bpf_fd_attempts)?;
    // SAFETY: `raw_fd` was just opened and exclusive ownership moves into the
    // guard exactly once.
    let fd = unsafe { nex_sys::FileDesc::from_raw(raw_fd) };

    // SAFETY: A zero bit pattern is a valid initial value for `ifreq`.
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    for (i, c) in network_interface.name.bytes().enumerate() {
        iface.ifr_name[i] = c as libc::c_char;
    }

    let buflen = config.read_buffer_size as libc::c_uint;
    // SAFETY: The descriptor is open and `buflen` has the exact argument type
    // expected by BIOCSBLEN.
    if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCSBLEN, &buflen) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `iface` remains readable throughout the ioctl call.
    if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCSETIF, &iface) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: The descriptor is open and the integer argument is valid for
    // BIOCIMMEDIATE.
    if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCIMMEDIATE, &1) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut dlt: libc::c_uint = 0;
    // SAFETY: `dlt` is writable for the returned device type.
    if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCGDLT, &mut dlt) } == -1 {
        return Err(io::Error::last_os_error());
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
        // SAFETY: The descriptor is open and the integer argument is valid for
        // BIOCSHDRCMPLT.
        if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCSHDRCMPLT, &1) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    // SAFETY: The descriptor is open and F_SETFL retains no borrowed pointers.
    if unsafe { libc::fcntl(fd.as_raw(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
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
