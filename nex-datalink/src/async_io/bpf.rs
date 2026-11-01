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

use crate::bpf::{LinkType, parse_records, write_packet};

#[derive(Debug)]
struct Inner {
    fd: nex_sys::FileDesc,
    link_type: LinkType,
}

/// Sender half of an asynchronous BPF socket.
#[derive(Clone, Debug)]
pub struct AsyncBpfSocketSender {
    inner: Arc<Inner>,
}

impl AsyncRawSender for AsyncBpfSocketSender {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        self.poll_send_with(cx, packet, write_packet)
    }
}

impl AsyncBpfSocketSender {
    fn poll_send_with(
        &self,
        cx: &mut Context<'_>,
        packet: &[u8],
        write: impl FnOnce(libc::c_int, &[u8]) -> io::Result<()>,
    ) -> Poll<io::Result<()>> {
        let prepared = match self.inner.link_type.prepare_send(packet) {
            Ok(prepared) => prepared,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let err = match write(self.inner.fd.as_raw(), &prepared) {
            Ok(()) => return Poll::Ready(Ok(())),
            Err(error) => error,
        };
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
        if me.packets.is_empty() {
            let buffer = &mut me.read_buffer[..];
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
                me.packets = match parse_records(&buffer[..ret as usize]) {
                    Ok(packets) => packets,
                    Err(err) => return Poll::Ready(Some(Err(err))),
                };
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
        if let Some((start, len)) = me.packets.pop_front() {
            let packet = &me.read_buffer[start..start + len];
            let mut output = Vec::new();
            match me.inner.link_type.normalize(packet, &mut output) {
                Ok(()) => Poll::Ready(Some(Ok(output))),
                Err(err) => Poll::Ready(Some(Err(err))),
            }
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

    let mut buflen = config.read_buffer_size as libc::c_uint;
    // SAFETY: The descriptor is open and `buflen` has the exact argument type
    // expected by BIOCSBLEN.
    if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCSBLEN, &mut buflen) } == -1 {
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

    let link_type = LinkType::from_dlt(dlt)?;
    let read_buffer_size = buflen as usize;
    if link_type.header_complete() {
        // SAFETY: The descriptor is open and the ioctl reads an integer.
        if unsafe { bpf::ioctl(fd.as_raw(), bpf::BIOCSHDRCMPLT, &1) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    // SAFETY: The descriptor is open and F_SETFL retains no borrowed pointers.
    if unsafe { libc::fcntl(fd.as_raw(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let read_buffer = vec![0u8; read_buffer_size];

    let inner = Arc::new(Inner { fd, link_type });
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
    fn async_send_uses_link_framing_and_retries_whole_packet_after_would_block() {
        use crate::bpf::test_ip_frame;
        use std::os::{fd::IntoRawFd, unix::net::UnixDatagram};
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        // SAFETY: into_raw_fd transfers exclusive descriptor ownership.
        let fd = unsafe { nex_sys::FileDesc::from_raw(writer.into_raw_fd()) };
        let mut sender = AsyncBpfSocketSender {
            inner: Arc::new(Inner {
                fd,
                link_type: LinkType::Null,
            }),
        };
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buffer = [0; 128];
        for version in [4, 6] {
            let packet = test_ip_frame(version);
            assert!(matches!(
                sender.poll_send(&mut cx, &packet),
                Poll::Ready(Ok(()))
            ));
            let n = reader.recv(&mut buffer).unwrap();
            assert_eq!(
                &buffer[..n],
                &*LinkType::Null.prepare_send(&packet).unwrap()
            );
        }
        assert!(
            matches!(sender.poll_send(&mut cx, &[0; 13]), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            reader.recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let packet = test_ip_frame(6);
        #[derive(Default)]
        struct WakeCount(std::sync::atomic::AtomicUsize);
        impl futures::task::ArcWake for WakeCount {
            fn wake_by_ref(this: &Arc<Self>) {
                this.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let wakes = Arc::new(WakeCount::default());
        let waker = futures::task::waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(
            sender
                .poll_send_with(&mut cx, &packet, |_, bytes| {
                    assert_eq!(bytes, &*LinkType::Null.prepare_send(&packet).unwrap());
                    Err(io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                })
                .is_pending()
        );
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(matches!(sender.poll_send_with(&mut cx, &packet, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EINTR))
        }), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
        assert!(matches!(
            sender.poll_send(&mut cx, &packet),
            Poll::Ready(Ok(()))
        ));
        let n = reader.recv(&mut buffer).unwrap();
        assert_eq!(
            &buffer[..n],
            &*LinkType::Null.prepare_send(&packet).unwrap()
        );
        assert_eq!(
            reader.recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

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
