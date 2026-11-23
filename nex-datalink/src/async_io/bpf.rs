//! Asynchronous raw datalink support for BSD BPF devices.

use crate::Config;
use crate::async_io::{AsyncChannel, AsyncRawSender};
use async_io::Async;
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::bpf::{LinkType, parse_records, write_packet};

#[derive(Debug)]
struct Inner {
    fd: Async<OwnedFd>,
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
        let err = match write(self.inner.fd.as_raw_fd(), &prepared) {
            Ok(()) => return Poll::Ready(Ok(())),
            Err(error) => error,
        };
        if err.kind() == io::ErrorKind::WouldBlock {
            let readiness = self.inner.fd.poll_writable(cx);
            super::retry_when_ready(cx, readiness)
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
                    me.inner.fd.as_raw_fd(),
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
                    let readiness = me.inner.fd.poll_readable(cx);
                    return super::retry_when_ready(cx, readiness).map(Some);
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
            let readiness = me.inner.fd.poll_readable(cx);
            super::retry_when_ready(cx, readiness).map(Some)
        }
    }
}

/// Create a new asynchronous BPF socket channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    let (fd, link_type, read_buffer_size) =
        crate::bpf::open_device(network_interface, (&config).into())?;
    let fd = Async::new_nonblocking(fd)?;
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

    #[test]
    fn async_send_uses_link_framing_and_retries_whole_packet_after_would_block() {
        use crate::bpf::test_ip_frame;
        use std::os::unix::net::UnixDatagram;
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let fd = Async::new_nonblocking(writer.into()).unwrap();
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
        assert!(
            sender
                .poll_send_with(&mut cx, &packet, |_, bytes| {
                    assert_eq!(bytes, &*LinkType::Null.prepare_send(&packet).unwrap());
                    Err(io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                })
                .is_pending()
        );
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
}
