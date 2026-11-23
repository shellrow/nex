//! Asynchronous raw socket support for Linux using epoll.

use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::linux;
use crate::linux::{LoopbackFilter, receive_packet};
use crate::{ChannelType, Config};
use async_io::Async;
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use nex_core::mac::MacAddr;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

fn network_addr_to_sockaddr(
    ni: &Interface,
    storage: *mut libc::sockaddr_storage,
    proto: libc::c_int,
) -> usize {
    // SAFETY: `storage` points to writable `sockaddr_storage`, whose size and
    // alignment are sufficient for `sockaddr_ll`; it is used only in this call.
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        if let Some(MacAddr(a, b, c, d, e, f)) = ni.mac_addr {
            (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}

#[derive(Debug)]
struct Inner {
    fd: Async<OwnedFd>,
    send_addr: libc::sockaddr_ll,
}

/// Sender half of an asynchronous raw socket.
#[derive(Clone, Debug)]
pub struct AsyncRawSocketSender {
    inner: Arc<Inner>,
}

impl AsyncRawSender for AsyncRawSocketSender {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        // SAFETY: The descriptor is open, `packet` remains readable, and
        // `send_addr` remains valid throughout sendto.
        let ret = unsafe {
            libc::sendto(
                self.inner.fd.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &self.inner.send_addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret >= 0 {
            return Poll::Ready(Ok(()));
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            let readiness = self.inner.fd.poll_writable(cx);
            super::retry_when_ready(cx, readiness)
        } else {
            Poll::Ready(Err(err))
        }
    }
}

/// Receiver half of an asynchronous raw socket.
#[derive(Debug)]
pub struct AsyncRawSocketReceiver {
    inner: Arc<Inner>,
    read_buffer: Vec<u8>,
    filter: LoopbackFilter,
}

impl Stream for AsyncRawSocketReceiver {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        match poll_receive_filtered(cx, || {
            receive_packet(me.inner.fd.as_raw_fd(), &mut me.read_buffer, me.filter)
        }) {
            Poll::Ready(Ok(length)) => Poll::Ready(Some(Ok(me.read_buffer[..length].to_vec()))),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                let readiness = me.inner.fd.poll_readable(cx);
                super::retry_when_ready(cx, readiness).map(Some)
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Bound the work of a single poll even if the socket never becomes empty.
const RECEIVE_BUDGET: usize = 64;

fn poll_receive_filtered(
    cx: &mut Context<'_>,
    mut receive: impl FnMut() -> io::Result<(usize, bool)>,
) -> Poll<io::Result<usize>> {
    for _ in 0..RECEIVE_BUDGET {
        match receive() {
            Ok((_, true)) => continue,
            Ok((length, false)) => return Poll::Ready(Ok(length)),
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    // The budget expired with potentially more packets ready.
    cx.waker().wake_by_ref();
    Poll::Pending
}

/// Create a new asynchronous raw socket channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match config.channel_type {
        ChannelType::Layer2 => (libc::SOCK_RAW, eth_p_all),
        ChannelType::Layer3(proto) => (libc::SOCK_DGRAM, proto as i32),
    };
    // SAFETY: `socket` receives valid AF_PACKET arguments and retains no
    // borrowed pointers.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            typ | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            (proto as u16).to_be() as i32,
        )
    };
    if raw_fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` was just opened and exclusive ownership transfers to
    // this guard exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SAFETY: A zero bit pattern is a valid initial socket address storage.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto);
    // SAFETY: `network_addr_to_sockaddr` initialized `addr` as sockaddr_ll.
    let send_addr = unsafe { *(&addr as *const _ as *const libc::sockaddr_ll) };
    let bind_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // SAFETY: `bind_addr` points into live initialized storage for `len` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), bind_addr, len as libc::socklen_t) } == -1 {
        return Err(io::Error::last_os_error());
    }

    if config.promiscuous {
        // SAFETY: A zero bit pattern is valid for a packet membership request.
        let mut request: linux::packet_mreq = unsafe { mem::zeroed() };
        request.mr_ifindex = network_interface.index as i32;
        request.mr_type = linux::PACKET_MR_PROMISC as u16;
        // SAFETY: The descriptor is open and `request` remains readable for
        // the exact size supplied to setsockopt.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                linux::SOL_PACKET,
                linux::PACKET_ADD_MEMBERSHIP,
                (&request as *const linux::packet_mreq).cast(),
                mem::size_of::<linux::packet_mreq>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }

    if let Some(fanout) = config.linux_fanout {
        use crate::FanoutType;

        let mut fanout_type = match fanout.fanout_type {
            FanoutType::Hash => linux::PACKET_FANOUT_HASH,
            FanoutType::LoadBalance => linux::PACKET_FANOUT_LB,
            FanoutType::Cpu => linux::PACKET_FANOUT_CPU,
            FanoutType::Rollover => linux::PACKET_FANOUT_ROLLOVER,
            FanoutType::Random => linux::PACKET_FANOUT_RND,
            FanoutType::QueueMapping => linux::PACKET_FANOUT_QM,
            FanoutType::ClassicBpf => linux::PACKET_FANOUT_CBPF,
            FanoutType::ExtendedBpf => linux::PACKET_FANOUT_EBPF,
        } as u32;
        if fanout.defrag {
            fanout_type |= linux::PACKET_FANOUT_FLAG_DEFRAG;
        }
        if fanout.rollover {
            fanout_type |= linux::PACKET_FANOUT_FLAG_ROLLOVER;
        }
        let argument: libc::c_uint = fanout.group_id as u32 | (fanout_type << 16);
        // SAFETY: The descriptor is open and `argument` remains readable for
        // the exact size supplied to setsockopt.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                linux::SOL_PACKET,
                linux::PACKET_FANOUT,
                (&argument as *const libc::c_uint).cast(),
                mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }

    let inner = Arc::new(Inner {
        fd: Async::new_nonblocking(fd)?,
        send_addr,
    });
    let tx = AsyncRawSocketSender {
        inner: inner.clone(),
    };
    let rx = AsyncRawSocketReceiver {
        inner,
        read_buffer: vec![0u8; config.read_buffer_size],
        filter: LoopbackFilter::new(network_interface, config.linux_suppress_loopback_duplicates),
    };
    Ok(AsyncChannel::Ethernet(Box::new(tx), Box::new(rx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;

    #[derive(Default)]
    struct WakeCount(std::sync::atomic::AtomicUsize);

    impl futures::task::ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn filtered_receive_yields_and_guarantees_repoll() {
        use std::sync::atomic::Ordering::SeqCst;
        let wakes = Arc::new(WakeCount::default());
        let waker = futures::task::waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut calls = 0;
        assert!(
            poll_receive_filtered(&mut cx, || {
                calls += 1;
                assert!(calls <= RECEIVE_BUDGET);
                Ok((52, true))
            })
            .is_pending()
        );
        assert_eq!(calls, RECEIVE_BUDGET);
        assert_eq!(wakes.0.load(SeqCst), 1);
        assert!(matches!(
            poll_receive_filtered(&mut cx, || Ok((17, false))),
            Poll::Ready(Ok(17))
        ));
        assert!(
            matches!(poll_receive_filtered(&mut cx, || Err(io::ErrorKind::WouldBlock.into())), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(wakes.0.load(SeqCst), 1);
        for code in [libc::EBADF, libc::EINTR] {
            let Poll::Ready(Err(error)) =
                poll_receive_filtered(&mut cx, || Err(io::Error::from_raw_os_error(code)))
            else {
                panic!("expected error")
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn continuous_suppression_allows_other_future_and_cancellation() {
        use futures::future::{Either, select};
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let calls = AtomicUsize::new(0);
        let progress = AtomicUsize::new(0);
        futures::executor::block_on(async {
            let receive = Box::pin(poll_fn(|cx| {
                poll_receive_filtered(cx, || {
                    calls.fetch_add(1, SeqCst);
                    Ok((52, true))
                })
            }));
            let other = Box::pin(async {
                progress.fetch_add(1, SeqCst);
            });
            let Either::Right(((), pending_receive)) = select(receive, other).await else {
                panic!("suppressed copy escaped")
            };
            drop(pending_receive);
        });
        assert_eq!(progress.load(SeqCst), 1);
        assert!(calls.load(SeqCst) <= RECEIVE_BUDGET);
    }
}
