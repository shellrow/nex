//! Asynchronous raw socket support for Linux using epoll.

use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::linux;
use crate::{ChannelType, Config};
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use nex_core::mac::MacAddr;
use nex_sys;
use std::io;
use std::mem;
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
    fd: nex_sys::FileDesc,
    send_addr: libc::sockaddr_ll,
    epfd: nex_sys::FileDesc,
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
                self.inner.fd.as_raw(),
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
            // SAFETY: `events` provides writable storage for one epoll event
            // and the epoll descriptor is open.
            unsafe {
                let mut events = [mem::zeroed::<libc::epoll_event>()];
                libc::epoll_wait(self.inner.epfd.as_raw(), events.as_mut_ptr(), 1, 0);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
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
}

impl Stream for AsyncRawSocketReceiver {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        // SAFETY: The descriptor is open and `read_buffer` is writable for its
        // entire length.
        let ret = unsafe {
            libc::recv(
                me.inner.fd.as_raw(),
                me.read_buffer.as_mut_ptr() as *mut libc::c_void,
                me.read_buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if ret >= 0 {
            let n = ret as usize;
            let pkt = me.read_buffer[..n].to_vec();
            return Poll::Ready(Some(Ok(pkt)));
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            // SAFETY: `events` provides writable storage for one epoll event
            // and the epoll descriptor is open.
            unsafe {
                let mut events = [mem::zeroed::<libc::epoll_event>()];
                libc::epoll_wait(me.inner.epfd.as_raw(), events.as_mut_ptr(), 1, 0);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Some(Err(err)))
        }
    }
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
            typ | libc::SOCK_NONBLOCK,
            (proto as u16).to_be() as i32,
        )
    };
    if raw_fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` was just opened and exclusive ownership transfers to
    // this guard exactly once.
    let fd = unsafe { nex_sys::FileDesc::from_raw(raw_fd) };

    // SAFETY: A zero bit pattern is a valid initial socket address storage.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto);
    // SAFETY: `network_addr_to_sockaddr` initialized `addr` as sockaddr_ll.
    let send_addr = unsafe { *(&addr as *const _ as *const libc::sockaddr_ll) };
    let bind_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // SAFETY: `bind_addr` points into live initialized storage for `len` bytes.
    if unsafe { libc::bind(fd.as_raw(), bind_addr, len as libc::socklen_t) } == -1 {
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
                fd.as_raw(),
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
                fd.as_raw(),
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

    // SAFETY: `epoll_create1` receives a supported zero flag value.
    let raw_epfd = unsafe { libc::epoll_create1(0) };
    if raw_epfd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_epfd` was just opened and ownership transfers exactly once.
    let epfd = unsafe { nex_sys::FileDesc::from_raw(raw_epfd) };

    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLOUT) as u32,
        u64: fd.as_raw() as u64,
    };
    // SAFETY: Both descriptors are open and `event` is writable for the call.
    if unsafe { libc::epoll_ctl(epfd.as_raw(), libc::EPOLL_CTL_ADD, fd.as_raw(), &mut event) } == -1
    {
        return Err(io::Error::last_os_error());
    }

    let inner = Arc::new(Inner {
        fd,
        send_addr,
        epfd,
    });
    let tx = AsyncRawSocketSender {
        inner: inner.clone(),
    };
    let rx = AsyncRawSocketReceiver {
        inner,
        read_buffer: vec![0u8; config.read_buffer_size],
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
