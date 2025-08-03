//! Asynchronous raw socket support for Linux using epoll.

use crate::{ChannelType, Config};
use crate::async_io::{AsyncChannel, AsyncRawSender};
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use nex_core::mac::MacAddr;
use nex_sys;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

fn network_addr_to_sockaddr(
    ni: &Interface,
    storage: *mut libc::sockaddr_storage,
    proto: libc::c_int,
) -> usize {
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
    fd: RawFd,
    send_addr: libc::sockaddr_ll,
    epfd: RawFd,
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            nex_sys::close(self.fd);
            nex_sys::close(self.epfd);
        }
    }
}

/// Sender half of an asynchronous raw socket.
#[derive(Clone, Debug)]
pub struct AsyncRawSocketSender {
    inner: Arc<Inner>,
}

impl AsyncRawSender for AsyncRawSocketSender {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        let ret = unsafe {
            libc::sendto(
                self.inner.fd,
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
            unsafe {
                let mut events = [mem::zeroed::<libc::epoll_event>()];
                libc::epoll_wait(self.inner.epfd, events.as_mut_ptr(), 1, 0);
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
        let ret = unsafe {
            libc::recv(
                me.inner.fd,
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
            unsafe {
                let mut events = [mem::zeroed::<libc::epoll_event>()];
                libc::epoll_wait(me.inner.epfd, events.as_mut_ptr(), 1, 0);
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
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            typ | libc::SOCK_NONBLOCK,
            (proto as u16).to_be() as i32,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto);
    let send_addr = unsafe { *(&addr as *const _ as *const libc::sockaddr_ll) };
    let bind_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    if unsafe { libc::bind(fd, bind_addr, len as libc::socklen_t) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(fd);
        }
        return Err(err);
    }

    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLOUT) as u32,
        u64: fd as u64,
    };
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut event) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(epfd);
            nex_sys::close(fd);
        }
        return Err(err);
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
