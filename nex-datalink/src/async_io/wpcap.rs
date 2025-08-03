//! Asynchronous raw datalink support for Windows using the Npcap / WinPcap library.

use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::{bpf, windows};
use crate::Config;
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use std::cmp;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::pin::Pin;
use std::slice;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;

#[derive(Debug)]
struct WinPcapAdapter {
    adapter: windows::LPADAPTER,
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        unsafe { windows::PacketCloseAdapter(self.adapter) };
    }
}

unsafe impl Send for WinPcapAdapter {}
unsafe impl Sync for WinPcapAdapter {}

#[derive(Clone, Debug)]
struct WinPcapPacket {
    packet: windows::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        unsafe { windows::PacketFreePacket(self.packet) };
    }
}

unsafe impl Send for WinPcapPacket {}

#[derive(Debug)]
struct Inner {
    adapter: Arc<WinPcapAdapter>,
    packets: Arc<Mutex<VecDeque<Vec<u8>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

/// Sender half of a WinPcap socket.
#[derive(Clone, Debug)]
pub struct AsyncWpcapSocketSender {
    inner: Arc<Inner>,
    write_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl AsyncRawSender for AsyncWpcapSocketSender {
    fn poll_send(&mut self, _cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        let len = cmp::min(packet.len(), self.write_buffer.len());
        self.write_buffer[..len].copy_from_slice(&packet[..len]);
        unsafe {
            windows::PacketInitPacket(
                self.packet.packet,
                self.write_buffer.as_mut_ptr() as windows::PVOID,
                len as windows::UINT,
            );
        }
        let ret =
            unsafe { windows::PacketSendPacket(self.inner.adapter.adapter, self.packet.packet, 1) };
        if ret == 0 {
            Poll::Ready(Err(io::Error::last_os_error()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

/// Receiver half of a WinPcap socket.
#[derive(Debug)]
pub struct AsyncWpcapSocketReceiver {
    inner: Arc<Inner>,
}

impl Stream for AsyncWpcapSocketReceiver {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut queue = self.inner.packets.lock().unwrap();
        if let Some(pkt) = queue.pop_front() {
            Poll::Ready(Some(Ok(pkt)))
        } else {
            *self.inner.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Create a new asynchronous WinPcap channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    let mut write_buffer = vec![0u8; config.write_buffer_size];

    let adapter = unsafe {
        let npf_if_name: String = windows::to_npf_name(&network_interface.name);
        let net_if_str = CString::new(npf_if_name.as_bytes()).unwrap();
        windows::PacketOpenAdapter(net_if_str.as_ptr() as *mut libc::c_char)
    };
    if adapter.is_null() {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { windows::PacketSetHwFilter(adapter, windows::NDIS_PACKET_TYPE_PROMISCUOUS) };
    if ret == 0 {
        unsafe { windows::PacketCloseAdapter(adapter) };
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { windows::PacketSetBuff(adapter, config.read_buffer_size as libc::c_int) };
    if ret == 0 {
        unsafe { windows::PacketCloseAdapter(adapter) };
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { windows::PacketSetMinToCopy(adapter, 1) };
    if ret == 0 {
        unsafe { windows::PacketCloseAdapter(adapter) };
        return Err(io::Error::last_os_error());
    }

    let write_packet = unsafe { windows::PacketAllocatePacket() };
    if write_packet.is_null() {
        unsafe { windows::PacketCloseAdapter(adapter) };
        return Err(io::Error::last_os_error());
    }
    unsafe {
        windows::PacketInitPacket(
            write_packet,
            write_buffer.as_mut_ptr() as windows::PVOID,
            config.write_buffer_size as windows::UINT,
        );
    }

    let adapter = Arc::new(WinPcapAdapter { adapter });
    let packets = Arc::new(Mutex::new(VecDeque::new()));
    let waker: Arc<Mutex<Option<std::task::Waker>>> = Arc::new(Mutex::new(None));

    {
        let adapter = adapter.clone();
        let packets = packets.clone();
        let waker = waker.clone();
        let read_buffer_size = config.read_buffer_size;
        thread::spawn(move || {
            let mut read_buffer = vec![0u8; read_buffer_size];
            let read_packet = unsafe { windows::PacketAllocatePacket() };
            if read_packet.is_null() {
                return;
            }
            unsafe {
                windows::PacketInitPacket(
                    read_packet,
                    read_buffer.as_mut_ptr() as windows::PVOID,
                    read_buffer_size as windows::UINT,
                );
            }
            loop {
                let ret = unsafe { windows::PacketReceivePacket(adapter.adapter, read_packet, 1) };
                if ret == 0 {
                    continue;
                }
                let buflen = unsafe { (*read_packet).ulBytesReceived as isize };
                let mut ptr = unsafe { (*read_packet).Buffer as *mut libc::c_char };
                let end = unsafe { ((*read_packet).Buffer as *mut libc::c_char).offset(buflen) };
                while ptr < end {
                    unsafe {
                        let hdr: *const bpf::bpf_hdr = mem::transmute(ptr);
                        let start = ptr as isize + (*hdr).bh_hdrlen as isize
                            - (*read_packet).Buffer as isize;
                        let caplen = (*hdr).bh_caplen as usize;
                        let data_ptr = ((*read_packet).Buffer as isize + start) as *const u8;
                        let data = slice::from_raw_parts(data_ptr, caplen).to_vec();
                        {
                            let mut queue = packets.lock().unwrap();
                            queue.push_back(data);
                        }
                        let offset = (*hdr).bh_hdrlen as isize + (*hdr).bh_caplen as isize;
                        ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                    }
                }
                if let Some(w) = waker.lock().unwrap().take() {
                    w.wake();
                }
            }
        });
    }

    let inner = Arc::new(Inner {
        adapter,
        packets,
        waker,
    });
    let tx = AsyncWpcapSocketSender {
        inner: inner.clone(),
        write_buffer,
        packet: WinPcapPacket {
            packet: write_packet,
        },
    };
    let rx = AsyncWpcapSocketReceiver { inner };
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
