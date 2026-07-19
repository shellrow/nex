//! Asynchronous raw datalink support for Windows using the Npcap / WinPcap library.

use crate::Config;
use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::{bpf, windows};
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use std::cmp;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::pin::Pin;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

#[derive(Debug)]
struct WinPcapAdapter {
    adapter: windows::LPADAPTER,
    operation_lock: Mutex<()>,
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        // SAFETY: This is the last owning `Arc`; the receive thread has been
        // joined and no operation can still use the adapter.
        unsafe { windows::PacketCloseAdapter(self.adapter) };
    }
}

// SAFETY: The adapter is owned until Drop and every Npcap operation is
// serialized by `operation_lock`.
unsafe impl Send for WinPcapAdapter {}
// SAFETY: Shared access cannot reach the raw adapter without acquiring
// `operation_lock`.
unsafe impl Sync for WinPcapAdapter {}

#[derive(Debug)]
struct WinPcapPacket {
    packet: windows::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        // SAFETY: `packet` is uniquely owned and came from
        // PacketAllocatePacket, so it must be freed exactly once.
        unsafe { windows::PacketFreePacket(self.packet) };
    }
}

// SAFETY: Each packet wrapper is moved into one sender or receive thread and is
// never accessed concurrently.
unsafe impl Send for WinPcapPacket {}

#[derive(Debug)]
struct Inner {
    adapter: Arc<WinPcapAdapter>,
    packets: Arc<Mutex<VecDeque<Vec<u8>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    stop: Arc<AtomicBool>,
    receive_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(thread) = self.receive_thread.get_mut()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

/// Sender half of a WinPcap socket.
#[derive(Debug)]
pub struct AsyncWpcapSocketSender {
    inner: Arc<Inner>,
    write_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl AsyncRawSender for AsyncWpcapSocketSender {
    fn poll_send(&mut self, _cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        let len = cmp::min(packet.len(), self.write_buffer.len());
        self.write_buffer[..len].copy_from_slice(&packet[..len]);
        // SAFETY: The packet wrapper and backing vector are exclusively owned
        // by this sender and remain live throughout the call.
        unsafe {
            windows::PacketInitPacket(
                self.packet.packet,
                self.write_buffer.as_mut_ptr() as windows::PVOID,
                len as windows::UINT,
            );
        }
        let _operation = match self.inner.adapter.operation_lock.lock() {
            Ok(lock) => lock,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other(
                    "Npcap adapter operation mutex poisoned",
                )));
            }
        };
        // SAFETY: The adapter operation is serialized and both handles remain
        // live throughout the call.
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
        let mut queue = match self.inner.packets.lock() {
            Ok(queue) => queue,
            Err(_) => {
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "wpcap packet queue mutex poisoned",
                ))));
            }
        };
        if let Some(pkt) = queue.pop_front() {
            Poll::Ready(Some(Ok(pkt)))
        } else {
            match self.inner.waker.lock() {
                Ok(mut waker) => {
                    *waker = Some(cx.waker().clone());
                }
                Err(_) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "wpcap waker mutex poisoned",
                    ))));
                }
            }
            Poll::Pending
        }
    }
}

/// Create a new asynchronous WinPcap channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    let read_buffer_size = config.read_buffer_size;
    let mut write_buffer = vec![0u8; config.write_buffer_size];

    // SAFETY: PacketOpenAdapter reads the temporary NUL-terminated name during
    // the call and returns an owned adapter handle.
    let adapter = unsafe {
        let npf_if_name: String = windows::to_npf_name(&network_interface.name);
        let net_if_str = CString::new(npf_if_name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        windows::PacketOpenAdapter(net_if_str.as_ptr() as *mut libc::c_char)
    };
    if adapter.is_null() {
        return Err(io::Error::last_os_error());
    }
    let adapter = Arc::new(WinPcapAdapter {
        adapter,
        operation_lock: Mutex::new(()),
    });

    // SAFETY: The adapter is open and the filter is an Npcap constant.
    let ret = unsafe {
        windows::PacketSetHwFilter(adapter.adapter, windows::NDIS_PACKET_TYPE_PROMISCUOUS)
    };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: The adapter is open and the size value is passed by value.
    let ret = unsafe { windows::PacketSetBuff(adapter.adapter, read_buffer_size as libc::c_int) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: The adapter is open and the threshold is valid.
    let ret = unsafe { windows::PacketSetMinToCopy(adapter.adapter, 1) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Use a bounded receive wait so dropping the channel can join the worker.
    // SAFETY: The adapter is open and the timeout is passed by value.
    let ret = unsafe { windows::PacketSetReadTimeout(adapter.adapter, 100) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: PacketAllocatePacket takes no arguments and returns an owned
    // packet pointer or null.
    let write_packet = unsafe { windows::PacketAllocatePacket() };
    if write_packet.is_null() {
        return Err(io::Error::last_os_error());
    }
    let write_packet = WinPcapPacket {
        packet: write_packet,
    };
    // SAFETY: The packet and backing vector remain live and immovable in the
    // sender after this initialization.
    unsafe {
        windows::PacketInitPacket(
            write_packet.packet,
            write_buffer.as_mut_ptr() as windows::PVOID,
            config.write_buffer_size as windows::UINT,
        );
    }

    let packets = Arc::new(Mutex::new(VecDeque::new()));
    let waker: Arc<Mutex<Option<std::task::Waker>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));

    let receive_thread = {
        let adapter = adapter.clone();
        let packets = packets.clone();
        let waker = waker.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut read_buffer = vec![0u8; read_buffer_size];
            // SAFETY: PacketAllocatePacket takes no arguments and returns an
            // owned packet pointer or null.
            let read_packet = unsafe { windows::PacketAllocatePacket() };
            if read_packet.is_null() {
                return;
            }
            let read_packet = WinPcapPacket {
                packet: read_packet,
            };
            // SAFETY: The packet and backing buffer remain owned by this thread
            // and live until the receive loop exits.
            unsafe {
                windows::PacketInitPacket(
                    read_packet.packet,
                    read_buffer.as_mut_ptr() as windows::PVOID,
                    read_buffer_size as windows::UINT,
                );
            }
            while !stop.load(Ordering::Acquire) {
                let _operation = match adapter.operation_lock.lock() {
                    Ok(lock) => lock,
                    Err(poisoned) => poisoned.into_inner(),
                };
                // SAFETY: The operation is serialized and both handles remain
                // live for the duration of the bounded receive.
                let ret =
                    unsafe { windows::PacketReceivePacket(adapter.adapter, read_packet.packet, 1) };
                if ret == 0 {
                    continue;
                }
                // SAFETY: A successful receive initialized the byte count and
                // the packet buffer capacity.
                let (buflen, buffer_capacity, base) = unsafe {
                    (
                        (*read_packet.packet).ulBytesReceived as usize,
                        (*read_packet.packet).Length as usize,
                        (*read_packet.packet).Buffer as *const u8,
                    )
                };
                if buflen > buffer_capacity {
                    continue;
                }
                let mut cursor = 0usize;
                while cursor < buflen {
                    let remaining = buflen - cursor;
                    if remaining < mem::size_of::<bpf::bpf_hdr>() {
                        break;
                    }
                    // SAFETY: The size check proves the full header is in the
                    // buffer. `read_unaligned` handles the backing Vec's alignment.
                    let hdr = unsafe {
                        std::ptr::read_unaligned(base.add(cursor) as *const bpf::bpf_hdr)
                    };
                    let header_len = hdr.bh_hdrlen as usize;
                    let captured_len = hdr.bh_caplen as usize;
                    let Some(record_len) = header_len.checked_add(captured_len) else {
                        break;
                    };
                    if header_len < mem::size_of::<bpf::bpf_hdr>() || record_len > remaining {
                        break;
                    }
                    // SAFETY: The validated record lengths prove this packet
                    // payload is fully in-bounds.
                    let data = unsafe {
                        slice::from_raw_parts(base.add(cursor + header_len), captured_len)
                    }
                    .to_vec();
                    {
                        let mut queue = match packets.lock() {
                            Ok(queue) => queue,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        queue.push_back(data);
                    }
                    let Ok(record_len) = isize::try_from(record_len) else {
                        break;
                    };
                    let Some(next) = cursor.checked_add(bpf::BPF_WORDALIGN(record_len) as usize)
                    else {
                        break;
                    };
                    cursor = next;
                }
                let mut waker = match waker.lock() {
                    Ok(waker) => waker,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(w) = waker.take() {
                    w.wake();
                }
            }
        })
    };

    let inner = Arc::new(Inner {
        adapter,
        packets,
        waker,
        stop,
        receive_thread: Mutex::new(Some(receive_thread)),
    });
    let tx = AsyncWpcapSocketSender {
        inner: inner.clone(),
        write_buffer,
        packet: write_packet,
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
