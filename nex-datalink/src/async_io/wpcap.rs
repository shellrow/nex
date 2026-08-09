//! Asynchronous raw datalink support for Windows using the Npcap / WinPcap library.

use crate::Config;
use crate::async_io::{AsyncChannel, AsyncRawSender};
use crate::bindings::{bpf, windows};
use futures_core::stream::Stream;
use nex_core::interface::Interface;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::pin::Pin;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Bounded receive wait, so dropping the channel can join the worker promptly.
/// The worker holds the adapter lock for at most this long, which bounds how
/// long a contended `poll_send` stays `Pending` before the worker wakes it.
const RECEIVE_TIMEOUT_MS: libc::c_int = 100;

/// Backoff after a failed receive so a persistently failing adapter does not
/// spin the worker thread.
const RECEIVE_ERROR_BACKOFF: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct WinPcapAdapter {
    api: &'static windows::PacketApi,
    adapter: windows::LPADAPTER,
    operation_lock: Mutex<()>,
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        let api = self.api;
        // SAFETY: This is the last owning `Arc`; the receive thread has been
        // joined and no operation can still use the adapter.
        unsafe { (api.PacketCloseAdapter)(self.adapter) };
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
    api: &'static windows::PacketApi,
    packet: windows::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        let api = self.api;
        // SAFETY: `packet` is uniquely owned and came from
        // PacketAllocatePacket, so it must be freed exactly once.
        unsafe { (api.PacketFreePacket)(self.packet) };
    }
}

// SAFETY: Each packet wrapper is moved into one sender or receive thread and is
// never accessed concurrently.
unsafe impl Send for WinPcapPacket {}

/// Queue shared with the receive worker. Entries carry `io::Result` so a
/// receive failure reaches the consumer instead of being swallowed.
type PacketQueue = Arc<Mutex<VecDeque<io::Result<Vec<u8>>>>>;

#[derive(Debug)]
struct Inner {
    adapter: Arc<WinPcapAdapter>,
    packets: PacketQueue,
    waker: Arc<Mutex<Option<Waker>>>,
    /// Woken when the worker releases the adapter lock, so a send that found
    /// the lock contended can retry without blocking the executor.
    send_waker: Arc<Mutex<Option<Waker>>>,
    stop: Arc<AtomicBool>,
    receive_thread: Mutex<Option<JoinHandle<()>>>,
}

/// Wake a registered task, if any. Poisoning is not fatal here: the stored
/// waker is plain data and a missed wake-up would hang the consumer.
fn wake(slot: &Arc<Mutex<Option<Waker>>>) {
    let mut slot = match slot.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(waker) = slot.take() {
        waker.wake();
    }
}

/// Record an error for the consumer without letting a persistently failing
/// adapter grow the queue without bound: at most one error is left pending.
fn push_error(queue: &PacketQueue, error: io::Error) {
    let mut queue = match queue.lock() {
        Ok(queue) => queue,
        Err(poisoned) => poisoned.into_inner(),
    };
    if matches!(queue.back(), Some(Err(_))) {
        return;
    }
    queue.push_back(Err(error));
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
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        // Truncating here would silently put a malformed frame on the wire.
        if packet.len() > self.write_buffer.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is larger than the configured write buffer",
            )));
        }

        // The receive worker can hold the adapter lock for a full receive
        // timeout. Blocking on it here would stall the executor thread, so
        // register for a wake-up and yield instead.
        let _operation = match self.inner.adapter.operation_lock.try_lock() {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => {
                match self.inner.send_waker.lock() {
                    Ok(mut waker) => *waker = Some(cx.waker().clone()),
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::other(
                            "wpcap send waker mutex poisoned",
                        )));
                    }
                }
                // Re-check after registering: the worker may have released the
                // lock in between, in which case no further wake-up is coming.
                match self.inner.adapter.operation_lock.try_lock() {
                    Ok(lock) => lock,
                    Err(TryLockError::WouldBlock) => return Poll::Pending,
                    Err(TryLockError::Poisoned(_)) => {
                        return Poll::Ready(Err(io::Error::other(
                            "Npcap adapter operation mutex poisoned",
                        )));
                    }
                }
            }
            Err(TryLockError::Poisoned(_)) => {
                return Poll::Ready(Err(io::Error::other(
                    "Npcap adapter operation mutex poisoned",
                )));
            }
        };

        let api = self.inner.adapter.api;
        let len = packet.len();
        self.write_buffer[..len].copy_from_slice(packet);
        // SAFETY: The packet wrapper and backing vector are exclusively owned
        // by this sender and remain live throughout the call.
        unsafe {
            (api.PacketInitPacket)(
                self.packet.packet,
                self.write_buffer.as_mut_ptr() as windows::PVOID,
                len as windows::UINT,
            );
        }
        // SAFETY: The adapter operation is serialized and both handles remain
        // live throughout the call.
        let ret =
            unsafe { (api.PacketSendPacket)(self.inner.adapter.adapter, self.packet.packet, 1) };
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
                return Poll::Ready(Some(Err(io::Error::other(
                    "wpcap packet queue mutex poisoned",
                ))));
            }
        };
        if let Some(pkt) = queue.pop_front() {
            Poll::Ready(Some(pkt))
        } else {
            match self.inner.waker.lock() {
                Ok(mut waker) => {
                    *waker = Some(cx.waker().clone());
                }
                Err(_) => {
                    return Poll::Ready(Some(Err(io::Error::other("wpcap waker mutex poisoned"))));
                }
            }
            Poll::Pending
        }
    }
}

/// Create a new asynchronous WinPcap channel.
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<AsyncChannel> {
    // Resolve Packet.dll first: without Npcap there is nothing to configure.
    let api = windows::packet_api()?;

    let read_buffer_size = config.read_buffer_size;
    let mut write_buffer = vec![0u8; config.write_buffer_size];

    // SAFETY: PacketOpenAdapter reads the temporary NUL-terminated name during
    // the call and returns an owned adapter handle.
    let adapter = unsafe {
        let npf_if_name: String = windows::to_npf_name(&network_interface.name);
        let net_if_str = CString::new(npf_if_name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        (api.PacketOpenAdapter)(net_if_str.as_ptr() as *mut libc::c_char)
    };
    if adapter.is_null() {
        return Err(io::Error::last_os_error());
    }
    let adapter = Arc::new(WinPcapAdapter {
        api,
        adapter,
        operation_lock: Mutex::new(()),
    });

    // SAFETY: The adapter is open and the filter is an Npcap constant.
    let ret = unsafe {
        (api.PacketSetHwFilter)(adapter.adapter, windows::hw_filter_for(config.promiscuous))
    };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: The adapter is open and the size value is passed by value.
    let ret = unsafe { (api.PacketSetBuff)(adapter.adapter, read_buffer_size as libc::c_int) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: The adapter is open and the threshold is valid.
    let ret = unsafe { (api.PacketSetMinToCopy)(adapter.adapter, 1) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Use a bounded receive wait so dropping the channel can join the worker.
    // SAFETY: The adapter is open and the timeout is passed by value.
    let ret = unsafe { (api.PacketSetReadTimeout)(adapter.adapter, RECEIVE_TIMEOUT_MS) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: PacketAllocatePacket takes no arguments and returns an owned
    // packet pointer or null.
    let write_packet = unsafe { (api.PacketAllocatePacket)() };
    if write_packet.is_null() {
        return Err(io::Error::last_os_error());
    }
    let write_packet = WinPcapPacket {
        api,
        packet: write_packet,
    };
    // SAFETY: The packet and backing vector remain live and immovable in the
    // sender after this initialization.
    unsafe {
        (api.PacketInitPacket)(
            write_packet.packet,
            write_buffer.as_mut_ptr() as windows::PVOID,
            config.write_buffer_size as windows::UINT,
        );
    }

    let packets: PacketQueue = Arc::new(Mutex::new(VecDeque::new()));
    let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let send_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));

    let receive_thread = {
        let adapter = adapter.clone();
        let packets = packets.clone();
        let waker = waker.clone();
        let send_waker = send_waker.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut read_buffer = vec![0u8; read_buffer_size];
            // SAFETY: PacketAllocatePacket takes no arguments and returns an
            // owned packet pointer or null.
            let read_packet = unsafe { (api.PacketAllocatePacket)() };
            if read_packet.is_null() {
                push_error(&packets, io::Error::last_os_error());
                wake(&waker);
                return;
            }
            let read_packet = WinPcapPacket {
                api,
                packet: read_packet,
            };
            // SAFETY: The packet and backing buffer remain owned by this thread
            // and live until the receive loop exits.
            unsafe {
                (api.PacketInitPacket)(
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
                    unsafe { (api.PacketReceivePacket)(adapter.adapter, read_packet.packet, 1) };
                if ret == 0 {
                    let error = io::Error::last_os_error();
                    // Release the adapter lock before backing off so a pending
                    // send is not starved, and avoid spinning on a persistent
                    // adapter failure.
                    drop(_operation);
                    wake(&send_waker);
                    push_error(&packets, error);
                    wake(&waker);
                    thread::sleep(RECEIVE_ERROR_BACKOFF);
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
                    drop(_operation);
                    wake(&send_waker);
                    push_error(
                        &packets,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Npcap reported bytes beyond the receive buffer",
                        ),
                    );
                    wake(&waker);
                    continue;
                }
                let mut cursor = 0usize;
                let mut malformed: Option<&'static str> = None;
                while cursor < buflen {
                    let remaining = buflen - cursor;
                    if remaining < mem::size_of::<bpf::bpf_hdr>() {
                        malformed = Some("truncated Npcap BPF record header");
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
                        malformed = Some("Npcap record length overflow");
                        break;
                    };
                    if header_len < mem::size_of::<bpf::bpf_hdr>() || record_len > remaining {
                        malformed = Some("invalid Npcap BPF record lengths");
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
                        queue.push_back(Ok(data));
                    }
                    let Ok(record_len) = isize::try_from(record_len) else {
                        malformed = Some("Npcap record exceeds platform pointer range");
                        break;
                    };
                    let Some(next) = cursor.checked_add(bpf::BPF_WORDALIGN(record_len) as usize)
                    else {
                        malformed = Some("Npcap record offset overflow");
                        break;
                    };
                    cursor = next;
                }

                // Release the adapter before waking anyone, so a sender woken
                // here finds the lock free.
                drop(_operation);
                wake(&send_waker);

                if let Some(reason) = malformed {
                    push_error(&packets, io::Error::new(io::ErrorKind::InvalidData, reason));
                    wake(&waker);
                } else if cursor > 0 {
                    // A bare receive timeout queues nothing; waking the consumer
                    // for it would just cost a poll that returns Pending again.
                    wake(&waker);
                }
            }
        })
    };

    let inner = Arc::new(Inner {
        adapter,
        packets,
        waker,
        send_waker,
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

    fn queue() -> PacketQueue {
        Arc::new(Mutex::new(VecDeque::new()))
    }

    fn kinds(queue: &PacketQueue) -> Vec<Result<usize, io::ErrorKind>> {
        queue
            .lock()
            .unwrap()
            .iter()
            .map(|entry| match entry {
                Ok(data) => Ok(data.len()),
                Err(error) => Err(error.kind()),
            })
            .collect()
    }

    #[test]
    fn push_error_surfaces_the_first_failure() {
        let queue = queue();
        push_error(&queue, io::Error::new(io::ErrorKind::InvalidData, "bad"));
        assert_eq!(kinds(&queue), vec![Err(io::ErrorKind::InvalidData)]);
    }

    #[test]
    fn push_error_does_not_grow_without_bound() {
        let queue = queue();
        for _ in 0..1_000 {
            push_error(&queue, io::Error::new(io::ErrorKind::BrokenPipe, "down"));
        }
        // A persistently failing adapter must not accumulate one entry per
        // retry while nothing is draining the queue.
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn push_error_reports_again_after_a_packet_is_queued() {
        let queue = queue();
        push_error(&queue, io::Error::new(io::ErrorKind::BrokenPipe, "down"));
        push_error(&queue, io::Error::new(io::ErrorKind::BrokenPipe, "down"));
        queue.lock().unwrap().push_back(Ok(vec![0u8; 4]));
        push_error(&queue, io::Error::new(io::ErrorKind::BrokenPipe, "down"));

        assert_eq!(
            kinds(&queue),
            vec![
                Err(io::ErrorKind::BrokenPipe),
                Ok(4),
                Err(io::ErrorKind::BrokenPipe),
            ]
        );
    }

    #[test]
    fn wake_takes_the_registered_waker_once() {
        let woken = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let flag = woken.clone();
        *slot.lock().unwrap() = Some(futures::task::waker(Arc::new(CountingWake(flag))));

        wake(&slot);
        assert!(woken.load(Ordering::Acquire));
        assert!(slot.lock().unwrap().is_none());

        // Waking an empty slot must be a no-op rather than a panic.
        wake(&slot);
    }

    struct CountingWake(Arc<AtomicBool>);

    impl futures::task::ArcWake for CountingWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.store(true, Ordering::Release);
        }
    }
}
