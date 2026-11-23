//! Support for sending and receiving data link layer packets using the npcap or winpcap library.

use super::bindings::{bpf, windows};
use super::{RawReceiver, RawSender};
use nex_core::interface::Interface;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct WinPcapAdapter {
    api: &'static windows::PacketApi,
    adapter: windows::LPADAPTER,
    operation_lock: Mutex<()>,
}

fn open_adapter(
    api: &'static windows::PacketApi,
    name: &CString,
) -> io::Result<Arc<WinPcapAdapter>> {
    // SAFETY: PacketOpenAdapter reads the NUL-terminated name only during the call.
    let adapter = unsafe { (api.PacketOpenAdapter)(name.as_ptr().cast_mut()) };
    if adapter.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Arc::new(WinPcapAdapter {
        api,
        adapter,
        operation_lock: Mutex::new(()),
    }))
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        let api = self.api;
        // SAFETY: This is the last owning `Arc`, so no operation can still use
        // the non-null adapter handle. Npcap requires exactly one close.
        unsafe {
            (api.PacketCloseAdapter)(self.adapter);
        }
    }
}

// SAFETY: The non-null adapter handle is owned until `Drop`. All send and
// receive operations are serialized by `operation_lock`, and Npcap configuration
// is completed before this wrapper is shared.
unsafe impl Send for WinPcapAdapter {}
// SAFETY: See the `Send` rationale; shared access cannot reach the handle
// without acquiring `operation_lock`.
unsafe impl Sync for WinPcapAdapter {}

struct WinPcapPacket {
    api: &'static windows::PacketApi,
    packet: windows::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        let api = self.api;
        // SAFETY: `packet` was returned by PacketAllocatePacket, is owned by
        // this wrapper, and is freed exactly once.
        unsafe {
            (api.PacketFreePacket)(self.packet);
        }
    }
}

// SAFETY: A packet wrapper is moved into exactly one sender or receiver and all
// access then occurs through that half's exclusive `&mut self`.
unsafe impl Send for WinPcapPacket {}

/// The Npcap / WinPcap's specific configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// The read timeout applied via `PacketSetReadTimeout`. Defaults to None
    /// (block until at least one packet arrives).
    pub read_timeout: Option<Duration>,

    /// Whether the adapter should capture in promiscuous mode. Defaults to true.
    pub promiscuous: bool,
}

const DEFAULT_WRITE_BUFFER_SIZE: usize = 4096;
const DEFAULT_READ_BUFFER_SIZE: usize = 65536;

impl From<&super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            read_timeout: config.read_timeout,
            promiscuous: config.promiscuous,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: DEFAULT_WRITE_BUFFER_SIZE,
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
            read_timeout: None,
            promiscuous: true,
        }
    }
}

/// Convert a read timeout into the millisecond value `PacketSetReadTimeout`
/// expects. `None` maps to 0, which means "block until a packet arrives".
fn read_timeout_millis(timeout: Option<Duration>) -> io::Result<libc::c_int> {
    let Some(timeout) = timeout else {
        return Ok(0);
    };
    // A zero duration would otherwise be indistinguishable from "block
    // forever", so round it up to the shortest bounded wait Npcap accepts.
    let millis = timeout.as_millis().max(1);
    libc::c_int::try_from(millis).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "read_timeout exceeds the range Npcap accepts",
        )
    })
}

/// Create a datalink channel using the Npcap / WinPcap library.
#[inline]
pub(crate) fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    // Resolve Packet.dll first: without Npcap there is nothing to configure.
    let api = windows::packet_api()?;

    channel_with_api(network_interface, config, api)
}

fn channel_with_api(
    network_interface: &Interface,
    config: Config,
    api: &'static windows::PacketApi,
) -> io::Result<super::Channel> {
    // Reject an out-of-range timeout before any OS handle is opened.
    let read_timeout_ms = read_timeout_millis(config.read_timeout)?;

    let mut read_buffer = vec![0u8; config.read_buffer_size];
    let mut write_buffer = vec![0u8; config.write_buffer_size];

    let name = CString::new(windows::to_npf_name(&network_interface.name))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    let adapter = open_adapter(api, &name)?;

    let hw_filter = windows::hw_filter_for(config.promiscuous);
    // SAFETY: The adapter is open and the filter value is an Npcap constant.
    let ret = unsafe { (api.PacketSetHwFilter)(adapter.adapter, hw_filter) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Set kernel buffer size
    // SAFETY: The adapter is open and PacketSetBuff retains no Rust pointers.
    let ret =
        unsafe { (api.PacketSetBuff)(adapter.adapter, config.read_buffer_size as libc::c_int) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Immediate mode
    // SAFETY: The adapter is open and the integer threshold is valid.
    let ret = unsafe { (api.PacketSetMinToCopy)(adapter.adapter, 1) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Bound how long `RawReceiver::next` waits. 0 means block until a packet
    // arrives, which is the default when no timeout is configured.
    // SAFETY: The adapter is open and the timeout is passed by value.
    let ret = unsafe { (api.PacketSetReadTimeout)(adapter.adapter, read_timeout_ms) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: PacketAllocatePacket takes no arguments and returns an owned
    // packet pointer or null.
    let read_packet = unsafe { (api.PacketAllocatePacket)() };
    if read_packet.is_null() {
        return Err(io::Error::last_os_error());
    }

    let read_packet = WinPcapPacket {
        api,
        packet: read_packet,
    };
    // SAFETY: The packet and backing vector are live; the vector cannot move or
    // resize while the packet wrapper exists in the receiver.
    unsafe {
        (api.PacketInitPacket)(
            read_packet.packet,
            read_buffer.as_mut_ptr() as windows::PVOID,
            config.read_buffer_size as windows::UINT,
        )
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
    // SAFETY: The packet and backing vector are live; the vector cannot move or
    // resize while the packet wrapper exists in the sender.
    unsafe {
        (api.PacketInitPacket)(
            write_packet.packet,
            write_buffer.as_mut_ptr() as windows::PVOID,
            config.write_buffer_size as windows::UINT,
        )
    }

    // SAFETY: `read_packet.packet` is live and initialized above.
    let packet_capacity = unsafe { (*read_packet.packet).Length } as usize / 64;
    let sender = Box::new(RawSenderImpl {
        adapter: adapter.clone(),
        name,
        write_buffer,
        packet: write_packet,
    });
    let receiver = Box::new(RawReceiverImpl {
        adapter,
        read_buffer,
        packet: read_packet,
        // Enough room for minimally sized packets without reallocating
        packets: VecDeque::with_capacity(packet_capacity),
        timeout_configured: config.read_timeout.is_some(),
    });
    Ok(super::Channel::Ethernet(sender, receiver))
}

struct RawSenderImpl {
    name: CString,
    adapter: Arc<WinPcapAdapter>,
    write_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl RawSender for RawSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        if packet_size == 0 {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet_size must be greater than zero",
            )));
        }
        let len = num_packets.checked_mul(packet_size)?;
        let buffer = self.write_buffer.get_mut(..len)?;
        let api = self.adapter.api;
        for chunk in buffer.chunks_mut(packet_size) {
            func(chunk);
            let adapter = self.adapter.clone();
            let _operation = match adapter.operation_lock.try_lock() {
                Ok(lock) => Some(lock),
                Err(std::sync::TryLockError::WouldBlock) => {
                    // A blocking receive can hold the original adapter indefinitely.
                    // This handle belongs exclusively to the sender.
                    self.adapter = match open_adapter(api, &self.name) {
                        Ok(adapter) => adapter,
                        Err(error) => return Some(Err(error)),
                    };
                    None
                }
                Err(_) => {
                    return Some(Err(io::Error::other(
                        "Npcap adapter operation mutex poisoned",
                    )));
                }
            };
            // SAFETY: The packet points to this chunk until the synchronous send returns.
            unsafe {
                (api.PacketInitPacket)(
                    self.packet.packet,
                    chunk.as_mut_ptr().cast(),
                    packet_size as u32,
                );
                if (api.PacketSendPacket)(self.adapter.adapter, self.packet.packet, 1) == 0 {
                    return Some(Err(io::Error::last_os_error()));
                }
            }
        }
        Some(Ok(()))
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        self.build_and_send(1, packet.len(), &mut |eh: &mut [u8]| {
            eh.copy_from_slice(packet);
        })
    }
}

// SAFETY: The raw packet is uniquely owned by this sender and adapter access is
// serialized by `WinPcapAdapter::operation_lock`.
unsafe impl Send for RawSenderImpl {}

struct RawReceiverImpl {
    adapter: Arc<WinPcapAdapter>,
    read_buffer: Vec<u8>,
    packet: WinPcapPacket,
    packets: VecDeque<(usize, usize)>,
    /// Whether a bounded read timeout was configured. When it was, an empty
    /// receive means the timeout elapsed rather than "keep waiting".
    timeout_configured: bool,
}

// SAFETY: The raw packet is uniquely owned by this receiver and adapter access
// is serialized by `WinPcapAdapter::operation_lock`.
unsafe impl Send for RawReceiverImpl {}

impl RawReceiver for RawReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // NOTE Most of the logic here is identical to FreeBSD/OS X
        while self.packets.is_empty() {
            let _operation = self
                .adapter
                .operation_lock
                .lock()
                .map_err(|_| io::Error::other("Npcap adapter operation mutex poisoned"))?;
            // SAFETY: The adapter operation is serialized, and both owned
            // handles remain live for the duration of the call.
            let api = self.adapter.api;
            // SAFETY: The adapter operation is serialized, and both owned
            // handles remain live for the duration of the call.
            let ret =
                unsafe { (api.PacketReceivePacket)(self.adapter.adapter, self.packet.packet, 1) };
            let buflen = match ret {
                0 => return Err(io::Error::last_os_error()),
                // SAFETY: A successful receive initialized the byte count.
                _ => unsafe { (*self.packet.packet).ulBytesReceived as usize },
            };
            if buflen == 0 && self.timeout_configured {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no packet received before the configured read timeout elapsed",
                ));
            }
            let bytes = self.read_buffer.get(..buflen).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Npcap reported bytes beyond the receive buffer",
                )
            })?;
            self.packets = bpf::parse_records(bytes)?;
        }
        let (start, len) = self.packets.pop_front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet queue unexpectedly empty",
            )
        })?;
        Ok(&self.read_buffer[start..start + len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires NEX_TEST_INTERFACE and Npcap; run with --test-threads=1"]
    fn post_allocation_failure_closes_adapter() {
        windows::failure_tests::assert_cleanup(|interface, api| {
            channel_with_api(interface, Config::default(), api).is_err()
        });
    }

    #[test]
    fn config_from_preserves_explicitread_buffer() {
        let cfg = crate::Config::default().with_read_buffer_size(4096);
        let backend_cfg = Config::from(&cfg);
        assert_eq!(backend_cfg.read_buffer_size, 4096);
    }

    #[test]
    fn config_default_uses_largeread_buffer() {
        let cfg = Config::default();
        assert_eq!(cfg.write_buffer_size, DEFAULT_WRITE_BUFFER_SIZE);
        assert_eq!(cfg.read_buffer_size, DEFAULT_READ_BUFFER_SIZE);
    }

    #[test]
    fn config_from_forwards_promiscuous_and_timeout() {
        let cfg = crate::Config::default()
            .with_promiscuous(false)
            .with_read_timeout(Some(Duration::from_millis(250)));
        let backend_cfg = Config::from(&cfg);
        assert!(!backend_cfg.promiscuous);
        assert_eq!(backend_cfg.read_timeout, Some(Duration::from_millis(250)));
    }

    #[test]
    fn read_timeout_millis_maps_none_to_blocking() {
        assert_eq!(read_timeout_millis(None).unwrap(), 0);
    }

    #[test]
    fn read_timeout_millis_rounds_zero_up_to_bounded_wait() {
        // 0 would mean "block forever" to Npcap, which is the opposite of what
        // a zero-duration timeout requests.
        assert_eq!(read_timeout_millis(Some(Duration::ZERO)).unwrap(), 1);
        assert_eq!(
            read_timeout_millis(Some(Duration::from_micros(1))).unwrap(),
            1
        );
    }

    #[test]
    fn read_timeout_millis_converts_and_rejects_overflow() {
        assert_eq!(
            read_timeout_millis(Some(Duration::from_millis(1500))).unwrap(),
            1500
        );
        let err = read_timeout_millis(Some(Duration::from_secs(u64::MAX / 1000))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn hw_filter_tracks_promiscuous_setting() {
        assert_eq!(
            windows::hw_filter_for(true),
            windows::NDIS_PACKET_TYPE_PROMISCUOUS
        );
        let non_promiscuous = windows::hw_filter_for(false);
        assert_eq!(non_promiscuous & windows::NDIS_PACKET_TYPE_PROMISCUOUS, 0);
        assert_ne!(non_promiscuous & windows::NDIS_PACKET_TYPE_DIRECTED, 0);
    }
}
