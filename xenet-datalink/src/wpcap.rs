//! Support for sending and receiving data link layer packets using the npcap or winpcap library.

use super::bindings::{bpf, windows};
use super::{DataLinkReceiver, DataLinkSender};
use xenet_core::interface::Interface;

use libc::c_char;
use std::cmp;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::slice;
use std::sync::Arc;

struct WinPcapAdapter {
    adapter: windows::LPADAPTER,
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        unsafe {
            windows::PacketCloseAdapter(self.adapter);
        }
    }
}

struct WinPcapPacket {
    packet: windows::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        unsafe {
            windows::PacketFreePacket(self.packet);
        }
    }
}

/// The WinPcap's specific configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
        }
    }
}

/// Create a datalink channel using the WinPcap library.
#[inline]
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    let mut read_buffer = Vec::new();
    read_buffer.resize(config.read_buffer_size, 0u8);

    let mut write_buffer = Vec::new();
    write_buffer.resize(config.write_buffer_size, 0u8);

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
        return Err(io::Error::last_os_error());
    }

    // Set kernel buffer size
    let ret = unsafe { windows::PacketSetBuff(adapter, config.read_buffer_size as libc::c_int) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Immediate mode
    let ret = unsafe { windows::PacketSetMinToCopy(adapter, 1) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    let read_packet = unsafe { windows::PacketAllocatePacket() };
    if read_packet.is_null() {
        unsafe {
            windows::PacketCloseAdapter(adapter);
        }
        return Err(io::Error::last_os_error());
    }

    unsafe {
        windows::PacketInitPacket(
            read_packet,
            read_buffer.as_mut_ptr() as windows::PVOID,
            config.read_buffer_size as windows::UINT,
        )
    }

    let write_packet = unsafe { windows::PacketAllocatePacket() };
    if write_packet.is_null() {
        unsafe {
            windows::PacketFreePacket(read_packet);
            windows::PacketCloseAdapter(adapter);
        }
        return Err(io::Error::last_os_error());
    }

    unsafe {
        windows::PacketInitPacket(
            write_packet,
            write_buffer.as_mut_ptr() as windows::PVOID,
            config.write_buffer_size as windows::UINT,
        )
    }

    let adapter = Arc::new(WinPcapAdapter { adapter: adapter });
    let sender = Box::new(DataLinkSenderImpl {
        adapter: adapter.clone(),
        _write_buffer: write_buffer,
        packet: WinPcapPacket {
            packet: write_packet,
        },
    });
    let receiver = Box::new(DataLinkReceiverImpl {
        adapter: adapter,
        _read_buffer: read_buffer,
        packet: WinPcapPacket {
            packet: read_packet,
        },
        // Enough room for minimally sized packets without reallocating
        packets: VecDeque::with_capacity(unsafe { (*read_packet).Length } as usize / 64),
    });
    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    adapter: Arc<WinPcapAdapter>,
    _write_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl DataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len >= unsafe { (*self.packet.packet).Length } as usize {
            None
        } else {
            let min = unsafe { cmp::min((*self.packet.packet).Length as usize, len) };
            let slice: &mut [u8] =
                unsafe { slice::from_raw_parts_mut((*self.packet.packet).Buffer as *mut u8, min) };
            for chunk in slice.chunks_mut(packet_size) {
                func(chunk);

                // Make sure the right length of packet is sent
                let old_len = unsafe { (*self.packet.packet).Length };
                unsafe {
                    (*self.packet.packet).Length = packet_size as u32;
                }

                let ret = unsafe {
                    windows::PacketSendPacket(self.adapter.adapter, self.packet.packet, 0)
                };

                unsafe {
                    (*self.packet.packet).Length = old_len;
                }

                if ret == 0 {
                    return Some(Err(io::Error::last_os_error()));
                }
            }
            Some(Ok(()))
        }
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        self.build_and_send(1, packet.len(), &mut |eh: &mut [u8]| {
            eh.copy_from_slice(packet);
        })
    }
}

unsafe impl Send for DataLinkSenderImpl {}
unsafe impl Sync for DataLinkSenderImpl {}

struct DataLinkReceiverImpl {
    adapter: Arc<WinPcapAdapter>,
    _read_buffer: Vec<u8>,
    packet: WinPcapPacket,
    packets: VecDeque<(usize, usize)>,
}

unsafe impl Send for DataLinkReceiverImpl {}
unsafe impl Sync for DataLinkReceiverImpl {}

impl DataLinkReceiver for DataLinkReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // NOTE Most of the logic here is identical to FreeBSD/OS X
        while self.packets.is_empty() {
            let ret = unsafe {
                windows::PacketReceivePacket(self.adapter.adapter, self.packet.packet, 0)
            };
            let buflen = match ret {
                0 => return Err(io::Error::last_os_error()),
                _ => unsafe { (*self.packet.packet).ulBytesReceived as isize },
            };
            let mut ptr = unsafe { (*self.packet.packet).Buffer as *mut c_char };
            let end = unsafe { ((*self.packet.packet).Buffer as *mut c_char).offset(buflen) };
            while ptr < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as isize + (*packet).bh_hdrlen as isize
                        - (*self.packet.packet).Buffer as isize;
                    self.packets
                        .push_back((start as usize, (*packet).bh_caplen as usize));
                    let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();
        let slice = unsafe {
            let data = (*self.packet.packet).Buffer as usize + start;
            slice::from_raw_parts(data as *const u8, len)
        };
        Ok(slice)
    }
}
