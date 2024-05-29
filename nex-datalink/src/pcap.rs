//! Support for sending and receiving data link layer packets using libpcap.
//! Also has support for reading pcap files.

use std::io;
use std::marker::{Send, Sync};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pcap::{Activated, Active};

use nex_core::interface::Interface;
use nex_core::interface::InterfaceType;
use crate::Channel::Ethernet;
use crate::{FrameReceiver, FrameSender};

/// Configuration for the pcap datalink backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when reading packets. Must be at least
    /// 65516 with pcap.
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// Promiscuous mode.
    pub promiscuous: bool,
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        let mut c = Config {
            read_buffer_size: config.read_buffer_size,
            read_timeout: config.read_timeout,
            promiscuous: config.promiscuous,
        };
        // pcap is unique in that the buffer size must be greater or equal to
        // MAXIMUM_SNAPLEN, which is currently hard-coded to 65536
        // So, just reset it to the default.
        if c.read_buffer_size < 65536 {
            c.read_buffer_size = Config::default().read_buffer_size;
        }
        c
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            // Just let pcap pick the default size
            read_buffer_size: 0,
            read_timeout: None,
            promiscuous: true,
        }
    }
}

/// Create a datalink channel from the provided pcap device.
#[inline]
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    let cap = match pcap::Capture::from_device(&*network_interface.name) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    }
    .buffer_size(config.read_buffer_size as i32);
    // Set pcap timeout (in milliseconds).
    // For conversion .as_millis() method could be used as well, but might have
    // a small performance impact as it uses u128 as return type
    let cap = match config.read_timeout {
        Some(to) => cap.timeout((to.as_secs() as u32 * 1000 + to.subsec_millis()) as i32),
        None => cap,
    };
    // Enable promiscuous capture
    let cap = cap.promisc(config.promiscuous);
    let cap = match cap.open() {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(FrameSenderImpl {
            capture: cap.clone(),
        }),
        Box::new(FrameReceiverImpl {
            capture: cap.clone(),
            read_buffer: vec![0; config.read_buffer_size],
        }),
    ))
}

/// Create a datalink channel from a pcap file.
#[inline]
pub fn from_file<P: AsRef<Path>>(path: P, config: Config) -> io::Result<super::Channel> {
    let cap = match pcap::Capture::from_file(path) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(InvalidFrameSenderImpl {}),
        Box::new(FrameReceiverImpl {
            capture: cap.clone(),
            read_buffer: vec![0; config.read_buffer_size],
        }),
    ))
}

struct FrameSenderImpl {
    capture: Arc<Mutex<pcap::Capture<Active>>>,
}

impl FrameSender for FrameSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        for _ in 0..num_packets {
            let mut data = vec![0; packet_size];
            func(&mut data);
            let mut cap = self.capture.lock().unwrap();
            if let Err(e) = cap.sendpacket(data) {
                return Some(Err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }
        Some(Ok(()))
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        let mut cap = self.capture.lock().unwrap();
        Some(match cap.sendpacket(packet) {
            Ok(()) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
    }
}

struct InvalidFrameSenderImpl {}

impl FrameSender for InvalidFrameSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        None
    }

    #[inline]
    fn send(&mut self, _packet: &[u8]) -> Option<io::Result<()>> {
        None
    }
}

struct FrameReceiverImpl<T: Activated + Send + Sync> {
    capture: Arc<Mutex<pcap::Capture<T>>>,
    read_buffer: Vec<u8>,
}

impl<T: Activated + Send + Sync> FrameReceiver for FrameReceiverImpl<T> {
    fn next(&mut self) -> io::Result<&[u8]> {
        let mut cap = self.capture.lock().unwrap();
        match cap.next_packet() {
            Ok(pkt) => {
                self.read_buffer.truncate(0);
                self.read_buffer.extend(pkt.data);
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        Ok(&self.read_buffer)
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    if let Ok(devices) = pcap::Device::list() {
        devices
            .iter()
            .enumerate()
            .map(|(i, dev)| Interface {
                name: dev.name.clone(),
                index: i as u32,
                friendly_name: None,
                description: dev.desc.clone(),
                if_type: InterfaceType::Unknown,
                mac_addr: None,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                flags: dev.flags.if_flags.bits(),
                transmit_speed: None,
                receive_speed: None,
                gateway: None,
                dns_servers: Vec::new(),
                default: false,
            })
            .collect()
    } else {
        vec![]
    }
}
