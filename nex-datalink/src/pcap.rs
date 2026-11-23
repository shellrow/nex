//! Support for sending and receiving data link layer packets using libpcap.
//! Also has support for reading pcap files.

use std::io;
use std::marker::{Send, Sync};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pcap::{Activated, Active, State};

use crate::Channel::Ethernet;
use crate::{RawReceiver, RawSender};
use nex_core::interface::Interface;
use nex_core::interface::{IFF_LOOPBACK, IFF_UP, OperState, get_interfaces};

/// Configuration for the pcap datalink backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Config {
    /// Kernel capture buffer size in bytes. Zero selects the libpcap default.
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// Promiscuous mode.
    pub promiscuous: bool,
}

impl From<&super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        let mut c = Config {
            read_buffer_size: config.read_buffer_size,
            read_timeout: config.read_timeout,
            promiscuous: config.promiscuous,
        };
        // Small per-read buffers translate poorly to kernel capture buffers.
        // Preserve the libpcap default for these channel configurations.
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
    let device_name = capture_device_name(&network_interface.name);
    let size = i32::try_from(config.read_buffer_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pcap buffer size exceeds i32"))?;
    let mut cap = pcap::Capture::from_device(device_name.as_ref())
        .map_err(io::Error::other)?
        .buffer_size(size);
    if let Some(timeout) = config.read_timeout {
        let millis =
            i32::try_from(timeout.as_nanos().div_ceil(1_000_000).max(1)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pcap timeout exceeds i32 milliseconds",
                )
            })?;
        cap = cap.timeout(millis);
    }
    // Enable promiscuous capture
    let cap = cap.promisc(config.promiscuous);
    let cap = match cap.open() {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::other(e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(RawSenderImpl {
            device_name: device_name.into_owned(),
            capture: cap.clone(),
        }),
        Box::new(RawReceiverImpl {
            capture: cap.clone(),
            read_buffer: Vec::new(),
        }),
    ))
}

fn capture_device_name(name: &str) -> std::borrow::Cow<'_, str> {
    // Core interfaces use bare adapter GUIDs on Windows, while pcap enumerates
    // full NPF paths. Preserve names already returned by pcap, including URLs.
    #[cfg(windows)]
    if name.starts_with('{') && name.ends_with('}') {
        return crate::bindings::windows::to_npf_name(name).into();
    }
    name.into()
}

/// Create a datalink channel from a pcap file.
#[inline]
pub fn from_file<P: AsRef<Path>>(path: P, _config: Config) -> io::Result<super::Channel> {
    let cap = match pcap::Capture::from_file(path) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::other(e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(InvalidRawSenderImpl {}),
        Box::new(RawReceiverImpl {
            capture: cap.clone(),
            read_buffer: Vec::new(),
        }),
    ))
}

struct RawSenderImpl {
    device_name: String,
    capture: Arc<Mutex<pcap::Capture<Active>>>,
}

fn lock_capture<T: State>(
    capture: &Mutex<pcap::Capture<T>>,
) -> io::Result<MutexGuard<'_, pcap::Capture<T>>> {
    capture
        .lock()
        .map_err(|_| io::Error::other("pcap capture mutex poisoned"))
}

impl RawSender for RawSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        if num_packets == 0 {
            return Some(Ok(()));
        }
        let mut data = vec![0; packet_size];
        for _ in 0..num_packets {
            data.fill(0);
            func(&mut data);
            if let Err(error) = self.send_packet(&data) {
                return Some(Err(error));
            }
        }
        Some(Ok(()))
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        Some(self.send_packet(packet))
    }
}

impl RawSenderImpl {
    fn send_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let capture = self.capture.clone();
        let mut cap = match capture.try_lock() {
            Ok(cap) => cap,
            Err(std::sync::TryLockError::WouldBlock) => {
                // Keep injection independent of an outstanding blocking capture.
                let tx = pcap::Capture::from_device(self.device_name.as_str())
                    .and_then(|cap| cap.snaplen(1).open())
                    .map_err(io::Error::other)?;
                self.capture = Arc::new(Mutex::new(tx));
                lock_capture(&self.capture)?
            }
            Err(_) => return Err(io::Error::other("pcap capture mutex poisoned")),
        };
        cap.sendpacket(packet).map_err(io::Error::other)
    }
}

struct InvalidRawSenderImpl {}

impl RawSender for InvalidRawSenderImpl {
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

struct RawReceiverImpl<T: Activated + State + Send + Sync> {
    capture: Arc<Mutex<pcap::Capture<T>>>,
    read_buffer: Vec<u8>,
}

impl<T: Activated + State + Send + Sync> RawReceiver for RawReceiverImpl<T> {
    fn next(&mut self) -> io::Result<&[u8]> {
        let mut cap = lock_capture(&self.capture)?;
        match cap.next_packet() {
            Ok(pkt) => {
                self.read_buffer.clear();
                self.read_buffer.extend(pkt.data);
            }
            Err(pcap::Error::TimeoutExpired) => return Err(io::ErrorKind::TimedOut.into()),
            Err(pcap::Error::NoMorePackets) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Err(e) => return Err(io::Error::other(e)),
        };
        Ok(&self.read_buffer)
    }
}

/// List libpcap capture devices. Matched interfaces carry their operating-system
/// index. Capture-only devices, such as Linux `any`, have index zero.
pub fn interfaces() -> Vec<Interface> {
    let Ok(devices) = pcap::Device::list() else {
        return Vec::new();
    };
    let mut system_interfaces: std::collections::HashMap<_, _> = get_interfaces()
        .into_iter()
        .map(|iface| (device_key(&capture_device_name(&iface.name)), iface))
        .collect();
    devices
        .into_iter()
        .map(|dev| {
            let mut interface = system_interfaces
                .remove(&device_key(&dev.name))
                .unwrap_or_else(|| {
                    let mut iface = Interface::dummy();
                    if dev.flags.is_up() {
                        iface.flags |= IFF_UP;
                    }
                    if dev.flags.is_loopback() {
                        iface.flags |= IFF_LOOPBACK;
                    }
                    #[cfg(unix)]
                    if dev.flags.is_running() {
                        iface.flags |= nex_core::interface::IFF_RUNNING;
                    }
                    iface.oper_state = OperState::from_if_flags(iface.flags);
                    iface
                });
            interface.name = dev.name;
            if dev.desc.is_some() {
                interface.description = dev.desc;
            }
            interface
        })
        .collect()
}

fn device_key(name: &str) -> String {
    #[cfg(windows)]
    {
        name.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::capture_device_name;

    #[test]
    fn empty_capture_reports_end_of_file() {
        let dir = std::env::temp_dir().join(format!("nex-pcap-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("empty.pcap");
        let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
        drop(cap.savefile(&path).unwrap());
        let crate::Channel::Ethernet(_, mut rx) =
            super::from_file(&path, super::Config::default()).unwrap();
        let result = rx.next().unwrap_err().kind();
        drop(rx);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
        assert_eq!(result, std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn capture_names_are_preserved() {
        for name in [
            "eth0",
            r"\Device\NPF_{12345678-0000-0000-0000-000000000000}",
            "rpcap://host/eth0",
        ] {
            assert_eq!(capture_device_name(name), name);
        }
    }

    #[cfg(windows)]
    #[test]
    fn core_adapter_guid_is_converted_to_npf_path() {
        assert_eq!(
            capture_device_name("{12345678-0000-0000-0000-000000000000}"),
            r"\Device\NPF_{12345678-0000-0000-0000-000000000000}"
        );
    }
}
