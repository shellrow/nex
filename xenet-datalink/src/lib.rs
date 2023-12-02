//! Provides functionality for interacting with the data link layer, support for sending and receiving packets.

#![deny(warnings)]
extern crate libc;
extern crate xenet_core;
extern crate xenet_sys;

use std::io;
use std::option::Option;
use std::time::Duration;

pub use xenet_core::mac::{MacAddr, ParseMacAddrError};

mod bindings;
pub use xenet_core::interface;

#[cfg(windows)]
#[path = "wpcap.rs"]
mod backend;

#[cfg(windows)]
pub mod wpcap;

#[cfg(all(
    any(target_os = "linux", target_os = "android")
))]
#[path = "linux.rs"]
mod backend;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

#[cfg(all(
    any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "macos",
        target_os = "ios"
    )
))]
#[path = "bpf.rs"]
mod backend;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios"
))]
pub mod bpf;

#[cfg(feature = "pcap")]
pub mod pcap;

/// Type alias for an `EtherType`.
pub type EtherType = u16;

/// Type of data link channel to present (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChannelType {
    /// Send and receive layer 2 packets directly, including headers.
    Layer2,
    /// Send and receive "cooked" packets - send and receive network layer packets.
    Layer3(EtherType),
}

/// A channel for sending and receiving at the data link layer.
#[non_exhaustive]
pub enum Channel {
    /// A datalink channel which sends and receives Ethernet packets.
    Ethernet(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
}

/// Socket fanout type (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FanoutType {
    HASH,
    LB,
    CPU,
    ROLLOVER,
    RND,
    QM,
    CBPF,
    EBPF,
}

/// Fanout settings (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FanoutOption {
    pub group_id: u16,
    pub fanout_type: FanoutType,
    pub defrag: bool,
    pub rollover: bool,
}

/// A generic configuration type, encapsulating all options supported by each backend.
///
/// Each option should be treated as a hint - each backend is free to ignore any and all
/// options which don't apply to it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// Linux/BPF/Netmap only: The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// Linux/BPF/Netmap only: The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,

    /// Linux only: Specifies whether to read packets at the datalink layer or network layer.
    /// Defaults to Layer2
    pub channel_type: ChannelType,

    /// BPF/OS X only: The number of /dev/bpf* file descriptors to attempt before failing. Defaults
    /// to: 1000.
    pub bpf_fd_attempts: usize,

    pub linux_fanout: Option<FanoutOption>,

    pub promiscuous: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
        }
    }
}

/// Create a new datalink channel for sending and receiving data.
///
/// This allows for sending and receiving packets at the data link layer.
///
/// A list of network interfaces can be retrieved using datalink::interfaces().
///
/// The configuration serves as a hint to the backend - some or all of it may be used or ignored,
/// depending on which backend is used.
///
/// When matching on the returned channel, make sure to include a catch-all so that code doesn't
/// break when new channel types are added.
#[inline]
pub fn channel(
    network_interface: &interface::Interface,
    configuration: Config,
) -> io::Result<Channel> {
    backend::channel(network_interface, (&configuration).into())
}

/// Trait to enable sending `$packet` packets.
pub trait DataLinkSender: Send {
    /// Create and send a number of packets.
    ///
    /// This will call `func` `num_packets` times. The function will be provided with a
    /// mutable packet to manipulate, which will then be sent. This allows packets to be
    /// built in-place, avoiding the copy required for `send`. If there is not sufficient
    /// capacity in the buffer, None will be returned.
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>>;

    /// Send a packet.
    ///
    /// This may require an additional copy compared to `build_and_send`, depending on the
    /// operating system being used.
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>>;
}

/// Structure for receiving packets at the data link layer. Should be constructed using
/// `datalink_channel()`.
pub trait DataLinkReceiver: Send {
    /// Get the next ethernet frame in the channel.
    fn next(&mut self) -> io::Result<&[u8]>;
}
