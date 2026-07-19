//! Cross-platform datalink I/O primitives for sending and receiving raw packets.

use std::fmt;
use std::io;
use std::option::Option;
use std::time::Duration;

mod bindings;

#[cfg(feature = "async")]
pub mod async_io;

#[cfg(windows)]
mod wpcap;

#[cfg(windows)]
use wpcap as backend;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(any(target_os = "linux", target_os = "android"))]
use linux as backend;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios"
))]
mod bpf;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios"
))]
use bpf as backend;

#[cfg(feature = "pcap")]
pub mod pcap;

/// Type alias for an `EtherType`.
pub type EtherType = u16;

/// Type of data link channel to present (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ChannelType {
    /// Send and receive layer 2 packets directly, including headers.
    Layer2,
    /// Send and receive IP packets - send and receive network layer packets.
    Layer3(EtherType),
}

/// A channel for sending and receiving at the data link layer.
#[non_exhaustive]
pub enum Channel {
    /// A datalink channel which sends and receives Ethernet packets.
    Ethernet(Box<dyn RawSender>, Box<dyn RawReceiver>),
}

/// Socket fanout type (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FanoutType {
    /// Fan out packets by hashing packet fields.
    Hash,
    /// Round-robin load balancing.
    LoadBalance,
    /// Fan out packets to the CPU that received them.
    Cpu,
    /// Roll over to the next socket when one socket's queue is full.
    Rollover,
    /// Random fanout.
    Random,
    /// Queue-mapping fanout.
    QueueMapping,
    /// Classic BPF fanout.
    ClassicBpf,
    /// Extended BPF fanout.
    ExtendedBpf,
}

impl FanoutType {
    /// Compatibility alias for [`FanoutType::Hash`].
    #[deprecated(note = "use FanoutType::Hash")]
    pub const HASH: Self = Self::Hash;
    /// Compatibility alias for [`FanoutType::LoadBalance`].
    #[deprecated(note = "use FanoutType::LoadBalance")]
    pub const LB: Self = Self::LoadBalance;
    /// Compatibility alias for [`FanoutType::Cpu`].
    #[deprecated(note = "use FanoutType::Cpu")]
    pub const CPU: Self = Self::Cpu;
    /// Compatibility alias for [`FanoutType::Rollover`].
    #[deprecated(note = "use FanoutType::Rollover")]
    pub const ROLLOVER: Self = Self::Rollover;
    /// Compatibility alias for [`FanoutType::Random`].
    #[deprecated(note = "use FanoutType::Random")]
    pub const RND: Self = Self::Random;
    /// Compatibility alias for [`FanoutType::QueueMapping`].
    #[deprecated(note = "use FanoutType::QueueMapping")]
    pub const QM: Self = Self::QueueMapping;
    /// Compatibility alias for [`FanoutType::ClassicBpf`].
    #[deprecated(note = "use FanoutType::ClassicBpf")]
    pub const CBPF: Self = Self::ClassicBpf;
    /// Compatibility alias for [`FanoutType::ExtendedBpf`].
    #[deprecated(note = "use FanoutType::ExtendedBpf")]
    pub const EBPF: Self = Self::ExtendedBpf;
}

/// Fanout settings (Linux only).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct FanoutOption {
    /// Fanout group identifier.
    pub group_id: u16,
    /// Fanout distribution strategy.
    pub fanout_type: FanoutType,
    /// Whether fragmented packets should be defragmented before fanout.
    pub defrag: bool,
    /// Whether queue rollover should be enabled.
    pub rollover: bool,
}

/// A generic configuration type, encapsulating all options supported by each backend.
///
/// Each option should be treated as a hint - each backend is free to ignore any and all
/// options which don't apply to it.
///
/// # Platform behavior
///
/// - Linux uses `AF_PACKET`. [`ChannelType::Layer2`] includes link-layer
///   headers; [`ChannelType::Layer3`] uses datagram packet sockets for the
///   selected EtherType. Buffer sizes configure the reusable userspace buffers,
///   timeouts bound `poll`, and promiscuous/fanout settings are applied by the
///   kernel.
/// - macOS and BSD use BPF devices. `bpf_fd_attempts` bounds `/dev/bpf*`
///   discovery, read buffering follows the BPF buffer size, and timeouts bound
///   readiness waits.
/// - Windows uses Npcap. Buffer sizes configure Npcap packet buffers. Timeout
///   fields and Linux/BPF-only options are not applied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
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

    /// BPF/macOS only: The number of /dev/bpf* file descriptors to attempt before failing. Defaults
    /// to: 1000.
    pub bpf_fd_attempts: usize,

    /// Linux only: optional packet fanout group and distribution settings.
    pub linux_fanout: Option<FanoutOption>,

    /// Whether the backend should request promiscuous packet capture.
    pub promiscuous: bool,
}

/// Semantic failures while validating or opening a datalink channel.
#[derive(Debug)]
#[non_exhaustive]
pub enum DatalinkError {
    /// A configuration value cannot be used by any backend.
    InvalidConfig {
        /// Configuration field that failed validation.
        field: &'static str,
        /// Required constraint.
        requirement: &'static str,
    },
    /// The operating-system backend failed while creating the channel.
    Io(io::Error),
}

impl fmt::Display for DatalinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field, requirement } => {
                write!(f, "invalid datalink configuration: {field} {requirement}")
            }
            Self::Io(error) => write!(f, "failed to open datalink channel: {error}"),
        }
    }
}

impl std::error::Error for DatalinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfig { .. } => None,
        }
    }
}

impl From<io::Error> for DatalinkError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
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

impl Config {
    /// Validates whether this configuration can be used safely.
    pub fn validate(&self) -> Result<(), DatalinkError> {
        if self.write_buffer_size == 0 {
            return Err(DatalinkError::InvalidConfig {
                field: "write_buffer_size",
                requirement: "must be greater than zero",
            });
        }
        if self.read_buffer_size == 0 {
            return Err(DatalinkError::InvalidConfig {
                field: "read_buffer_size",
                requirement: "must be greater than zero",
            });
        }
        if self.bpf_fd_attempts == 0 {
            return Err(DatalinkError::InvalidConfig {
                field: "bpf_fd_attempts",
                requirement: "must be greater than zero",
            });
        }
        Ok(())
    }

    pub fn with_write_buffer_size(mut self, write_buffer_size: usize) -> Self {
        self.write_buffer_size = write_buffer_size;
        self
    }

    pub fn with_read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.read_buffer_size = read_buffer_size;
        self
    }

    pub fn with_read_timeout(mut self, read_timeout: Option<Duration>) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    pub fn with_write_timeout(mut self, write_timeout: Option<Duration>) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    pub fn with_channel_type(mut self, channel_type: ChannelType) -> Self {
        self.channel_type = channel_type;
        self
    }

    pub fn with_bpf_fd_attempts(mut self, bpf_fd_attempts: usize) -> Self {
        self.bpf_fd_attempts = bpf_fd_attempts;
        self
    }

    pub fn with_linux_fanout(mut self, linux_fanout: Option<FanoutOption>) -> Self {
        self.linux_fanout = linux_fanout;
        self
    }

    pub fn with_promiscuous(mut self, promiscuous: bool) -> Self {
        self.promiscuous = promiscuous;
        self
    }
}

/// Creates a new datalink channel for sending and receiving raw packets.
///
/// This function sets up a channel to send and receive raw packets directly from a data link layer
/// such as Ethernet. It uses the provided network interface and configuration settings to
/// establish the channel. Note that the actual usage of the configuration may vary based on the
/// underlying backend; some settings may be ignored or treated differently depending on the system
/// and library capabilities.
///
/// The synchronous receiver blocks until data, an error, or a configured
/// platform-supported timeout occurs. A timeout is reported as an
/// [`io::ErrorKind::TimedOut`] or [`io::ErrorKind::WouldBlock`] according to
/// the operating-system backend.
///
/// The function returns a `Channel` object encapsulating the transmission and reception capabilities.
#[inline]
pub fn channel(
    network_interface: &nex_core::interface::Interface,
    configuration: Config,
) -> Result<Channel, DatalinkError> {
    configuration.validate()?;
    backend::channel(network_interface, (&configuration).into()).map_err(DatalinkError::Io)
}

/// Trait to enable sending `$packet` packets.
pub trait RawSender: Send {
    /// Create and send a number of packets.
    ///
    /// This will call `func` `num_packets` times. The function will be provided with a
    /// mutable packet to manipulate, which will then be sent. This allows packets to be
    /// built in-place, avoiding the copy required for `send`.
    ///
    /// `None` means the requested packet count or size does not fit the
    /// sender's reusable userspace buffer and no send was attempted.
    /// `Some(Err(_))` means capacity was available but an operating-system I/O
    /// operation failed. `Some(Ok(()))` means every requested packet was
    /// accepted by the backend.
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>>;

    /// Send a packet.
    ///
    /// This may require an additional copy compared to `build_and_send`,
    /// depending on the operating system being used. `None` means the packet
    /// exceeds the sender's reusable capacity; `Some` contains the I/O result
    /// when a send was attempted.
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>>;
}

/// Structure for receiving packets at the data link layer. Should be constructed using
/// `channel()`.
pub trait RawReceiver: Send {
    /// Get the next ethernet frame in the channel.
    fn next(&mut self) -> io::Result<&[u8]>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_values() {
        let cfg = Config::default();
        assert_eq!(cfg.write_buffer_size, 4096);
        assert_eq!(cfg.read_buffer_size, 4096);
        assert_eq!(cfg.read_timeout, None);
        assert_eq!(cfg.write_timeout, None);
        assert_eq!(cfg.channel_type, ChannelType::Layer2);
        assert_eq!(cfg.bpf_fd_attempts, 1000);
        assert!(cfg.linux_fanout.is_none());
        assert!(cfg.promiscuous);
    }

    #[test]
    fn config_validate_rejects_zero_buffer_size() {
        let cfg = Config::default().with_read_buffer_size(0);
        assert!(cfg.validate().is_err());

        let cfg = Config::default().with_write_buffer_size(0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_builder_updates_fields() {
        let cfg = Config::default()
            .with_channel_type(ChannelType::Layer3(0x0800))
            .with_promiscuous(false)
            .with_bpf_fd_attempts(42);

        assert_eq!(cfg.channel_type, ChannelType::Layer3(0x0800));
        assert!(!cfg.promiscuous);
        assert_eq!(cfg.bpf_fd_attempts, 42);
    }

    fn assert_error_contract<T: std::error::Error + Send + Sync + 'static>() {}

    #[test]
    fn datalink_error_implements_public_error_contract() {
        assert_error_contract::<DatalinkError>();
    }
}
