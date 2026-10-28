//! Explicit, receive-only Windows Packet Monitor backend.
//!
//! Requires the `winptap` feature and administrator privileges, but no Npcap.
//! This module never injects packets or requests promiscuous mode. The official
//! API observes receive and transmit traffic; native IOCTL observes receive only.
//! With the `async` feature, `open_async` provides runtime-independent reception.

#[cfg(feature = "async")]
mod async_io;
#[cfg(feature = "async")]
pub use async_io::{AsyncCancellationToken, AsyncReceiver, open_async};

use crate::RawReceiver;
pub use ::winptap::{Backend, CancellationToken, Error, OverflowPolicy, Statistics};
use ::winptap::{
    CaptureConfig, CaptureDevice, InterfaceIdentity, LinkType, Packet, PacketReceiver,
};
use nex_core::interface::{Interface, get_interfaces};
use std::{io, time::Duration};

/// Receive-only settings, independent of the send/receive [`crate::Config`].
///
/// No conversion from that configuration is provided: its buffer sizes and
/// promiscuous setting have different semantics. Duplicate observations are kept.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Config {
    /// Packet Monitor backend. Auto probes official APIs before native IOCTL.
    pub backend: Backend,
    /// Maximum captured bytes per frame (1..=9000). Frames may be truncated.
    pub snaplen: u16,
    /// Maximum number of queued packets (1..=1048576), excluding the borrowed frame.
    pub queue_capacity: usize,
    /// Which packets to discard when the bounded queue fills.
    pub overflow_policy: OverflowPolicy,
    /// Receive wait limit. None waits indefinitely; zero polls without waiting.
    pub read_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: Backend::Auto,
            snaplen: 9000,
            queue_capacity: 1024,
            overflow_policy: OverflowPolicy::DropNewest,
            read_timeout: None,
        }
    }
}

impl Config {
    /// Validate without enumerating devices or requiring privileges.
    pub fn validate(&self) -> io::Result<()> {
        self.capture_config(None).map(|_| ())
    }

    fn capture_config(&self, device: Option<CaptureDevice>) -> io::Result<CaptureConfig> {
        let mut builder = CaptureConfig::builder()
            .backend(self.backend)
            .link_type(LinkType::Ethernet)
            .snaplen(self.snaplen)
            .queue_capacity(self.queue_capacity)
            .overflow_policy(self.overflow_policy);
        if let Some(timeout) = self.read_timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(device) = device {
            builder = builder.device(device);
        }
        builder.build().map_err(Into::into)
    }
}

fn identity(interface: &Interface) -> InterfaceIdentity<'_> {
    InterfaceIdentity {
        name: &interface.name,
        description: interface.description.as_deref(),
        mac_address: interface.mac_addr.map(|mac| mac.octets()),
    }
}

fn select_device(
    interface: &Interface,
    interfaces: &[Interface],
    devices: &[CaptureDevice],
) -> io::Result<CaptureDevice> {
    // Never use an OS interface index as a Packet Monitor component ID.
    // Reject stale identities rather than falling back from an incomplete snapshot.
    if !interfaces.iter().any(|current| {
        current.name.eq_ignore_ascii_case(&interface.name)
            && current.mac_addr == interface.mac_addr
            && current.description == interface.description
    }) {
        return Err(Error::InvalidConfig("interface is absent or changed; enumerate again").into());
    }
    let identities: Vec<_> = interfaces.iter().map(identity).collect();
    CaptureDevice::for_interface(identity(interface), &identities, devices).map_err(Into::into)
}

/// Open and start an Ethernet receiver for the supplied OS interface.
///
/// Enumerates the complete OS interface snapshot for unambiguous GUID/MAC/
/// description matching. Missing or ambiguous identities fail. Initialization
/// errors preserve [`Error`] inside [`io::Error`]; this never falls back to Npcap.
/// Invalid configuration is rejected before device access.
pub fn open(interface: &Interface, config: Config) -> io::Result<Receiver> {
    config.validate()?;
    let interfaces = get_interfaces();
    let devices = CaptureDevice::list_with_backend(config.backend).map_err(io::Error::from)?;
    let device = select_device(interface, &interfaces, &devices)?;
    let inner = PacketReceiver::open(config.capture_config(Some(device))?)?;
    Ok(Receiver {
        inner,
        packet: None,
    })
}

/// A movable, receive-only Ethernet endpoint implementing [`RawReceiver`].
///
/// The capture session stays on winptap's dedicated owner thread. Only one
/// delivered packet is retained outside its bounded queue; borrowing its bytes
/// adds no copy. Drop stops capture and joins the owner. There is no restart.
pub struct Receiver {
    inner: PacketReceiver,
    packet: Option<Packet>,
}

impl Receiver {
    /// Stop and join capture, preserving queued frames for subsequent reads.
    /// After draining, reads return [`io::ErrorKind::UnexpectedEof`].
    pub fn stop(&mut self) -> io::Result<()> {
        self.inner.stop().map_err(Into::into)
    }

    /// Obtain a token that can wake a blocked receive from another thread.
    /// Cancellation discards queued delivery and returns `Interrupted` on reads.
    /// Drop or stop joins the owner thread after cancellation.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation_token()
    }

    /// Cumulative capture statistics, including queue overflow and truncation.
    pub fn statistics(&self) -> Statistics {
        self.inner.statistics()
    }
}

fn retain_packet(
    slot: &mut Option<Packet>,
    result: ::winptap::Result<Option<Packet>>,
) -> io::Result<&[u8]> {
    *slot = result.map_err(io::Error::from)?;
    slot.as_ref()
        .map(Packet::data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Packet Monitor capture ended"))
}

impl RawReceiver for Receiver {
    /// Borrow the next Ethernet frame until the next mutable receiver operation.
    /// Timeouts return `TimedOut`, cancellation `Interrupted`, and drained normal
    /// termination `UnexpectedEof`. Other winptap failures retain their source.
    fn next(&mut self) -> io::Result<&[u8]> {
        // Release the prior allocation before waiting for another frame.
        self.packet = None;
        retain_packet(&mut self.packet, self.inner.next_packet())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_core::mac::MacAddr;
    use winptap_core::{Device, wire::decode_stream};

    fn interface() -> Interface {
        let mut interface = Interface::dummy();
        interface.index = 999;
        interface.name = "{00112233-4455-6677-8899-aabbccddeeff}".into();
        interface.description = Some("Test NIC".into());
        interface.mac_addr = Some(MacAddr::new(2, 1, 2, 3, 4, 5));
        interface
    }

    fn device() -> CaptureDevice {
        CaptureDevice(Device {
            backend: Backend::Pktmon,
            id: 42,
            secondary_id: 0,
            parent_id: 0,
            name: "test.sys".into(),
            description: "Test NIC".into(),
            network_interface: true,
            guid: None,
            mac_address: Some([2, 1, 2, 3, 4, 5]),
        })
    }

    #[test]
    fn receiver_satisfies_send_and_object_safe_raw_receiver() {
        fn contract<T: RawReceiver + Send + 'static>() {}
        contract::<Receiver>();
        let _: fn(Receiver) -> Box<dyn RawReceiver> = |receiver| Box::new(receiver);
    }

    #[test]
    fn config_validation_precedes_device_access() {
        let mut config = Config::default();
        config.validate().unwrap();
        for snaplen in [0, 9001, u16::MAX] {
            config.snaplen = snaplen;
            let error = open(&Interface::dummy(), config.clone()).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.get_ref().unwrap().is::<Error>());
        }
        config.snaplen = 9000;
        for capacity in [0, 1_048_577, usize::MAX] {
            config.queue_capacity = capacity;
            assert_eq!(
                config.validate().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for capacity in [1, 1_048_576] {
            config.queue_capacity = capacity;
            config.read_timeout = Some(Duration::ZERO);
            config.validate().unwrap();
        }
    }

    #[test]
    fn guid_takes_priority_over_mac_and_os_index() {
        let interface = interface();
        let mut target = device();
        target.0.guid = Some([
            0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ]);
        let mut unrelated = device();
        unrelated.0.id = interface.index;
        let selected = select_device(
            &interface,
            std::slice::from_ref(&interface),
            &[unrelated, target],
        )
        .unwrap();
        assert_eq!(selected.id, 42);
    }

    #[test]
    fn fallback_requires_complete_unambiguous_identity() {
        let interface = interface();
        let snapshot = [interface.clone()];
        assert_eq!(
            select_device(&interface, &snapshot, &[device()])
                .unwrap()
                .id,
            42
        );
        let mut other = interface.clone();
        other.name = "other adapter".into();
        assert!(select_device(&interface, &[interface.clone(), other], &[device()]).is_err());
        let mut other_device = device();
        other_device.0.id = 43;
        assert!(select_device(&interface, &snapshot, &[device(), other_device]).is_err());
        assert!(select_device(&interface, &[], &[device()]).is_err());
        assert!(select_device(&interface, &snapshot, &[]).is_err());
        let mut stale = interface.clone();
        stale.mac_addr = None;
        assert!(select_device(&stale, &snapshot, &[device()]).is_err());
    }

    #[test]
    fn description_fallback_and_identity_conflicts() {
        let mut interface = interface();
        interface.mac_addr = None;
        let snapshot = [interface.clone()];
        let mut target = device();
        target.0.mac_address = None;
        assert!(select_device(&interface, &snapshot, &[target.clone()]).is_ok());
        target.0.guid = Some([0; 16]);
        assert!(select_device(&interface, &snapshot, &[target]).is_err());
    }

    #[test]
    fn packet_retention_borrows_original_allocation_and_handles_end() {
        let mut record = [0; 54];
        record[40..].fill(0xab);
        let packet = decode_stream(&record, 0, 40, 14, 9000, Backend::Pktmon).unwrap();
        let address = packet.data().as_ptr();
        let mut slot = None;
        let frame = retain_packet(&mut slot, Ok(Some(packet))).unwrap();
        assert_eq!(frame, &[0xab; 14]);
        assert_eq!(frame.as_ptr(), address);
        assert_eq!(
            retain_packet(&mut slot, Ok(None)).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(slot.is_none());
    }

    #[test]
    fn receive_errors_preserve_kind_and_typed_source() {
        for (error, kind) in [
            (Error::Timeout, io::ErrorKind::TimedOut),
            (Error::Cancelled, io::ErrorKind::Interrupted),
            (Error::PermissionDenied, io::ErrorKind::PermissionDenied),
            (Error::MissingApi("test".into()), io::ErrorKind::NotFound),
            (Error::RevisionMismatch, io::ErrorKind::Unsupported),
            (Error::StreamFailed(123), io::ErrorKind::Other),
        ] {
            let converted = retain_packet(&mut None, Err(error.clone())).unwrap_err();
            assert_eq!(converted.kind(), kind);
            assert_eq!(
                converted.get_ref().unwrap().downcast_ref::<Error>(),
                Some(&error)
            );
        }
    }
}
