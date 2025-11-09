//! An ICMPv6 packet abstraction.

use crate::checksum::{ChecksumMode, ChecksumState, TransportChecksumContext};
use crate::ip::IpNextProtocol;
use crate::ipv6::IPV6_HEADER_LEN;
use crate::{
    ethernet::ETHERNET_HEADER_LEN,
    packet::{MutablePacket, Packet},
};
use std::net::Ipv6Addr;

use bytes::Bytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ICMPv6 Common Header Length.
pub const ICMPV6_COMMON_HEADER_LEN: usize = 4;
/// ICMPv6 Header Length. Including the common header (4 bytes) and the type specific header (4 bytes).
pub const ICMPV6_HEADER_LEN: usize = 8;
/// ICMPv6 Minimum Packet Length.
pub const ICMPV6_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;
/// ICMPv6 IP Packet Length.
pub const ICMPV6_IP_PACKET_LEN: usize = IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;

/// Represents the ICMPv6 types.
/// <https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml>
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    MulticastListenerQuery,
    MulticastListenerReport,
    MulticastListenerDone,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    RedirectMessage,
    RouterRenumbering,
    NodeInformationQuery,
    NodeInformationResponse,
    InverseNeighborDiscoverySolicitation,
    InverseNeighborDiscoveryAdvertisement,
    Version2MulticastListenerReport,
    HomeAgentAddressDiscoveryRequest,
    HomeAgentAddressDiscoveryReply,
    MobilePrefixSolicitation,
    MobilePrefixAdvertisement,
    CertificationPathSolicitationMessage,
    CertificationPathAdvertisementMessage,
    ExperimentalMobilityProtocols,
    MulticastRouterAdvertisement,
    MulticastRouterSolicitation,
    MulticastRouterTermination,
    FMIPv6Messages,
    RPLControlMessage,
    ILNPv6LocatorUpdateMessage,
    DuplicateAddressRequest,
    DuplicateAddressConfirmation,
    MPLControlMessage,
    ExtendedEchoRequest,
    ExtendedEchoReply,
    Unknown(u8),
}

impl Icmpv6Type {
    pub fn new(value: u8) -> Self {
        match value {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            130 => Icmpv6Type::MulticastListenerQuery,
            131 => Icmpv6Type::MulticastListenerReport,
            132 => Icmpv6Type::MulticastListenerDone,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::RedirectMessage,
            138 => Icmpv6Type::RouterRenumbering,
            139 => Icmpv6Type::NodeInformationQuery,
            140 => Icmpv6Type::NodeInformationResponse,
            141 => Icmpv6Type::InverseNeighborDiscoverySolicitation,
            142 => Icmpv6Type::InverseNeighborDiscoveryAdvertisement,
            143 => Icmpv6Type::Version2MulticastListenerReport,
            144 => Icmpv6Type::HomeAgentAddressDiscoveryRequest,
            145 => Icmpv6Type::HomeAgentAddressDiscoveryReply,
            146 => Icmpv6Type::MobilePrefixSolicitation,
            147 => Icmpv6Type::MobilePrefixAdvertisement,
            148 => Icmpv6Type::CertificationPathSolicitationMessage,
            149 => Icmpv6Type::CertificationPathAdvertisementMessage,
            150 => Icmpv6Type::ExperimentalMobilityProtocols,
            151 => Icmpv6Type::MulticastRouterAdvertisement,
            152 => Icmpv6Type::MulticastRouterSolicitation,
            153 => Icmpv6Type::MulticastRouterTermination,
            154 => Icmpv6Type::FMIPv6Messages,
            155 => Icmpv6Type::RPLControlMessage,
            156 => Icmpv6Type::ILNPv6LocatorUpdateMessage,
            157 => Icmpv6Type::DuplicateAddressRequest,
            158 => Icmpv6Type::DuplicateAddressConfirmation,
            159 => Icmpv6Type::MPLControlMessage,
            160 => Icmpv6Type::ExtendedEchoRequest,
            161 => Icmpv6Type::ExtendedEchoReply,
            n => Icmpv6Type::Unknown(n),
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Icmpv6Type::DestinationUnreachable => "Destination Unreachable",
            Icmpv6Type::PacketTooBig => "Packet Too Big",
            Icmpv6Type::TimeExceeded => "Time Exceeded",
            Icmpv6Type::ParameterProblem => "Parameter Problem",
            Icmpv6Type::EchoRequest => "Echo Request",
            Icmpv6Type::EchoReply => "Echo Reply",
            Icmpv6Type::MulticastListenerQuery => "Multicast Listener Query",
            Icmpv6Type::MulticastListenerReport => "Multicast Listener Report",
            Icmpv6Type::MulticastListenerDone => "Multicast Listener Done",
            Icmpv6Type::RouterSolicitation => "Router Solicitation",
            Icmpv6Type::RouterAdvertisement => "Router Advertisement",
            Icmpv6Type::NeighborSolicitation => "Neighbor Solicitation",
            Icmpv6Type::NeighborAdvertisement => "Neighbor Advertisement",
            Icmpv6Type::RedirectMessage => "Redirect Message",
            Icmpv6Type::RouterRenumbering => "Router Renumbering",
            Icmpv6Type::NodeInformationQuery => "Node Information Query",
            Icmpv6Type::NodeInformationResponse => "Node Information Response",
            Icmpv6Type::InverseNeighborDiscoverySolicitation => {
                "Inverse Neighbor Discovery Solicitation"
            }
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => {
                "Inverse Neighbor Discovery Advertisement"
            }
            Icmpv6Type::Version2MulticastListenerReport => "Version 2 Multicast Listener Report",
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => "Home Agent Address Discovery Request",
            Icmpv6Type::HomeAgentAddressDiscoveryReply => "Home Agent Address Discovery Reply",
            Icmpv6Type::MobilePrefixSolicitation => "Mobile Prefix Solicitation",
            Icmpv6Type::MobilePrefixAdvertisement => "Mobile Prefix Advertisement",
            Icmpv6Type::CertificationPathSolicitationMessage => {
                "Certification Path Solicitation Message"
            }
            Icmpv6Type::CertificationPathAdvertisementMessage => {
                "Certification Path Advertisement Message"
            }
            Icmpv6Type::ExperimentalMobilityProtocols => "Experimental Mobility Protocols",
            Icmpv6Type::MulticastRouterAdvertisement => "Multicast Router Advertisement",
            Icmpv6Type::MulticastRouterSolicitation => "Multicast Router Solicitation",
            Icmpv6Type::MulticastRouterTermination => "Multicast Router Termination",
            Icmpv6Type::FMIPv6Messages => "FMIPv6 Messages",
            Icmpv6Type::RPLControlMessage => "RPL Control Message",
            Icmpv6Type::ILNPv6LocatorUpdateMessage => "ILNPv6 Locator Update Message",
            Icmpv6Type::DuplicateAddressRequest => "Duplicate Address Request",
            Icmpv6Type::DuplicateAddressConfirmation => "Duplicate Address Confirmation",
            Icmpv6Type::MPLControlMessage => "MPL Control Message",
            Icmpv6Type::ExtendedEchoRequest => "Extended Echo Request",
            Icmpv6Type::ExtendedEchoReply => "Extended Echo Reply",
            Icmpv6Type::Unknown(_) => "Unknown",
        }
    }
    pub fn value(&self) -> u8 {
        match self {
            Icmpv6Type::DestinationUnreachable => 1,
            Icmpv6Type::PacketTooBig => 2,
            Icmpv6Type::TimeExceeded => 3,
            Icmpv6Type::ParameterProblem => 4,
            Icmpv6Type::EchoRequest => 128,
            Icmpv6Type::EchoReply => 129,
            Icmpv6Type::MulticastListenerQuery => 130,
            Icmpv6Type::MulticastListenerReport => 131,
            Icmpv6Type::MulticastListenerDone => 132,
            Icmpv6Type::RouterSolicitation => 133,
            Icmpv6Type::RouterAdvertisement => 134,
            Icmpv6Type::NeighborSolicitation => 135,
            Icmpv6Type::NeighborAdvertisement => 136,
            Icmpv6Type::RedirectMessage => 137,
            Icmpv6Type::RouterRenumbering => 138,
            Icmpv6Type::NodeInformationQuery => 139,
            Icmpv6Type::NodeInformationResponse => 140,
            Icmpv6Type::InverseNeighborDiscoverySolicitation => 141,
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => 142,
            Icmpv6Type::Version2MulticastListenerReport => 143,
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => 144,
            Icmpv6Type::HomeAgentAddressDiscoveryReply => 145,
            Icmpv6Type::MobilePrefixSolicitation => 146,
            Icmpv6Type::MobilePrefixAdvertisement => 147,
            Icmpv6Type::CertificationPathSolicitationMessage => 148,
            Icmpv6Type::CertificationPathAdvertisementMessage => 149,
            Icmpv6Type::ExperimentalMobilityProtocols => 150,
            Icmpv6Type::MulticastRouterAdvertisement => 151,
            Icmpv6Type::MulticastRouterSolicitation => 152,
            Icmpv6Type::MulticastRouterTermination => 153,
            Icmpv6Type::FMIPv6Messages => 154,
            Icmpv6Type::RPLControlMessage => 155,
            Icmpv6Type::ILNPv6LocatorUpdateMessage => 156,
            Icmpv6Type::DuplicateAddressRequest => 157,
            Icmpv6Type::DuplicateAddressConfirmation => 158,
            Icmpv6Type::MPLControlMessage => 159,
            Icmpv6Type::ExtendedEchoRequest => 160,
            Icmpv6Type::ExtendedEchoReply => 161,
            Icmpv6Type::Unknown(n) => *n,
        }
    }
}

/// Represents the "ICMPv6 code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Icmpv6Code(pub u8);

impl Icmpv6Code {
    /// Create a new `Icmpv6Code` instance.
    pub fn new(val: u8) -> Icmpv6Code {
        Icmpv6Code(val)
    }
    /// Get the value of the `Icmpv6Code`.
    pub fn value(&self) -> u8 {
        self.0
    }
}

/// Represents the ICMPv6 header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Icmpv6Header {
    pub icmpv6_type: Icmpv6Type,
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16,
}

/// ICMP packet representation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv6Packet {
    pub header: Icmpv6Header,
    pub payload: Bytes,
}

impl Packet for Icmpv6Packet {
    type Header = Icmpv6Header;

    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ICMPV6_HEADER_LEN {
            return None;
        }
        let icmpv6_type = Icmpv6Type::new(bytes[0]);
        let icmpv6_code = Icmpv6Code::new(bytes[1]);
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let header = Icmpv6Header {
            icmpv6_type,
            icmpv6_code,
            checksum,
        };
        let payload = Bytes::copy_from_slice(&bytes[ICMPV6_COMMON_HEADER_LEN..]);
        Some(Icmpv6Packet { header, payload })
    }
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }
    fn to_bytes(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(ICMPV6_COMMON_HEADER_LEN + self.payload.len());
        bytes.push(self.header.icmpv6_type.value());
        bytes.push(self.header.icmpv6_code.value());
        bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Bytes::from(bytes)
    }
    fn header(&self) -> Bytes {
        self.to_bytes().slice(..self.header_len())
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        ICMPV6_COMMON_HEADER_LEN
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        (self.header, self.payload)
    }
}

/// Represents a mutable ICMPv6 packet.
pub struct MutableIcmpv6Packet<'a> {
    buffer: &'a mut [u8],
    checksum: ChecksumState,
    checksum_context: Option<TransportChecksumContext>,
}

impl<'a> MutablePacket<'a> for MutableIcmpv6Packet<'a> {
    type Packet = Icmpv6Packet;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        Icmpv6Packet::from_buf(buffer)?;
        Some(Self {
            buffer,
            checksum: ChecksumState::new(),
            checksum_context: None,
        })
    }

    fn packet(&self) -> &[u8] {
        &*self.buffer
    }

    fn packet_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn header(&self) -> &[u8] {
        &self.packet()[..ICMPV6_COMMON_HEADER_LEN]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let (header, _) = (&mut *self.buffer).split_at_mut(ICMPV6_COMMON_HEADER_LEN);
        header
    }

    fn payload(&self) -> &[u8] {
        &self.packet()[ICMPV6_COMMON_HEADER_LEN..]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let (_, payload) = (&mut *self.buffer).split_at_mut(ICMPV6_COMMON_HEADER_LEN);
        payload
    }
}

impl<'a> MutableIcmpv6Packet<'a> {
    /// Create a mutable ICMPv6 packet without performing validation.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            checksum: ChecksumState::new(),
            checksum_context: None,
        }
    }

    fn raw(&self) -> &[u8] {
        &*self.buffer
    }

    fn raw_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn after_field_mutation(&mut self) {
        self.checksum.mark_dirty();
        if self.checksum.automatic() {
            let _ = self.recompute_checksum();
        }
    }

    fn write_checksum(&mut self, value: u16) {
        self.raw_mut()[2..4].copy_from_slice(&value.to_be_bytes());
    }

    /// Returns the checksum recalculation mode.
    pub fn checksum_mode(&self) -> ChecksumMode {
        self.checksum.mode()
    }

    /// Sets how checksum updates should be handled.
    pub fn set_checksum_mode(&mut self, mode: ChecksumMode) {
        self.checksum.set_mode(mode);
        if self.checksum.automatic() && self.checksum.is_dirty() {
            let _ = self.recompute_checksum();
        }
    }

    /// Enables automatic checksum recomputation.
    pub fn enable_auto_checksum(&mut self) {
        self.set_checksum_mode(ChecksumMode::Automatic);
    }

    /// Disables automatic checksum recomputation.
    pub fn disable_auto_checksum(&mut self) {
        self.set_checksum_mode(ChecksumMode::Manual);
    }

    /// Returns true if the checksum needs to be recomputed.
    pub fn is_checksum_dirty(&self) -> bool {
        self.checksum.is_dirty()
    }

    /// Marks the checksum as dirty and recomputes it when automatic mode is enabled.
    pub fn mark_checksum_dirty(&mut self) {
        self.checksum.mark_dirty();
        if self.checksum.automatic() {
            let _ = self.recompute_checksum();
        }
    }

    /// Sets the pseudo-header context required for checksum calculation.
    pub fn set_checksum_context(&mut self, context: TransportChecksumContext) {
        self.checksum_context = match context {
            TransportChecksumContext::Ipv6 { .. } => Some(context),
            _ => None,
        };

        if self.checksum.automatic() && self.checksum.is_dirty() {
            let _ = self.recompute_checksum();
        }
    }

    /// Configures the pseudo-header context for IPv6 checksums.
    pub fn set_ipv6_checksum_context(&mut self, source: Ipv6Addr, destination: Ipv6Addr) {
        self.set_checksum_context(TransportChecksumContext::ipv6(source, destination));
    }

    /// Clears the configured pseudo-header context.
    pub fn clear_checksum_context(&mut self) {
        self.checksum_context = None;
    }

    /// Returns the configured pseudo-header context.
    pub fn checksum_context(&self) -> Option<TransportChecksumContext> {
        self.checksum_context
    }

    /// Recomputes the checksum using the configured pseudo-header context.
    pub fn recompute_checksum(&mut self) -> Option<u16> {
        let context = match self.checksum_context? {
            TransportChecksumContext::Ipv6 {
                source,
                destination,
            } => (source, destination),
            _ => return None,
        };

        let checksum = crate::util::ipv6_checksum(
            self.raw(),
            1,
            &[],
            &context.0,
            &context.1,
            IpNextProtocol::Icmpv6,
        ) as u16;

        self.write_checksum(checksum);
        self.checksum.clear_dirty();
        Some(checksum)
    }

    /// Returns the ICMPv6 type field.
    pub fn get_type(&self) -> Icmpv6Type {
        Icmpv6Type::new(self.raw()[0])
    }

    /// Sets the ICMPv6 type field and marks the checksum as dirty.
    pub fn set_type(&mut self, icmpv6_type: Icmpv6Type) {
        self.raw_mut()[0] = icmpv6_type.value();
        self.after_field_mutation();
    }

    /// Returns the ICMPv6 code field.
    pub fn get_code(&self) -> Icmpv6Code {
        Icmpv6Code::new(self.raw()[1])
    }

    /// Sets the ICMPv6 code field and marks the checksum as dirty.
    pub fn set_code(&mut self, icmpv6_code: Icmpv6Code) {
        self.raw_mut()[1] = icmpv6_code.value();
        self.after_field_mutation();
    }

    /// Returns the serialized checksum value.
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes([self.raw()[2], self.raw()[3]])
    }

    /// Sets the serialized checksum value and clears the dirty flag.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.write_checksum(checksum);
        self.checksum.clear_dirty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutable_icmpv6_packet_manual_checksum() {
        let mut raw = [
            Icmpv6Type::EchoRequest.value(),
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            b'p',
            b'i',
        ];

        let mut packet = MutableIcmpv6Packet::new(&mut raw).expect("mutable icmpv6");
        let addr = Ipv6Addr::LOCALHOST;
        packet.set_ipv6_checksum_context(addr, addr);
        packet.set_type(Icmpv6Type::EchoReply);

        assert!(packet.is_checksum_dirty());

        let updated = packet.recompute_checksum().expect("checksum");
        assert_eq!(packet.get_checksum(), updated);

        let frozen = packet.freeze().expect("freeze");
        let expected = checksum(&frozen, &addr, &addr);
        assert_eq!(packet.get_checksum(), expected);
    }

    #[test]
    fn test_mutable_icmpv6_packet_auto_checksum() {
        let mut raw = [
            Icmpv6Type::EchoRequest.value(),
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            b'p',
            b'i',
        ];

        let mut packet = MutableIcmpv6Packet::new(&mut raw).expect("mutable icmpv6");
        let addr = Ipv6Addr::LOCALHOST;
        packet.set_ipv6_checksum_context(addr, addr);
        let baseline = packet.recompute_checksum().expect("checksum");

        packet.enable_auto_checksum();
        packet.set_code(Icmpv6Code::new(1));

        assert!(!packet.is_checksum_dirty());

        let frozen = packet.freeze().expect("freeze");
        let expected = checksum(&frozen, &addr, &addr);
        assert_ne!(baseline, expected);
        assert_eq!(packet.get_checksum(), expected);
    }
}

/// Calculates a checksum of an ICMPv6 packet.
pub fn checksum(packet: &Icmpv6Packet, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16 {
    use crate::util;
    util::ipv6_checksum(
        &packet.to_bytes(),
        1, // skip the checksum field
        &[],
        source,
        destination,
        crate::ip::IpNextProtocol::Icmpv6,
    )
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn checksum_echo_request() {
        // The equivalent of your typical ping -6 ::1%lo
        let lo = &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let data = Bytes::from_static(&[
            0x80, // Icmpv6 Type (Echo Request)
            0x00, // Code
            0xff, 0xff, // Checksum
            0x00, 0x00, // Id
            0x00, 0x01, // Sequence
            // 56 bytes of "random" data
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
            0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
            0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
        ]);
        let mut pkg = Icmpv6Packet::from_bytes(data.clone()).unwrap();
        assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::EchoRequest);
        assert_eq!(pkg.header.icmpv6_code, Icmpv6Code::new(0));
        assert_eq!(pkg.header.checksum, 0xffff);
        assert_eq!(pkg.to_bytes(), data);
        assert_eq!(checksum(&pkg, lo, lo), 0x1d2e);

        // Change type to Echo Reply
        pkg.header.icmpv6_type = Icmpv6Type::new(0x81);
        assert_eq!(checksum(&pkg, lo, lo), 0x1c2e);
    }
}

pub mod ndp {
    //! Abstractions for the Neighbor Discovery Protocol [RFC 4861]
    //!
    //! [RFC 4861]: https://tools.ietf.org/html/rfc4861

    use bytes::Bytes;
    use nex_core::bitfield::{self, u24be, u32be};

    use crate::icmpv6::{Icmpv6Code, Icmpv6Header, Icmpv6Packet, Icmpv6Type, ICMPV6_HEADER_LEN};
    use crate::packet::Packet;
    use std::net::Ipv6Addr;

    /// NDP SOL Packet Length.
    pub const NDP_SOL_PACKET_LEN: usize = 24;
    /// NDP ADV Packet Length.
    pub const NDP_ADV_PACKET_LEN: usize = 24;
    /// NDP REDIRECT Packet Length.
    pub const NDP_REDIRECT_PACKET_LEN: usize = 40;
    /// NDP OPT Packet Length.
    pub const NDP_OPT_PACKET_LEN: usize = 2;

    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 Code for the NDP.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents a Neighbor Discovery Option Type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NdpOptionType(pub u8);

    impl NdpOptionType {
        /// Create a new `NdpOptionType` instance.
        pub fn new(value: u8) -> NdpOptionType {
            NdpOptionType(value)
        }
        /// Get the value of the `NdpOptionType`.
        pub fn value(&self) -> u8 {
            self.0
        }
    }

    /// Neighbor Discovery Option Types [RFC 4861 § 4.6]
    ///
    /// [RFC 4861 § 4.6]: https://tools.ietf.org/html/rfc4861#section-4.6
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod NdpOptionTypes {
        use super::NdpOptionType;

        /// Source Link-Layer Address Option [RFC 4861 § 4.6.1]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |    Link-Layer Address ...
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.1]: https://tools.ietf.org/html/rfc4861#section-4.6.1
        pub const SourceLLAddr: NdpOptionType = NdpOptionType(1);

        /// Target Link-Layer Address Option [RFC 4861 § 4.6.1]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |    Link-Layer Address ...
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.1]: https://tools.ietf.org/html/rfc4861#section-4.6.1
        pub const TargetLLAddr: NdpOptionType = NdpOptionType(2);

        /// Prefix Information Option [RFC 4861 § 4.6.2]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                         Valid Lifetime                        |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                       Preferred Lifetime                      |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                           Reserved2                           |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                                                               |
        /// +                                                               +
        /// |                                                               |
        /// +                            Prefix                             +
        /// |                                                               |
        /// +                                                               +
        /// |                                                               |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.2]: https://tools.ietf.org/html/rfc4861#section-4.6.2
        pub const PrefixInformation: NdpOptionType = NdpOptionType(3);

        /// Redirected Header Option [RFC 4861 § 4.6.3]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |            Reserved           |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                           Reserved                            |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                                                               |
        /// ~                       IP header + data                        ~
        /// |                                                               |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.3]: https://tools.ietf.org/html/rfc4861#section-4.6.3
        pub const RedirectedHeader: NdpOptionType = NdpOptionType(4);

        /// MTU Option [RFC 4861 § 4.6.4]
        ///
        /// ```text
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |     Type      |    Length     |           Reserved            |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// |                              MTU                              |
        /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /// ```
        ///
        /// [RFC 4861 § 4.6.4]: https://tools.ietf.org/html/rfc4861#section-4.6.4
        pub const MTU: NdpOptionType = NdpOptionType(5);
    }

    /// Neighbor Discovery Option [RFC 4861 § 4.6]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |    Length     |              ...              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ~                              ...                              ~
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// [RFC 4861 § 4.6]: https://tools.ietf.org/html/rfc4861#section-4.6
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NdpOptionPacket {
        pub option_type: NdpOptionType,
        pub length: u8,
        pub payload: Bytes,
    }

    impl Packet for NdpOptionPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 2 {
                return None;
            }

            let option_type = NdpOptionType::new(bytes[0]);
            let length = bytes[1]; // unit: 8 bytes

            let total_len = (length as usize) * 8;
            if bytes.len() < total_len {
                return None;
            }

            let data_len = total_len - 2;
            let payload = Bytes::copy_from_slice(&bytes[2..2 + data_len]);

            Some(Self {
                option_type,
                length,
                payload,
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_OPT_PACKET_LEN + self.payload.len());
            bytes.push(self.option_type.value());
            bytes.push(self.length);
            bytes.extend_from_slice(&self.payload);
            Bytes::from(bytes)
        }

        fn header(&self) -> Bytes {
            self.to_bytes().slice(..NDP_OPT_PACKET_LEN)
        }

        fn payload(&self) -> Bytes {
            self.payload.clone()
        }

        fn header_len(&self) -> usize {
            NDP_OPT_PACKET_LEN
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl NdpOptionPacket {
        /// Calculate the length of the option's payload.
        pub fn option_payload_length(&self) -> usize {
            //let len = option.get_length();
            let len = self.payload.len();
            if len > 0 {
                ((len * 8) - 2) as usize
            } else {
                0
            }
        }
    }

    /// Calculate a length of a `NdpOption`'s payload.

    /// Router Solicitation Message [RFC 4861 § 4.1]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                            Reserved                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// ```
    ///
    /// [RFC 4861 § 4.1]: https://tools.ietf.org/html/rfc4861#section-4.1
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RouterSolicitPacket {
        pub header: Icmpv6Header,
        pub reserved: u32,
        pub options: Vec<NdpOptionPacket>,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for RouterSolicitPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::RouterSolicitation {
                return Err("Not a Router Solicitation packet");
            }
            if value.payload.len() < 8 {
                return Err("Payload too short for Router Solicitation");
            }
            let reserved = u32::from_be_bytes([
                value.payload[0],
                value.payload[1],
                value.payload[2],
                value.payload[3],
            ]);
            let options = value
                .payload
                .slice(4..)
                .chunks(8)
                .map(|chunk| {
                    let option_type = NdpOptionType::new(chunk[0]);
                    let length = chunk[1];
                    let payload = Bytes::from(chunk[2..].to_vec());
                    NdpOptionPacket {
                        option_type,
                        length,
                        payload,
                    }
                })
                .collect();
            Ok(RouterSolicitPacket {
                header: value.header,
                reserved,
                options,
                payload: Bytes::new(),
            })
        }
    }

    impl Packet for RouterSolicitPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < NDP_SOL_PACKET_LEN {
                return None;
            }

            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let header = Icmpv6Header {
                icmpv6_type,
                icmpv6_code,
                checksum,
            };
            let reserved = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

            let mut options = Vec::new();
            let mut i = 8;
            while i + 2 <= bytes.len() {
                let option_type = NdpOptionType::new(bytes[i]);
                let length = bytes[i + 1];
                let option_len = (length as usize) * 8;

                if i + option_len > bytes.len() {
                    break;
                }

                let payload = Bytes::copy_from_slice(&bytes[i + 2..i + option_len]);
                options.push(NdpOptionPacket {
                    option_type,
                    length,
                    payload,
                });
                i += option_len;
            }

            let payload = Bytes::copy_from_slice(&bytes[i..]);

            Some(RouterSolicitPacket {
                header,
                reserved,
                options,
                payload,
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_SOL_PACKET_LEN);
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.extend_from_slice(&self.reserved.to_be_bytes());
            for option in &self.options {
                bytes.push(option.option_type.value());
                bytes.push(option.length);
                bytes.extend_from_slice(&option.payload);
            }
            Bytes::from(bytes)
        }

        fn header(&self) -> Bytes {
            self.to_bytes().slice(..ICMPV6_HEADER_LEN)
        }

        fn payload(&self) -> Bytes {
            self.payload.clone()
        }

        fn header_len(&self) -> usize {
            ICMPV6_HEADER_LEN + 4 // 4 for reserved
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }
        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl RouterSolicitPacket {
        /// Router Solicit packet calculation for the length of the options.
        pub fn options_length(&self) -> usize {
            if self.to_bytes().len() > 8 {
                self.to_bytes().len() - 8
            } else {
                0
            }
        }
    }

    /// The enumeration of recognized Router Advert flags.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod RouterAdvertFlags {
        /// "Managed Address Configuration" flag. This is set when
        /// addresses are available via DHCPv6.
        pub const ManagedAddressConf: u8 = 0b10000000;
        /// "Other Configuration" flag. This is set when other
        /// configuration information is available via DHCPv6.
        pub const OtherConf: u8 = 0b01000000;
    }

    /// Router Advertisement Message Format [RFC 4861 § 4.2]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Reachable Time                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          Retrans Timer                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RouterAdvertPacket {
        pub header: Icmpv6Header,
        pub hop_limit: u8,
        pub flags: u8,
        pub lifetime: u16,
        pub reachable_time: u32,
        pub retrans_time: u32,
        pub options: Vec<NdpOptionPacket>,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for RouterAdvertPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::RouterAdvertisement {
                return Err("Not a Router Advertisement packet");
            }
            if value.payload.len() < 16 {
                return Err("Payload too short for Router Advertisement");
            }
            let hop_limit = value.payload[0];
            let flags = value.payload[1];
            let lifetime = u16::from_be_bytes([value.payload[2], value.payload[3]]);
            let reachable_time = u32::from_be_bytes([
                value.payload[4],
                value.payload[5],
                value.payload[6],
                value.payload[7],
            ]);
            let retrans_time = u32::from_be_bytes([
                value.payload[8],
                value.payload[9],
                value.payload[10],
                value.payload[11],
            ]);
            let options = value
                .payload
                .slice(12..)
                .chunks(8)
                .map(|chunk| {
                    let option_type = NdpOptionType::new(chunk[0]);
                    let length = chunk[1];
                    let payload = Bytes::from(chunk[2..].to_vec());
                    NdpOptionPacket {
                        option_type,
                        length,
                        payload,
                    }
                })
                .collect();
            Ok(RouterAdvertPacket {
                header: value.header,
                hop_limit,
                flags,
                lifetime,
                reachable_time,
                retrans_time,
                options,
                payload: Bytes::new(),
            })
        }
    }
    impl Packet for RouterAdvertPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < NDP_ADV_PACKET_LEN {
                return None;
            }

            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let header = Icmpv6Header {
                icmpv6_type,
                icmpv6_code,
                checksum,
            };

            let hop_limit = bytes[4];
            let flags = bytes[5];
            let lifetime = u16::from_be_bytes([bytes[6], bytes[7]]);
            let reachable_time = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let retrans_time = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

            let mut options = Vec::new();
            let mut i = 16;
            while i + 2 <= bytes.len() {
                let option_type = NdpOptionType::new(bytes[i]);
                let length = bytes[i + 1];
                let option_len = (length as usize) * 8;

                if i + option_len > bytes.len() {
                    break;
                }

                let payload = Bytes::copy_from_slice(&bytes[i + 2..i + option_len]);
                options.push(NdpOptionPacket {
                    option_type,
                    length,
                    payload,
                });
                i += option_len;
            }

            let payload = Bytes::copy_from_slice(&bytes[i..]);

            Some(RouterAdvertPacket {
                header,
                hop_limit,
                flags,
                lifetime,
                reachable_time,
                retrans_time,
                options,
                payload,
            })
        }

        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_ADV_PACKET_LEN);
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.push(self.hop_limit);
            bytes.push(self.flags);
            bytes.extend_from_slice(&self.lifetime.to_be_bytes());
            bytes.extend_from_slice(&self.reachable_time.to_be_bytes());
            bytes.extend_from_slice(&self.retrans_time.to_be_bytes());
            for option in &self.options {
                bytes.push(option.option_type.value());
                bytes.push(option.length);
                bytes.extend_from_slice(&option.payload);
            }
            Bytes::from(bytes)
        }

        fn header(&self) -> Bytes {
            self.to_bytes().slice(..ICMPV6_HEADER_LEN + 16) // 16 for the fixed part of the Router Advert
        }
        fn payload(&self) -> Bytes {
            self.payload.clone()
        }
        fn header_len(&self) -> usize {
            ICMPV6_HEADER_LEN + 16 // 16 for the fixed part of the Router Advert
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }
        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl RouterAdvertPacket {
        /// Router Advert packet calculation for the length of the options.
        pub fn options_length(&self) -> usize {
            if self.to_bytes().len() > 16 {
                self.to_bytes().len() - 16
            } else {
                0
            }
        }
    }

    /// Neighbor Solicitation Message Format [RFC 4861 § 4.3]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NeighborSolicitPacket {
        pub header: Icmpv6Header,
        pub reserved: u32,
        pub target_addr: Ipv6Addr,
        pub options: Vec<NdpOptionPacket>,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for NeighborSolicitPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::NeighborSolicitation {
                return Err("Not a Neighbor Solicitation packet");
            }
            if value.payload.len() < 24 {
                return Err("Payload too short for Neighbor Solicitation");
            }
            let reserved = u32::from_be_bytes([
                value.payload[0],
                value.payload[1],
                value.payload[2],
                value.payload[3],
            ]);
            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([value.payload[4], value.payload[5]]),
                u16::from_be_bytes([value.payload[6], value.payload[7]]),
                u16::from_be_bytes([value.payload[8], value.payload[9]]),
                u16::from_be_bytes([value.payload[10], value.payload[11]]),
                u16::from_be_bytes([value.payload[12], value.payload[13]]),
                u16::from_be_bytes([value.payload[14], value.payload[15]]),
                u16::from_be_bytes([value.payload[16], value.payload[17]]),
                u16::from_be_bytes([value.payload[18], value.payload[19]]),
            );
            let options = value
                .payload
                .slice(20..)
                .chunks(8)
                .map(|chunk| {
                    let option_type = NdpOptionType::new(chunk[0]);
                    let length = chunk[1];
                    let payload: Bytes = Bytes::from(chunk[2..].to_vec());
                    NdpOptionPacket {
                        option_type,
                        length,
                        payload,
                    }
                })
                .collect();
            Ok(NeighborSolicitPacket {
                header: value.header,
                reserved,
                target_addr,
                options,
                payload: Bytes::new(),
            })
        }
    }

    impl Packet for NeighborSolicitPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 24 {
                return None;
            }

            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let reserved = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
                u16::from_be_bytes([bytes[20], bytes[21]]),
                u16::from_be_bytes([bytes[22], bytes[23]]),
            );

            let mut options = Vec::new();
            let mut i = 24;
            while i + 2 <= bytes.len() {
                let option_type = NdpOptionType::new(bytes[i]);
                let length = bytes[i + 1];
                let option_len = (length as usize) * 8;

                if option_len < 2 || i + option_len > bytes.len() {
                    break;
                }

                let payload = Bytes::copy_from_slice(&bytes[i + 2..i + option_len]);
                options.push(NdpOptionPacket {
                    option_type,
                    length,
                    payload,
                });

                i += option_len;
            }

            let payload = Bytes::copy_from_slice(&bytes[i..]);

            Some(NeighborSolicitPacket {
                header: Icmpv6Header {
                    icmpv6_type,
                    icmpv6_code,
                    checksum,
                },
                reserved,
                target_addr,
                options,
                payload,
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_SOL_PACKET_LEN);
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.extend_from_slice(&self.reserved.to_be_bytes());
            for (_, segment) in self.target_addr.segments().iter().enumerate() {
                bytes.extend_from_slice(&segment.to_be_bytes());
            }
            for option in &self.options {
                bytes.push(option.option_type.value());
                bytes.push(option.length);
                bytes.extend_from_slice(&option.payload);
            }
            Bytes::from(bytes)
        }
        fn header(&self) -> Bytes {
            self.to_bytes().slice(..ICMPV6_HEADER_LEN + 24) // 24 for the fixed part of the Neighbor Solicit
        }
        fn payload(&self) -> Bytes {
            self.payload.clone()
        }
        fn header_len(&self) -> usize {
            ICMPV6_HEADER_LEN + 24 // 24 for the fixed part of the Neighbor Solicit
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl NeighborSolicitPacket {
        /// Neighbor Solicit packet calculation for the length of the options.
        pub fn options_length(&self) -> usize {
            // Calculate the length of the options in the Neighbor Solicitation packet.
            if self.to_bytes().len() > 24 {
                self.to_bytes().len() - 24
            } else {
                0
            }
        }
    }

    /// Enumeration of recognized Neighbor Advert flags.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod NeighborAdvertFlags {
        /// Indicates that the sender is a router.
        pub const Router: u8 = 0b10000000;
        /// Indicates that the advertisement was sent due to the receipt of a
        /// Neighbor Solicitation message.
        pub const Solicited: u8 = 0b01000000;
        /// Indicates that the advertisement should override an existing cache
        /// entry.
        pub const Override: u8 = 0b00100000;
    }

    /// Neighbor Advertisement Message Format [RFC 4861 § 4.4]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |R|S|O|                     Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.4]: https://tools.ietf.org/html/rfc4861#section-4.4
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NeighborAdvertPacket {
        pub header: Icmpv6Header,
        pub flags: u8,
        pub reserved: u24be,
        pub target_addr: Ipv6Addr,
        pub options: Vec<NdpOptionPacket>,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for NeighborAdvertPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::NeighborAdvertisement {
                return Err("Not a Neighbor Advert packet");
            }
            // The fixed part of a Neighbor Advertisement message is 20 bytes:
            // 1 byte for flags, 3 bytes reserved, and 16 bytes for the target address.
            // See RFC 4861 Section 4.4.
            // Some packets may not include any options, so 20 bytes is the minimum length.
            if value.payload.len() < 20 {
                return Err("Payload too short for Neighbor Advert");
            }
            let flags = value.payload[0];
            let reserved = bitfield::utils::u24be_from_bytes([
                value.payload[1],
                value.payload[2],
                value.payload[3],
            ]);
            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([value.payload[4], value.payload[5]]),
                u16::from_be_bytes([value.payload[6], value.payload[7]]),
                u16::from_be_bytes([value.payload[8], value.payload[9]]),
                u16::from_be_bytes([value.payload[10], value.payload[11]]),
                u16::from_be_bytes([value.payload[12], value.payload[13]]),
                u16::from_be_bytes([value.payload[14], value.payload[15]]),
                u16::from_be_bytes([value.payload[16], value.payload[17]]),
                u16::from_be_bytes([value.payload[18], value.payload[19]]),
            );
            let options = value
                .payload
                .slice(20..)
                .chunks(8)
                .map(|chunk| {
                    let option_type = NdpOptionType::new(chunk[0]);
                    let length = chunk[1];
                    let payload = Bytes::from(chunk[2..].to_vec());
                    NdpOptionPacket {
                        option_type,
                        length,
                        payload,
                    }
                })
                .collect();
            Ok(NeighborAdvertPacket {
                header: value.header,
                flags,
                reserved,
                target_addr,
                options,
                payload: Bytes::new(),
            })
        }
    }

    impl Packet for NeighborAdvertPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 24 {
                return None;
            }

            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let header = Icmpv6Header {
                icmpv6_type,
                icmpv6_code,
                checksum,
            };

            let flags = bytes[4];
            let reserved = bitfield::utils::u24be_from_bytes([bytes[5], bytes[6], bytes[7]]);

            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
                u16::from_be_bytes([bytes[20], bytes[21]]),
                u16::from_be_bytes([bytes[22], bytes[23]]),
            );

            let mut options = Vec::new();
            let mut i = 24;
            while i + 2 <= bytes.len() {
                let option_type = NdpOptionType::new(bytes[i]);
                let length = bytes[i + 1];
                let option_len = (length as usize) * 8;

                if option_len < 2 || i + option_len > bytes.len() {
                    break;
                }

                let payload = Bytes::copy_from_slice(&bytes[i + 2..i + option_len]);
                options.push(NdpOptionPacket {
                    option_type,
                    length,
                    payload,
                });

                i += option_len;
            }

            let payload = Bytes::copy_from_slice(&bytes[i..]);

            Some(NeighborAdvertPacket {
                header,
                flags,
                reserved,
                target_addr,
                options,
                payload,
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_ADV_PACKET_LEN);
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());

            // Combine flags and reserved (flags in the most significant 8 bits)
            let flags_reserved = (self.flags as u32) << 24 | (self.reserved & 0x00FF_FFFF);
            bytes.extend_from_slice(&flags_reserved.to_be_bytes());

            for segment in self.target_addr.segments().iter() {
                bytes.extend_from_slice(&segment.to_be_bytes());
            }

            for option in &self.options {
                bytes.push(option.option_type.value());
                bytes.push(option.length);
                bytes.extend_from_slice(&option.payload);
            }

            Bytes::from(bytes)
        }
        fn header(&self) -> Bytes {
            self.to_bytes().slice(..ICMPV6_HEADER_LEN + 24) // 24 for the fixed part of the Neighbor Advert
        }
        fn payload(&self) -> Bytes {
            self.payload.clone()
        }
        fn header_len(&self) -> usize {
            ICMPV6_HEADER_LEN + 24 // 24 for the fixed part of the Neighbor Advert
        }
        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl NeighborAdvertPacket {
        /// Neighbor Advert packet calculation for the length of the options.
        pub fn options_length(&self) -> usize {
            // Calculate the length of the options in the Neighbor Advert packet.
            if self.to_bytes().len() > 24 {
                self.to_bytes().len() - 24
            } else {
                0
            }
        }
    }

    /// Redirect Message Format [RFC 4861 § 4.5]
    ///
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Type      |     Code      |          Checksum             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Reserved                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                       Target Address                          +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                     Destination Address                       +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Options ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-
    /// ```
    ///
    /// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RedirectPacket {
        pub header: Icmpv6Header,
        pub reserved: u32be,
        pub target_addr: Ipv6Addr,
        pub dest_addr: Ipv6Addr,
        pub options: Vec<NdpOptionPacket>,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for RedirectPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::RedirectMessage {
                return Err("Not a Redirect packet");
            }
            if value.payload.len() < 40 {
                return Err("Payload too short for Redirect");
            }
            let reserved = u32be::from_be_bytes([
                value.payload[0],
                value.payload[1],
                value.payload[2],
                value.payload[3],
            ]);
            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([value.payload[4], value.payload[5]]),
                u16::from_be_bytes([value.payload[6], value.payload[7]]),
                u16::from_be_bytes([value.payload[8], value.payload[9]]),
                u16::from_be_bytes([value.payload[10], value.payload[11]]),
                u16::from_be_bytes([value.payload[12], value.payload[13]]),
                u16::from_be_bytes([value.payload[14], value.payload[15]]),
                u16::from_be_bytes([value.payload[16], value.payload[17]]),
                u16::from_be_bytes([value.payload[18], value.payload[19]]),
            );
            let dest_addr = Ipv6Addr::new(
                u16::from_be_bytes([value.payload[20], value.payload[21]]),
                u16::from_be_bytes([value.payload[22], value.payload[23]]),
                u16::from_be_bytes([value.payload[24], value.payload[25]]),
                u16::from_be_bytes([value.payload[26], value.payload[27]]),
                u16::from_be_bytes([value.payload[28], value.payload[29]]),
                u16::from_be_bytes([value.payload[30], value.payload[31]]),
                u16::from_be_bytes([value.payload[32], value.payload[33]]),
                u16::from_be_bytes([value.payload[34], value.payload[35]]),
            );
            let options = value
                .payload
                .slice(36..)
                .chunks(8)
                .map(|chunk| {
                    let option_type = NdpOptionType::new(chunk[0]);
                    let length = chunk[1];
                    let payload = Bytes::from(chunk[2..].to_vec());
                    NdpOptionPacket {
                        option_type,
                        length,
                        payload,
                    }
                })
                .collect();
            Ok(RedirectPacket {
                header: value.header,
                reserved,
                target_addr,
                dest_addr,
                options,
                payload: Bytes::new(),
            })
        }
    }

    impl Packet for RedirectPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 40 {
                return None;
            }

            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let header = Icmpv6Header {
                icmpv6_type,
                icmpv6_code,
                checksum,
            };

            let reserved = u32be::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

            let target_addr = Ipv6Addr::new(
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
                u16::from_be_bytes([bytes[16], bytes[17]]),
                u16::from_be_bytes([bytes[18], bytes[19]]),
                u16::from_be_bytes([bytes[20], bytes[21]]),
                u16::from_be_bytes([bytes[22], bytes[23]]),
            );

            let dest_addr = Ipv6Addr::new(
                u16::from_be_bytes([bytes[24], bytes[25]]),
                u16::from_be_bytes([bytes[26], bytes[27]]),
                u16::from_be_bytes([bytes[28], bytes[29]]),
                u16::from_be_bytes([bytes[30], bytes[31]]),
                u16::from_be_bytes([bytes[32], bytes[33]]),
                u16::from_be_bytes([bytes[34], bytes[35]]),
                u16::from_be_bytes([bytes[36], bytes[37]]),
                u16::from_be_bytes([bytes[38], bytes[39]]),
            );

            let mut options = Vec::new();
            let mut i = 40;
            while i + 2 <= bytes.len() {
                let option_type = NdpOptionType::new(bytes[i]);
                let length = bytes[i + 1];
                let option_len = (length as usize) * 8;

                if option_len < 2 || i + option_len > bytes.len() {
                    break;
                }

                let payload = Bytes::copy_from_slice(&bytes[i + 2..i + option_len]);
                options.push(NdpOptionPacket {
                    option_type,
                    length,
                    payload,
                });

                i += option_len;
            }

            let payload = Bytes::copy_from_slice(&bytes[i..]);

            Some(RedirectPacket {
                header,
                reserved,
                target_addr,
                dest_addr,
                options,
                payload,
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }
        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(NDP_REDIRECT_PACKET_LEN);
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.extend_from_slice(&self.reserved.to_be_bytes());
            for (_, segment) in self.target_addr.segments().iter().enumerate() {
                bytes.extend_from_slice(&segment.to_be_bytes());
            }
            for (_, segment) in self.dest_addr.segments().iter().enumerate() {
                bytes.extend_from_slice(&segment.to_be_bytes());
            }
            for option in &self.options {
                bytes.push(option.option_type.value());
                bytes.push(option.length);
                bytes.extend_from_slice(&option.payload);
            }
            Bytes::from(bytes)
        }
        fn header(&self) -> Bytes {
            self.to_bytes().slice(..ICMPV6_HEADER_LEN + 40) // 40 for the fixed part of the Redirect
        }
        fn payload(&self) -> Bytes {
            self.payload.clone()
        }
        fn header_len(&self) -> usize {
            ICMPV6_HEADER_LEN + 40 // 40 for the fixed part of the Redirect
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }

    impl RedirectPacket {
        /// Redirect packet calculation for the length of the options.
        pub fn options_length(&self) -> usize {
            // Calculate the length of the options in the Redirect packet.
            if self.to_bytes().len() > 40 {
                self.to_bytes().len() - 40
            } else {
                0
            }
        }
    }

    #[cfg(test)]
    mod ndp_tests {
        use super::*;
        use crate::icmpv6::{Icmpv6Code, Icmpv6Type};

        #[test]
        fn basic_option_parsing() {
            let data = Bytes::from_static(&[
                0x02, 0x01, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                // Extra bytes to confuse the parsing
                0x00, 0x00, 0x00,
            ]);
            let pkg = NdpOptionPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.option_type, NdpOptionTypes::TargetLLAddr);
            assert_eq!(pkg.length, 0x01);
            assert_eq!(pkg.payload.len(), 6);
            assert_eq!(pkg.payload.as_ref(), &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        }

        #[test]
        fn basic_rs_parse() {
            let data = Bytes::from_static(&[
                0x85, // Type
                0x00, // Code
                0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x00, // Reserved
                0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]);

            let pkg = RouterSolicitPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::RouterSolicitation);
            assert_eq!(pkg.header.icmpv6_code, Icmpv6Code(0));
            assert_eq!(pkg.header.checksum, 0);
            assert_eq!(pkg.reserved, 0);
            assert_eq!(pkg.options.len(), 2);

            let option = &pkg.options[0];
            assert_eq!(option.option_type, NdpOptionTypes::TargetLLAddr);
            assert_eq!(option.length, 0x01);
            assert_eq!(
                option.payload.as_ref(),
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            );
            assert_eq!(option.payload.len(), 6);

            let option = &pkg.options[1];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(
                option.payload.as_ref(),
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            );
        }

        #[test]
        fn basic_rs_create() {
            use crate::icmpv6::ndp::{NdpOptionPacket, RouterSolicitPacket};

            let options = vec![NdpOptionPacket {
                option_type: NdpOptionTypes::SourceLLAddr,
                length: 1,
                payload: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            }];

            let packet = RouterSolicitPacket {
                header: Icmpv6Header {
                    icmpv6_type: Icmpv6Type::RouterSolicitation,
                    icmpv6_code: Icmpv6Code(0),
                    checksum: 0,
                },
                reserved: 0,
                options,
                payload: Bytes::new(),
            };

            let bytes = packet.to_bytes();

            let expected = Bytes::from_static(&[
                0x85, 0x00, 0x00, 0x00, // Type, Code, Checksum
                0x00, 0x00, 0x00, 0x00, // Reserved
                0x01, 0x01, // Option Type, Length
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Option Data
            ]);

            assert_eq!(bytes, expected);
        }

        #[test]
        fn basic_ra_parse() {
            let data = Bytes::from_static(&[
                0x86, // Type
                0x00, // Code
                0x00, 0x00, // Checksum
                0xff, // Hop Limit
                0x80, // Flags
                0x09, 0x00, // Lifetime
                0x12, 0x34, 0x56, 0x78, // Reachable
                0x87, 0x65, 0x43, 0x21, // Retrans
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Link-Layer
                0x05, 0x01, 0x00, 0x00, 0x57, 0x68, 0x61, 0x74, // MTU
            ]);
            let pkg = RouterAdvertPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::RouterAdvertisement);
            assert_eq!(pkg.header.icmpv6_code, Icmpv6Code(0));
            assert_eq!(pkg.header.checksum, 0x00);
            assert_eq!(pkg.hop_limit, 0xff);
            assert_eq!(pkg.flags, RouterAdvertFlags::ManagedAddressConf);
            assert_eq!(pkg.lifetime, 0x900);
            assert_eq!(pkg.reachable_time, 0x12345678);
            assert_eq!(pkg.retrans_time, 0x87654321);
            assert_eq!(pkg.options.len(), 2);

            let option = &pkg.options[0];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(
                option.payload.as_ref(),
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            );

            let option = &pkg.options[1];
            assert_eq!(option.option_type, NdpOptionTypes::MTU);
            assert_eq!(option.length, 1);
            assert_eq!(
                option.payload.as_ref(),
                &[0x00, 0x00, 0x57, 0x68, 0x61, 0x74]
            );
        }

        #[test]
        fn basic_ra_create() {
            use crate::icmpv6::ndp::{NdpOptionPacket, RouterAdvertFlags, RouterAdvertPacket};

            let options = vec![NdpOptionPacket {
                option_type: NdpOptionTypes::MTU,
                length: 1,
                payload: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            }];

            let packet = RouterAdvertPacket {
                header: Icmpv6Header {
                    icmpv6_type: Icmpv6Type::RouterAdvertisement,
                    icmpv6_code: Icmpv6Code(0),
                    checksum: 0,
                },
                hop_limit: 0xff,
                flags: RouterAdvertFlags::ManagedAddressConf,
                lifetime: 0,
                reachable_time: 0,
                retrans_time: 0,
                options,
                payload: Bytes::new(),
            };

            let bytes = packet.to_bytes();
            let expected = Bytes::from_static(&[
                0x86, 0x00, 0x00, 0x00, // header
                0xff, 0x80, 0x00, 0x00, // hop limit, flags, lifetime
                0x00, 0x00, 0x00, 0x00, // reachable
                0x00, 0x00, 0x00, 0x00, // retrans
                0x05, 0x01, // option type + len
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // option data
            ]);

            assert_eq!(bytes, expected);
        }

        #[test]
        fn basic_ns_parse() {
            let data = Bytes::from_static(&[
                0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]);
            let pkg = NeighborSolicitPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::NeighborSolicitation);
            assert_eq!(pkg.header.icmpv6_code, Icmpv6Code(0));
            assert_eq!(pkg.header.checksum, 0x00);
            assert_eq!(pkg.reserved, 0x00);
            assert_eq!(pkg.target_addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        }

        #[test]
        fn basic_ns_create() {
            use crate::icmpv6::ndp::NeighborSolicitPacket;

            let packet = NeighborSolicitPacket {
                header: Icmpv6Header {
                    icmpv6_type: Icmpv6Type::NeighborSolicitation,
                    icmpv6_code: Icmpv6Code(0),
                    checksum: 0,
                },
                reserved: 0,
                target_addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                options: vec![],
                payload: Bytes::new(),
            };

            let bytes = packet.to_bytes();

            let expected = Bytes::from_static(&[
                0x87, 0x00, 0x00, 0x00, // header
                0x00, 0x00, 0x00, 0x00, // reserved
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, // target
            ]);

            assert_eq!(bytes, expected);
        }

        #[test]
        fn basic_na_parse() {
            let data = Bytes::from_static(&[
                0x88, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]);
            let pkg = NeighborAdvertPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::NeighborAdvertisement);
            assert_eq!(pkg.header.icmpv6_code, Icmpv6Code(0));
            assert_eq!(pkg.header.checksum, 0x00);
            assert_eq!(pkg.reserved, 0x00);
            assert_eq!(pkg.flags, 0x80);
            assert_eq!(pkg.target_addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        }

        #[test]
        fn basic_na_create() {
            use crate::icmpv6::ndp::{NeighborAdvertFlags, NeighborAdvertPacket};

            let packet = NeighborAdvertPacket {
                header: Icmpv6Header {
                    icmpv6_type: Icmpv6Type::NeighborAdvertisement,
                    icmpv6_code: Icmpv6Code(0),
                    checksum: 0,
                },
                flags: NeighborAdvertFlags::Router,
                reserved: 0,
                target_addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                options: vec![],
                payload: Bytes::new(),
            };

            let bytes = packet.to_bytes();

            let expected = Bytes::from_static(&[
                0x88, 0x00, 0x00, 0x00, // header
                0x80, 0x00, 0x00, 0x00, // flags + reserved
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]);

            assert_eq!(bytes, expected);
        }

        #[test]
        fn basic_redirect_parse() {
            let data = Bytes::from_static(&[
                0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            let pkg = RedirectPacket::from_bytes(data).unwrap();
            assert_eq!(pkg.header.icmpv6_type, Icmpv6Type::RedirectMessage);
            assert_eq!(pkg.header.icmpv6_code, Icmpv6Code(0));
            assert_eq!(pkg.header.checksum, 0x00);
            assert_eq!(pkg.reserved, 0x00);
            assert_eq!(pkg.target_addr, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            assert_eq!(pkg.dest_addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        }

        #[test]
        fn basic_redirect_create() {
            use crate::icmpv6::ndp::RedirectPacket;

            let packet = RedirectPacket {
                header: Icmpv6Header {
                    icmpv6_type: Icmpv6Type::RedirectMessage,
                    icmpv6_code: Icmpv6Code(0),
                    checksum: 0,
                },
                reserved: 0,
                target_addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                dest_addr: Ipv6Addr::UNSPECIFIED,
                options: vec![],
                payload: Bytes::new(),
            };

            let bytes = packet.to_bytes();

            let expected = Bytes::from_static(&[
                0x89, 0x00, 0x00, 0x00, // header
                0x00, 0x00, 0x00, 0x00, // reserved
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, // target
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, // dest
            ]);

            assert_eq!(bytes, expected);
        }
    }
}

pub mod echo_request {
    //! abstraction for "echo request" ICMPv6 packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |           Identifier          |        Sequence Number        |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Data ...
    //! +-+-+-+-+-
    //! ```

    use bytes::Bytes;

    use crate::{
        icmpv6::{Icmpv6Code, Icmpv6Header, Icmpv6Packet, Icmpv6Type},
        packet::Packet,
    };

    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
        /// Get the value of the identifier.
        pub fn value(&self) -> u16 {
            self.0
        }
    }

    /// Represents the sequence number field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a new `SequenceNumber` instance.
        pub fn new(val: u16) -> SequenceNumber {
            SequenceNumber(val)
        }
        /// Get the value of the sequence number.
        pub fn value(&self) -> u16 {
            self.0
        }
    }

    /// Enumeration of available ICMPv6 codes for "echo reply" ICMPv6 packets. There is actually only
    /// one, since the only valid ICMPv6 code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 code for "echo reply" ICMPv6 packets.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents an "echo request" ICMPv6 packet.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EchoRequestPacket {
        pub header: Icmpv6Header,
        pub identifier: u16,
        pub sequence_number: u16,
        pub payload: Bytes,
    }

    impl TryFrom<Icmpv6Packet> for EchoRequestPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::EchoRequest {
                return Err("Not an Echo Request packet");
            }
            if value.payload.len() < 8 {
                return Err("Payload too short for Echo Request");
            }
            let identifier = u16::from_be_bytes([value.payload[0], value.payload[1]]);
            let sequence_number = u16::from_be_bytes([value.payload[2], value.payload[3]]);
            Ok(EchoRequestPacket {
                header: value.header,
                identifier,
                sequence_number,
                payload: value.payload.slice(4..),
            })
        }
    }

    impl Packet for EchoRequestPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 8 {
                return None;
            }
            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
            let sequence_number = u16::from_be_bytes([bytes[6], bytes[7]]);
            Some(EchoRequestPacket {
                header: Icmpv6Header {
                    icmpv6_type,
                    icmpv6_code,
                    checksum,
                },
                identifier,
                sequence_number,
                payload: Bytes::copy_from_slice(&bytes[8..]),
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(8 + self.payload.len());
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.extend_from_slice(&self.identifier.to_be_bytes());
            bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
            bytes.extend_from_slice(&self.payload);
            Bytes::from(bytes)
        }

        fn header(&self) -> Bytes {
            self.to_bytes().slice(..8)
        }

        fn payload(&self) -> Bytes {
            self.payload.clone()
        }

        fn header_len(&self) -> usize {
            8 // Header length for echo request
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }
}

pub mod echo_reply {
    //! abstraction for "echo reply" ICMPv6 packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |           Identifier          |        Sequence Number        |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Data ...
    //! +-+-+-+-+-
    //! ```

    use bytes::Bytes;

    use crate::{
        icmpv6::{Icmpv6Code, Icmpv6Header, Icmpv6Packet, Icmpv6Type},
        packet::Packet,
    };
    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
        /// Get the value of the identifier.
        pub fn value(&self) -> u16 {
            self.0
        }
    }

    /// Represents the sequence number field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SequenceNumber(pub u16);

    impl SequenceNumber {
        /// Create a new `SequenceNumber` instance.
        pub fn new(val: u16) -> SequenceNumber {
            SequenceNumber(val)
        }
        /// Get the value of the sequence number.
        pub fn value(&self) -> u16 {
            self.0
        }
    }

    /// Enumeration of available ICMPv6 codes for "echo reply" ICMPv6 packets. There is actually only
    /// one, since the only valid ICMPv6 code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Icmpv6Codes {
        use crate::icmpv6::Icmpv6Code;
        /// 0 is the only available ICMPv6 code for "echo reply" ICMPv6 packets.
        pub const NoCode: Icmpv6Code = Icmpv6Code(0);
    }

    /// Represents an "echo reply" ICMPv6 packet.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EchoReplyPacket {
        pub header: Icmpv6Header,
        pub identifier: u16,
        pub sequence_number: u16,
        pub payload: Bytes,
    }
    impl TryFrom<Icmpv6Packet> for EchoReplyPacket {
        type Error = &'static str;

        fn try_from(value: Icmpv6Packet) -> Result<Self, Self::Error> {
            if value.header.icmpv6_type != Icmpv6Type::EchoReply {
                return Err("Not an Echo Reply packet");
            }
            if value.payload.len() < 8 {
                return Err("Payload too short for Echo Reply");
            }
            let identifier = u16::from_be_bytes([value.payload[0], value.payload[1]]);
            let sequence_number = u16::from_be_bytes([value.payload[2], value.payload[3]]);
            Ok(EchoReplyPacket {
                header: value.header,
                identifier,
                sequence_number,
                payload: value.payload.slice(4..),
            })
        }
    }
    impl Packet for EchoReplyPacket {
        type Header = ();
        fn from_buf(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 8 {
                return None;
            }
            let icmpv6_type = Icmpv6Type::new(bytes[0]);
            let icmpv6_code = Icmpv6Code::new(bytes[1]);
            let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
            let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
            let sequence_number = u16::from_be_bytes([bytes[6], bytes[7]]);
            Some(EchoReplyPacket {
                header: Icmpv6Header {
                    icmpv6_type,
                    icmpv6_code,
                    checksum,
                },
                identifier,
                sequence_number,
                payload: Bytes::copy_from_slice(&bytes[8..]),
            })
        }
        fn from_bytes(bytes: Bytes) -> Option<Self> {
            Self::from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            let mut bytes = Vec::with_capacity(8 + self.payload.len());
            bytes.push(self.header.icmpv6_type.value());
            bytes.push(self.header.icmpv6_code.value());
            bytes.extend_from_slice(&self.header.checksum.to_be_bytes());
            bytes.extend_from_slice(&self.identifier.to_be_bytes());
            bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
            bytes.extend_from_slice(&self.payload);
            Bytes::from(bytes)
        }

        fn header(&self) -> Bytes {
            self.to_bytes().slice(..8)
        }

        fn payload(&self) -> Bytes {
            self.payload.clone()
        }

        fn header_len(&self) -> usize {
            8 // Header length for echo reply
        }

        fn payload_len(&self) -> usize {
            self.payload.len()
        }

        fn total_len(&self) -> usize {
            self.header_len() + self.payload_len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.payload)
        }
    }
}

#[cfg(test)]
mod echo_tests {
    use super::*;
    use crate::icmpv6::{
        echo_reply::EchoReplyPacket, echo_request::EchoRequestPacket, Icmpv6Code, Icmpv6Type,
    };

    #[test]
    fn test_echo_request_parse() {
        let raw = Bytes::from_static(&[
            0x80, 0x00, 0xbe, 0xef, // header: type, code, checksum
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence number
            b'p', b'i', b'n', b'g', b'!',
        ]);

        let parsed = EchoRequestPacket::from_bytes(raw.clone())
            .expect("Failed to parse Echo Request packet");

        assert_eq!(parsed.header.icmpv6_type, Icmpv6Type::EchoRequest);
        assert_eq!(parsed.header.icmpv6_code, Icmpv6Code(0));
        assert_eq!(parsed.header.checksum, 0xbeef);
        assert_eq!(parsed.identifier, 0x1234);
        assert_eq!(parsed.sequence_number, 0x5678);
        assert_eq!(parsed.payload, Bytes::from_static(b"ping!"));
    }

    #[test]
    fn test_echo_request_create() {
        let payload = Bytes::from_static(b"hello");
        let packet = EchoRequestPacket {
            header: Icmpv6Header {
                icmpv6_type: Icmpv6Type::EchoRequest,
                icmpv6_code: Icmpv6Code(0),
                checksum: 0,
            },
            identifier: 0x1234,
            sequence_number: 0x5678,
            payload: payload.clone(),
        };
        let bytes = packet.to_bytes();
        let parsed = EchoRequestPacket::from_bytes(bytes).unwrap();

        assert_eq!(parsed.identifier, 0x1234);
        assert_eq!(parsed.sequence_number, 0x5678);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_echo_reply_parse() {
        let raw = Bytes::from_static(&[
            0x81, 0x00, 0x12, 0x34, // header: type, code, checksum
            0xab, 0xcd, // identifier
            0x56, 0x78, // sequence number
            b'h', b'e', b'l', b'l', b'o',
        ]);

        let parsed =
            EchoReplyPacket::from_bytes(raw.clone()).expect("Failed to parse Echo Reply packet");

        assert_eq!(parsed.header.icmpv6_type, Icmpv6Type::EchoReply);
        assert_eq!(parsed.header.icmpv6_code, Icmpv6Code(0));
        assert_eq!(parsed.header.checksum, 0x1234);
        assert_eq!(parsed.identifier, 0xabcd);
        assert_eq!(parsed.sequence_number, 0x5678);
        assert_eq!(parsed.payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn test_echo_reply_create() {
        let payload = Bytes::from_static(b"world");
        let packet = EchoReplyPacket {
            header: Icmpv6Header {
                icmpv6_type: Icmpv6Type::EchoReply,
                icmpv6_code: Icmpv6Code(0),
                checksum: 0,
            },
            identifier: 0xabcd,
            sequence_number: 0x1234,
            payload: payload.clone(),
        };

        let bytes = packet.to_bytes();
        let parsed = EchoReplyPacket::from_bytes(bytes).expect("Failed to parse Echo Reply packet");

        assert_eq!(parsed.header.icmpv6_type, Icmpv6Type::EchoReply);
        assert_eq!(parsed.identifier, 0xabcd);
        assert_eq!(parsed.sequence_number, 0x1234);
        assert_eq!(parsed.payload, payload);
    }
}
