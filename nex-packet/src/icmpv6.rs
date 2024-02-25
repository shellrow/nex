//! An ICMPv6 packet abstraction.

use crate::ip::IpNextLevelProtocol;
use crate::PrimitiveValues;

use alloc::vec::Vec;

use crate::ethernet::ETHERNET_HEADER_LEN;
use crate::ipv6::IPV6_HEADER_LEN;
use nex_macro::packet;
use nex_macro_helper::types::*;
use std::net::Ipv6Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ICMPv6 Header Length.
pub const ICMPV6_HEADER_LEN: usize = echo_request::MutableEchoRequestPacket::minimum_packet_size();
/// ICMPv6 Minimum Packet Length.
pub const ICMPV6_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;
/// ICMPv6 IP Packet Length.
pub const ICMPV6_IP_PACKET_LEN: usize = IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;

/// Represents the ICMPv6 header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Icmpv6Header {
    pub icmpv6_type: Icmpv6Type,
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16be,
}

impl Icmpv6Header {
    /// Construct an ICMPv6 header from a byte slice.
    pub fn from_bytes(packet: &[u8]) -> Result<Icmpv6Header, String> {
        if packet.len() < ICMPV6_HEADER_LEN {
            return Err("Packet is too small for ICMPv6 header".to_string());
        }
        match Icmpv6Packet::new(packet) {
            Some(icmpv6_packet) => Ok(Icmpv6Header {
                icmpv6_type: icmpv6_packet.get_icmpv6_type(),
                icmpv6_code: icmpv6_packet.get_icmpv6_code(),
                checksum: icmpv6_packet.get_checksum(),
            }),
            None => Err("Failed to parse ICMPv6 packet".to_string()),
        }
    }
    /// Construct an ICMPv6 header from a Icmpv6Packet.
    pub(crate) fn from_packet(icmpv6_packet: &Icmpv6Packet) -> Icmpv6Header {
        Icmpv6Header {
            icmpv6_type: icmpv6_packet.get_icmpv6_type(),
            icmpv6_code: icmpv6_packet.get_icmpv6_code(),
            checksum: icmpv6_packet.get_checksum(),
        }
    }
}

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
}

impl PrimitiveValues for Icmpv6Type {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match *self {
            Icmpv6Type::DestinationUnreachable => (1,),
            Icmpv6Type::PacketTooBig => (2,),
            Icmpv6Type::TimeExceeded => (3,),
            Icmpv6Type::ParameterProblem => (4,),
            Icmpv6Type::EchoRequest => (128,),
            Icmpv6Type::EchoReply => (129,),
            Icmpv6Type::MulticastListenerQuery => (130,),
            Icmpv6Type::MulticastListenerReport => (131,),
            Icmpv6Type::MulticastListenerDone => (132,),
            Icmpv6Type::RouterSolicitation => (133,),
            Icmpv6Type::RouterAdvertisement => (134,),
            Icmpv6Type::NeighborSolicitation => (135,),
            Icmpv6Type::NeighborAdvertisement => (136,),
            Icmpv6Type::RedirectMessage => (137,),
            Icmpv6Type::RouterRenumbering => (138,),
            Icmpv6Type::NodeInformationQuery => (139,),
            Icmpv6Type::NodeInformationResponse => (140,),
            Icmpv6Type::InverseNeighborDiscoverySolicitation => (141,),
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => (142,),
            Icmpv6Type::Version2MulticastListenerReport => (143,),
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => (144,),
            Icmpv6Type::HomeAgentAddressDiscoveryReply => (145,),
            Icmpv6Type::MobilePrefixSolicitation => (146,),
            Icmpv6Type::MobilePrefixAdvertisement => (147,),
            Icmpv6Type::CertificationPathSolicitationMessage => (148,),
            Icmpv6Type::CertificationPathAdvertisementMessage => (149,),
            Icmpv6Type::ExperimentalMobilityProtocols => (150,),
            Icmpv6Type::MulticastRouterAdvertisement => (151,),
            Icmpv6Type::MulticastRouterSolicitation => (152,),
            Icmpv6Type::MulticastRouterTermination => (153,),
            Icmpv6Type::FMIPv6Messages => (154,),
            Icmpv6Type::RPLControlMessage => (155,),
            Icmpv6Type::ILNPv6LocatorUpdateMessage => (156,),
            Icmpv6Type::DuplicateAddressRequest => (157,),
            Icmpv6Type::DuplicateAddressConfirmation => (158,),
            Icmpv6Type::MPLControlMessage => (159,),
            Icmpv6Type::ExtendedEchoRequest => (160,),
            Icmpv6Type::ExtendedEchoReply => (161,),
            Icmpv6Type::Unknown(n) => (n,),
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
}

impl PrimitiveValues for Icmpv6Code {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents a generic ICMPv6 packet [RFC 4443 § 2.1]
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                         Message Body                          +
/// |                                                               |
/// ```
///
/// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
#[packet]
pub struct Icmpv6 {
    #[construct_with(u8)]
    pub icmpv6_type: Icmpv6Type,
    #[construct_with(u8)]
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16be,
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an ICMPv6 packet.
pub fn checksum(packet: &Icmpv6Packet, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16be {
    use crate::util;
    use crate::Packet;

    util::ipv6_checksum(
        packet.packet(),
        1,
        &[],
        source,
        destination,
        IpNextLevelProtocol::Icmpv6,
    )
}

#[cfg(test)]
mod checksum_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn checksum_echo_request() {
        // The equivalent of your typical ping -6 ::1%lo
        let lo = &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut data = vec![
            0x80, // Icmpv6 Type
            0x00, // Code
            0xff, 0xff, // Checksum
            0x00, 0x00, // Id
            0x00, 0x01, // Sequence
            // 56 bytes of "random" data
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
            0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
            0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
        ];
        let mut pkg = MutableIcmpv6Packet::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable(), lo, lo), 0x1d2e);

        // Check
        pkg.set_icmpv6_type(Icmpv6Type::new(0x81));
        assert_eq!(checksum(&pkg.to_immutable(), lo, lo), 0x1c2e);
    }
}

pub mod ndp {
    //! Abstractions for the Neighbor Discovery Protocol [RFC 4861]
    //!
    //! [RFC 4861]: https://tools.ietf.org/html/rfc4861

    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
    use crate::Packet;
    use crate::PrimitiveValues;

    use alloc::vec::Vec;

    use nex_macro::packet;
    use nex_macro_helper::types::*;
    use std::net::Ipv6Addr;

    /// NDP SOL Packet Length.
    pub const NDP_SOL_PACKET_LEN: usize = NeighborSolicitPacket::minimum_packet_size();
    /// NDP ADV Packet Length.
    pub const NDP_ADV_PACKET_LEN: usize = NeighborAdvertPacket::minimum_packet_size();
    /// NDP OPT Packet Length.
    pub const NDP_OPT_PACKET_LEN: usize = NdpOptionPacket::minimum_packet_size();

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
    }

    impl PrimitiveValues for NdpOptionType {
        type T = (u8,);
        fn to_primitive_values(&self) -> (u8,) {
            (self.0,)
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
    #[packet]
    pub struct NdpOption {
        #[construct_with(u8)]
        pub option_type: NdpOptionType,
        #[construct_with(u8)]
        pub length: u8,
        #[length_fn = "ndp_option_payload_length"]
        #[payload]
        pub data: Vec<u8>,
    }

    /// Calculate a length of a `NdpOption`'s payload.
    fn ndp_option_payload_length(option: &NdpOptionPacket) -> usize {
        let len = option.get_length();
        if len > 0 {
            ((len * 8) - 2) as usize
        } else {
            0
        }
    }

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
    #[packet]
    pub struct RouterSolicit {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[length_fn = "rs_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Router Solicit packet calculation for the length of the options.
    fn rs_ndp_options_length(pkt: &RouterSolicitPacket) -> usize {
        if pkt.packet().len() > 8 {
            pkt.packet().len() - 8
        } else {
            0
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
    #[packet]
    pub struct RouterAdvert {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub hop_limit: u8,
        pub flags: u8,
        pub lifetime: u16be,
        pub reachable_time: u32be,
        pub retrans_time: u32be,
        #[length_fn = "ra_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Router Advert packet calculation for the length of the options.
    fn ra_ndp_options_length(pkt: &RouterAdvertPacket) -> usize {
        if pkt.packet().len() > 16 {
            pkt.packet().len() - 16
        } else {
            0
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
    #[packet]
    pub struct NeighborSolicit {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[length_fn = "ns_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Neighbor Solicit packet calculation for the length of the options.
    fn ns_ndp_options_length(pkt: &NeighborSolicitPacket) -> usize {
        if pkt.packet().len() > 24 {
            pkt.packet().len() - 24
        } else {
            0
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
    #[packet]
    pub struct NeighborAdvert {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub flags: u8,
        pub reserved: u24be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[length_fn = "na_ndp_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Neighbor Advert packet calculation for the length of the options.
    fn na_ndp_options_length(pkt: &NeighborAdvertPacket) -> usize {
        if pkt.packet().len() > 24 {
            pkt.packet().len() - 24
        } else {
            0
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
    #[packet]
    pub struct Redirect {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub reserved: u32be,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub target_addr: Ipv6Addr,
        #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
        pub dest_addr: Ipv6Addr,
        #[length_fn = "redirect_options_length"]
        pub options: Vec<NdpOption>,
        #[payload]
        #[length = "0"]
        pub payload: Vec<u8>,
    }

    /// Redirect packet calculation for the length of the options.
    fn redirect_options_length(pkt: &RedirectPacket) -> usize {
        if pkt.packet().len() > 40 {
            pkt.packet().len() - 40
        } else {
            0
        }
    }

    #[cfg(test)]
    mod ndp_tests {
        use super::*;
        use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
        use alloc::vec;

        #[test]
        fn basic_option_parsing() {
            let mut data = vec![
                0x02, 0x01, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                // Extra bytes to confuse the parsing
                0x00, 0x00, 0x00,
            ];
            let pkg = MutableNdpOptionPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_option_type(), NdpOptionTypes::TargetLLAddr);
            assert_eq!(pkg.get_length(), 0x01);
            assert_eq!(pkg.payload().len(), 6);
            assert_eq!(pkg.payload(), &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        }

        #[test]
        fn basic_rs_parse() {
            let mut data = vec![
                0x85, // Type
                0x00, // Code
                0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x00, // Reserved
                0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];

            let pkg = MutableRouterSolicitPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Type::RouterSolicitation);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0);
            assert_eq!(pkg.get_reserved(), 0);
            assert_eq!(pkg.get_options().len(), 2);

            let option = &pkg.get_options()[0];
            assert_eq!(option.option_type, NdpOptionTypes::TargetLLAddr);
            assert_eq!(option.length, 0x01);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(option.data.len(), 6);

            let option = &pkg.get_options()[1];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn basic_rs_create() {
            let ref_packet = vec![
                0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            let mut packet = [0u8; 16];
            let options = vec![NdpOption {
                option_type: NdpOptionTypes::SourceLLAddr,
                length: 1,
                data: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            }];
            {
                let mut rs_packet = MutableRouterSolicitPacket::new(&mut packet[..]).unwrap();
                rs_packet.set_icmpv6_type(Icmpv6Type::RouterSolicitation);
                rs_packet.set_icmpv6_code(Icmpv6Code(0));
                rs_packet.set_options(&options[..]);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_ra_parse() {
            let mut data = vec![
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
            ];
            let pkg = MutableRouterAdvertPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Type::RouterAdvertisement);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_hop_limit(), 0xff);
            assert_eq!(pkg.get_flags(), RouterAdvertFlags::ManagedAddressConf);
            assert_eq!(pkg.get_lifetime(), 0x900);
            assert_eq!(pkg.get_reachable_time(), 0x12345678);
            assert_eq!(pkg.get_retrans_time(), 0x87654321);
            assert_eq!(pkg.get_options().len(), 2);

            let option = &pkg.get_options()[0];
            assert_eq!(option.option_type, NdpOptionTypes::SourceLLAddr);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

            let option = &pkg.get_options()[1];
            assert_eq!(option.option_type, NdpOptionTypes::MTU);
            assert_eq!(option.length, 1);
            assert_eq!(option.data, &[0x00, 0x00, 0x57, 0x68, 0x61, 0x74]);
        }

        #[test]
        fn basic_ra_create() {
            let ref_packet = vec![
                0x86, 0x00, 0x00, 0x00, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let mut packet = [0u8; 24];
            let options = vec![NdpOption {
                option_type: NdpOptionTypes::MTU,
                length: 1,
                data: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            }];
            {
                let mut ra_packet = MutableRouterAdvertPacket::new(&mut packet[..]).unwrap();
                ra_packet.set_icmpv6_type(Icmpv6Type::RouterAdvertisement);
                ra_packet.set_icmpv6_code(Icmpv6Code(0));
                ra_packet.set_hop_limit(0xff);
                ra_packet.set_flags(RouterAdvertFlags::ManagedAddressConf);
                ra_packet.set_options(&options[..]);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_ns_parse() {
            let mut data = vec![
                0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ];
            let pkg = MutableNeighborSolicitPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Type::NeighborSolicitation);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(
                pkg.get_target_addr(),
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
            );
        }

        #[test]
        fn basic_ns_create() {
            let ref_packet = vec![
                0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ];
            let mut packet = [0u8; 24];
            {
                let mut ns_packet = MutableNeighborSolicitPacket::new(&mut packet[..]).unwrap();
                ns_packet.set_icmpv6_type(Icmpv6Type::NeighborSolicitation);
                ns_packet.set_icmpv6_code(Icmpv6Code(0));
                ns_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_na_parse() {
            let mut data = vec![
                0x88, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ];
            let pkg = MutableNeighborAdvertPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Type::NeighborAdvertisement);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(pkg.get_flags(), 0x80);
            assert_eq!(
                pkg.get_target_addr(),
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
            );
        }

        #[test]
        fn basic_na_create() {
            let ref_packet = vec![
                0x88, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ];
            let mut packet = [0u8; 24];
            {
                let mut na_packet = MutableNeighborAdvertPacket::new(&mut packet[..]).unwrap();
                na_packet.set_icmpv6_type(Icmpv6Type::NeighborAdvertisement);
                na_packet.set_icmpv6_code(Icmpv6Code(0));
                na_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                na_packet.set_flags(NeighborAdvertFlags::Router);
            }
            assert_eq!(&ref_packet[..], &packet[..]);
        }

        #[test]
        fn basic_redirect_parse() {
            let mut data = vec![
                0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let pkg = MutableRedirectPacket::new(&mut data[..]).unwrap();
            assert_eq!(pkg.get_icmpv6_type(), Icmpv6Type::RedirectMessage);
            assert_eq!(pkg.get_icmpv6_code(), Icmpv6Code(0));
            assert_eq!(pkg.get_checksum(), 0x00);
            assert_eq!(pkg.get_reserved(), 0x00);
            assert_eq!(
                pkg.get_target_addr(),
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
            );
            assert_eq!(pkg.get_dest_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        }

        #[test]
        fn basic_redirect_create() {
            let ref_packet = vec![
                0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let mut packet = [0u8; 40];
            {
                let mut rdr_packet = MutableRedirectPacket::new(&mut packet[..]).unwrap();
                rdr_packet.set_icmpv6_type(Icmpv6Type::RedirectMessage);
                rdr_packet.set_icmpv6_code(Icmpv6Code(0));
                rdr_packet.set_target_addr(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                rdr_packet.set_dest_addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            }
            assert_eq!(&ref_packet[..], &packet[..]);
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

    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
    use crate::PrimitiveValues;

    use alloc::vec::Vec;

    use nex_macro::packet;
    use nex_macro_helper::types::*;

    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
    }

    impl PrimitiveValues for Identifier {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
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
    }

    impl PrimitiveValues for SequenceNumber {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
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
    #[packet]
    pub struct EchoReply {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
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

    use crate::icmpv6::{Icmpv6Code, Icmpv6Type};
    use crate::PrimitiveValues;

    use alloc::vec::Vec;

    use nex_macro::packet;
    use nex_macro_helper::types::*;

    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
    }

    impl PrimitiveValues for Identifier {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
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
    }

    impl PrimitiveValues for SequenceNumber {
        type T = (u16,);
        fn to_primitive_values(&self) -> (u16,) {
            (self.0,)
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
    #[packet]
    pub struct EchoRequest {
        #[construct_with(u8)]
        pub icmpv6_type: Icmpv6Type,
        #[construct_with(u8)]
        pub icmpv6_code: Icmpv6Code,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}
