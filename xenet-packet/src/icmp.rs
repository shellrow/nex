//! An ICMP packet abstraction.

use crate::PrimitiveValues;

use alloc::vec::Vec;

use crate::ethernet::ETHERNET_HEADER_LEN;
use crate::ipv4::IPV4_HEADER_LEN;
use xenet_macro::packet;
use xenet_macro_helper::types::*;

/// ICMPv4 Header Length.
pub const ICMPV4_HEADER_LEN: usize = echo_request::MutableEchoRequestPacket::minimum_packet_size();
/// ICMPv4 Minimum Packet Length.
pub const ICMPV4_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN;
/// ICMPv4 IP Packet Length.
pub const ICMPV4_IP_PACKET_LEN: usize = IPV4_HEADER_LEN + ICMPV4_HEADER_LEN;

/// Represents the ICMPv4 header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub checksum: u16be,
}

impl IcmpHeader {
    /// Construct an ICMPv4 header from a byte slice.
    pub fn from_bytes(packet: &[u8]) -> Result<IcmpHeader, String> {
        if packet.len() < ICMPV4_HEADER_LEN {
            return Err("Packet is too small for ICMPv4 header".to_string());
        }
        match IcmpPacket::new(packet) {
            Some(icmp_packet) => Ok(IcmpHeader {
                icmp_type: icmp_packet.get_icmp_type(),
                icmp_code: icmp_packet.get_icmp_code(),
                checksum: icmp_packet.get_checksum(),
            }),
            None => Err("Failed to parse ICMPv4 packet".to_string()),
        }
    }
    /// Construct an ICMPv4 header from a IcmpPacket.
    pub(crate) fn from_packet(icmp_packet: &IcmpPacket) -> IcmpHeader {
        IcmpHeader {
            icmp_type: icmp_packet.get_icmp_type(),
            icmp_code: icmp_packet.get_icmp_code(),
            checksum: icmp_packet.get_checksum(),
        }
    }
}

/// Represents the "ICMP type" header field.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    RedirectMessage,
    EchoRequest,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    InformationRequest,
    InformationReply,
    AddressMaskRequest,
    AddressMaskReply,
    Traceroute,
    DatagramConversionError,
    MobileHostRedirect,
    IPv6WhereAreYou,
    IPv6IAmHere,
    MobileRegistrationRequest,
    MobileRegistrationReply,
    DomainNameRequest,
    DomainNameReply,
    SKIP,
    Photuris,
    Unknown(u8),
}

impl IcmpType {
    /// Create a new `IcmpType` instance.
    pub fn new(val: u8) -> IcmpType {
        match val {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::RedirectMessage,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            15 => IcmpType::InformationRequest,
            16 => IcmpType::InformationReply,
            17 => IcmpType::AddressMaskRequest,
            18 => IcmpType::AddressMaskReply,
            30 => IcmpType::Traceroute,
            31 => IcmpType::DatagramConversionError,
            32 => IcmpType::MobileHostRedirect,
            33 => IcmpType::IPv6WhereAreYou,
            34 => IcmpType::IPv6IAmHere,
            35 => IcmpType::MobileRegistrationRequest,
            36 => IcmpType::MobileRegistrationReply,
            37 => IcmpType::DomainNameRequest,
            38 => IcmpType::DomainNameReply,
            39 => IcmpType::SKIP,
            40 => IcmpType::Photuris,
            n => IcmpType::Unknown(n),
        }
    }
    /// Get the name of the ICMP type
    pub fn name(&self) -> String {
        match *self {
            IcmpType::EchoReply => String::from("Echo Reply"),
            IcmpType::DestinationUnreachable => String::from("Destination Unreachable"),
            IcmpType::SourceQuench => String::from("Source Quench"),
            IcmpType::RedirectMessage => String::from("Redirect Message"),
            IcmpType::EchoRequest => String::from("Echo Request"),
            IcmpType::RouterAdvertisement => String::from("Router Advertisement"),
            IcmpType::RouterSolicitation => String::from("Router Solicitation"),
            IcmpType::TimeExceeded => String::from("Time Exceeded"),
            IcmpType::ParameterProblem => String::from("Parameter Problem"),
            IcmpType::TimestampRequest => String::from("Timestamp Request"),
            IcmpType::TimestampReply => String::from("Timestamp Reply"),
            IcmpType::InformationRequest => String::from("Information Request"),
            IcmpType::InformationReply => String::from("Information Reply"),
            IcmpType::AddressMaskRequest => String::from("Address Mask Request"),
            IcmpType::AddressMaskReply => String::from("Address Mask Reply"),
            IcmpType::Traceroute => String::from("Traceroute"),
            IcmpType::DatagramConversionError => String::from("Datagram Conversion Error"),
            IcmpType::MobileHostRedirect => String::from("Mobile Host Redirect"),
            IcmpType::IPv6WhereAreYou => String::from("IPv6 Where Are You"),
            IcmpType::IPv6IAmHere => String::from("IPv6 I Am Here"),
            IcmpType::MobileRegistrationRequest => String::from("Mobile Registration Request"),
            IcmpType::MobileRegistrationReply => String::from("Mobile Registration Reply"),
            IcmpType::DomainNameRequest => String::from("Domain Name Request"),
            IcmpType::DomainNameReply => String::from("Domain Name Reply"),
            IcmpType::SKIP => String::from("SKIP"),
            IcmpType::Photuris => String::from("Photuris"),
            IcmpType::Unknown(n) => format!("Unknown ({})", n),
        }
    }
}

impl PrimitiveValues for IcmpType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match *self {
            IcmpType::EchoReply => (0,),
            IcmpType::DestinationUnreachable => (3,),
            IcmpType::SourceQuench => (4,),
            IcmpType::RedirectMessage => (5,),
            IcmpType::EchoRequest => (8,),
            IcmpType::RouterAdvertisement => (9,),
            IcmpType::RouterSolicitation => (10,),
            IcmpType::TimeExceeded => (11,),
            IcmpType::ParameterProblem => (12,),
            IcmpType::TimestampRequest => (13,),
            IcmpType::TimestampReply => (14,),
            IcmpType::InformationRequest => (15,),
            IcmpType::InformationReply => (16,),
            IcmpType::AddressMaskRequest => (17,),
            IcmpType::AddressMaskReply => (18,),
            IcmpType::Traceroute => (30,),
            IcmpType::DatagramConversionError => (31,),
            IcmpType::MobileHostRedirect => (32,),
            IcmpType::IPv6WhereAreYou => (33,),
            IcmpType::IPv6IAmHere => (34,),
            IcmpType::MobileRegistrationRequest => (35,),
            IcmpType::MobileRegistrationReply => (36,),
            IcmpType::DomainNameRequest => (37,),
            IcmpType::DomainNameReply => (38,),
            IcmpType::SKIP => (39,),
            IcmpType::Photuris => (40,),
            IcmpType::Unknown(n) => (n,),
        }
    }
}

/// Represents the "ICMP code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IcmpCode(pub u8);

impl IcmpCode {
    /// Create a new `IcmpCode` instance.
    pub fn new(val: u8) -> IcmpCode {
        IcmpCode(val)
    }
}

impl PrimitiveValues for IcmpCode {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents a generic ICMP packet.
#[packet]
pub struct Icmp {
    #[construct_with(u8)]
    pub icmp_type: IcmpType,
    #[construct_with(u8)]
    pub icmp_code: IcmpCode,
    pub checksum: u16be,
    // theoretically, the header is 64 bytes long, but since the "Rest Of Header" part depends on
    // the ICMP type and ICMP code, we consider it's part of the payload.
    // rest_of_header: u32be,
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an ICMP packet.
pub fn checksum(packet: &IcmpPacket) -> u16be {
    use crate::util;
    use crate::Packet;

    util::checksum(packet.packet(), 1)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn checksum_zeros() {
        let mut data = vec![0u8; 8];
        let expected = 65535;
        let mut pkg = MutableIcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_nonzero() {
        let mut data = vec![255u8; 8];
        let expected = 0;
        let mut pkg = MutableIcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(0);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_odd_bytes() {
        let mut data = vec![191u8; 7];
        let expected = 49535;
        let pkg = IcmpPacket::new(&mut data[..]).unwrap();
        assert_eq!(checksum(&pkg), expected);
    }
}

pub mod echo_reply {
    //! abstraction for ICMP "echo reply" packets.
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

    use crate::icmp::{IcmpCode, IcmpType};
    use crate::PrimitiveValues;

    use alloc::vec::Vec;

    use xenet_macro::packet;
    use xenet_macro_helper::types::*;

    /// Represent the "identifier" field of the ICMP echo replay header.
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

    /// Represent the "sequence number" field of the ICMP echo replay header.
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

    /// Enumeration of available ICMP codes for ICMP echo replay packets. There is actually only
    /// one, since the only valid ICMP code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an ICMP echo reply packet.
    #[packet]
    pub struct EchoReply {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod echo_request {
    //! abstraction for "echo request" ICMP packets.
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

    use crate::icmp::{IcmpCode, IcmpType};
    use crate::PrimitiveValues;

    use alloc::vec::Vec;

    use xenet_macro::packet;
    use xenet_macro_helper::types::*;

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

    /// Enumeration of available ICMP codes for "echo reply" ICMP packets. There is actually only
    /// one, since the only valid ICMP code is 0.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// 0 is the only available ICMP code for "echo reply" ICMP packets.
        pub const NoCode: IcmpCode = IcmpCode(0);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct EchoRequest {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub identifier: u16be,
        pub sequence_number: u16be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod destination_unreachable {
    //! abstraction for "destination unreachable" ICMP packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |                             unused                            |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |      Internet Header + 64 bits of Original Data Datagram      |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! ```

    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use xenet_macro::packet;
    use xenet_macro_helper::types::*;

    /// Enumeration of the recognized ICMP codes for "destination unreachable" ICMP packets.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// ICMP code for "destination network unreachable" packet.
        pub const DestinationNetworkUnreachable: IcmpCode = IcmpCode(0);
        /// ICMP code for "destination host unreachable" packet.
        pub const DestinationHostUnreachable: IcmpCode = IcmpCode(1);
        /// ICMP code for "destination protocol unreachable" packet.
        pub const DestinationProtocolUnreachable: IcmpCode = IcmpCode(2);
        /// ICMP code for "destination port unreachable" packet.
        pub const DestinationPortUnreachable: IcmpCode = IcmpCode(3);
        /// ICMP code for "fragmentation required and DFF flag set" packet.
        pub const FragmentationRequiredAndDFFlagSet: IcmpCode = IcmpCode(4);
        /// ICMP code for "source route failed" packet.
        pub const SourceRouteFailed: IcmpCode = IcmpCode(5);
        /// ICMP code for "destination network unknown" packet.
        pub const DestinationNetworkUnknown: IcmpCode = IcmpCode(6);
        /// ICMP code for "destination host unknown" packet.
        pub const DestinationHostUnknown: IcmpCode = IcmpCode(7);
        /// ICMP code for "source host isolated" packet.
        pub const SourceHostIsolated: IcmpCode = IcmpCode(8);
        /// ICMP code for "network administrative prohibited" packet.
        pub const NetworkAdministrativelyProhibited: IcmpCode = IcmpCode(9);
        /// ICMP code for "host administrative prohibited" packet.
        pub const HostAdministrativelyProhibited: IcmpCode = IcmpCode(10);
        /// ICMP code for "network unreachable for this Type Of Service" packet.
        pub const NetworkUnreachableForTOS: IcmpCode = IcmpCode(11);
        /// ICMP code for "host unreachable for this Type Of Service" packet.
        pub const HostUnreachableForTOS: IcmpCode = IcmpCode(12);
        /// ICMP code for "communication administratively prohibited" packet.
        pub const CommunicationAdministrativelyProhibited: IcmpCode = IcmpCode(13);
        /// ICMP code for "host precedence violation" packet.
        pub const HostPrecedenceViolation: IcmpCode = IcmpCode(14);
        /// ICMP code for "precedence cut off in effect" packet.
        pub const PrecedenceCutoffInEffect: IcmpCode = IcmpCode(15);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct DestinationUnreachable {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub unused: u32be,
        #[payload]
        pub payload: Vec<u8>,
    }
}

pub mod time_exceeded {
    //! abstraction for "time exceeded" ICMP packets.
    //!
    //! ```text
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |     Type      |     Code      |          Checksum             |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |                             unused                            |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! |      Internet Header + 64 bits of Original Data Datagram      |
    //! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //! ```

    use crate::icmp::{IcmpCode, IcmpType};

    use alloc::vec::Vec;

    use xenet_macro::packet;
    use xenet_macro_helper::types::*;

    /// Enumeration of the recognized ICMP codes for "time exceeded" ICMP packets.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod IcmpCodes {
        use crate::icmp::IcmpCode;
        /// ICMP code for "time to live exceeded in transit" packet.
        pub const TimeToLiveExceededInTransit: IcmpCode = IcmpCode(0);
        /// ICMP code for "fragment reassembly time exceeded" packet.
        pub const FragmentReasemblyTimeExceeded: IcmpCode = IcmpCode(1);
    }

    /// Represents an "echo request" ICMP packet.
    #[packet]
    pub struct TimeExceeded {
        #[construct_with(u8)]
        pub icmp_type: IcmpType,
        #[construct_with(u8)]
        pub icmp_code: IcmpCode,
        pub checksum: u16be,
        pub unused: u32be,
        #[payload]
        pub payload: Vec<u8>,
    }
}
