//! An ICMP packet abstraction.
use crate::{ethernet::ETHERNET_HEADER_LEN, packet::Packet};
use crate::ipv4::IPV4_HEADER_LEN;

use bytes::{BufMut, Bytes, BytesMut};
use nex_core::bitfield::u16be;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ICMP Common Header Length.
pub const ICMP_COMMON_HEADER_LEN: usize = 4;
/// ICMPv4 Header Length. Including the common header (4 bytes) and the type specific header (4 bytes).
pub const ICMPV4_HEADER_LEN: usize = 8;
/// ICMPv4 Minimum Packet Length.
pub const ICMPV4_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN;
/// ICMPv4 IP Packet Length.
pub const ICMPV4_IP_PACKET_LEN: usize = IPV4_HEADER_LEN + ICMPV4_HEADER_LEN;

/// Represents the "ICMP type" header field.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    pub fn name(&self) -> &'static str {
        match *self {
            IcmpType::EchoReply => "Echo Reply",
            IcmpType::DestinationUnreachable => "Destination Unreachable",
            IcmpType::SourceQuench => "Source Quench",
            IcmpType::RedirectMessage => "Redirect Message",
            IcmpType::EchoRequest => "Echo Request",
            IcmpType::RouterAdvertisement => "Router Advertisement",
            IcmpType::RouterSolicitation => "Router Solicitation",
            IcmpType::TimeExceeded => "Time Exceeded",
            IcmpType::ParameterProblem => "Parameter Problem",
            IcmpType::TimestampRequest => "Timestamp Request",
            IcmpType::TimestampReply => "Timestamp Reply",
            IcmpType::InformationRequest => "Information Request",
            IcmpType::InformationReply => "Information Reply",
            IcmpType::AddressMaskRequest => "Address Mask Request",
            IcmpType::AddressMaskReply => "Address Mask Reply",
            IcmpType::Traceroute => "Traceroute",
            IcmpType::DatagramConversionError => "Datagram Conversion Error",
            IcmpType::MobileHostRedirect => "Mobile Host Redirect",
            IcmpType::IPv6WhereAreYou => "IPv6 Where Are You",
            IcmpType::IPv6IAmHere => "IPv6 I Am Here",
            IcmpType::MobileRegistrationRequest => "Mobile Registration Request",
            IcmpType::MobileRegistrationReply => "Mobile Registration Reply",
            IcmpType::DomainNameRequest => "Domain Name Request",
            IcmpType::DomainNameReply => "Domain Name Reply",
            IcmpType::SKIP => "SKIP",
            IcmpType::Photuris => "Photuris",
            IcmpType::Unknown(_) => "Unknown",
        }
    }
    pub fn value(&self) -> u8 {
        match *self {
            IcmpType::EchoReply => 0,
            IcmpType::DestinationUnreachable => 3,
            IcmpType::SourceQuench => 4,
            IcmpType::RedirectMessage => 5,
            IcmpType::EchoRequest => 8,
            IcmpType::RouterAdvertisement => 9,
            IcmpType::RouterSolicitation => 10,
            IcmpType::TimeExceeded => 11,
            IcmpType::ParameterProblem => 12,
            IcmpType::TimestampRequest => 13,
            IcmpType::TimestampReply => 14,
            IcmpType::InformationRequest => 15,
            IcmpType::InformationReply => 16,
            IcmpType::AddressMaskRequest => 17,
            IcmpType::AddressMaskReply => 18,
            IcmpType::Traceroute => 30,
            IcmpType::DatagramConversionError => 31,
            IcmpType::MobileHostRedirect => 32,
            IcmpType::IPv6WhereAreYou => 33,
            IcmpType::IPv6IAmHere => 34,
            IcmpType::MobileRegistrationRequest => 35,
            IcmpType::MobileRegistrationReply => 36,
            IcmpType::DomainNameRequest => 37,
            IcmpType::DomainNameReply => 38,
            IcmpType::SKIP => 39,
            IcmpType::Photuris => 40,
            IcmpType::Unknown(n) => n,
        }
    }
}

/// Represents the "ICMP code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IcmpCode(pub u8);

impl IcmpCode {
    /// Create a new `IcmpCode` instance.
    pub fn new(val: u8) -> IcmpCode {
        IcmpCode(val)
    }
    pub fn value(&self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub checksum: u16,
}

/// ICMP packet representation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpPacket {
    pub header: IcmpHeader,
    pub payload: Bytes,
}

impl Packet for IcmpPacket {
    type Header = IcmpHeader;

    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ICMPV4_HEADER_LEN {
            return None;
        }
        let icmp_type = IcmpType::new(bytes[0]);
        let icmp_code = IcmpCode::new(bytes[1]);
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let payload = Bytes::copy_from_slice(&bytes[ICMP_COMMON_HEADER_LEN..]);
        Some(IcmpPacket {
            header: IcmpHeader {
                icmp_type,
                icmp_code,
                checksum,
            },
            payload,
        })
    }
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(ICMP_COMMON_HEADER_LEN + self.payload.len());
        buf.put_u8(self.header.icmp_type.value());
        buf.put_u8(self.header.icmp_code.value());
        buf.put_u16(self.header.checksum);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(..self.header_len())
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        ICMP_COMMON_HEADER_LEN
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

impl IcmpPacket {
    pub fn with_computed_checksum(&self) -> Self {
        let mut pkt = self.clone();
        pkt.header.checksum = checksum(&pkt).into();
        pkt
    }
}

/// Calculates a checksum of an ICMP packet.
pub fn checksum(packet: &IcmpPacket) -> u16be {
    use crate::util;
    util::checksum(&packet.to_bytes(), 1)
}

pub mod echo_request {
    use bytes::Bytes;

    use crate::icmp::{IcmpHeader, IcmpPacket, IcmpType};

    /// Represents the identifier field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
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
        pub fn value(&self) -> u16 {
            self.0
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
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EchoRequestPacket {
        pub header: IcmpHeader,
        pub identifier: u16,
        pub sequence_number: u16,
        pub payload: Bytes,
    }

    impl TryFrom<IcmpPacket> for EchoRequestPacket {
        type Error = &'static str;

        fn try_from(pkt: IcmpPacket) -> Result<Self, Self::Error> {
            if pkt.header.icmp_type != IcmpType::EchoRequest {
                return Err("Not an Echo Request");
            }
            if pkt.payload.len() < 4 {
                return Err("Payload too short for Echo Request");
            }

            Ok(Self {
                header: pkt.header,
                identifier: u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]),
                sequence_number: u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]),
                payload: pkt.payload.slice(4..),
            })
        }
    }

}

pub mod echo_reply {
    use bytes::Bytes;

    use crate::icmp::{IcmpHeader, IcmpPacket, IcmpType};

    /// Represent the "identifier" field of the ICMP echo replay header.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Identifier(pub u16);

    impl Identifier {
        /// Create a new `Identifier` instance.
        pub fn new(val: u16) -> Identifier {
            Identifier(val)
        }
        pub fn value(&self) -> u16 {
            self.0
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
        pub fn value(&self) -> u16 {
            self.0
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
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EchoReplyPacket {
        pub header: IcmpHeader,
        pub identifier: u16,
        pub sequence_number: u16,
        pub payload: Bytes,
    }

    impl TryFrom<IcmpPacket> for EchoReplyPacket {
        type Error = &'static str;

        fn try_from(pkt: IcmpPacket) -> Result<Self, Self::Error> {
            if pkt.header.icmp_type != IcmpType::EchoReply {
                return Err("Not an Echo Reply");
            }
            if pkt.payload.len() < 4 {
                return Err("Payload too short for Echo Reply");
            }

            Ok(Self {
                header: pkt.header,
                identifier: u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]).into(),
                sequence_number: u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]).into(),
                payload: pkt.payload.slice(4..),
            })
        }
    }

}

pub mod destination_unreachable {
    use bytes::Bytes;

    use crate::icmp::{IcmpHeader, IcmpPacket, IcmpType};

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
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DestinationUnreachablePacket {
        pub header: IcmpHeader,
        pub unused: u16,
        pub next_hop_mtu: u16,
        pub payload: Bytes,
    }

    impl TryFrom<IcmpPacket> for DestinationUnreachablePacket {
        type Error = &'static str;

        fn try_from(pkt: IcmpPacket) -> Result<Self, Self::Error> {
            if pkt.header.icmp_type != IcmpType::DestinationUnreachable {
                return Err("Not a Destination Unreachable");
            }
            if pkt.payload.len() < 4 {
                return Err("Payload too short for Destination Unreachable");
            }

            Ok(Self {
                header: pkt.header,
                unused: u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]).into(),
                next_hop_mtu: u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]).into(),
                payload: pkt.payload.slice(4..),
            })
        }
    }

}

pub mod time_exceeded {
    use bytes::Bytes;

    use crate::icmp::{IcmpHeader, IcmpPacket, IcmpType};

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
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TimeExceededPacket {
        pub header: IcmpHeader,
        pub unused: u32,
        pub payload: Bytes,
    }

    impl TryFrom<IcmpPacket> for TimeExceededPacket {
        type Error = &'static str;

        fn try_from(pkt: IcmpPacket) -> Result<Self, Self::Error> {
            if pkt.header.icmp_type != IcmpType::TimeExceeded {
                return Err("Not a Time Exceeded");
            }
            if pkt.payload.len() < 4 {
                return Err("Payload too short for Time Exceeded");
            }

            Ok(Self {
                header: pkt.header,
                unused: u32::from_be_bytes([
                    pkt.payload[0],
                    pkt.payload[1],
                    pkt.payload[2],
                    pkt.payload[3],
                ])
                .into(),
                payload: pkt.payload.slice(4..),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request_from_bytes() {
        let raw_bytes = Bytes::from_static(&[
            8, 0, 0x3a, 0xbc, // Type = 8 (Echo Request), Code = 0, Checksum = 0x3abc
            0x04, 0xd2,       // Identifier = 0x04d2 (1234)
            0x00, 0x2a,       // Sequence = 0x002a (42)
            b'p', b'i', b'n', b'g',
        ]);

        let parsed = IcmpPacket::from_bytes(raw_bytes.clone()).expect("Failed to parse ICMP");
        let echo = echo_request::EchoRequestPacket::try_from(parsed).expect("Failed to downcast");

        assert_eq!(echo.header.icmp_type, IcmpType::EchoRequest);
        assert_eq!(echo.header.icmp_code, IcmpCode(0));
        assert_eq!(echo.header.checksum, 0x3abc);
        assert_eq!(echo.identifier, 1234);
        assert_eq!(echo.sequence_number, 42);
        assert_eq!(echo.payload, Bytes::from_static(b"ping"));
    }

    #[test]
    fn test_echo_reply_roundtrip() {
        let identifier: u16 = 5678;
        let sequence: u16 = 99;
        let payload = Bytes::from_static(b"pong");

        let header = IcmpHeader {
            icmp_type: IcmpType::EchoReply,
            icmp_code: IcmpCode(0),
            checksum: 0,
        };

        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u16(identifier);
        buf.put_u16(sequence);
        buf.extend_from_slice(&payload);

        let pkt = IcmpPacket { header, payload: buf.freeze() }.with_computed_checksum();
        let bytes = pkt.to_bytes();

        let parsed = IcmpPacket::from_bytes(bytes.clone()).expect("Failed to parse ICMP");
        let echo = echo_reply::EchoReplyPacket::try_from(parsed).expect("Failed to downcast");

        assert_eq!(echo.identifier, identifier);
        assert_eq!(echo.sequence_number, sequence);
        assert_eq!(echo.payload, payload);
    }

    #[test]
    fn test_destination_unreachable() {
        let unused: u16 = 0;
        let mtu: u16 = 1500;
        let payload = Bytes::from_static(b"bad ip");

        let header = IcmpHeader {
            icmp_type: IcmpType::DestinationUnreachable,
            icmp_code: IcmpCode(3), // Port unreachable
            checksum: 0,
        };

        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u16(unused);
        buf.put_u16(mtu);
        buf.extend_from_slice(&payload);

        let pkt = IcmpPacket { header, payload: buf.freeze() }.with_computed_checksum();
        let parsed = IcmpPacket::from_bytes(pkt.to_bytes()).unwrap();
        let unreachable = destination_unreachable::DestinationUnreachablePacket::try_from(parsed).unwrap();

        assert_eq!(unreachable.next_hop_mtu, mtu);
        assert_eq!(unreachable.payload, payload);
    }

    #[test]
    fn test_time_exceeded() {
        let unused: u32 = 0xdeadbeef;
        let payload = Bytes::from_static(b"timeout");

        let header = IcmpHeader {
            icmp_type: IcmpType::TimeExceeded,
            icmp_code: IcmpCode(0), // TTL exceeded
            checksum: 0,
        };

        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u32(unused);
        buf.extend_from_slice(&payload);

        let pkt = IcmpPacket { header, payload: buf.freeze() }.with_computed_checksum();
        let parsed = IcmpPacket::from_bytes(pkt.to_bytes()).unwrap();
        let exceeded = time_exceeded::TimeExceededPacket::try_from(parsed).unwrap();

        assert_eq!(exceeded.unused, unused);
        assert_eq!(exceeded.payload, payload);
    }
}
