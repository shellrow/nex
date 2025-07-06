//! An IPv4 packet abstraction.

use crate::{ip::IpNextProtocol, packet::Packet};
use bytes::{BufMut, Bytes, BytesMut};
use nex_core::bitfield::*;
use std::net::Ipv4Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// IPv4 Header Length
pub const IPV4_HEADER_LEN: usize = 20;
/// IPv4 Header Byte Unit (32 bits)
pub const IPV4_HEADER_LENGTH_BYTE_UNITS: usize = 4;

/// Represents the IPv4 header flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ipv4Flags {
    use nex_core::bitfield::*;
    /// Don't Fragment flag.
    pub const DontFragment: u3 = 0b010;
    /// More Fragments flag.
    pub const MoreFragments: u3 = 0b001;
}

/// Represents the IPv4 options.
/// <http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml>
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Ipv4OptionType {
    /// End of Options List
    EOL = 0,
    /// No Operation
    NOP = 1,
    /// Security
    SEC = 2,
    /// Loose Source Route
    LSR = 3,
    /// Time Stamp
    TS = 4,
    /// Extended Security
    ESEC = 5,
    /// Commercial Security
    CIPSO = 6,
    /// Record Route
    RR = 7,
    /// Stream ID
    SID = 8,
    /// Strict Source Route
    SSR = 9,
    /// Experimental Measurement
    ZSU = 10,
    /// MTU Probe
    MTUP = 11,
    /// MTU Reply
    MTUR = 12,
    /// Experimental Flow Control
    FINN = 13,
    /// Experimental Access Control
    VISA = 14,
    /// Encode
    ENCODE = 15,
    /// IMI Traffic Descriptor
    IMITD = 16,
    /// Extended Internet Protocol
    EIP = 17,
    /// Traceroute
    TR = 18,
    /// Address Extension
    ADDEXT = 19,
    /// Router Alert
    RTRALT = 20,
    /// Selective Directed Broadcast
    SDB = 21,
    /// Unassigned
    Unassigned = 22,
    /// Dynamic Packet State
    DPS = 23,
    /// Upstream Multicast Packet
    UMP = 24,
    /// Quick-Start
    QS = 25,
    /// RFC3692-style Experiment
    EXP = 30,
    /// Unknown
    Unknown(u8),
}

impl Ipv4OptionType {
    /// Constructs a new Ipv4OptionType from u8
    pub fn new(n: u8) -> Ipv4OptionType {
        match n {
            0 => Ipv4OptionType::EOL,
            1 => Ipv4OptionType::NOP,
            2 => Ipv4OptionType::SEC,
            3 => Ipv4OptionType::LSR,
            4 => Ipv4OptionType::TS,
            5 => Ipv4OptionType::ESEC,
            6 => Ipv4OptionType::CIPSO,
            7 => Ipv4OptionType::RR,
            8 => Ipv4OptionType::SID,
            9 => Ipv4OptionType::SSR,
            10 => Ipv4OptionType::ZSU,
            11 => Ipv4OptionType::MTUP,
            12 => Ipv4OptionType::MTUR,
            13 => Ipv4OptionType::FINN,
            14 => Ipv4OptionType::VISA,
            15 => Ipv4OptionType::ENCODE,
            16 => Ipv4OptionType::IMITD,
            17 => Ipv4OptionType::EIP,
            18 => Ipv4OptionType::TR,
            19 => Ipv4OptionType::ADDEXT,
            20 => Ipv4OptionType::RTRALT,
            21 => Ipv4OptionType::SDB,
            22 => Ipv4OptionType::Unassigned,
            23 => Ipv4OptionType::DPS,
            24 => Ipv4OptionType::UMP,
            25 => Ipv4OptionType::QS,
            30 => Ipv4OptionType::EXP,
            _ => Ipv4OptionType::Unknown(n),
        }
    }
    pub fn value(&self) -> u8 {
        match *self {
            Ipv4OptionType::EOL => 0,
            Ipv4OptionType::NOP => 1,
            Ipv4OptionType::SEC => 2,
            Ipv4OptionType::LSR => 3,
            Ipv4OptionType::TS => 4,
            Ipv4OptionType::ESEC => 5,
            Ipv4OptionType::CIPSO => 6,
            Ipv4OptionType::RR => 7,
            Ipv4OptionType::SID => 8,
            Ipv4OptionType::SSR => 9,
            Ipv4OptionType::ZSU => 10,
            Ipv4OptionType::MTUP => 11,
            Ipv4OptionType::MTUR => 12,
            Ipv4OptionType::FINN => 13,
            Ipv4OptionType::VISA => 14,
            Ipv4OptionType::ENCODE => 15,
            Ipv4OptionType::IMITD => 16,
            Ipv4OptionType::EIP => 17,
            Ipv4OptionType::TR => 18,
            Ipv4OptionType::ADDEXT => 19,
            Ipv4OptionType::RTRALT => 20,
            Ipv4OptionType::SDB => 21,
            Ipv4OptionType::Unassigned => 22,
            Ipv4OptionType::DPS => 23,
            Ipv4OptionType::UMP => 24,
            Ipv4OptionType::QS => 25,
            Ipv4OptionType::EXP => 30,
            Ipv4OptionType::Unknown(n) => n,
        }
    }
}

/// Represents the IPv4 option header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4OptionHeader {
    pub copied: u1,
    pub class: u2,
    pub number: Ipv4OptionType,
    pub length: Option<u8>,
}

/// Represents the IPv4 Option field.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4OptionPacket {
    pub header: Ipv4OptionHeader,
    pub data: Bytes,
}

/// Represents the IPv4 header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4Header {
    pub version: u4,
    pub header_length: u4,
    pub dscp: u6,
    pub ecn: u2,
    pub total_length: u16be,
    pub identification: u16be,
    pub flags: u3,
    pub fragment_offset: u13be,
    pub ttl: u8,
    pub next_level_protocol: IpNextProtocol,
    pub checksum: u16be,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Vec<Ipv4OptionPacket>,
}

/// Represents an IPv4 Packet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Bytes,
}

impl Packet for Ipv4Packet {
    type Header = Ipv4Header;
    
    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPV4_HEADER_LEN {
            return None;
        }

        let version = (bytes[0] & 0xF0) >> 4;
        let header_length = (bytes[0] & 0x0F) as usize;
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        if bytes.len() < total_length || header_length < 5 {
            return None;
        }

        let ihl_bytes = header_length * 4;
        if ihl_bytes < IPV4_HEADER_LEN || ihl_bytes > total_length {
            return None;
        }
        let payload = Bytes::copy_from_slice(&bytes[ihl_bytes..total_length]);

        let mut options = Vec::new();
        let mut i = IPV4_HEADER_LEN;

        while i < ihl_bytes {
            let b = bytes[i];
            let copied = (b >> 7) & 0x01;
            let class = (b >> 5) & 0x03;
            let number = Ipv4OptionType::new(b & 0b0001_1111);

            match number {
                Ipv4OptionType::EOL => {
                    options.push(Ipv4OptionPacket {
                        header: Ipv4OptionHeader {
                            copied,
                            class,
                            number,
                            length: None,
                        },
                        data: Bytes::new(),
                    });
                    break;
                }
                Ipv4OptionType::NOP => {
                    options.push(Ipv4OptionPacket {
                        header: Ipv4OptionHeader {
                            copied,
                            class,
                            number,
                            length: None,
                        },
                        data: Bytes::new(),
                    });
                    i += 1;
                }
                _ => {
                    if i + 2 > ihl_bytes {
                        break;
                    }
                    let len = bytes[i + 1] as usize;
                    if len < 2 || i + len > ihl_bytes {
                        break;
                    }

                    let data = Bytes::copy_from_slice(&bytes[i + 2..i + len]);

                    options.push(Ipv4OptionPacket {
                        header: Ipv4OptionHeader {
                            copied,
                            class,
                            number,
                            length: Some(len as u8),
                        },
                        data,
                    });

                    i += len;
                }
            }
        }

        Some(Self {
            header: Ipv4Header {
                version: version as u4,
                header_length: header_length as u4,
                dscp: (bytes[1] >> 2) as u6,
                ecn: (bytes[1] & 0x03) as u2,
                total_length: u16::from_be_bytes([bytes[2], bytes[3]]) as u16be,
                identification: u16::from_be_bytes([bytes[4], bytes[5]]) as u16be,
                flags: (bytes[6] >> 5) as u3,
                fragment_offset: ((u16::from_be_bytes([bytes[6], bytes[7]])) & 0x1FFF) as u13be,
                ttl: bytes[8],
                next_level_protocol: IpNextProtocol::new(bytes[9]),
                checksum: u16::from_be_bytes([bytes[10], bytes[11]]) as u16be,
                source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
                destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
                options,
            },
            payload,
        })
    }
    
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        // 1. Version/IHL + DSCP/ECN
        let mut tmp_buf = BytesMut::with_capacity(60); // max header size
        for option in &self.header.options {
            let number = option.header.number.value();
            let type_byte = (option.header.copied << 7)
                | (option.header.class << 5)
                | (number & 0b0001_1111);
            tmp_buf.put_u8(type_byte);

            match option.header.number {
                Ipv4OptionType::EOL | Ipv4OptionType::NOP => {}
                _ => {
                    let len = option.header.length.unwrap_or((option.data.len() + 2) as u8);
                    tmp_buf.put_u8(len);
                    tmp_buf.extend_from_slice(&option.data);
                }
            }
        }

        // padding
        while tmp_buf.len() % 4 != 0 {
            tmp_buf.put_u8(0);
        }

        let header_len = IPV4_HEADER_LEN + tmp_buf.len();

        let total_len_expected = header_len + self.payload.len();
        // Check if the total length exceeds the header's total_length field
        if total_len_expected > self.header.total_length as usize {
            panic!(
                "Payload too long: header {} + payload {} = {} > total_length {}",
                header_len,
                self.payload.len(),
                total_len_expected,
                self.header.total_length
            );
        }

        let header_len_words = (header_len / 4) as u8;

        let mut buf = BytesMut::with_capacity(self.total_len());

        buf.put_u8((self.header.version << 4 | header_len_words) as u8);
        buf.put_u8((self.header.dscp << 2 | self.header.ecn) as u8);

        // 2. Fixed header fields
        buf.put_u16(self.header.total_length);
        buf.put_u16(self.header.identification);
        buf.put_u16(((self.header.flags as u16) << 13) | self.header.fragment_offset);
        buf.put_u8(self.header.ttl);
        buf.put_u8(self.header.next_level_protocol.value());
        buf.put_u16(self.header.checksum);
        buf.extend_from_slice(&self.header.source.octets());
        buf.extend_from_slice(&self.header.destination.octets());

        // 3. options
        buf.extend_from_slice(&tmp_buf);

        // 4. payload
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
        self.header.header_length as usize * 4
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

impl Ipv4Packet {
    pub fn with_computed_checksum(mut self) -> Self {
        self.header.checksum = checksum(&self);
        self
    }
}

/// Calculates a checksum of an IPv4 packet header.
/// The checksum field of the packet is regarded as zeros during the calculation.
pub fn checksum(packet: &Ipv4Packet) -> u16be {
    use crate::util;

    let bytes = packet.to_bytes();
    let len = packet.header_len();
    util::checksum(&bytes[..len], 5)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ipv4_packet_round_trip() {
        let raw = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x1c, // Version + IHL, DSCP + ECN, Total Length (28)
            0x1c, 0x46, 0x40, 0x00, // Identification, Flags + Fragment Offset
            0x40, 0x06, 0xb1, 0xe6, // TTL, Protocol (TCP), Header checksum
            0xc0, 0xa8, 0x00, 0x01, // Source: 192.168.0.1
            0xc0, 0xa8, 0x00, 0xc7, // Destination: 192.168.0.199
            // Payload (8 bytes)
            0xde, 0xad, 0xbe, 0xef,
            0xca, 0xfe, 0xba, 0xbe,
        ]);

        let packet = Ipv4Packet::from_bytes(raw.clone()).expect("Failed to parse Ipv4Packet");
        assert_eq!(packet.header.version, 4);
        assert_eq!(packet.header.header_length, 5);
        assert_eq!(packet.header.total_length, 28u16);
        assert_eq!(packet.header.source, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(packet.header.destination, Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(packet.payload, Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]));

        let serialized = packet.to_bytes();
        assert_eq!(&serialized[..], &raw[..]);
    }

    #[test]
    fn test_ipv4_packet_with_options_round_trip() {
        let raw = Bytes::from_static(&[
            // IPv4 header (20bytes + 8bytes option + 4bytes payload = 32bytes -> IHL=7)
            0x47, 0x00, 0x00, 0x20, // [0-3] Version(4), IHL(7=28bytes), DSCP/ECN, Total Length=32 bytes
            0x12, 0x34, 0x40, 0x00, // [4-7] Identification, Flags=DF(0x40), Fragment Offset
            0x40, 0x11, 0x00, 0x00, // [8-11] TTL=64, Protocol=17(UDP), Header Checksum (0 for now)
            0xc0, 0xa8, 0x00, 0x01, // [12-15] Source IP = 192.168.0.1
            0xc0, 0xa8, 0x00, 0x02, // [16-19] Destination IP = 192.168.0.2

            // IPv4 options (8bytes)
            // Option 1: 1byte NOP
            0x01,                   // [20] NOP (No Operation)

            // Option 2: 4bytes 
            0x87, 0x04, 0x12, 0x34, // [21-24] Option Type=RR(7), Copied=1, Class=0, Length=4, Data=[0x12, 0x34]

            // Option 3: EOL (End of Options List) with padding
            0x00,                   // [25] EOL (End of Options List)
            0x00,                   // [26] Padding
            0x00,                   // [27] Padding

            // Payload 4bytes
            0xde, 0xad, 0xbe, 0xef, // [28-31] Payload: deadbeef
        ]);

        let packet = Ipv4Packet::from_bytes(raw.clone()).expect("Failed to parse Ipv4Packet");

        assert_eq!(packet.header.version, 4);
        assert_eq!(packet.header.header_length, 7);
        assert_eq!(packet.header.total_length, 32);
        assert_eq!(packet.header.source, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(packet.header.destination, Ipv4Addr::new(192, 168, 0, 2));

        assert_eq!(
            packet.payload,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );

        assert_eq!(packet.header.options.len(), 3);
        assert_eq!(packet.header.options[0].header.number, Ipv4OptionType::NOP);
        assert_eq!(packet.header.options[1].header.copied, 1);
        assert_eq!(packet.header.options[1].header.class, 0);
        assert_eq!(packet.header.options[1].header.number, Ipv4OptionType::RR);
        assert_eq!(packet.header.options[1].header.number.value(), 7);
        assert_eq!(packet.header.options[1].header.length, Some(4));
        assert_eq!(packet.header.options[1].data.as_ref(), &[0x12, 0x34]);
        assert_eq!(packet.header.options[2].header.number, Ipv4OptionType::EOL);

        let serialized = packet.to_bytes();
        assert_eq!(&serialized[..], &raw[..]);
    }

    #[test]
    fn ipv4_option_packet_test() {
        let option = Ipv4OptionPacket {
            header: Ipv4OptionHeader {
                copied: 1,
                class: 0,
                number: Ipv4OptionType::LSR,
                length: Some(3),
            },
            data: Bytes::from_static(&[0x10]),
        };

        let mut buf = BytesMut::new();
        let ty = (option.header.copied << 7) | (option.header.class << 5) | (option.header.number.value() & 0x1F);
        buf.put_u8(ty);
        buf.put_u8(3);
        buf.put_slice(&[0x10]);

        assert_eq!(buf.freeze(), Bytes::from_static(&[0x83, 0x03, 0x10]));
    }

    #[test]
    #[should_panic(expected = "Payload too long")]
    fn ipv4_payload_too_long_should_panic() {
        let packet = Ipv4Packet {
            header: Ipv4Header {
                version: 4,
                header_length: 5,
                dscp: 0,
                ecn: 0,
                total_length: 24, // Header 20 + payload 4 = 24 but ...
                identification: 0,
                flags: 0,
                fragment_offset: 0,
                ttl: 64,
                next_level_protocol: IpNextProtocol::Udp,
                checksum: 0,
                source: Ipv4Addr::LOCALHOST,
                destination: Ipv4Addr::LOCALHOST,
                options: vec![],
            },
            payload: Bytes::from_static(&[0, 1, 2, 3, 4, 5]), // 6 bytes payload
        };

        // This should panic because the payload length exceeds the total_length specified in the header
        let _ = packet.to_bytes(); 
    }

    #[test]
    fn test_ipv4_checksum() {
        let raw = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, // checksum: 0
            0x0a, 0x00, 0x00, 0x01,
            0x0a, 0x00, 0x00, 0x02,
        ]);

        let mut packet = Ipv4Packet::from_bytes(raw.clone()).expect("Failed to parse");
        let computed = checksum(&packet);
        packet.header.checksum = computed;

        let serialized = packet.to_bytes();
        let reparsed = Ipv4Packet::from_bytes(serialized).expect("Reparse failed");

        // Check if the checksum matches
        assert_eq!(reparsed.header.checksum, computed);

        // Check if the serialized bytes match the original raw bytes
        let mut raw_copy = raw.to_vec();
        raw_copy[10] = (computed >> 8) as u8;
        raw_copy[11] = (computed & 0xff) as u8;
        assert_eq!(&packet.to_bytes()[..], &raw_copy[..]);
    }
}


