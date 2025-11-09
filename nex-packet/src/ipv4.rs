//! An IPv4 packet abstraction.

use crate::{
    checksum::{ChecksumMode, ChecksumState},
    ip::IpNextProtocol,
    packet::{MutablePacket, Packet},
    util,
};
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
        let total_length = if total_length > bytes.len() {
            // fallback
            bytes.len()
        } else {
            total_length
        };

        if header_length < 5 {
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
            let type_byte =
                (option.header.copied << 7) | (option.header.class << 5) | (number & 0b0001_1111);
            tmp_buf.put_u8(type_byte);

            match option.header.number {
                Ipv4OptionType::EOL | Ipv4OptionType::NOP => {}
                _ => {
                    let len = option
                        .header
                        .length
                        .unwrap_or((option.data.len() + 2) as u8);
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

/// Represents a mutable IPv4 packet.
pub struct MutableIpv4Packet<'a> {
    buffer: &'a mut [u8],
    checksum: ChecksumState,
}

impl<'a> MutablePacket<'a> for MutableIpv4Packet<'a> {
    type Packet = Ipv4Packet;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < IPV4_HEADER_LEN {
            return None;
        }

        let ihl = (buffer[0] & 0x0F) as usize;
        if ihl < 5 {
            return None;
        }

        let header_len = ihl * IPV4_HEADER_LENGTH_BYTE_UNITS;
        if header_len > buffer.len() {
            return None;
        }

        let total_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        if total_len != 0 && total_len < header_len {
            return None;
        }

        Some(Self {
            buffer,
            checksum: ChecksumState::new(),
        })
    }

    fn packet(&self) -> &[u8] {
        &*self.buffer
    }

    fn packet_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn header(&self) -> &[u8] {
        let header_len = self.header_len();
        &self.packet()[..header_len]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        let (header, _) = (&mut *self.buffer).split_at_mut(header_len);
        header
    }

    fn payload(&self) -> &[u8] {
        let start = self.header_len();
        let end = start + self.payload_len();
        &self.packet()[start..end]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        let payload_len = self.payload_len();
        let (_, payload) = (&mut *self.buffer).split_at_mut(header_len);
        &mut payload[..payload_len]
    }
}

impl<'a> MutableIpv4Packet<'a> {
    /// Create a mutable packet without validating the header fields.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            checksum: ChecksumState::new(),
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

    fn write_checksum(&mut self, checksum: u16) {
        self.raw_mut()[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    /// Returns the current checksum recalculation mode.
    pub fn checksum_mode(&self) -> ChecksumMode {
        self.checksum.mode()
    }

    /// Updates the checksum recalculation mode.
    pub fn set_checksum_mode(&mut self, mode: ChecksumMode) {
        self.checksum.set_mode(mode);
        if self.checksum.automatic() && self.checksum.is_dirty() {
            let _ = self.recompute_checksum();
        }
    }

    /// Enables automatic checksum recalculation.
    pub fn enable_auto_checksum(&mut self) {
        self.set_checksum_mode(ChecksumMode::Automatic);
    }

    /// Disables automatic checksum recalculation.
    pub fn disable_auto_checksum(&mut self) {
        self.set_checksum_mode(ChecksumMode::Manual);
    }

    /// Returns true when the checksum must be recomputed before serialization.
    pub fn is_checksum_dirty(&self) -> bool {
        self.checksum.is_dirty()
    }

    /// Marks the checksum as stale and triggers recomputation when automatic mode is enabled.
    pub fn mark_checksum_dirty(&mut self) {
        self.checksum.mark_dirty();
        if self.checksum.automatic() {
            let _ = self.recompute_checksum();
        }
    }

    /// Recomputes the IPv4 header checksum using the current buffer contents.
    pub fn recompute_checksum(&mut self) -> Option<u16> {
        let header_len = self.header_len();
        if header_len > self.raw().len() {
            return None;
        }

        let checksum = util::checksum(&self.raw()[..header_len], 5) as u16;
        self.write_checksum(checksum);
        self.checksum.clear_dirty();
        Some(checksum)
    }

    /// Returns the header length in bytes.
    pub fn header_len(&self) -> usize {
        let ihl = (self.raw()[0] & 0x0F) as usize;
        let header_len = ihl * IPV4_HEADER_LENGTH_BYTE_UNITS;
        header_len.max(IPV4_HEADER_LEN).min(self.raw().len())
    }

    /// Returns the payload length based on the total length field.
    pub fn payload_len(&self) -> usize {
        let total = self.total_len();
        total.saturating_sub(self.header_len())
    }

    /// Returns the effective total length of the packet.
    pub fn total_len(&self) -> usize {
        let total = u16::from_be_bytes([self.raw()[2], self.raw()[3]]) as usize;
        if total == 0 {
            self.raw().len()
        } else {
            total.min(self.raw().len())
        }
    }

    /// Retrieve the version field.
    pub fn get_version(&self) -> u8 {
        self.raw()[0] >> 4
    }

    /// Update the version field.
    pub fn set_version(&mut self, version: u8) {
        let buffer = self.raw_mut();
        buffer[0] = (buffer[0] & 0x0F) | ((version & 0x0F) << 4);
        self.after_field_mutation();
    }

    /// Retrieve the header length in 32-bit words.
    pub fn get_header_length(&self) -> u8 {
        self.raw()[0] & 0x0F
    }

    /// Update the header length in 32-bit words.
    pub fn set_header_length(&mut self, ihl: u8) {
        let buffer = self.raw_mut();
        buffer[0] = (buffer[0] & 0xF0) | (ihl & 0x0F);
        self.after_field_mutation();
    }

    /// Retrieve the DSCP field.
    pub fn get_dscp(&self) -> u8 {
        self.raw()[1] >> 2
    }

    /// Update the DSCP field.
    pub fn set_dscp(&mut self, dscp: u8) {
        let buffer = self.raw_mut();
        buffer[1] = (buffer[1] & 0x03) | ((dscp & 0x3F) << 2);
        self.after_field_mutation();
    }

    /// Retrieve the ECN field.
    pub fn get_ecn(&self) -> u8 {
        self.raw()[1] & 0x03
    }

    /// Update the ECN field.
    pub fn set_ecn(&mut self, ecn: u8) {
        let buffer = self.raw_mut();
        buffer[1] = (buffer[1] & 0xFC) | (ecn & 0x03);
        self.after_field_mutation();
    }

    /// Retrieve the total length field.
    pub fn get_total_length(&self) -> u16 {
        u16::from_be_bytes([self.raw()[2], self.raw()[3]])
    }

    /// Update the total length field.
    pub fn set_total_length(&mut self, len: u16) {
        self.raw_mut()[2..4].copy_from_slice(&len.to_be_bytes());
        self.after_field_mutation();
    }

    /// Retrieve the identification field.
    pub fn get_identification(&self) -> u16 {
        u16::from_be_bytes([self.raw()[4], self.raw()[5]])
    }

    /// Update the identification field.
    pub fn set_identification(&mut self, id: u16) {
        self.raw_mut()[4..6].copy_from_slice(&id.to_be_bytes());
        self.after_field_mutation();
    }

    /// Retrieve the flags field.
    pub fn get_flags(&self) -> u8 {
        (self.raw()[6] & 0xE0) >> 5
    }

    /// Update the flags field.
    pub fn set_flags(&mut self, flags: u8) {
        let buffer = self.raw_mut();
        buffer[6] = (buffer[6] & 0x1F) | ((flags & 0x07) << 5);
        self.after_field_mutation();
    }

    /// Retrieve the fragment offset field.
    pub fn get_fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.raw()[6], self.raw()[7]]) & 0x1FFF
    }

    /// Update the fragment offset field.
    pub fn set_fragment_offset(&mut self, offset: u16) {
        let buffer = self.raw_mut();
        let combined = (u16::from_be_bytes([buffer[6], buffer[7]]) & 0xE000) | (offset & 0x1FFF);
        buffer[6..8].copy_from_slice(&combined.to_be_bytes());
        self.after_field_mutation();
    }

    /// Retrieve the TTL field.
    pub fn get_ttl(&self) -> u8 {
        self.raw()[8]
    }

    /// Update the TTL field.
    pub fn set_ttl(&mut self, ttl: u8) {
        self.raw_mut()[8] = ttl;
        self.after_field_mutation();
    }

    /// Retrieve the next-level protocol field.
    pub fn get_next_level_protocol(&self) -> IpNextProtocol {
        IpNextProtocol::new(self.raw()[9])
    }

    /// Update the next-level protocol field.
    pub fn set_next_level_protocol(&mut self, proto: IpNextProtocol) {
        self.raw_mut()[9] = proto.value();
        self.after_field_mutation();
    }

    /// Retrieve the checksum field.
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes([self.raw()[10], self.raw()[11]])
    }

    /// Update the checksum field.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.write_checksum(checksum);
        self.checksum.clear_dirty();
    }

    /// Retrieve the source address.
    pub fn get_source(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.raw()[12],
            self.raw()[13],
            self.raw()[14],
            self.raw()[15],
        )
    }

    /// Update the source address.
    pub fn set_source(&mut self, addr: Ipv4Addr) {
        self.raw_mut()[12..16].copy_from_slice(&addr.octets());
        self.after_field_mutation();
    }

    /// Retrieve the destination address.
    pub fn get_destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.raw()[16],
            self.raw()[17],
            self.raw()[18],
            self.raw()[19],
        )
    }

    /// Update the destination address.
    pub fn set_destination(&mut self, addr: Ipv4Addr) {
        self.raw_mut()[16..20].copy_from_slice(&addr.octets());
        self.after_field_mutation();
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
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ]);

        let packet = Ipv4Packet::from_bytes(raw.clone()).expect("Failed to parse Ipv4Packet");
        assert_eq!(packet.header.version, 4);
        assert_eq!(packet.header.header_length, 5);
        assert_eq!(packet.header.total_length, 28u16);
        assert_eq!(packet.header.source, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(packet.header.destination, Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(
            packet.payload,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe])
        );

        let serialized = packet.to_bytes();
        assert_eq!(&serialized[..], &raw[..]);
    }

    #[test]
    fn test_ipv4_packet_with_options_round_trip() {
        let raw = Bytes::from_static(&[
            // IPv4 header (20bytes + 8bytes option + 4bytes payload = 32bytes -> IHL=7)
            0x47, 0x00, 0x00,
            0x20, // [0-3] Version(4), IHL(7=28bytes), DSCP/ECN, Total Length=32 bytes
            0x12, 0x34, 0x40, 0x00, // [4-7] Identification, Flags=DF(0x40), Fragment Offset
            0x40, 0x11, 0x00,
            0x00, // [8-11] TTL=64, Protocol=17(UDP), Header Checksum (0 for now)
            0xc0, 0xa8, 0x00, 0x01, // [12-15] Source IP = 192.168.0.1
            0xc0, 0xa8, 0x00, 0x02, // [16-19] Destination IP = 192.168.0.2
            // IPv4 options (8bytes)
            // Option 1: 1byte NOP
            0x01, // [20] NOP (No Operation)
            // Option 2: 4bytes
            0x87, 0x04, 0x12,
            0x34, // [21-24] Option Type=RR(7), Copied=1, Class=0, Length=4, Data=[0x12, 0x34]
            // Option 3: EOL (End of Options List) with padding
            0x00, // [25] EOL (End of Options List)
            0x00, // [26] Padding
            0x00, // [27] Padding
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
        let ty = (option.header.copied << 7)
            | (option.header.class << 5)
            | (option.header.number.value() & 0x1F);
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
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00,
            0x00, // checksum: 0
            0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
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

    #[test]
    fn test_mutable_ipv4_packet_updates() {
        let mut raw = [
            0x45, 0x00, 0x00, 0x1c, // Version + IHL, DSCP/ECN, Total Length
            0x1c, 0x46, 0x40, 0x00, // Identification, Flags/Fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Header checksum
            0xc0, 0xa8, 0x00, 0x01, // Source
            0xc0, 0xa8, 0x00, 0xc7, // Destination
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // Payload
        ];

        let mut packet = MutableIpv4Packet::new(&mut raw).expect("mutable ipv4");
        assert_eq!(packet.get_version(), 4);
        assert_eq!(packet.get_ttl(), 0x40);

        packet.set_ttl(128);
        packet.set_destination(Ipv4Addr::new(192, 0, 2, 1));
        packet.payload_mut()[0] = 0x11;

        {
            let packet_view = packet.packet();
            assert_eq!(packet_view[8], 128);
            assert_eq!(&packet_view[16..20], &[192, 0, 2, 1]);
            assert_eq!(packet_view[20], 0x11);
        }

        let frozen = packet.freeze().expect("freeze mutable packet");
        drop(packet);

        assert_eq!(raw[8], 128);
        assert_eq!(&raw[16..20], &[192, 0, 2, 1]);
        assert_eq!(raw[20], 0x11);

        assert_eq!(frozen.header.ttl, 128);
        assert_eq!(frozen.header.destination, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(frozen.payload[0], 0x11);
    }

    #[test]
    fn test_ipv4_auto_checksum_updates() {
        let mut raw = [
            0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ];

        let mut packet = MutableIpv4Packet::new(&mut raw).expect("mutable ipv4");
        packet.enable_auto_checksum();
        let baseline = packet.recompute_checksum().expect("checksum");
        let before = packet.get_checksum();
        assert_eq!(baseline, before);

        packet.set_ttl(0x41);
        let after = packet.get_checksum();
        assert_ne!(before, after);
        assert!(!packet.is_checksum_dirty());

        let frozen = packet.freeze().expect("freeze");
        let expected = checksum(&frozen);
        assert_eq!(after, expected);
    }

    #[test]
    fn test_ipv4_manual_checksum_tracking() {
        let mut raw = [
            0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        ];

        let mut packet = MutableIpv4Packet::new(&mut raw).expect("mutable ipv4");
        assert!(!packet.is_checksum_dirty());

        packet.set_identification(0x1c47);
        assert!(packet.is_checksum_dirty());

        let recomputed = packet.recompute_checksum().expect("checksum");
        assert_eq!(recomputed, packet.get_checksum());
        assert!(!packet.is_checksum_dirty());
    }
}
