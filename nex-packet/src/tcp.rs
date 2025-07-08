//! A TCP packet abstraction.

use crate::ip::IpNextProtocol;
use crate::packet::Packet;

use crate::util::{self, Octets};
use std::net::{IpAddr, Ipv4Addr};
use std::net::Ipv6Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use nex_core::bitfield::{u16be, u32be, u4};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Minimum TCP Header Length
pub const TCP_HEADER_LEN: usize = 20;
/// Minimum TCP Data Offset
pub const TCP_MIN_DATA_OFFSET: u8 = 5;
/// Maximum TCP Option Length
pub const TCP_OPTION_MAX_LEN: usize = 40;
/// Maximum TCP Header Length (with options)
pub const TCP_HEADER_MAX_LEN: usize = TCP_HEADER_LEN + TCP_OPTION_MAX_LEN;

/// Represents a TCP Option Kind.
/// <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1>
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TcpOptionKind {
    EOL = 0,
    NOP = 1,
    MSS = 2,
    WSCALE = 3,
    SACK_PERMITTED = 4,
    SACK = 5,
    ECHO = 6,
    ECHO_REPLY = 7,
    TIMESTAMPS = 8,
    POCP = 9,
    POSP = 10,
    CC = 11,
    CC_NEW = 12,
    CC_ECHO = 13,
    ALT_CHECKSUM_REQ = 14,
    ALT_CHECKSUM_DATA = 15,
    SKEETER = 16,
    BUBBA = 17,
    TRAILER_CHECKSUM = 18,
    MD5_SIGNATURE = 19,
    SCPS_CAPABILITIES = 20,
    SELECTIVE_ACK = 21,
    RECORD_BOUNDARIES = 22,
    CORRUPTION_EXPERIENCED = 23,
    SNAP = 24,
    UNASSIGNED = 25,
    TCP_COMPRESSION_FILTER = 26,
    QUICK_START = 27,
    USER_TIMEOUT = 28,
    TCP_AO = 29,
    MPTCP = 30,
    RESERVED_31 = 31,
    RESERVED_32 = 32,
    RESERVED_33 = 33,
    FAST_OPEN_COOKIE = 34,
    TCP_ENO = 69,
    ACC_ECNO_0 = 172,
    ACC_ECNO_1 = 174,
    EXPERIMENT_1 = 253,
    EXPERIMENT_2 = 254,
    RESERVED(u8),
}

impl TcpOptionKind {
    /// Construct a TCP option kind from a u8.
    pub fn new(n: u8) -> TcpOptionKind {
        match n {
            0 => TcpOptionKind::EOL,
            1 => TcpOptionKind::NOP,
            2 => TcpOptionKind::MSS,
            3 => TcpOptionKind::WSCALE,
            4 => TcpOptionKind::SACK_PERMITTED,
            5 => TcpOptionKind::SACK,
            6 => TcpOptionKind::ECHO,
            7 => TcpOptionKind::ECHO_REPLY,
            8 => TcpOptionKind::TIMESTAMPS,
            9 => TcpOptionKind::POCP,
            10 => TcpOptionKind::POSP,
            11 => TcpOptionKind::CC,
            12 => TcpOptionKind::CC_NEW,
            13 => TcpOptionKind::CC_ECHO,
            14 => TcpOptionKind::ALT_CHECKSUM_REQ,
            15 => TcpOptionKind::ALT_CHECKSUM_DATA,
            16 => TcpOptionKind::SKEETER,
            17 => TcpOptionKind::BUBBA,
            18 => TcpOptionKind::TRAILER_CHECKSUM,
            19 => TcpOptionKind::MD5_SIGNATURE,
            20 => TcpOptionKind::SCPS_CAPABILITIES,
            21 => TcpOptionKind::SELECTIVE_ACK,
            22 => TcpOptionKind::RECORD_BOUNDARIES,
            23 => TcpOptionKind::CORRUPTION_EXPERIENCED,
            24 => TcpOptionKind::SNAP,
            25 => TcpOptionKind::UNASSIGNED,
            26 => TcpOptionKind::TCP_COMPRESSION_FILTER,
            27 => TcpOptionKind::QUICK_START,
            28 => TcpOptionKind::USER_TIMEOUT,
            29 => TcpOptionKind::TCP_AO,
            30 => TcpOptionKind::MPTCP,
            31 => TcpOptionKind::RESERVED_31,
            32 => TcpOptionKind::RESERVED_32,
            33 => TcpOptionKind::RESERVED_33,
            34 => TcpOptionKind::FAST_OPEN_COOKIE,
            69 => TcpOptionKind::TCP_ENO,
            172 => TcpOptionKind::ACC_ECNO_0,
            174 => TcpOptionKind::ACC_ECNO_1,
            253 => TcpOptionKind::EXPERIMENT_1,
            254 => TcpOptionKind::EXPERIMENT_2,
            _ => TcpOptionKind::RESERVED(n),
        }
    }

    /// Get the name of the TCP option kind.
    pub fn name(&self) -> &'static str {
        match *self {
            TcpOptionKind::EOL => "EOL",
            TcpOptionKind::NOP => "NOP",
            TcpOptionKind::MSS => "MSS",
            TcpOptionKind::WSCALE => "WSCALE",
            TcpOptionKind::SACK_PERMITTED => "SACK_PERMITTED",
            TcpOptionKind::SACK => "SACK",
            TcpOptionKind::ECHO => "ECHO",
            TcpOptionKind::ECHO_REPLY => "ECHO_REPLY",
            TcpOptionKind::TIMESTAMPS => "TIMESTAMPS",
            TcpOptionKind::POCP => "POCP",
            TcpOptionKind::POSP => "POSP",
            TcpOptionKind::CC => "CC",
            TcpOptionKind::CC_NEW => "CC_NEW",
            TcpOptionKind::CC_ECHO => "CC_ECHO",
            TcpOptionKind::ALT_CHECKSUM_REQ => "ALT_CHECKSUM_REQ",
            TcpOptionKind::ALT_CHECKSUM_DATA => "ALT_CHECKSUM_DATA",
            TcpOptionKind::SKEETER => "SKEETER",
            TcpOptionKind::BUBBA => "BUBBA",
            TcpOptionKind::TRAILER_CHECKSUM => "TRAILER_CHECKSUM",
            TcpOptionKind::MD5_SIGNATURE => "MD5_SIGNATURE",
            TcpOptionKind::SCPS_CAPABILITIES => "SCPS_CAPABILITIES",
            TcpOptionKind::SELECTIVE_ACK => "SELECTIVE_ACK",
            TcpOptionKind::RECORD_BOUNDARIES => "RECORD_BOUNDARIES",
            TcpOptionKind::CORRUPTION_EXPERIENCED => "CORRUPTION_EXPERIENCED",
            TcpOptionKind::SNAP => "SNAP",
            TcpOptionKind::UNASSIGNED => "UNASSIGNED",
            TcpOptionKind::TCP_COMPRESSION_FILTER => "TCP_COMPRESSION_FILTER",
            TcpOptionKind::QUICK_START => "QUICK_START",
            TcpOptionKind::USER_TIMEOUT => "USER_TIMEOUT",
            TcpOptionKind::TCP_AO => "TCP_AO",
            TcpOptionKind::MPTCP => "MPTCP",
            TcpOptionKind::RESERVED_31 => "RESERVED_31",
            TcpOptionKind::RESERVED_32 => "RESERVED_32",
            TcpOptionKind::RESERVED_33 => "RESERVED_33",
            TcpOptionKind::FAST_OPEN_COOKIE => "FAST_OPEN_COOKIE",
            TcpOptionKind::TCP_ENO => "TCP_ENO",
            TcpOptionKind::ACC_ECNO_0 => "ACC_ECNO_0",
            TcpOptionKind::ACC_ECNO_1 => "ACC_ECNO_1",
            TcpOptionKind::EXPERIMENT_1 => "EXPERIMENT_1",
            TcpOptionKind::EXPERIMENT_2 => "EXPERIMENT_2",
            TcpOptionKind::RESERVED(_) => "RESERVED",
        }
    }
    /// Get the value of the TCP option kind.
    pub fn value(&self) -> u8 {
        match *self {
            TcpOptionKind::EOL => 0,
            TcpOptionKind::NOP => 1,
            TcpOptionKind::MSS => 2,
            TcpOptionKind::WSCALE => 3,
            TcpOptionKind::SACK_PERMITTED => 4,
            TcpOptionKind::SACK => 5,
            TcpOptionKind::ECHO => 6,
            TcpOptionKind::ECHO_REPLY => 7,
            TcpOptionKind::TIMESTAMPS => 8,
            TcpOptionKind::POCP => 9,
            TcpOptionKind::POSP => 10,
            TcpOptionKind::CC => 11,
            TcpOptionKind::CC_NEW => 12,
            TcpOptionKind::CC_ECHO => 13,
            TcpOptionKind::ALT_CHECKSUM_REQ => 14,
            TcpOptionKind::ALT_CHECKSUM_DATA => 15,
            TcpOptionKind::SKEETER => 16,
            TcpOptionKind::BUBBA => 17,
            TcpOptionKind::TRAILER_CHECKSUM => 18,
            TcpOptionKind::MD5_SIGNATURE => 19,
            TcpOptionKind::SCPS_CAPABILITIES => 20,
            TcpOptionKind::SELECTIVE_ACK => 21,
            TcpOptionKind::RECORD_BOUNDARIES => 22,
            TcpOptionKind::CORRUPTION_EXPERIENCED => 23,
            TcpOptionKind::SNAP => 24,
            TcpOptionKind::UNASSIGNED => 25,
            TcpOptionKind::TCP_COMPRESSION_FILTER => 26,
            TcpOptionKind::QUICK_START => 27,
            TcpOptionKind::USER_TIMEOUT => 28,
            TcpOptionKind::TCP_AO => 29,
            TcpOptionKind::MPTCP => 30,
            TcpOptionKind::RESERVED_31 => 31,
            TcpOptionKind::RESERVED_32 => 32,
            TcpOptionKind::RESERVED_33 => 33,
            TcpOptionKind::FAST_OPEN_COOKIE => 34,
            TcpOptionKind::TCP_ENO => 69,
            TcpOptionKind::ACC_ECNO_0 => 172,
            TcpOptionKind::ACC_ECNO_1 => 174,
            TcpOptionKind::EXPERIMENT_1 => 253,
            TcpOptionKind::EXPERIMENT_2 => 254,
            TcpOptionKind::RESERVED(n) => n,
        }
    }
    /// Get size (bytes) of the TCP option.
    pub fn size(&self) -> usize {
        match *self {
            TcpOptionKind::EOL => 1,
            TcpOptionKind::NOP => 1,
            TcpOptionKind::MSS => 4,
            TcpOptionKind::WSCALE => 3,
            TcpOptionKind::SACK_PERMITTED => 2,
            TcpOptionKind::SACK => 10,
            TcpOptionKind::ECHO => 6,
            TcpOptionKind::ECHO_REPLY => 6,
            TcpOptionKind::TIMESTAMPS => 10,
            TcpOptionKind::POCP => 2,
            TcpOptionKind::POSP => 3,
            TcpOptionKind::ALT_CHECKSUM_REQ => 3,
            TcpOptionKind::ALT_CHECKSUM_DATA => 12,
            TcpOptionKind::TRAILER_CHECKSUM => 3,
            TcpOptionKind::MD5_SIGNATURE => 18,
            TcpOptionKind::QUICK_START => 8,
            TcpOptionKind::USER_TIMEOUT => 4,
            _ => 0,
        }
    }
}

/// Represents the TCP Flags
/// <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-header-flags>
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod TcpFlags {
    /// CWR – Congestion Window Reduced (CWR) flag is set by the sending
    /// host to indicate that it received a TCP segment with the ECE flag set
    /// and had responded in congestion control mechanism.
    pub const CWR: u8 = 0b10000000;
    /// ECE – ECN-Echo has a dual role, depending on the value of the
    /// SYN flag. It indicates:
    /// If the SYN flag is set (1), that the TCP peer is ECN capable.
    /// If the SYN flag is clear (0), that a packet with Congestion Experienced
    /// flag set (ECN=11) in IP header received during normal transmission.
    pub const ECE: u8 = 0b01000000;
    /// URG – indicates that the Urgent pointer field is significant.
    pub const URG: u8 = 0b00100000;
    /// ACK – indicates that the Acknowledgment field is significant.
    /// All packets after the initial SYN packet sent by the client should have this flag set.
    pub const ACK: u8 = 0b00010000;
    /// PSH – Push function. Asks to push the buffered data to the receiving application.
    pub const PSH: u8 = 0b00001000;
    /// RST – Reset the connection.
    pub const RST: u8 = 0b00000100;
    /// SYN – Synchronize sequence numbers. Only the first packet sent from each end
    /// should have this flag set.
    pub const SYN: u8 = 0b00000010;
    /// FIN – No more data from sender.
    pub const FIN: u8 = 0b00000001;
}

/// Represents the TCP option header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpOptionHeader {
    pub kind: TcpOptionKind,
    pub length: Option<u8>,
    pub data: Bytes,
}

impl TcpOptionHeader {
    /// Get the timestamp of the TCP option
    pub fn get_timestamp(&self) -> (u32, u32) {
        if self.kind == TcpOptionKind::TIMESTAMPS && self.data.len() >= 8 {
            let mut my: [u8; 4] = [0; 4];
            my.copy_from_slice(&self.data[0..4]);
            let mut their: [u8; 4] = [0; 4];
            their.copy_from_slice(&self.data[4..8]);
            (u32::from_be_bytes(my), u32::from_be_bytes(their))
        } else {
            return (0, 0);
        }
    }
    /// Get the MSS of the TCP option
    pub fn get_mss(&self) -> u16 {
        if self.kind == TcpOptionKind::MSS && self.data.len() >= 2 {
            let mut mss: [u8; 2] = [0; 2];
            mss.copy_from_slice(&self.data[0..2]);
            u16::from_be_bytes(mss)
        } else {
            0
        }
    }
    /// Get the WSCALE of the TCP option
    pub fn get_wscale(&self) -> u8 {
        if self.kind == TcpOptionKind::WSCALE && self.data.len() > 0 {
            self.data[0]
        } else {
            0
        }
    }
}

/// A TCP option.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpOptionPacket {
    kind: TcpOptionKind,
    length: Option<u8>,
    data: Bytes,
}

impl TcpOptionPacket {
    /// NOP: This may be used to align option fields on 32-bit boundaries for better performance.
    pub fn nop() -> Self {
        TcpOptionPacket {
            kind: TcpOptionKind::NOP,
            length: None,
            data: Bytes::new(),
        }
    }

    /// Timestamp: TCP timestamps, defined in RFC 1323, can help TCP determine in which order
    /// packets were sent. TCP timestamps are not normally aligned to the system clock and
    /// start at some random value.
    pub fn timestamp(my: u32, their: u32) -> Self {
        let mut data = BytesMut::new();
        data.extend_from_slice(&my.octets()[..]);
        data.extend_from_slice(&their.octets()[..]);

        TcpOptionPacket {
            kind: TcpOptionKind::TIMESTAMPS,
            length: Some(10),
            data: data.freeze(),
        }
    }

    /// MSS: The maximum segment size (MSS) is the largest amount of data, specified in bytes,
    /// that TCP is willing to receive in a single segment.
    pub fn mss(val: u16) -> Self {
        let mut data = BytesMut::new();
        data.extend_from_slice(&val.octets()[..]);

        TcpOptionPacket {
            kind: TcpOptionKind::MSS,
            length: Some(4),
            data: data.freeze(),
        }
    }

    /// Window scale: The TCP window scale option, as defined in RFC 1323, is an option used to
    /// increase the maximum window size from 65,535 bytes to 1 gigabyte.
    pub fn wscale(val: u8) -> Self {
        TcpOptionPacket {
            kind: TcpOptionKind::WSCALE,
            length: Some(3),
            data: Bytes::from(vec![val]),
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. This options enables use of
    /// SACK during negotiation.
    pub fn sack_perm() -> Self {
        TcpOptionPacket {
            kind: TcpOptionKind::SACK_PERMITTED,
            length: Some(2),
            data: Bytes::new(),
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. The acknowledgement can specify
    /// a number of SACK blocks, where each SACK block is conveyed by the starting and ending sequence
    /// numbers of a contiguous range that the receiver correctly received.
    pub fn selective_ack(acks: &[u32]) -> Self {
        let mut data = BytesMut::new();
        for ack in acks {
            data.extend_from_slice(&ack.octets()[..]);
        }
        TcpOptionPacket {
            kind: TcpOptionKind::SACK,
            length: Some(1 /* number */ + 1 /* length */ + data.len() as u8),
            data: data.freeze(),
        }
    }
    /// Get the TCP option kind.
    pub fn kind(&self) -> TcpOptionKind {
        self.kind
    }
    /// Get length of the TCP option.
    pub fn length(&self) -> u8 {
        if let Some(len) = self.length {
            len
        } else {
            // If length is None, it means the option has no length (like NOP).
            0
        }
    }
    /// Get the timestamp of the TCP option
    pub fn get_timestamp(&self) -> (u32, u32) {
        if self.kind == TcpOptionKind::TIMESTAMPS && self.data.len() >= 8 {
            let mut my: [u8; 4] = [0; 4];
            my.copy_from_slice(&self.data[0..4]);
            let mut their: [u8; 4] = [0; 4];
            their.copy_from_slice(&self.data[4..8]);
            (u32::from_be_bytes(my), u32::from_be_bytes(their))
        } else {
            return (0, 0);
        }
    }
    /// Get the MSS of the TCP option
    pub fn get_mss(&self) -> u16 {
        if self.kind == TcpOptionKind::MSS && self.data.len() >= 2 {
            let mut mss: [u8; 2] = [0; 2];
            mss.copy_from_slice(&self.data[0..2]);
            u16::from_be_bytes(mss)
        } else {
            0
        }
    }
    /// Get the WSCALE of the TCP option
    pub fn get_wscale(&self) -> u8 {
        if self.kind == TcpOptionKind::WSCALE && self.data.len() > 0 {
            self.data[0]
        } else {
            0
        }
    }
}

/// Represents the TCP header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpHeader {
    pub source: u16be,
    pub destination: u16be,
    pub sequence: u32be,
    pub acknowledgement: u32be,
    pub data_offset: u4,
    pub reserved: u4,
    pub flags: u8,
    pub window: u16be,
    pub checksum: u16be,
    pub urgent_ptr: u16be,
    pub options: Vec<TcpOptionPacket>,
}

/// Represents a TCP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpPacket {
    pub header: TcpHeader,
    pub payload: Bytes,
}

impl Packet for TcpPacket {
    type Header = TcpHeader;

    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TCP_HEADER_LEN {
            return None;
        }

        let source = bytes.get_u16();
        let destination = bytes.get_u16();
        let sequence = bytes.get_u32();
        let acknowledgement = bytes.get_u32();

        let offset_reserved = bytes.get_u8();
        let data_offset = offset_reserved >> 4;
        let reserved = offset_reserved & 0x0F;

        let flags = bytes.get_u8();
        let window = bytes.get_u16();
        let checksum = bytes.get_u16();
        let urgent_ptr = bytes.get_u16();

        let header_len = data_offset as usize * 4;
        if header_len < TCP_HEADER_LEN || bytes.len() + 20 < header_len {
            return None;
        }

        let mut options = Vec::new();
        let options_len = header_len - TCP_HEADER_LEN;
        let (mut options_bytes, rest) = bytes.split_at(options_len);
        bytes = rest;

        while options_bytes.has_remaining() {
            let kind = TcpOptionKind::new(options_bytes.get_u8());
            match kind {
                TcpOptionKind::EOL => {
                    options.push(TcpOptionPacket { kind, length: None, data: Bytes::new() });
                    break;
                }
                TcpOptionKind::NOP => {
                    options.push(TcpOptionPacket { kind, length: None, data: Bytes::new() });
                }
                _ => {
                    if options_bytes.remaining() < 1 {
                        return None;
                    }
                    let len = options_bytes.get_u8();
                    if len < 2 || (len as usize) > options_bytes.remaining() + 2 {
                        return None;
                    }
                    let data_len = (len - 2) as usize;
                    let (data_slice, rest) = options_bytes.split_at(data_len);
                    options_bytes = rest;
                    options.push(TcpOptionPacket {
                        kind,
                        length: Some(len),
                        data: Bytes::copy_from_slice(data_slice),
                    });
                }
            }
        }

        Some(TcpPacket {
            header: TcpHeader {
                source,
                destination,
                sequence,
                acknowledgement,
                data_offset: u4::from_be(data_offset),
                reserved: u4::from_be(reserved),
                flags,
                window,
                checksum,
                urgent_ptr,
                options,
            },
            payload: Bytes::copy_from_slice(bytes),
        })
    }
    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)   
    }
    
    fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.header_len() + self.payload.len());

        bytes.put_u16(self.header.source);
        bytes.put_u16(self.header.destination);
        bytes.put_u32(self.header.sequence);
        bytes.put_u32(self.header.acknowledgement);

        let offset_reserved = (self.header.data_offset.to_be() << 4) | (self.header.reserved.to_be() & 0x0F);
        bytes.put_u8(offset_reserved);

        bytes.put_u8(self.header.flags);
        bytes.put_u16(self.header.window);
        bytes.put_u16(self.header.checksum);
        bytes.put_u16(self.header.urgent_ptr);

        for option in &self.header.options {
            bytes.put_u8(option.kind.value());
            if let Some(length) = option.length {
                bytes.put_u8(length);
                bytes.extend_from_slice(&option.data);
            }
        }

        // Padding to 4-byte alignment
        while bytes.len() % 4 != 0 {
            bytes.put_u8(0);
        }

        bytes.extend_from_slice(&self.payload);

        bytes.freeze()
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(..self.header_len())
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        let base = TCP_HEADER_LEN;
        let mut opt_len = 0;

        for opt in &self.header.options {
            match opt.kind {
                TcpOptionKind::EOL | TcpOptionKind::NOP => {
                    opt_len += 1; // EOL and NOP are one byte
                }
                _ => {
                    // kind(1B) + length(1B) + payload
                    if let Some(len) = opt.length {
                        opt_len += len as usize;
                    } else {
                        // Ensure at least 2 bytes (kind + length)
                        opt_len += 2;
                    }
                }
            }
        }

        let total = base + opt_len;
        // The TCP header is always rounded to a 4 byte boundary
        (total + 3) & !0x03
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

impl TcpPacket {
    pub fn tcp_options_length(&self) -> usize {
        if self.header.data_offset > 5 {
            self.header.data_offset as usize * 4 - 20
        } else {
            0
        }
    }
}

pub fn checksum(packet: &TcpPacket, source: &IpAddr, destination: &IpAddr) -> u16 {
    match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => ipv4_checksum(packet, src, dst),
        (IpAddr::V6(src), IpAddr::V6(dst)) => ipv6_checksum(packet, src, dst),
        _ => 0, // Unsupported IP version
    }
}

/// Calculate a checksum for a packet built on IPv4.
pub fn ipv4_checksum(packet: &TcpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16 {
    ipv4_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv4, Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv4_checksum_adv(
    packet: &TcpPacket,
    extra_data: &[u8],
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
) -> u16 {
    util::ipv4_checksum(
        &packet.to_bytes(),
        8,
        extra_data,
        source,
        destination,
        IpNextProtocol::Tcp,
    )
}

/// Calculate a checksum for a packet built on IPv6.
pub fn ipv6_checksum(packet: &TcpPacket, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16 {
    ipv6_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv6, Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv6_checksum_adv(
    packet: &TcpPacket,
    extra_data: &[u8],
    source: &Ipv6Addr,
    destination: &Ipv6Addr,
) -> u16 {
    util::ipv6_checksum(
        &packet.to_bytes(),
        8,
        extra_data,
        source,
        destination,
        IpNextProtocol::Tcp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tcp_parse() {
        let ref_packet = Bytes::from_static(&[
            0xc1, 0x67, /* source */
            0x23, 0x28, /* destination */
            0x90, 0x37, 0xd2, 0xb8, /* seq */
            0x94, 0x4b, 0xb2, 0x76, /* ack */
            0x80, 0x18, 0x0f, 0xaf, /* offset+reserved, flags, win */
            0xc0, 0x31, /* checksum */
            0x00, 0x00, /* urg ptr */
            0x01, 0x01, /* NOP */
            0x08, 0x0a, 0x2c, 0x57, 0xcd, 0xa5, 0x02, 0xa0, 0x41, 0x92, /* timestamp */
            0x74, 0x65, 0x73, 0x74, /* payload: "test" */
        ]);
        let packet = TcpPacket::from_bytes(ref_packet.clone()).unwrap();

        assert_eq!(packet.header.source, 0xc167);
        assert_eq!(packet.header.destination, 0x2328);
        assert_eq!(packet.header.sequence, 0x9037d2b8);
        assert_eq!(packet.header.acknowledgement, 0x944bb276);
        assert_eq!(packet.header.data_offset, 8); // adjusted
        assert_eq!(packet.header.reserved, 0);
        assert_eq!(packet.header.flags, 0x18); // PSH + ACK
        assert_eq!(packet.header.window, 0x0faf);
        assert_eq!(packet.header.checksum, 0xc031);
        assert_eq!(packet.header.urgent_ptr, 0x0000);
        assert_eq!(packet.header.options.len(), 3);
        assert_eq!(packet.header.options[0].kind, TcpOptionKind::NOP);
        assert_eq!(packet.header.options[1].kind, TcpOptionKind::NOP);
        assert_eq!(packet.header.options[2].kind, TcpOptionKind::TIMESTAMPS);
        assert_eq!(
            packet.header.options[2].get_timestamp(),
            (0x2c57cda5, 0x02a04192)
        );
        assert_eq!(packet.payload, Bytes::from_static(b"test"));
        assert_eq!(packet.header_len(), 32); // adjusted
        assert_eq!(packet.to_bytes(), ref_packet);
        assert_eq!(packet.header().len(), 32); // adjusted
        assert_eq!(packet.payload().len(), 4);
    }

    #[test]
    fn test_basic_tcp_create() {
        let options = vec![
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(0x2c57cda5, 0x02a04192),
        ];

        let packet = TcpPacket {
            header: TcpHeader {
                source: 0xc167,
                destination: 0x2328,
                sequence: 0x9037d2b8,
                acknowledgement: 0x944bb276,
                data_offset: 8.into(), // 8 * 4 = 32 bytes
                reserved: 0.into(),
                flags: 0x18, // PSH + ACK
                window: 0x0faf,
                checksum: 0xc031,
                urgent_ptr: 0x0000,
                options: options.clone(),
            },
            payload: Bytes::from_static(b"test"),
        };

        let bytes = packet.to_bytes();
        let parsed = TcpPacket::from_bytes(bytes.clone()).expect("Failed to parse TCP packet");

        assert_eq!(parsed, packet);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.header.options.len(), 3);
        assert_eq!(parsed.header.options[2].get_timestamp(), (0x2c57cda5, 0x02a04192));
    }

}
