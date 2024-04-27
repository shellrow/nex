//! A TCP packet abstraction.

use crate::ip::IpNextLevelProtocol;
use crate::Packet;
use crate::PrimitiveValues;

use alloc::{vec, vec::Vec};

use nex_macro::packet;
use nex_macro_helper::types::*;

use crate::util::{self, Octets};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Minimum TCP Header Length
pub const TCP_HEADER_LEN: usize = MutableTcpPacket::minimum_packet_size();
/// Minimum TCP Data Offset
pub const TCP_MIN_DATA_OFFSET: u8 = 5;
/// Maximum TCP Option Length
pub const TCP_OPTION_MAX_LEN: usize = 40;
/// Maximum TCP Header Length (with options)
pub const TCP_HEADER_MAX_LEN: usize = TCP_HEADER_LEN + TCP_OPTION_MAX_LEN;

/// Represents the TCP option header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpOptionHeader {
    pub kind: TcpOptionKind,
    pub length: Option<u8>,
    pub data: Vec<u8>,
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
    pub options: Vec<TcpOptionHeader>,
}

impl TcpHeader {
    /// Construct a TCP header from a byte slice.
    pub fn from_bytes(packet: &[u8]) -> Result<TcpHeader, String> {
        if packet.len() < TCP_HEADER_LEN {
            return Err("Packet is too small for TCP header".to_string());
        }
        match TcpPacket::new(packet) {
            Some(tcp_packet) => Ok(TcpHeader {
                source: tcp_packet.get_source(),
                destination: tcp_packet.get_destination(),
                sequence: tcp_packet.get_sequence(),
                acknowledgement: tcp_packet.get_acknowledgement(),
                data_offset: tcp_packet.get_data_offset(),
                reserved: tcp_packet.get_reserved(),
                flags: tcp_packet.get_flags(),
                window: tcp_packet.get_window(),
                checksum: tcp_packet.get_checksum(),
                urgent_ptr: tcp_packet.get_urgent_ptr(),
                options: tcp_packet
                    .get_options_iter()
                    .map(|opt| TcpOptionHeader {
                        kind: opt.get_kind(),
                        length: opt.get_length_raw().first().cloned(),
                        data: opt.payload().to_vec(),
                    })
                    .collect(),
            }),
            None => Err("Failed to parse TCP packet".to_string()),
        }
    }
    /// Construct a TCP header from a TcpPacket.
    pub(crate) fn from_packet(tcp_packet: &TcpPacket) -> TcpHeader {
        TcpHeader {
            source: tcp_packet.get_source(),
            destination: tcp_packet.get_destination(),
            sequence: tcp_packet.get_sequence(),
            acknowledgement: tcp_packet.get_acknowledgement(),
            data_offset: tcp_packet.get_data_offset(),
            reserved: tcp_packet.get_reserved(),
            flags: tcp_packet.get_flags(),
            window: tcp_packet.get_window(),
            checksum: tcp_packet.get_checksum(),
            urgent_ptr: tcp_packet.get_urgent_ptr(),
            options: tcp_packet
                .get_options_iter()
                .map(|opt| TcpOptionHeader {
                    kind: opt.get_kind(),
                    length: opt.get_length_raw().first().cloned(),
                    data: opt.payload().to_vec(),
                })
                .collect(),
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

/// Represents a TCP packet.
#[packet]
pub struct Tcp {
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
    #[length_fn = "tcp_options_length"]
    pub options: Vec<TcpOption>,
    #[payload]
    pub payload: Vec<u8>,
}

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
    pub fn name(&self) -> String {
        match *self {
            TcpOptionKind::EOL => String::from("EOL"),
            TcpOptionKind::NOP => String::from("NOP"),
            TcpOptionKind::MSS => String::from("MSS"),
            TcpOptionKind::WSCALE => String::from("WSCALE"),
            TcpOptionKind::SACK_PERMITTED => String::from("SACK_PERMITTED"),
            TcpOptionKind::SACK => String::from("SACK"),
            TcpOptionKind::ECHO => String::from("ECHO"),
            TcpOptionKind::ECHO_REPLY => String::from("ECHO_REPLY"),
            TcpOptionKind::TIMESTAMPS => String::from("TIMESTAMPS"),
            TcpOptionKind::POCP => String::from("POCP"),
            TcpOptionKind::POSP => String::from("POSP"),
            TcpOptionKind::CC => String::from("CC"),
            TcpOptionKind::CC_NEW => String::from("CC_NEW"),
            TcpOptionKind::CC_ECHO => String::from("CC_ECHO"),
            TcpOptionKind::ALT_CHECKSUM_REQ => String::from("ALT_CHECKSUM_REQ"),
            TcpOptionKind::ALT_CHECKSUM_DATA => String::from("ALT_CHECKSUM_DATA"),
            TcpOptionKind::SKEETER => String::from("SKEETER"),
            TcpOptionKind::BUBBA => String::from("BUBBA"),
            TcpOptionKind::TRAILER_CHECKSUM => String::from("TRAILER_CHECKSUM"),
            TcpOptionKind::MD5_SIGNATURE => String::from("MD5_SIGNATURE"),
            TcpOptionKind::SCPS_CAPABILITIES => String::from("SCPS_CAPABILITIES"),
            TcpOptionKind::SELECTIVE_ACK => String::from("SELECTIVE_ACK"),
            TcpOptionKind::RECORD_BOUNDARIES => String::from("RECORD_BOUNDARIES"),
            TcpOptionKind::CORRUPTION_EXPERIENCED => String::from("CORRUPTION_EXPERIENCED"),
            TcpOptionKind::SNAP => String::from("SNAP"),
            TcpOptionKind::UNASSIGNED => String::from("UNASSIGNED"),
            TcpOptionKind::TCP_COMPRESSION_FILTER => String::from("TCP_COMPRESSION_FILTER"),
            TcpOptionKind::QUICK_START => String::from("QUICK_START"),
            TcpOptionKind::USER_TIMEOUT => String::from("USER_TIMEOUT"),
            TcpOptionKind::TCP_AO => String::from("TCP_AO"),
            TcpOptionKind::MPTCP => String::from("MPTCP"),
            TcpOptionKind::RESERVED_31 => String::from("RESERVED_31"),
            TcpOptionKind::RESERVED_32 => String::from("RESERVED_32"),
            TcpOptionKind::RESERVED_33 => String::from("RESERVED_33"),
            TcpOptionKind::FAST_OPEN_COOKIE => String::from("FAST_OPEN_COOKIE"),
            TcpOptionKind::TCP_ENO => String::from("TCP_ENO"),
            TcpOptionKind::ACC_ECNO_0 => String::from("ACC_ECNO_0"),
            TcpOptionKind::ACC_ECNO_1 => String::from("ACC_ECNO_1"),
            TcpOptionKind::EXPERIMENT_1 => String::from("EXPERIMENT_1"),
            TcpOptionKind::EXPERIMENT_2 => String::from("EXPERIMENT_2"),
            TcpOptionKind::RESERVED(n) => format!("RESERVED_{}", n),
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

impl PrimitiveValues for TcpOptionKind {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match *self {
            TcpOptionKind::EOL => (0,),
            TcpOptionKind::NOP => (1,),
            TcpOptionKind::MSS => (2,),
            TcpOptionKind::WSCALE => (3,),
            TcpOptionKind::SACK_PERMITTED => (4,),
            TcpOptionKind::SACK => (5,),
            TcpOptionKind::ECHO => (6,),
            TcpOptionKind::ECHO_REPLY => (7,),
            TcpOptionKind::TIMESTAMPS => (8,),
            TcpOptionKind::POCP => (9,),
            TcpOptionKind::POSP => (10,),
            TcpOptionKind::CC => (11,),
            TcpOptionKind::CC_NEW => (12,),
            TcpOptionKind::CC_ECHO => (13,),
            TcpOptionKind::ALT_CHECKSUM_REQ => (14,),
            TcpOptionKind::ALT_CHECKSUM_DATA => (15,),
            TcpOptionKind::SKEETER => (16,),
            TcpOptionKind::BUBBA => (17,),
            TcpOptionKind::TRAILER_CHECKSUM => (18,),
            TcpOptionKind::MD5_SIGNATURE => (19,),
            TcpOptionKind::SCPS_CAPABILITIES => (20,),
            TcpOptionKind::SELECTIVE_ACK => (21,),
            TcpOptionKind::RECORD_BOUNDARIES => (22,),
            TcpOptionKind::CORRUPTION_EXPERIENCED => (23,),
            TcpOptionKind::SNAP => (24,),
            TcpOptionKind::UNASSIGNED => (25,),
            TcpOptionKind::TCP_COMPRESSION_FILTER => (26,),
            TcpOptionKind::QUICK_START => (27,),
            TcpOptionKind::USER_TIMEOUT => (28,),
            TcpOptionKind::TCP_AO => (29,),
            TcpOptionKind::MPTCP => (30,),
            TcpOptionKind::RESERVED_31 => (31,),
            TcpOptionKind::RESERVED_32 => (32,),
            TcpOptionKind::RESERVED_33 => (33,),
            TcpOptionKind::FAST_OPEN_COOKIE => (34,),
            TcpOptionKind::TCP_ENO => (35,),
            TcpOptionKind::ACC_ECNO_0 => (36,),
            TcpOptionKind::ACC_ECNO_1 => (37,),
            TcpOptionKind::EXPERIMENT_1 => (253,),
            TcpOptionKind::EXPERIMENT_2 => (254,),
            TcpOptionKind::RESERVED(n) => (n,),
        }
    }
}

/// A TCP option.
#[packet]
pub struct TcpOption {
    #[construct_with(u8)]
    kind: TcpOptionKind,
    #[length_fn = "tcp_option_length"]
    // The length field is an optional field, using a Vec is a way to implement
    // it
    length: Vec<u8>,
    #[length_fn = "tcp_option_payload_length"]
    #[payload]
    data: Vec<u8>,
}

impl TcpOption {
    /// NOP: This may be used to align option fields on 32-bit boundaries for better performance.
    pub fn nop() -> Self {
        TcpOption {
            kind: TcpOptionKind::NOP,
            length: vec![],
            data: vec![],
        }
    }

    /// Timestamp: TCP timestamps, defined in RFC 1323, can help TCP determine in which order
    /// packets were sent. TCP timestamps are not normally aligned to the system clock and
    /// start at some random value.
    pub fn timestamp(my: u32, their: u32) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&my.octets()[..]);
        data.extend_from_slice(&their.octets()[..]);

        TcpOption {
            kind: TcpOptionKind::TIMESTAMPS,
            length: vec![10],
            data: data,
        }
    }

    /// MSS: The maximum segment size (MSS) is the largest amount of data, specified in bytes,
    /// that TCP is willing to receive in a single segment.
    pub fn mss(val: u16) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&val.octets()[..]);

        TcpOption {
            kind: TcpOptionKind::MSS,
            length: vec![4],
            data: data,
        }
    }

    /// Window scale: The TCP window scale option, as defined in RFC 1323, is an option used to
    /// increase the maximum window size from 65,535 bytes to 1 gigabyte.
    pub fn wscale(val: u8) -> Self {
        TcpOption {
            kind: TcpOptionKind::WSCALE,
            length: vec![3],
            data: vec![val],
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. This options enables use of
    /// SACK during negotiation.
    pub fn sack_perm() -> Self {
        TcpOption {
            kind: TcpOptionKind::SACK_PERMITTED,
            length: vec![2],
            data: vec![],
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. The acknowledgement can specify
    /// a number of SACK blocks, where each SACK block is conveyed by the starting and ending sequence
    /// numbers of a contiguous range that the receiver correctly received.
    pub fn selective_ack(acks: &[u32]) -> Self {
        let mut data = vec![];
        for ack in acks {
            data.extend_from_slice(&ack.octets()[..]);
        }
        TcpOption {
            kind: TcpOptionKind::SACK,
            length: vec![1 /* number */ + 1 /* length */ + data.len() as u8],
            data: data,
        }
    }
    /// Get the TCP option kind.
    pub fn kind(&self) -> TcpOptionKind {
        self.kind
    }
    /// Get length of the TCP option.
    pub fn length(&self) -> u8 {
        if self.length.is_empty() {
            0
        } else {
            self.length[0]
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

/// This function gets the 'length' of the length field of the IPv4Option packet
/// Few options (EOL, NOP) are 1 bytes long, and then have a length field equal
/// to 0.
#[inline]
fn tcp_option_length(option: &TcpOptionPacket) -> usize {
    match option.get_kind() {
        TcpOptionKind::EOL => 0,
        TcpOptionKind::NOP => 0,
        _ => 1,
    }
}

fn tcp_option_payload_length(ipv4_option: &TcpOptionPacket) -> usize {
    match ipv4_option.get_length_raw().first() {
        Some(len) if *len >= 2 => *len as usize - 2,
        _ => 0,
    }
}

#[inline]
fn tcp_options_length(tcp: &TcpPacket) -> usize {
    let data_offset = tcp.get_data_offset();

    if data_offset > 5 {
        data_offset as usize * 4 - 20
    } else {
        0
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
        packet.packet(),
        8,
        extra_data,
        source,
        destination,
        IpNextLevelProtocol::Tcp,
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
        packet.packet(),
        8,
        extra_data,
        source,
        destination,
        IpNextLevelProtocol::Tcp,
    )
}

#[test]
fn tcp_header_ipv4_test() {
    use crate::ip::IpNextLevelProtocol;
    use crate::ipv4::MutableIpv4Packet;

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 32;
    const TEST_DATA_LEN: usize = 4;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN];
    let ipv4_source = Ipv4Addr::new(192, 168, 2, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 111, 51);
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextLevelProtocol::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN] = 't' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(49511);
        assert_eq!(tcp_header.get_source(), 49511);

        tcp_header.set_destination(9000);
        assert_eq!(tcp_header.get_destination(), 9000);

        tcp_header.set_sequence(0x9037d2b8);
        assert_eq!(tcp_header.get_sequence(), 0x9037d2b8);

        tcp_header.set_acknowledgement(0x944bb276);
        assert_eq!(tcp_header.get_acknowledgement(), 0x944bb276);

        tcp_header.set_flags(TcpFlags::PSH | TcpFlags::ACK);
        assert_eq!(tcp_header.get_flags(), TcpFlags::PSH | TcpFlags::ACK);

        tcp_header.set_window(4015);
        assert_eq!(tcp_header.get_window(), 4015);

        tcp_header.set_data_offset(8);
        assert_eq!(tcp_header.get_data_offset(), 8);

        let ts = TcpOption::timestamp(743951781, 44056978);
        tcp_header.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

        let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
        tcp_header.set_checksum(checksum);
        assert_eq!(tcp_header.get_checksum(), 0xc031);
    }
    let ref_packet = [
        0xc1, 0x67, /* source */
        0x23, 0x28, /* destination */
        0x90, 0x37, 0xd2, 0xb8, /* seq */
        0x94, 0x4b, 0xb2, 0x76, /* ack */
        0x80, 0x18, 0x0f, 0xaf, /* length, flags, win */
        0xc0, 0x31, /* checksum */
        0x00, 0x00, /* urg ptr */
        0x01, 0x01, /* options: nop */
        0x08, 0x0a, 0x2c, 0x57, 0xcd, 0xa5, 0x02, 0xa0, 0x41, 0x92, /* timestamp */
        0x74, 0x65, 0x73, 0x74, /* "test" */
    ];
    assert_eq!(&ref_packet[..], &packet[20..]);
}

#[test]
fn tcp_test_options_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options_iter(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_options_vec_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_options_slice_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options_raw(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_option_invalid_len() {
    use std::println;
    let mut buf = [0; 24];
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(6);
        }
        buf[20] = 2; // option type
        buf[21] = 8; // option len, not enough space for it
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let options = tcp.get_options_iter();
        for opt in options {
            println!("{:?}", opt);
        }
    }
}

#[test]
fn tcp_test_payload_slice_invalid_offset() {
    let mut buf = [0; 20];
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        assert_eq!(tcp.payload().len(), 0);
    }
}
