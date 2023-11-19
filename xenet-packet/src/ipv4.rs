//! An IPv4 packet abstraction.

use crate::ip::IpNextLevelProtocol;
use crate::PrimitiveValues;

use alloc::vec::Vec;

use xenet_macro::packet;
use xenet_macro_helper::types::*;

use std::net::Ipv4Addr;

/// IPv4 Header Length
pub const IPV4_HEADER_LEN: usize = MutableIpv4Packet::minimum_packet_size();
/// IPv4 Header Byte Unit (32 bits)
pub const IPV4_HEADER_LENGTH_BYTE_UNITS: usize = 4;

/// Represents the IPv4 option header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4OptionHeader {
    copied: u1,
    class: u2,
    number: Ipv4OptionType,
    length: Option<u8>,
}

/// Represents the IPv4 header.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub next_level_protocol: IpNextLevelProtocol,
    pub checksum: u16be,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Vec<Ipv4OptionHeader>,
}

impl Ipv4Header {
    /// Construct an IPv4 header from a byte slice.
    pub fn from_bytes(packet: &[u8]) -> Result<Ipv4Header, String> {
        if packet.len() < IPV4_HEADER_LEN {
            return Err("Packet is too small for IPv4 header".to_string());
        }
        match Ipv4Packet::new(packet) {
            Some(ipv4_packet) => Ok(Ipv4Header {
                version: ipv4_packet.get_version(),
                header_length: ipv4_packet.get_header_length(),
                dscp: ipv4_packet.get_dscp(),
                ecn: ipv4_packet.get_ecn(),
                total_length: ipv4_packet.get_total_length(),
                identification: ipv4_packet.get_identification(),
                flags: ipv4_packet.get_flags(),
                fragment_offset: ipv4_packet.get_fragment_offset(),
                ttl: ipv4_packet.get_ttl(),
                next_level_protocol: ipv4_packet.get_next_level_protocol(),
                checksum: ipv4_packet.get_checksum(),
                source: ipv4_packet.get_source(),
                destination: ipv4_packet.get_destination(),
                options: ipv4_packet
                    .get_options_iter()
                    .map(|o| Ipv4OptionHeader {
                        copied: o.get_copied(),
                        class: o.get_class(),
                        number: o.get_number(),
                        length: o.get_length().first().cloned(),
                    })
                    .collect(),
            }),
            None => Err("Failed to parse IPv4 packet".to_string()),
        }
    }
    /// Construct an IPv4 header from a Ipv4Packet.
    pub(crate) fn from_packet(ipv4_packet: &Ipv4Packet) -> Ipv4Header {
        Ipv4Header {
            version: ipv4_packet.get_version(),
            header_length: ipv4_packet.get_header_length(),
            dscp: ipv4_packet.get_dscp(),
            ecn: ipv4_packet.get_ecn(),
            total_length: ipv4_packet.get_total_length(),
            identification: ipv4_packet.get_identification(),
            flags: ipv4_packet.get_flags(),
            fragment_offset: ipv4_packet.get_fragment_offset(),
            ttl: ipv4_packet.get_ttl(),
            next_level_protocol: ipv4_packet.get_next_level_protocol(),
            checksum: ipv4_packet.get_checksum(),
            source: ipv4_packet.get_source(),
            destination: ipv4_packet.get_destination(),
            options: ipv4_packet
                .get_options_iter()
                .map(|o| Ipv4OptionHeader {
                    copied: o.get_copied(),
                    class: o.get_class(),
                    number: o.get_number(),
                    length: o.get_length().first().cloned(),
                })
                .collect(),
        }
    }
}

/// Represents the IPv4 header flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ipv4Flags {
    use xenet_macro_helper::types::*;

    /// Don't Fragment flag.
    pub const DontFragment: u3 = 0b010;
    /// More Fragments flag.
    pub const MoreFragments: u3 = 0b001;
}

/// Represents the IPv4 options.
/// <http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml>
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl PrimitiveValues for Ipv4OptionType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match *self {
            Ipv4OptionType::EOL => (0,),
            Ipv4OptionType::NOP => (1,),
            Ipv4OptionType::SEC => (2,),
            Ipv4OptionType::LSR => (3,),
            Ipv4OptionType::TS => (4,),
            Ipv4OptionType::ESEC => (5,),
            Ipv4OptionType::CIPSO => (6,),
            Ipv4OptionType::RR => (7,),
            Ipv4OptionType::SID => (8,),
            Ipv4OptionType::SSR => (9,),
            Ipv4OptionType::ZSU => (10,),
            Ipv4OptionType::MTUP => (11,),
            Ipv4OptionType::MTUR => (12,),
            Ipv4OptionType::FINN => (13,),
            Ipv4OptionType::VISA => (14,),
            Ipv4OptionType::ENCODE => (15,),
            Ipv4OptionType::IMITD => (16,),
            Ipv4OptionType::EIP => (17,),
            Ipv4OptionType::TR => (18,),
            Ipv4OptionType::ADDEXT => (19,),
            Ipv4OptionType::RTRALT => (20,),
            Ipv4OptionType::SDB => (21,),
            Ipv4OptionType::Unassigned => (22,),
            Ipv4OptionType::DPS => (23,),
            Ipv4OptionType::UMP => (24,),
            Ipv4OptionType::QS => (25,),
            Ipv4OptionType::EXP => (30,),
            Ipv4OptionType::Unknown(n) => (n,),
        }
    }
}

/// Represents an IPv4 Packet.
#[packet]
pub struct Ipv4 {
    pub version: u4,
    pub header_length: u4,
    pub dscp: u6,
    pub ecn: u2,
    pub total_length: u16be,
    pub identification: u16be,
    pub flags: u3,
    pub fragment_offset: u13be,
    pub ttl: u8,
    #[construct_with(u8)]
    pub next_level_protocol: IpNextLevelProtocol,
    pub checksum: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub source: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub destination: Ipv4Addr,
    #[length_fn = "ipv4_options_length"]
    pub options: Vec<Ipv4Option>,
    #[length_fn = "ipv4_payload_length"]
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an IPv4 packet header.
/// The checksum field of the packet is regarded as zeros during the calculation.
pub fn checksum(packet: &Ipv4Packet) -> u16be {
    use crate::util;
    use crate::Packet;

    let min = Ipv4Packet::minimum_packet_size();
    let max = packet.packet().len();
    let header_length = match packet.get_header_length() as usize * 4 {
        length if length < min => min,
        length if length > max => max,
        length => length,
    };
    let data = &packet.packet()[..header_length];
    util::checksum(data, 5)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn checksum_zeros() {
        let mut data = vec![0; 20];
        let expected = 64255;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(5);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_nonzero() {
        let mut data = vec![255; 20];
        let expected = 2560;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(5);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_too_small_header_length() {
        let mut data = vec![148; 20];
        let expected = 51910;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(0);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_too_large_header_length() {
        let mut data = vec![148; 20];
        let expected = 51142;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(99);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }
}

fn ipv4_options_length(ipv4: &Ipv4Packet) -> usize {
    // the header_length unit is the "word"
    // - and a word is made of 4 bytes,
    // - and the header length (without the options) is 5 words long
    (ipv4.get_header_length() as usize * 4).saturating_sub(20)
}

#[test]
fn ipv4_options_length_test() {
    let mut packet = [0u8; 20];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_header_length(5);
    assert_eq!(ipv4_options_length(&ip_header.to_immutable()), 0);
}

fn ipv4_payload_length(ipv4: &Ipv4Packet) -> usize {
    (ipv4.get_total_length() as usize).saturating_sub(ipv4.get_header_length() as usize * 4)
}

#[test]
fn ipv4_payload_length_test() {
    let mut packet = [0u8; 30];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_header_length(5);
    ip_header.set_total_length(20);
    assert_eq!(ipv4_payload_length(&ip_header.to_immutable()), 0);
    // just comparing with 0 is prone to false positives in this case.
    // for instance if one forgets to set total_length, one always gets 0
    ip_header.set_total_length(30);
    assert_eq!(ipv4_payload_length(&ip_header.to_immutable()), 10);
}

/// Represents the IPv4 Option field.
#[packet]
pub struct Ipv4Option {
    copied: u1,
    class: u2,
    #[construct_with(u5)]
    number: Ipv4OptionType,
    #[length_fn = "ipv4_option_length"]
    // The length field is an optional field, using a Vec is a way to implement
    // it
    length: Vec<u8>,
    #[length_fn = "ipv4_option_payload_length"]
    #[payload]
    data: Vec<u8>,
}

/// This function gets the 'length' of the length field of the IPv4Option packet
/// Few options (EOOL, NOP) are 1 bytes long, and then have a length field equal
/// to 0.
fn ipv4_option_length(option: &Ipv4OptionPacket) -> usize {
    match option.get_number() {
        Ipv4OptionType::EOL => 0,
        Ipv4OptionType::NOP => 0,
        _ => 1,
    }
}

fn ipv4_option_payload_length(ipv4_option: &Ipv4OptionPacket) -> usize {
    match ipv4_option.get_length().first() {
        Some(len) => (*len as usize).saturating_sub(2),
        None => 0,
    }
}

#[test]
fn ipv4_packet_test() {
    use crate::ip::IpNextLevelProtocol;
    use crate::Packet;
    use crate::PacketSize;

    let mut packet = [0u8; 200];
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_version(4);
        assert_eq!(ip_header.get_version(), 4);

        ip_header.set_header_length(5);
        assert_eq!(ip_header.get_header_length(), 5);

        ip_header.set_dscp(4);
        assert_eq!(ip_header.get_dscp(), 4);

        ip_header.set_ecn(1);
        assert_eq!(ip_header.get_ecn(), 1);

        ip_header.set_total_length(115);
        assert_eq!(ip_header.get_total_length(), 115);
        assert_eq!(95, ip_header.payload().len());
        assert_eq!(ip_header.get_total_length(), ip_header.packet_size() as u16);

        ip_header.set_identification(257);
        assert_eq!(ip_header.get_identification(), 257);

        ip_header.set_flags(Ipv4Flags::DontFragment as u3);
        assert_eq!(ip_header.get_flags(), 2);

        ip_header.set_fragment_offset(257);
        assert_eq!(ip_header.get_fragment_offset(), 257);

        ip_header.set_ttl(64);
        assert_eq!(ip_header.get_ttl(), 64);

        ip_header.set_next_level_protocol(IpNextLevelProtocol::Udp);
        assert_eq!(
            ip_header.get_next_level_protocol(),
            IpNextLevelProtocol::Udp
        );

        ip_header.set_source(Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ip_header.get_source(), Ipv4Addr::new(192, 168, 0, 1));

        ip_header.set_destination(Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(ip_header.get_destination(), Ipv4Addr::new(192, 168, 0, 199));

        let imm_header = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(imm_header);
        assert_eq!(ip_header.get_checksum(), 0xb64e);
    }

    let ref_packet = [
        0x45, /* ver/ihl */
        0x11, /* dscp/ecn */
        0x00, 0x73, /* total len */
        0x01, 0x01, /* identification */
        0x41, 0x01, /* flags/frag offset */
        0x40, /* ttl */
        0x11, /* proto */
        0xb6, 0x4e, /* checksum */
        0xc0, 0xa8, 0x00, 0x01, /* source ip */
        0xc0, 0xa8, 0x00, 0xc7, /* dest ip */
    ];

    assert_eq!(&ref_packet[..], &packet[..ref_packet.len()]);
}

#[test]
fn ipv4_packet_option_test() {
    use alloc::vec;

    let mut packet = [0u8; 3];
    {
        let mut ipv4_options = MutableIpv4OptionPacket::new(&mut packet[..]).unwrap();

        ipv4_options.set_copied(1);
        assert_eq!(ipv4_options.get_copied(), 1);

        ipv4_options.set_class(0);
        assert_eq!(ipv4_options.get_class(), 0);

        ipv4_options.set_number(Ipv4OptionType::new(3));
        assert_eq!(ipv4_options.get_number(), Ipv4OptionType::LSR);

        ipv4_options.set_length(&vec![3]);
        assert_eq!(ipv4_options.get_length(), vec![3]);

        ipv4_options.set_data(&vec![16]);
    }

    let ref_packet = [
        0x83, /* copy / class / number */
        0x03, /* length */
        0x10, /* data */
    ];

    assert_eq!(&ref_packet[..], &packet[..]);
}

#[test]
fn ipv4_packet_set_payload_test() {
    use crate::Packet;

    let mut packet = [0u8; 25]; // allow 20 byte header and 5 byte payload
    let mut ip_packet = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_packet.set_total_length(25);
    ip_packet.set_header_length(5);
    let payload = b"stuff"; // 5 bytes
    ip_packet.set_payload(&payload[..]);
    assert_eq!(ip_packet.payload(), payload);
}

#[test]
#[should_panic(expected = "index 25 out of range for slice of length 24")]
fn ipv4_packet_set_payload_test_panic() {
    let mut packet = [0u8; 24]; // allow 20 byte header and 4 byte payload
    let mut ip_packet = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_packet.set_total_length(25);
    ip_packet.set_header_length(5);
    let payload = b"stuff"; // 5 bytes
    ip_packet.set_payload(&payload[..]); // panic
}
