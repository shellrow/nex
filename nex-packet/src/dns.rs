use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, str};
use nex_macro::packet;
use nex_macro_helper::packet::{Packet, PacketSize, PrimitiveValues};
use nex_macro_helper::types::{u1, u16be, u32be, u4};
use std::str::Utf8Error;

/// Represents an DNS operation.
/// These identifiers correspond to DNS resource record classes.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2>
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DnsClasses {
    use super::DnsClass;

    /// Internet
    pub const IN: DnsClass = DnsClass(1);
    /// CSNET (Unassigned)
    pub const CS: DnsClass = DnsClass(2);
    /// Chaos
    pub const CH: DnsClass = DnsClass(3);
    /// Hesiod
    pub const HS: DnsClass = DnsClass(4);
}

/// Represents a DNS class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsClass(pub u16);

impl DnsClass {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl PrimitiveValues for DnsClass {
    type T = (u16,);

    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &DnsClasses::IN => "IN", // 1
                &DnsClasses::CS => "CS", // 2
                &DnsClasses::CH => "CH", // 3
                &DnsClasses::HS => "HS", // 4
                _ => "unknown",
            }
        )
    }
}

/// Represents an DNS types.
/// These identifiers are used to specify the type of DNS query or response.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DnsTypes {
    use super::DnsType;

    pub const A: DnsType = DnsType(1);
    pub const NS: DnsType = DnsType(2);
    pub const MD: DnsType = DnsType(3);
    pub const MF: DnsType = DnsType(4);
    pub const CNAME: DnsType = DnsType(5);
    pub const SOA: DnsType = DnsType(6);
    pub const MB: DnsType = DnsType(7);
    pub const MG: DnsType = DnsType(8);
    pub const MR: DnsType = DnsType(9);
    pub const NULL: DnsType = DnsType(10);
    pub const WKS: DnsType = DnsType(11);
    pub const PTR: DnsType = DnsType(12);
    pub const HINFO: DnsType = DnsType(13);
    pub const MINFO: DnsType = DnsType(14);
    pub const MX: DnsType = DnsType(15);
    pub const TXT: DnsType = DnsType(16);
    pub const RP: DnsType = DnsType(17);
    pub const AFSDB: DnsType = DnsType(18);
    pub const X25: DnsType = DnsType(19);
    pub const ISDN: DnsType = DnsType(20);
    pub const RT: DnsType = DnsType(21);
    pub const NSAP: DnsType = DnsType(22);
    pub const NSAP_PTR: DnsType = DnsType(23);
    pub const SIG: DnsType = DnsType(24);
    pub const KEY: DnsType = DnsType(25);
    pub const PX: DnsType = DnsType(26);
    pub const GPOS: DnsType = DnsType(27);
    pub const AAAA: DnsType = DnsType(28);
    pub const LOC: DnsType = DnsType(29);
    pub const NXT: DnsType = DnsType(30);
    pub const EID: DnsType = DnsType(31);
    pub const NIMLOC: DnsType = DnsType(32);
    pub const SRV: DnsType = DnsType(33);
    pub const ATMA: DnsType = DnsType(34);
    pub const NAPTR: DnsType = DnsType(35);
    pub const KX: DnsType = DnsType(36);
    pub const CERT: DnsType = DnsType(37);
    pub const A6: DnsType = DnsType(38);
    pub const DNAME: DnsType = DnsType(39);
    pub const SINK: DnsType = DnsType(40);
    pub const OPT: DnsType = DnsType(41);
    pub const APL: DnsType = DnsType(42);
    pub const DS: DnsType = DnsType(43);
    pub const SSHFP: DnsType = DnsType(44);
    pub const IPSECKEY: DnsType = DnsType(45);
    pub const RRSIG: DnsType = DnsType(46);
    pub const NSEC: DnsType = DnsType(47);
    pub const DNSKEY: DnsType = DnsType(48);
    pub const DHCID: DnsType = DnsType(49);
    pub const NSEC3: DnsType = DnsType(50);
    pub const NSEC3PARAM: DnsType = DnsType(51);
    pub const TLSA: DnsType = DnsType(52);
    pub const SMIMEA: DnsType = DnsType(53);
    pub const HIP: DnsType = DnsType(55);
    pub const NINFO: DnsType = DnsType(56);
    pub const RKEY: DnsType = DnsType(57);
    pub const TALINK: DnsType = DnsType(58);
    pub const CDS: DnsType = DnsType(59);
    pub const CDNSKEY: DnsType = DnsType(60);
    pub const OPENPGPKEY: DnsType = DnsType(61);
    pub const CSYNC: DnsType = DnsType(62);
    pub const ZONEMD: DnsType = DnsType(63);
    pub const SVCB: DnsType = DnsType(64);
    pub const HTTPS: DnsType = DnsType(65);
    pub const SPF: DnsType = DnsType(99);
    pub const UINFO: DnsType = DnsType(100);
    pub const UID: DnsType = DnsType(101);
    pub const GID: DnsType = DnsType(102);
    pub const UNSPEC: DnsType = DnsType(103);
    pub const NID: DnsType = DnsType(104);
    pub const L32: DnsType = DnsType(105);
    pub const L64: DnsType = DnsType(106);
    pub const LP: DnsType = DnsType(107);
    pub const EUI48: DnsType = DnsType(108);
    pub const EUI64: DnsType = DnsType(109);
    pub const TKEY: DnsType = DnsType(249);
    pub const TSIG: DnsType = DnsType(250);
    pub const IXFR: DnsType = DnsType(251);
    pub const AXFR: DnsType = DnsType(252);
    pub const MAILB: DnsType = DnsType(253);
    pub const MAILA: DnsType = DnsType(254);
    pub const ANY: DnsType = DnsType(255);
    pub const URI: DnsType = DnsType(256);
    pub const CAA: DnsType = DnsType(257);
    pub const AVC: DnsType = DnsType(258);
    pub const DOA: DnsType = DnsType(259);
    pub const AMTRELAY: DnsType = DnsType(260);
    pub const TA: DnsType = DnsType(32768);
    pub const DLV: DnsType = DnsType(32769);
}

/// Represents a DNS type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsType(pub u16);

impl DnsType {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl PrimitiveValues for DnsType {
    type T = (u16,);

    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &DnsTypes::A => "A",                   // 1
                &DnsTypes::NS => "NS",                 // 2
                &DnsTypes::MD => "MD",                 // 3
                &DnsTypes::MF => "MF",                 // 4
                &DnsTypes::CNAME => "CNAME",           // 5
                &DnsTypes::SOA => "SOA",               // 6
                &DnsTypes::MB => "MB",                 // 7
                &DnsTypes::MG => "MG",                 // 8
                &DnsTypes::MR => "MR",                 // 9
                &DnsTypes::NULL => "NULL",             // 10
                &DnsTypes::WKS => "WKS",               // 11
                &DnsTypes::PTR => "PTR",               // 12
                &DnsTypes::HINFO => "HINFO",           // 13
                &DnsTypes::MINFO => "MINFO",           // 14
                &DnsTypes::MX => "MX",                 // 15
                &DnsTypes::TXT => "TXT",               // 16
                &DnsTypes::RP => "RP",                 // 17
                &DnsTypes::AFSDB => "AFSDB",           // 18
                &DnsTypes::X25 => "X25",               // 19
                &DnsTypes::ISDN => "ISDN",             // 20
                &DnsTypes::RT => "RT",                 // 21
                &DnsTypes::NSAP => "NSAP",             // 22
                &DnsTypes::NSAP_PTR => "NSAP_PTR",     // 23
                &DnsTypes::SIG => "SIG",               // 24
                &DnsTypes::KEY => "KEY",               // 25
                &DnsTypes::PX => "PX",                 // 26
                &DnsTypes::GPOS => "GPOS",             // 27
                &DnsTypes::AAAA => "AAAA",             // 28
                &DnsTypes::LOC => "LOC",               // 29
                &DnsTypes::NXT => "NXT",               // 30
                &DnsTypes::EID => "EID",               // 31
                &DnsTypes::NIMLOC => "NIMLOC",         // 32
                &DnsTypes::SRV => "SRV",               // 33
                &DnsTypes::ATMA => "ATMA",             // 34
                &DnsTypes::NAPTR => "NAPTR",           // 35
                &DnsTypes::KX => "KX",                 // 36
                &DnsTypes::CERT => "CERT",             // 37
                &DnsTypes::A6 => "A6",                 // 38
                &DnsTypes::DNAME => "DNAME",           // 39
                &DnsTypes::SINK => "SINK",             // 40
                &DnsTypes::OPT => "OPT",               // 41
                &DnsTypes::APL => "APL",               // 42
                &DnsTypes::DS => "DS",                 // 43
                &DnsTypes::SSHFP => "SSHFP",           // 44
                &DnsTypes::IPSECKEY => "IPSECKEY",     // 45
                &DnsTypes::RRSIG => "RRSIG",           // 46
                &DnsTypes::NSEC => "NSEC",             // 47
                &DnsTypes::DNSKEY => "DNSKEY",         // 48
                &DnsTypes::DHCID => "DHCID",           // 49
                &DnsTypes::NSEC3 => "NSEC3",           // 50
                &DnsTypes::NSEC3PARAM => "NSEC3PARAM", // 51
                &DnsTypes::TLSA => "TLSA",             // 52
                &DnsTypes::SMIMEA => "SMIMEA",         // 53
                &DnsTypes::HIP => "HIP",               // 55
                &DnsTypes::NINFO => "NINFO",           // 56
                &DnsTypes::RKEY => "RKEY",             // 57
                &DnsTypes::TALINK => "TALINK",         // 58
                &DnsTypes::CDS => "CDS",               // 59
                &DnsTypes::CDNSKEY => "CDNSKEY",       // 60
                &DnsTypes::OPENPGPKEY => "OPENPGPKEY", // 61
                &DnsTypes::CSYNC => "CSYNC",           // 62
                &DnsTypes::ZONEMD => "ZONEMD",         // 63
                &DnsTypes::SVCB => "SVCB",             // 64
                &DnsTypes::HTTPS => "HTTPS",           // 65
                &DnsTypes::SPF => "SPF",               // 99
                &DnsTypes::UINFO => "UINFO",           // 100
                &DnsTypes::UID => "UID",               // 101
                &DnsTypes::GID => "GID",               // 102
                &DnsTypes::UNSPEC => "UNSPEC",         // 103
                &DnsTypes::NID => "NID",               // 104
                &DnsTypes::L32 => "L32",               // 105
                &DnsTypes::L64 => "L64",               // 106
                &DnsTypes::LP => "LP",                 // 107
                &DnsTypes::EUI48 => "EUI48",           // 108
                &DnsTypes::EUI64 => "EUI64",           // 109
                &DnsTypes::TKEY => "TKEY",             // 249
                &DnsTypes::TSIG => "TSIG",             // 250
                &DnsTypes::IXFR => "IXFR",             // 251
                &DnsTypes::AXFR => "AXFR",             // 252
                &DnsTypes::MAILB => "MAILB",           // 253
                &DnsTypes::MAILA => "MAILA",           // 254
                &DnsTypes::ANY => "ANY",               // 255
                &DnsTypes::URI => "URI",               // 256
                &DnsTypes::CAA => "CAA",               // 257
                &DnsTypes::AVC => "AVC",               // 258
                &DnsTypes::DOA => "DOA",               // 259
                &DnsTypes::AMTRELAY => "AMTRELAY",     // 260
                &DnsTypes::TA => "TA",                 // 32768
                &DnsTypes::DLV => "DLV",               // 32769
                _ => "unknown",
            }
        )
    }
}

/// Represents a DNS packet.
/// Including its header and all the associated records.
#[packet]
pub struct Dns {
    pub id: u16be,
    pub is_response: u1,
    #[construct_with(u4)]
    pub opcode: OpCode,
    pub is_authoriative: u1,
    pub is_truncated: u1,
    pub is_recursion_desirable: u1,
    pub is_recursion_available: u1,
    pub zero_reserved: u1,
    pub is_answer_authenticated: u1,
    pub is_non_authenticated_data: u1,
    #[construct_with(u4)]
    pub rcode: RetCode,
    pub query_count: u16be,
    pub response_count: u16be,
    pub authority_rr_count: u16be,
    pub additional_rr_count: u16be,
    #[length_fn = "queries_length"]
    pub queries: Vec<DnsQuery>,
    #[length_fn = "responses_length"]
    pub responses: Vec<DnsResponse>,
    #[length_fn = "authority_length"]
    pub authorities: Vec<DnsResponse>,
    #[length_fn = "additional_length"]
    pub additionals: Vec<DnsResponse>,
    #[payload]
    pub payload: Vec<u8>,
}

fn queries_length(packet: &DnsPacket) -> usize {
    let base = 12;
    let mut length = 0;
    for _ in 0..packet.get_query_count() {
        match DnsQueryPacket::new(&packet.packet()[base + length..]) {
            Some(query) => length += query.packet_size(),
            None => break,
        }
    }
    length
}

fn responses_length(packet: &DnsPacket) -> usize {
    let base = 12 + queries_length(packet);
    let mut length = 0;
    for _ in 0..packet.get_response_count() {
        match DnsResponsePacket::new(&packet.packet()[base + length..]) {
            Some(query) => length += query.packet_size(),
            None => break,
        }
    }
    length
}

fn authority_length(packet: &DnsPacket) -> usize {
    let base = 12 + queries_length(packet) + responses_length(packet);
    let mut length = 0;
    for _ in 0..packet.get_authority_rr_count() {
        match DnsResponsePacket::new(&packet.packet()[base + length..]) {
            Some(query) => length += query.packet_size(),
            None => break,
        }
    }
    length
}

fn additional_length(packet: &DnsPacket) -> usize {
    let base = 12 + queries_length(packet) + responses_length(packet) + authority_length(packet);
    let mut length = 0;
    for _ in 0..packet.get_additional_rr_count() {
        match DnsResponsePacket::new(&packet.packet()[base + length..]) {
            Some(query) => length += query.packet_size(),
            None => break,
        }
    }
    length
}

/// Represents an DNS operation code.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpCode {
    Query,
    InverseQuery,
    Status,
    Reserved,
    Notify,
    Update,
    Dso,
    Unassigned(u8),
}

impl PrimitiveValues for OpCode {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match self {
            Self::Query => (0,),
            Self::InverseQuery => (1,),
            Self::Status => (2,),
            Self::Reserved => (3,),
            Self::Notify => (4,),
            Self::Update => (5,),
            Self::Dso => (6,),
            Self::Unassigned(n) => (*n,),
        }
    }
}

impl OpCode {
    pub fn new(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::InverseQuery,
            2 => Self::Status,
            3 => Self::Reserved,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::Dso,
            _ => Self::Unassigned(value),
        }
    }
}

/// Represents an DNS return code.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Dsotypeni,
    BadVers,
    BadKey,
    BadTime,
    BadMode,
    BadName,
    BadAlg,
    BadTrunc,
    BadCookie,
    Unassigned(u8),
}

impl PrimitiveValues for RetCode {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match self {
            Self::NoError => (0,),
            Self::FormErr => (1,),
            Self::ServFail => (2,),
            Self::NXDomain => (3,),
            Self::NotImp => (4,),
            Self::Refused => (5,),
            Self::YXDomain => (6,),
            Self::YXRRSet => (7,),
            Self::NXRRSet => (8,),
            Self::NotAuth => (9,),
            Self::NotZone => (10,),
            Self::Dsotypeni => (11,),
            Self::BadVers => (16,),
            Self::BadKey => (17,),
            Self::BadTime => (18,),
            Self::BadMode => (19,),
            Self::BadName => (20,),
            Self::BadAlg => (21,),
            Self::BadTrunc => (22,),
            Self::BadCookie => (23,),
            Self::Unassigned(n) => (*n,),
        }
    }
}

impl RetCode {
    pub fn new(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            11 => Self::Dsotypeni,
            16 => Self::BadVers,
            17 => Self::BadKey,
            18 => Self::BadTime,
            19 => Self::BadMode,
            20 => Self::BadName,
            21 => Self::BadAlg,
            22 => Self::BadTrunc,
            23 => Self::BadCookie,
            _ => Self::Unassigned(value),
        }
    }
}

/// DNS query packet structure.
#[packet]
pub struct DnsQuery {
    #[length_fn = "qname_length"]
    pub qname: Vec<u8>,
    #[construct_with(u16be)]
    pub qtype: DnsType,
    #[construct_with(u16be)]
    pub qclass: DnsClass,
    #[payload]
    pub payload: Vec<u8>,
}

fn qname_length(packet: &DnsQueryPacket) -> usize {
    packet.packet().iter().take_while(|w| *w != &0).count() + 1
}

impl DnsQuery {
    pub fn get_qname_parsed(&self) -> Result<String, Utf8Error> {
        let name = &self.qname;
        let mut qname = String::new();
        let mut offset = 0;
        loop {
            let label_len = name[offset] as usize;
            if label_len == 0 {
                break;
            }
            if !qname.is_empty() {
                qname.push('.');
            }
            match str::from_utf8(&name[offset + 1..offset + 1 + label_len]) {
                Ok(label) => qname.push_str(label),
                Err(e) => return Err(e),
            }
            offset += label_len + 1;
        }
        Ok(qname)
    }
}

/// DNS response packet structure.
#[packet]
pub struct DnsResponse {
    #[length_fn = "rname_length"]
    pub rname: Vec<u8>,
    #[construct_with(u16be)]
    pub rtype: DnsType,
    #[construct_with(u16be)]
    pub rclass: DnsClass,
    pub ttl: u32be,
    pub data_len: u16be,
    #[length = "data_len"]
    pub data: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

/// Parses and Returns the length of the rname field.
fn rname_length(packet: &DnsResponsePacket) -> usize {
    let mut offset = 0;
    let mut size = 0;
    loop {
        let label_len = packet.packet()[offset] as usize;
        if label_len == 0 {
            size += 1;
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            size += 2;
            break;
        }
        size += label_len + 1;
        offset += label_len + 1;
    }
    size
}

/// Parses the rname field of a DNS packet.
pub fn parse_name(packet: &DnsPacket, coded_name: &Vec<u8>) -> Result<String, Utf8Error> {
    // First follow the path in the rname, except if it starts with a C0
    // then move to using the offsets from the start
    let start = packet.packet();
    let mut name = coded_name.as_slice();
    let mut rname = String::new();
    let mut offset: usize = 0;

    loop {
        let label_len: u16 = name[offset] as u16;
        if label_len == 0 {
            break;
        }
        if (label_len & 0xC0) == 0xC0 {
            let offset1 = ((label_len & 0x3F) as usize) << 8;
            let offset2 = name[offset + 1] as usize;
            offset = offset1 + offset2;
            // now change name
            name = start;
            continue;
        }
        if !rname.is_empty() {
            rname.push('.');
        }
        match str::from_utf8(&name[offset + 1..offset + 1 + label_len as usize]) {
            Ok(label) => rname.push_str(label),
            Err(e) => return Err(e),
        }
        offset += label_len as usize + 1;
    }
    Ok(rname)
}

/// Represents a DNS TXT record.
///
/// TXT records hold descriptive text. The actual text is stored in the `text` field.
#[packet]
pub struct DnsRrTXT {
    pub data_len: u8,
    #[length = "data_len"]
    pub text: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

/// Represents a DNS SRV record.
///
/// SRV records are used to specify the location of services by providing a hostname and port number.
#[packet]
pub struct DnsRrSrv {
    pub priority: u16be,
    pub weight: u16be,
    pub port: u16be,
    #[length_fn = "target_length"]
    pub target: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn target_length(packet: &DnsRrSrvPacket) -> usize {
    let mut offset = 6;
    let mut size = 0;
    loop {
        let label_len = packet.packet()[offset] as usize;
        if label_len == 0 {
            size += 1;
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            size += 2;
            break;
        }
        size += label_len + 1;
        offset += label_len + 1;
    }
    size
}

/// A structured representation of a Service Name (SRV record content).
///
/// Parses and holds components of an SRV record's target domain, which includes service instance, service type, protocol, and domain name.
/// SRV record name
#[derive(Debug)]
pub struct SrvName {
    pub instance: Option<String>,
    pub service: Option<String>,
    pub protocol: Option<String>,
    pub domain: Option<String>,
}

impl SrvName {
    pub fn new(name: &str) -> Self {
        let parts: Vec<&str> = name.split('.').collect();
        let (instance, service, protocol, domain) = match parts.as_slice() {
            [instance, service, protocol, domain @ ..]
                if service.starts_with('_') && protocol.starts_with('_') =>
            {
                (
                    Some(String::from(*instance)),
                    Some(String::from(*service)),
                    Some(String::from(*protocol)),
                    Some(String::from(domain.join("."))),
                )
            }
            [service, protocol, domain @ ..]
                if service.starts_with('_') && protocol.starts_with('_') =>
            {
                (
                    None,
                    Some(String::from(*service)),
                    Some(String::from(*protocol)),
                    Some(String::from(domain.join("."))),
                )
            }
            [instance, service, protocol, domain @ ..] => (
                Some(String::from(*instance)),
                Some(String::from(*service)),
                Some(String::from(*protocol)),
                Some(String::from(domain.join("."))),
            ),
            _ => (None, None, None, None),
        };

        SrvName {
            instance,
            service,
            protocol,
            domain,
        }
    }
}

#[test]
fn test_dns_query_packet() {
    let packet = DnsPacket::new(b"\x1e\xcb\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00").unwrap();
    assert_eq!(packet.get_id(), 7883);
    assert_eq!(packet.get_is_response(), 0);
    assert_eq!(packet.get_opcode(), OpCode::Query);
    assert_eq!(packet.get_is_authoriative(), 0);
    assert_eq!(packet.get_is_truncated(), 0);
    assert_eq!(packet.get_is_recursion_desirable(), 1);
    assert_eq!(packet.get_is_recursion_available(), 0);
    assert_eq!(packet.get_zero_reserved(), 0);
    assert_eq!(packet.get_rcode(), RetCode::NoError);
    assert_eq!(packet.get_query_count(), 1);
    assert_eq!(packet.get_response_count(), 0);
    assert_eq!(packet.get_authority_rr_count(), 0);
    assert_eq!(packet.get_additional_rr_count(), 1);
    assert_eq!(packet.get_queries().len(), 1);
    assert_eq!(
        packet.get_queries()[0]
            .get_qname_parsed()
            .unwrap_or(String::new()),
        "cloudflare.com"
    );
    assert_eq!(packet.get_queries()[0].qtype, DnsTypes::A);
    assert_eq!(packet.get_queries()[0].qclass, DnsClasses::IN);
    assert_eq!(packet.get_responses().len(), 0);
    assert_eq!(packet.get_authorities().len(), 0);
    assert_eq!(packet.get_additionals().len(), 1);
}

#[test]
fn test_dns_reponse_packet() {
    let packet = DnsPacket::new(b"\x1e\xcb\x81\xa0\x00\x01\x00\x02\x00\x00\x00\x01\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xc4\x00\x04h\x10\x85\xe5\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xc4\x00\x04h\x10\x84\xe5\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x00").unwrap();
    assert_eq!(packet.get_id(), 7883);
    assert_eq!(packet.get_is_response(), 1);
    assert_eq!(packet.get_opcode(), OpCode::Query);
    assert_eq!(packet.get_is_authoriative(), 0);
    assert_eq!(packet.get_is_truncated(), 0);
    assert_eq!(packet.get_is_recursion_desirable(), 1);
    assert_eq!(packet.get_is_recursion_available(), 1);
    assert_eq!(packet.get_zero_reserved(), 0);
    assert_eq!(packet.get_rcode(), RetCode::NoError);
    assert_eq!(packet.get_query_count(), 1);
    assert_eq!(packet.get_response_count(), 2);
    assert_eq!(packet.get_authority_rr_count(), 0);
    assert_eq!(packet.get_additional_rr_count(), 1);
    assert_eq!(packet.get_queries().len(), 1);
    assert_eq!(
        packet.get_queries()[0]
            .get_qname_parsed()
            .unwrap_or(String::new()),
        "cloudflare.com"
    );
    assert_eq!(packet.get_queries()[0].qtype, DnsTypes::A);
    assert_eq!(packet.get_queries()[0].qclass, DnsClasses::IN);
    assert_eq!(packet.get_responses().len(), 2);
    assert_eq!(packet.get_responses()[0].rtype, DnsTypes::A);
    assert_eq!(packet.get_responses()[0].rclass, DnsClasses::IN);
    assert_eq!(packet.get_responses()[0].ttl, 196);
    assert_eq!(packet.get_responses()[0].data_len, 4);
    assert_eq!(
        packet.get_responses()[0].data.as_slice(),
        [104, 16, 133, 229]
    );
    assert_eq!(packet.get_authorities().len(), 0);
    assert_eq!(packet.get_additionals().len(), 1);
}

#[test]
fn test_mdns_response() {
    let data = b"\x00\x00\x84\x00\x00\x00\x00\x04\x00\x00\x00\x00\x0b\x5f\x61\x6d\x7a\x6e\x2d\x61\x6c\x65\x78\x61\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x0b\x08\x5f\x73\x65\x72\x76\x69\x63\x65\xc0\x0c\xc0\x2e\x00\x10\x80\x01\x00\x00\x11\x94\x00\x0a\x09\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31\xc0\x2e\x00\x21\x80\x01\x00\x00\x00\x78\x00\x1d\x00\x00\x00\x00\x19\x8f\x14\x61\x76\x73\x2d\x66\x66\x72\x65\x67\x2d\x31\x36\x35\x34\x34\x37\x35\x36\x38\x33\xc0\x1d\xc0\x61\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x01\x06";
    let packet = DnsPacket::new(data).expect("Failed to parse dns response");
    assert_eq!(packet.get_id(), 0);
    assert_eq!(packet.get_is_response(), 1);
    assert_eq!(packet.get_opcode(), OpCode::Query);
    assert_eq!(packet.get_is_authoriative(), 1);
    assert_eq!(packet.get_is_truncated(), 0);
    assert_eq!(packet.get_is_recursion_desirable(), 0);
    assert_eq!(packet.get_is_recursion_available(), 0);
    assert_eq!(packet.get_zero_reserved(), 0);
    assert_eq!(packet.get_rcode(), RetCode::NoError);
    assert_eq!(packet.get_query_count(), 0);
    assert_eq!(packet.get_response_count(), 4);
    assert_eq!(packet.get_authority_rr_count(), 0);
    assert_eq!(packet.get_additional_rr_count(), 0);
    assert_eq!(packet.get_responses().len(), 4);
    let responses = packet.get_responses();
    // RR #1
    assert_eq!(
        parse_name(&packet, &responses[0].rname).unwrap_or(String::new()),
        "_amzn-alexa._tcp.local"
    );
    assert_eq!(responses[0].rtype, DnsTypes::PTR);
    assert_eq!(responses[0].rclass, DnsClasses::IN);
    assert_eq!(responses[0].ttl, 4500);
    assert_eq!(responses[0].data_len, 11);
    assert_eq!(
        parse_name(&packet, &responses[0].data).unwrap_or(String::new()),
        "_service._amzn-alexa._tcp.local"
    );
    // RR #2
    assert_eq!(
        parse_name(&packet, &responses[1].rname).unwrap_or(String::new()),
        "_service._amzn-alexa._tcp.local"
    );
    assert_eq!(responses[1].rtype, DnsTypes::TXT);
    assert_eq!(responses[1].ttl, 4500);
    assert_eq!(responses[1].data_len, 10);
    let text_rr = DnsRrTXTPacket::new(&responses[1].data).unwrap();
    assert_eq!(text_rr.get_data_len(), 9);
    assert_eq!(String::from_utf8(text_rr.get_text()).unwrap(), "version=1");
    // RR #3
    let srv_name = parse_name(&packet, &responses[2].rname).unwrap_or(String::new());
    assert_eq!(srv_name, "_service._amzn-alexa._tcp.local");
    assert_eq!(responses[2].rtype, DnsTypes::SRV);
    assert_eq!(responses[2].data_len, 29);
    let srv_rr = DnsRrSrvPacket::new(&responses[2].data).unwrap();
    assert_eq!(srv_rr.get_priority(), 0);
    assert_eq!(srv_rr.get_weight(), 0);
    assert_eq!(srv_rr.get_port(), 6543);
    assert_eq!(
        parse_name(&packet, &srv_rr.get_target()).unwrap_or(String::new()),
        "avs-ffreg-1654475683.local"
    );
    let srv = SrvName::new(&srv_name);
    assert_eq!(srv.instance, Some(String::from("_service")));
    assert_eq!(srv.service, Some(String::from("_amzn-alexa")));
    assert_eq!(srv.protocol, Some(String::from("_tcp")));
    assert_eq!(srv.domain, Some(String::from("local")));
    // RR #4
    assert_eq!(responses[3].rtype, DnsTypes::A);
    assert_eq!(responses[3].data.as_slice(), [192, 168, 1, 6]);
}
