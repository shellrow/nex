use crate::packet::Packet;
use bytes::{BufMut, Bytes, BytesMut};
use core::str;
use nex_core::bitfield::{u1, u16be, u32be};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::Utf8Error,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents an DNS operation.
/// These identifiers correspond to DNS resource record classes.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2>
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsClass {
    IN = 1, // Internet
    CS = 2, // CSNET (Obsolete)
    CH = 3, // Chaos
    HS = 4, // Hesiod
    Unknown(u16),
}

impl DnsClass {
    pub fn new(value: u16) -> Self {
        match value {
            1 => DnsClass::IN,
            2 => DnsClass::CS,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            v => DnsClass::Unknown(v),
        }
    }

    pub fn value(&self) -> u16 {
        match self {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::Unknown(v) => *v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DnsClass::IN => "IN",
            DnsClass::CS => "CS",
            DnsClass::CH => "CH",
            DnsClass::HS => "HS",
            DnsClass::Unknown(_) => "Unknown",
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAP_PTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    SINK = 40,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
    URI = 256,
    CAA = 257,
    AVC = 258,
    DOA = 259,
    AMTRELAY = 260,
    TA = 32768,
    DLV = 32769,
    Unknown(u16),
}

impl DnsType {
    pub fn new(value: u16) -> Self {
        match value {
            1 => DnsType::A,
            2 => DnsType::NS,
            3 => DnsType::MD,
            4 => DnsType::MF,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            7 => DnsType::MB,
            8 => DnsType::MG,
            9 => DnsType::MR,
            10 => DnsType::NULL,
            11 => DnsType::WKS,
            12 => DnsType::PTR,
            13 => DnsType::HINFO,
            14 => DnsType::MINFO,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            17 => DnsType::RP,
            18 => DnsType::AFSDB,
            19 => DnsType::X25,
            20 => DnsType::ISDN,
            21 => DnsType::RT,
            22 => DnsType::NSAP,
            23 => DnsType::NSAP_PTR,
            24 => DnsType::SIG,
            25 => DnsType::KEY,
            26 => DnsType::PX,
            27 => DnsType::GPOS,
            28 => DnsType::AAAA,
            29 => DnsType::LOC,
            30 => DnsType::NXT,
            31 => DnsType::EID,
            32 => DnsType::NIMLOC,
            33 => DnsType::SRV,
            34 => DnsType::ATMA,
            35 => DnsType::NAPTR,
            36 => DnsType::KX,
            37 => DnsType::CERT,
            38 => DnsType::A6,
            39 => DnsType::DNAME,
            40 => DnsType::SINK,
            41 => DnsType::OPT,
            42 => DnsType::APL,
            43 => DnsType::DS,
            44 => DnsType::SSHFP,
            45 => DnsType::IPSECKEY,
            46 => DnsType::RRSIG,
            47 => DnsType::NSEC,
            48 => DnsType::DNSKEY,
            49 => DnsType::DHCID,
            50 => DnsType::NSEC3,
            51 => DnsType::NSEC3PARAM,
            52 => DnsType::TLSA,
            53 => DnsType::SMIMEA,
            55 => DnsType::HIP,
            56 => DnsType::NINFO,
            57 => DnsType::RKEY,
            58 => DnsType::TALINK,
            59 => DnsType::CDS,
            60 => DnsType::CDNSKEY,
            61 => DnsType::OPENPGPKEY,
            62 => DnsType::CSYNC,
            63 => DnsType::ZONEMD,
            64 => DnsType::SVCB,
            65 => DnsType::HTTPS,
            99 => DnsType::SPF,
            100 => DnsType::UINFO,
            101 => DnsType::UID,
            102 => DnsType::GID,
            103 => DnsType::UNSPEC,
            104 => DnsType::NID,
            105 => DnsType::L32,
            106 => DnsType::L64,
            107 => DnsType::LP,
            108 => DnsType::EUI48,
            109 => DnsType::EUI64,
            249 => DnsType::TKEY,
            250 => DnsType::TSIG,
            251 => DnsType::IXFR,
            252 => DnsType::AXFR,
            253 => DnsType::MAILB,
            254 => DnsType::MAILA,
            255 => DnsType::ANY,
            256 => DnsType::URI,
            257 => DnsType::CAA,
            258 => DnsType::AVC,
            259 => DnsType::DOA,
            260 => DnsType::AMTRELAY,
            32768 => DnsType::TA,
            32769 => DnsType::DLV,
            v => DnsType::Unknown(v),
        }
    }

    pub fn value(&self) -> u16 {
        match self {
            DnsType::A => 1,
            DnsType::NS => 2,
            DnsType::MD => 3,
            DnsType::MF => 4,
            DnsType::CNAME => 5,
            DnsType::SOA => 6,
            DnsType::MB => 7,
            DnsType::MG => 8,
            DnsType::MR => 9,
            DnsType::NULL => 10,
            DnsType::WKS => 11,
            DnsType::PTR => 12,
            DnsType::HINFO => 13,
            DnsType::MINFO => 14,
            DnsType::MX => 15,
            DnsType::TXT => 16,
            DnsType::RP => 17,
            DnsType::AFSDB => 18,
            DnsType::X25 => 19,
            DnsType::ISDN => 20,
            DnsType::RT => 21,
            DnsType::NSAP => 22,
            DnsType::NSAP_PTR => 23,
            DnsType::SIG => 24,
            DnsType::KEY => 25,
            DnsType::PX => 26,
            DnsType::GPOS => 27,
            DnsType::AAAA => 28,
            DnsType::LOC => 29,
            DnsType::NXT => 30,
            DnsType::EID => 31,
            DnsType::NIMLOC => 32,
            DnsType::SRV => 33,
            DnsType::ATMA => 34,
            DnsType::NAPTR => 35,
            DnsType::KX => 36,
            DnsType::CERT => 37,
            DnsType::A6 => 38,
            DnsType::DNAME => 39,
            DnsType::SINK => 40,
            DnsType::OPT => 41,
            DnsType::APL => 42,
            DnsType::DS => 43,
            DnsType::SSHFP => 44,
            DnsType::IPSECKEY => 45,
            DnsType::RRSIG => 46,
            DnsType::NSEC => 47,
            DnsType::DNSKEY => 48,
            DnsType::DHCID => 49,
            DnsType::NSEC3 => 50,
            DnsType::NSEC3PARAM => 51,
            DnsType::TLSA => 52,
            DnsType::SMIMEA => 53,
            DnsType::HIP => 55,
            DnsType::NINFO => 56,
            DnsType::RKEY => 57,
            DnsType::TALINK => 58,
            DnsType::CDS => 59,
            DnsType::CDNSKEY => 60,
            DnsType::OPENPGPKEY => 61,
            DnsType::CSYNC => 62,
            DnsType::ZONEMD => 63,
            DnsType::SVCB => 64,
            DnsType::HTTPS => 65,
            DnsType::SPF => 99,
            DnsType::UINFO => 100,
            DnsType::UID => 101,
            DnsType::GID => 102,
            DnsType::UNSPEC => 103,
            DnsType::NID => 104,
            DnsType::L32 => 105,
            DnsType::L64 => 106,
            DnsType::LP => 107,
            DnsType::EUI48 => 108,
            DnsType::EUI64 => 109,
            DnsType::TKEY => 249,
            DnsType::TSIG => 250,
            DnsType::IXFR => 251,
            DnsType::AXFR => 252,
            DnsType::MAILB => 253,
            DnsType::MAILA => 254,
            DnsType::ANY => 255,
            DnsType::URI => 256,
            DnsType::CAA => 257,
            DnsType::AVC => 258,
            DnsType::DOA => 259,
            DnsType::AMTRELAY => 260,
            DnsType::TA => 32768,
            DnsType::DLV => 32769,
            DnsType::Unknown(v) => *v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DnsType::A => "A",                   // 1
            DnsType::NS => "NS",                 // 2
            DnsType::MD => "MD",                 // 3
            DnsType::MF => "MF",                 // 4
            DnsType::CNAME => "CNAME",           // 5
            DnsType::SOA => "SOA",               // 6
            DnsType::MB => "MB",                 // 7
            DnsType::MG => "MG",                 // 8
            DnsType::MR => "MR",                 // 9
            DnsType::NULL => "NULL",             // 10
            DnsType::WKS => "WKS",               // 11
            DnsType::PTR => "PTR",               // 12
            DnsType::HINFO => "HINFO",           // 13
            DnsType::MINFO => "MINFO",           // 14
            DnsType::MX => "MX",                 // 15
            DnsType::TXT => "TXT",               // 16
            DnsType::RP => "RP",                 // 17
            DnsType::AFSDB => "AFSDB",           // 18
            DnsType::X25 => "X25",               // 19
            DnsType::ISDN => "ISDN",             // 20
            DnsType::RT => "RT",                 // 21
            DnsType::NSAP => "NSAP",             // 22
            DnsType::NSAP_PTR => "NSAP_PTR",     // 23
            DnsType::SIG => "SIG",               // 24
            DnsType::KEY => "KEY",               // 25
            DnsType::PX => "PX",                 // 26
            DnsType::GPOS => "GPOS",             // 27
            DnsType::AAAA => "AAAA",             // 28
            DnsType::LOC => "LOC",               // 29
            DnsType::NXT => "NXT",               // 30
            DnsType::EID => "EID",               // 31
            DnsType::NIMLOC => "NIMLOC",         // 32
            DnsType::SRV => "SRV",               // 33
            DnsType::ATMA => "ATMA",             // 34
            DnsType::NAPTR => "NAPTR",           // 35
            DnsType::KX => "KX",                 // 36
            DnsType::CERT => "CERT",             // 37
            DnsType::A6 => "A6",                 // 38
            DnsType::DNAME => "DNAME",           // 39
            DnsType::SINK => "SINK",             // 40
            DnsType::OPT => "OPT",               // 41
            DnsType::APL => "APL",               // 42
            DnsType::DS => "DS",                 // 43
            DnsType::SSHFP => "SSHFP",           // 44
            DnsType::IPSECKEY => "IPSECKEY",     // 45
            DnsType::RRSIG => "RRSIG",           // 46
            DnsType::NSEC => "NSEC",             // 47
            DnsType::DNSKEY => "DNSKEY",         // 48
            DnsType::DHCID => "DHCID",           // 49
            DnsType::NSEC3 => "NSEC3",           // 50
            DnsType::NSEC3PARAM => "NSEC3PARAM", // 51
            DnsType::TLSA => "TLSA",             // 52
            DnsType::SMIMEA => "SMIMEA",         // 53
            DnsType::HIP => "HIP",               // 55
            DnsType::NINFO => "NINFO",           // 56
            DnsType::RKEY => "RKEY",             // 57
            DnsType::TALINK => "TALINK",         // 58
            DnsType::CDS => "CDS",               // 59
            DnsType::CDNSKEY => "CDNSKEY",       // 60
            DnsType::OPENPGPKEY => "OPENPGPKEY", // 61
            DnsType::CSYNC => "CSYNC",           // 62
            DnsType::ZONEMD => "ZONEMD",         // 63
            DnsType::SVCB => "SVCB",             // 64
            DnsType::HTTPS => "HTTPS",           // 65
            DnsType::SPF => "SPF",               // 99
            DnsType::UINFO => "UINFO",           // 100
            DnsType::UID => "UID",               // 101
            DnsType::GID => "GID",               // 102
            DnsType::UNSPEC => "UNSPEC",         // 103
            DnsType::NID => "NID",               // 104
            DnsType::L32 => "L32",               // 105
            DnsType::L64 => "L64",               // 106
            DnsType::LP => "LP",                 // 107
            DnsType::EUI48 => "EUI48",           // 108
            DnsType::EUI64 => "EUI64",           // 109
            DnsType::TKEY => "TKEY",             // 249
            DnsType::TSIG => "TSIG",             // 250
            DnsType::IXFR => "IXFR",             // 251
            DnsType::AXFR => "AXFR",             // 252
            DnsType::MAILB => "MAILB",           // 253
            DnsType::MAILA => "MAILA",           // 254
            DnsType::ANY => "ANY",               // 255
            DnsType::URI => "URI",               // 256
            DnsType::CAA => "CAA",               // 257
            DnsType::AVC => "AVC",               // 258
            DnsType::DOA => "DOA",               // 259
            DnsType::AMTRELAY => "AMTRELAY",     // 260
            DnsType::TA => "TA",                 // 32768
            DnsType::DLV => "DLV",               // 32769
            _ => "unknown",
        }
    }
}

/// Represents an DNS operation code.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    pub fn value(&self) -> u8 {
        match self {
            Self::Query => 0,
            Self::InverseQuery => 1,
            Self::Status => 2,
            Self::Reserved => 3,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Dso => 6,
            Self::Unassigned(v) => *v,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::InverseQuery => "Inverse Query",
            Self::Status => "Status",
            Self::Reserved => "Reserved",
            Self::Notify => "Notify",
            Self::Update => "Update",
            Self::Dso => "DSO",
            Self::Unassigned(_) => "Unassigned",
        }
    }
}

/// Represents an DNS return code.
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
            12 => Self::BadVers,
            13 => Self::BadKey,
            14 => Self::BadTime,
            15 => Self::BadMode,
            16 => Self::BadName,
            17 => Self::BadAlg,
            18 => Self::BadTrunc,
            19 => Self::BadCookie,
            _ => Self::Unassigned(value),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YXDomain => 6,
            Self::YXRRSet => 7,
            Self::NXRRSet => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::Dsotypeni => 11,
            Self::BadVers => 12,
            Self::BadKey => 13,
            Self::BadTime => 14,
            Self::BadMode => 15,
            Self::BadName => 16,
            Self::BadAlg => 17,
            Self::BadTrunc => 18,
            Self::BadCookie => 19,
            Self::Unassigned(v) => *v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RetCode::NoError => "No Error",
            RetCode::FormErr => "Format Error",
            RetCode::ServFail => "Server Failure",
            RetCode::NXDomain => "Non-Existent Domain",
            RetCode::NotImp => "Not Implemented",
            RetCode::Refused => "Query Refused",
            RetCode::YXDomain => "Name Exists When It Shouldn't",
            RetCode::YXRRSet => "RR Set Exists When It Shouldn't",
            RetCode::NXRRSet => "RR Set Doesn't Exist When It Should",
            RetCode::NotAuth => "Not Authorized",
            RetCode::NotZone => "Name Not Zone",
            RetCode::Dsotypeni => "DSO Type NI",
            RetCode::BadVers => "Bad Version",
            RetCode::BadKey => "Bad Key",
            RetCode::BadTime => "Bad Time",
            RetCode::BadMode => "Bad Mode",
            RetCode::BadName => "Bad Name",
            RetCode::BadAlg => "Bad Algorithm",
            RetCode::BadTrunc => "Bad Truncation",
            RetCode::BadCookie => "Bad Cookie",
            RetCode::Unassigned(_) => "Unassigned",
        }
    }
}

/// DNS query packet structure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DnsQueryPacket {
    pub qname: Vec<u8>,
    pub qtype: DnsType,
    pub qclass: DnsClass,
    pub payload: Bytes,
}

impl Packet for DnsQueryPacket {
    type Header = ();
    fn from_buf(buf: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let mut qname = Vec::new();

        // Parse the QNAME field
        loop {
            if pos >= buf.len() {
                return None;
            }

            let len = buf[pos];
            pos += 1;
            qname.push(len);

            if len == 0 {
                break;
            }

            if pos + len as usize > buf.len() {
                return None;
            }

            qname.extend_from_slice(&buf[pos..pos + len as usize]);
            pos += len as usize;
        }

        // Read QTYPE and QCLASS
        if pos + 4 > buf.len() {
            return None;
        }

        let qtype = DnsType::new(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let qclass = DnsClass::new(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        pos += 4;

        // The rest is stored as payload
        let payload = Bytes::copy_from_slice(&buf[pos..]);

        Some(Self {
            qname,
            qtype,
            qclass,
            payload,
        })
    }

    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.qname.len() + 4);
        buf.extend_from_slice(&self.qname);
        buf.put_u16(self.qtype.value());
        buf.put_u16(self.qclass.value());
        buf.freeze()
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(0..self.header_len())
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        self.qname.len() + 4
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        let header = ();
        let payload = self.payload;
        (header, payload)
    }
}

impl DnsQueryPacket {
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
    pub fn qname_length(&self) -> usize {
        self.to_bytes().iter().take_while(|w| *w != &0).count() + 1
    }
    pub fn from_buf_mut(buf: &mut &[u8]) -> Option<Self> {
        let mut qname = Vec::new();

        loop {
            if buf.is_empty() {
                return None;
            }
            let len = buf[0];
            *buf = &buf[1..];
            qname.push(len);
            if len == 0 {
                break;
            }
            if buf.len() < len as usize {
                return None;
            }
            qname.extend_from_slice(&buf[..len as usize]);
            *buf = &buf[len as usize..];
        }

        if buf.len() < 4 {
            return None;
        }

        let qtype = DnsType::new(u16::from_be_bytes([buf[0], buf[1]]));
        *buf = &buf[2..];

        let qclass = DnsClass::new(u16::from_be_bytes([buf[0], buf[1]]));
        *buf = &buf[2..];

        let payload = Bytes::copy_from_slice(buf);

        Some(Self {
            qname,
            qtype,
            qclass,
            payload,
        })
    }
}

/// DNS response packet structure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DnsResponsePacket {
    pub name_tag: u16be,
    pub rtype: DnsType,
    pub rclass: DnsClass,
    pub ttl: u32be,
    pub data_len: u16be,
    pub data: Vec<u8>,
    pub payload: Bytes,
}

impl Packet for DnsResponsePacket {
    type Header = ();
    fn from_buf(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let mut pos = 0;

        let name_tag = u16::from_be_bytes([buf[pos], buf[pos + 1]]).into();
        pos += 2;

        let rtype = DnsType::new(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;

        let rclass = DnsClass::new(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;

        let ttl = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]).into();
        pos += 4;

        let data_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]).into();
        pos += 2;

        let data_len_usize = data_len as usize;

        if buf.len() < pos + data_len_usize {
            return None;
        }

        let data = buf[pos..pos + data_len_usize].to_vec();
        pos += data_len_usize;

        let payload = Bytes::copy_from_slice(&buf[pos..]);

        Some(Self {
            name_tag,
            rtype,
            rclass,
            ttl,
            data_len,
            data,
            payload,
        })
    }
    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::with_capacity(self.total_len());

        buf.put_u16(self.name_tag.into());
        buf.put_u16(self.rtype.value());
        buf.put_u16(self.rclass.value());
        buf.put_u32(self.ttl.into());
        buf.put_u16(self.data_len.into());
        buf.put_slice(&self.data);

        buf.freeze()
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(0..self.total_len())
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        12
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        let header = ();
        let payload = self.payload;
        (header, payload)
    }
}

impl DnsResponsePacket {
    /// Creates a new `DnsResponsePacket` from a mutable buffer.
    pub fn from_buf_mut(buf: &mut &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        // name_tag (2)
        let name_tag = u16::from_be_bytes([buf[0], buf[1]]).into();
        *buf = &buf[2..];

        // rtype (2)
        let rtype = DnsType::new(u16::from_be_bytes([buf[0], buf[1]]));
        *buf = &buf[2..];

        // rclass (2)
        let rclass = DnsClass::new(u16::from_be_bytes([buf[0], buf[1]]));
        *buf = &buf[2..];

        // ttl (4)
        let ttl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        *buf = &buf[4..];

        // data_len (2)
        let data_len = u16::from_be_bytes([buf[0], buf[1]]);
        *buf = &buf[2..];

        let safe_data_len = std::cmp::min(buf.len(), data_len as usize);
        let data = buf[..safe_data_len].to_vec();
        *buf = &buf[safe_data_len..];

        // Remaining bytes are stored as payload
        let payload = Bytes::copy_from_slice(buf);

        Some(Self {
            name_tag,
            rtype,
            rclass,
            ttl,
            data_len: data_len.into(),
            data,
            payload,
        })
    }

    /// Returns the IPv4 address if the record type is A and data length is 4 bytes.
    pub fn get_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rtype == DnsType::A && self.data.len() == 4 {
            Some(Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }
    /// Returns the IPv6 address if the record type is AAAA and data length is 16 bytes.
    pub fn get_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rtype == DnsType::AAAA && self.data.len() == 16 {
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(&self.data[..]).ok()?))
        } else {
            None
        }
    }

    /// Returns the IP address based on the record type.
    pub fn get_ip(&self) -> Option<IpAddr> {
        match self.rtype {
            DnsType::A => self.get_ipv4().map(IpAddr::V4),
            DnsType::AAAA => self.get_ipv6().map(IpAddr::V6),
            _ => None,
        }
    }

    /// Returns the DNS name if the record type is CNAME, NS, or PTR.
    pub fn get_name(&self) -> Option<DnsName> {
        match self.rtype {
            DnsType::CNAME | DnsType::NS | DnsType::PTR => DnsName::from_bytes(&self.data).ok(),
            _ => None,
        }
    }

    /// Returns the TXT strings if the record type is TXT.
    pub fn get_txt_strings(&self) -> Option<Vec<String>> {
        if self.rtype != DnsType::TXT {
            return None;
        }

        let mut pos = 0;
        let mut result = Vec::new();

        while pos < self.data.len() {
            let len = self.data[pos] as usize;
            pos += 1;
            if pos + len > self.data.len() {
                break;
            }

            match std::str::from_utf8(&self.data[pos..pos + len]) {
                Ok(s) => result.push(s.to_string()),
                Err(_) => return None,
            }

            pos += len;
        }

        Some(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DnsHeader {
    pub id: u16be,
    pub is_response: u1,
    pub opcode: OpCode,
    pub is_authoriative: u1,
    pub is_truncated: u1,
    pub is_recursion_desirable: u1,
    pub is_recursion_available: u1,
    pub zero_reserved: u1,
    pub is_answer_authenticated: u1,
    pub is_non_authenticated_data: u1,
    pub rcode: RetCode,
    pub query_count: u16be,
    pub response_count: u16be,
    pub authority_rr_count: u16be,
    pub additional_rr_count: u16be,
}

/// Represents a DNS packet.
/// Including its header and all the associated records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQueryPacket>,
    pub responses: Vec<DnsResponsePacket>,
    pub authorities: Vec<DnsResponsePacket>,
    pub additionals: Vec<DnsResponsePacket>,
    pub payload: Bytes,
}

impl Packet for DnsPacket {
    type Header = ();
    fn from_buf(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let mut cursor = buf;

        // Read DNS header
        let id = u16::from_be_bytes([cursor[0], cursor[1]]);
        let flags = u16::from_be_bytes([cursor[2], cursor[3]]);
        let query_count = u16::from_be_bytes([cursor[4], cursor[5]]);
        let response_count = u16::from_be_bytes([cursor[6], cursor[7]]);
        let authority_rr_count = u16::from_be_bytes([cursor[8], cursor[9]]);
        let additional_rr_count = u16::from_be_bytes([cursor[10], cursor[11]]);
        cursor = &cursor[12..];

        let header = DnsHeader {
            id: id.into(),
            is_response: ((flags >> 15) & 0x1) as u8,
            opcode: OpCode::new(((flags >> 11) & 0xF) as u8),
            is_authoriative: ((flags >> 10) & 0x1) as u8,
            is_truncated: ((flags >> 9) & 0x1) as u8,
            is_recursion_desirable: ((flags >> 8) & 0x1) as u8,
            is_recursion_available: ((flags >> 7) & 0x1) as u8,
            zero_reserved: ((flags >> 6) & 0x1) as u8,
            is_answer_authenticated: ((flags >> 5) & 0x1) as u8,
            is_non_authenticated_data: ((flags >> 4) & 0x1) as u8,
            rcode: RetCode::new((flags & 0xF) as u8),
            query_count: query_count.into(),
            response_count: response_count.into(),
            authority_rr_count: authority_rr_count.into(),
            additional_rr_count: additional_rr_count.into(),
        };

        // Parse each section, passing mutable slices
        fn parse_queries(count: usize, buf: &mut &[u8]) -> Option<Vec<DnsQueryPacket>> {
            (0..count)
                .map(|_| DnsQueryPacket::from_buf_mut(buf))
                .collect()
        }

        fn parse_responses(count: usize, buf: &mut &[u8]) -> Option<Vec<DnsResponsePacket>> {
            let mut packets = Vec::with_capacity(count);
            for _ in 0..count {
                if let Some(pkt) = DnsResponsePacket::from_buf_mut(buf) {
                    packets.push(pkt);
                } else {
                    break;
                }
            }
            Some(packets)
        }

        let mut working_buf = cursor;

        let queries = parse_queries(query_count as usize, &mut working_buf)?;
        let responses = parse_responses(response_count as usize, &mut working_buf)?;
        let authorities = parse_responses(authority_rr_count as usize, &mut working_buf)?;
        let additionals = parse_responses(additional_rr_count as usize, &mut working_buf)?;

        // Remaining data becomes the payload
        let payload = Bytes::copy_from_slice(working_buf);

        Some(Self {
            header,
            queries,
            responses,
            authorities,
            additionals,
            payload,
        })
    }

    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)
    }

    fn to_bytes(&self) -> Bytes {
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::with_capacity(self.header_len() + self.payload.len());

        // DNS Header
        let mut flags = 0u16;
        flags |= (self.header.is_response as u16) << 15;
        flags |= (self.header.opcode.value() as u16) << 11;
        flags |= (self.header.is_authoriative as u16) << 10;
        flags |= (self.header.is_truncated as u16) << 9;
        flags |= (self.header.is_recursion_desirable as u16) << 8;
        flags |= (self.header.is_recursion_available as u16) << 7;
        flags |= (self.header.zero_reserved as u16) << 6;
        flags |= (self.header.is_answer_authenticated as u16) << 5;
        flags |= (self.header.is_non_authenticated_data as u16) << 4;
        flags |= self.header.rcode.value() as u16;

        buf.put_u16(self.header.id.into());
        buf.put_u16(flags);
        buf.put_u16(self.header.query_count.into());
        buf.put_u16(self.header.response_count.into());
        buf.put_u16(self.header.authority_rr_count.into());
        buf.put_u16(self.header.additional_rr_count.into());

        // Write all queries
        for query in &self.queries {
            buf.extend_from_slice(&query.to_bytes());
        }

        // Write all responses
        for response in &self.responses {
            buf.extend_from_slice(&response.to_bytes());
        }

        // Write authorities
        for auth in &self.authorities {
            buf.extend_from_slice(&auth.to_bytes());
        }

        // Write additionals
        for add in &self.additionals {
            buf.extend_from_slice(&add.to_bytes());
        }

        Bytes::from(buf)
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(0..12)
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        12
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        let header = ();
        let payload = self.payload;
        (header, payload)
    }
}

/// Represents a DNS name
pub struct DnsName(String);

impl DnsName {
    /// Creates a new `DnsName` string from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Utf8Error> {
        let mut pos = 0;
        let mut labels = Vec::new();

        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 {
                break;
            }
            pos += 1;
            if pos + len > buf.len() {
                break;
            }
            let label = std::str::from_utf8(&buf[pos..pos + len])?;
            labels.push(label);
            pos += len;
        }

        Ok(DnsName(labels.join(".")))
    }

    /// Returns the DNS name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Splits the DNS name into its labels.
    /// For example, "example.com" becomes ["example", "com"].
    pub fn labels(&self) -> Vec<&str> {
        self.0.split('.').collect()
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query() {
        let bytes = Bytes::from_static(&[
            0x07, b'b', b'e', b'a', b'c', b'o', b'n', b's', 0x04, b'g', b'v', b't', b'2', 0x03,
            b'c', b'o', b'm', 0x00, 0x00, 0x41, 0x00, 0x01, // type: HTTPS, class: IN
        ]);
        let packet = DnsQueryPacket::from_bytes(bytes).unwrap();
        assert_eq!(
            packet.qname,
            vec![
                0x07, b'b', b'e', b'a', b'c', b'o', b'n', b's', 0x04, b'g', b'v', b't', b'2', 0x03,
                b'c', b'o', b'm', 0x00
            ]
        );
        assert_eq!(packet.qtype, DnsType::HTTPS);
        assert_eq!(packet.qclass, DnsClass::IN);
    }

    #[test]
    fn test_dns_response() {
        let bytes = Bytes::from_static(&[
            0xc0, 0x0c, // name_tag
            0x00, 0x01, // type = A
            0x00, 0x01, // class = IN
            0x00, 0x00, 0x00, 0x3c, // TTL = 60
            0x00, 0x04, // data_len = 4
            0x0d, 0xe2, 0x02, 0x12, // data
        ]);
        let packet = DnsResponsePacket::from_bytes(bytes).unwrap();
        assert_eq!(packet.rtype, DnsType::A);
        assert_eq!(packet.rclass, DnsClass::IN);
        assert_eq!(packet.ttl, 60);
        assert_eq!(packet.data_len, 4);
        assert_eq!(packet.data, vec![13, 226, 2, 18]);
    }

    #[test]
    fn test_dns_query_packet() {
        let bytes = Bytes::from_static(&[
            0x9b, 0xa0, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'_',
            b'l', b'd', b'a', b'p', 0x04, b'_', b't', b'c', b'p', 0x02, b'd', b'c', 0x06, b'_',
            b'm', b's', b'd', b'c', b's', 0x05, b'S', b'4', b'D', b'O', b'M', 0x07, b'P', b'R',
            b'I', b'V', b'A', b'T', b'E', 0x00, 0x00, 0x21, 0x00, 0x01,
        ]);
        let packet = DnsPacket::from_bytes(bytes).unwrap();
        assert_eq!(packet.header.id, 0x9ba0);
        assert_eq!(packet.header.is_response, 0);
        assert_eq!(packet.header.query_count, 1);
        assert_eq!(packet.queries.len(), 1);
        assert_eq!(
            packet.queries[0].get_qname_parsed().unwrap(),
            "_ldap._tcp.dc._msdcs.S4DOM.PRIVATE"
        );
        assert_eq!(packet.queries[0].qtype, DnsType::SRV);
        assert_eq!(packet.queries[0].qclass, DnsClass::IN);
    }
    #[test]
    fn test_dns_response_packet() {
        let bytes = Bytes::from_static(&[
            0xbc, 0x12, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, b's',
            b'4', b'd', b'c', b'1', 0x05, b's', b'a', b'm', b'b', b'a', 0x08, b'w', b'i', b'n',
            b'd', b'o', b'w', b's', b'8', 0x07, b'p', b'r', b'i', b'v', b'a', b't', b'e', 0x00,
            0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x84,
            0x00, 0x04, 0xc0, 0xa8, 0x7a, 0xbd,
        ]);
        let packet = DnsPacket::from_bytes(bytes).unwrap();
        assert_eq!(packet.header.id, 0xbc12);
        assert_eq!(packet.header.is_response, 1);
        assert_eq!(packet.header.query_count, 1);
        assert_eq!(packet.header.response_count, 1);
        assert_eq!(packet.queries.len(), 1);
        assert_eq!(
            packet.queries[0].get_qname_parsed().unwrap(),
            "s4dc1.samba.windows8.private"
        );
        assert_eq!(packet.queries[0].qtype, DnsType::A);
        assert_eq!(packet.responses[0].rtype, DnsType::A);
        assert_eq!(packet.responses[0].rclass, DnsClass::IN);
        assert_eq!(packet.responses[0].ttl, 900);
        assert_eq!(packet.responses[0].data_len, 4);
        assert_eq!(packet.responses[0].data, vec![192, 168, 122, 189]);
    }
}
