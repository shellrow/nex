//! An ethernet packet abstraction.

use crate::PrimitiveValues;

use alloc::vec::Vec;
use core::fmt;

use xenet_core::mac::MacAddr;
use xenet_macro::packet;

/// Represents the Ethernet header length.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Represents the Ethernet Header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub destination: MacAddr,
    /// Source MAC address
    pub source: MacAddr,
    /// EtherType
    pub ethertype: EtherType,
}

/// Represents an Ethernet packet.
#[packet]
pub struct Ethernet {
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub destination: MacAddr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub source: MacAddr,
    #[construct_with(u16)]
    pub ethertype: EtherType,
    #[payload]
    pub payload: Vec<u8>,
}

#[test]
fn ethernet_header_test() {
    let mut packet = [0u8; 14];
    {
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).unwrap();

        let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        ethernet_header.set_source(source);
        assert_eq!(ethernet_header.get_source(), source);

        let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
        ethernet_header.set_destination(dest);
        assert_eq!(ethernet_header.get_destination(), dest);

        ethernet_header.set_ethertype(EtherType::Ipv6);
        assert_eq!(ethernet_header.get_ethertype(), EtherType::Ipv6);
    }

    let ref_packet = [
        0xde, 0xf0, 0x12, 0x34, 0x45, 0x67, /* destination */
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, /* source */
        0x86, 0xdd, /* ethertype */
    ];
    assert_eq!(&ref_packet[..], &packet[..]);
}

/// Represents the Ethernet types.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum EtherType {
    Ipv4,
    Arp,
    WakeOnLan,
    Trill,
    DECnet,
    Rarp,
    AppleTalk,
    Aarp,
    Ipx,
    Qnx,
    Ipv6,
    FlowControl,
    CobraNet,
    Mpls,
    MplsMcast,
    PppoeDiscovery,
    PppoeSession,
    Vlan,
    PBridge,
    Lldp,
    Ptp,
    Cfm,
    QinQ,
    Rldp,
    Unknown(u16),
}

impl EtherType {
    /// Constructs a new EtherType from u16
    pub fn new(value: u16) -> EtherType {
        match value {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x0842 => EtherType::WakeOnLan,
            0x22F3 => EtherType::Trill,
            0x6003 => EtherType::DECnet,
            0x8035 => EtherType::Rarp,
            0x809B => EtherType::AppleTalk,
            0x80F3 => EtherType::Aarp,
            0x8137 => EtherType::Ipx,
            0x8204 => EtherType::Qnx,
            0x86DD => EtherType::Ipv6,
            0x8808 => EtherType::FlowControl,
            0x8819 => EtherType::CobraNet,
            0x8847 => EtherType::Mpls,
            0x8848 => EtherType::MplsMcast,
            0x8863 => EtherType::PppoeDiscovery,
            0x8864 => EtherType::PppoeSession,
            0x8100 => EtherType::Vlan,
            0x88a8 => EtherType::PBridge,
            0x88cc => EtherType::Lldp,
            0x88f7 => EtherType::Ptp,
            0x8902 => EtherType::Cfm,
            0x9100 => EtherType::QinQ,
            0x8899 => EtherType::Rldp,
            _ => EtherType::Unknown(value),
        }
    }
    /// Return the name of the EtherType
    pub fn name(&self) -> &str {
        match *self {
            EtherType::Ipv4 => "IPv4",
            EtherType::Arp => "ARP",
            EtherType::WakeOnLan => "WakeOnLan",
            EtherType::Trill => "Trill",
            EtherType::DECnet => "DECnet",
            EtherType::Rarp => "RARP",
            EtherType::AppleTalk => "AppleTalk",
            EtherType::Aarp => "AARP",
            EtherType::Ipx => "IPX",
            EtherType::Qnx => "QNX",
            EtherType::Ipv6 => "IPv6",
            EtherType::FlowControl => "FlowControl",
            EtherType::CobraNet => "CobraNet",
            EtherType::Mpls => "MPLS",
            EtherType::MplsMcast => "MPLS Multicast",
            EtherType::PppoeDiscovery => "PPPoE Discovery",
            EtherType::PppoeSession => "PPPoE Session",
            EtherType::Vlan => "VLAN",
            EtherType::PBridge => "Provider Bridging",
            EtherType::Lldp => "LLDP",
            EtherType::Ptp => "PTP",
            EtherType::Cfm => "CFM",
            EtherType::QinQ => "QinQ",
            EtherType::Rldp => "RLDP",
            EtherType::Unknown(_) => "Unknown",
        }
    }
}

impl PrimitiveValues for EtherType {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        match *self {
            EtherType::Ipv4 => (0x0800,),
            EtherType::Arp => (0x0806,),
            EtherType::WakeOnLan => (0x0842,),
            EtherType::Trill => (0x22F3,),
            EtherType::DECnet => (0x6003,),
            EtherType::Rarp => (0x8035,),
            EtherType::AppleTalk => (0x809B,),
            EtherType::Aarp => (0x80F3,),
            EtherType::Ipx => (0x8137,),
            EtherType::Qnx => (0x8204,),
            EtherType::Ipv6 => (0x86DD,),
            EtherType::FlowControl => (0x8808,),
            EtherType::CobraNet => (0x8819,),
            EtherType::Mpls => (0x8847,),
            EtherType::MplsMcast => (0x8848,),
            EtherType::PppoeDiscovery => (0x8863,),
            EtherType::PppoeSession => (0x8864,),
            EtherType::Vlan => (0x8100,),
            EtherType::PBridge => (0x88a8,),
            EtherType::Lldp => (0x88cc,),
            EtherType::Ptp => (0x88f7,),
            EtherType::Cfm => (0x8902,),
            EtherType::QinQ => (0x9100,),
            EtherType::Rldp => (0x8899,),
            EtherType::Unknown(n) => (n,),
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EtherType::Ipv4 => "Ipv4",
                EtherType::Arp => "Arp",
                EtherType::WakeOnLan => "WakeOnLan",
                EtherType::Trill => "Trill",
                EtherType::DECnet => "DECnet",
                EtherType::Rarp => "Rarp",
                EtherType::AppleTalk => "AppleTalk",
                EtherType::Aarp => "Aarp",
                EtherType::Ipx => "Ipx",
                EtherType::Qnx => "Qnx",
                EtherType::Ipv6 => "Ipv6",
                EtherType::FlowControl => "FlowControl",
                EtherType::CobraNet => "CobraNet",
                EtherType::Mpls => "Mpls",
                EtherType::MplsMcast => "MplsMcast",
                EtherType::PppoeDiscovery => "PppoeDiscovery",
                EtherType::PppoeSession => "PppoeSession",
                EtherType::Vlan => "Vlan",
                EtherType::PBridge => "PBridge",
                EtherType::Lldp => "Lldp",
                EtherType::Ptp => "Ptp",
                EtherType::Cfm => "Cfm",
                EtherType::QinQ => "QinQ",
                EtherType::Rldp => "Rldp",
                EtherType::Unknown(_) => "unknown",
            }
        )
    }
}

#[test]
fn ether_type_to_str() {
    use std::format;
    let ipv4 = EtherType::new(0x0800);
    assert_eq!(format!("{}", ipv4), "Ipv4");
    let arp = EtherType::new(0x0806);
    assert_eq!(format!("{}", arp), "Arp");
    let unknown = EtherType::new(0x0666);
    assert_eq!(format!("{}", unknown), "unknown");
}
