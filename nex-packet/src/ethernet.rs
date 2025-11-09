//! An ethernet packet abstraction.

use bytes::Bytes;
use core::fmt;
use nex_core::mac::MacAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::packet::{MutablePacket, Packet};

/// Represents the Ethernet header length.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Represents the MAC address length.
pub const MAC_ADDR_LEN: usize = 6;

/// Represents the Ethernet types.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    pub fn value(&self) -> u16 {
        match *self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::WakeOnLan => 0x0842,
            EtherType::Trill => 0x22F3,
            EtherType::DECnet => 0x6003,
            EtherType::Rarp => 0x8035,
            EtherType::AppleTalk => 0x809B,
            EtherType::Aarp => 0x80F3,
            EtherType::Ipx => 0x8137,
            EtherType::Qnx => 0x8204,
            EtherType::Ipv6 => 0x86DD,
            EtherType::FlowControl => 0x8808,
            EtherType::CobraNet => 0x8819,
            EtherType::Mpls => 0x8847,
            EtherType::MplsMcast => 0x8848,
            EtherType::PppoeDiscovery => 0x8863,
            EtherType::PppoeSession => 0x8864,
            EtherType::Vlan => 0x8100,
            EtherType::PBridge => 0x88a8,
            EtherType::Lldp => 0x88cc,
            EtherType::Ptp => 0x88f7,
            EtherType::Cfm => 0x8902,
            EtherType::QinQ => 0x9100,
            EtherType::Rldp => 0x8899,
            EtherType::Unknown(value) => value,
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Represents the Ethernet Header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EthernetHeader {
    /// Destination MAC address
    pub destination: MacAddr,
    /// Source MAC address
    pub source: MacAddr,
    /// EtherType
    pub ethertype: EtherType,
}

impl EthernetHeader {
    /// Construct an Ethernet header from a byte slice.
    pub fn from_bytes(packet: Bytes) -> Result<EthernetHeader, String> {
        if packet.len() < ETHERNET_HEADER_LEN {
            return Err("Packet is too small for Ethernet header".to_string());
        }
        match EthernetPacket::from_bytes(packet) {
            Some(ethernet_packet) => Ok(EthernetHeader {
                destination: ethernet_packet.get_destination(),
                source: ethernet_packet.get_source(),
                ethertype: ethernet_packet.get_ethertype(),
            }),
            None => Err("Failed to parse Ethernet packet".to_string()),
        }
    }
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(ETHERNET_HEADER_LEN);
        buf.extend_from_slice(&self.destination.octets());
        buf.extend_from_slice(&self.source.octets());
        buf.extend_from_slice(&self.ethertype.value().to_be_bytes());
        Bytes::from(buf)
    }
}

/// Represents an Ethernet packet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EthernetPacket {
    /// The Ethernet header.
    pub header: EthernetHeader,
    pub payload: Bytes,
}

impl Packet for EthernetPacket {
    type Header = EthernetHeader;

    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ETHERNET_HEADER_LEN {
            return None;
        }
        let destination = MacAddr::from_octets(bytes[0..MAC_ADDR_LEN].try_into().unwrap());
        let source =
            MacAddr::from_octets(bytes[MAC_ADDR_LEN..2 * MAC_ADDR_LEN].try_into().unwrap());
        let ethertype = EtherType::new(u16::from_be_bytes([bytes[12], bytes[13]]));
        let payload = Bytes::copy_from_slice(&bytes[ETHERNET_HEADER_LEN..]);

        Some(EthernetPacket {
            header: EthernetHeader {
                destination,
                source,
                ethertype,
            },
            payload,
        })
    }
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }
    fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(ETHERNET_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        Bytes::from(buf)
    }
    fn header(&self) -> Bytes {
        self.header.to_bytes()
    }
    fn payload(&self) -> Bytes {
        self.payload.clone()
    }
    fn header_len(&self) -> usize {
        ETHERNET_HEADER_LEN
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

impl EthernetPacket {
    /// Create a new Ethernet packet.
    pub fn new(header: EthernetHeader, payload: Bytes) -> Self {
        EthernetPacket { header, payload }
    }
    /// Get the destination MAC address.
    pub fn get_destination(&self) -> MacAddr {
        self.header.destination
    }

    /// Get the source MAC address.
    pub fn get_source(&self) -> MacAddr {
        self.header.source
    }

    /// Get the EtherType.
    pub fn get_ethertype(&self) -> EtherType {
        self.header.ethertype
    }

    pub fn ip_packet(&self) -> Option<Bytes> {
        if self.get_ethertype() == EtherType::Ipv4 || self.get_ethertype() == EtherType::Ipv6 {
            Some(self.payload.clone())
        } else {
            None
        }
    }
}

impl fmt::Display for EthernetPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EthernetPacket {{ destination: {}, source: {}, ethertype: {} }}",
            self.get_destination(),
            self.get_source(),
            self.get_ethertype()
        )
    }
}

/// Represents a mutable Ethernet packet.
pub struct MutableEthernetPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> MutablePacket<'a> for MutableEthernetPacket<'a> {
    type Packet = EthernetPacket;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < ETHERNET_HEADER_LEN {
            None
        } else {
            Some(Self { buffer })
        }
    }

    fn packet(&self) -> &[u8] {
        &*self.buffer
    }

    fn packet_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn header(&self) -> &[u8] {
        &self.packet()[..ETHERNET_HEADER_LEN]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let (header, _) = (&mut *self.buffer).split_at_mut(ETHERNET_HEADER_LEN);
        header
    }

    fn payload(&self) -> &[u8] {
        &self.packet()[ETHERNET_HEADER_LEN..]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let (_, payload) = (&mut *self.buffer).split_at_mut(ETHERNET_HEADER_LEN);
        payload
    }
}

impl<'a> MutableEthernetPacket<'a> {
    /// Create a mutable packet without performing size checks.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    /// Retrieve the destination MAC address.
    pub fn get_destination(&self) -> MacAddr {
        MacAddr::from_octets(self.header()[0..MAC_ADDR_LEN].try_into().unwrap())
    }

    /// Update the destination MAC address.
    pub fn set_destination(&mut self, addr: MacAddr) {
        self.header_mut()[0..MAC_ADDR_LEN].copy_from_slice(&addr.octets());
    }

    /// Retrieve the source MAC address.
    pub fn get_source(&self) -> MacAddr {
        MacAddr::from_octets(
            self.header()[MAC_ADDR_LEN..2 * MAC_ADDR_LEN]
                .try_into()
                .unwrap(),
        )
    }

    /// Update the source MAC address.
    pub fn set_source(&mut self, addr: MacAddr) {
        self.header_mut()[MAC_ADDR_LEN..2 * MAC_ADDR_LEN].copy_from_slice(&addr.octets());
    }

    /// Retrieve the EtherType.
    pub fn get_ethertype(&self) -> EtherType {
        EtherType::new(u16::from_be_bytes([self.header()[12], self.header()[13]]))
    }

    /// Update the EtherType.
    pub fn set_ethertype(&mut self, ty: EtherType) {
        let bytes = ty.value().to_be_bytes();
        self.header_mut()[12..14].copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use nex_core::mac::MacAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ethernet_parse_basic() {
        let raw = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
            0x08, 0x00, // EtherType: IPv4
            0xde, 0xad, 0xbe, 0xef, // Payload (dummy)
        ];
        let packet = EthernetPacket::from_bytes(Bytes::copy_from_slice(&raw)).unwrap();
        assert_eq!(
            packet.get_destination(),
            MacAddr::from_octets([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            packet.get_source(),
            MacAddr::from_octets([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );
        assert_eq!(packet.get_ethertype(), EtherType::Ipv4);
        assert_eq!(packet.payload.len(), 4);
    }

    #[test]
    fn test_ethernet_serialize_roundtrip() {
        let original = EthernetPacket {
            header: EthernetHeader {
                destination: MacAddr::from_octets([1, 2, 3, 4, 5, 6]),
                source: MacAddr::from_octets([10, 20, 30, 40, 50, 60]),
                ethertype: EtherType::Arp,
            },
            payload: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
        };

        let bytes = original.to_bytes();
        let parsed = EthernetPacket::from_bytes(bytes).unwrap();

        assert_eq!(parsed, original);
    }

    #[test]
    fn test_ethernet_header_parse_and_serialize() {
        let header = EthernetHeader {
            destination: MacAddr::from_octets([1, 1, 1, 1, 1, 1]),
            source: MacAddr::from_octets([2, 2, 2, 2, 2, 2]),
            ethertype: EtherType::Ipv6,
        };
        let bytes = header.to_bytes();
        let parsed = EthernetHeader::from_bytes(bytes.clone()).unwrap();

        assert_eq!(header, parsed);
        assert_eq!(bytes.len(), ETHERNET_HEADER_LEN);
    }

    #[test]
    fn test_ethernet_parse_too_short() {
        let short = Bytes::from_static(&[0, 1, 2, 3]); // insufficient length
        assert!(EthernetPacket::from_bytes(short).is_none());
    }

    #[test]
    fn test_ethernet_unknown_ethertype() {
        let raw = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xde,
            0xad, // Unknown EtherType
            0x00, 0x11, 0x22, 0x33,
        ];
        let packet = EthernetPacket::from_bytes(Bytes::copy_from_slice(&raw)).unwrap();
        match packet.get_ethertype() {
            EtherType::Unknown(val) => assert_eq!(val, 0xdead),
            _ => panic!("Expected unknown EtherType"),
        }
    }

    #[test]
    fn test_mutable_chaining_updates_in_place() {
        let mut raw = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
            0x08, 0x00, // IPv4 EtherType
            0x45, 0x00, 0x00, 0x1c, // IPv4 header start (20 bytes header + 8 bytes payload)
            0x1c, 0x46, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // rest of IPv4 header
            0xc0, 0xa8, 0x00, 0x01, // src IP
            0xc0, 0xa8, 0x00, 0xc7, // dst IP
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // payload
        ];

        let mut ethernet = MutableEthernetPacket::new(&mut raw).expect("mutable ethernet");
        assert_eq!(ethernet.get_ethertype(), EtherType::Ipv4);

        use crate::ipv4::MutableIpv4Packet;

        {
            let mut ipv4 = MutableIpv4Packet::new(ethernet.payload_mut()).expect("mutable ipv4");
            ipv4.set_ttl(99);
            ipv4.set_source(Ipv4Addr::new(10, 0, 0, 1));
            ipv4.payload_mut()[0] = 0xaa;
        }

        {
            let packet_view = ethernet.packet();
            assert_eq!(packet_view[22], 99);
            assert_eq!(&packet_view[26..30], &[10, 0, 0, 1]);
            assert_eq!(packet_view[34], 0xaa);
        }

        drop(ethernet);
        assert_eq!(raw[22], 99);
        assert_eq!(&raw[26..30], &[10, 0, 0, 1]);
        assert_eq!(raw[34], 0xaa);
    }
}
