use xenet_macro_helper::packet::Packet;

use crate::ethernet::{EthernetPacket, EtherType};
use crate::ethernet::EthernetHeader;
use crate::arp::{ArpHeader, ArpPacket};
use crate::ip::IpNextLevelProtocol;
use crate::ipv4::{Ipv4Header, Ipv4Packet};
use crate::ipv6::{Ipv6Header, Ipv6Packet};
use crate::tcp::{TcpHeader, TcpPacket};
use crate::udp::{UdpHeader, UdpPacket};
use crate::icmp::{IcmpHeader, IcmpPacket};
use crate::icmpv6::{Icmpv6Header, Icmpv6Packet};

/// Represents a data link layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatalinkLayer {
    pub ethernet: Option<EthernetHeader>,
    pub arp: Option<ArpHeader>,
}

/// Represents an IP layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpLayer {
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
}

/// Represents a transport layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportLayer {
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
}

/// Represents a packet frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The datalink layer.
    pub datalink: Option<DatalinkLayer>,
    /// The IP layer.
    pub ip: Option<IpLayer>,
    /// The transport layer.
    pub transport: Option<TransportLayer>,
    /// Rest of the packet that could not be parsed as a header. (Usually payload)
    pub payload: &'a [u8],
    packet: &'a [u8],
}

impl Frame<'_> {
    /// Construct a frame from a byte slice.
    pub fn from_bytes(packet: &[u8]) -> Frame {
        parse_packet(packet)
    }
    /// Return packet as a byte array.
    pub fn packet(&self) -> Vec<u8> {
        self.packet.to_vec()
    }
    /// Return packet length.
    pub fn packet_len(&self) -> usize {
        self.packet.len()
    }
}

fn parse_packet(packet: &[u8]) -> Frame {
    let mut frame = Frame {
        datalink: None,
        ip: None,
        transport: None,
        payload: &[],
        packet: packet,
    };
    let ethernet_packet = EthernetPacket::new(packet).unwrap();
    let ethernet_header = EthernetHeader::from_packet(&ethernet_packet);
    frame.datalink = Some(DatalinkLayer{
        ethernet: Some(ethernet_header),
        arp: None,
    });
    match ethernet_packet.get_ethertype() {
        EtherType::Ipv4 => {
            parse_ipv4_packet(&ethernet_packet, &mut frame);
        },
        EtherType::Ipv6 => {
            parse_ipv6_packet(&ethernet_packet, &mut frame);
        },
        EtherType::Arp => {
            let arp_packet = ArpPacket::new(packet).unwrap();
            let arp_header = ArpHeader::from_packet(&arp_packet);
            if let Some(datalink) = &mut frame.datalink {
                datalink.arp = Some(arp_header);
            }
        },
        _ => {}
    }
    frame
}

fn parse_ipv4_packet(ethernet_packet: &EthernetPacket, frame: &mut Frame) {
    let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
    let ipv4_header = Ipv4Header::from_packet(&ipv4_packet);
    frame.ip = Some(IpLayer{
        ipv4: Some(ipv4_header),
        ipv6: None,
        icmp: None,
        icmpv6: None,
    });
    match ipv4_packet.get_next_level_protocol() {
        IpNextLevelProtocol::Tcp => {
            parse_ipv4_tcp_packet(&ipv4_packet, frame);
        },
        IpNextLevelProtocol::Udp => {
            parse_ipv4_udp_packet(&ipv4_packet, frame);
        },
        IpNextLevelProtocol::Icmp => {
            parse_icmp_packet(&ipv4_packet, frame);
        },
        _ => {}
    }
}

fn parse_ipv6_packet(ethernet_packet: &EthernetPacket, frame: &mut Frame) {
    let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
    let ipv6_header = Ipv6Header::from_packet(&ipv6_packet);
    frame.ip = Some(IpLayer{
        ipv4: None,
        ipv6: Some(ipv6_header),
        icmp: None,
        icmpv6: None,
    });
    match ipv6_packet.get_next_header() {
        IpNextLevelProtocol::Tcp => {
            parse_ipv6_tcp_packet(&ipv6_packet, frame);
        },
        IpNextLevelProtocol::Udp => {
            parse_ipv6_udp_packet(&ipv6_packet, frame);
        },
        IpNextLevelProtocol::Icmpv6 => {
            parse_icmpv6_packet(&ipv6_packet, frame);
        },
        _ => {}
    }
}

fn parse_ipv4_tcp_packet(ipv4_packet: &Ipv4Packet, frame: &mut Frame) {
    let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
    let tcp_header = TcpHeader::from_packet(&tcp_packet);
    frame.transport = Some(TransportLayer{
        tcp: Some(tcp_header),
        udp: None,
    });
}

fn parse_ipv6_tcp_packet(ipv6_packet: &Ipv6Packet, frame: &mut Frame) {
    let tcp_packet = TcpPacket::new(ipv6_packet.payload()).unwrap();
    let tcp_header = TcpHeader::from_packet(&tcp_packet);
    frame.transport = Some(TransportLayer{
        tcp: Some(tcp_header),
        udp: None,
    });
}

fn parse_ipv4_udp_packet(ipv4_packet: &Ipv4Packet, frame: &mut Frame) {
    let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
    let udp_header = UdpHeader::from_packet(&udp_packet);
    frame.transport = Some(TransportLayer{
        tcp: None,
        udp: Some(udp_header),
    });
}

fn parse_ipv6_udp_packet(ipv6_packet: &Ipv6Packet, frame: &mut Frame) {
    let udp_packet = UdpPacket::new(ipv6_packet.payload()).unwrap();
    let udp_header = UdpHeader::from_packet(&udp_packet);
    frame.transport = Some(TransportLayer{
        tcp: None,
        udp: Some(udp_header),
    });
}

fn parse_icmp_packet(ipv4_packet: &Ipv4Packet, frame: &mut Frame) {
    let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).unwrap();
    let icmp_header = IcmpHeader::from_packet(&icmp_packet);
    if let Some(ip) = &mut frame.ip {
        ip.icmp = Some(icmp_header);
    }
}

fn parse_icmpv6_packet(ipv6_packet: &Ipv6Packet, frame: &mut Frame) {
    let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload()).unwrap();
    let icmpv6_header = Icmpv6Header::from_packet(&icmpv6_packet);
    if let Some(ip) = &mut frame.ip {
        ip.icmpv6 = Some(icmpv6_header);
    }
}
