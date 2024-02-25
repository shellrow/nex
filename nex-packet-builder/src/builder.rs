use nex_packet::ethernet::ETHERNET_HEADER_LEN;
use nex_packet::ipv4::IPV4_HEADER_LEN;
use nex_packet::ipv6::IPV6_HEADER_LEN;

use crate::arp::ArpPacketBuilder;
use crate::ethernet::EthernetPacketBuilder;
use crate::icmp::IcmpPacketBuilder;
use crate::icmpv6::Icmpv6PacketBuilder;
use crate::ipv4::Ipv4PacketBuilder;
use crate::ipv6::Ipv6PacketBuilder;
use crate::ndp::NdpPacketBuilder;
use crate::tcp::TcpPacketBuilder;
use crate::udp::UdpPacketBuilder;

/// Packet builder for building full packet.
#[derive(Clone, Debug)]
pub struct PacketBuilder {
    packet: Vec<u8>,
}

impl PacketBuilder {
    /// Constructs a new PacketBuilder.
    pub fn new() -> Self {
        PacketBuilder { packet: Vec::new() }
    }
    /// Return packet bytes.
    pub fn packet(&self) -> Vec<u8> {
        self.packet.clone()
    }
    /// Retern IP packet bytes (without ethernet header).
    pub fn ip_packet(&self) -> Vec<u8> {
        if self.packet.len() < ETHERNET_HEADER_LEN {
            return Vec::new();
        }
        self.packet[ETHERNET_HEADER_LEN..].to_vec()
    }
    /// Set ethernet header.
    pub fn set_ethernet(&mut self, packet_builder: EthernetPacketBuilder) {
        if self.packet.len() < ETHERNET_HEADER_LEN {
            self.packet.resize(ETHERNET_HEADER_LEN, 0);
        }
        self.packet[0..ETHERNET_HEADER_LEN].copy_from_slice(&packet_builder.build());
    }
    /// Set arp header.
    pub fn set_arp(&mut self, packet_builder: ArpPacketBuilder) {
        let arp_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + arp_packet.len() {
            self.packet
                .resize(ETHERNET_HEADER_LEN + arp_packet.len(), 0);
        }
        self.packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + arp_packet.len()]
            .copy_from_slice(&arp_packet);
    }
    /// Set IPv4 header.
    pub fn set_ipv4(&mut self, packet_builder: Ipv4PacketBuilder) {
        let ipv4_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + ipv4_packet.len() {
            self.packet
                .resize(ETHERNET_HEADER_LEN + ipv4_packet.len(), 0);
        }
        self.packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + ipv4_packet.len()]
            .copy_from_slice(&ipv4_packet);
    }
    /// Set IPv6 header.
    pub fn set_ipv6(&mut self, packet_builder: Ipv6PacketBuilder) {
        let ipv6_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + ipv6_packet.len() {
            self.packet
                .resize(ETHERNET_HEADER_LEN + ipv6_packet.len(), 0);
        }
        self.packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + ipv6_packet.len()]
            .copy_from_slice(&ipv6_packet);
    }
    /// Set ICMP header.
    pub fn set_icmp(&mut self, packet_builder: IcmpPacketBuilder) {
        let icmp_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + icmp_packet.len() {
            self.packet
                .resize(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + icmp_packet.len(), 0);
        }
        self.packet[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN
            ..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + icmp_packet.len()]
            .copy_from_slice(&icmp_packet);
    }
    /// Set ICMPv6 header.
    pub fn set_icmpv6(&mut self, packet_builder: Icmpv6PacketBuilder) {
        let icmpv6_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + icmpv6_packet.len() {
            self.packet.resize(
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + icmpv6_packet.len(),
                0,
            );
        }
        self.packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN
            ..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + icmpv6_packet.len()]
            .copy_from_slice(&icmpv6_packet);
    }
    /// Set NDP header.
    pub fn set_ndp(&mut self, packet_builder: NdpPacketBuilder) {
        let ndp_packet = packet_builder.build();
        if self.packet.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ndp_packet.len() {
            self.packet
                .resize(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ndp_packet.len(), 0);
        }
        self.packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN
            ..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ndp_packet.len()]
            .copy_from_slice(&ndp_packet);
    }
    /// Set TCP header and payload.
    pub fn set_tcp(&mut self, packet_builder: TcpPacketBuilder) {
        let tcp_packet = packet_builder.build();
        if packet_builder.dst_ip.is_ipv4() {
            if self.packet.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp_packet.len() {
                self.packet
                    .resize(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp_packet.len(), 0);
            }
            self.packet[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN
                ..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp_packet.len()]
                .copy_from_slice(&tcp_packet);
        } else if packet_builder.dst_ip.is_ipv6() {
            if self.packet.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + tcp_packet.len() {
                self.packet
                    .resize(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + tcp_packet.len(), 0);
            }
            self.packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN
                ..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + tcp_packet.len()]
                .copy_from_slice(&tcp_packet);
        }
    }
    /// Set UDP header and payload.
    pub fn set_udp(&mut self, packet_builder: UdpPacketBuilder) {
        let udp_packet = packet_builder.build();
        if packet_builder.dst_ip.is_ipv4() {
            if self.packet.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + udp_packet.len() {
                self.packet
                    .resize(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + udp_packet.len(), 0);
            }
            self.packet[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN
                ..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + udp_packet.len()]
                .copy_from_slice(&udp_packet);
        } else if packet_builder.dst_ip.is_ipv6() {
            if self.packet.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + udp_packet.len() {
                self.packet
                    .resize(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + udp_packet.len(), 0);
            }
            self.packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN
                ..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + udp_packet.len()]
                .copy_from_slice(&udp_packet);
        }
    }
}
