use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use xenet_core::mac::MacAddr;
use xenet_packet::Packet;
use xenet_packet::ethernet::{EtherType, MutableEthernetPacket};
use xenet_packet::ip::IpNextLevelProtocol;
use xenet_packet::ethernet::ETHERNET_HEADER_LEN;
use xenet_packet::arp::{ARP_HEADER_LEN, MutableArpPacket};
use xenet_packet::ipv4::{IPV4_HEADER_LEN, MutableIpv4Packet};
use xenet_packet::ipv6::{IPV6_HEADER_LEN, MutableIpv6Packet};
use xenet_packet::icmp::ICMPV4_HEADER_LEN;
use xenet_packet::icmpv6::ICMPV6_HEADER_LEN;
use xenet_packet::tcp::{TCP_HEADER_LEN, MutableTcpPacket};
use xenet_packet::udp::{UDP_HEADER_LEN, MutableUdpPacket};
use crate::ipv6::build_ipv6_packet;
use crate::tcp::{TCP_DEFAULT_OPTION_LEN, build_tcp_packet};
use crate::udp::build_udp_packet;
use crate::icmp::build_icmp_echo_packet;
use crate::icmpv6::build_icmpv6_echo_packet;

use crate::ethernet::{build_ethernet_arp_packet, build_ethernet_packet};
use crate::arp::build_arp_packet;
use crate::ipv4::build_ipv4_packet;

/// Higher level packet build option.
/// For building packet, use PacketBuilder or protocol specific packet builder.
#[derive(Clone, Debug)]
pub struct PacketBuildOption {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: EtherType,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: Option<IpNextLevelProtocol>,
    pub payload: Vec<u8>,
    pub use_tun: bool,
}

impl PacketBuildOption {
    /// Constructs a new PacketBuildOption.
    pub fn new() -> Self {
        PacketBuildOption {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            ether_type: EtherType::Ipv4,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            payload: Vec::new(),
            use_tun: false,
        }
    }
}

/// Build ARP Packet from PacketBuildOption.
pub fn build_full_arp_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_option.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_option.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer =
        [0u8; ETHERNET_HEADER_LEN + ARP_HEADER_LEN];
    let mut ethernet_packet: MutableEthernetPacket =
        MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    build_ethernet_arp_packet(
        &mut ethernet_packet,
        packet_option.src_mac.clone(),
    );
    let mut arp_buffer = [0u8; ARP_HEADER_LEN];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    build_arp_packet(
        &mut arp_packet,
        packet_option.src_mac,
        packet_option.dst_mac,
        src_ip,
        dst_ip,
    );
    ethernet_packet.set_payload(arp_packet.packet());
    ethernet_packet.packet().to_vec()
}

/// Build ICMP Packet from PacketBuildOption. Build full packet with ethernet and ipv4 header.
pub fn build_full_icmp_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_option.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_option.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
        + IPV4_HEADER_LEN
        + ICMPV4_HEADER_LEN];
    let mut ethernet_packet: MutableEthernetPacket =
        MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    build_ethernet_packet(
        &mut ethernet_packet,
        packet_option.src_mac.clone(),
        packet_option.dst_mac.clone(),
        packet_option.ether_type,
    );
    let mut ipv4_buffer = [0u8; IPV4_HEADER_LEN + ICMPV4_HEADER_LEN];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    build_ipv4_packet(
        &mut ipv4_packet,
        src_ip,
        dst_ip,
        packet_option.ip_protocol.unwrap(),
    );
    let mut icmp_buffer = [0u8; ICMPV4_HEADER_LEN];
    let mut icmp_packet =
        xenet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    build_icmp_echo_packet(&mut icmp_packet);
    ipv4_packet.set_payload(icmp_packet.packet());
    ethernet_packet.set_payload(ipv4_packet.packet());
    if packet_option.use_tun {
        ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        ethernet_packet.packet().to_vec()
    }
}

/// Build ICMP Packet.
pub fn build_min_icmp_packet() -> Vec<u8> {
    let mut icmp_buffer = [0u8; ICMPV4_HEADER_LEN];
    let mut icmp_packet =
        xenet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    build_icmp_echo_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

/// Build ICMPv6 Packet from PacketBuildOption. Build full packet with ethernet and ipv6 header.
pub fn build_full_icmpv6_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv6Addr = match packet_option.src_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv6Addr = match packet_option.dst_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
        + IPV6_HEADER_LEN
        + ICMPV6_HEADER_LEN];
    let mut ethernet_packet: MutableEthernetPacket =
        MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    build_ethernet_packet(
        &mut ethernet_packet,
        packet_option.src_mac.clone(),
        packet_option.dst_mac.clone(),
        packet_option.ether_type,
    );
    let mut ipv6_buffer = [0u8; IPV6_HEADER_LEN + ICMPV6_HEADER_LEN];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
    build_ipv6_packet(
        &mut ipv6_packet,
        src_ip,
        dst_ip,
        packet_option.ip_protocol.unwrap(),
    );
    let mut icmpv6_buffer = [0u8; ICMPV6_HEADER_LEN];
    let mut icmpv6_packet =
        xenet_packet::icmpv6::echo_request::MutableEchoRequestPacket::new(&mut icmpv6_buffer)
            .unwrap();
    build_icmpv6_echo_packet(&mut icmpv6_packet, src_ip, dst_ip);
    ipv6_packet.set_payload(icmpv6_packet.packet());
    ethernet_packet.set_payload(ipv6_packet.packet());
    if packet_option.use_tun {
        ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        ethernet_packet.packet().to_vec()
    }
}

/// Build ICMPv6 Packet from PacketBuildOption.
pub fn build_min_icmpv6_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv6Addr = match packet_option.src_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv6Addr = match packet_option.dst_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let mut icmpv6_buffer = [0u8; ICMPV6_HEADER_LEN];
    let mut icmpv6_packet =
        xenet_packet::icmpv6::echo_request::MutableEchoRequestPacket::new(&mut icmpv6_buffer)
            .unwrap();
    build_icmpv6_echo_packet(&mut icmpv6_packet, src_ip, dst_ip);
    icmpv6_packet.packet().to_vec()
}

/// Build TCP Packet from PacketBuildOption. Build full packet with Ethernet and IP header.
pub fn build_full_tcp_syn_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    match packet_option.src_ip {
        IpAddr::V4(src_ip) => match packet_option.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
                    + IPV4_HEADER_LEN
                    + TCP_HEADER_LEN
                    + TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet: MutableEthernetPacket =
                    MutableEthernetPacket::new(&mut ethernet_buffer)
                        .unwrap();
                build_ethernet_packet(
                    &mut ethernet_packet,
                    packet_option.src_mac.clone(),
                    packet_option.dst_mac.clone(),
                    packet_option.ether_type,
                );
                let mut ipv4_buffer = [0u8; IPV4_HEADER_LEN
                    + TCP_HEADER_LEN
                    + TCP_DEFAULT_OPTION_LEN];
                let mut ipv4_packet =
                    MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                build_ipv4_packet(
                    &mut ipv4_packet,
                    src_ip,
                    dst_ip,
                    packet_option.ip_protocol.unwrap(),
                );
                let mut tcp_buffer =
                    [0u8; TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet =
                    MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                build_tcp_packet(
                    &mut tcp_packet,
                    packet_option.src_ip,
                    packet_option.src_port.unwrap(),
                    packet_option.dst_ip,
                    packet_option.dst_port.unwrap(),
                );
                ipv4_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                if packet_option.use_tun {
                    ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
                }else {
                    ethernet_packet.packet().to_vec()
                }
            }
            IpAddr::V6(_) => return Vec::new(),
        },
        IpAddr::V6(src_ip) => match packet_option.dst_ip {
            IpAddr::V4(_) => return Vec::new(),
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
                    + IPV6_HEADER_LEN
                    + TCP_HEADER_LEN
                    + TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet: MutableEthernetPacket =
                    MutableEthernetPacket::new(&mut ethernet_buffer)
                        .unwrap();
                build_ethernet_packet(
                    &mut ethernet_packet,
                    packet_option.src_mac.clone(),
                    packet_option.dst_mac.clone(),
                    packet_option.ether_type,
                );
                let mut ipv6_buffer = [0u8; IPV6_HEADER_LEN
                    + TCP_HEADER_LEN
                    + TCP_DEFAULT_OPTION_LEN];
                let mut ipv6_packet =
                    MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                build_ipv6_packet(
                    &mut ipv6_packet,
                    src_ip,
                    dst_ip,
                    packet_option.ip_protocol.unwrap(),
                );
                let mut tcp_buffer =
                    [0u8; TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet =
                    MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                build_tcp_packet(
                    &mut tcp_packet,
                    packet_option.src_ip,
                    packet_option.src_port.unwrap(),
                    packet_option.dst_ip,
                    packet_option.dst_port.unwrap(),
                );
                ipv6_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                if packet_option.use_tun {
                    ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
                }else {
                    ethernet_packet.packet().to_vec()
                }
            }
        },
    }
}

/// Build TCP Packet from PacketBuildOption.
pub fn build_min_tcp_syn_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let mut tcp_buffer = [0u8; TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    build_tcp_packet(
        &mut tcp_packet,
        packet_option.src_ip,
        packet_option.src_port.unwrap(),
        packet_option.dst_ip,
        packet_option.dst_port.unwrap(),
    );
    tcp_packet.packet().to_vec()
}

/// Build UDP Packet from PacketBuildOption. Build full packet with Ethernet and IP header.
pub fn build_full_udp_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    match packet_option.src_ip {
        IpAddr::V4(src_ip) => match packet_option.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
                    + IPV4_HEADER_LEN
                    + UDP_HEADER_LEN];
                let mut ethernet_packet: MutableEthernetPacket =
                    MutableEthernetPacket::new(&mut ethernet_buffer)
                        .unwrap();
                build_ethernet_packet(
                    &mut ethernet_packet,
                    packet_option.src_mac.clone(),
                    packet_option.dst_mac.clone(),
                    packet_option.ether_type,
                );
                let mut ipv4_buffer =
                    [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN];
                let mut ipv4_packet =
                    MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                build_ipv4_packet(
                    &mut ipv4_packet,
                    src_ip,
                    dst_ip,
                    packet_option.ip_protocol.unwrap(),
                );
                let mut udp_buffer = [0u8; UDP_HEADER_LEN];
                let mut udp_packet =
                    MutableUdpPacket::new(&mut udp_buffer).unwrap();
                build_udp_packet(
                    &mut udp_packet,
                    packet_option.src_ip,
                    packet_option.src_port.unwrap(),
                    packet_option.dst_ip,
                    packet_option.dst_port.unwrap(),
                );
                ipv4_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                if packet_option.use_tun {
                    ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
                }else {
                    ethernet_packet.packet().to_vec()
                }
            }
            IpAddr::V6(_) => return Vec::new(),
        },
        IpAddr::V6(src_ip) => match packet_option.dst_ip {
            IpAddr::V4(_) => return Vec::new(),
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN
                    + IPV6_HEADER_LEN
                    + UDP_HEADER_LEN];
                let mut ethernet_packet: MutableEthernetPacket =
                    MutableEthernetPacket::new(&mut ethernet_buffer)
                        .unwrap();
                build_ethernet_packet(
                    &mut ethernet_packet,
                    packet_option.src_mac.clone(),
                    packet_option.dst_mac.clone(),
                    packet_option.ether_type,
                );
                let mut ipv6_buffer =
                    [0u8; IPV6_HEADER_LEN + UDP_HEADER_LEN];
                let mut ipv6_packet =
                    MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                build_ipv6_packet(
                    &mut ipv6_packet,
                    src_ip,
                    dst_ip,
                    packet_option.ip_protocol.unwrap(),
                );
                let mut udp_buffer = [0u8; UDP_HEADER_LEN];
                let mut udp_packet =
                    MutableUdpPacket::new(&mut udp_buffer).unwrap();
                build_udp_packet(
                    &mut udp_packet,
                    packet_option.src_ip,
                    packet_option.src_port.unwrap(),
                    packet_option.dst_ip,
                    packet_option.dst_port.unwrap(),
                );
                ipv6_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                if packet_option.use_tun {
                    ethernet_packet.packet()[ETHERNET_HEADER_LEN..].to_vec()
                }else {
                    ethernet_packet.packet().to_vec()
                }
            }
        },
    }
}

/// Build UDP Packet from PacketBuildOption.
pub fn build_min_udp_packet(packet_option: PacketBuildOption) -> Vec<u8> {
    let mut udp_buffer = [0u8; UDP_HEADER_LEN];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    build_udp_packet(
        &mut udp_packet,
        packet_option.src_ip,
        packet_option.src_port.unwrap(),
        packet_option.dst_ip,
        packet_option.dst_port.unwrap(),
    );
    udp_packet.packet().to_vec()
}
