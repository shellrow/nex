//! This example sends a UDP packet to a specified target port (33435) and waits for an ICMP Port Unreachable reply.
//!
//! Usage:
//!   udp_ping <TARGET IP> <NETWORK INTERFACE>
//!
//! Example:
//!   IPv4: udp_ping 1.1.1.1 eth0
//!   IPv6: udp_ping 2606:4700:4700::1111 eth0

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process;
use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextLevelProtocol;
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use nex::util::packet_builder::ipv4::Ipv4PacketBuilder;
use nex::util::packet_builder::ipv6::Ipv6PacketBuilder;
use nex::util::packet_builder::udp::UdpPacketBuilder;

const USAGE: &str = "USAGE: udp_ping <TARGET IP> <NETWORK INTERFACE>";

const SRC_PORT: u16 = 53443;
const DST_PORT: u16 = 33435;

fn main() {
    let interface: Interface = match env::args().nth(2) {
        Some(n) => {
            // Use the interface specified by the user
            let interfaces: Vec<Interface> = nex::net::interface::get_interfaces();
            let interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        }
        None => {
            // Use the default interface
            match Interface::default() {
                Ok(interface) => interface,
                Err(e) => {
                    println!("Failed to get the default interface: {}", e);
                    process::exit(1);
                }
            }
        }
    };
    let use_tun: bool = interface.is_tun();
    let target_ip: IpAddr = match env::args().nth(1) {
        Some(target_ip_str) => match target_ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                println!("Failed to parse the target IP: {}", e);
                eprintln!("{USAGE}");
                process::exit(1);
            }
        },
        None => {
            println!("Failed to get the target IP");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };

    // Create a new channel
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create a channel: {}", e),
    };

    // Packet builder for UDP Ping
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: if use_tun {
            MacAddr::zero()
        } else {
            interface.mac_addr.clone().unwrap()
        },
        dst_mac: if use_tun {
            MacAddr::zero()
        } else {
            interface.gateway.clone().unwrap().mac_addr
        },
        ether_type: match target_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    match target_ip {
        IpAddr::V4(dst_ipv4) => match interface.ipv4.get(0) {
            Some(src_ipv4) => {
                let ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4.addr, dst_ipv4, IpNextLevelProtocol::Udp);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            None => {
                println!("No IPv4 address on the interface");
                process::exit(1);
            }
        },
        IpAddr::V6(dst_ipv6) => {
            match interface
                .ipv6
                .iter()
                .find(|ipv6| nex::net::ipnet::is_global_ipv6(&ipv6.addr))
            {
                Some(src_ipv6) => {
                    let ipv6_packet_builder =
                        Ipv6PacketBuilder::new(src_ipv6.addr, dst_ipv6, IpNextLevelProtocol::Udp);
                    packet_builder.set_ipv6(ipv6_packet_builder);
                }
                None => {
                    println!("No global IPv6 address on the interface");
                    process::exit(1);
                }
            }
        }
    }

    match target_ip {
        IpAddr::V4(_dst_ipv4) => match interface.ipv4.get(0) {
            Some(src_ipv4) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V4(src_ipv4.addr), SRC_PORT),
                    SocketAddr::new(target_ip, DST_PORT),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
            None => {
                println!("No IPv4 address on the interface");
                process::exit(1);
            }
        },
        IpAddr::V6(_dst_ipv6) => {
            match interface
                .ipv6
                .iter()
                .find(|ipv6| nex::net::ipnet::is_global_ipv6(&ipv6.addr))
            {
                Some(src_ipv6) => {
                    let udp_packet_builder = UdpPacketBuilder::new(
                        SocketAddr::new(IpAddr::V6(src_ipv6.addr), SRC_PORT),
                        SocketAddr::new(target_ip, DST_PORT),
                    );
                    packet_builder.set_udp(udp_packet_builder);
                }
                None => {
                    println!("No global IPv6 address on the interface");
                    process::exit(1);
                }
            }
        }
    }

    // Send UDP Ping packet
    let packet: Vec<u8> = if use_tun {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    };
    match tx.send(&packet) {
        Some(_) => println!("UDP Ping packet sent"),
        None => println!("Failed to send UDP Ping packet"),
    }

    // Receive ICMP Port Unreachable
    println!("Waiting for ICMP Port Unreachable...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset = if interface.is_loopback() { 14 } else { 0 };
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                // Check each layer. If the packet is a ICMP Port Unreachable, print it out
                if let Some(ip_layer) = &frame.ip {
                    if let Some(icmp_header) = &ip_layer.icmp {
                        if icmp_header.icmp_type == IcmpType::DestinationUnreachable {
                            if let Some(ipv4) = &ip_layer.ipv4 {
                                println!("Received ICMP Port Unreachable from {}", ipv4.source);
                                println!(
                                    "---- Interface: {}, Total Length: {} bytes ----",
                                    interface.name,
                                    packet.len()
                                );
                                println!("Packet Frame: {:?}", frame);
                                break;
                            }
                        }
                    } else if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                        if icmpv6_header.icmpv6_type == Icmpv6Type::DestinationUnreachable {
                            if let Some(ipv6) = &ip_layer.ipv6 {
                                println!("Received ICMP Port Unreachable from {}", ipv6.source);
                                println!(
                                    "---- Interface: {}, Total Length: {} bytes ----",
                                    interface.name,
                                    packet.len()
                                );
                                println!("Packet Frame: {:?}", frame);
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => println!("Failed to receive packet: {}", e),
        }
    }
}
