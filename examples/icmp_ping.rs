//! This example sends ICMP Echo request packet to the target socket and waits for ICMP Echo reply packet.
//!
//! e.g.
//!
//! IPv4: icmp_ping 1.1.1.1 eth0
//!
//! IPv6: icmp_ping "2606:4700:4700::1111" eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::Frame;
use nex::packet::frame::ParseOption;
use nex::packet::icmp::IcmpType;
use nex::packet::ip::IpNextLevelProtocol;
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use nex::util::packet_builder::icmp::IcmpPacketBuilder;
use nex::util::packet_builder::icmpv6::Icmpv6PacketBuilder;
use nex::util::packet_builder::ipv4::Ipv4PacketBuilder;
use nex::util::packet_builder::ipv6::Ipv6PacketBuilder;
use nex_packet::icmpv6::Icmpv6Type;
use std::env;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::process;

const USAGE: &str = "USAGE: icmp_ping <TARGET IP> <NETWORK INTERFACE>";

fn get_global_ipv6(interface: &Interface) -> Option<Ipv6Addr> {
    interface
        .ipv6
        .iter()
        .find(|ipv6| nex::net::ipnet::is_global_ipv6(&ipv6.addr))
        .map(|ipv6| ipv6.addr)
}

fn main() {
    let interface: Interface = match env::args().nth(2) {
        Some(n) => {
            // Use interface specified by the user
            let interfaces: Vec<Interface> = nex::net::interface::get_interfaces();
            let interface: Interface = interfaces
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
                    println!("Failed to get default interface: {}", e);
                    process::exit(1);
                }
            }
        }
    };
    let dst_ip: IpAddr = match env::args().nth(1) {
        Some(target_ip) => match target_ip.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(e) => {
                println!("Failed to parse target ip: {}", e);
                eprintln!("{USAGE}");
                process::exit(1);
            }
        },
        None => {
            println!("Failed to get target ip");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };
    let use_tun: bool = interface.is_tun();
    let src_ip: IpAddr = match dst_ip {
        IpAddr::V4(_) => interface.ipv4[0].addr.into(),
        IpAddr::V6(_) => {
            let ipv6 = get_global_ipv6(&interface).expect("Failed to get global IPv6 address");
            ipv6.into()
        }
    };

    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };

    // Packet builder for ICMP Echo Request
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
        ether_type: match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    match dst_ip {
        IpAddr::V4(dst_ipv4) => match src_ip {
            IpAddr::V4(src_ipv4) => {
                let ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Icmp);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Icmpv6);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }

    match dst_ip {
        IpAddr::V4(dst_ipv4) => match src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut icmp_packet_builder = IcmpPacketBuilder::new(src_ipv4, dst_ipv4);
                icmp_packet_builder.icmp_type = IcmpType::EchoRequest;
                packet_builder.set_icmp(icmp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6);
                icmpv6_packet_builder.icmpv6_type = Icmpv6Type::EchoRequest;
                packet_builder.set_icmpv6(icmpv6_packet_builder);
            }
        },
    }

    // Send ICMP Echo Request packets
    let packet: Vec<u8> = if use_tun {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    };
    match tx.send(&packet) {
        Some(_) => println!("Packet sent"),
        None => println!("Failed to send packet"),
    }

    // Receive ICMP Echo Reply packets
    println!("Waiting for ICMP Echo Reply packets...");
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
                if let Some(ip_layer) = &frame.ip {
                    if let Some(icmp_packet) = &ip_layer.icmp {
                        if icmp_packet.icmp_type == IcmpType::EchoReply {
                            println!(
                                "Received ICMP Echo Reply packet from {}",
                                ip_layer.ipv4.as_ref().unwrap().source
                            );
                            println!(
                                "---- Interface: {}, Total Length: {} bytes ----",
                                interface.name,
                                packet.len()
                            );
                            println!("Packet Frame: {:?}", frame);
                            break;
                        }
                    }
                    if let Some(icmpv6_packet) = &ip_layer.icmpv6 {
                        if icmpv6_packet.icmpv6_type == Icmpv6Type::EchoReply {
                            println!(
                                "Received ICMPv6 Echo Reply packet from {}",
                                ip_layer.ipv6.as_ref().unwrap().source
                            );
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
            Err(e) => println!("Failed to receive packet: {}", e),
        }
    }
}
