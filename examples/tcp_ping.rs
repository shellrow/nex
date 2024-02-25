//! This example sends TCP SYN packet to the target socket and waits for TCP SYN+ACK or RST+ACK packet.
//!
//! e.g.
//!
//! IPv4: tcp_ping 1.1.1.1:80 eth0
//!
//! IPv6: tcp_ping "[2606:4700:4700::1111]:80" eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::ip::IpNextLevelProtocol;
use nex::packet::tcp::{TcpFlags, TcpOption};
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use nex::util::packet_builder::ipv4::Ipv4PacketBuilder;
use nex::util::packet_builder::ipv6::Ipv6PacketBuilder;
use nex::util::packet_builder::tcp::TcpPacketBuilder;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process;

const USAGE: &str = "USAGE: tcp_ping <TARGET SOCKETADDR> <NETWORK INTERFACE>";

fn main() {
    let interface: Interface = match env::args().nth(2) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = nex::net::interface::get_interfaces();
            let interface: Interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        }
        None => {
            // Use default interface
            match Interface::default() {
                Ok(interface) => interface,
                Err(e) => {
                    println!("Failed to get default interface: {}", e);
                    process::exit(1);
                }
            }
        }
    };
    let use_tun: bool = interface.is_tun();
    let target_socket: SocketAddr = match env::args().nth(1) {
        Some(target_socket_str) => match target_socket_str.parse() {
            Ok(socket) => socket,
            Err(e) => {
                println!("Failed to parse target socket: {}", e);
                eprintln!("{USAGE}");
                process::exit(1);
            }
        },
        None => {
            println!("Failed to get target socket");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };

    // Create new channel
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    // Packet builder for TCP SYN
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
        ether_type: match target_socket.ip() {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    match target_socket.ip() {
        IpAddr::V4(dst_ipv4) => match interface.ipv4.get(0) {
            Some(src_ipv4) => {
                let ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4.addr, dst_ipv4, IpNextLevelProtocol::Tcp);
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
                .find(|ipv6| nex::net::ip::is_global_ipv6(&ipv6.addr))
            {
                Some(src_ipv6) => {
                    let ipv6_packet_builder =
                        Ipv6PacketBuilder::new(src_ipv6.addr, dst_ipv6, IpNextLevelProtocol::Tcp);
                    packet_builder.set_ipv6(ipv6_packet_builder);
                }
                None => {
                    println!("No global IPv6 address on the interface");
                    process::exit(1);
                }
            }
        }
    }

    match target_socket.ip() {
        IpAddr::V4(_dst_ipv4) => match interface.ipv4.get(0) {
            Some(src_ipv4) => {
                let mut tcp_packet_builder = TcpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V4(src_ipv4.addr), 53443),
                    target_socket,
                );
                tcp_packet_builder.flags = TcpFlags::SYN;
                tcp_packet_builder.options = vec![
                    TcpOption::mss(1460),
                    TcpOption::sack_perm(),
                    TcpOption::nop(),
                    TcpOption::nop(),
                    TcpOption::wscale(7),
                ];
                packet_builder.set_tcp(tcp_packet_builder);
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
                .find(|ipv6| nex::net::ip::is_global_ipv6(&ipv6.addr))
            {
                Some(src_ipv6) => {
                    let mut tcp_packet_builder = TcpPacketBuilder::new(
                        SocketAddr::new(IpAddr::V6(src_ipv6.addr), 53443),
                        target_socket,
                    );
                    tcp_packet_builder.flags = TcpFlags::SYN;
                    tcp_packet_builder.options = vec![
                        TcpOption::mss(1460),
                        TcpOption::sack_perm(),
                        TcpOption::nop(),
                        TcpOption::nop(),
                        TcpOption::wscale(7),
                    ];
                    packet_builder.set_tcp(tcp_packet_builder);
                }
                None => {
                    println!("No global IPv6 address on the interface");
                    process::exit(1);
                }
            }
        }
    }

    // Send TCP SYN packets
    let packet: Vec<u8> = if use_tun {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    };
    match tx.send(&packet) {
        Some(_) => println!("Packet sent"),
        None => println!("Failed to send packet"),
    }

    // Receive TCP SYN+ACK or RST+ACK
    println!("Waiting for TCP SYN+ACK or RST+ACK packet...");
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
                // Check each layer. If the packet is TCP SYN+ACK or RST+ACK, print it out
                if let Some(ip_layer) = &frame.ip {
                    if let Some(transport_layer) = &frame.transport {
                        if let Some(tcp_packet) = &transport_layer.tcp {
                            if tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                                if let Some(ipv4) = &ip_layer.ipv4 {
                                    println!(
                                        "Received TCP SYN+ACK packet from {}:{}",
                                        ipv4.source, tcp_packet.source
                                    );
                                } else if let Some(ipv6) = &ip_layer.ipv6 {
                                    println!(
                                        "Received TCP SYN+ACK packet from {}:{}",
                                        ipv6.source, tcp_packet.source
                                    );
                                }
                                println!(
                                    "---- Interface: {}, Total Length: {} bytes ----",
                                    interface.name,
                                    packet.len()
                                );
                                println!("Packet Frame: {:?}", frame);
                                break;
                            } else if tcp_packet.flags == TcpFlags::RST | TcpFlags::ACK {
                                if let Some(ipv4) = &ip_layer.ipv4 {
                                    println!(
                                        "Received TCP RST+ACK packet from {}:{}",
                                        ipv4.source, tcp_packet.source
                                    );
                                } else if let Some(ipv6) = &ip_layer.ipv6 {
                                    println!(
                                        "Received TCP RST+ACK packet from {}:{}",
                                        ipv6.source, tcp_packet.source
                                    );
                                }
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
