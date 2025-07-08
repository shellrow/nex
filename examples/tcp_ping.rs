//! Sends TCP SYN packet to the target socket and waits for TCP SYN+ACK or RST+ACK packet.
//!
//! Usage:
//!   tcp_ping <SOCKET ADDR> <NETWORK INTERFACE>
//! 
//! Example:
//!
//! IPv4: tcp_ping 1.1.1.1:80 eth0
//!
//! IPv6: tcp_ping "[2606:4700:4700::1111]:80" eth0

use bytes::Bytes;
use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::ip::IpNextProtocol;
use nex::packet::tcp::{TcpFlags, TcpOptionPacket};
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::ipv4::Ipv4PacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::builder::tcp::TcpPacketBuilder;
use nex_packet::ipv4::Ipv4Flags;
use nex_packet::packet::Packet;
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

    let dst_ip = target_socket.ip();
    let src_ip: IpAddr;
    match dst_ip {
        IpAddr::V4(_) => {
            // For IPv4, use the first IPv4 address of the interface
            match interface.ipv4.get(0) {
                Some(ipv4) => src_ip = IpAddr::V4(ipv4.addr()),
                None => {
                    println!("No IPv4 address on the interface");
                    process::exit(1);
                }
            }
        }
        IpAddr::V6(_) => {
            // For IPv6, use the first global IPv6 address of the interface
            match interface
                .ipv6
                .iter()
                .find(|ipv6| nex::net::ip::is_global_ipv6(&ipv6.addr()))
            {
                Some(ipv6) => src_ip = IpAddr::V6(ipv6.addr()),
                None => {
                    println!("No global IPv6 address on the interface");
                    process::exit(1);
                }
            }
        }
    }

    // Packet builder for TCP SYN
    let tcp_packet = TcpPacketBuilder::new()
        .source(53443)
        .destination(target_socket.port())
        .flags(TcpFlags::SYN)
        .window(64240)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::sack_perm(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(7),
        ])
        .calculate_checksum(&src_ip, &dst_ip)
        .build();

    let ip_packet: Bytes;
    match dst_ip {
        IpAddr::V4(dst_ipv4) => {
            match src_ip {
                IpAddr::V4(src_ipv4) => {
                    // Use the source IPv4 address
                    let ipv4_packet = Ipv4PacketBuilder::new()
                        .source(src_ipv4)
                        .destination(dst_ipv4)
                        .protocol(IpNextProtocol::Tcp)
                        .flags(Ipv4Flags::DontFragment)
                        .payload(tcp_packet.to_bytes())
                        .build();
                    ip_packet = ipv4_packet.to_bytes();
                }
                IpAddr::V6(_) => {
                    println!("Source IP must be IPv4 for IPv4 destination");
                    process::exit(1);
                }
            }
            
        },
        IpAddr::V6(dst_ipv6) => {
            match src_ip {
                IpAddr::V4(_) => {
                    println!("Source IP must be IPv6 for IPv6 destination");
                    process::exit(1);
                }
                IpAddr::V6(src_ipv6) => {
                    // Use the source IPv6 address
                    let ipv6_packet = Ipv6PacketBuilder::new()
                        .source(src_ipv6)
                        .destination(dst_ipv6)
                        .next_header(IpNextProtocol::Tcp)
                        .payload(tcp_packet.to_bytes())
                        .build();
                    ip_packet = ipv6_packet.to_bytes();
                }
            }
        }
    }

    let ethernet_packet = EthernetPacketBuilder::new()
        .source(if use_tun {
            MacAddr::zero()
        } else {
            interface.mac_addr.clone().unwrap()
        })
        .destination(if use_tun {
            MacAddr::zero()
        } else {
            interface.gateway.clone().unwrap().mac_addr
        })
        .ethertype(match target_socket.ip() {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    // Send TCP SYN packets
    let packet: Bytes = if use_tun {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
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
                let frame: Frame = Frame::from_buf(&packet, parse_option).unwrap();
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
