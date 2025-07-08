//! Sends ICMP Echo Request and waits for ICMP Echo Reply.
//!
//! Usage:
//!   icmp_ping <TARGET IP> <NETWORK INTERFACE>
//!
//! Example:
//!   IPv4: icmp_ping 1.1.1.1 eth0
//!   IPv6: icmp_ping "2606:4700:4700::1111" eth0

use bytes::Bytes;
use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::builder::icmp::IcmpPacketBuilder;
use nex::packet::builder::icmpv6::Icmpv6PacketBuilder;
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::ipv4::Ipv4PacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex_packet::{icmp, icmpv6};
use nex_packet::ip::IpNextProtocol;
use nex_packet::ipv4::Ipv4Flags;
use nex_packet::packet::Packet;
use std::env;
use std::net::IpAddr;

fn main() {
    let interface = match env::args().nth(2) {
        Some(name) => nex::net::interface::get_interfaces()
            .into_iter()
            .find(|i| i.name == name)
            .expect("Failed to get interface"),
        None => Interface::default().expect("Failed to get default interface"),
    };
    let use_tun = interface.is_tun();

    let target_ip: IpAddr = env::args()
        .nth(1)
        .expect("Missing target IP")
        .parse()
        .expect("Failed to parse target IP");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    let src_ip: IpAddr = match target_ip {
        IpAddr::V4(_) => interface
            .ipv4
            .get(0)
            .map(|v| IpAddr::V4(v.addr()))
            .expect("No IPv4 address"),
        IpAddr::V6(_) => interface
            .ipv6
            .iter()
            .find(|v| nex::net::ip::is_global_ipv6(&v.addr()))
            .map(|v| IpAddr::V6(v.addr()))
            .expect("No global IPv6 address"),
    };

    let icmp_packet: Bytes = match (src_ip, target_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => IcmpPacketBuilder::new(src, dst)
            .icmp_type(IcmpType::EchoRequest)
            .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .calculate_checksum()
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Icmpv6PacketBuilder::new(src, dst)
            .icmpv6_type(Icmpv6Type::EchoRequest)
            .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .calculate_checksum()
            .build()
            .to_bytes(),
        _ => panic!("Source and destination IP version mismatch"),
    };

    let ip_packet = match (src_ip, target_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Icmp)
            .flags(Ipv4Flags::DontFragment)
            .payload(icmp_packet)
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Icmpv6)
            .payload(icmp_packet)
            .build()
            .to_bytes(),
        _ => unreachable!(),
    };

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
        .ethertype(match target_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    let packet = if use_tun {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
    };

    match tx.send(&packet) {
        Some(_) => println!("Packet sent"),
        None => println!("Failed to send packet"),
    }

    println!("Waiting for ICMP Echo Reply...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option = ParseOption::default();
                if interface.is_tun() {
                    parse_option.from_ip_packet = true;
                    parse_option.offset = if interface.is_loopback() { 14 } else { 0 };
                }
                let frame = Frame::from_buf(&packet, parse_option).unwrap();

                if let Some(ip_layer) = &frame.ip {
                    if let Some(icmp) = &ip_layer.icmp {
                        if icmp.icmp_type == IcmpType::EchoReply {
                            println!(
                                "Received ICMP Echo Reply from {}",
                                ip_layer.ipv4.as_ref().unwrap().source
                            );
                            println!(
                                "---- Interface: {}, Total Length: {} bytes ----",
                                interface.name,
                                packet.len()
                            );
                            println!("Frame: {:?}", frame);
                            break;
                        }
                    }
                    if let Some(icmpv6) = &ip_layer.icmpv6 {
                        if icmpv6.icmpv6_type == Icmpv6Type::EchoReply {
                            println!(
                                "Received ICMPv6 Echo Reply from {}",
                                ip_layer.ipv6.as_ref().unwrap().source
                            );
                            println!(
                                "---- Interface: {}, Total Length: {} bytes ----",
                                interface.name,
                                packet.len()
                            );
                            println!("Frame: {:?}", frame);
                            break;
                        }
                    }
                }
            }
            Err(e) => eprintln!("Failed to receive: {}", e),
        }
    }
}
