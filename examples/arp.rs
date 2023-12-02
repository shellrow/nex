//! This example sends ARP request packet to the target and waits for ARP reply packets.
//!
//! e.g.
//!
//! arp 192.168.1.1 eth0

use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process;
use xenet::datalink;
use xenet::datalink::Channel::Ethernet;
use xenet::net::interface::Interface;
use xenet::net::mac::MacAddr;
use xenet::packet::ethernet::EtherType;
use xenet::packet::frame::Frame;
use xenet::packet::frame::ParseOption;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet_packet::arp::ArpOperation;
use xenet_packet_builder::arp::ArpPacketBuilder;

const USAGE: &str = "USAGE: arp <TARGET IPv4 Addr> <NETWORK INTERFACE>";

fn main() {
    let interface: Interface = match env::args().nth(2) {
        Some(n) => {
            // Use interface specified by the user
            let interfaces: Vec<Interface> = xenet::net::interface::get_interfaces();
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
    let dst_ip: Ipv4Addr = match env::args().nth(1) {
        Some(target_ip) => match target_ip.parse::<IpAddr>() {
            Ok(ip) => match ip {
                IpAddr::V4(ipv4) => ipv4,
                IpAddr::V6(_ipv6) => {
                    println!("IPv6 is not supported. Use ndp instead.");
                    eprintln!("{USAGE}");
                    process::exit(1);
                }
            }
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

    let src_ip: Ipv4Addr = interface.ipv4[0].addr.into();

    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };

    // Packet builder for ARP Request
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: interface.mac_addr.clone().unwrap(),
        dst_mac: MacAddr::broadcast(),
        ether_type: EtherType::Arp,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    let arp_packet = ArpPacketBuilder {
        src_mac: interface.mac_addr.clone().unwrap(),
        dst_mac: MacAddr::broadcast(),
        src_ip: src_ip,
        dst_ip: dst_ip,
    };
    packet_builder.set_arp(arp_packet);

    // Send ARP Request packet
    match tx.send(&packet_builder.packet()) {
        Some(_) => println!("ARP Packet sent"),
        None => println!("Failed to send packet"),
    }

    // Receive ARP Reply packet
    println!("Waiting for ARP Reply packet...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let parse_option: ParseOption = ParseOption::default();
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if let Some(datalik_layer) = &frame.datalink {
                    if let Some(arp_packet) = &datalik_layer.arp {
                        if arp_packet.operation == ArpOperation::Reply {
                            println!("ARP Reply packet received");
                            println!("Received ARP Reply packet from {}", arp_packet.sender_proto_addr);
                            println!("MAC address: {}", arp_packet.sender_hw_addr);
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
