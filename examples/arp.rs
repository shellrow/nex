//! Sends ARP request to the target and waits for ARP reply.
//!
//! Usage:
//!   arp <TARGET IPv4 Addr> <INTERFACE NAME>
//!
//! Example:
//!   arp 192.168.1.1 eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::{get_interfaces, Interface};
use nex::net::mac::MacAddr;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex_packet::arp::ArpOperation;
use nex_packet::builder::arp::ArpPacketBuilder;
use nex_packet::packet::Packet;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: arp <TARGET IPv4 Addr> <INTERFACE NAME>");
        process::exit(1);
    }

    let target_ip: Ipv4Addr = match args[1].parse() {
        Ok(IpAddr::V4(ipv4)) => ipv4,
        Ok(_) => {
            eprintln!("IPv6 is not supported. Use ndp instead.");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to parse target IP: {}", e);
            process::exit(1);
        }
    };

    let interface = match env::args().nth(2) {
        Some(name) => get_interfaces()
            .into_iter()
            .find(|i| i.name == name)
            .expect("Failed to get interface"),
        None => Interface::default().expect("Failed to get default interface"),
    };

    let src_mac = interface
        .mac_addr
        .clone()
        .expect("No MAC address on interface");
    let src_ip = interface.ipv4.get(0).expect("No IPv4 address").addr();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    let eth_builder = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(MacAddr::broadcast())
        .ethertype(EtherType::Arp);

    let arp_builder = ArpPacketBuilder::new(src_mac, src_ip, target_ip);

    let packet = eth_builder.payload(arp_builder.build().to_bytes()).build();

    match tx.send(&packet.to_bytes()) {
        Some(_) => println!("ARP Request sent to {}", target_ip),
        None => {
            eprintln!("Failed to send ARP packet");
            process::exit(1);
        }
    }

    println!("Waiting for ARP Reply...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let frame = Frame::from_buf(&packet, ParseOption::default()).unwrap();
                match &frame.datalink {
                    Some(dlink) => {
                        if let Some(arp) = &dlink.arp {
                            if arp.operation == ArpOperation::Reply
                                && arp.sender_proto_addr == target_ip
                            {
                                println!("Received ARP Reply from {}", arp.sender_proto_addr);
                                println!("MAC address: {}", arp.sender_hw_addr);
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
                    None => continue, // No datalink layer
                }
            }
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
}
