//! Basic packet capture using nex
//!
//! Parse packet as Frame and print it

use nex::datalink;
use nex::net::interface::Interface;
use nex::packet::frame::Frame;
use nex::packet::frame::ParseOption;
use std::env;
use std::process;

fn main() {
    use nex::datalink::Channel::Ethernet;
    let interface: Interface = match env::args().nth(1) {
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

    // Create a channel to receive packet
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };
    let mut capture_no: usize = 0;
    loop {
        match rx.next() {
            Ok(packet) => {
                capture_no += 1;
                println!(
                    "---- Interface: {}, No.: {}, Total Length: {} bytes ----",
                    interface.name,
                    capture_no,
                    packet.len()
                );
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun()
                    || (cfg!(any(target_os = "macos", target_os = "ios"))
                        && interface.is_loopback())
                {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                match Frame::from_buf(&packet, parse_option) {
                    Some(frame) => {
                        display_frame(&frame);
                    }
                    None => {
                        println!("Failed to parse packet as Frame");
                    }
                }
            }
            Err(e) => panic!("parse_frame: unable to receive packet: {}", e),
        }
    }
}

pub fn display_frame(frame: &Frame) {
    println!("Packet Frame ({} bytes)", frame.packet_len);

    if let Some(dl) = &frame.datalink {
        if let Some(eth) = &dl.ethernet {
            println!(
                "  Ethernet: {} > {} ({:?})",
                eth.source, eth.destination, eth.ethertype
            );
        }
        if let Some(arp) = &dl.arp {
            println!(
                "  ARP: {}({}) > {}({}); operation: {:?}",
                arp.sender_hw_addr,
                arp.sender_proto_addr,
                arp.target_hw_addr,
                arp.target_proto_addr,
                arp.operation
            );
        }
    }

    if let Some(ip) = &frame.ip {
        if let Some(ipv4) = &ip.ipv4 {
            println!(
                "  IPv4: {} -> {} (protocol: {:?})",
                ipv4.source, ipv4.destination, ipv4.next_level_protocol
            );
        }
        if let Some(ipv6) = &ip.ipv6 {
            println!(
                "  IPv6: {} -> {} (next header: {:?})",
                ipv6.source, ipv6.destination, ipv6.next_header
            );
        }
        if ip.icmp.is_some() {
            println!("  ICMP: present");
        }
        if ip.icmpv6.is_some() {
            println!("  ICMPv6: present");
        }
    }

    if let Some(tp) = &frame.transport {
        if let Some(tcp) = &tp.tcp {
            println!("  TCP: {} -> {}", tcp.source, tcp.destination);
        }
        if let Some(udp) = &tp.udp {
            println!("  UDP: {} -> {}", udp.source, udp.destination);
        }
    }

    if !frame.payload.is_empty() {
        println!("  Payload: {} bytes", frame.payload.len());
    }
}
