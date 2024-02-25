//! This example sends NDP packet to the target and waits for NDP NeighborAdvertisement packets.
//!
//! e.g.
//!
//! ndp "fe80::6284:bdff:fe95:ca80" eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::packet::ethernet::MAC_ADDR_LEN;
use nex::packet::frame::Frame;
use nex::packet::frame::ParseOption;
use nex::packet::icmpv6::ndp::{NDP_OPT_PACKET_LEN, NDP_SOL_PACKET_LEN};
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextLevelProtocol;
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use nex::util::packet_builder::ipv6::Ipv6PacketBuilder;
use nex::util::packet_builder::ndp::NdpPacketBuilder;
use std::env;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::process;

const USAGE: &str = "USAGE: ndp <TARGET IPv6 Addr> <NETWORK INTERFACE>";

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
    let dst_ip: Ipv6Addr = match env::args().nth(1) {
        Some(target_ip) => match target_ip.parse::<IpAddr>() {
            Ok(ip) => match ip {
                IpAddr::V4(_) => {
                    println!("IPv4 is not supported");
                    eprintln!("{USAGE}");
                    process::exit(1);
                }
                IpAddr::V6(ipv6) => ipv6,
            },
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

    let src_ip: Ipv6Addr = interface.ipv6[0].addr.into();

    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };

    // Packet builder for ICMP Echo Request
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: interface.mac_addr.clone().unwrap(),
        dst_mac: MacAddr::broadcast(),
        ether_type: EtherType::Ipv6,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    let mut ipv6_packet_builder =
        Ipv6PacketBuilder::new(src_ip, dst_ip, IpNextLevelProtocol::Icmpv6);
    ipv6_packet_builder.payload_length =
        Some((NDP_SOL_PACKET_LEN + NDP_OPT_PACKET_LEN + MAC_ADDR_LEN) as u16);
    ipv6_packet_builder.hop_limit = Some(u8::MAX);
    packet_builder.set_ipv6(ipv6_packet_builder);

    let ndp_packet_builder =
        NdpPacketBuilder::new(interface.mac_addr.clone().unwrap(), src_ip, dst_ip);
    packet_builder.set_ndp(ndp_packet_builder);

    // Send NDP NeighborSolicitation packets
    match tx.send(&packet_builder.packet()) {
        Some(_) => println!("NDP Packet sent"),
        None => println!("Failed to send packet"),
    }

    // Receive NDP Neighbor Advertisement packets
    println!("Waiting for NDP Neighbor Advertisement packets...");
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
                    if let Some(icmpv6_packet) = &ip_layer.icmpv6 {
                        if icmpv6_packet.icmpv6_type == Icmpv6Type::NeighborAdvertisement {
                            println!(
                                "Received NDP Neighbor Advertisement packet from {}",
                                ip_layer.ipv6.as_ref().unwrap().source
                            );
                            println!(
                                "MAC address: {}",
                                frame
                                    .datalink
                                    .as_ref()
                                    .unwrap()
                                    .ethernet
                                    .as_ref()
                                    .unwrap()
                                    .source
                                    .address()
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
