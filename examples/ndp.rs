//! Sends NDP Neighbor Solicitation and waits for Neighbor Advertisement.
//!
//! Usage:
//!   ndp <TARGET IPv6 Addr> <INTERFACE NAME>
//!
//! Example:
//!   ndp "fe80::6284:bdff:fe95:ca80" eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::{get_interfaces, Interface};
use nex::net::mac::MacAddr;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextProtocol;
use nex_packet::builder::ndp::NdpPacketBuilder;
use nex_packet::packet::Packet;
use std::env;
use std::net::{IpAddr, Ipv6Addr};
use std::process;

/// Compute multicast MAC address from solicited-node multicast IPv6 address
fn ipv6_multicast_mac(ipv6: &Ipv6Addr) -> MacAddr {
    let segments = ipv6.segments();
    MacAddr::new(
        0x33,
        0x33,
        ((segments[6] >> 8) & 0xff) as u8,
        (segments[6] & 0xff) as u8,
        ((segments[7] >> 8) & 0xff) as u8,
        (segments[7] & 0xff) as u8,
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ndp <TARGET IPv6 Addr> <INTERFACE NAME>");
        process::exit(1);
    }

    let target_ip: Ipv6Addr = match args[1].parse() {
        Ok(IpAddr::V6(addr)) => addr,
        _ => {
            eprintln!("Please provide a valid IPv6 address");
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

    let src_ip: Ipv6Addr = interface.ipv6[0].addr();

    let src_mac = interface.mac_addr.expect("No MAC address on interface");
    let dst_mac = ipv6_multicast_mac(&target_ip);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Build NDP packet
    //let ndp_payload_len = (NDP_SOL_PACKET_LEN + NDP_OPT_PACKET_LEN + MAC_ADDR_LEN) as u16;

    let ipv6 = Ipv6PacketBuilder::new()
        .source(src_ip)
        .destination(target_ip)
        .next_header(IpNextProtocol::Icmpv6)
        .hop_limit(255);

    let ndp = NdpPacketBuilder::new(src_mac, src_ip, target_ip);

    let ethernet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(EtherType::Ipv6)
        .payload(ipv6.payload(ndp.build().to_bytes()).build().to_bytes());

    // Send NDP Neighbor Solicitation
    let packet = ethernet.build().to_bytes();

    if tx.send(&packet).is_some() {
        println!("NDP Neighbor Solicitation sent to {}", target_ip);
    } else {
        eprintln!("Failed to send NDP packet");
        return;
    }

    println!("Waiting for Neighbor Advertisement...");

    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option = ParseOption::default();
                if interface.is_tun() {
                    parse_option.from_ip_packet = true;
                    parse_option.offset = if interface.is_loopback() { 14 } else { 0 };
                }

                if let Some(frame) = Frame::from_buf(&packet, parse_option) {
                    if let Some(ip_layer) = &frame.ip {
                        if let Some(icmpv6) = &ip_layer.icmpv6 {
                            if icmpv6.icmpv6_type == Icmpv6Type::NeighborAdvertisement {
                                if let Some(ipv6_hdr) = &ip_layer.ipv6 {
                                    println!(
                                        "Received Neighbor Advertisement from {}",
                                        ipv6_hdr.source
                                    );
                                    if let Some(dlink) = &frame.datalink {
                                        if let Some(eth) = &dlink.ethernet {
                                            println!("MAC address: {}", eth.source.address());
                                        }
                                    }
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
                }
            }
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
}
