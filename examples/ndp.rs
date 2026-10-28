//! Sends NDP Neighbor Solicitation and waits for Neighbor Advertisement.
//!
//! Usage:
//!   ndp <TARGET IPv6 Addr> <INTERFACE NAME>
//!
//! Example:
//!   ndp "fe80::6284:bdff:fe95:ca80" eth0

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::{Interface, get_interfaces};
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

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(octets[13]),
        u16::from_be_bytes([octets[14], octets[15]]),
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
    let multicast_ip = solicited_node_multicast(target_ip);
    let dst_mac = ipv6_multicast_mac(&multicast_ip);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let ipv6 = Ipv6PacketBuilder::new()
        .source(src_ip)
        .destination(multicast_ip)
        .next_header(IpNextProtocol::Icmpv6)
        .hop_limit(255);

    let ndp = NdpPacketBuilder::new(src_mac, src_ip, target_ip);
    let mut ndp_packet = ndp.build().expect("valid NDP packet");
    // The target remains the unicast neighbor, but the checksum uses the
    // solicited-node multicast address carried by the IPv6 header.
    ndp_packet.header.checksum = nex_packet::icmpv6::checksum(&ndp_packet, &src_ip, &multicast_ip);
    let ipv6_packet = ipv6
        .payload(ndp_packet.to_bytes())
        .build()
        .expect("valid IPv6 packet");

    let ethernet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(EtherType::Ipv6)
        .payload(ipv6_packet.to_bytes());

    // Send NDP Neighbor Solicitation
    let packet = ethernet.build().to_bytes();

    match tx.send(&packet) {
        Some(Ok(())) => println!("NDP Neighbor Solicitation sent to {}", target_ip),
        result => {
            eprintln!("Failed to send NDP packet: {result:?}");
            process::exit(1);
        }
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

                if let Ok(frame) = Frame::try_from_buf(packet, parse_option)
                    && let Some(ip_layer) = &frame.ip
                    && let Some(icmpv6) = &ip_layer.icmpv6
                    && icmpv6.icmpv6_type == Icmpv6Type::NeighborAdvertisement
                    && frame.payload.get(4..20) == Some(target_ip.octets().as_slice())
                    && let Some(ipv6_hdr) = &ip_layer.ipv6
                {
                    println!("Received Neighbor Advertisement from {}", ipv6_hdr.source);
                    if let Some(dlink) = &frame.datalink
                        && let Some(eth) = &dlink.ethernet
                    {
                        println!("MAC address: {}", eth.source.address());
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
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_discovery_uses_solicited_node_multicast() {
        let target = "2001:db8::1234:5678".parse().unwrap();
        let multicast = solicited_node_multicast(target);
        assert_eq!(multicast, "ff02::1:ff34:5678".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            ipv6_multicast_mac(&multicast),
            MacAddr::new(0x33, 0x33, 0xff, 0x34, 0x56, 0x78)
        );
    }
}
