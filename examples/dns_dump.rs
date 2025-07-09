//! DNS packet capture example
//!
//! Captures DNS UDP traffic over IPv4/IPv6 and extracts:
//!   - Queries: domain name, type, class
//!   - Responses: IPs (A, AAAA), names (CNAME, PTR, NS), and TXT content

use bytes::Bytes;
use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::packet::dns::{DnsPacket, DnsType};
use nex::packet::ethernet::{EtherType, EthernetPacket};
use nex::packet::ipv4::Ipv4Packet;
use nex::packet::ipv6::Ipv6Packet;
use nex::packet::udp::UdpPacket;
use nex_core::mac::MacAddr;
use nex_packet::ethernet::EthernetHeader;
use nex_packet::packet::Packet;
use std::env;
use std::net::IpAddr;

fn main() {
    let interface: Interface = match env::args().nth(1) {
        Some(n) => {
            let interfaces = nex::net::interface::get_interfaces();
            interfaces
                .into_iter()
                .find(|iface| iface.name == n)
                .expect("Interface not found")
        }
        None => Interface::default().expect("Failed to get default interface"),
    };

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("dns_dump: unhandled channel type"),
        Err(e) => panic!("dns_dump: failed to create channel: {}", e),
    };

    let mut capture_no = 0;
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

                let eth_packet = if interface.is_tun()
                    || (cfg!(any(target_os = "macos", target_os = "ios"))
                        && interface.is_loopback())
                {
                    let offset = if interface.is_loopback() { 14 } else { 0 };
                    let payload = Bytes::copy_from_slice(&packet[offset..]);
                    let version = Ipv4Packet::from_buf(packet).unwrap().header.version;
                    EthernetPacket {
                        header: EthernetHeader {
                            destination: MacAddr::zero(),
                            source: MacAddr::zero(),
                            ethertype: if version == 4 {
                                EtherType::Ipv4
                            } else {
                                EtherType::Ipv6
                            },
                        },
                        payload,
                    }
                } else {
                    EthernetPacket::from_buf(packet).unwrap()
                };

                if let EtherType::Ipv4 = eth_packet.header.ethertype {
                    if let Some(ipv4) = Ipv4Packet::from_bytes(eth_packet.payload.clone()) {
                        handle_udp(
                            ipv4.payload,
                            IpAddr::V4(ipv4.header.source),
                            IpAddr::V4(ipv4.header.destination),
                        );
                    }
                } else if let EtherType::Ipv6 = eth_packet.header.ethertype {
                    if let Some(ipv6) = Ipv6Packet::from_bytes(eth_packet.payload.clone()) {
                        handle_udp(
                            ipv6.payload,
                            IpAddr::V6(ipv6.header.source),
                            IpAddr::V6(ipv6.header.destination),
                        );
                    }
                }
            }
            Err(e) => eprintln!("Failed to read packet: {}", e),
        }
    }
}

fn handle_udp(packet: Bytes, src: IpAddr, dst: IpAddr) {
    if let Some(udp) = UdpPacket::from_bytes(packet.clone()) {
        if udp.payload.len() > 0 {
            if let Some(dns) = DnsPacket::from_bytes(udp.payload.clone()) {
                println!(
                    "DNS Packet: {}:{} > {}:{}",
                    src, udp.header.source, dst, udp.header.destination
                );

                for query in &dns.queries {
                    println!(
                        "  Query: {:?} (type: {:?}, class: {:?})",
                        query.get_qname_parsed(),
                        query.qtype,
                        query.qclass
                    );
                }

                for response in &dns.responses {
                    match response.rtype {
                        DnsType::A | DnsType::AAAA => {
                            if let Some(ip) = response.get_ip() {
                                println!(
                                    "  Response: {} (type: {:?}, ttl: {})",
                                    ip, response.rtype, response.ttl
                                );
                            } else {
                                println!("  Invalid IP data for type: {:?}", response.rtype);
                            }
                        }
                        DnsType::CNAME | DnsType::NS | DnsType::PTR => {
                            if let Some(name) = response.get_name() {
                                println!(
                                    "  Response: {} (type: {:?}, ttl: {})",
                                    name, response.rtype, response.ttl
                                );
                            } else {
                                println!("  Invalid name data for type: {:?}", response.rtype);
                            }
                        }
                        DnsType::TXT => {
                            if let Some(txts) = response.get_txt_strings() {
                                for txt in txts {
                                    println!("  TXT: \"{}\" (ttl: {})", txt, response.ttl);
                                }
                            } else {
                                println!("  Invalid TXT data");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
