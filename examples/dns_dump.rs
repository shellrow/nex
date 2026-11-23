//! DNS packet capture example
//!
//! Captures DNS UDP traffic over IPv4/IPv6 and extracts:
//!   - Queries: domain name, type, class
//!   - Responses: IPs (A, AAAA), names (CNAME, PTR, NS), and TXT content

use bytes::Bytes;
use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::packet::dns::{DnsName, DnsPacket, DnsType};
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::packet::Packet;
use nex::packet::udp::UdpHeader;
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

                let options = ParseOption {
                    from_ip_packet: cfg!(any(target_os = "linux", target_os = "android"))
                        && interface.is_tun(),
                    offset: 0,
                };
                let Ok(frame) = Frame::try_from_buf(packet, options) else {
                    continue;
                };
                let Some(udp) = frame.transport.and_then(|layer| layer.udp) else {
                    continue;
                };
                if udp.source != 53 && udp.destination != 53 {
                    continue;
                }
                let Some(ip) = frame.ip else { continue };
                let addresses = ip
                    .ipv4
                    .map(|v4| (IpAddr::V4(v4.source), IpAddr::V4(v4.destination)))
                    .or_else(|| {
                        ip.ipv6
                            .map(|v6| (IpAddr::V6(v6.source), IpAddr::V6(v6.destination)))
                    });
                if let Some((src, dst)) = addresses {
                    handle_dns(frame.payload, udp, src, dst);
                }
            }
            Err(e) => eprintln!("Failed to read packet: {}", e),
        }
    }
}

fn handle_dns(packet: Bytes, udp: UdpHeader, src: IpAddr, dst: IpAddr) {
    if let Ok(dns) = DnsPacket::try_from_bytes(packet.clone()) {
        println!(
            "DNS Packet: {}:{} > {}:{}",
            src, udp.source, dst, udp.destination
        );

        let mut offset = 12;
        for query in &dns.queries {
            println!(
                "  Query: {:?} (type: {:?}, class: {:?})",
                DnsName::try_from_message(&packet, offset),
                query.qtype,
                query.qclass
            );
            offset += query.header_len();
        }

        for response in &dns.responses {
            match response.rtype {
                DnsType::A | DnsType::AAAA => {
                    if let Some(ip) = response.ip() {
                        println!(
                            "  Response: {} (type: {:?}, ttl: {})",
                            ip, response.rtype, response.ttl
                        );
                    } else {
                        println!("  Invalid IP data for type: {:?}", response.rtype);
                    }
                }
                DnsType::CNAME | DnsType::NS | DnsType::PTR => {
                    if let Ok(name) =
                        DnsName::try_from_message(&packet, offset + response.name.len() + 10)
                    {
                        println!(
                            "  Response: {} (type: {:?}, ttl: {})",
                            name, response.rtype, response.ttl
                        );
                    } else {
                        println!("  Invalid name data for type: {:?}", response.rtype);
                    }
                }
                DnsType::TXT => {
                    if let Some(txts) = response.txt_strings() {
                        for txt in txts {
                            println!("  TXT: \"{}\" (ttl: {})", txt, response.ttl);
                        }
                    } else {
                        println!("  Invalid TXT data");
                    }
                }
                _ => {}
            }
            offset += response.header_len();
        }
    }
}
