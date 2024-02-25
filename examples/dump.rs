//! Basic packet capture using nex

use nex::datalink;
use nex::datalink::Channel::Ethernet;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::arp::ArpPacket;
use nex::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use nex::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpType};
use nex::packet::icmpv6::Icmpv6Packet;
use nex::packet::ip::IpNextLevelProtocol;
use nex::packet::ipv4::Ipv4Packet;
use nex::packet::ipv6::Ipv6Packet;
use nex::packet::tcp::TcpPacket;
use nex::packet::udp::UdpPacket;
use nex::packet::Packet;
use std::env;
use std::net::IpAddr;
use std::process;

fn main() {
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
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("dump: unhandled channel type"),
        Err(e) => panic!("dump: unable to create channel: {}", e),
    };
    let mut capture_no: usize = 0;
    loop {
        let mut buf: [u8; 4096] = [0u8; 4096];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                capture_no += 1;
                println!(
                    "---- Interface: {}, No.: {}, Total Length: {} bytes ----",
                    interface.name,
                    capture_no,
                    packet.len()
                );
                let payload_offset;
                if interface.is_tun()
                    || (cfg!(any(target_os = "macos", target_os = "ios"))
                        && interface.is_loopback())
                {
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherType::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherType::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&fake_ethernet_frame.to_immutable());
                            continue;
                        }
                    }
                } else {
                    handle_ethernet_frame(&EthernetPacket::new(packet).unwrap());
                }
            }
            Err(e) => panic!("dump: unable to receive packet: {}", e),
        }
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherType::Ipv4 => handle_ipv4_packet(ethernet),
        EtherType::Ipv6 => handle_ipv6_packet(ethernet),
        EtherType::Arp => handle_arp_packet(ethernet),
        _ => {
            let ether_type = ethernet.get_ethertype();
            println!(
                "{} packet: {} > {}; ethertype: {:?} length: {}",
                ether_type.name(),
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            )
        }
    }
}

fn handle_arp_packet(ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "ARP packet: {}({}) > {}({}); operation: {:?}",
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
    } else {
        println!("Malformed ARP Packet");
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ipv6_packet(ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("Malformed IPv6 Packet");
    }
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextLevelProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextLevelProtocol::Tcp => handle_tcp_packet(source, destination, packet),
        IpNextLevelProtocol::Udp => handle_udp_packet(source, destination, packet),
        IpNextLevelProtocol::Icmp => handle_icmp_packet(source, destination, packet),
        IpNextLevelProtocol::Icmpv6 => handle_icmpv6_packet(source, destination, packet),
        _ => println!(
            "Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    } else {
        println!("Malformed TCP Packet");
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "UDP Packet: {}:{} > {}:{}; length: {}",
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpType::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "ICMP echo reply {} -> {} (seq={:?}, id={:?}), length: {}",
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier(),
                    packet.len()
                );
            }
            IcmpType::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "ICMP echo request {} -> {} (seq={:?}, id={:?}), length: {}",
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier(),
                    packet.len()
                );
            }
            _ => println!(
                "ICMP packet {} -> {} (type={:?}), length: {}",
                source,
                destination,
                icmp_packet.get_icmp_type(),
                packet.len()
            ),
        }
    } else {
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "ICMPv6 packet {} -> {} (type={:?}), length: {}",
            source,
            destination,
            icmpv6_packet.get_icmpv6_type(),
            packet.len()
        )
    } else {
        println!("Malformed ICMPv6 Packet");
    }
}
