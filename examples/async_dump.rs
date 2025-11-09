//! Basic packet capture using asynchronous receive channel.

use bytes::Bytes;
use futures::stream::StreamExt;
use nex::net::interface::Interface;
use nex::net::mac::MacAddr;
use nex::packet::arp::ArpPacket;
use nex::packet::ethernet::{EtherType, EthernetPacket};
use nex::packet::icmp::{IcmpPacket, IcmpType};
use nex::packet::icmpv6::Icmpv6Packet;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Packet;
use nex::packet::ipv6::Ipv6Packet;
use nex::packet::packet::Packet;
use nex::packet::tcp::TcpPacket;
use nex::packet::udp::UdpPacket;
use nex_datalink::async_io::{async_channel, AsyncChannel};
use nex_datalink::Config;
use nex_packet::ethernet::EthernetHeader;
use nex_packet::{icmp, icmpv6};
use std::net::IpAddr;

fn main() -> std::io::Result<()> {
    // Choose the default interface.
    let interface = Interface::default().expect("no default interface");
    let AsyncChannel::Ethernet(_tx, mut rx) = async_channel(&interface, Config::default())? else {
        unreachable!();
    };

    futures::executor::block_on(async {
        let mut capture_no: usize = 0;
        // Receive packets asynchronously.
        while let Some(Ok(packet)) = rx.next().await {
            capture_no += 1;
            println!(
                "---- Interface: {}, No.: {}, Total Length: {} bytes ----",
                interface.name,
                capture_no,
                packet.len()
            );

            if interface.is_tun()
                || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback())
            {
                let payload_offset: usize;
                if interface.is_loopback() {
                    payload_offset = 14;
                } else {
                    payload_offset = 0;
                }
                let payload = Bytes::copy_from_slice(&packet[payload_offset..]);
                if packet.len() > payload_offset {
                    let version = Ipv4Packet::from_buf(&packet).unwrap().header.version;
                    let fake_eth = EthernetPacket {
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
                    };
                    handle_ethernet_frame(fake_eth);
                }
            } else {
                handle_ethernet_frame(EthernetPacket::from_buf(&packet).unwrap());
            }
        }
        Ok::<(), std::io::Error>(())
    })?;

    Ok(())
}

fn handle_ethernet_frame(ethernet: EthernetPacket) {
    let total_len = ethernet.total_len();
    let (header, payload) = ethernet.into_parts();
    match header.ethertype {
        EtherType::Ipv4 => handle_ipv4_packet(payload),
        EtherType::Ipv6 => handle_ipv6_packet(payload),
        EtherType::Arp => handle_arp_packet(payload),
        _ => {
            println!(
                "{} packet: {} > {}; ethertype: {:?} length: {}",
                header.ethertype.name(),
                header.source,
                header.destination,
                header.ethertype,
                total_len,
            )
        }
    }
}

fn handle_arp_packet(packet: Bytes) {
    match ArpPacket::from_bytes(packet) { Some(arp) => {
        println!(
            "ARP packet: {}({}) > {}({}); operation: {:?}",
            arp.header.sender_hw_addr,
            arp.header.sender_proto_addr,
            arp.header.target_hw_addr,
            arp.header.target_proto_addr,
            arp.header.operation
        );
    } _ => {
        println!("Malformed ARP Packet");
    }}
}

fn handle_ipv4_packet(packet: Bytes) {
    match Ipv4Packet::from_bytes(packet) { Some(ipv4) => {
        handle_transport_protocol(
            IpAddr::V4(ipv4.header.source),
            IpAddr::V4(ipv4.header.destination),
            ipv4.header.next_level_protocol,
            ipv4.payload,
        );
    } _ => {
        println!("Malformed IPv4 Packet");
    }}
}

fn handle_ipv6_packet(packet: Bytes) {
    match Ipv6Packet::from_bytes(packet) { Some(ipv6) => {
        handle_transport_protocol(
            IpAddr::V6(ipv6.header.source),
            IpAddr::V6(ipv6.header.destination),
            ipv6.header.next_header,
            ipv6.payload,
        );
    } _ => {
        println!("Malformed IPv6 Packet");
    }}
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextProtocol,
    packet: Bytes,
) {
    match protocol {
        IpNextProtocol::Tcp => handle_tcp_packet(source, destination, packet),
        IpNextProtocol::Udp => handle_udp_packet(source, destination, packet),
        IpNextProtocol::Icmp => handle_icmp_packet(source, destination, packet),
        IpNextProtocol::Icmpv6 => handle_icmpv6_packet(source, destination, packet),
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

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: Bytes) {
    match TcpPacket::from_bytes(packet) { Some(tcp) => {
        println!(
            "TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            tcp.header.source,
            destination,
            tcp.header.destination,
            tcp.total_len(),
        );
    } _ => {
        println!("Malformed TCP Packet");
    }}
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: Bytes) {
    let udp = UdpPacket::from_bytes(packet);

    if let Some(udp) = udp {
        println!(
            "UDP Packet: {}:{} > {}:{}; length: {}",
            source,
            udp.header.source,
            destination,
            udp.header.destination,
            udp.total_len(),
        );
    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: Bytes) {
    let icmp_packet = IcmpPacket::from_bytes(packet);
    if let Some(icmp_packet) = icmp_packet {
        let total_len = icmp_packet.total_len();
        match icmp_packet.header.icmp_type {
            IcmpType::EchoRequest => {
                let echo_request_packet =
                    icmp::echo_request::EchoRequestPacket::try_from(icmp_packet).unwrap();
                println!(
                    "ICMP echo request {} -> {} (seq={:?}, id={:?}), length: {}",
                    source,
                    destination,
                    echo_request_packet.sequence_number,
                    echo_request_packet.identifier,
                    total_len
                );
            }
            IcmpType::EchoReply => {
                let echo_reply_packet =
                    icmp::echo_reply::EchoReplyPacket::try_from(icmp_packet).unwrap();
                println!(
                    "ICMP echo reply {} -> {} (seq={:?}, id={:?}), length: {}",
                    source,
                    destination,
                    echo_reply_packet.sequence_number,
                    echo_reply_packet.identifier,
                    total_len,
                );
            }
            IcmpType::DestinationUnreachable => {
                let unreachable_packet =
                    icmp::destination_unreachable::DestinationUnreachablePacket::try_from(
                        icmp_packet,
                    )
                    .unwrap();
                println!(
                    "ICMP destination unreachable {} -> {} (code={:?}), next_hop_mtu={}, length: {}",
                    source,
                    destination,
                    unreachable_packet.header.icmp_code,
                    unreachable_packet.next_hop_mtu,
                    total_len
                );
            }
            IcmpType::TimeExceeded => {
                let time_exceeded_packet =
                    icmp::time_exceeded::TimeExceededPacket::try_from(icmp_packet).unwrap();
                println!(
                    "ICMP time exceeded {} -> {} (code={:?}), length: {}",
                    source, destination, time_exceeded_packet.header.icmp_code, total_len
                );
            }
            _ => {
                println!(
                    "ICMP packet {} -> {} (type={:?}), length: {}",
                    source, destination, icmp_packet.header.icmp_type, total_len
                )
            }
        }
    } else {
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: Bytes) {
    let icmpv6_packet = Icmpv6Packet::from_bytes(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        match icmpv6_packet.header.icmpv6_type {
            nex::packet::icmpv6::Icmpv6Type::EchoRequest => {
                let echo_request_packet =
                    icmpv6::echo_request::EchoRequestPacket::try_from(icmpv6_packet).unwrap();
                println!(
                    "ICMPv6 echo request {} -> {} (type={:?}), length: {}",
                    source,
                    destination,
                    echo_request_packet.header.icmpv6_type,
                    echo_request_packet.total_len(),
                );
            }
            nex::packet::icmpv6::Icmpv6Type::EchoReply => {
                let echo_reply_packet =
                    icmpv6::echo_reply::EchoReplyPacket::try_from(icmpv6_packet).unwrap();
                println!(
                    "ICMPv6 echo reply {} -> {} (type={:?}), length: {}",
                    source,
                    destination,
                    echo_reply_packet.header.icmpv6_type,
                    echo_reply_packet.total_len(),
                );
            }
            nex::packet::icmpv6::Icmpv6Type::NeighborSolicitation => {
                let ns_packet =
                    icmpv6::ndp::NeighborSolicitPacket::try_from(icmpv6_packet).unwrap();
                println!(
                    "ICMPv6 neighbor solicitation {} -> {} (type={:?}), length: {}",
                    source,
                    destination,
                    ns_packet.header.icmpv6_type,
                    ns_packet.total_len(),
                );
            }
            nex::packet::icmpv6::Icmpv6Type::NeighborAdvertisement => {
                let na_packet = icmpv6::ndp::NeighborAdvertPacket::try_from(icmpv6_packet).unwrap();
                println!(
                    "ICMPv6 neighbor advertisement {} -> {} (type={:?}), length: {}",
                    source,
                    destination,
                    na_packet.header.icmpv6_type,
                    na_packet.total_len(),
                );
            }
            _ => {
                println!(
                    "ICMPv6 packet {} -> {} (type={:?}), length: {}",
                    source,
                    destination,
                    icmpv6_packet.header.icmpv6_type,
                    icmpv6_packet.total_len(),
                )
            }
        }
    } else {
        println!("Malformed ICMPv6 Packet");
    }
}
