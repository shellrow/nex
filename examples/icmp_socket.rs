//! Ping using IcmpSocket
//!
//! Usage: icmp_socket <TARGET IP> <INTERFACE>

use bytes::Bytes;
use nex::net::interface::{get_interfaces, Interface};
use nex_packet::builder::icmp::IcmpPacketBuilder;
use nex_packet::builder::icmpv6::Icmpv6PacketBuilder;
use nex_packet::icmp::IcmpPacket;
use nex_packet::icmpv6::Icmpv6Packet;
use nex_packet::ipv4::Ipv4Packet;
use nex_packet::packet::Packet;
use nex_packet::{icmp, icmpv6};
use nex_socket::icmp::{IcmpConfig, IcmpKind, IcmpSocket};
use std::env;
use std::net::{IpAddr, SocketAddr};

fn main() -> std::io::Result<()> {
    let target_ip: IpAddr = env::args()
        .nth(1)
        .expect("Missing target IP")
        .parse()
        .expect("parse ip");
    let interface = match env::args().nth(2) {
        Some(name) => get_interfaces()
            .into_iter()
            .find(|i| i.name == name)
            .expect("interface not found"),
        None => Interface::default().expect("default interface"),
    };

    let src_ip = match target_ip {
        IpAddr::V4(_) => interface
            .ipv4
            .get(0)
            .map(|v| IpAddr::V4(v.addr()))
            .expect("No IPv4 address"),
        IpAddr::V6(_) => interface
            .ipv6
            .iter()
            .find(|v| nex::net::ip::is_global_ipv6(&v.addr()))
            .map(|v| IpAddr::V6(v.addr()))
            .expect("No global IPv6 address"),
    };

    let kind = if target_ip.is_ipv4() {
        IcmpKind::V4
    } else {
        IcmpKind::V6
    };
    let socket = IcmpSocket::new(&IcmpConfig::new(kind))?;

    let packet = match (src_ip, target_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => IcmpPacketBuilder::new(src, dst)
            .icmp_type(nex_packet::icmp::IcmpType::EchoRequest)
            .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
            .echo_fields(0x1234, 1)
            .payload(Bytes::from_static(b"hello"))
            .calculate_checksum()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Icmpv6PacketBuilder::new(src, dst)
            .icmpv6_type(nex_packet::icmpv6::Icmpv6Type::EchoRequest)
            .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
            .echo_fields(0x1234, 1)
            .payload(Bytes::from_static(b"hello"))
            .calculate_checksum()
            .to_bytes(),
        _ => unreachable!(),
    };

    socket.send_to(&packet, SocketAddr::new(target_ip, 0))?;
    println!("Sent echo request to {}", target_ip);

    let mut buf = [0u8; 1500];
    let (n, from) = socket.recv_from(&mut buf)?;
    println!("Received {} bytes from {}", n, from.ip());
    let packet: &[u8] = &buf[..n];
    match kind {
        IcmpKind::V4 => {
            // Parse IPv4 + ICMP
            if let Some(ipv4_packet) = Ipv4Packet::from_buf(packet) {
                if ipv4_packet.header.next_level_protocol == nex_packet::ip::IpNextProtocol::Icmp {
                    if let Some(icmp_packet) = IcmpPacket::from_bytes(ipv4_packet.payload()) {
                        println!(
                            "\t{:?} from: {:?} to {:?}, TTL: {}",
                            icmp_packet.header.icmp_type,
                            ipv4_packet.header.source,
                            ipv4_packet.header.destination,
                            ipv4_packet.header.ttl
                        );
                        match icmp::echo_reply::EchoReplyPacket::try_from(icmp_packet) {
                            Ok(reply) => {
                                println!(
                                    "\tID: {}, Seq: {}",
                                    reply.identifier, reply.sequence_number
                                );
                            }
                            Err(_) => {
                                println!("\tReceived non-echo-reply ICMP packet");
                            }
                        }
                    }
                }
            }
        }
        IcmpKind::V6 => {
            // Parse ICMPv6
            // The IPv6 header is automatically cropped off when recvfrom() is used.
            if let Some(icmpv6_packet) = Icmpv6Packet::from_buf(packet) {
                println!(
                    "\t{:?} from: {:?}",
                    icmpv6_packet.header.icmpv6_type,
                    from.ip()
                );
                match icmpv6::echo_reply::EchoReplyPacket::from_buf(packet) {
                    Some(reply) => {
                        println!("\tID: {}, Seq: {}", reply.identifier, reply.sequence_number);
                    }
                    None => {
                        println!("\tReceived non-echo-reply ICMPv6 packet");
                    }
                }
            }
        }
    }
    Ok(())
}
