use std::env;
use std::net::Ipv4Addr;
use std::process;
use xenet::datalink;
use xenet::net::interface::Interface;
use xenet::packet::frame::ParseOption;
use xenet::packet::frame::Frame;
use xenet::datalink::Channel::Ethernet;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::ipv4::Ipv4PacketBuilder;
use xenet::net::mac::MacAddr;
use xenet::packet::ethernet::EtherType;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::icmp::IcmpType;
use xenet::util::packet_builder::icmp::IcmpPacketBuilder;

fn main() {
    let interface: Interface = match env::args().nth(1) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = xenet::net::interface::get_interfaces();
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
    let use_tun: bool = interface.is_tun();
    let src_ip: Ipv4Addr = interface.ipv4[0].addr;
    let dst_ip: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    // Create a channel to sned/receive packet
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };

    // Packet builder for ICMP Echo Request
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: if use_tun { MacAddr::zero() } else { interface.mac_addr.clone().unwrap() },
        dst_mac: if use_tun { MacAddr::zero() } else { interface.gateway.clone().unwrap().mac_addr },
        ether_type: EtherType::Ipv4,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    let ipv4_packet_builder = Ipv4PacketBuilder::new(src_ip, dst_ip, IpNextLevelProtocol::Icmp);
    packet_builder.set_ipv4(ipv4_packet_builder);
    let mut icmp_packet_builder = IcmpPacketBuilder::new(src_ip, dst_ip);
    icmp_packet_builder.icmp_type = IcmpType::EchoRequest;
    packet_builder.set_icmp(icmp_packet_builder);

    // Send ICMP Echo Request packets to 1.1.1.1
    let packet: Vec<u8> = if use_tun {packet_builder.ip_packet()} else {packet_builder.packet()};
    match tx.send_to(&packet, None) {
        Some(_) => println!("Packet sent"),
        None => println!("Failed to send packet"),
    }

    // Receive ICMP Echo Reply packets
    println!("Waiting for ICMP Echo Reply packets...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if let Some(ip_layer) = &frame.ip {
                    if let Some(icmp_packet) = &ip_layer.icmp {
                        if icmp_packet.icmp_type == IcmpType::EchoReply {
                            println!("Received ICMP Echo Reply packet from {}", ip_layer.ipv4.as_ref().unwrap().source);
                            println!("---- Interface: {}, Total Length: {} bytes ----", interface.name, packet.len());
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
