//! Demonstrates chaining mutable packet views across Ethernet/IPv4/UDP layers.

use nex::net::mac::MacAddr;
use nex::packet::ethernet::{
    ETHERNET_HEADER_LEN, EtherType, EthernetPacket, MutableEthernetPacket,
};
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::{self, IPV4_HEADER_LEN, Ipv4Packet, MutableIpv4Packet};
use nex::packet::packet::{MutablePacket, Packet};
use nex::packet::udp::{self, MutableUdpPacket, UDP_HEADER_LEN, UdpPacket};
use std::net::Ipv4Addr;

fn main() {
    // Build a simple Ethernet/IPv4/UDP frame in-place.
    let payload = b"hello mutable packets";
    let frame_len = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut frame = vec![0u8; frame_len];

    {
        let mut ethernet = MutableEthernetPacket::new(&mut frame).expect("ethernet");
        ethernet.set_source(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
        ethernet.set_destination(MacAddr::new(0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc));
        ethernet.set_ethertype(EtherType::Ipv4);

        let ipv4_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
        {
            // Use `new_unchecked` because the buffer starts zeroed; we will
            // populate all required header fields before freezing it back into
            // an immutable packet for validation.
            let mut ipv4 = MutableIpv4Packet::new_unchecked(ethernet.payload_mut());
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextProtocol::Udp);
            ipv4.set_source(Ipv4Addr::new(192, 0, 2, 1));
            ipv4.set_destination(Ipv4Addr::new(198, 51, 100, 1));
            ipv4.set_identification(0x1337);
            ipv4.set_checksum(0);

            {
                let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp");
                udp.set_source(5353);
                udp.set_destination(8080);
                udp.set_length((UDP_HEADER_LEN + payload.len()) as u16);
                udp.set_checksum(0);

                let udp_payload = udp.payload_mut();
                udp_payload[..payload.len()].copy_from_slice(payload);
            }

            let snapshot = ipv4.freeze().expect("snapshot ipv4");
            let udp_snapshot = UdpPacket::from_buf(&snapshot.payload).expect("snapshot udp");
            let udp_checksum = udp::ipv4_checksum(
                &udp_snapshot,
                &snapshot.header.source,
                &snapshot.header.destination,
            );
            MutableUdpPacket::new(ipv4.payload_mut())
                .expect("udp checksum")
                .set_checksum(udp_checksum);
            let ipv4_checksum = ipv4::checksum(&snapshot);
            ipv4.set_checksum(ipv4_checksum);
        }
    }

    // Inspect immutable packet views to confirm changes persisted across layers.
    let ethernet_packet = EthernetPacket::from_buf(&frame).expect("immutable ethernet");
    let ipv4_packet = Ipv4Packet::from_buf(&ethernet_packet.payload).expect("immutable ipv4");
    let udp_packet = UdpPacket::from_buf(&ipv4_packet.payload).expect("immutable udp");

    println!(
        "Ethernet: {} -> {} ({:?})",
        ethernet_packet.header.source,
        ethernet_packet.header.destination,
        ethernet_packet.header.ethertype
    );
    println!(
        "IPv4: {} -> {} ttl={} checksum=0x{:04x}",
        ipv4_packet.header.source,
        ipv4_packet.header.destination,
        ipv4_packet.header.ttl,
        ipv4_packet.header.checksum
    );
    println!(
        "UDP: {} -> {} len={} checksum=0x{:04x}",
        udp_packet.header.source,
        udp_packet.header.destination,
        udp_packet.header.length,
        udp_packet.header.checksum
    );
    println!("Payload: {}", String::from_utf8_lossy(&udp_packet.payload));
}
