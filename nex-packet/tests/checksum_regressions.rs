use bytes::Bytes;
use nex_packet::builder::udp::UdpPacketBuilder;
use nex_packet::icmpv6::MutableIcmpv6Packet;
use nex_packet::packet::{MutablePacket, Packet};
use nex_packet::tcp::MutableTcpPacket;
use nex_packet::udp::MutableUdpPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn udp_zero_checksum_is_encoded_as_all_ones() {
    for (address, payload) in [
        (IpAddr::V4(Ipv4Addr::LOCALHOST), [0x01, 0xd5]),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), [0xff, 0xd5]),
    ] {
        // Ports 1 and 2, length 10, and these payloads sum to negative zero.
        let packet = UdpPacketBuilder::new(address, address)
            .source(1)
            .destination(2)
            .payload(Bytes::copy_from_slice(&payload))
            .build()
            .unwrap();
        assert_eq!(packet.header.checksum, 0xffff);
        let mut raw = packet.to_bytes().to_vec();
        let mut mutable = MutableUdpPacket::new(&mut raw).unwrap();
        match address {
            IpAddr::V4(ip) => mutable.set_ipv4_checksum_context(ip, ip),
            IpAddr::V6(ip) => mutable.set_ipv6_checksum_context(ip, ip),
        }
        assert_eq!(mutable.recompute_checksum(), Some(0xffff));
    }
}

#[test]
fn changing_pseudo_header_invalidates_transport_checksums() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = "2001:db8::1".parse().unwrap();
    let changed_destination = "2001:db8::2".parse().unwrap();
    macro_rules! check_context {
        ($packet:expr) => {{
            let mut packet = $packet;
            packet.set_ipv6_checksum_context(source, destination);
            packet.recompute_checksum().unwrap();
            assert!(!packet.is_checksum_dirty());
            packet.set_ipv6_checksum_context(source, changed_destination);
            assert!(packet.is_checksum_dirty());
            packet.enable_auto_checksum();
            let previous = packet.checksum();
            packet.set_ipv6_checksum_context(source, destination);
            assert_ne!(packet.checksum(), previous);
            assert!(!packet.is_checksum_dirty());
            assert_eq!(Some(packet.checksum()), packet.recompute_checksum());
        }};
    }
    let mut udp = [0, 1, 0, 2, 0, 8, 0, 0];
    check_context!(MutableUdpPacket::new(&mut udp).unwrap());
    let mut tcp = [0; 20];
    tcp[12] = 0x50;
    check_context!(MutableTcpPacket::new(&mut tcp).unwrap());
    let mut icmpv6 = [128, 0, 0, 0, 0, 0, 0, 0];
    check_context!(MutableIcmpv6Packet::new(&mut icmpv6).unwrap());
}
