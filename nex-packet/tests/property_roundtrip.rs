use nex_packet::{
    ethernet::EthernetPacket, ipv4::Ipv4Packet, ipv6::Ipv6Packet, packet::Packet, tcp::TcpPacket,
    udp::UdpPacket, vlan::VlanPacket,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn ethernet_round_trip(
        destination in any::<[u8; 6]>(),
        source in any::<[u8; 6]>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut bytes = Vec::with_capacity(14 + payload.len());
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        let packet = EthernetPacket::try_from_buf(&bytes).expect("valid Ethernet packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }

    #[test]
    fn vlan_round_trip(
        tci in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.extend_from_slice(&tci.to_be_bytes());
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        let packet = VlanPacket::try_from_buf(&bytes).expect("valid VLAN packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }

    #[test]
    fn ipv4_round_trip(
        identification in any::<u16>(),
        source in any::<[u8; 4]>(),
        destination in any::<[u8; 4]>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let total_length = (20 + payload.len()) as u16;
        let mut bytes = Vec::with_capacity(total_length as usize);
        bytes.extend_from_slice(&[0x45, 0]);
        bytes.extend_from_slice(&total_length.to_be_bytes());
        bytes.extend_from_slice(&identification.to_be_bytes());
        bytes.extend_from_slice(&[0x40, 0, 64, 17, 0, 0]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&payload);
        let packet = Ipv4Packet::try_from_buf(&bytes).expect("valid IPv4 packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }

    #[test]
    fn ipv6_round_trip(
        source in any::<[u8; 16]>(),
        destination in any::<[u8; 16]>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut bytes = Vec::with_capacity(40 + payload.len());
        bytes.extend_from_slice(&[0x60, 0, 0, 0]);
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[17, 64]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&payload);
        let packet = Ipv6Packet::try_from_buf(&bytes).expect("valid IPv6 packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }

    #[test]
    fn udp_round_trip(
        source in any::<u16>(),
        destination in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let length = (8 + payload.len()) as u16;
        let mut bytes = Vec::with_capacity(length as usize);
        bytes.extend_from_slice(&source.to_be_bytes());
        bytes.extend_from_slice(&destination.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        let packet = UdpPacket::try_from_buf(&bytes).expect("valid UDP packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }

    #[test]
    fn tcp_round_trip(
        source in any::<u16>(),
        destination in any::<u16>(),
        sequence in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut bytes = Vec::with_capacity(20 + payload.len());
        bytes.extend_from_slice(&source.to_be_bytes());
        bytes.extend_from_slice(&destination.to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0x50, 0x18, 0x20, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&payload);
        let packet = TcpPacket::try_from_buf(&bytes).expect("valid TCP packet");
        let serialized = packet.to_bytes();
        prop_assert_eq!(serialized.as_ref(), bytes.as_slice());
    }
}
