use nex_packet::{
    arp::ArpPacket,
    dhcp::DhcpPacket,
    dns::{DnsName, DnsPacket},
    ethernet::EthernetPacket,
    flowcontrol::FlowControlPacket,
    frame::{Frame, FrameView, ParseOption},
    gre::GrePacket,
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    packet::Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    vlan::VlanPacket,
    vxlan::VxlanPacket,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn all_public_packet_parsers_accept_arbitrary_input_without_panicking(
        data in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = EthernetPacket::try_from_buf(&data);
        let _ = VlanPacket::try_from_buf(&data);
        let _ = ArpPacket::try_from_buf(&data);
        let _ = Ipv4Packet::try_from_buf(&data);
        let _ = Ipv6Packet::try_from_buf(&data);
        let _ = TcpPacket::try_from_buf(&data);
        let _ = UdpPacket::try_from_buf(&data);
        let _ = IcmpPacket::try_from_buf(&data);
        let _ = Icmpv6Packet::try_from_buf(&data);
        let _ = DhcpPacket::try_from_buf(&data);
        let _ = DnsPacket::try_from_buf(&data);
        let _ = DnsName::try_from_bytes(&data);
        let _ = GrePacket::try_from_buf(&data);
        let _ = VxlanPacket::try_from_buf(&data);
        let _ = FlowControlPacket::try_from_buf(&data);
        let _ = Frame::try_from_buf(&data, ParseOption::default());
        let _ = FrameView::try_from_buf(&data, ParseOption::default());
    }
}
