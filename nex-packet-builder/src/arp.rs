use nex_core::mac::MacAddr;
use nex_packet::arp::ArpHardwareType;
use nex_packet::arp::ArpOperation;
use nex_packet::arp::MutableArpPacket;
use nex_packet::arp::ARP_HEADER_LEN;
use nex_packet::ethernet::EtherType;
use nex_packet::Packet;
use std::net::Ipv4Addr;

/// Build ARP packet.
pub(crate) fn build_arp_packet(
    arp_packet: &mut MutableArpPacket,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) {
    arp_packet.set_hardware_type(ArpHardwareType::Ethernet);
    arp_packet.set_protocol_type(EtherType::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperation::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(dst_mac);
    arp_packet.set_target_proto_addr(dst_ip);
}

/// ARP Packet Builder.
#[derive(Clone, Debug)]
pub struct ArpPacketBuilder {
    /// Source MAC address.
    pub src_mac: MacAddr,
    /// Destination MAC address.
    pub dst_mac: MacAddr,
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
}

impl ArpPacketBuilder {
    /// Constructs a new ArpPacketBuilder.
    pub fn new() -> ArpPacketBuilder {
        ArpPacketBuilder {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::broadcast(),
            src_ip: Ipv4Addr::UNSPECIFIED,
            dst_ip: Ipv4Addr::UNSPECIFIED,
        }
    }
    /// Builds ARP packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buffer = [0u8; ARP_HEADER_LEN];
        let mut arp_packet = MutableArpPacket::new(&mut buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareType::Ethernet);
        arp_packet.set_protocol_type(EtherType::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperation::Request);
        arp_packet.set_sender_hw_addr(self.src_mac);
        arp_packet.set_sender_proto_addr(self.src_ip);
        arp_packet.set_target_hw_addr(self.dst_mac);
        arp_packet.set_target_proto_addr(self.dst_ip);
        arp_packet.packet().to_vec()
    }
}
