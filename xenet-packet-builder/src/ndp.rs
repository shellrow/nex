use std::net::Ipv6Addr;
use xenet_core::mac::MacAddr;
use xenet_packet::ethernet::MAC_ADDR_LEN;
use xenet_packet::icmpv6::ndp::{
    MutableNdpOptionPacket, MutableNeighborSolicitPacket, NdpOptionTypes,
};
use xenet_packet::icmpv6::ndp::{NDP_OPT_PACKET_LEN, NDP_SOL_PACKET_LEN};
use xenet_packet::icmpv6::{self, Icmpv6Type, MutableIcmpv6Packet};
//use xenet_packet::Packet;

/// Length in octets (8bytes)
fn octets_len(len: usize) -> u8 {
    // 3 = log2(8)
    (len.next_power_of_two() >> 3).try_into().unwrap()
}

/// NDP Packet Builder.
#[derive(Clone, Debug)]
pub struct NdpPacketBuilder {
    /// Source MAC address.
    pub src_mac: MacAddr,
    /// Destination MAC address.
    pub dst_mac: MacAddr,
    /// Source IPv6 address.
    pub src_ip: Ipv6Addr,
    /// Destination IPv6 address.
    pub dst_ip: Ipv6Addr,
}

impl NdpPacketBuilder {
    /// Constructs a new NdpPacketBuilder.
    pub fn new(src_mac: MacAddr, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> NdpPacketBuilder {
        NdpPacketBuilder {
            src_mac: src_mac,
            dst_mac: MacAddr::broadcast(),
            src_ip: src_ip,
            dst_ip: dst_ip,
        }
    }
    /// Build ICMPv6 packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buffer = [0u8; NDP_SOL_PACKET_LEN + NDP_OPT_PACKET_LEN + MAC_ADDR_LEN];
        // Build the NDP packet
        let mut ndp_packet = MutableNeighborSolicitPacket::new(&mut buffer).unwrap();
        ndp_packet.set_target_addr(self.dst_ip);
        ndp_packet.set_icmpv6_type(Icmpv6Type::NeighborSolicitation);
        ndp_packet.set_checksum(0x3131);

        let mut opt_packet = MutableNdpOptionPacket::new(ndp_packet.get_options_raw_mut()).unwrap();
        opt_packet.set_option_type(NdpOptionTypes::SourceLLAddr);
        opt_packet.set_length(octets_len(MAC_ADDR_LEN));
        opt_packet.set_data(&self.src_mac.octets());

        // Set the checksum (part of the NDP packet)
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_checksum(icmpv6::checksum(
            &icmpv6_packet.to_immutable(),
            &self.src_ip,
            &self.dst_ip,
        ));
        buffer.to_vec()
    }
}
