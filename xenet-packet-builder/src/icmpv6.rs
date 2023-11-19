use std::net::Ipv6Addr;
use xenet_packet::icmpv6::echo_request::MutableEchoRequestPacket;
use xenet_packet::icmpv6::Icmpv6Packet;
use xenet_packet::icmpv6::Icmpv6Type;
use xenet_packet::icmpv6::ICMPV6_HEADER_LEN;
use xenet_packet::Packet;

/// Build ICMPv6 packet.
pub(crate) fn build_icmpv6_echo_packet(
    icmp_packet: &mut MutableEchoRequestPacket,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) {
    icmp_packet.set_icmpv6_type(Icmpv6Type::EchoRequest);
    icmp_packet.set_identifier(rand::random::<u16>());
    icmp_packet.set_sequence_number(rand::random::<u16>());
    let icmpv6_packet = Icmpv6Packet::new(icmp_packet.packet()).unwrap();
    let icmpv6_checksum = xenet_packet::icmpv6::checksum(&icmpv6_packet, &src_ip, &dst_ip);
    //let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmpv6_checksum);
}

/// ICMPv6 Packet Builder.
#[derive(Clone, Debug)]
pub struct Icmpv6PacketBuilder {
    /// Source IPv6 address.
    pub src_ip: Ipv6Addr,
    /// Destination IPv6 address.
    pub dst_ip: Ipv6Addr,
    /// ICMPv6 type.
    pub icmpv6_type: Icmpv6Type,
    /// ICMPv6 sequence number.
    pub sequence_number: Option<u16>,
    /// ICMPv6 identifier.
    pub identifier: Option<u16>,
}

impl Icmpv6PacketBuilder {
    /// Constructs a new Icmpv6PacketBuilder.
    pub fn new(src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Icmpv6PacketBuilder {
        Icmpv6PacketBuilder {
            src_ip,
            dst_ip,
            icmpv6_type: Icmpv6Type::EchoRequest,
            sequence_number: None,
            identifier: None,
        }
    }
    /// Build ICMPv6 packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let buffer: &mut [u8] = &mut [0u8; ICMPV6_HEADER_LEN];
        let mut icmp_packet = MutableEchoRequestPacket::new(buffer).unwrap();
        icmp_packet.set_icmpv6_type(self.icmpv6_type);
        icmp_packet.set_identifier(self.identifier.unwrap_or(rand::random::<u16>()));
        icmp_packet.set_sequence_number(self.sequence_number.unwrap_or(rand::random::<u16>()));
        let icmpv6_packet = Icmpv6Packet::new(icmp_packet.packet()).unwrap();
        let icmpv6_checksum =
            xenet_packet::icmpv6::checksum(&icmpv6_packet, &self.src_ip, &self.dst_ip);
        icmp_packet.set_checksum(icmpv6_checksum);
        icmp_packet.packet().to_vec()
    }
}
