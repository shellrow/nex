use std::net::Ipv4Addr;
use nex_packet::icmp::echo_request::MutableEchoRequestPacket;
use nex_packet::icmp::IcmpType;
use nex_packet::icmp::ICMPV4_HEADER_LEN;
use nex_packet::Packet;

/// Build ICMP packet.
pub(crate) fn build_icmp_echo_packet(icmp_packet: &mut MutableEchoRequestPacket) {
    icmp_packet.set_icmp_type(IcmpType::EchoRequest);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = nex_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}

/// ICMP Packet Builder.
#[derive(Clone, Debug)]
pub struct IcmpPacketBuilder {
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
    /// ICMP type.
    pub icmp_type: IcmpType,
    /// ICMP sequence number.
    pub sequence_number: Option<u16>,
    /// ICMP identifier.
    pub identifier: Option<u16>,
}

impl IcmpPacketBuilder {
    /// Constructs a new IcmpPacketBuilder.
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> IcmpPacketBuilder {
        IcmpPacketBuilder {
            src_ip: src_ip,
            dst_ip: dst_ip,
            icmp_type: IcmpType::EchoRequest,
            sequence_number: None,
            identifier: None,
        }
    }
    /// Build ICMP packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let buffer: &mut [u8] = &mut [0u8; ICMPV4_HEADER_LEN];
        let mut icmp_packet = MutableEchoRequestPacket::new(buffer).unwrap();
        icmp_packet.set_icmp_type(self.icmp_type);
        if let Some(sequence_number) = self.sequence_number {
            icmp_packet.set_sequence_number(sequence_number);
        } else {
            icmp_packet.set_sequence_number(rand::random::<u16>());
        }
        if let Some(identifier) = self.identifier {
            icmp_packet.set_identifier(identifier);
        } else {
            icmp_packet.set_identifier(rand::random::<u16>());
        }
        let icmp_check_sum = nex_packet::util::checksum(&icmp_packet.packet(), 1);
        icmp_packet.set_checksum(icmp_check_sum);
        icmp_packet.packet().to_vec()
    }
}
