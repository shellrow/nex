use nex_packet::ip::IpNextLevelProtocol;
use nex_packet::ipv6::MutableIpv6Packet;
use nex_packet::ipv6::IPV6_HEADER_LEN;
use nex_packet::Packet;
use std::net::Ipv6Addr;

pub(crate) fn build_ipv6_packet(
    ipv6_packet: &mut MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextLevelProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    ipv6_packet.set_hop_limit(64);
    match next_protocol {
        IpNextLevelProtocol::Tcp => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Tcp);
            ipv6_packet.set_payload_length(32);
        }
        IpNextLevelProtocol::Udp => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Udp);
            ipv6_packet.set_payload_length(8);
        }
        IpNextLevelProtocol::Icmpv6 => {
            ipv6_packet.set_next_header(IpNextLevelProtocol::Icmpv6);
            ipv6_packet.set_payload_length(8);
        }
        _ => {}
    }
}

/// IPv6 Packet Builder.
#[derive(Clone, Debug)]
pub struct Ipv6PacketBuilder {
    /// Source IPv6 address.
    pub src_ip: Ipv6Addr,
    /// Destination IPv6 address.
    pub dst_ip: Ipv6Addr,
    /// Next level protocol.
    pub next_protocol: IpNextLevelProtocol,
    /// Payload Length.
    pub payload_length: Option<u16>,
    /// Hop Limit.
    pub hop_limit: Option<u8>,
}

impl Ipv6PacketBuilder {
    /// Constructs a new Ipv6PacketBuilder.
    pub fn new(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, next_protocol: IpNextLevelProtocol) -> Self {
        Ipv6PacketBuilder {
            src_ip,
            dst_ip,
            next_protocol,
            payload_length: None,
            hop_limit: None,
        }
    }
    /// Buid IPv6 packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; IPV6_HEADER_LEN];
        let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer).unwrap();
        ipv6_packet.set_source(self.src_ip);
        ipv6_packet.set_destination(self.dst_ip);
        ipv6_packet.set_version(6);
        if let Some(hop_limit) = self.hop_limit {
            ipv6_packet.set_hop_limit(hop_limit);
        } else {
            ipv6_packet.set_hop_limit(64);
        }
        match self.next_protocol {
            IpNextLevelProtocol::Tcp => {
                ipv6_packet.set_next_header(IpNextLevelProtocol::Tcp);
                ipv6_packet.set_payload_length(32);
            }
            IpNextLevelProtocol::Udp => {
                ipv6_packet.set_next_header(IpNextLevelProtocol::Udp);
                ipv6_packet.set_payload_length(8);
            }
            IpNextLevelProtocol::Icmpv6 => {
                ipv6_packet.set_next_header(IpNextLevelProtocol::Icmpv6);
                ipv6_packet.set_payload_length(8);
            }
            _ => {}
        }
        if let Some(payload_length) = self.payload_length {
            ipv6_packet.set_payload_length(payload_length);
        }
        ipv6_packet.packet().to_vec()
    }
}
