use nex_packet::ip::IpNextLevelProtocol;
use nex_packet::ipv4::Ipv4Flags;
use nex_packet::ipv4::MutableIpv4Packet;
use nex_packet::ipv4::IPV4_HEADER_LEN;
use nex_packet::ipv4::IPV4_HEADER_LENGTH_BYTE_UNITS;
use nex_packet::Packet;
use std::net::Ipv4Addr;

/// Build IPv4 packet.
pub(crate) fn build_ipv4_packet(
    ipv4_packet: &mut MutableIpv4Packet,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    next_protocol: IpNextLevelProtocol,
) {
    ipv4_packet.set_header_length((IPV4_HEADER_LEN / IPV4_HEADER_LENGTH_BYTE_UNITS) as u8);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_version(4);
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    match next_protocol {
        IpNextLevelProtocol::Tcp => {
            ipv4_packet.set_total_length(52);
            ipv4_packet.set_next_level_protocol(IpNextLevelProtocol::Tcp);
        }
        IpNextLevelProtocol::Udp => {
            ipv4_packet.set_total_length(28);
            ipv4_packet.set_next_level_protocol(IpNextLevelProtocol::Udp);
        }
        IpNextLevelProtocol::Icmp => {
            ipv4_packet.set_total_length(28);
            ipv4_packet.set_next_level_protocol(IpNextLevelProtocol::Icmp);
        }
        _ => {}
    }
    let checksum = nex_packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
}

/// IPv4 Packet Builder.
#[derive(Clone, Debug)]
pub struct Ipv4PacketBuilder {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub next_protocol: IpNextLevelProtocol,
    pub total_length: Option<u16>,
    pub identification: Option<u16>,
    pub ttl: Option<u8>,
    pub flags: Option<u8>,
}

impl Ipv4PacketBuilder {
    /// Constructs a new Ipv4PacketBuilder.
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, next_protocol: IpNextLevelProtocol) -> Self {
        Ipv4PacketBuilder {
            src_ip,
            dst_ip,
            next_protocol,
            total_length: None,
            identification: None,
            ttl: None,
            flags: None,
        }
    }
    /// Builds IPv4 packet and return bytes
    pub fn build(&self) -> Vec<u8> {
        let mut buffer = vec![0; IPV4_HEADER_LEN];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        ipv4_packet.set_header_length((IPV4_HEADER_LEN / IPV4_HEADER_LENGTH_BYTE_UNITS) as u8);
        ipv4_packet.set_source(self.src_ip);
        ipv4_packet.set_destination(self.dst_ip);
        ipv4_packet.set_identification(self.identification.unwrap_or(rand::random::<u16>()));
        ipv4_packet.set_ttl(self.ttl.unwrap_or(64));
        ipv4_packet.set_version(4);
        ipv4_packet.set_next_level_protocol(self.next_protocol);
        if let Some(flags) = self.flags {
            match flags {
                Ipv4Flags::DontFragment => {
                    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
                }
                Ipv4Flags::MoreFragments => {
                    ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
                }
                _ => {}
            }
        } else {
            ipv4_packet.set_flags(Ipv4Flags::DontFragment);
        }
        match self.next_protocol {
            IpNextLevelProtocol::Tcp => {
                if let Some(total_length) = self.total_length {
                    ipv4_packet.set_total_length(total_length);
                } else {
                    ipv4_packet.set_total_length(52);
                }
            }
            IpNextLevelProtocol::Udp => {
                if let Some(total_length) = self.total_length {
                    ipv4_packet.set_total_length(total_length);
                } else {
                    ipv4_packet.set_total_length(28);
                }
            }
            IpNextLevelProtocol::Icmp => {
                if let Some(total_length) = self.total_length {
                    ipv4_packet.set_total_length(total_length);
                } else {
                    ipv4_packet.set_total_length(28);
                }
            }
            _ => {}
        }
        let checksum = nex_packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        ipv4_packet.packet().to_vec()
    }
}
