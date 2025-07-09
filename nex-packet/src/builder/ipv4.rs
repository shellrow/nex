use crate::{
    ip::IpNextProtocol,
    ipv4::{Ipv4Header, Ipv4OptionPacket, Ipv4OptionType, Ipv4Packet},
    packet::Packet,
};
use bytes::Bytes;
use nex_core::bitfield::*;
use std::net::Ipv4Addr;

/// Builder for constructing IPv4 packets.
#[derive(Debug, Clone)]
pub struct Ipv4PacketBuilder {
    packet: Ipv4Packet,
}

impl Ipv4PacketBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            packet: Ipv4Packet {
                header: Ipv4Header {
                    version: 4,
                    header_length: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 0, // automatically set during build
                    identification: rand::random::<u16>(),
                    flags: 0,
                    fragment_offset: 0,
                    ttl: 64,
                    next_level_protocol: IpNextProtocol::new(0),
                    checksum: 0,
                    source: Ipv4Addr::UNSPECIFIED,
                    destination: Ipv4Addr::UNSPECIFIED,
                    options: vec![],
                },
                payload: Bytes::new(),
            },
        }
    }

    pub fn source(mut self, addr: Ipv4Addr) -> Self {
        self.packet.header.source = addr;
        self
    }

    pub fn destination(mut self, addr: Ipv4Addr) -> Self {
        self.packet.header.destination = addr;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.packet.header.ttl = ttl;
        self
    }

    pub fn protocol(mut self, proto: IpNextProtocol) -> Self {
        self.packet.header.next_level_protocol = proto;
        self
    }

    pub fn identification(mut self, id: u16) -> Self {
        self.packet.header.identification = id;
        self
    }

    pub fn flags(mut self, flags: u3) -> Self {
        self.packet.header.flags = flags;
        self
    }

    pub fn fragment_offset(mut self, offset: u13be) -> Self {
        self.packet.header.fragment_offset = offset;
        self
    }

    pub fn options(mut self, options: Vec<Ipv4OptionPacket>) -> Self {
        self.packet.header.options = options;
        self.packet.header.header_length = ((20
            + self
                .packet
                .header
                .options
                .iter()
                .map(|opt| match opt.header.number {
                    Ipv4OptionType::EOL | Ipv4OptionType::NOP => 1,
                    _ => 2 + opt.data.len(),
                })
                .sum::<usize>()
            + 3)
            / 4) as u4; // includes padding
        self
    }

    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    pub fn build(mut self) -> Ipv4Packet {
        let total_length = self.packet.header_len() + self.packet.payload_len();
        self.packet.header.total_length = total_length as u16be;
        self.packet.header.checksum = 0;
        self.packet.header.checksum = crate::ipv4::checksum(&self.packet);
        self.packet
    }

    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::IpNextProtocol;
    use bytes::Bytes;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_builder_total_length() {
        let payload = Bytes::from_static(&[1, 2]);
        let pkt = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(1, 1, 1, 1))
            .destination(Ipv4Addr::new(2, 2, 2, 2))
            .protocol(IpNextProtocol::Udp)
            .payload(payload.clone())
            .build();
        assert_eq!(
            pkt.header.total_length,
            (pkt.header_len() + payload.len()) as u16
        );
        assert_eq!(pkt.payload, payload);
    }
}
