use crate::{
    builder::BuildError,
    ip::IpNextProtocol,
    ipv4::{IPV4_HEADER_LEN, Ipv4Header, Ipv4OptionPacket, Ipv4OptionType, Ipv4Packet},
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

impl Default for Ipv4PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
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
                    identification: 0,
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
        self
    }

    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    pub fn build(mut self) -> Result<Ipv4Packet, BuildError> {
        let mut options_length = 0usize;
        for option in &self.packet.header.options {
            let encoded_length = match option.header.number {
                Ipv4OptionType::EOL | Ipv4OptionType::NOP => 1,
                _ => {
                    let encoded_length = 2usize.checked_add(option.data.len()).ok_or(
                        BuildError::LengthOverflow {
                            context: "IPv4 option",
                            maximum: u8::MAX as usize,
                            actual: usize::MAX,
                        },
                    )?;
                    if encoded_length > u8::MAX as usize {
                        return Err(BuildError::LengthOverflow {
                            context: "IPv4 option",
                            maximum: u8::MAX as usize,
                            actual: encoded_length,
                        });
                    }
                    match option.header.length {
                        Some(declared) if declared as usize != encoded_length => {
                            return Err(BuildError::InvalidFieldLength {
                                context: "IPv4 option length",
                                expected: encoded_length,
                                actual: declared as usize,
                            });
                        }
                        _ => {}
                    }
                    encoded_length
                }
            };
            options_length =
                options_length
                    .checked_add(encoded_length)
                    .ok_or(BuildError::LengthOverflow {
                        context: "IPv4 options",
                        maximum: 40,
                        actual: usize::MAX,
                    })?;
        }

        let padded_options_length = options_length.div_ceil(4) * 4;
        if padded_options_length > 40 {
            return Err(BuildError::LengthOverflow {
                context: "IPv4 options",
                maximum: 40,
                actual: padded_options_length,
            });
        }

        let header_length = IPV4_HEADER_LEN + padded_options_length;
        let total_length = header_length.checked_add(self.packet.payload_len()).ok_or(
            BuildError::LengthOverflow {
                context: "IPv4 total length",
                maximum: u16::MAX as usize,
                actual: usize::MAX,
            },
        )?;
        if total_length > u16::MAX as usize {
            return Err(BuildError::LengthOverflow {
                context: "IPv4 total length",
                maximum: u16::MAX as usize,
                actual: total_length,
            });
        }

        self.packet.header.header_length = (header_length / 4) as u4;
        self.packet.header.total_length = total_length as u16be;
        self.packet.header.checksum = crate::ipv4::checksum(&self.packet);
        Ok(self.packet)
    }

    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::IpNextProtocol;
    use crate::ipv4::Ipv4OptionHeader;
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
            .build()
            .expect("valid IPv4 packet");
        assert_eq!(
            pkt.header.total_length,
            (pkt.header_len() + payload.len()) as u16
        );
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn ipv4_builder_identification_is_caller_controlled() {
        let default_packet = Ipv4PacketBuilder::new().build().expect("valid IPv4 packet");
        assert_eq!(default_packet.header.identification, 0);

        let packet = Ipv4PacketBuilder::new()
            .identification(0x1234)
            .build()
            .expect("valid IPv4 packet");
        assert_eq!(packet.header.identification, 0x1234);
    }

    #[test]
    fn ipv4_builder_rejects_oversized_payload() {
        let payload = Bytes::from(vec![0; u16::MAX as usize]);
        let error = Ipv4PacketBuilder::new()
            .payload(payload)
            .build()
            .expect_err("oversized IPv4 packet");

        assert!(matches!(
            error,
            BuildError::LengthOverflow {
                context: "IPv4 total length",
                ..
            }
        ));
    }

    #[test]
    fn ipv4_builder_rejects_options_beyond_ihl_capacity() {
        let option = Ipv4OptionPacket {
            header: Ipv4OptionHeader {
                copied: 0,
                class: 0,
                number: Ipv4OptionType::NOP,
                length: None,
            },
            data: Bytes::new(),
        };
        let error = Ipv4PacketBuilder::new()
            .options(vec![option; 41])
            .build()
            .expect_err("IPv4 IHL overflow");

        assert!(matches!(
            error,
            BuildError::LengthOverflow {
                context: "IPv4 options",
                ..
            }
        ));
    }
}
