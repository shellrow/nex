use crate::{
    builder::BuildError,
    ip::IpNextProtocol,
    ipv6::{Ipv6ExtensionHeader, Ipv6Header, Ipv6Packet},
    packet::Packet,
};
use bytes::Bytes;
use std::net::Ipv6Addr;

/// Builder for constructing IPv6 packets
#[derive(Debug, Clone)]
pub struct Ipv6PacketBuilder {
    packet: Ipv6Packet,
}

impl Default for Ipv6PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6PacketBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            packet: Ipv6Packet {
                header: Ipv6Header {
                    version: 6,
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: 0,
                    next_header: IpNextProtocol::Reserved,
                    hop_limit: 64,
                    source: Ipv6Addr::UNSPECIFIED,
                    destination: Ipv6Addr::UNSPECIFIED,
                },
                extensions: Vec::new(),
                payload: Bytes::new(),
            },
        }
    }

    pub fn source(mut self, addr: Ipv6Addr) -> Self {
        self.packet.header.source = addr;
        self
    }

    pub fn destination(mut self, addr: Ipv6Addr) -> Self {
        self.packet.header.destination = addr;
        self
    }

    pub fn traffic_class(mut self, tc: u8) -> Self {
        self.packet.header.traffic_class = tc;
        self
    }

    pub fn flow_label(mut self, label: u32) -> Self {
        self.packet.header.flow_label = label & 0x000FFFFF;
        self
    }

    pub fn hop_limit(mut self, limit: u8) -> Self {
        self.packet.header.hop_limit = limit;
        self
    }

    pub fn next_header(mut self, proto: IpNextProtocol) -> Self {
        self.packet.header.next_header = proto;
        self
    }

    pub fn extension(mut self, ext: Ipv6ExtensionHeader) -> Self {
        self.packet.extensions.push(ext);
        self
    }

    pub fn extensions(mut self, list: Vec<Ipv6ExtensionHeader>) -> Self {
        self.packet.extensions = list;
        self
    }

    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    /// Build the packet and return it
    pub fn build(mut self) -> Result<Ipv6Packet, BuildError> {
        let mut extensions_length = 0usize;
        for extension in &self.packet.extensions {
            let extension_length = extension.len();
            match extension {
                Ipv6ExtensionHeader::HopByHop { .. }
                | Ipv6ExtensionHeader::Destination { .. }
                | Ipv6ExtensionHeader::Routing { .. }
                    if extension_length > 2048 =>
                {
                    return Err(BuildError::LengthOverflow {
                        context: "IPv6 extension header",
                        maximum: 2048,
                        actual: extension_length,
                    });
                }
                Ipv6ExtensionHeader::Fragment { offset, .. } if *offset > 0x1fff => {
                    return Err(BuildError::ValueOutOfRange {
                        context: "IPv6 fragment offset",
                        maximum: 0x1fff,
                        actual: *offset as usize,
                    });
                }
                Ipv6ExtensionHeader::Raw { raw, .. } if raw.is_empty() => {
                    return Err(BuildError::LengthTooShort {
                        context: "raw IPv6 extension header",
                        minimum: 1,
                        actual: 0,
                    });
                }
                _ => {}
            }
            extensions_length = extensions_length.checked_add(extension_length).ok_or(
                BuildError::LengthOverflow {
                    context: "IPv6 payload length",
                    maximum: u16::MAX as usize,
                    actual: usize::MAX,
                },
            )?;
        }

        let payload_length = extensions_length
            .checked_add(self.packet.payload.len())
            .ok_or(BuildError::LengthOverflow {
                context: "IPv6 payload length",
                maximum: u16::MAX as usize,
                actual: usize::MAX,
            })?;
        if payload_length > u16::MAX as usize {
            return Err(BuildError::LengthOverflow {
                context: "IPv6 payload length",
                maximum: u16::MAX as usize,
                actual: payload_length,
            });
        }

        self.packet.header.payload_length = payload_length as u16;
        Ok(self.packet)
    }

    /// Serialize the packet into bytes
    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
    }

    /// Get only the header bytes
    pub fn header_bytes(&self) -> Bytes {
        self.packet.header().slice(..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::IpNextProtocol;
    use bytes::Bytes;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv6_builder_payload_len() {
        let payload = Bytes::from_static(&[1, 2, 3, 4]);
        let pkt = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpNextProtocol::Tcp)
            .payload(payload.clone())
            .build()
            .expect("valid IPv6 packet");
        assert_eq!(pkt.header.payload_length, payload.len() as u16);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn ipv6_builder_rejects_oversized_payload() {
        let payload = Bytes::from(vec![0; u16::MAX as usize + 1]);
        let error = Ipv6PacketBuilder::new()
            .payload(payload)
            .build()
            .expect_err("oversized IPv6 payload");

        assert!(matches!(
            error,
            BuildError::LengthOverflow {
                context: "IPv6 payload length",
                ..
            }
        ));
    }
}
