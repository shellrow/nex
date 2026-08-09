use std::net::Ipv4Addr;

use crate::{
    builder::BuildError,
    icmp::{self, IcmpCode, IcmpHeader, IcmpPacket, IcmpType},
    packet::Packet,
};
use bytes::{BufMut, Bytes, BytesMut};

/// Builder for constructing ICMP packets
#[derive(Debug, Clone)]
pub struct IcmpPacketBuilder {
    packet: IcmpPacket,
}

impl IcmpPacketBuilder {
    /// Create a new builder with an initial ICMP Type and Code
    pub fn new(_source: Ipv4Addr, _destination: Ipv4Addr) -> Self {
        let header = IcmpHeader {
            icmp_type: IcmpType::EchoRequest,
            icmp_code: icmp::echo_request::IcmpCodes::NoCode,
            checksum: 0,
        };
        Self {
            packet: IcmpPacket {
                header,
                payload: Bytes::new(),
            },
        }
    }

    /// Set the ICMP Type
    pub fn icmp_type(mut self, icmp_type: IcmpType) -> Self {
        self.packet.header.icmp_type = icmp_type;
        self
    }

    /// Set the ICMP Code
    pub fn icmp_code(mut self, icmp_code: IcmpCode) -> Self {
        self.packet.header.icmp_code = icmp_code;
        self
    }

    /// Set an arbitrary payload
    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    /// For Echo Request/Reply: place identifier and sequence number at the start of the payload
    pub fn echo_fields(mut self, identifier: u16, sequence_number: u16) -> Self {
        let mut buf = BytesMut::with_capacity(4 + self.packet.payload.len());
        buf.put_u16(identifier);
        buf.put_u16(sequence_number);
        buf.extend_from_slice(&self.packet.payload);
        self.packet.payload = buf.freeze();
        self
    }

    /// Calculate the checksum and set it in the header
    pub fn calculate_checksum(mut self) -> Self {
        self.packet.header.checksum = icmp::checksum(&self.packet);
        self
    }

    /// Return an `IcmpPacket` with checksum computed
    pub fn build(mut self) -> Result<IcmpPacket, BuildError> {
        let packet_length =
            4usize
                .checked_add(self.packet.payload.len())
                .ok_or(BuildError::LengthOverflow {
                    context: "ICMP packet",
                    maximum: u16::MAX as usize - 20,
                    actual: usize::MAX,
                })?;
        let maximum = u16::MAX as usize - 20;
        if packet_length > maximum {
            return Err(BuildError::LengthOverflow {
                context: "ICMP packet",
                maximum,
                actual: packet_length,
            });
        }
        self.packet.header.checksum = icmp::checksum(&self.packet);
        Ok(self.packet)
    }

    /// Return the packet bytes with checksum computed
    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
    }

    /// Access the intermediate `IcmpPacket` if needed
    pub fn packet(&self) -> &IcmpPacket {
        &self.packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_builder_rejects_packet_too_large_for_ipv4() {
        let error = IcmpPacketBuilder::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
            .payload(Bytes::from(vec![0; u16::MAX as usize]))
            .build()
            .expect_err("oversized ICMP packet");

        assert!(matches!(
            error,
            BuildError::LengthOverflow {
                context: "ICMP packet",
                ..
            }
        ));
    }
}
