use std::net::Ipv4Addr;

use bytes::Bytes;
use nex_core::mac::MacAddr;

use crate::{
    builder::BuildError,
    dhcp::{DHCP_MIN_PACKET_SIZE, DhcpHardwareType, DhcpHeader, DhcpOperation, DhcpPacket},
    packet::Packet,
};

/// Builder for constructing DHCP packets
#[derive(Debug, Clone)]
pub struct DhcpPacketBuilder {
    packet: DhcpPacket,
}

impl DhcpPacketBuilder {
    /// Create an initial builder for DHCP Discover (can be adapted for Request, Offer, etc.)
    pub fn new_discover(xid: u32, chaddr: MacAddr) -> Self {
        let header = DhcpHeader {
            op: DhcpOperation::Request,
            htype: DhcpHardwareType::Ethernet,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0x8000, // broadcast flag
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            chaddr_pad: [0u8; 10].to_vec(),
            sname: [0u8; 64].to_vec(),
            file: [0u8; 128].to_vec(),
        };
        Self {
            packet: DhcpPacket {
                header,
                payload: Bytes::new(),
            },
        }
    }

    /// Set the payload including options
    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    /// Mutably access the header
    pub fn header_mut(&mut self) -> &mut DhcpHeader {
        &mut self.packet.header
    }

    /// Validate fixed fields and build the DHCP packet.
    pub fn build(self) -> Result<DhcpPacket, BuildError> {
        for (context, expected, actual) in [
            (
                "DHCP client hardware address padding",
                10,
                self.packet.header.chaddr_pad.len(),
            ),
            ("DHCP server name", 64, self.packet.header.sname.len()),
            ("DHCP boot file", 128, self.packet.header.file.len()),
        ] {
            if actual != expected {
                return Err(BuildError::InvalidFieldLength {
                    context,
                    expected,
                    actual,
                });
            }
        }

        let packet_length = DHCP_MIN_PACKET_SIZE
            .checked_add(self.packet.payload.len())
            .ok_or(BuildError::LengthOverflow {
                context: "DHCP packet",
                maximum: u16::MAX as usize - 8,
                actual: usize::MAX,
            })?;
        let maximum = u16::MAX as usize - 8;
        if packet_length > maximum {
            return Err(BuildError::LengthOverflow {
                context: "DHCP packet",
                maximum,
                actual: packet_length,
            });
        }

        Ok(self.packet)
    }

    /// Build and return the packet bytes
    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
    }

    /// Get a reference to the packet
    pub fn packet(&self) -> &DhcpPacket {
        &self.packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_builder_rejects_invalid_fixed_field_length() {
        let mut builder = DhcpPacketBuilder::new_discover(1, MacAddr::zero());
        builder.header_mut().sname.clear();

        let error = builder.build().expect_err("invalid DHCP server name");
        assert!(matches!(
            error,
            BuildError::InvalidFieldLength {
                context: "DHCP server name",
                ..
            }
        ));
    }
}
