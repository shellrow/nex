use crate::builder::BuildError;
use crate::icmpv6::ndp::{NdpOptionPacket, NdpOptionTypes, NeighborSolicitPacket};
use crate::icmpv6::{self, Icmpv6Header, Icmpv6Packet, Icmpv6Type, checksum};
use crate::packet::Packet;
use bytes::Bytes;
use nex_core::mac::MacAddr;
use std::net::Ipv6Addr;

/// Length rounded up to an 8-byte multiple (for option length)
fn octets_len(len: usize) -> u8 {
    len.div_ceil(8) as u8
}

/// Builder for ICMPv6 Neighbor Solicitation packets
#[derive(Clone, Debug)]
pub struct NdpPacketBuilder {
    /// Source MAC address
    pub src_mac: MacAddr,
    /// Destination MAC address
    pub dst_mac: MacAddr,
    /// Source IPv6 address
    pub src_ip: Ipv6Addr,
    /// Target (destination) IPv6 address
    pub dst_ip: Ipv6Addr,
}

impl NdpPacketBuilder {
    /// Create a new builder
    pub fn new(src_mac: MacAddr, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Self {
        Self {
            src_mac,
            dst_mac: MacAddr::broadcast(),
            src_ip,
            dst_ip,
        }
    }

    /// Override the destination MAC
    pub fn dst_mac(mut self, dst_mac: MacAddr) -> Self {
        self.dst_mac = dst_mac;
        self
    }

    /// Build the Neighbor Solicitation packet
    pub fn build(&self) -> Result<Icmpv6Packet, BuildError> {
        // Build the MAC address option
        let mac_bytes = self.src_mac.octets();
        let opt_payload = Bytes::copy_from_slice(&mac_bytes);
        let opt_len = octets_len(mac_bytes.len());

        let options = vec![NdpOptionPacket {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: opt_len,
            payload: opt_payload,
        }];

        let packet = NeighborSolicitPacket {
            header: Icmpv6Header {
                icmpv6_type: Icmpv6Type::NeighborSolicitation,
                icmpv6_code: icmpv6::ndp::Icmpv6Codes::NoCode,
                checksum: 0,
            },
            reserved: 0,
            target_addr: self.dst_ip,
            options,
            payload: Bytes::new(),
        };

        // Build an Icmpv6Packet and calculate the checksum
        let mut icmp_packet =
            Icmpv6Packet::from_bytes(packet.to_bytes()).ok_or(BuildError::SerializationFailed {
                context: "NDP neighbor solicitation",
            })?;

        icmp_packet.header.checksum = checksum(&icmp_packet, &self.src_ip, &self.dst_ip);
        Ok(icmp_packet)
    }

    /// Get the packet as bytes
    pub fn to_bytes(&self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndp_builder_produces_aligned_source_link_layer_option() {
        let packet =
            NdpPacketBuilder::new(MacAddr::zero(), Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST)
                .build()
                .expect("valid NDP packet");

        assert_eq!(packet.payload.len(), 28);
    }
}
