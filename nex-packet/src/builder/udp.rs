use std::net::IpAddr;

use crate::udp::{UdpPacket, UdpHeader, UDP_HEADER_LEN};
use crate::packet::Packet;
use bytes::Bytes;

/// Builder for constructing UDP packets
#[derive(Debug, Clone)]
pub struct UdpPacketBuilder {
    packet: UdpPacket,
}

impl UdpPacketBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            packet: UdpPacket {
                header: UdpHeader {
                    source: 0,
                    destination: 0,
                    length: 0, // automatically set during build
                    checksum: 0,
                },
                payload: Bytes::new(),
            },
        }
    }

    /// Set the source port
    pub fn source(mut self, port: u16) -> Self {
        self.packet.header.source = port.into();
        self
    }

    /// Set the destination port
    pub fn destination(mut self, port: u16) -> Self {
        self.packet.header.destination = port.into();
        self
    }

    /// Set the checksum (optional)
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.packet.header.checksum = checksum.into();
        self
    }

    /// Set the payload
    pub fn payload(mut self, data: Bytes) -> Self {
        self.packet.payload = data;
        self
    }

    pub fn calculate_checksum(mut self, src_ip: &IpAddr, dst_ip: &IpAddr) -> Self {
        // Calculate the checksum and set it in the header
        self.packet.header.checksum = crate::udp::checksum(&self.packet, src_ip, dst_ip);
        self
    }

    /// Build the packet
    pub fn build(mut self) -> UdpPacket {
        // Automatically compute the length
        let total_len = UDP_HEADER_LEN + self.packet.payload.len();
        self.packet.header.length = (total_len as u16).into();
        self.packet
    }

    /// Serialize the packet into bytes
    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }

    /// Retrieve only the header bytes
    pub fn header_bytes(&self) -> Bytes {
        let mut pkt = self.clone().packet;
        pkt.header.length = (UDP_HEADER_LEN + pkt.payload.len()) as u16;
        pkt.header().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn udp_builder_sets_length() {
        let pkt = UdpPacketBuilder::new()
            .source(1)
            .destination(2)
            .payload(Bytes::from_static(&[1,2,3]))
            .build();
        assert_eq!(pkt.header.length, (UDP_HEADER_LEN + 3) as u16);
        assert_eq!(pkt.payload, Bytes::from_static(&[1,2,3]));
    }
}

