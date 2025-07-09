use crate::{
    ethernet::{EtherType, EthernetHeader, EthernetPacket},
    packet::Packet,
};
use bytes::Bytes;
use nex_core::mac::MacAddr;

/// Builder for constructing Ethernet packets.
#[derive(Debug, Clone)]
pub struct EthernetPacketBuilder {
    packet: EthernetPacket,
}

impl EthernetPacketBuilder {
    /// Create a new builder instance.
    pub fn new() -> Self {
        Self {
            packet: EthernetPacket {
                header: EthernetHeader {
                    destination: MacAddr::zero(),
                    source: MacAddr::zero(),
                    ethertype: EtherType::Ipv4,
                },
                payload: Bytes::new(),
            },
        }
    }

    /// Set the destination MAC address.
    pub fn destination(mut self, mac: MacAddr) -> Self {
        self.packet.header.destination = mac;
        self
    }

    /// Set the source MAC address.
    pub fn source(mut self, mac: MacAddr) -> Self {
        self.packet.header.source = mac;
        self
    }

    /// Set the EtherType (IPv4, ARP, IPv6, etc.).
    pub fn ethertype(mut self, ether_type: EtherType) -> Self {
        self.packet.header.ethertype = ether_type;
        self
    }

    /// Set the payload bytes.
    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    /// Consume the builder and produce an `EthernetPacket`.
    pub fn build(self) -> EthernetPacket {
        self.packet
    }

    /// Serialize the packet into raw bytes.
    pub fn to_bytes(self) -> Bytes {
        self.packet.to_bytes()
    }

    /// Retrieve only the header bytes.
    pub fn header_bytes(&self) -> Bytes {
        self.packet.header.to_bytes()
    }
}
