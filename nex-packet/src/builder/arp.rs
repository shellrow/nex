use bytes::Bytes;
use crate::{
    ethernet::EtherType,
    packet::Packet,
    arp::{ArpHeader, ArpPacket, ArpHardwareType, ArpOperation},
};
use nex_core::mac::MacAddr;
use std::net::Ipv4Addr;

/// Builder for constructing ARP packets
#[derive(Debug, Clone)]
pub struct ArpPacketBuilder {
    packet: ArpPacket,
}

impl ArpPacketBuilder {
    /// Create a new builder
    pub fn new(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        let header = ArpHeader {
            hardware_type: ArpHardwareType::Ethernet,
            protocol_type: EtherType::Ipv4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ArpOperation::Request,
            sender_hw_addr: sender_mac,
            sender_proto_addr: sender_ip,
            target_hw_addr: MacAddr::zero(),
            target_proto_addr: target_ip,
        };
        Self {
            packet: ArpPacket {
                header,
                payload: Bytes::new(),
            },
        }
    }

    pub fn hardware_type(mut self, hw_type: ArpHardwareType) -> Self {
        self.packet.header.hardware_type = hw_type;
        self
    }

    pub fn protocol_type(mut self, proto_type: EtherType) -> Self {
        self.packet.header.protocol_type = proto_type;
        self
    }

    /// Set the length of the sender MAC address
    pub fn sender_hw_addr_len(mut self, len: u8) -> Self {
        self.packet.header.hw_addr_len = len;
        self
    }

    /// Set the length of the sender IP address
    pub fn sender_proto_addr_len(mut self, len: u8) -> Self {
        self.packet.header.proto_addr_len = len;
        self
    }

    /// Set the sender MAC address
    pub fn sender_mac(mut self, mac: MacAddr) -> Self {
        self.packet.header.sender_hw_addr = mac;
        self
    }

    /// Set the sender IP address
    pub fn sender_ip(mut self, ip: Ipv4Addr) -> Self {
        self.packet.header.sender_proto_addr = ip;
        self
    }

    /// Set the target MAC address
    pub fn target_mac(mut self, mac: MacAddr) -> Self {
        self.packet.header.target_hw_addr = mac;
        self
    }

    /// Set the target IP address
    pub fn target_ip(mut self, ip: Ipv4Addr) -> Self {
        self.packet.header.target_proto_addr = ip;
        self
    }

    /// Set the ARP operation
    pub fn operation(mut self, operation: ArpOperation) -> Self {
        self.packet.header.operation = operation;
        self
    }

    /// Set an optional payload
    pub fn payload(mut self, payload: Bytes) -> Self {
        self.packet.payload = payload;
        self
    }

    /// Return the finished `ArpPacket`
    pub fn build(self) -> ArpPacket {
        self.packet
    }

    /// Return the serialized bytes
    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }

    /// Return a reference to the internal `ArpPacket`
    pub fn packet(&self) -> &ArpPacket {
        &self.packet
    }
}
