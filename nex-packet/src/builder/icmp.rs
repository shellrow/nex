use std::net::Ipv4Addr;

use crate::{
    icmp::{self, checksum, IcmpCode, IcmpHeader, IcmpPacket, IcmpType},
    packet::Packet,
};
use bytes::{BufMut, Bytes, BytesMut};

/// Builder for constructing ICMP packets
#[derive(Debug, Clone)]
pub struct IcmpPacketBuilder {
    #[allow(unused)]
    source: Ipv4Addr,
    #[allow(unused)]
    destination: Ipv4Addr,
    packet: IcmpPacket,
}

impl IcmpPacketBuilder {
    /// Create a new builder with an initial ICMP Type and Code
    pub fn new(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        let header = IcmpHeader {
            icmp_type: IcmpType::EchoRequest,
            icmp_code: icmp::echo_request::IcmpCodes::NoCode,
            checksum: 0,
        };
        Self {
            source,
            destination,
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

    pub fn calculate_checksum(mut self) -> Self {
        // Calculate the checksum and set it in the header
        self.packet.header.checksum = checksum(&self.packet);
        self
    }

    /// Return an `IcmpPacket` with checksum computed
    pub fn build(mut self) -> IcmpPacket {
        self.packet.header.checksum = checksum(&self.packet);
        self.packet
    }

    /// Return the packet bytes with checksum computed
    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }

    /// Access the intermediate `IcmpPacket` if needed
    pub fn packet(&self) -> &IcmpPacket {
        &self.packet
    }
}
