use std::net::Ipv6Addr;

use bytes::{Bytes, BytesMut, BufMut};
use crate::{
    icmpv6::{self, checksum, Icmpv6Code, Icmpv6Header, Icmpv6Packet, Icmpv6Type},
    packet::Packet,
};

/// Builder for constructing ICMPv6 packets
#[derive(Debug, Clone)]
pub struct Icmpv6PacketBuilder {
    source: Ipv6Addr, 
    destination: Ipv6Addr,
    packet: Icmpv6Packet,
}

impl Icmpv6PacketBuilder {
    /// Create a new builder with an initial ICMPv6 Type and Code
    pub fn new(source: Ipv6Addr, destination: Ipv6Addr) -> Self {
        let header = Icmpv6Header {
            icmpv6_type: Icmpv6Type::EchoRequest,
            icmpv6_code: icmpv6::echo_request::Icmpv6Codes::NoCode,
            checksum: 0,
        };
        Self {
            source,
            destination,
            packet: Icmpv6Packet {
                header,
                payload: Bytes::new(),
            },
        }
    }

    pub fn icmpv6_type(mut self, icmpv6_type: Icmpv6Type) -> Self {
        self.packet.header.icmpv6_type = icmpv6_type;
        self
    }

    pub fn icmpv6_code(mut self, icmpv6_code: Icmpv6Code) -> Self {
        self.packet.header.icmpv6_code = icmpv6_code;
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

    pub fn culculate_checksum(mut self) -> Self {
        // Calculate the checksum and set it in the header
        self.packet.header.checksum = checksum(&self.packet, &self.source, &self.destination);
        self
    }

    /// Return an `Icmpv6Packet` with checksum computed
    pub fn build(mut self) -> Icmpv6Packet {
        self.packet.header.checksum = checksum(&self.packet, &self.source, &self.destination);
        self.packet
    }

    /// Return the packet bytes with checksum computed
    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }

    /// Access the intermediate `Icmpv6Packet` if needed
    pub fn packet(&self) -> &Icmpv6Packet {
        &self.packet
    }
}
