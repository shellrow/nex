use std::net::Ipv4Addr;

use bytes::Bytes;
use nex_core::mac::MacAddr;

use crate::{dhcp::{DhcpHardwareType, DhcpHeader, DhcpOperation, DhcpPacket}, packet::Packet};

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

    /// Build and return a `DhcpPacket`
    pub fn build(self) -> DhcpPacket {
        self.packet
    }

    /// Build and return the packet bytes
    pub fn to_bytes(self) -> Bytes {
        self.packet.to_bytes()
    }

    /// Get a reference to the packet
    pub fn packet(&self) -> &DhcpPacket {
        &self.packet
    }
}
