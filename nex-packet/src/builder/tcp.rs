use std::net::IpAddr;

use crate::packet::Packet;
use crate::tcp::{TcpHeader, TcpOptionPacket, TcpPacket};
use bytes::Bytes;

/// Builder for constructing TCP packets
#[derive(Debug, Clone)]
pub struct TcpPacketBuilder {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    packet: TcpPacket,
}

impl TcpPacketBuilder {
    /// Create a new builder
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        Self {
            src_ip,
            dst_ip,
            packet: TcpPacket {
                header: TcpHeader {
                    source: 0,
                    destination: 0,
                    sequence: 0,
                    acknowledgement: 0,
                    data_offset: 5.into(), // default: header 20 bytes (5 * 4)
                    reserved: 0.into(),
                    flags: 0,
                    window: 0xffff,
                    checksum: 0,
                    urgent_ptr: 0,
                    options: Vec::new(),
                },
                payload: Bytes::new(),
            },
        }
    }

    pub fn source(mut self, port: u16) -> Self {
        self.packet.header.source = port.into();
        self
    }

    pub fn destination(mut self, port: u16) -> Self {
        self.packet.header.destination = port.into();
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.packet.header.sequence = seq.into();
        self
    }

    pub fn acknowledgement(mut self, ack: u32) -> Self {
        self.packet.header.acknowledgement = ack.into();
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.packet.header.flags = flags;
        self
    }

    pub fn window(mut self, size: u16) -> Self {
        self.packet.header.window = size.into();
        self
    }

    pub fn urgent_ptr(mut self, ptr: u16) -> Self {
        self.packet.header.urgent_ptr = ptr.into();
        self
    }

    pub fn options(mut self, options: Vec<TcpOptionPacket>) -> Self {
        self.packet.header.options = options;
        // Recalculate data offset (header length is in 4-byte units)
        let base_len = 20; // base header
        let opt_len: usize = self
            .packet
            .header
            .options
            .iter()
            .map(|opt| opt.length() as usize)
            .sum();
        let total = base_len + opt_len;
        self.packet.header.data_offset = ((total + 3) / 4) as u8; // round up
        self
    }

    pub fn payload(mut self, data: Bytes) -> Self {
        self.packet.payload = data;
        self
    }

    /// Calculate the checksum and set it in the header
    pub fn calculate_checksum(mut self) -> Self {
        self.packet.header.checksum =
            crate::tcp::checksum(&self.packet, &self.src_ip, &self.dst_ip);
        self
    }
    /// Build the packet with checksum computed
    pub fn build(mut self) -> TcpPacket {
        self.packet.header.checksum =
            crate::tcp::checksum(&self.packet, &self.src_ip, &self.dst_ip);
        self.packet
    }
    /// Serialize the packet into bytes with checksum computed
    pub fn to_bytes(self) -> Bytes {
        self.build().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::tcp::TcpFlags;
    use bytes::Bytes;

    #[test]
    fn tcp_builder_basic() {
        let pkt = TcpPacketBuilder::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .source(1234)
        .destination(80)
        .sequence(1)
        .acknowledgement(2)
        .flags(TcpFlags::SYN)
        .window(1024)
        .urgent_ptr(0)
        .payload(Bytes::from_static(b"abc"))
        .build();
        assert_eq!(pkt.header.source, 1234);
        assert_eq!(pkt.header.destination, 80);
        assert_eq!(pkt.header.sequence, 1);
        assert_eq!(pkt.header.acknowledgement, 2);
        assert_eq!(pkt.header.flags, TcpFlags::SYN);
        assert_eq!(pkt.payload, Bytes::from_static(b"abc"));
    }
}
