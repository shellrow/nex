use std::net::IpAddr;

use crate::builder::BuildError;
use crate::packet::Packet;
use crate::tcp::{TCP_HEADER_LEN, TcpHeader, TcpOptionPacket, TcpPacket};
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
                    data_offset: 5, // default: header 20 bytes (5 * 4)
                    reserved: 0,
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
        self.packet.header.source = port;
        self
    }

    pub fn destination(mut self, port: u16) -> Self {
        self.packet.header.destination = port;
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.packet.header.sequence = seq;
        self
    }

    pub fn acknowledgement(mut self, ack: u32) -> Self {
        self.packet.header.acknowledgement = ack;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.packet.header.flags = flags;
        self
    }

    pub fn window(mut self, size: u16) -> Self {
        self.packet.header.window = size;
        self
    }

    pub fn urgent_ptr(mut self, ptr: u16) -> Self {
        self.packet.header.urgent_ptr = ptr;
        self
    }

    pub fn options(mut self, options: Vec<TcpOptionPacket>) -> Self {
        self.packet.header.options = options;
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
    pub fn build(mut self) -> Result<TcpPacket, BuildError> {
        let maximum_segment_length = match (self.src_ip, self.dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => u16::MAX as usize - 20,
            (IpAddr::V6(_), IpAddr::V6(_)) => u16::MAX as usize,
            _ => {
                return Err(BuildError::AddressFamilyMismatch { context: "TCP" });
            }
        };

        let mut options_length = 0usize;
        for option in &self.packet.header.options {
            let encoded_length = option.encoded_len();
            if encoded_length > u8::MAX as usize {
                return Err(BuildError::LengthOverflow {
                    context: "TCP option",
                    maximum: u8::MAX as usize,
                    actual: encoded_length,
                });
            }
            if encoded_length > 1 && option.declared_len().map(usize::from) != Some(encoded_length)
            {
                return Err(BuildError::InvalidFieldLength {
                    context: "TCP option length",
                    expected: encoded_length,
                    actual: option.declared_len().map(usize::from).unwrap_or(0),
                });
            }
            options_length =
                options_length
                    .checked_add(encoded_length)
                    .ok_or(BuildError::LengthOverflow {
                        context: "TCP options",
                        maximum: 40,
                        actual: usize::MAX,
                    })?;
        }

        let padded_options_length = options_length.div_ceil(4) * 4;
        if padded_options_length > 40 {
            return Err(BuildError::LengthOverflow {
                context: "TCP options",
                maximum: 40,
                actual: padded_options_length,
            });
        }

        let segment_length = TCP_HEADER_LEN
            .checked_add(padded_options_length)
            .and_then(|header_length| header_length.checked_add(self.packet.payload.len()))
            .ok_or(BuildError::LengthOverflow {
                context: "TCP segment",
                maximum: maximum_segment_length,
                actual: usize::MAX,
            })?;
        if segment_length > maximum_segment_length {
            return Err(BuildError::LengthOverflow {
                context: "TCP segment",
                maximum: maximum_segment_length,
                actual: segment_length,
            });
        }

        self.packet.header.data_offset = ((TCP_HEADER_LEN + padded_options_length) / 4) as u8;
        self.packet.header.checksum =
            crate::tcp::checksum(&self.packet, &self.src_ip, &self.dst_ip);
        Ok(self.packet)
    }
    /// Serialize the packet into bytes with checksum computed
    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|packet| packet.to_bytes())
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
        .build()
        .expect("valid TCP packet");
        assert_eq!(pkt.header.source, 1234);
        assert_eq!(pkt.header.destination, 80);
        assert_eq!(pkt.header.sequence, 1);
        assert_eq!(pkt.header.acknowledgement, 2);
        assert_eq!(pkt.header.flags, TcpFlags::SYN);
        assert_eq!(pkt.payload, Bytes::from_static(b"abc"));
    }

    #[test]
    fn tcp_builder_rejects_address_family_mismatch() {
        let error = TcpPacketBuilder::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        )
        .build()
        .expect_err("mismatched checksum context");

        assert_eq!(error, BuildError::AddressFamilyMismatch { context: "TCP" });
    }

    #[test]
    fn tcp_builder_rejects_oversized_options() {
        let options = vec![TcpOptionPacket::timestamp(0, 0); 5];
        let error = TcpPacketBuilder::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .options(options)
        .build()
        .expect_err("TCP data offset overflow");

        assert!(matches!(
            error,
            BuildError::LengthOverflow {
                context: "TCP options",
                ..
            }
        ));
    }
}
