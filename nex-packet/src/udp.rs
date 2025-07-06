//! A UDP packet abstraction.

use crate::ip::IpNextProtocol;
use crate::packet::Packet;

use crate::util;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use nex_core::bitfield::u16be;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// UDP Header Length
pub const UDP_HEADER_LEN: usize = 8;

/// Represents the UDP header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UdpHeader {
    pub source: u16be,
    pub destination: u16be,
    pub length: u16be,
    pub checksum: u16be,
}

/// Represents a UDP Packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpPacket {
    pub header: UdpHeader,
    pub payload: Bytes,
}

impl Packet for UdpPacket {
    type Header = UdpHeader;
    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < UDP_HEADER_LEN {
            return None;
        }

        let source = bytes.get_u16();
        let destination = bytes.get_u16();
        let length = bytes.get_u16();
        let checksum = bytes.get_u16();

        if length < UDP_HEADER_LEN as u16 {
            return None;
        }

        let payload_len = length as usize - UDP_HEADER_LEN;
        if bytes.len() < payload_len {
            return None;
        }

        let (payload_slice, _) = bytes.split_at(payload_len);

        Some(UdpPacket {
            header: UdpHeader {
                source,
                destination,
                length,
                checksum,
            },
            payload: Bytes::copy_from_slice(payload_slice),
        })
    }
    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)
    }
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(UDP_HEADER_LEN + self.payload.len());
        buf.put_u16(self.header.source);
        buf.put_u16(self.header.destination);
        buf.put_u16((UDP_HEADER_LEN + self.payload.len()) as u16);
        buf.put_u16(self.header.checksum);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }
    fn header(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(UDP_HEADER_LEN);
        buf.put_u16(self.header.source);
        buf.put_u16(self.header.destination);
        buf.put_u16(self.header.length);
        buf.put_u16(self.header.checksum);
        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        UDP_HEADER_LEN
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        (self.header, self.payload)
    }
}

pub fn checksum(packet: &UdpPacket, source: &IpAddr, destination: &IpAddr) -> u16 {
    match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => ipv4_checksum(packet, src, dst),
        (IpAddr::V6(src), IpAddr::V6(dst)) => ipv6_checksum(packet, src, dst),
        _ => 0, // Unsupported IP version
    }
}

/// Calculate a checksum for a packet built on IPv4.
pub fn ipv4_checksum(packet: &UdpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16be {
    ipv4_checksum_adv(packet, &[], source, destination)
}

/// Calculate a checksum for a packet built on IPv4. Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv4_checksum_adv(
    packet: &UdpPacket,
    extra_data: &[u8],
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
) -> u16be {
    util::ipv4_checksum(
        packet.to_bytes().as_ref(),
        3,
        extra_data,
        source,
        destination,
        IpNextProtocol::Udp,
    )
}

/// Calculate a checksum for a packet built on IPv6.
pub fn ipv6_checksum(packet: &UdpPacket, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16be {
    ipv6_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv6. Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv6_checksum_adv(
    packet: &UdpPacket,
    extra_data: &[u8],
    source: &Ipv6Addr,
    destination: &Ipv6Addr,
) -> u16be {
    util::ipv6_checksum(
        packet.to_bytes().as_ref(),
        3,
        extra_data,
        source,
        destination,
        IpNextProtocol::Udp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_basic_udp_parse() {
        let raw = Bytes::from_static(&[
            0x12, 0x34, // source
            0xab, 0xcd, // destination
            0x00, 0x0c, // length = 12 bytes (8 header + 4 payload)
            0x55, 0xaa, // checksum
            b'd', b'a', b't', b'a', // payload
        ]);
        let packet = UdpPacket::from_bytes(raw.clone()).expect("Failed to parse UDP packet");

        assert_eq!(packet.header.source, 0x1234);
        assert_eq!(packet.header.destination, 0xabcd);
        assert_eq!(packet.header.length, 12);
        assert_eq!(packet.header.checksum, 0x55aa);
        assert_eq!(packet.payload, Bytes::from_static(b"data"));
        assert_eq!(packet.to_bytes(), raw);
    }
    #[test]
    fn test_basic_udp_create() {
        let payload = Bytes::from_static(b"data");
        let packet = UdpPacket {
            header: UdpHeader {
                source: 0x1234,
                destination: 0xabcd,
                length: (UDP_HEADER_LEN + payload.len()) as u16,
                checksum: 0x55aa,
            },
            payload: payload.clone(),
        };

        let expected = Bytes::from_static(&[
            0x12, 0x34, // source
            0xab, 0xcd, // destination
            0x00, 0x0c, // length
            0x55, 0xaa, // checksum
            b'd', b'a', b't', b'a', // payload
        ]);

        assert_eq!(packet.to_bytes(), expected);
        assert_eq!(packet.payload(), payload);
        assert_eq!(packet.header_len(), UDP_HEADER_LEN);
    }
}
