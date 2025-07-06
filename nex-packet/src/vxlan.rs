//! A VXLAN packet abstraction.
use bytes::{Buf, Bytes};
use nex_core::bitfield::{self, u24be};

use crate::packet::Packet;

/// Virtual eXtensible Local Area Network (VXLAN)
///
/// See [RFC 7348](https://datatracker.ietf.org/doc/html/rfc7348)
///
/// VXLAN Header:
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|R|R|R|I|R|R|R|            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                VXLAN Network Identifier (VNI) |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct Vxlan {
    pub flags: u8,
    pub reserved1: u24be,
    pub vni: u24be,
    pub reserved2: u8,
    pub payload: Bytes,
}

impl Packet for Vxlan {
    type Header = ();

    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let flags = bytes.get_u8();

        let reserved1 = {
            let b1 = bytes.get_u8();
            let b2 = bytes.get_u8();
            let b3 = bytes.get_u8();
            bitfield::utils::u24be_from_bytes([b1, b2, b3])
        };

        let vni = {
            let b1 = bytes.get_u8();
            let b2 = bytes.get_u8();
            let b3 = bytes.get_u8();
            bitfield::utils::u24be_from_bytes([b1, b2, b3])
        };

        let reserved2 = bytes.get_u8();

        let payload = Bytes::copy_from_slice(bytes);

        Some(Self {
            flags,
            reserved1,
            vni,
            reserved2,
            payload,
        })
    }

    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        use bytes::BufMut;
        let mut buf = bytes::BytesMut::with_capacity(8 + self.payload.len());

        buf.put_u8(self.flags);
        buf.put_slice(&bitfield::utils::u24be_to_bytes(self.reserved1));
        buf.put_slice(&bitfield::utils::u24be_to_bytes(self.vni));
        buf.put_u8(self.reserved2);
        buf.put_slice(&self.payload);

        buf.freeze()
    }
    fn header(&self) -> Bytes {
        use bytes::BufMut;
        let mut buf = bytes::BytesMut::with_capacity(8);

        buf.put_u8(self.flags);
        buf.put_slice(&self.reserved1.to_be_bytes());
        buf.put_slice(&self.vni.to_be_bytes());
        buf.put_u8(self.reserved2);

        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        8
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        ((), self.payload)
    }
}

#[test]
fn vxlan_packet_test() {
    let packet = Bytes::from_static(&[
        0x08, // I flag
        0x00, 0x00, 0x00, // Reserved
        0x12, 0x34, 0x56, // VNI
        0x00 // Reserved
    ]);
    let vxlan_packet = Vxlan::from_bytes(packet.clone()).unwrap();
    assert_eq!(vxlan_packet.to_bytes(), packet);
}
