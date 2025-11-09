//! GRE Packet abstraction.

use crate::packet::{GenericMutablePacket, Packet};
use bytes::{Buf, Bytes};
use nex_core::bitfield::{u1, u16be, u3, u32be, u5};

/// GRE (Generic Routing Encapsulation) Packet.
///
/// See RFCs 1701, 2784, 2890, 7676, 2637
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrePacket {
    pub checksum_present: u1,
    pub routing_present: u1,
    pub key_present: u1,
    pub sequence_present: u1,
    pub strict_source_route: u1,
    pub recursion_control: u3,
    pub zero_flags: u5,
    pub version: u3,
    pub protocol_type: u16be, // 0x800 for IPv4
    pub checksum: Vec<u16be>,
    pub offset: Vec<u16be>,
    pub key: Vec<u32be>,
    pub sequence: Vec<u32be>,
    pub routing: Vec<u8>,
    pub payload: Bytes,
}

impl Packet for GrePacket {
    type Header = ();

    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.remaining() < 4 {
            return None;
        }

        let flags = bytes.get_u16();
        let protocol_type = bytes.get_u16();

        let checksum_present = ((flags >> 15) & 0x1) as u1;
        let routing_present = ((flags >> 14) & 0x1) as u1;
        let key_present = ((flags >> 13) & 0x1) as u1;
        let sequence_present = ((flags >> 12) & 0x1) as u1;
        let strict_source_route = ((flags >> 11) & 0x1) as u1;
        let recursion_control = ((flags >> 8) & 0x7) as u3;
        let zero_flags = ((flags >> 3) & 0x1f) as u5;
        let version = (flags & 0x7) as u3;

        // Retrieve optional fields in order
        let mut checksum = Vec::new();
        let mut offset = Vec::new();
        let mut key = Vec::new();
        let mut sequence = Vec::new();
        let routing = Vec::new();

        if checksum_present != 0 || routing_present != 0 {
            if bytes.remaining() < 4 {
                return None;
            }
            checksum.push(bytes.get_u16());
            offset.push(bytes.get_u16());
        }

        if key_present != 0 {
            if bytes.remaining() < 4 {
                return None;
            }
            key.push(bytes.get_u32());
        }

        if sequence_present != 0 {
            if bytes.remaining() < 4 {
                return None;
            }
            sequence.push(bytes.get_u32());
        }

        if routing_present != 0 {
            // Not implemented for this crate
            panic!("Source routed GRE packets not supported");
        }

        let payload = Bytes::copy_from_slice(bytes);

        Some(Self {
            checksum_present,
            routing_present,
            key_present,
            sequence_present,
            strict_source_route,
            recursion_control,
            zero_flags,
            version,
            protocol_type: protocol_type.into(),
            checksum,
            offset,
            key,
            sequence,
            routing,
            payload,
        })
    }

    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::with_capacity(self.header_len());

        // Build the flags field
        let mut flags: u16 = 0;
        flags |= (self.checksum_present as u16) << 15;
        flags |= (self.routing_present as u16) << 14;
        flags |= (self.key_present as u16) << 13;
        flags |= (self.sequence_present as u16) << 12;
        flags |= (self.strict_source_route as u16) << 11;
        flags |= (self.recursion_control as u16) << 8;
        flags |= (self.zero_flags as u16) << 3;
        flags |= self.version as u16;

        buf.put_u16(flags);
        buf.put_u16(self.protocol_type.into());

        if self.checksum_present != 0 || self.routing_present != 0 {
            for c in &self.checksum {
                buf.put_u16(*c);
            }
            for o in &self.offset {
                buf.put_u16(*o);
            }
        }

        if self.key_present != 0 {
            for k in &self.key {
                buf.put_u32(*k);
            }
        }

        if self.sequence_present != 0 {
            for s in &self.sequence {
                buf.put_u32(*s);
            }
        }

        // Panic if routing_present is set (not supported by this implementation)
        if self.routing_present != 0 {
            panic!("to_bytes does not support source routed GRE packets");
        }

        buf.put_slice(&self.payload);

        buf.freeze()
    }
    fn header(&self) -> Bytes {
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::with_capacity(self.header_len());

        // Build the flags field
        let mut flags: u16 = 0;
        flags |= (self.checksum_present as u16) << 15;
        flags |= (self.routing_present as u16) << 14;
        flags |= (self.key_present as u16) << 13;
        flags |= (self.sequence_present as u16) << 12;
        flags |= (self.strict_source_route as u16) << 11;
        flags |= (self.recursion_control as u16) << 8;
        flags |= (self.zero_flags as u16) << 3;
        flags |= self.version as u16;

        buf.put_u16(flags);
        buf.put_u16(self.protocol_type.into());

        if self.checksum_present != 0 || self.routing_present != 0 {
            for c in &self.checksum {
                buf.put_u16(*c);
            }
            for o in &self.offset {
                buf.put_u16(*o);
            }
        }

        if self.key_present != 0 {
            for k in &self.key {
                buf.put_u32(*k);
            }
        }

        if self.sequence_present != 0 {
            for s in &self.sequence {
                buf.put_u32(*s);
            }
        }

        // Panic if routing_present is set (not supported by this implementation)
        if self.routing_present != 0 {
            panic!("header does not support source routed GRE packets");
        }

        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        4 // base header: 2 bytes flags + 2 bytes protocol_type
            + self.checksum_length()
            + self.offset_length()
            + self.key_length()
            + self.sequence_length()
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        ((), self.to_bytes())
    }
}

impl GrePacket {
    pub fn checksum_length(&self) -> usize {
        (self.checksum_present | self.routing_present) as usize * 2
    }

    pub fn offset_length(&self) -> usize {
        (self.checksum_present | self.routing_present) as usize * 2
    }

    pub fn key_length(&self) -> usize {
        self.key_present as usize * 4
    }

    pub fn sequence_length(&self) -> usize {
        self.sequence_present as usize * 4
    }

    pub fn routing_length(&self) -> usize {
        if 0 == self.routing_present {
            0
        } else {
            panic!("Source routed GRE packets not supported")
        }
    }
}

/// Represents a mutable GRE packet.
pub type MutableGrePacket<'a> = GenericMutablePacket<'a, GrePacket>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MutablePacket;

    #[test]
    fn gre_packet_test() {
        let packet = Bytes::from_static(&[
            0x00, /* no flags */
            0x00, /* no flags, version 0 */
            0x08, /* protocol 0x0800 */
            0x00,
        ]);

        let gre_packet = GrePacket::from_buf(&mut packet.clone()).unwrap();

        assert_eq!(&gre_packet.to_bytes(), &packet);
    }

    #[test]
    fn gre_checksum_test() {
        let packet = Bytes::from_static(&[
            0x80, /* checksum on */
            0x00, /* no flags, version 0 */
            0x00, /* protocol 0x0000 */
            0x00, 0x00, /* 16 bits of checksum */
            0x00, 0x00, /* 16 bits of offset */
            0x00,
        ]);

        let gre_packet = GrePacket::from_buf(&mut packet.clone()).unwrap();

        assert_eq!(&gre_packet.to_bytes(), &packet);
    }

    #[test]
    fn test_mutable_gre_packet_alias() {
        let mut raw = [
            0x00, 0x00, // flags
            0x08, 0x00, // protocol type
            0xaa, 0xbb,
        ];

        let mut packet = <MutableGrePacket as MutablePacket>::new(&mut raw).expect("mutable gre");
        packet.header_mut()[2] = 0x86;
        packet.header_mut()[3] = 0xdd; // IPv6 protocol
        packet.payload_mut()[0] = 0xff;

        let frozen = packet.freeze().expect("freeze");
        assert_eq!(frozen.protocol_type, 0x86dd);
        assert_eq!(frozen.payload[0], 0xff);
    }
}
