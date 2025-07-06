//! Ethernet Flow Control \[IEEE 802.3x\] abstraction.
use core::fmt;

use bytes::{Buf, BufMut, Bytes};
use nex_core::bitfield::u16be;

use crate::packet::Packet;

/// Represents the opcode field in an Ethernet Flow Control packet.
/// 
/// Flow control opcodes are defined in IEEE 802.3x
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum FlowControlOpcode {
    Pause = 0x0001,
    Unknown(u16),
}

impl FlowControlOpcode {
    pub fn new(value: u16) -> Self {
        match value {
            0x0001 => FlowControlOpcode::Pause,
            other => FlowControlOpcode::Unknown(other),
        }
    }

    pub fn value(&self) -> u16 {
        match *self {
            FlowControlOpcode::Pause => 0x0001,
            FlowControlOpcode::Unknown(v) => v,
        }
    }
}

impl fmt::Display for FlowControlOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            FlowControlOpcode::Pause => "pause",
            FlowControlOpcode::Unknown(_) => "unknown",
        })
    }
}

/// Represents an Ethernet Flow Control packet defined by IEEE 802.3x.
/// 
/// [EtherTypes::FlowControl](crate::ethernet::EtherTypes::FlowControl) ethertype (0x8808).
pub struct FlowControlPacket {
    pub command: FlowControlOpcode,
    pub quanta: u16be,
    pub payload: Bytes,
}

impl Packet for FlowControlPacket {
    type Header = ();
    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }

        let command = FlowControlOpcode::new(bytes.get_u16());
        let quanta = bytes.get_u16();

        // Payload including padding; its contents are not specified by the standard
        let payload = Bytes::copy_from_slice(bytes);

        Some(Self {
            command,
            quanta: quanta.into(),
            payload,
        })
    }

    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::with_capacity(4 + self.payload.len());

        buf.put_u16(self.command.value());
        buf.put_u16(self.quanta.into());
        buf.put_slice(&self.payload);

        buf.freeze()
    }
    fn header(&self) -> Bytes {
        let mut buf = bytes::BytesMut::with_capacity(4);

        buf.put_u16(self.command.value());
        buf.put_u16(self.quanta.into());

        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        4
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flowcontrol_pause_test() {
        let packet = Bytes::from_static(&[
            0x00, 0x01,       // Opcode: Pause
            0x12, 0x34,       // Quanta: 0x1234
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // Padding ...
        ]);

        let fc_packet = FlowControlPacket::from_bytes(packet.clone()).unwrap();
        assert_eq!(fc_packet.command, FlowControlOpcode::Pause);
        assert_eq!(fc_packet.quanta, 0x1234);
        assert_eq!(fc_packet.to_bytes(), packet);
    }
}
