//! A VLAN (802.1Q) packet abstraction.
//!
use crate::{ethernet::EtherType, packet::Packet};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use nex_core::bitfield::{u1, u12be};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// VLAN Header length in bytes
pub const VLAN_HEADER_LEN: usize = 4;

/// Class of Service (IEEE 802.1p Priority Code Point)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClassOfService {
    // Background
    BK = 1,
    // Best Effort
    BE = 0,
    // Excellent Effort
    EE = 2,
    // Critical Applications
    CA = 3,
    // Video
    VI = 4,
    // Voice
    VO = 5,
    // Internetwork Control
    IC = 6,
    // Network Control
    NC = 7,
    /// Unknown Class of Service
    Unknown(u8),
}

impl ClassOfService {
    pub fn new(val: u8) -> Self {
        match val {
            0 => ClassOfService::BE,
            1 => ClassOfService::BK,
            2 => ClassOfService::EE,
            3 => ClassOfService::CA,
            4 => ClassOfService::VI,
            5 => ClassOfService::VO,
            6 => ClassOfService::IC,
            7 => ClassOfService::NC,
            other => ClassOfService::Unknown(other),
        }
    }

    pub fn value(&self) -> u8 {
        match *self {
            ClassOfService::BK => 1,
            ClassOfService::BE => 0,
            ClassOfService::EE => 2,
            ClassOfService::CA => 3,
            ClassOfService::VI => 4,
            ClassOfService::VO => 5,
            ClassOfService::IC => 6,
            ClassOfService::NC => 7,
            ClassOfService::Unknown(v) => v,
        }
    }
}

/// VLAN header structure
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VlanHeader {
    pub priority_code_point: ClassOfService,
    pub drop_eligible_id: u1,
    pub vlan_id: u12be,
    pub ethertype: EtherType,
}

/// VLAN packet
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlanPacket {
    pub header: VlanHeader,
    pub payload: Bytes,
}

impl Packet for VlanPacket {
    type Header = VlanHeader;

    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < VLAN_HEADER_LEN {
            return None;
        }

        // VLAN TCI
        let tci = bytes.get_u16();
        let raw_pcp = ((tci >> 13) & 0b111) as u8;
        println!("DEBUG: tci=0x{:04x}, raw_pcp={}", tci, raw_pcp);
        let pcp = ClassOfService::new(((tci >> 13) & 0b111) as u8);
        let drop_eligible_id = ((tci >> 12) & 0b1) as u1;
        let vlan_id = (tci & 0x0FFF) as u12be;

        // EtherType
        let ethertype = EtherType::new(bytes.get_u16());

        // Payload
        Some(VlanPacket {
            header: VlanHeader {
                priority_code_point: pcp,
                drop_eligible_id,
                vlan_id,
                ethertype,
            },
            payload: Bytes::copy_from_slice(bytes),
        })
    }
    fn from_bytes(mut bytes: Bytes) -> Option<Self> {
        Self::from_buf(&mut bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(VLAN_HEADER_LEN + self.payload.len());

        let pcp_bits = (self.header.priority_code_point.value() as u16 & 0b111) << 13;
        let dei_bits = (self.header.drop_eligible_id as u16 & 0b1) << 12;
        let vlan_bits = self.header.vlan_id as u16 & 0x0FFF;

        let tci = pcp_bits | dei_bits | vlan_bits;

        buf.put_u16(tci);
        buf.put_u16(self.header.ethertype.value());
        buf.extend_from_slice(&self.payload);

        buf.freeze()
    }

    fn header(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(VLAN_HEADER_LEN);

        let mut first = (self.header.priority_code_point.value() & 0b111) << 5;
        first |= (self.header.drop_eligible_id & 0b1) << 4;
        first |= ((self.header.vlan_id >> 8) & 0b0000_1111) as u8;

        let second = (self.header.vlan_id & 0xFF) as u8;

        buf.put_u8(first);
        buf.put_u8(second);
        buf.put_u16(self.header.ethertype.value());

        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        VLAN_HEADER_LEN
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_parse() {
        let raw = Bytes::from_static(&[
            0x20, 0x00, // TCI: pcp=1 (BK), dei=0, vid=0
            0x08, 0x00, // EtherType: IPv4
            b'x', b'y', b'z',
        ]);

        let packet = VlanPacket::from_bytes(raw.clone()).unwrap();

        assert_eq!(packet.header.priority_code_point, ClassOfService::BK);
        assert_eq!(packet.header.drop_eligible_id, 0);
        assert_eq!(packet.header.vlan_id, 0x000);
        assert_eq!(packet.header.ethertype, EtherType::Ipv4);
        assert_eq!(packet.payload, Bytes::from_static(b"xyz"));
        assert_eq!(packet.to_bytes(), raw);
    }
    #[test]
    fn test_vlan_parse_2() {
        let raw = Bytes::from_static(&[
            0x01, 0x00, // TCI: PCP=0(BE), DEI=0, VID=0x100
            0x08, 0x00, // EtherType: IPv4
            b'x', b'y', b'z',
        ]);

        let packet = VlanPacket::from_bytes(raw.clone()).unwrap();

        assert_eq!(packet.header.priority_code_point, ClassOfService::BE);
        assert_eq!(packet.header.drop_eligible_id, 0);
        assert_eq!(packet.header.vlan_id, 0x100);
        assert_eq!(packet.header.ethertype, EtherType::Ipv4);
        assert_eq!(packet.payload, Bytes::from_static(b"xyz"));
        assert_eq!(packet.to_bytes(), raw);
    }
}
