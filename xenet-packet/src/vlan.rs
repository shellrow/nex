//! A VLAN packet abstraction.

use crate::ethernet::EtherType;
use crate::PrimitiveValues;

use alloc::vec::Vec;

use xenet_macro::packet;
use xenet_macro_helper::types::*;

/// Represents an IEEE 802.1p class of a service.
/// <https://en.wikipedia.org/wiki/IEEE_P802.1p>
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassOfService {
    /// Background
    BK = 1,
    /// Best Effort
    BE = 0,
    /// Excellent Effort
    EE = 2,
    /// Critical Applications
    CA = 3,
    /// Video, < 100 ms latency
    VI = 4,
    /// Voice, < 10 ms latency
    VO = 5,
    /// Internetwork Control
    IC = 6,
    /// Network Control
    NC = 7,
    /// Unknown class of service
    Unknown(u3),
}

impl ClassOfService {
    /// Constructs a new ClassOfServiceEnum from u3.
    pub fn new(value: u3) -> ClassOfService {
        match value {
            1 => ClassOfService::BK,
            0 => ClassOfService::BE,
            2 => ClassOfService::EE,
            3 => ClassOfService::CA,
            4 => ClassOfService::VI,
            5 => ClassOfService::VO,
            6 => ClassOfService::IC,
            7 => ClassOfService::NC,
            _ => ClassOfService::Unknown(value),
        }
    }
}

impl PrimitiveValues for ClassOfService {
    type T = (u3,);
    fn to_primitive_values(&self) -> (u3,) {
        match *self {
            ClassOfService::BK => (1,),
            ClassOfService::BE => (0,),
            ClassOfService::EE => (2,),
            ClassOfService::CA => (3,),
            ClassOfService::VI => (4,),
            ClassOfService::VO => (5,),
            ClassOfService::IC => (6,),
            ClassOfService::NC => (7,),
            ClassOfService::Unknown(n) => (n,),
        }
    }
}

/// Represents a VLAN-tagged packet.
#[packet]
pub struct Vlan {
    #[construct_with(u3)]
    pub priority_code_point: ClassOfService,
    pub drop_eligible_indicator: u1,
    pub vlan_identifier: u12be,
    #[construct_with(u16be)]
    pub ethertype: EtherType,
    #[payload]
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::EtherType;

    #[test]
    fn vlan_packet_test() {
        let mut packet = [0u8; 4];
        {
            let mut vlan_header = MutableVlanPacket::new(&mut packet[..]).unwrap();
            vlan_header.set_priority_code_point(ClassOfService::BE);
            assert_eq!(vlan_header.get_priority_code_point(), ClassOfService::BE);

            vlan_header.set_drop_eligible_indicator(0);
            assert_eq!(vlan_header.get_drop_eligible_indicator(), 0);

            vlan_header.set_ethertype(EtherType::Ipv4);
            assert_eq!(vlan_header.get_ethertype(), EtherType::Ipv4);

            vlan_header.set_vlan_identifier(0x100);
            assert_eq!(vlan_header.get_vlan_identifier(), 0x100);
        }

        let ref_packet = [
            0x01, // PCP, DEI, and first nibble of VID
            0x00, // Remainder of VID
            0x08, // First byte of ethertype
            0x00,
        ]; // Second byte of ethertype
        assert_eq!(&ref_packet[..], &packet[..]);
    }
}
