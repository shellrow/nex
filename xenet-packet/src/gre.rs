//! GRE Packet abstraction.

#[cfg(test)]
use crate::Packet;

use alloc::vec::Vec;

use xenet_macro::packet;
use xenet_macro_helper::types::*;

/// GRE (Generic Routing Encapsulation) Packet.
///
/// See RFCs 1701, 2784, 2890, 7676, 2637
#[packet]
pub struct Gre {
    pub checksum_present: u1,
    pub routing_present: u1,
    pub key_present: u1,
    pub sequence_present: u1,
    pub strict_source_route: u1,
    pub recursion_control: u3,
    pub zero_flags: u5,
    pub version: u3,
    pub protocol_type: u16be, // 0x800 for ipv4 [basically an ethertype
    #[length_fn = "gre_checksum_length"]
    pub checksum: Vec<U16BE>,
    #[length_fn = "gre_offset_length"]
    pub offset: Vec<U16BE>,
    #[length_fn = "gre_key_length"]
    pub key: Vec<U32BE>,
    #[length_fn = "gre_sequence_length"]
    pub sequence: Vec<U32BE>,
    #[length_fn = "gre_routing_length"]
    pub routing: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn gre_checksum_length(gre: &GrePacket) -> usize {
    (gre.get_checksum_present() | gre.get_routing_present()) as usize * 2
}

fn gre_offset_length(gre: &GrePacket) -> usize {
    (gre.get_checksum_present() | gre.get_routing_present()) as usize * 2
}

fn gre_key_length(gre: &GrePacket) -> usize {
    gre.get_key_present() as usize * 4
}

fn gre_sequence_length(gre: &GrePacket) -> usize {
    gre.get_sequence_present() as usize * 4
}

fn gre_routing_length(gre: &GrePacket) -> usize {
    if 0 == gre.get_routing_present() {
        0
    } else {
        panic!("Source routed GRE packets not supported")
    }
}

/// `u16be`, but we can't use that directly in a `Vec` :(
#[packet]
pub struct U16BE {
    number: u16be,
    #[length = "0"]
    #[payload]
    unused: Vec<u8>,
}

/// `u32be`, but we can't use that directly in a `Vec` :(
#[packet]
pub struct U32BE {
    number: u32be,
    #[length = "0"]
    #[payload]
    unused: Vec<u8>,
}

#[test]
fn gre_packet_test() {
    let mut packet = [0u8; 4];
    {
        let mut gre_packet = MutableGrePacket::new(&mut packet[..]).unwrap();
        gre_packet.set_protocol_type(0x0800);
        assert_eq!(gre_packet.payload().len(), 0);
    }

    let ref_packet = [
        0x00, /* no flags */
        0x00, /* no flags, version 0 */
        0x08, /* protocol 0x0800 */
        0x00,
    ];

    assert_eq!(&ref_packet[..], &packet[..]);
}

#[test]
fn gre_checksum_test() {
    let mut packet = [0u8; 8];
    {
        let mut gre_packet = MutableGrePacket::new(&mut packet[..]).unwrap();
        gre_packet.set_checksum_present(1);
        assert_eq!(gre_packet.payload().len(), 0);
        assert_eq!(gre_packet.get_checksum().len(), 1);
        assert_eq!(gre_packet.get_offset().len(), 1);
    }

    let ref_packet = [
        0x80, /* checksum on */
        0x00, /* no flags, version 0 */
        0x00, /* protocol 0x0000 */
        0x00, 0x00, /* 16 bits of checksum */
        0x00, 0x00, /* 16 bits of offset */
        0x00,
    ];

    assert_eq!(&ref_packet[..], &packet[..]);
}
