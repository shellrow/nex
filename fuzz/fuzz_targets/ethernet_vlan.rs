#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::{ethernet::EthernetPacket, packet::Packet, vlan::VlanPacket};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = EthernetPacket::try_from_buf(data);
    let _ = VlanPacket::try_from_buf(data);
});
