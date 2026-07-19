#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::{gre::GrePacket, packet::Packet};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = GrePacket::try_from_buf(data);
});
