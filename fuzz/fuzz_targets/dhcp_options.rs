#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::{dhcp::DhcpPacket, packet::Packet};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = DhcpPacket::try_from_buf(data);
});
