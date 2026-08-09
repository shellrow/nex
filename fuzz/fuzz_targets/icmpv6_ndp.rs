#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::{icmpv6::Icmpv6Packet, packet::Packet};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = Icmpv6Packet::try_from_buf(data);
});
