#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::{ipv4::Ipv4Packet, parse::ParseMode};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = Ipv4Packet::try_from_buf(data);
    let _ = Ipv4Packet::try_from_buf_with_mode(data, ParseMode::Strict);
});
