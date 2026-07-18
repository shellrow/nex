#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::ipv6::Ipv6Packet;
use nex_packet::packet::Packet;
use nex_packet::parse::ParseMode;

fuzz_target!(|data: &[u8]| {
    let _ = Ipv6Packet::from_buf(data);
    let _ = Ipv6Packet::try_from_buf(data);
    let _ = Ipv6Packet::try_from_buf_with_mode(data, ParseMode::Strict);
});
