#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::dns::{DnsName, DnsPacket};

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    let _ = DnsPacket::try_from_buf(data);
    let _ = DnsName::try_from_bytes(data);
});
