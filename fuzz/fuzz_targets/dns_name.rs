#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::dns::DnsName;

fuzz_target!(|data: &[u8]| {
    let _ = DnsName::from_bytes(data);
    let _ = DnsName::try_from_bytes(data);
});
