#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use nex_packet::dns::DnsPacket;
use nex_packet::packet::Packet;

fuzz_target!(|data: &[u8]| {
    let data = support::decode_seed(data);
    let data = data.as_ref();
    if let Ok(packet) = DnsPacket::try_from_buf(data) {
        assert_eq!(packet.to_bytes().as_ref(), data);
    }
});
