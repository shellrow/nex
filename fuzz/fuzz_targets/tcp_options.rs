#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nex_packet::packet::Packet;
use nex_packet::tcp::TcpPacket;

fuzz_target!(|data: &[u8]| {
    let _ = TcpPacket::from_buf(data);
    let _ = TcpPacket::try_from_buf(data);
    let _ = TcpPacket::try_from_bytes(Bytes::copy_from_slice(data));
});
