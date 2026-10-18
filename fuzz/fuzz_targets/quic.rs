#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::{
    packet::Packet,
    quic::{QuicDatagram, QuicPacket, QuicParseOptions, QuicVarInt},
};

fuzz_target!(|data: &[u8]| {
    let _ = QuicPacket::try_from_buf(data);
    let _ = QuicVarInt::decode(data);
    let options = QuicParseOptions {
        short_header_dcid_len: Some(data.first().copied().unwrap_or(0) as usize % 22),
        allow_greased_fixed_bit: true,
    };
    let mut consumed = 0;
    for packet in QuicDatagram::new(data, options).flatten() {
        let owned = packet.to_owned();
        assert_eq!(owned.to_bytes().as_ref(), packet.packet());
        assert_eq!(
            packet.header().len() + packet.payload().len(),
            packet.packet().len()
        );
        consumed += packet.packet().len();
        assert!(consumed <= data.len());
    }
});
