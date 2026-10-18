use bytes::Bytes;
use nex_packet::{
    builder::quic::QuicPacketBuilder as Builder,
    packet::Packet,
    quic::{
        QUIC_VERSION_1, QUIC_VERSION_2, QuicDatagram, QuicPacket, QuicPacketSlice,
        QuicPacketType as Kind, QuicParseOptions, QuicVarInt, QuicVersion,
    },
};
use proptest::prelude::*;

fn hex(input: &str) -> Vec<u8> {
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    s.as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn body() -> Bytes {
    Bytes::from_static(&[0xab; 20])
}
fn short_options(len: usize) -> QuicParseOptions {
    QuicParseOptions {
        short_header_dcid_len: Some(len),
        ..Default::default()
    }
}

#[test]
fn rfc_initial_vectors_and_every_truncated_prefix() {
    for (version, client, server) in [
        (
            QUIC_VERSION_1,
            include_str!("fixtures/quic/rfc9001_client_initial.hex"),
            include_str!("fixtures/quic/rfc9001_server_initial.hex"),
        ),
        (
            QUIC_VERSION_2,
            include_str!("fixtures/quic/rfc9369_client_initial.hex"),
            include_str!("fixtures/quic/rfc9369_server_initial.hex"),
        ),
    ] {
        for (is_client, encoded) in [(true, client), (false, server)] {
            let raw = hex(encoded);
            let packet = QuicPacketSlice::try_from_buf(&raw).unwrap();
            assert_eq!(packet.packet_type(), Kind::Initial);
            assert_eq!(packet.version(), Some(version));
            assert_eq!(packet.token(), Some(&[][..]));
            assert_eq!(
                packet.declared_length(),
                Some(if is_client { 1182 } else { 117 })
            );
            assert_eq!(
                packet.destination_connection_id(),
                if is_client {
                    hex("8394c8f03e515708")
                } else {
                    vec![]
                }
            );
            assert_eq!(
                packet.source_connection_id().unwrap(),
                if is_client {
                    vec![]
                } else {
                    hex("f067a5502a4262b5")
                }
            );
            assert_eq!(packet.packet().len(), raw.len());
            if is_client {
                assert_eq!(raw.len(), 1200);
            }
            assert_eq!(packet.packet_number_offset(), Some(18));
            assert_eq!(packet.to_owned().to_bytes().as_ref(), raw);
            for end in 0..raw.len() {
                assert!(
                    QuicPacketSlice::try_from_buf(&raw[..end]).is_err(),
                    "accepted truncated Initial at {end}"
                );
            }
        }
    }
}

#[test]
fn rfc_retry_vectors_and_short_header_vector() {
    for (version, encoded) in [
        (
            QuicVersion::V1,
            include_str!("fixtures/quic/rfc9001_retry.hex"),
        ),
        (
            QuicVersion::V2,
            include_str!("fixtures/quic/rfc9369_retry.hex"),
        ),
    ] {
        let raw = hex(encoded);
        let p = QuicPacketSlice::try_from_buf(&raw).unwrap();
        assert_eq!(p.packet_type(), Kind::Retry);
        assert_eq!(p.token(), Some(b"token".as_slice()));
        assert_eq!(p.retry_integrity_tag().unwrap().len(), 16);
        assert_eq!(p.packet_number_offset(), None);
        let rebuilt = Builder::retry(
            version,
            Bytes::from_static(b"token"),
            p.retry_integrity_tag().unwrap().try_into().unwrap(),
        )
        .source_connection_id(Bytes::copy_from_slice(p.source_connection_id().unwrap()))
        .first_byte(p.first_byte())
        .to_bytes()
        .unwrap();
        assert_eq!(rebuilt.as_ref(), raw);
    }
    let raw = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    assert!(QuicPacketSlice::try_from_buf(&raw).is_err());
    let p = QuicPacketSlice::try_from_buf_with_options(&raw, short_options(0)).unwrap();
    assert_eq!(p.packet_type(), Kind::OneRtt);
    assert_eq!(p.packet_number_offset(), Some(1));
    assert_eq!(p.version(), None);
    assert_eq!(p.payload(), &raw[1..]); // Do not use protected low bits as PN length.
}

#[test]
fn all_supported_packet_types_round_trip() {
    for version in [QuicVersion::V1, QuicVersion::V2] {
        for (builder, kind, bits) in [
            (
                Builder::initial(version, Bytes::from_static(b"token"), body()),
                Kind::Initial,
                0,
            ),
            (Builder::zero_rtt(version, body()), Kind::ZeroRtt, 1),
            (Builder::handshake(version, body()), Kind::Handshake, 2),
            (
                Builder::retry(version, Bytes::from_static(b"token"), [0xaa; 16]),
                Kind::Retry,
                3,
            ),
        ] {
            let expected_bits = if version == QuicVersion::V1 {
                bits
            } else {
                (bits + 1) & 3
            };
            let first = 0xc0 | expected_bits << 4 | 0xf;
            let packet = builder
                .destination_connection_id(Bytes::from_static(b"dest"))
                .source_connection_id(Bytes::from_static(b"src"))
                .first_byte(first)
                .build()
                .unwrap();
            let bytes = packet.to_bytes();
            let parsed = QuicPacketSlice::try_from_buf(&bytes).unwrap();
            assert_eq!(parsed.first_byte(), first);
            assert_eq!(parsed.packet_type(), kind);
            assert_eq!(parsed.destination_connection_id(), b"dest");
            assert_eq!(parsed.source_connection_id(), Some(b"src".as_slice()));
            assert_eq!(
                packet.header_len() + packet.payload_len(),
                packet.total_len()
            );
            let (header, payload) = packet.into_parts();
            assert_eq!([header.as_ref(), payload.as_ref()].concat(), bytes);
        }
    }
}

#[test]
fn coalesced_packets_are_bounded_and_errors_are_fused() {
    let initial = Builder::initial(QuicVersion::V1, Bytes::new(), body())
        .to_bytes()
        .unwrap();
    let handshake = Builder::handshake(QuicVersion::V1, body())
        .to_bytes()
        .unwrap();
    let short = Builder::one_rtt(body())
        .destination_connection_id(Bytes::from_static(b"id"))
        .to_bytes()
        .unwrap();
    let raw = [initial.as_ref(), handshake.as_ref(), short.as_ref()].concat();
    let packets: Vec<_> = QuicDatagram::new(&raw, short_options(2))
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        packets.iter().map(|p| p.packet_type()).collect::<Vec<_>>(),
        [Kind::Initial, Kind::Handshake, Kind::OneRtt]
    );
    assert_eq!(
        packets
            .iter()
            .flat_map(|p| p.packet())
            .copied()
            .collect::<Vec<_>>(),
        raw
    );
    let invalid = [initial.as_ref(), &[0x80]].concat();
    let mut packets = QuicDatagram::new(&invalid, Default::default());
    assert!(packets.next().unwrap().is_ok());
    assert!(packets.next().unwrap().is_err());
    assert!(packets.next().is_none());
    assert!(packets.next().is_none());
    assert!(QuicDatagram::new(&[], Default::default()).next().is_none());
}

#[test]
fn version_invariants_and_fixed_bit_policy() {
    let vn = Builder::version_negotiation(vec![1, QUIC_VERSION_2, 0x0a0a0a0a])
        .destination_connection_id(Bytes::from(vec![0; 255]))
        .source_connection_id(Bytes::from(vec![1; 255]))
        .first_byte(0x80)
        .to_bytes()
        .unwrap();
    let parsed = QuicPacketSlice::try_from_buf(&vn).unwrap();
    assert_eq!(
        parsed.supported_versions().unwrap().collect::<Vec<_>>(),
        [1, QUIC_VERSION_2, 0x0a0a0a0a]
    );
    let mut unknown = vn.to_vec();
    unknown[1..5].copy_from_slice(&0x0a0a0a0au32.to_be_bytes());
    let parsed = QuicPacketSlice::try_from_buf(&unknown).unwrap();
    assert_eq!(parsed.packet_type(), Kind::UnknownVersion);
    assert_eq!(parsed.packet().len(), unknown.len());
    assert_eq!(parsed.destination_connection_id().len(), 255);
    assert!(parsed.supported_versions().is_none());
    let greased = Builder::handshake(QuicVersion::V1, body())
        .first_byte(0xa0)
        .to_bytes()
        .unwrap();
    assert!(QuicPacketSlice::try_from_buf(&greased).is_err());
    assert!(
        QuicPacketSlice::try_from_buf_with_options(
            &greased,
            QuicParseOptions {
                allow_greased_fixed_bit: true,
                ..Default::default()
            }
        )
        .is_ok()
    );
}

#[test]
fn malformed_lengths_and_builder_inputs_are_rejected() {
    for raw in [
        hex("c0000000011500"),                                 // CID longer than 20.
        hex("c000000001000040"),                               // Truncated token length.
        hex("c000000001000001"),                               // Missing token.
        hex("c00000000100000000"),                             // Zero protected length.
        hex("c000000001000000ffffffffffffffff"),               // Huge protected length.
        hex("c0000000010000ffffffffffffffff"),                 // Huge token length.
        hex("80000000000000"),                                 // Empty VN list.
        hex("8000000000000001"),                               // Nonintegral VN list.
        hex("f000000001000000000000000000000000000000000000"), // Retry without token.
    ] {
        assert!(QuicPacketSlice::try_from_buf(&raw).is_err(), "{raw:x?}");
    }
    assert!(QuicPacketSlice::try_from_buf_with_options(&[0x40], short_options(0)).is_err());
    assert!(QuicPacketSlice::try_from_buf_with_options(&[0x40; 30], short_options(21)).is_err());
    assert!(
        Builder::initial(QuicVersion::V1, Bytes::new(), Bytes::new())
            .build()
            .is_err()
    );
    assert!(
        Builder::retry(QuicVersion::V1, Bytes::new(), [0; 16])
            .build()
            .is_err()
    );
    assert!(Builder::version_negotiation(vec![]).build().is_err());
    assert!(Builder::version_negotiation(vec![0]).build().is_err());
    assert!(
        Builder::one_rtt(body())
            .source_connection_id(Bytes::from_static(b"x"))
            .build()
            .is_err()
    );
    assert!(
        Builder::handshake(QuicVersion::V1, body())
            .first_byte(0xc0)
            .build()
            .is_err()
    );
    assert!(Builder::one_rtt(body()).first_byte(0xc0).build().is_err());
    assert!(
        Builder::handshake(QuicVersion::V1, body())
            .destination_connection_id(Bytes::from(vec![0; 21]))
            .build()
            .is_err()
    );
}

#[test]
fn varint_rfc_vectors_widths_and_error_atomicity() {
    for (wire, value) in [
        ("c2197c5eff14e88c", 151288809941952652),
        ("9d7f3e7d", 494878333),
        ("7bbd", 15293),
        ("25", 37),
        ("4025", 37),
    ] {
        let raw = hex(wire);
        let (parsed, width) = QuicVarInt::decode(&raw).unwrap();
        assert_eq!(parsed.value(), value);
        assert_eq!(width, raw.len());
        let mut encoded = [0; 8];
        parsed.encode_with_len(&mut encoded, width).unwrap();
        assert_eq!(&encoded[..width], raw);
        for i in 0..raw.len() {
            assert!(QuicVarInt::decode(&raw[..i]).is_err());
        }
    }
    assert!(QuicVarInt::new(1 << 62).is_none());
    let value = QuicVarInt::new(64).unwrap();
    let mut out = [0xaa; 8];
    assert!(value.encode_with_len(&mut out, 1).is_err());
    assert!(value.encode_with_len(&mut out, 3).is_err());
    assert!(value.encode(&mut out[..1]).is_err());
    assert_eq!(out, [0xaa; 8]);
}

#[test]
fn owned_parsing_retains_storage_and_nonminimal_encoding() {
    let mut raw = hex("e000000001000080000014"); // Four-byte encoding of body length 20.
    raw.extend([0xaa; 20]);
    let original = Bytes::from(raw);
    let packet = QuicPacket::try_from_bytes(original.clone()).unwrap();
    assert_eq!(packet.to_bytes().as_ptr(), original.as_ptr());
    assert_eq!(packet.to_bytes(), original);
    assert_eq!(packet.as_slice().header().len(), 11);
}

proptest! {
    #[test]
    fn variable_integers_round_trip(value in 0..=QuicVarInt::MAX) {
        let value = QuicVarInt::new(value).unwrap();
        let mut out = [0; 8];
        let length = value.encode(&mut out).unwrap();
        prop_assert_eq!(QuicVarInt::decode(&out[..length]).unwrap(), (value, length));
    }
    #[test]
    fn arbitrary_packets_are_panic_free_and_lossless(data in prop::collection::vec(any::<u8>(), 0..4096), cid in 0usize..=21) {
        let options = short_options(cid);
        for packet in QuicDatagram::new(&data, options).flatten() {
                let owned = packet.to_owned().to_bytes();
                prop_assert_eq!(owned.as_ref(), packet.packet());
                prop_assert_eq!(packet.header().len() + packet.payload().len(), packet.packet().len());
        }
        let _ = QuicVarInt::decode(&data);
    }
}

#[test]
fn udp_and_frame_helpers_preserve_transport_metadata() {
    use nex_packet::{
        builder::{ipv4::Ipv4PacketBuilder, udp::UdpPacketBuilder},
        frame::{Frame, FrameView, ParseOption},
        ip::IpNextProtocol,
    };
    use std::net::Ipv4Addr;
    let payload = Builder::handshake(QuicVersion::V2, body())
        .to_bytes()
        .unwrap();
    let udp = UdpPacketBuilder::new(Ipv4Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into())
        .source(12345)
        .destination(45678)
        .payload(payload)
        .build()
        .unwrap();
    assert_eq!(
        udp.quic_packets(Default::default())
            .next()
            .unwrap()
            .unwrap()
            .packet_type(),
        Kind::Handshake
    );
    let ip = Ipv4PacketBuilder::new()
        .source(Ipv4Addr::LOCALHOST)
        .destination(Ipv4Addr::LOCALHOST)
        .protocol(IpNextProtocol::Udp)
        .payload(udp.to_bytes())
        .to_bytes()
        .unwrap();
    let option = ParseOption {
        from_ip_packet: true,
        offset: 0,
    };
    let frame = Frame::try_from_buf(&ip, option.clone()).unwrap();
    assert_eq!(
        frame
            .transport
            .as_ref()
            .unwrap()
            .udp
            .as_ref()
            .unwrap()
            .destination,
        45678
    );
    assert_eq!(
        frame
            .quic_packets(Default::default())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .version(),
        Some(QUIC_VERSION_2)
    );
    let view = FrameView::try_from_buf(&ip, option).unwrap();
    assert_eq!(view.quic_packets(Default::default()).unwrap().count(), 1);
}

#[test]
fn local_udp_datagram_round_trip() {
    use std::{net::UdpSocket, time::Duration};
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let wire = Builder::version_negotiation(vec![QUIC_VERSION_1, QUIC_VERSION_2])
        .destination_connection_id(Bytes::from_static(b"client"))
        .source_connection_id(Bytes::from_static(b"server"))
        .to_bytes()
        .unwrap();
    sender
        .send_to(&wire, receiver.local_addr().unwrap())
        .unwrap();
    let mut buffer = [0; 1500];
    let (length, _) = receiver.recv_from(&mut buffer).unwrap();
    let packet = QuicPacket::try_from_buf(&buffer[..length]).unwrap();
    assert_eq!(packet.to_bytes(), wire);
    assert_eq!(
        packet
            .as_slice()
            .supported_versions()
            .unwrap()
            .collect::<Vec<_>>(),
        [QUIC_VERSION_1, QUIC_VERSION_2]
    );
}

proptest! {
    #[test]
    fn builders_preserve_random_fields(
        dcid in prop::collection::vec(any::<u8>(), 0..=20),
        scid in prop::collection::vec(any::<u8>(), 0..=20),
        token in prop::collection::vec(any::<u8>(), 0..256),
        data in prop::collection::vec(any::<u8>(), 1..2048),
        v2 in any::<bool>(),
    ) {
        let version = if v2 { QuicVersion::V2 } else { QuicVersion::V1 };
        let packet = Builder::initial(version, Bytes::copy_from_slice(&token), Bytes::copy_from_slice(&data))
            .destination_connection_id(Bytes::copy_from_slice(&dcid))
            .source_connection_id(Bytes::copy_from_slice(&scid)).build().unwrap();
        let bytes = packet.to_bytes();
        let parsed = QuicPacketSlice::try_from_buf(&bytes).unwrap();
        prop_assert_eq!(parsed.destination_connection_id(), dcid);
        prop_assert_eq!(parsed.source_connection_id().unwrap(), scid);
        prop_assert_eq!(parsed.token().unwrap(), token);
        prop_assert_eq!(parsed.payload(), data);
    }
}
