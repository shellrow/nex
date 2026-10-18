use nex_packet::frame::{Frame, FrameSlice, FrameView, ParseOption};
use nex_packet::ipv6::Ipv6Packet;

fn ip_option() -> ParseOption {
    ParseOption {
        from_ip_packet: true,
        offset: 0,
    }
}

fn ipv4(fragment_offset: u16) -> Vec<u8> {
    let mut raw = vec![0; 32];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&32u16.to_be_bytes());
    raw[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
    raw[9] = 17;
    raw[20..].copy_from_slice(&[0, 1, 0, 2, 0, 12, 0, 0, 1, 2, 3, 4]);
    raw
}

fn ipv6(offset: u16, next: u8) -> Vec<u8> {
    let mut raw = vec![0; 60];
    raw[0] = 0x60;
    raw[4..6].copy_from_slice(&20u16.to_be_bytes());
    raw[6] = 44;
    raw[40] = next;
    raw[42..44].copy_from_slice(&(offset << 3).to_be_bytes());
    raw[48..].copy_from_slice(&[0, 1, 0, 2, 0, 12, 0, 0, 1, 2, 3, 4]);
    raw
}

#[test]
fn noninitial_fragments_preserve_data_without_transport_decoding() {
    for (raw, header_len) in [(ipv4(1), 20), (ipv6(1, 17), 48), (ipv6(1, 60), 48)] {
        let frame = Frame::try_from_buf(&raw, ip_option()).unwrap();
        assert!(frame.transport.is_none());
        assert_eq!(frame.payload.as_ref(), &raw[header_len..]);
        let slices = FrameSlice::try_from_buf(&raw, ip_option()).unwrap();
        assert!(slices.transport.is_none());
        assert_eq!(slices.payload, &raw[header_len..]);
        if header_len == 48 {
            let packet = Ipv6Packet::try_from_buf(&raw).unwrap();
            assert_eq!(packet.payload.as_ref(), &raw[header_len..]);
        }
    }
}

#[test]
fn ipv6_transport_is_decoded_after_extension_header() {
    let raw = ipv6(0, 17);
    let frame = Frame::try_from_buf(&raw, ip_option()).unwrap();
    assert_eq!(frame.transport.unwrap().udp.unwrap().destination, 2);
    assert_eq!(frame.payload.as_ref(), &[1, 2, 3, 4]);
}

#[test]
fn borrowed_payload_excludes_ethernet_padding() {
    let mut raw = vec![0; 14];
    raw[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    raw.extend(ipv4(0));
    raw.extend([0xaa; 14]);
    for option in [
        ParseOption::default(),
        ParseOption {
            from_ip_packet: true,
            offset: 14,
        },
    ] {
        let frame = Frame::try_from_buf(&raw, option.clone()).unwrap();
        let view = FrameView::try_from_buf(&raw, option).unwrap();
        assert_eq!(view.payload, frame.payload.as_ref());
        assert_eq!(view.payload, &[1, 2, 3, 4]);
    }
}

#[test]
fn borrowed_icmp_payloads_match_owned_frames_with_padding() {
    let mut v4 = ipv4(0);
    v4[9] = 1;
    v4[20] = 8;
    let mut v6 = ipv6(0, 58);
    v6[48] = 128;
    for (mut raw, start) in [(v4, 24), (v6, 52)] {
        let end = raw.len();
        raw.extend([0xaa; 8]);
        let frame = Frame::try_from_buf(&raw, ip_option()).unwrap();
        let view = FrameView::try_from_buf(&raw, ip_option()).unwrap();
        assert_eq!(view.payload, &raw[start..end]);
        assert_eq!(view.payload, frame.payload.as_ref());
    }
}
