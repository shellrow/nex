use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use nex_packet::{
    frame::{Frame, FrameView, ParseOption},
    packet::Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

fn ipv4_tcp_frame() -> Bytes {
    Bytes::from_static(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40,
        0x00, 64, 0x06, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1, 0,
        0, 0, 0, 0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', b'!', b'!',
        b'!',
    ])
}

fn ipv6_udp_frame() -> Bytes {
    Bytes::from_static(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, 0x60, 0, 0, 0, 0, 16, 17, 64, 0xfe, 0x80,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2, 0x04, 0xd2, 0x00, 0x35, 0x00, 0x10, 0, 0, b'd', b'n', b's', b'!', 0, 1, 2, 3,
    ])
}

fn bench_packet_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parse");
    let ipv4_tcp = ipv4_tcp_frame();
    let ipv6_udp = ipv6_udp_frame();
    let tcp_segment = ipv4_tcp.slice(14 + 20..);
    let udp_datagram = ipv6_udp.slice(14 + 40..);

    group.bench_function("frame_from_buf_ipv4_tcp", |b| {
        b.iter(|| Frame::from_buf(&ipv4_tcp, ParseOption::default()))
    });
    group.bench_function("frame_try_from_bytes_ipv4_tcp", |b| {
        b.iter(|| Frame::try_from_bytes(ipv4_tcp.clone(), ParseOption::default()))
    });
    group.bench_function("frame_view_from_buf_ipv4_tcp", |b| {
        b.iter(|| FrameView::from_buf(&ipv4_tcp, ParseOption::default()))
    });
    group.bench_function("tcp_from_buf", |b| {
        b.iter(|| TcpPacket::from_buf(&tcp_segment))
    });
    group.bench_function("tcp_from_bytes", |b| {
        b.iter(|| TcpPacket::from_bytes(tcp_segment.clone()))
    });
    group.bench_function("udp_from_buf", |b| {
        b.iter(|| UdpPacket::from_buf(&udp_datagram))
    });
    group.bench_function("udp_from_bytes", |b| {
        b.iter(|| UdpPacket::from_bytes(udp_datagram.clone()))
    });

    for (name, packet) in [("ipv4_tcp", ipv4_tcp), ("ipv6_udp", ipv6_udp)] {
        group.bench_with_input(
            BenchmarkId::new("frame_view", name),
            &packet,
            |b, packet| b.iter(|| FrameView::from_buf(packet, ParseOption::default())),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_packet_parse);
criterion_main!(benches);
