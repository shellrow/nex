use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nex_packet::{
    dns::DnsName,
    ethernet::EthernetPacket,
    ipv4::{Ipv4Packet, checksum as ipv4_checksum},
    ipv6::Ipv6Packet,
    packet::Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    vlan::VlanPacket,
};

const ETHERNET: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
];
const VLAN: &[u8] = &[0x20, 0x01, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
const IPV4: &[u8] = &[
    0x45, 0, 0, 28, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04, 0xd2,
    0, 53, 0, 8, 0, 0,
];
const IPV6: &[u8] = &[
    0x60, 0, 0, 0, 0, 8, 17, 64, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xfe, 0x80,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x04, 0xd2, 0, 53, 0, 8, 0, 0,
];
const TCP: &[u8] = &[
    0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
];
const UDP: &[u8] = &[0x04, 0xd2, 0, 53, 0, 8, 0, 0];
const DNS_NAME: &[u8] = &[
    3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
];

fn bench_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_parse");
    for (name, len) in [
        ("ethernet", ETHERNET.len()),
        ("vlan", VLAN.len()),
        ("ipv4", IPV4.len()),
        ("ipv6", IPV6.len()),
        ("tcp", TCP.len()),
        ("udp", UDP.len()),
        ("dns_name", DNS_NAME.len()),
    ] {
        group.throughput(Throughput::Bytes(len as u64));
        match name {
            "ethernet" => {
                group.bench_function(name, |b| b.iter(|| EthernetPacket::try_from_buf(ETHERNET)))
            }
            "vlan" => group.bench_function(name, |b| b.iter(|| VlanPacket::try_from_buf(VLAN))),
            "ipv4" => group.bench_function(name, |b| b.iter(|| Ipv4Packet::try_from_buf(IPV4))),
            "ipv6" => group.bench_function(name, |b| b.iter(|| Ipv6Packet::try_from_buf(IPV6))),
            "tcp" => group.bench_function(name, |b| b.iter(|| TcpPacket::try_from_buf(TCP))),
            "udp" => group.bench_function(name, |b| b.iter(|| UdpPacket::try_from_buf(UDP))),
            "dns_name" => {
                group.bench_function(name, |b| b.iter(|| DnsName::try_from_bytes(DNS_NAME)))
            }
            _ => unreachable!(),
        };
    }
    group.finish();
}

fn bench_serialization_and_checksum(c: &mut Criterion) {
    let packet = Ipv4Packet::try_from_buf(IPV4).expect("benchmark packet");
    let mut group = c.benchmark_group("packet_operations");
    group.throughput(Throughput::Bytes(IPV4.len() as u64));
    group.bench_function("ipv4_serialize", |b| b.iter(|| packet.to_bytes()));
    group.bench_function("ipv4_checksum", |b| b.iter(|| ipv4_checksum(&packet)));
    group.bench_function("owned_parse", |b| {
        b.iter(|| Ipv4Packet::try_from_bytes(Bytes::copy_from_slice(IPV4)))
    });
    group.finish();
}

criterion_group!(benches, bench_parsing, bench_serialization_and_checksum);
criterion_main!(benches);
