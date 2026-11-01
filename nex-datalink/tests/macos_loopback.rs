#![cfg(all(target_os = "macos", feature = "async"))]

use futures::StreamExt;
use nex_core::interface::get_interfaces;
use nex_datalink::async_io::{AsyncChannel, async_channel};
use nex_datalink::{Channel, Config, channel};
use std::io;
use std::net::{TcpListener, UdpSocket};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(ipv6: bool, protocol: u8, transport: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 14 + if ipv6 { 40 } else { 20 }];
    packet[12..14].copy_from_slice(&if ipv6 { 0x86ddu16 } else { 0x0800u16 }.to_be_bytes());
    let ip = &mut packet[14..];
    if ipv6 {
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        ip[6] = protocol;
        ip[7] = 64;
        ip[23] = 1;
        ip[39] = 1;
    } else {
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let sum = checksum(ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    let mut pseudo = Vec::new();
    if ipv6 {
        pseudo.extend_from_slice(&ip[8..40]);
        pseudo.extend_from_slice(&(transport.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    } else if protocol != 1 {
        pseudo.extend_from_slice(&ip[12..20]);
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
    }
    pseudo.extend_from_slice(transport);
    let offset = packet.len();
    packet.extend_from_slice(transport);
    let position = match protocol {
        1 | 58 => 2,
        6 => 16,
        17 => 6,
        _ => unreachable!(),
    };
    let sum = checksum(&pseudo);
    packet[offset + position..offset + position + 2]
        .copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    packet
}

#[test]
#[ignore = "requires access to /dev/bpf; sends ICMP, TCP, and UDP only to localhost"]
fn localhost_request_response_all_send_paths() {
    let interface = get_interfaces()
        .into_iter()
        .find(|i| i.is_loopback())
        .unwrap();
    let config = Config::default()
        .with_promiscuous(false)
        .with_read_timeout(Some(Duration::from_millis(30)))
        .with_write_timeout(Some(Duration::from_secs(1)));
    for ipv6 in [true, false] {
        for mode in 0..3 {
            for protocol in [if ipv6 { 58 } else { 1 }, 6, 17] {
                let address = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
                // Reserve both endpoints so probes cannot reach an unrelated service.
                let tcp = TcpListener::bind(address).unwrap();
                let source_tcp = TcpListener::bind(address).unwrap();
                let udp = UdpSocket::bind(address).unwrap();
                let source_udp = UdpSocket::bind(address).unwrap();
                let source = if protocol == 6 {
                    source_tcp.local_addr().unwrap().port()
                } else {
                    source_udp.local_addr().unwrap().port()
                };
                let destination = if protocol == 6 {
                    tcp.local_addr().unwrap().port()
                } else {
                    udp.local_addr().unwrap().port()
                };
                let marker = b"nex-bpf-loopback-response";
                let mut transport = vec![0u8; if protocol == 6 { 20 } else { 8 }];
                if matches!(protocol, 1 | 58) {
                    transport[0] = if ipv6 { 128 } else { 8 };
                    transport[4..6].copy_from_slice(&source.to_be_bytes());
                    transport[6..8].copy_from_slice(&123u16.to_be_bytes());
                    transport.extend_from_slice(marker);
                } else {
                    transport[..2].copy_from_slice(&source.to_be_bytes());
                    transport[2..4].copy_from_slice(&destination.to_be_bytes());
                    if protocol == 6 {
                        transport[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
                        transport[12] = 0x50;
                        transport[13] = 2;
                        transport[14..16].copy_from_slice(&4096u16.to_be_bytes());
                    } else {
                        transport[4..6].copy_from_slice(&((8 + marker.len()) as u16).to_be_bytes());
                        transport.extend_from_slice(marker);
                    }
                }
                let packet = frame(ipv6, protocol, &transport);
                let Channel::Ethernet(mut tx, mut rx) = channel(&interface, config).unwrap() else {
                    unreachable!()
                };
                let AsyncChannel::Ethernet(mut async_tx, mut async_rx) =
                    async_channel(&interface, config).unwrap()
                else {
                    unreachable!()
                };
                let deadline = Instant::now() + Duration::from_secs(2);
                let waker = futures::task::noop_waker();
                let mut cx = Context::from_waker(&waker);
                match mode {
                    0 => tx.send(&packet).unwrap().unwrap(),
                    1 => tx
                        .build_and_send(1, packet.len(), &mut |out| out.copy_from_slice(&packet))
                        .unwrap()
                        .unwrap(),
                    _ => loop {
                        assert!(Instant::now() < deadline, "async send timed out");
                        match async_tx.poll_send(&mut cx, &packet) {
                            Poll::Ready(result) => {
                                result.unwrap();
                                break;
                            }
                            Poll::Pending => std::thread::yield_now(),
                        }
                    },
                }
                if protocol == 17 {
                    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                    let mut received = [0; 128];
                    let (n, peer) = udp.recv_from(&mut received).expect("UDP request delivered");
                    assert_eq!(&received[..n], marker);
                    assert_eq!(peer, source_udp.local_addr().unwrap());
                    udp.send_to(&received[..n], peer).unwrap();
                }
                loop {
                    assert!(
                        Instant::now() < deadline,
                        "missing response: IPv6={ipv6}, mode={mode}, protocol={protocol}"
                    );
                    let received = if mode == 2 {
                        match async_rx.poll_next_unpin(&mut cx) {
                            Poll::Ready(Some(result)) => result.unwrap(),
                            Poll::Ready(None) => panic!("stream ended"),
                            Poll::Pending => {
                                std::thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                        }
                    } else {
                        match rx.next() {
                            Ok(bytes) => bytes.to_vec(),
                            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                            Err(e) => panic!("receive: {e}"),
                        }
                    };
                    let offset = 14 + if ipv6 { 40 } else { 20 };
                    if received.len() < offset + 8 || received[14] >> 4 != if ipv6 { 6 } else { 4 }
                    {
                        continue;
                    }
                    if received[14 + if ipv6 { 6 } else { 9 }] != protocol {
                        continue;
                    }
                    let body = &received[offset..];
                    if matches!(protocol, 1 | 58) {
                        if body[0] != if ipv6 { 129 } else { 0 } || body[4..8] != transport[4..8] {
                            continue;
                        }
                        assert_eq!(body[1], 0);
                        assert_eq!(&body[8..], marker);
                    } else {
                        if body[..2] != destination.to_be_bytes()
                            || body[2..4] != source.to_be_bytes()
                        {
                            continue;
                        }
                        if protocol == 6 {
                            assert!(body.len() >= 20);
                            assert_eq!(body[13] & 0x17, 0x12, "expected SYN-ACK");
                            assert_eq!(&body[8..12], &0x12345679u32.to_be_bytes());
                        } else {
                            assert_eq!(&body[8..], marker);
                        }
                    }
                    let ip = &received[14..offset];
                    if ipv6 {
                        assert_eq!(&ip[8..24], &std::net::Ipv6Addr::LOCALHOST.octets());
                        assert_eq!(&ip[24..40], &std::net::Ipv6Addr::LOCALHOST.octets());
                    } else {
                        assert_eq!(&ip[12..16], &[127, 0, 0, 1]);
                        assert_eq!(&ip[16..20], &[127, 0, 0, 1]);
                    }
                    eprintln!("response verified: IPv6={ipv6}, mode={mode}, protocol={protocol}");
                    break;
                }
            }
        }
    }
}
