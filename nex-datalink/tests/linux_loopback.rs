#![cfg(target_os = "linux")]

use nex_core::interface::{Interface, get_interfaces};
use nex_datalink::{Channel, ChannelType, Config, channel};
use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn interface() -> Interface {
    let name = std::env::var("NEX_TEST_INTERFACE").expect("set an isolated test interface");
    get_interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .unwrap()
}

fn config(enabled: bool, layer: ChannelType) -> Config {
    Config::default()
        .with_promiscuous(false)
        .with_channel_type(layer)
        .with_read_timeout(Some(Duration::from_millis(20)))
        .with_linux_suppress_loopback_duplicates(enabled)
}

// Repeated identifier 3 deliberately sends exactly the same payload twice.
const IDS: [u8; 5] = [0, 1, 2, 3, 3];

struct Traffic {
    receiver: UdpSocket,
    sender: UdpSocket,
    marker: Vec<u8>,
}

impl Traffic {
    fn new(ipv6: bool) -> Self {
        let address = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
        let receiver = UdpSocket::bind(address).unwrap();
        let sender = UdpSocket::bind(address).unwrap();
        let marker = format!(
            "nex-loopback-{}-{}-",
            std::process::id(),
            receiver.local_addr().unwrap().port()
        )
        .into_bytes();
        Self {
            receiver,
            sender,
            marker,
        }
    }

    fn send(&self) {
        for id in IDS {
            let mut payload = self.marker.clone();
            payload.push(id);
            self.sender
                .send_to(&payload, self.receiver.local_addr().unwrap())
                .unwrap();
        }
    }

    fn record(&self, packet: &[u8], layer: ChannelType, ipv6: bool, seen: &mut Vec<u8>) {
        let size = self.marker.len() + 1;
        if packet.len() < size || !packet[packet.len() - size..].starts_with(&self.marker) {
            return;
        }
        let link = if layer == ChannelType::Layer2 { 14 } else { 0 };
        assert_eq!(packet.len(), link + if ipv6 { 40 } else { 20 } + 8 + size);
        assert_eq!(packet[link] >> 4, if ipv6 { 6 } else { 4 });
        seen.push(*packet.last().unwrap());
    }
}

fn verify(seen: Vec<u8>, enabled: bool, layer: ChannelType) {
    // Protocol-specific packet sockets receive only the incoming copy on Linux.
    let copies = if enabled || matches!(layer, ChannelType::Layer3(p) if p != 3) {
        1
    } else {
        2
    };
    let expected: Vec<_> = IDS
        .into_iter()
        .flat_map(|id| std::iter::repeat_n(id, copies))
        .collect();
    assert_eq!(seen, expected, "enabled={enabled}, layer={layer:?}");
}

#[test]
#[ignore = "requires NEX_TEST_INTERFACE on isolated loopback and CAP_NET_RAW"]
fn synchronous_loopback_duplicates() {
    let iface = interface();
    assert!(iface.is_loopback());
    for ipv6 in [false, true] {
        for layer in [
            ChannelType::Layer2,
            ChannelType::Layer3(3),
            ChannelType::Layer3(if ipv6 { 0x86dd } else { 0x0800 }),
        ] {
            for enabled in [false, true] {
                let traffic = Traffic::new(ipv6);
                let Channel::Ethernet(_, mut rx) = channel(&iface, config(enabled, layer)).unwrap()
                else {
                    unreachable!()
                };
                traffic.send();
                let deadline = Instant::now() + Duration::from_millis(200);
                let mut seen = Vec::new();
                // Keep listening after all expected packets to catch late duplicates.
                while Instant::now() < deadline {
                    match rx.next() {
                        Ok(packet) => traffic.record(packet, layer, ipv6, &mut seen),
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => (),
                        Err(e) => panic!("receive: {e}"),
                    }
                }
                verify(seen, enabled, layer);
            }
        }
    }
}

#[cfg(feature = "async")]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE on isolated loopback and CAP_NET_RAW"]
fn asynchronous_loopback_duplicates() {
    use futures::{
        StreamExt,
        future::{Either, select},
    };
    use nex_datalink::async_io::{AsyncChannel, async_channel};
    let iface = interface();
    assert!(iface.is_loopback());
    for ipv6 in [false, true] {
        for layer in [
            ChannelType::Layer2,
            ChannelType::Layer3(3),
            ChannelType::Layer3(if ipv6 { 0x86dd } else { 0x0800 }),
        ] {
            for enabled in [false, true] {
                let traffic = Traffic::new(ipv6);
                let AsyncChannel::Ethernet(_, mut rx) =
                    async_channel(&iface, config(enabled, layer)).unwrap()
                else {
                    unreachable!()
                };
                traffic.send();
                let (tx, deadline) = futures::channel::oneshot::channel();
                let timer = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = tx.send(());
                });
                let mut seen = Vec::new();
                futures::executor::block_on(async {
                    let receive = Box::pin(async {
                        loop {
                            let packet = rx.next().await.unwrap().unwrap();
                            traffic.record(&packet, layer, ipv6, &mut seen);
                        }
                    });
                    assert!(matches!(select(receive, deadline).await, Either::Right(_)));
                });
                timer.join().unwrap();
                verify(seen, enabled, layer);
            }
        }
    }
}

#[test]
#[ignore = "requires NEX_TEST_INTERFACE on an isolated veth and CAP_NET_RAW"]
fn non_loopback_outgoing_is_preserved() {
    let iface = interface();
    assert!(!iface.is_loopback());
    for layer in [ChannelType::Layer2, ChannelType::Layer3(3)] {
        for enabled in [false, true] {
            let Channel::Ethernet(_, mut rx) = channel(&iface, config(enabled, layer)).unwrap()
            else {
                unreachable!()
            };
            let Channel::Ethernet(mut tx, _) =
                channel(&iface, config(false, ChannelType::Layer2)).unwrap()
            else {
                unreachable!()
            };
            #[cfg(feature = "async")]
            let nex_datalink::async_io::AsyncChannel::Ethernet(_, mut async_rx) =
                nex_datalink::async_io::async_channel(&iface, config(enabled, layer)).unwrap()
            else {
                unreachable!()
            };
            let mut frame = [0x97; 60];
            frame[..6].fill(0xff);
            frame[6..12].copy_from_slice(&iface.mac_addr.unwrap().octets());
            frame[12..14].copy_from_slice(&[0x88, 0xb5]);
            tx.send(&frame).unwrap().unwrap();
            let expected = if layer == ChannelType::Layer2 {
                &frame[..]
            } else {
                &frame[14..]
            };
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                assert!(Instant::now() < deadline);
                match rx.next() {
                    Ok(packet) if packet == expected => break,
                    Ok(_) => (),
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => (),
                    Err(e) => panic!("receive: {e}"),
                }
            }
            #[cfg(feature = "async")]
            {
                use futures::StreamExt;
                futures::executor::block_on(async {
                    loop {
                        assert!(Instant::now() < deadline);
                        // Poll directly so the deadline is checked even when idle.
                        let result = futures::future::poll_fn(|cx| {
                            std::task::Poll::Ready(async_rx.poll_next_unpin(cx))
                        })
                        .await;
                        if let std::task::Poll::Ready(Some(packet)) = result
                            && packet.unwrap() == expected
                        {
                            break;
                        }
                    }
                });
            }
        }
    }
}

#[test]
#[ignore = "requires isolated NEX_TEST_INTERFACE and CAP_NET_RAW; run with --test-threads=1"]
fn idle_timeout_cancellation_and_release() {
    let iface = interface();
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = descriptors();
    let settings = config(true, ChannelType::Layer3(0x88b5));
    let Channel::Ethernet(tx, mut rx) = channel(&iface, settings).unwrap() else {
        unreachable!()
    };
    let start = Instant::now();
    assert_eq!(rx.next().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(1));
    drop((tx, rx));
    assert_eq!(descriptors(), before);

    #[cfg(feature = "async")]
    {
        use futures::{FutureExt, StreamExt};
        let nex_datalink::async_io::AsyncChannel::Ethernet(tx, mut rx) =
            nex_datalink::async_io::async_channel(&iface, settings).unwrap()
        else {
            unreachable!()
        };
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut pending = rx.next();
        assert!(pending.poll_unpin(&mut cx).is_pending());
        drop(pending);
        // Cancelling a receive leaves the stream usable, without emitting an item.
        assert!(rx.poll_next_unpin(&mut cx).is_pending());
        drop((tx, rx));
        assert_eq!(descriptors(), before);
    }
}
