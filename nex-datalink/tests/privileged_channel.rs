use nex_core::interface::{Interface, get_interfaces};
#[cfg(any(target_os = "linux", target_os = "android"))]
use nex_datalink::ChannelType;
use nex_datalink::{Config, channel};

fn test_interface() -> Interface {
    let requested =
        std::env::var("NEX_TEST_INTERFACE").expect("set NEX_TEST_INTERFACE to a test interface");
    get_interfaces()
        .into_iter()
        .find(|interface| interface.name == requested)
        .unwrap_or_else(|| panic!("interface {requested:?} was not found"))
}

#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_and_close_platform_channel() {
    let interface = test_interface();
    let config = Config::default()
        .with_promiscuous(false)
        .with_read_timeout(Some(std::time::Duration::from_millis(100)))
        .with_write_timeout(Some(std::time::Duration::from_millis(100)));

    let opened = channel(&interface, config).expect("open privileged datalink channel");
    drop(opened);
}

#[cfg(feature = "pcap")]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and packet-capture privileges"]
fn open_and_close_pcap_channel() {
    let interface = test_interface();
    let config = Config::default()
        .with_promiscuous(false)
        .with_read_timeout(Some(std::time::Duration::from_millis(100)));
    drop(nex_datalink::pcap::channel(&interface, (&config).into()).expect("open pcap channel"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_linux_layer3_channel() {
    let interface = test_interface();
    let config = Config::default()
        .with_promiscuous(false)
        .with_channel_type(ChannelType::Layer3(0x0800));

    let opened = channel(&interface, config).expect("open Linux Layer3 channel");
    drop(opened);
}

#[cfg(feature = "async")]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_and_close_async_platform_channel() {
    let interface = test_interface();
    let opened = nex_datalink::async_io::async_channel(
        &interface,
        Config::default().with_promiscuous(false),
    )
    .expect("open privileged async datalink channel");
    drop(opened);
}

#[cfg(any(target_os = "linux", windows))]
fn test_config() -> Config {
    Config::default()
        .with_read_buffer_size(1_048_576)
        .with_promiscuous(false)
        .with_read_timeout(Some(std::time::Duration::from_millis(100)))
        .with_write_timeout(Some(std::time::Duration::from_millis(100)))
}

#[cfg(any(target_os = "linux", windows))]
fn test_frame(interface: &Interface, marker: u8) -> Vec<u8> {
    let mac = interface
        .mac_addr
        .expect("test interface MAC address")
        .octets();
    let mut frame = vec![marker; 60];
    frame[..6].copy_from_slice(&mac);
    frame[6..12].copy_from_slice(&mac);
    // IEEE local experimental EtherType; no IP traffic or remote service needed.
    frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    frame
}

#[cfg(any(target_os = "linux", windows))]
fn receive_frame(rx: &mut dyn nex_datalink::RawReceiver, expected: &[u8]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) if frame.starts_with(expected) => return,
            Ok(_) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => panic!("receive test frame: {error}"),
        }
    }
    panic!("test frame was not captured within five seconds");
}

#[cfg(any(target_os = "linux", windows))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges; sends experimental Ethernet frames"]
fn synchronous_frame_send_and_capture() {
    let interface = test_interface();
    for promiscuous in [false, true] {
        let nex_datalink::Channel::Ethernet(_, mut rx) =
            channel(&interface, test_config().with_promiscuous(promiscuous)).unwrap()
        else {
            unreachable!()
        };
        let nex_datalink::Channel::Ethernet(mut tx, _) =
            channel(&interface, test_config()).unwrap()
        else {
            unreachable!()
        };
        let frame = test_frame(&interface, 0x51);
        tx.send(&frame)
            .expect("supported send")
            .expect("send test frame");
        receive_frame(&mut *rx, &frame);
    }
}

#[cfg(all(feature = "async", any(target_os = "linux", windows)))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges; sends experimental Ethernet frames"]
fn asynchronous_frame_send_and_capture() {
    use futures::{
        StreamExt,
        future::{Either, poll_fn, select},
    };
    use nex_datalink::async_io::{AsyncChannel, async_channel};
    let interface = test_interface();
    let AsyncChannel::Ethernet(mut async_tx, mut async_rx) =
        async_channel(&interface, test_config()).unwrap()
    else {
        unreachable!()
    };
    let nex_datalink::Channel::Ethernet(mut tx, mut rx) =
        channel(&interface, test_config()).unwrap()
    else {
        unreachable!()
    };
    let (deadline_tx, deadline_rx) = futures::channel::oneshot::channel();
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let timer = std::thread::spawn(move || {
        if cancel_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            let _ = deadline_tx.send(());
        }
    });
    let result = futures::executor::block_on(async {
        let operation = async {
            let sent = test_frame(&interface, 0x52);
            let send_start = std::time::Instant::now();
            poll_fn(|cx| async_tx.poll_send(cx, &sent))
                .await
                .expect("async send");
            eprintln!("async send elapsed: {:?}", send_start.elapsed());
            receive_frame(&mut *rx, &sent);
            let received = test_frame(&interface, 0x53);
            tx.send(&received).unwrap().unwrap();
            loop {
                let frame = async_rx
                    .next()
                    .await
                    .expect("open stream")
                    .expect("async receive");
                if frame.starts_with(&received) {
                    break;
                }
            }
        };
        matches!(
            select(Box::pin(operation), deadline_rx).await,
            Either::Left(_)
        )
    });
    let _ = cancel_tx.send(());
    timer.join().unwrap();
    assert!(result, "async send/receive exceeded five seconds");
}

#[cfg(any(target_os = "linux", windows))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges; run with --test-threads=1"]
fn repeated_channel_lifecycle() {
    let interface = test_interface();
    // Warm up lazy DLL loading and runtime bookkeeping before taking a baseline.
    drop(channel(&interface, test_config()).unwrap());
    #[cfg(feature = "async")]
    drop(nex_datalink::async_io::async_channel(&interface, test_config()).unwrap());
    let before = resource_count();
    for _ in 0..1_000 {
        drop(channel(&interface, test_config()).unwrap());
        #[cfg(feature = "async")]
        drop(nex_datalink::async_io::async_channel(&interface, test_config()).unwrap());
    }
    let after = resource_count();
    eprintln!("resource count before={before}, after={after}");
    assert!(after <= before, "channel lifecycle leaked OS resources");
}

#[cfg(target_os = "linux")]
fn resource_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[cfg(windows)]
fn resource_count() -> usize {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut count = 0;
    // SAFETY: The current process pseudo-handle is valid and count is writable.
    assert_ne!(
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
        0
    );
    count as usize
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires raw-packet privileges; run with --test-threads=1"]
fn failed_channel_creation_does_not_leak_descriptors() {
    let mut interface = Interface::dummy();
    // AF_PACKET allocation succeeds before bind rejects this interface index.
    interface.index = u32::MAX;
    let before = resource_count();
    for _ in 0..1_000 {
        assert!(channel(&interface, test_config()).is_err());
        #[cfg(feature = "async")]
        assert!(nex_datalink::async_io::async_channel(&interface, test_config()).is_err());
    }
    assert_eq!(resource_count(), before);
}

#[cfg(all(feature = "pcap", any(target_os = "linux", windows)))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and capture privileges; use an external test watchdog"]
fn pcap_frame_send_and_capture() {
    let interface = test_interface();
    let nex_datalink::Channel::Ethernet(mut pcap_tx, mut pcap_rx) =
        nex_datalink::pcap::channel(&interface, (&test_config()).into()).unwrap()
    else {
        unreachable!()
    };
    let nex_datalink::Channel::Ethernet(mut tx, mut rx) =
        channel(&interface, test_config()).unwrap()
    else {
        unreachable!()
    };
    let outgoing = test_frame(&interface, 0x61);
    pcap_tx.send(&outgoing).unwrap().unwrap();
    receive_frame(&mut *rx, &outgoing);
    let incoming = test_frame(&interface, 0x62);
    tx.send(&incoming).unwrap().unwrap();
    receive_frame(&mut *pcap_rx, &incoming);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and NEX_TEST_PEER_INTERFACE on an isolated veth pair"]
fn linux_veth_layer3_fanout_and_timeout() {
    use nex_datalink::{Channel, FanoutOption, FanoutType};
    use std::time::{Duration, Instant};
    let interface = test_interface();
    let peer_name = std::env::var("NEX_TEST_PEER_INTERFACE").unwrap();
    let peer = get_interfaces()
        .into_iter()
        .find(|i| i.name == peer_name)
        .unwrap();
    let Channel::Ethernet(_, mut quiet_rx) = channel(&interface, test_config()).unwrap() else {
        unreachable!()
    };
    let start = Instant::now();
    assert_eq!(
        quiet_rx.next().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() >= Duration::from_millis(50));
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(quiet_rx);

    let config = test_config().with_channel_type(ChannelType::Layer3(0x0800));
    let Channel::Ethernet(_, mut rx) = channel(&peer, config).unwrap() else {
        unreachable!()
    };
    let mut destination = interface.clone();
    destination.mac_addr = peer.mac_addr;
    let Channel::Ethernet(mut tx, _) = channel(&destination, config).unwrap() else {
        unreachable!()
    };
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 203, 28, 1, 10, 203, 28, 2,
    ];
    tx.send(&packet).unwrap().unwrap();
    assert_eq!(
        rx.next().unwrap(),
        packet,
        "Layer3 must omit the Ethernet header"
    );
    drop((tx, rx));

    let config = test_config().with_linux_fanout(Some(FanoutOption::new(
        std::process::id() as u16,
        FanoutType::LoadBalance,
    )));
    let Channel::Ethernet(_, mut first) = channel(&interface, config).unwrap() else {
        unreachable!()
    };
    let Channel::Ethernet(_, mut second) = channel(&interface, config).unwrap() else {
        unreachable!()
    };
    let Channel::Ethernet(mut tx, _) = channel(&peer, test_config()).unwrap() else {
        unreachable!()
    };
    for sequence in 0..20u8 {
        let mut packet = test_frame(&peer, 0x63);
        packet[..6].copy_from_slice(&interface.mac_addr.unwrap().octets());
        packet[14] = sequence;
        tx.send(&packet).unwrap().unwrap();
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut counts = [0usize; 2];
    for (index, rx) in [&mut first, &mut second].into_iter().enumerate() {
        loop {
            match rx.next() {
                Ok(packet) => {
                    assert_eq!(packet[15], 0x63);
                    assert!(seen.insert(packet[14]), "fanout duplicated a frame");
                    counts[index] += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                Err(error) => panic!("fanout receive: {error}"),
            }
        }
    }
    assert_eq!(counts, [10, 10]);
    assert_eq!(seen.len(), 20);
}

#[cfg(all(feature = "async", any(target_os = "linux", windows)))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE; runs for 60 seconds; use a 120-second external watchdog"]
fn sustained_bidirectional_capture() {
    use futures::{StreamExt, future::poll_fn};
    use nex_datalink::async_io::{AsyncChannel, async_channel};
    use std::time::{Duration, Instant};
    let interface = test_interface();
    // Initialize the executor's per-thread parking resources before measuring
    // capture handles. A first block_on can allocate a persistent OS handle.
    let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
    let warmup = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        ready_tx.send(()).unwrap();
    });
    futures::executor::block_on(ready_rx).unwrap();
    warmup.join().unwrap();
    drop(channel(&interface, test_config()).unwrap());
    drop(async_channel(&interface, test_config()).unwrap());
    // Exercise actual I/O as well as opening handles: capture libraries can
    // initialize process-wide resources on the first send or receive.
    asynchronous_frame_send_and_capture();
    let warmed = resource_count();
    asynchronous_frame_send_and_capture();
    assert_eq!(
        resource_count(),
        warmed,
        "resources grew across warmup I/O cycles"
    );
    let baseline = resource_count();
    let AsyncChannel::Ethernet(mut async_tx, mut async_rx) =
        async_channel(&interface, test_config()).unwrap()
    else {
        unreachable!()
    };
    let nex_datalink::Channel::Ethernet(mut tx, mut rx) =
        channel(&interface, test_config()).unwrap()
    else {
        unreachable!()
    };
    let start = Instant::now();
    let mut count = 0u64;
    let mut live_resources = baseline;
    futures::executor::block_on(async {
        while start.elapsed() < Duration::from_secs(60) {
            let mut sent = test_frame(&interface, 0x64);
            sent[14..22].copy_from_slice(&count.to_be_bytes());
            poll_fn(|cx| async_tx.poll_send(cx, &sent)).await.unwrap();
            receive_frame(&mut *rx, &sent);
            let mut reply = sent.clone();
            reply[22] = 0x65;
            tx.send(&reply).unwrap().unwrap();
            loop {
                let received = async_rx.next().await.unwrap().unwrap();
                if received.starts_with(&reply) {
                    break;
                }
            }
            count += 1;
            if count == 1 {
                live_resources = resource_count();
            }
        }
    });
    let before_drop = resource_count();
    drop((async_tx, async_rx, tx, rx));
    let after = resource_count();
    eprintln!(
        "{count} bidirectional exchanges in {:?}; baseline={baseline}, live={live_resources}, before_drop={before_drop}, after_drop={after}",
        start.elapsed()
    );
    assert!(
        count >= 100,
        "insufficient progress under sustained traffic"
    );
    // Windows process housekeeping can replace ALPC ports with cached
    // thread/event handles during a minute-long run, even with no capture
    // channels open. Check the capture allocation delta at drop instead of
    // attributing unrelated process-wide housekeeping to this channel.
    #[cfg(windows)]
    {
        let capture_handles = live_resources
            .checked_sub(baseline)
            .expect("capture handle delta");
        assert!(
            capture_handles > 0,
            "capture allocated no observable handles"
        );
        assert!(
            before_drop.saturating_sub(after) >= capture_handles,
            "capture handles were not released on drop"
        );
    }
    #[cfg(target_os = "linux")]
    assert!(
        after <= baseline,
        "descriptors leaked after sustained capture"
    );
}
