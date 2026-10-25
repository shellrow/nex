//! Opt-in live validation through the public nex facade.
#![cfg(all(windows, feature = "winptap"))]

use nex::datalink::{RawReceiver, winptap};
use nex::net::interface::{Interface, get_interfaces};
use std::{
    io,
    time::{Duration, Instant},
};

fn interface() -> Interface {
    let name =
        std::env::var("NEX_TEST_INTERFACE").expect("set NEX_TEST_INTERFACE to the OS adapter GUID");
    get_interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .expect("requested OS interface is present")
}

fn config(backend: winptap::Backend) -> winptap::Config {
    let mut config = winptap::Config::default();
    config.backend = backend;
    config.queue_capacity = 8;
    config.read_timeout = Some(Duration::from_millis(100));
    config
}

#[test]
#[ignore = "requires administrator, NEX_TEST_INTERFACE, and incoming UDP fixture; see docs/WINPTAP.md"]
fn receive_controlled_ethernet_through_facade() {
    let interface = interface();
    // Keep the destination port open without changing firewall/network settings.
    let _listener = std::net::UdpSocket::bind("0.0.0.0:48932").unwrap();
    let marker = b"nex-winptap-controlled-fixture-v1";
    for backend in [winptap::Backend::Pktmon, winptap::Backend::NativeIoctl] {
        let receiver = winptap::open(&interface, config(backend)).unwrap();
        // Move the real receiver across threads and use the actual trait object.
        std::thread::spawn(move || {
            let mut receiver = receiver;
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut found = false;
            while Instant::now() < deadline {
                let raw: &mut dyn RawReceiver = &mut receiver;
                match raw.next() {
                    Ok(frame) => {
                        if frame.len() >= 14
                            && frame.windows(marker.len()).any(|window| window == marker)
                        {
                            assert_eq!(&frame[12..14], &[8, 0]);
                            found = true;
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => (),
                    Err(error) => panic!("receive failed: {error}"),
                }
            }
            assert!(
                found,
                "controlled IPv4/UDP Ethernet fixture not observed with {backend:?}"
            );
            receiver.stop().unwrap();
            let mut drained = 0;
            loop {
                match receiver.next() {
                    Ok(_) => drained += 1,
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                        break;
                    }
                }
            }
            assert!(drained <= 8);
            println!(
                "{backend:?}: fixture received, drained {drained}, {:?}",
                receiver.statistics()
            );
            receiver.stop().unwrap();
        })
        .join()
        .unwrap();
    }
}

#[test]
#[ignore = "requires administrator and NEX_TEST_INTERFACE; run sequentially"]
fn repeated_stop_cancel_drop() {
    let interface = interface();
    for backend in [winptap::Backend::Pktmon, winptap::Backend::NativeIoctl] {
        for cycle in 0..12 {
            let receiver = winptap::open(&interface, config(backend)).unwrap();
            let token = receiver.cancellation_token();
            std::thread::spawn(move || {
                let mut receiver = receiver;
                match cycle % 3 {
                    0 => receiver.stop().unwrap(),
                    1 => {
                        std::thread::spawn(move || token.cancel()).join().unwrap();
                        let error = receiver.next().unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                        assert_eq!(
                            error.get_ref().unwrap().downcast_ref::<winptap::Error>(),
                            Some(&winptap::Error::Cancelled)
                        );
                        receiver.stop().unwrap();
                    }
                    _ => (), // Drop joins a running capture's owner thread.
                }
            })
            .join()
            .unwrap();
        }
    }
}

#[cfg(feature = "async")]
#[test]
#[ignore = "requires administrator, NEX_TEST_INTERFACE, and incoming UDP fixture; see docs/WINPTAP.md"]
fn async_receive_cancel_and_drop_without_tokio() {
    use futures::{StreamExt, executor::block_on};
    let interface = interface();
    let _listener = std::net::UdpSocket::bind("0.0.0.0:48932").unwrap();
    let marker = b"nex-winptap-controlled-fixture-v1";
    for backend in [winptap::Backend::Pktmon, winptap::Backend::NativeIoctl] {
        let mut config = config(backend);
        config.read_timeout = None;
        let mut receiver = winptap::open_async(&interface, config.clone()).unwrap();
        let token = receiver.cancellation_token();
        let (done, finished) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if matches!(
                finished.recv_timeout(Duration::from_secs(15)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                token.cancel();
            }
        });
        block_on(async {
            let raw: &mut dyn nex::datalink::async_io::AsyncRawReceiver = &mut receiver;
            loop {
                let frame = raw
                    .next()
                    .await
                    .expect("stream ended before fixture")
                    .expect("receive fixture before watchdog");
                if frame.len() >= 14 && frame.windows(marker.len()).any(|window| window == marker) {
                    assert_eq!(&frame[12..14], &[8, 0]);
                    break;
                }
            }
        });
        done.send(()).unwrap();
        watchdog.join().unwrap();
        let token = receiver.cancellation_token();
        std::thread::spawn(move || token.cancel()).join().unwrap();
        assert_eq!(
            block_on(receiver.next()).unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(block_on(receiver.next()).is_none());
        receiver.close().unwrap();
        for cycle in 0..12 {
            let mut receiver = winptap::open_async(&interface, config.clone()).unwrap();
            if cycle % 2 == 0 {
                receiver.close().unwrap();
            }
            drop(receiver);
        }
        println!(
            "{backend:?}: runtime-independent async receive, cancellation, and 12 close/drop cycles passed"
        );
    }
}
