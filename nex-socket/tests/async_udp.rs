#![cfg(feature = "async")]

use nex_socket::udp::AsyncUdpSocket;
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn converts_blocking_std_socket_and_receives_without_blocking_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = socket.local_addr().unwrap();
        let receiver = AsyncUdpSocket::from_std_socket(socket).unwrap();
        let sender =
            AsyncUdpSocket::from_std_socket(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        let send = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            sender.send_to(b"ping", target).await.unwrap();
        });
        let mut buffer = [0; 16];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..size], b"ping");
        send.await.unwrap();
    });
}
