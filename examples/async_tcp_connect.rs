use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use futures::stream::{self, StreamExt};
use nex_socket::{AsyncSocket, IpVersion, SocketOption, SocketType};
use nex_packet::ip::IpNextLevelProtocol;

fn main() {
    // List of destination.
    let dst_sockets = vec![
        "1.0.0.2:53",
        "1.0.0.3:53",
        "1.1.1.1:53",
        "1.1.1.3:53",
        "4.2.2.6:53",
        "8.0.7.0:53",
        "8.8.8.8:53",
        "77.88.8.1:53",
        "77.88.8.3:53",
        "77.88.8.88:53",
    ];
    let conn_timeout = Duration::from_millis(500);
    let concurrency: usize = 10;
    async_io::block_on(async {
        let fut = stream::iter(dst_sockets).for_each_concurrent(concurrency, |socket_addr_str| {
            async move {
                let socket_option = SocketOption {
                    ip_version: IpVersion::V4,
                    socket_type: SocketType::Stream,
                    protocol: Some(IpNextLevelProtocol::Tcp),
                    non_blocking: true,
                };
                let socket_addr: SocketAddr = SocketAddr::from_str(socket_addr_str).unwrap();
                match AsyncSocket::new_with_connect_timeout(socket_option, &socket_addr, conn_timeout) {
                    Ok(async_socket) => {
                        let local_socket_addr = async_socket.local_addr().await.unwrap();
                        let remote_socket_addr = async_socket.peer_addr().await.unwrap();
                        println!("Connected {} -> {}", local_socket_addr, remote_socket_addr);
                        match async_socket.shutdown(std::net::Shutdown::Both).await {
                            Ok(_) => {
                                println!("Connection closed ({} -> {})", local_socket_addr, remote_socket_addr);
                            }
                            Err(e) => {
                                println!("shutdown error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("connect error: {}", e);
                    }
                }
            }
        });
        fut.await;
    });
}