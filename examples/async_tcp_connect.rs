use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use futures::stream::{self, StreamExt};
use nex_socket::AsyncSocket;

fn main() {
    // List of destination for TCP connect test.
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
    let conn_timeout = Duration::from_millis(300);
    let concurrency: usize = 10;
    let start_time = std::time::Instant::now();
    async_io::block_on(async {
        let fut = stream::iter(dst_sockets).for_each_concurrent(concurrency, |socket_addr_str| {
            async move {
                let socket_addr: SocketAddr = SocketAddr::from_str(socket_addr_str).unwrap();
                let conn_start_time = std::time::Instant::now();
                match AsyncSocket::new_with_async_connect_timeout(&socket_addr, conn_timeout).await {
                    Ok(async_socket) => {
                        let local_socket_addr = async_socket.local_addr().await.unwrap();
                        let remote_socket_addr = async_socket.peer_addr().await.unwrap();
                        println!("Connected {} -> {} in {}ms", local_socket_addr, remote_socket_addr, conn_start_time.elapsed().as_millis());
                        match async_socket.shutdown(std::net::Shutdown::Both).await {
                            Ok(_) => {
                                println!("Connection closed ({} -> {})", local_socket_addr, remote_socket_addr);
                            }
                            Err(e) => {
                                println!("shutdown error (for {}): {}", socket_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("connection error (for {}): {}", socket_addr, e);
                    }
                }
            }
        });
        fut.await;
    });
    println!("Total time: {}ms", start_time.elapsed().as_millis());
}
