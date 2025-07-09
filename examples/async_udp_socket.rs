//! UDP echo using AsyncUdpSocket
//!
//! This example starts a small UDP echo server and client using nex-socket and Tokio.
//!
//! It will send a single UDP datagram to the server and print the echoed reply.

use nex_socket::udp::{AsyncUdpSocket, UdpConfig};
use tokio::task;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server_cfg = UdpConfig { bind_addr: Some("127.0.0.1:0".parse().unwrap()), ..Default::default() };
    let server = AsyncUdpSocket::from_config(&server_cfg)?;
    let server_addr = server.local_addr()?;

    let handle = task::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, peer) = server.recv_from(&mut buf).await?;
        println!("Server received: {}", String::from_utf8_lossy(&buf[..n]));
        server.send_to(&buf[..n], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let client = AsyncUdpSocket::v4_dgram()?;
    let msg = b"hello via async udp";
    client.send_to(msg, server_addr).await?;
    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf).await?;
    println!("Client received: {}", String::from_utf8_lossy(&buf[..n]));

    handle.await??;
    Ok(())
}
