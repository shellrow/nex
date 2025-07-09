//! UDP echo using UdpSocket
//!
//! This example starts a small UDP echo server and client using nex-socket.

use nex_socket::udp::{UdpConfig, UdpSocket};
use std::thread;

fn main() -> std::io::Result<()> {
    let server_cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        ..Default::default()
    };
    let server = UdpSocket::from_config(&server_cfg)?;
    let server_addr = server.local_addr()?;

    let handle = thread::spawn(move || -> std::io::Result<()> {
        let mut buf = [0u8; 512];
        let (n, peer) = server.recv_from(&mut buf)?;
        println!("Server received: {}", String::from_utf8_lossy(&buf[..n]));
        server.send_to(&buf[..n], peer)?;
        Ok(())
    });

    let client = UdpSocket::v4_dgram()?;
    let msg = b"hello via udp";
    client.send_to(msg, server_addr)?;
    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf)?;
    println!("Client received: {}", String::from_utf8_lossy(&buf[..n]));

    handle.join().unwrap()?;
    Ok(())
}
