//! Simple TCP connect using TcpSocket
//!
//! Usage: tcp_socket <TARGET IP> <PORT>

use nex_socket::tcp::TcpSocket;
use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};

fn main() -> std::io::Result<()> {
    let ip: IpAddr = env::args().nth(1).expect("IP").parse().expect("ip");
    let port: u16 = env::args()
        .nth(2)
        .unwrap_or_else(|| "80".into())
        .parse()
        .expect("port");
    let addr = SocketAddr::new(ip, port);

    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::v4_stream()?,
        SocketAddr::V6(_) => TcpSocket::v6_stream()?,
    };
    socket.connect(addr)?;
    let mut stream = socket.to_tcp_stream()?;

    let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", ip);
    stream.write_all(req.as_bytes())?;

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf)?;
    println!(
        "Received {} bytes:\n{}",
        n,
        String::from_utf8_lossy(&buf[..n])
    );
    Ok(())
}
