//! Simple TCP port scanner using AsyncTcpSocket
//!
//! Usage: async_tcp_socket <IP> <PORT1> <PORT2> ...

use nex_socket::tcp::{AsyncTcpSocket, TcpConfig};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = env::args().skip(1);
    let ip: IpAddr = args.next().expect("IP").parse().expect("ip");
    let ports: Vec<u16> = args.map(|p| p.parse().expect("port")).collect();

    let mut handles = Vec::new();
    for port in ports {
        let addr = SocketAddr::new(ip, port);
        handles.push(tokio::spawn(async move {
            let cfg = if ip.is_ipv4() { TcpConfig::v4_stream() } else { TcpConfig::v6_stream() };
            let sock = AsyncTcpSocket::from_config(&cfg).unwrap();
            match sock.connect_timeout(addr, Duration::from_millis(500)).await {
                Ok(_) => println!("Port {} is open", port),
                Err(e) => println!("Port {} is closed: {}", port, e),
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
