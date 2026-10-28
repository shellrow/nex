//! Simple IPv4 ping scanner using AsyncIcmpSocket
//!
//! Usage: async_icmp_socket <PREFIX>
//! Example: async_icmp_socket 192.168.1

use bytes::Bytes;
use nex::net::interface::{Interface, get_interfaces};
use nex_packet::builder::icmp::IcmpPacketBuilder;
use nex_packet::icmp::echo_reply::EchoReplyPacket;
use nex_packet::icmp::{self, IcmpPacket, IcmpType};
use nex_packet::ipv4::Ipv4Packet;
use nex_packet::packet::Packet;
use nex_socket::icmp::{AsyncIcmpSocket, IcmpConfig, IcmpKind};
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let prefix = env::args().nth(1).expect("prefix like 192.168.1");
    let parts: Vec<u8> = prefix.split('.').map(|s| s.parse().expect("num")).collect();
    assert!(parts.len() == 3, "prefix must be a.b.c");

    let interface = match env::args().nth(2) {
        Some(name) => get_interfaces()
            .into_iter()
            .find(|i| i.name == name)
            .expect("interface not found"),
        None => Interface::default().expect("default interface"),
    };

    let src_ip = interface
        .ipv4
        .first()
        .map(|v| v.addr())
        .expect("No IPv4 address on interface");

    let config = IcmpConfig::new(IcmpKind::V4);
    let socket = Arc::new(AsyncIcmpSocket::new(&config).await.unwrap());

    // Datagram ICMP sockets may rewrite identifiers. Match the source and
    // sequence instead, registering each request before it is sent.
    let replies = Arc::new(Mutex::new(HashMap::new()));

    // Receiver task
    let socket_clone = socket.clone();
    let received = replies.clone();

    let receiver = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((n, from)) = socket_clone.recv_from(&mut buf).await {
                println!("Received {} bytes from {}", n, from.ip());
                let payload = if buf.first().is_some_and(|byte| byte >> 4 == 4) {
                    let Ok(ipv4) = Ipv4Packet::try_from_buf(&buf[..n]) else {
                        continue;
                    };
                    ipv4.payload()
                } else {
                    Bytes::copy_from_slice(&buf[..n])
                };
                if let Ok(packet) = IcmpPacket::try_from_bytes(payload)
                    && let Ok(reply) = EchoReplyPacket::try_from(packet)
                    && reply.payload.as_ref() == b"ping"
                    && received
                        .lock()
                        .await
                        .remove(&(from.ip(), reply.sequence_number))
                        .is_some()
                {
                    println!(
                        "EchoReply from {}: ID: {}, Seq: {}",
                        from.ip(),
                        reply.identifier,
                        reply.sequence_number
                    );
                }
            }
        }
    });

    let mut handles = Vec::new();
    for i in 1u8..=254 {
        let addr = Ipv4Addr::new(parts[0], parts[1], parts[2], i);
        let id = std::process::id() as u16;
        let seq = u16::from(i);
        let socket = socket.clone();
        let replies = replies.clone();

        handles.push(tokio::spawn(async move {
            let pkt = IcmpPacketBuilder::new(src_ip, addr)
                .icmp_type(IcmpType::EchoRequest)
                .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
                .payload(Bytes::from_static(b"ping"))
                .echo_fields(id, seq)
                .to_bytes()
                .expect("valid ICMP packet");
            let target = SocketAddr::new(IpAddr::V4(addr), 0);
            {
                let mut lock = replies.lock().await;
                lock.insert((target.ip(), seq), addr);
            }
            if let Err(error) = socket.send_to(&pkt, target).await {
                replies.lock().await.remove(&(target.ip(), seq));
                eprintln!("Failed to send to {addr}: {error}");
                return;
            }
            time::sleep(Duration::from_millis(500)).await;
            let mut lock = replies.lock().await;
            if lock.remove(&(target.ip(), seq)).is_some() {
                println!("{} is not responding", addr);
            }
        }));
    }

    for h in handles {
        h.await?;
    }
    receiver.abort();
    Ok(())
}
