//! Simple IPv4 ping scanner using AsyncIcmpSocket
//!
//! Usage: async_icmp_socket <PREFIX>
//! Example: async_icmp_socket 192.168.1

use bytes::Bytes;
use nex::net::interface::{get_interfaces, Interface};
use nex_packet::builder::icmp::IcmpPacketBuilder;
use nex_packet::icmp::echo_reply::EchoReplyPacket;
use nex_packet::icmp::{self, IcmpPacket, IcmpType};
use nex_packet::ipv4::Ipv4Packet;
use nex_packet::packet::Packet;
use nex_socket::icmp::{AsyncIcmpSocket, IcmpConfig, IcmpKind};
use rand::{thread_rng, Rng};
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
        .get(0)
        .map(|v| v.addr())
        .expect("No IPv4 address on interface");

    let config = IcmpConfig::new(IcmpKind::V4);
    let socket = Arc::new(AsyncIcmpSocket::new(&config).await.unwrap());

    // map from (id, seq) to target IP
    let replies = Arc::new(Mutex::new(HashMap::new()));

    // Receiver task
    let socket_clone = socket.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((n, from)) = socket_clone.recv_from(&mut buf).await {
                println!("Received {} bytes from {}", n, from.ip());
                if let Some(ipv4_packet) = Ipv4Packet::from_buf(&buf[..n]) {
                    if ipv4_packet.header.next_level_protocol
                        == nex_packet::ip::IpNextProtocol::Icmp
                    {
                        if let Some(icmp_packet) = IcmpPacket::from_bytes(ipv4_packet.payload()) {
                            println!(
                                "\t{:?} from: {:?} to {:?}, TTL: {}",
                                icmp_packet.header.icmp_type,
                                ipv4_packet.header.source,
                                ipv4_packet.header.destination,
                                ipv4_packet.header.ttl
                            );
                            match EchoReplyPacket::try_from(icmp_packet) {
                                Ok(reply) => {
                                    println!(
                                        "\tID: {}, Seq: {}",
                                        reply.identifier, reply.sequence_number
                                    );
                                }
                                Err(_) => {
                                    println!("\tReceived non-echo-reply ICMP packet");
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let mut handles = Vec::new();
    for i in 1u8..=254 {
        let addr = Ipv4Addr::new(parts[0], parts[1], parts[2], i);
        let id: u16 = thread_rng().gen();
        let seq: u16 = 1;
        let socket = socket.clone();
        let replies = replies.clone();

        handles.push(tokio::spawn(async move {
            let pkt = IcmpPacketBuilder::new(src_ip, addr)
                .icmp_type(IcmpType::EchoRequest)
                .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
                .echo_fields(id, seq)
                .payload(Bytes::from_static(b"ping"))
                .to_bytes();
            let target = SocketAddr::new(IpAddr::V4(addr), 0);
            let _ = socket.send_to(&pkt, target).await;
            {
                let mut lock = replies.lock().await;
                lock.insert((id, seq), addr);
            }
            time::sleep(Duration::from_millis(500)).await;
            let mut lock = replies.lock().await;
            if lock.remove(&(id, seq)).is_some() {
                // already handled in receiver
            } else {
                println!("{} is not responding", addr);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
