use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};

use nex_socket::{Socket, IpVersion, SocketOption, SocketType};
use nex_packet::ip::IpNextLevelProtocol;

fn main() {
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Stream,
        protocol: Some(IpNextLevelProtocol::Tcp),
        non_blocking: false,
    };
    let socket = Socket::new(socket_option).unwrap();
    println!("Socket created");
    println!("Connecting to 1.1.1.1:80 ...");
    let ip_addr: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    match socket.connect(&SocketAddr::new(ip_addr, 80)) {
        Ok(_) => {
            println!("Connected to 1.1.1.1:80");
            let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", ip_addr.to_string());
            println!("Sending data (HTTP Request) ...");
            match socket.write(req.as_bytes()) {
                Ok(n) => println!("{} bytes sent (payload)", n),
                Err(e) => println!("{}", e),
            }
            let mut res = vec![0; 1024];
            println!("Receiving data ...");
            
            match socket.read(&mut res) {
                Ok(n) => {
                    println!("{} bytes received (HTTP Response):", n);
                    println!("----------------------------------------");
                    println!("{}", String::from_utf8_lossy(&res[..n]));
                    println!("----------------------------------------");
                },
                Err(e) => println!("{}", e),
            }
            
            println!("Closing socket ...");
            match socket.shutdown(Shutdown::Both) {
                Ok(_) => println!("Socket closed"),
                Err(e) => println!("{}", e),
            }
        },
        Err(e) => println!("{}", e),
    }
}
