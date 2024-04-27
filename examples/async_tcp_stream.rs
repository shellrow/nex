use nex_socket::AsyncTcpStream;
use std::{
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr},
    time::Duration,
};

fn main() {
    let ip_addr: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    println!("Connecting to 1.1.1.1:80 ...");
    async_io::block_on(async {
        match AsyncTcpStream::connect_timeout(
            &SocketAddr::new(ip_addr, 80),
            Duration::from_millis(200),
        )
        .await
        {
            Ok(stream) => {
                println!("Connected to 1.1.1.1:80");
                let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", ip_addr.to_string());
                println!("Sending data (HTTP Request) ...");
                match stream.write(req.as_bytes()).await {
                    Ok(n) => println!("{} bytes sent (payload)", n),
                    Err(e) => println!("{}", e),
                }
                let mut res = vec![0; 1024];
                println!("Receiving data ...");
                match stream.read(&mut res).await {
                    Ok(n) => {
                        println!("{} bytes received (HTTP Response):", n);
                        println!("----------------------------------------");
                        println!("{}", String::from_utf8_lossy(&res[..n]));
                        println!("----------------------------------------");
                    }
                    Err(e) => println!("{}", e),
                }
                println!("Closing socket ...");
                match stream.shutdown(Shutdown::Both).await {
                    Ok(_) => println!("Socket closed"),
                    Err(e) => println!("{}", e),
                }
            }
            Err(e) => println!("{}", e),
        }
    });
}
