use nex_socket::tls::socket::TlsClient;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

// connect to 1.1.1.1:443 using TLS and send a payload(HTTPS GET request)
fn main() {
    let native_certs = nex_socket::tls::certs::get_native_certs().unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(native_certs)
        .with_no_client_auth();

    // if you want to disable certificate verification
    //nex_socket::tls::danger::disable_certificate_verification(&mut config, rustls::crypto::ring::default_provider());

    // connect to 1.1.1.1:443 and send a payload(HTTPS GET request)
    let hostname = "1.1.1.1";
    let socket_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let stream: TcpStream = match TcpStream::connect(socket_addr.clone()) {
        Ok(s) => s,
        Err(e) => {
            println!("connect error: {}", e);
            return;
        }
    };
    match stream.set_read_timeout(Some(Duration::from_secs(1))) {
        Ok(_) => {}
        Err(e) => {
            println!("set_read_timeout error: {}", e);
            return;
        }
    }
    let mut tls_client = TlsClient::new(hostname.to_string(), stream, config).unwrap();
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
        hostname
    );

    match tls_client.write_all(req.as_bytes()) {
        Ok(_) => {
            println!("payload sent. {} bytes", req.len());
        }
        Err(e) => {
            println!("write_all error: {}", e);
            return;
        }
    }

    let mut res = Vec::new();
    match tls_client.read_to_end(&mut res) {
        Ok(_) => {}
        Err(e) => {
            println!("read_to_end error: {}", e);
            return;
        }
    }
    println!("response: {}", String::from_utf8_lossy(&res));
}
