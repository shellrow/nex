#[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and permission to bind a device"]
fn udp_device_binding() {
    let interface =
        std::env::var("NEX_TEST_INTERFACE").expect("set NEX_TEST_INTERFACE to a test interface");
    let config = nex_socket::udp::UdpConfig::new()
        .with_bind("0.0.0.0:0".parse().expect("bind address"))
        .with_bind_device(interface);

    let socket =
        nex_socket::udp::UdpSocket::from_config(&config).expect("bind UDP socket to device");
    drop(socket);
}

#[test]
#[ignore = "requires raw-socket privileges"]
fn raw_icmp_socket_creation() {
    let config = nex_socket::icmp::IcmpConfig::new(nex_socket::icmp::IcmpKind::V4)
        .with_sock_type(nex_socket::icmp::IcmpSocketType::Raw);
    let socket = nex_socket::icmp::IcmpSocket::new(&config).expect("create raw ICMP socket");
    drop(socket);
}

#[test]
#[ignore = "requires raw-socket privileges"]
fn raw_tcp_socket_creation() {
    let socket = nex_socket::tcp::TcpSocket::raw_v4().expect("create raw TCP socket");
    drop(socket);
}
