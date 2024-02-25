use nex_packet::ethernet::ETHERNET_HEADER_LEN;
use nex_packet::ipv4::IPV4_HEADER_LEN;
use nex_packet::ipv6::IPV6_HEADER_LEN;
use nex_packet::tcp::TCP_MIN_DATA_OFFSET;
use nex_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TCP_HEADER_LEN};
use nex_packet::Packet;
use std::net::{IpAddr, SocketAddr};

/// Default TCP Option Length.
pub const TCP_DEFAULT_OPTION_LEN: usize = 12;
/// Default TCP Source Port.
pub const DEFAULT_SRC_PORT: u16 = 53443;
/// TCP (IPv4) Minimum Packet Length.
pub const TCPV4_MINIMUM_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
/// TCP (IPv4) Default Packet Length.
pub const TCPV4_DEFAULT_PACKET_LEN: usize =
    ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN;
/// TCP (IPv4) Minimum IP Packet Length.
pub const TCPV4_MINIMUM_IP_PACKET_LEN: usize = IPV4_HEADER_LEN + TCP_HEADER_LEN;
/// TCP (IPv4) Default IP Packet Length.
pub const TCPV4_DEFAULT_IP_PACKET_LEN: usize =
    IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN;
/// TCP (IPv6) Minimum Packet Length.
pub const TCPV6_MINIMUM_PACKET_LEN: usize = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;
/// TCP (IPv6) Default Packet Length.
pub const TCPV6_DEFAULT_PACKET_LEN: usize =
    ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN;
/// TCP (IPv6) Minimum IP Packet Length.
pub const TCPV6_MINIMUM_IP_PACKET_LEN: usize = IPV6_HEADER_LEN + TCP_HEADER_LEN;
/// TCP (IPv6) Default IP Packet Length.
pub const TCPV6_DEFAULT_IP_PACKET_LEN: usize =
    IPV6_HEADER_LEN + TCP_HEADER_LEN + TCP_DEFAULT_OPTION_LEN;

/// Get the length of TCP options from TCP data offset.
pub fn get_tcp_options_length(data_offset: u8) -> usize {
    if data_offset > 5 {
        data_offset as usize * 4 - TCP_HEADER_LEN
    } else {
        0
    }
}

/// Get the TCP data offset from TCP options.
pub fn get_tcp_data_offset(opstions: Vec<TcpOption>) -> u8 {
    let mut total_size: u8 = 0;
    for opt in opstions {
        total_size += opt.kind().size() as u8;
    }
    if total_size % 4 == 0 {
        total_size / 4 + TCP_MIN_DATA_OFFSET
    } else {
        total_size / 4 + TCP_MIN_DATA_OFFSET + 1
    }
}

pub(crate) fn build_tcp_packet(
    tcp_packet: &mut MutableTcpPacket,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) {
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&[
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]);
    tcp_packet.set_flags(TcpFlags::SYN);
    match src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                let checksum =
                    nex_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                tcp_packet.set_checksum(checksum);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ip) => match dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ip) => {
                let checksum =
                    nex_packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                tcp_packet.set_checksum(checksum);
            }
        },
    }
}

/// TCP Packet Builder.
#[derive(Clone, Debug)]
pub struct TcpPacketBuilder {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port.
    pub dst_port: u16,
    /// Window size.
    pub window: u16,
    /// TCP flags.
    pub flags: u8,
    /// TCP options.
    pub options: Vec<TcpOption>,
    /// TCP payload.
    pub payload: Vec<u8>,
}

impl TcpPacketBuilder {
    /// Constructs a new TcpPacketBuilder from Source SocketAddr and Destination SocketAddr with default options.
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr) -> TcpPacketBuilder {
        TcpPacketBuilder {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dst_ip: dst_addr.ip(),
            dst_port: dst_addr.port(),
            window: 64240,
            flags: TcpFlags::SYN,
            options: vec![
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ],
            payload: vec![],
        }
    }
    /// Build a TCP packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let data_offset = get_tcp_data_offset(self.options.clone());
        let tcp_options_len = get_tcp_options_length(data_offset);
        let mut buffer: Vec<u8> = vec![0; TCP_HEADER_LEN + tcp_options_len + self.payload.len()];
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer).unwrap();
        tcp_packet.set_source(self.src_port);
        tcp_packet.set_destination(self.dst_port);
        tcp_packet.set_window(self.window);
        tcp_packet.set_data_offset(data_offset);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_sequence(0);
        tcp_packet.set_flags(self.flags);
        tcp_packet.set_options(&self.options);
        if self.payload.len() > 0 {
            tcp_packet.set_payload(&self.payload);
        }
        match self.src_ip {
            IpAddr::V4(src_ip) => match self.dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum = nex_packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &src_ip,
                        &dst_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                }
                IpAddr::V6(_) => {}
            },
            IpAddr::V6(src_ip) => match self.dst_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(dst_ip) => {
                    let checksum = nex_packet::tcp::ipv6_checksum(
                        &tcp_packet.to_immutable(),
                        &src_ip,
                        &dst_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                }
            },
        }
        tcp_packet.packet().to_vec()
    }
}
