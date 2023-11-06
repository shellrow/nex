use crate::ethernet::EthernetHeader;
use crate::arp::ArpHeader;
use crate::ipv4::Ipv4Header;
use crate::ipv6::Ipv6Header;
use crate::tcp::TcpHeader;
use crate::udp::UdpHeader;
use crate::icmp::IcmpHeader;
use crate::icmpv6::Icmpv6Header;

/// Represents a data link layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatalinkLayer {
    pub ethernet: Option<EthernetHeader>,
    pub arp: Option<ArpHeader>,
}

/// Represents an IP layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpLayer {
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
}

/// Represents a transport layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportLayer {
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
}

/// Represents a packet frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The datalink layer.
    pub datalink: Option<DatalinkLayer>,
    /// The IP layer.
    pub ip: Option<IpLayer>,
    /// The transport layer.
    pub transport: Option<TransportLayer>,
    /// Rest of the packet that could not be parsed as a header. (Usually payload)
    pub payload: &'a [u8],
    packet: &'a [u8],
}

impl Frame<'_> {
    /// Return packet as a byte array.
    pub fn packet(&self) -> Vec<u8> {
        self.packet.to_vec()
    }
    /// Return packet length.
    pub fn packet_len(&self) -> usize {
        self.packet.len()
    }
}
