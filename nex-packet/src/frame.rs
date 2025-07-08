use bytes::Bytes;
use nex_core::mac::MacAddr;

use crate::{arp::{ArpHeader, ArpPacket}, ethernet::{EtherType, EthernetHeader, EthernetPacket}, icmp::{IcmpHeader, IcmpPacket}, icmpv6::{Icmpv6Header, Icmpv6Packet}, ip::IpNextProtocol, ipv4::{Ipv4Header, Ipv4Packet}, ipv6::{Ipv6Header, Ipv6Packet}, packet::Packet, tcp::{TcpHeader, TcpPacket}, udp::{UdpHeader, UdpPacket}};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DatalinkLayer {
    pub ethernet: Option<EthernetHeader>,
    pub arp: Option<ArpHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IpLayer {
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransportLayer {
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ParseOption {
    pub from_ip_packet: bool,
    pub offset: usize,
}

impl Default for ParseOption {
    fn default() -> Self {
        Self { from_ip_packet: false, offset: 0 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Frame {
    pub datalink: Option<DatalinkLayer>,
    pub ip: Option<IpLayer>,
    pub transport: Option<TransportLayer>,
    pub payload: Bytes,
    pub packet_len: usize,
}

impl Frame {
    pub fn from_buf(packet: &[u8], option: ParseOption) -> Option<Self> {
        let mut frame = Frame {
            datalink: None,
            ip: None,
            transport: None,
            payload: Bytes::new(),
            packet_len: packet.len(),
        };

        let ethernet_packet = if option.from_ip_packet {
            create_dummy_ethernet_packet(packet, option.offset)?
        } else {
            EthernetPacket::from_buf(packet)?
        };

        let ether_type = ethernet_packet.get_ethertype();
        let (ether_header, ether_payload) = ethernet_packet.into_parts();
        frame.datalink = Some(DatalinkLayer {
            ethernet: Some(ether_header),
            arp: None,
        });

        match ether_type {
            EtherType::Ipv4 => parse_ipv4_packet(ether_payload, &mut frame),
            EtherType::Ipv6 => parse_ipv6_packet(ether_payload, &mut frame),
            EtherType::Arp => parse_arp_packet(ether_payload, &mut frame),
            _ => {}
        }

        Some(frame)
    }
}

pub fn create_dummy_ethernet_packet(packet: &[u8], offset: usize) -> Option<EthernetPacket> {
    if offset >= packet.len() {
        return None;
    }

    let payload = &packet[offset..];

    let ethertype = if Ipv4Packet::from_buf(payload).is_some() {
        EtherType::Ipv4
    } else if Ipv6Packet::from_buf(payload).is_some() {
        EtherType::Ipv6
    } else {
        return None;
    };

    let header = EthernetHeader {
        destination: MacAddr::zero(),
        source: MacAddr::zero(),
        ethertype,
    };

    Some(EthernetPacket {
        header,
        payload: Bytes::copy_from_slice(payload),
    })
}

fn parse_arp_packet(packet: Bytes, frame: &mut Frame) {
    match ArpPacket::from_buf(&packet) {
        Some(arp_packet) => {
            if let Some(datalink) = &mut frame.datalink {
                datalink.arp = Some(arp_packet.header);
            }
        }
        None => {
            if let Some(datalink) = &mut frame.datalink {
                datalink.arp = None;
            }
            frame.payload = packet;
        }
    }
}

fn parse_ipv4_packet(packet: Bytes, frame: &mut Frame) {
    match Ipv4Packet::from_bytes(packet) {
        Some(ipv4_packet) => {
            let (header, payload) = ipv4_packet.into_parts();
            let proto = header.next_level_protocol;
            frame.ip = Some(IpLayer {
                ipv4: Some(header),
                ipv6: None,
                icmp: None,
                icmpv6: None,
            });
            match proto {
                IpNextProtocol::Tcp => {
                    parse_tcp_packet(payload, frame);
                }
                IpNextProtocol::Udp => {
                    parse_udp_packet(payload, frame);
                }
                IpNextProtocol::Icmp => {
                    parse_icmp_packet(payload, frame);
                }
                _ => {
                    frame.payload = payload;
                }
            }
        }
        None => {
            frame.ip = Some(IpLayer {
                ipv4: None,
                ipv6: None,
                icmp: None,
                icmpv6: None,
            });
        }
    }
}

fn parse_ipv6_packet(packet: Bytes, frame: &mut Frame) {
    match Ipv6Packet::from_bytes(packet) {
        Some(ipv6_packet) => {
            let (header, payload) = ipv6_packet.into_parts();
            let proto = header.next_header;
            frame.ip = Some(IpLayer {
                ipv4: None,
                ipv6: Some(header),
                icmp: None,
                icmpv6: None,
            });
            match proto {
                IpNextProtocol::Tcp => {
                    parse_tcp_packet(payload, frame);
                }
                IpNextProtocol::Udp => {
                    parse_udp_packet(payload, frame);
                }
                IpNextProtocol::Icmpv6 => {
                    parse_icmpv6_packet(payload, frame);
                }
                _ => {
                    frame.payload = payload;
                }
            }
        }
        None => {
            frame.ip = Some(IpLayer {
                ipv4: None,
                ipv6: None,
                icmp: None,
                icmpv6: None,
            });
        }
    }
}

fn parse_tcp_packet(packet: Bytes, frame: &mut Frame) {
    match TcpPacket::from_bytes(packet.clone()) {
        Some(tcp_packet) => {
            let (header, payload) = tcp_packet.into_parts();
            frame.transport = Some(TransportLayer {
                tcp: Some(header),
                udp: None,
            });
            frame.payload = payload;
        }
        None => {
            frame.transport = Some(TransportLayer {
                tcp: None,
                udp: None,
            });
            frame.payload = packet;
        }
    }
}

fn parse_udp_packet(packet: Bytes, frame: &mut Frame) {
    match UdpPacket::from_bytes(packet.clone()) {
        Some(udp_packet) => {
            let (header, payload) = udp_packet.into_parts();
            frame.transport = Some(TransportLayer {
                tcp: None,
                udp: Some(header),
            });
            frame.payload = payload;
        }
        None => {
            frame.transport = Some(TransportLayer {
                tcp: None,
                udp: None,
            });
            frame.payload = packet;
        }
    }
}

fn parse_icmp_packet(packet: Bytes, frame: &mut Frame) {
    match IcmpPacket::from_bytes(packet.clone()) {
        Some(icmp_packet) => {
            let (header, payload) = icmp_packet.into_parts();
            if let Some(ip) = &mut frame.ip {
                ip.icmp = Some(header);
            }
            frame.payload = payload;
        }
        None => {
            if let Some(ip) = &mut frame.ip {
                ip.icmp = None;
            }
            frame.payload = packet;
        }
    }
}

fn parse_icmpv6_packet(packet: Bytes, frame: &mut Frame) {
    match Icmpv6Packet::from_bytes(packet.clone()) {
        Some(icmpv6_packet) => {
            let (header, payload) = icmpv6_packet.into_parts();
            if let Some(ip) = &mut frame.ip {
                ip.icmpv6 = Some(header);
            }
            frame.payload = payload;
        }
        None => {
            if let Some(ip) = &mut frame.ip {
                ip.icmpv6 = None;
            }
            frame.payload = packet;
        }
    }
}
