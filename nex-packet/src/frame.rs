use bytes::Bytes;
use nex_core::mac::MacAddr;

use crate::{
    arp::{ArpHeader, ArpPacket},
    ethernet::{EtherType, EthernetHeader, EthernetPacket},
    icmp::{IcmpHeader, IcmpPacket},
    icmpv6::{Icmpv6Header, Icmpv6Packet},
    ip::IpNextProtocol,
    ipv4::{Ipv4Header, Ipv4Packet},
    ipv6::{Ipv6Header, Ipv6Packet},
    packet::Packet,
    parse::ParseError,
    tcp::{TcpHeader, TcpPacket},
    udp::{UdpHeader, UdpPacket},
};

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
        Self {
            from_ip_packet: false,
            offset: 0,
        }
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
    /// Parse a frame from a raw buffer.
    ///
    /// Unknown or currently unsupported payloads are preserved in `payload`
    /// so callers can still inspect the raw bytes.
    pub fn from_buf(packet: &[u8], option: ParseOption) -> Option<Self> {
        Self::try_from_buf(packet, option).ok()
    }

    /// Parse a frame and return a structured error on failure.
    pub fn try_from_buf(packet: &[u8], option: ParseOption) -> Result<Self, ParseError> {
        parse_frame_from_bytes(Bytes::copy_from_slice(packet), option, false)
    }

    /// Parse a frame from owned bytes while preserving payload slices when possible.
    pub fn try_from_bytes(packet: Bytes, option: ParseOption) -> Result<Self, ParseError> {
        parse_frame_from_bytes(packet, option, false)
    }

    /// Parse a frame using validation-oriented strict IP parsing.
    pub fn try_from_buf_strict(packet: &[u8], option: ParseOption) -> Result<Self, ParseError> {
        parse_frame_from_bytes(Bytes::copy_from_slice(packet), option, true)
    }

    /// Parse a frame from owned bytes using validation-oriented strict IP parsing.
    pub fn try_from_bytes_strict(packet: Bytes, option: ParseOption) -> Result<Self, ParseError> {
        parse_frame_from_bytes(packet, option, true)
    }

    /// Parse a frame using validation-oriented strict IP parsing.
    pub fn from_buf_strict(packet: &[u8], option: ParseOption) -> Option<Self> {
        Self::try_from_buf_strict(packet, option).ok()
    }
}

/// Borrowed frame view for zero-copy packet inspection on hot paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameView<'a> {
    pub datalink: Option<DatalinkLayer>,
    pub ip: Option<IpLayer>,
    pub transport: Option<TransportLayer>,
    pub payload: &'a [u8],
    pub packet_len: usize,
}

impl<'a> FrameView<'a> {
    /// Parse a frame view without allocating payload storage.
    pub fn from_buf(packet: &'a [u8], option: ParseOption) -> Option<Self> {
        Self::try_from_buf(packet, option).ok()
    }

    /// Parse a frame view and return a structured error on failure.
    pub fn try_from_buf(packet: &'a [u8], option: ParseOption) -> Result<Self, ParseError> {
        let offset = option.offset;
        let from_ip_packet = option.from_ip_packet;
        let frame = Frame::try_from_buf(packet, option)?;
        let payload = find_payload_slice(packet, &frame, offset, from_ip_packet);
        Ok(FrameView {
            datalink: frame.datalink,
            ip: frame.ip,
            transport: frame.transport,
            payload,
            packet_len: frame.packet_len,
        })
    }
}

pub fn create_dummy_ethernet_packet(packet: &[u8], offset: usize) -> Option<EthernetPacket> {
    if offset >= packet.len() {
        return None;
    }

    let payload = &packet[offset..];

    let ethertype = if is_likely_ipv4_packet(payload) {
        EtherType::Ipv4
    } else if is_likely_ipv6_packet(payload) {
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

fn is_likely_ipv4_packet(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let version = packet[0] >> 4;
    let header_length = (packet[0] & 0x0f) as usize;
    version == 4 && header_length >= 5 && header_length * 4 <= packet.len()
}

fn is_likely_ipv6_packet(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    (packet[0] >> 4) == 6
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

fn parse_ipv4_packet(packet: Bytes, frame: &mut Frame, strict: bool) -> Result<(), ParseError> {
    let parsed = if strict {
        Ipv4Packet::try_from_bytes_strict(packet)
    } else {
        Ipv4Packet::try_from_bytes(packet)
    };
    match parsed {
        Ok(ipv4_packet) => {
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
            Ok(())
        }
        Err(err) if strict => Err(err),
        Err(_) => {
            frame.ip = Some(IpLayer {
                ipv4: None,
                ipv6: None,
                icmp: None,
                icmpv6: None,
            });
            Ok(())
        }
    }
}

fn parse_ipv6_packet(packet: Bytes, frame: &mut Frame, strict: bool) -> Result<(), ParseError> {
    let parsed = if strict {
        Ipv6Packet::try_from_bytes_strict(packet)
    } else {
        Ipv6Packet::try_from_bytes(packet)
    };
    match parsed {
        Ok(ipv6_packet) => {
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
            Ok(())
        }
        Err(err) if strict => Err(err),
        Err(_) => {
            frame.ip = Some(IpLayer {
                ipv4: None,
                ipv6: None,
                icmp: None,
                icmpv6: None,
            });
            Ok(())
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

fn parse_frame_from_bytes(
    packet: Bytes,
    option: ParseOption,
    strict: bool,
) -> Result<Frame, ParseError> {
    let packet_len = packet.len();
    let mut frame = Frame {
        datalink: None,
        ip: None,
        transport: None,
        payload: Bytes::new(),
        packet_len,
    };

    let ethernet_packet = if option.from_ip_packet {
        create_dummy_ethernet_packet(&packet, option.offset).ok_or(ParseError::Malformed {
            context: "Frame dummy Ethernet classification",
        })?
    } else {
        EthernetPacket::try_from_bytes(packet)?
    };

    let ether_type = ethernet_packet.get_ethertype();
    let (ether_header, ether_payload) = ethernet_packet.into_parts();
    frame.datalink = Some(DatalinkLayer {
        ethernet: Some(ether_header),
        arp: None,
    });

    match ether_type {
        EtherType::Ipv4 => parse_ipv4_packet(ether_payload, &mut frame, strict)?,
        EtherType::Ipv6 => parse_ipv6_packet(ether_payload, &mut frame, strict)?,
        EtherType::Arp => parse_arp_packet(ether_payload, &mut frame),
        _ => frame.payload = ether_payload,
    }

    Ok(frame)
}

fn find_payload_slice<'a>(
    packet: &'a [u8],
    frame: &Frame,
    offset: usize,
    from_ip_packet: bool,
) -> &'a [u8] {
    let start = if from_ip_packet { offset } else { 14 };
    let available = packet.get(start..).unwrap_or(&[]);
    let payload_len = frame.payload.len();
    if payload_len > available.len() {
        return &[];
    }
    &available[available.len() - payload_len..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::ETHERNET_HEADER_LEN;

    #[test]
    fn frame_preserves_unknown_ethertype_payload() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut raw = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
        raw[12] = 0x88;
        raw[13] = 0xb5;
        raw[ETHERNET_HEADER_LEN..].copy_from_slice(&payload);

        let frame = Frame::from_buf(&raw, ParseOption::default()).expect("frame");

        assert_eq!(frame.payload, Bytes::from(payload.to_vec()));
        assert!(frame.ip.is_none());
        assert!(frame.transport.is_none());
    }

    #[test]
    fn frame_keeps_known_ethertype_parsing_behavior() {
        let mut raw = vec![0u8; ETHERNET_HEADER_LEN + 20 + 8 + 4];
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45;
        raw[15] = 0x00;
        raw[16] = 0x00;
        raw[17] = 0x20;
        raw[18] = 0x00;
        raw[19] = 0x01;
        raw[20] = 0x00;
        raw[21] = 0x00;
        raw[22] = 64;
        raw[23] = IpNextProtocol::Udp.value();
        raw[24] = 0;
        raw[25] = 0;
        raw[26] = 192;
        raw[27] = 0;
        raw[28] = 2;
        raw[29] = 1;
        raw[30] = 198;
        raw[31] = 51;
        raw[32] = 100;
        raw[33] = 2;
        raw[34] = 0x04;
        raw[35] = 0xd2;
        raw[36] = 0x00;
        raw[37] = 0x35;
        raw[38] = 0x00;
        raw[39] = 0x0c;
        raw[40] = 0x00;
        raw[41] = 0x00;
        raw[42..46].copy_from_slice(&[1, 2, 3, 4]);

        let frame = Frame::from_buf(&raw, ParseOption::default()).expect("frame");

        assert_eq!(
            frame
                .ip
                .as_ref()
                .and_then(|ip| ip.ipv4.as_ref())
                .map(|h| h.version),
            Some(4)
        );
        assert_eq!(
            frame
                .transport
                .as_ref()
                .and_then(|tr| tr.udp.as_ref())
                .map(|h| h.destination),
            Some(53)
        );
        assert_eq!(frame.payload, Bytes::from_static(&[1, 2, 3, 4]));
    }

    #[test]
    fn dummy_ethernet_packet_uses_lightweight_ip_detection() {
        let ipv4 = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0,
            1,
        ];
        let packet = create_dummy_ethernet_packet(&ipv4, 0).expect("dummy ethernet");
        assert_eq!(packet.header.ethertype, EtherType::Ipv4);
        assert_eq!(packet.payload, Bytes::from(ipv4.to_vec()));
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
