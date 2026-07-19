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
    parse::{ParseError, ParseMode},
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
#[derive(Default)]
pub struct ParseOption {
    pub from_ip_packet: bool,
    pub offset: usize,
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

/// Allocation-free borrowed slices for each decoded frame layer.
///
/// This view identifies protocol boundaries without constructing owned packet
/// headers. Use the protocol-specific parser for decoded fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameSlice<'a> {
    /// Complete captured input.
    pub packet: &'a [u8],
    /// Link-layer header, when the input includes one.
    pub datalink: Option<&'a [u8]>,
    /// IP or ARP header, including variable-length options/extensions.
    pub network: Option<&'a [u8]>,
    /// TCP, UDP, ICMP, or ICMPv6 header.
    pub transport: Option<&'a [u8]>,
    /// Bytes after the last recognized header.
    pub payload: &'a [u8],
    /// Decoded Ethernet type when available.
    pub ethertype: Option<EtherType>,
    /// Decoded IP next-header value when available.
    pub ip_protocol: Option<IpNextProtocol>,
}

impl<'a> FrameSlice<'a> {
    /// Parse layer boundaries without copying or allocating packet bytes.
    pub fn try_from_buf(packet: &'a [u8], option: ParseOption) -> Result<Self, ParseError> {
        let (datalink, ethertype, network_bytes) = if option.from_ip_packet {
            let network_bytes = packet
                .get(option.offset..)
                .ok_or(ParseError::InvalidLength {
                    context: "frame IP offset",
                    value: option.offset,
                })?;
            let ethertype = match network_bytes.first().map(|byte| byte >> 4) {
                Some(4) => EtherType::Ipv4,
                Some(6) => EtherType::Ipv6,
                _ => {
                    return Err(ParseError::Malformed {
                        context: "frame IP version",
                    });
                }
            };
            (None, ethertype, network_bytes)
        } else {
            if packet.len() < 14 {
                return Err(ParseError::BufferTooShort {
                    context: "Ethernet frame",
                    minimum: 14,
                    actual: packet.len(),
                });
            }
            (
                Some(&packet[..14]),
                EtherType::new(u16::from_be_bytes([packet[12], packet[13]])),
                &packet[14..],
            )
        };

        let mut view = Self {
            packet,
            datalink,
            network: None,
            transport: None,
            payload: network_bytes,
            ethertype: Some(ethertype),
            ip_protocol: None,
        };

        match ethertype {
            EtherType::Ipv4 => view.parse_ipv4(network_bytes)?,
            EtherType::Ipv6 => view.parse_ipv6(network_bytes)?,
            EtherType::Arp if network_bytes.len() >= 28 => {
                view.network = Some(&network_bytes[..28]);
                view.payload = &network_bytes[28..];
            }
            _ => {}
        }
        Ok(view)
    }

    fn parse_ipv4(&mut self, bytes: &'a [u8]) -> Result<(), ParseError> {
        if bytes.len() < 20 {
            return Err(ParseError::BufferTooShort {
                context: "IPv4 frame",
                minimum: 20,
                actual: bytes.len(),
            });
        }
        if bytes[0] >> 4 != 4 {
            return Err(ParseError::Malformed {
                context: "IPv4 frame version",
            });
        }
        let header_len = (bytes[0] as usize & 0x0f) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return Err(ParseError::InvalidLength {
                context: "IPv4 frame header",
                value: header_len,
            });
        }
        let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let packet_len = if declared == 0 {
            bytes.len()
        } else {
            declared.min(bytes.len())
        };
        if packet_len < header_len {
            return Err(ParseError::InvalidLength {
                context: "IPv4 frame total length",
                value: declared,
            });
        }
        self.network = Some(&bytes[..header_len]);
        let protocol = IpNextProtocol::new(bytes[9]);
        self.ip_protocol = Some(protocol);
        self.parse_transport(protocol, &bytes[header_len..packet_len])
    }

    fn parse_ipv6(&mut self, bytes: &'a [u8]) -> Result<(), ParseError> {
        if bytes.len() < 40 {
            return Err(ParseError::BufferTooShort {
                context: "IPv6 frame",
                minimum: 40,
                actual: bytes.len(),
            });
        }
        if bytes[0] >> 4 != 6 {
            return Err(ParseError::Malformed {
                context: "IPv6 frame version",
            });
        }
        let declared_payload = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let packet_len = 40usize
            .checked_add(declared_payload)
            .map(|length| length.min(bytes.len()))
            .ok_or(ParseError::InvalidLength {
                context: "IPv6 frame payload length",
                value: declared_payload,
            })?;
        let mut next = bytes[6];
        let mut cursor = 40usize;
        while cursor < packet_len {
            let extension_len = match next {
                0 | 43 | 60 => {
                    if cursor + 2 > packet_len {
                        return Err(ParseError::Truncated {
                            context: "IPv6 extension header",
                            expected: cursor + 2,
                            actual: packet_len,
                        });
                    }
                    (bytes[cursor + 1] as usize + 1) * 8
                }
                44 => 8,
                51 => {
                    if cursor + 2 > packet_len {
                        return Err(ParseError::Truncated {
                            context: "IPv6 authentication header",
                            expected: cursor + 2,
                            actual: packet_len,
                        });
                    }
                    (bytes[cursor + 1] as usize + 2) * 4
                }
                _ => break,
            };
            let end = cursor
                .checked_add(extension_len)
                .filter(|end| *end <= packet_len)
                .ok_or(ParseError::Truncated {
                    context: "IPv6 extension header",
                    expected: cursor.saturating_add(extension_len),
                    actual: packet_len,
                })?;
            next = bytes[cursor];
            cursor = end;
        }
        self.network = Some(&bytes[..cursor]);
        let protocol = IpNextProtocol::new(next);
        self.ip_protocol = Some(protocol);
        self.parse_transport(protocol, &bytes[cursor..packet_len])
    }

    fn parse_transport(
        &mut self,
        protocol: IpNextProtocol,
        bytes: &'a [u8],
    ) -> Result<(), ParseError> {
        let header_len = match protocol {
            IpNextProtocol::Tcp => {
                if bytes.len() < 20 {
                    self.payload = bytes;
                    return Ok(());
                }
                let length = (bytes[12] as usize >> 4) * 4;
                if length < 20 || length > bytes.len() {
                    return Err(ParseError::InvalidLength {
                        context: "TCP frame header",
                        value: length,
                    });
                }
                length
            }
            IpNextProtocol::Udp => {
                if bytes.len() < 8 {
                    self.payload = bytes;
                    return Ok(());
                }
                8
            }
            IpNextProtocol::Icmp | IpNextProtocol::Icmpv6 => {
                if bytes.len() < 4 {
                    self.payload = bytes;
                    return Ok(());
                }
                4
            }
            _ => {
                self.payload = bytes;
                return Ok(());
            }
        };
        self.transport = Some(&bytes[..header_len]);
        self.payload = &bytes[header_len..];
        Ok(())
    }
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
        Self::try_from_buf_with_mode(packet, option, ParseMode::Lenient)
    }

    /// Parse a frame from owned bytes while preserving payload slices when possible.
    pub fn try_from_bytes(packet: Bytes, option: ParseOption) -> Result<Self, ParseError> {
        Self::try_from_bytes_with_mode(packet, option, ParseMode::Lenient)
    }

    /// Parse a frame using the requested validation mode.
    pub fn try_from_buf_with_mode(
        packet: &[u8],
        option: ParseOption,
        mode: ParseMode,
    ) -> Result<Self, ParseError> {
        parse_frame_from_bytes(Bytes::copy_from_slice(packet), option, mode.is_strict())
    }

    /// Parse an owned frame using the requested validation mode.
    pub fn try_from_bytes_with_mode(
        packet: Bytes,
        option: ParseOption,
        mode: ParseMode,
    ) -> Result<Self, ParseError> {
        parse_frame_from_bytes(packet, option, mode.is_strict())
    }

    /// Parse a frame using validation-oriented strict IP parsing.
    #[deprecated(note = "use Frame::try_from_buf_with_mode with ParseMode::Strict")]
    pub fn try_from_buf_strict(packet: &[u8], option: ParseOption) -> Result<Self, ParseError> {
        Self::try_from_buf_with_mode(packet, option, ParseMode::Strict)
    }

    /// Parse a frame from owned bytes using validation-oriented strict IP parsing.
    #[deprecated(note = "use Frame::try_from_bytes_with_mode with ParseMode::Strict")]
    pub fn try_from_bytes_strict(packet: Bytes, option: ParseOption) -> Result<Self, ParseError> {
        Self::try_from_bytes_with_mode(packet, option, ParseMode::Strict)
    }

    /// Parse a frame using validation-oriented strict IP parsing.
    #[deprecated(note = "use Frame::try_from_buf_with_mode with ParseMode::Strict")]
    pub fn from_buf_strict(packet: &[u8], option: ParseOption) -> Option<Self> {
        Self::try_from_buf_with_mode(packet, option, ParseMode::Strict).ok()
    }
}

/// Borrowed-payload frame view with decoded owned headers.
///
/// This compatibility type constructs decoded header values and may allocate
/// for packet options. Use [`FrameSlice`] when allocation-free layer slicing is
/// required.
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
        Ipv4Packet::try_from_bytes_with_mode(packet, ParseMode::Strict)
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
        Ipv6Packet::try_from_bytes_with_mode(packet, ParseMode::Strict)
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

    #[test]
    fn frame_slice_borrows_ipv4_tcp_layers() {
        let bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 44, 0, 0, 0, 0, 64, 6, 0,
            0, 192, 0, 2, 1, 198, 51, 100, 2, 0, 80, 0x04, 0xd2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50,
            0x18, 0, 0, 0, 0, 0, 0, b'd', b'a', b't', b'a',
        ];

        let view = FrameSlice::try_from_buf(&bytes, ParseOption::default()).expect("frame slice");
        assert_eq!(view.datalink, Some(&bytes[..14]));
        assert_eq!(view.network, Some(&bytes[14..34]));
        assert_eq!(view.transport, Some(&bytes[34..54]));
        assert_eq!(view.payload, b"data");
        assert_eq!(view.ip_protocol, Some(IpNextProtocol::Tcp));
        assert!(std::ptr::eq(view.payload.as_ptr(), bytes[54..].as_ptr()));
    }

    #[test]
    fn frame_slice_walks_ipv6_extension_headers() {
        let mut bytes = vec![0u8; 14 + 40 + 8 + 8 + 3];
        bytes[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        bytes[14] = 0x60;
        bytes[18..20].copy_from_slice(&19u16.to_be_bytes());
        bytes[20] = 0;
        bytes[21] = 64;
        bytes[54] = 17;
        bytes[55] = 0;
        bytes[62..64].copy_from_slice(&1234u16.to_be_bytes());
        bytes[64..66].copy_from_slice(&53u16.to_be_bytes());
        bytes[66..68].copy_from_slice(&11u16.to_be_bytes());
        bytes[70..].copy_from_slice(b"dns");

        let view = FrameSlice::try_from_buf(&bytes, ParseOption::default()).expect("frame slice");
        assert_eq!(view.network.expect("network").len(), 48);
        assert_eq!(view.transport.expect("transport").len(), 8);
        assert_eq!(view.payload, b"dns");
        assert_eq!(view.ip_protocol, Some(IpNextProtocol::Udp));
    }
}
