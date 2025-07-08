use std::net::Ipv6Addr;
use bytes::{Bytes, BytesMut, BufMut};
use crate::packet::Packet;
use crate::ip::IpNextProtocol;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ipv6Header {
    pub version: u8,         // 4 bits
    pub traffic_class: u8,   // 8 bits
    pub flow_label: u32,     // 20 bits
    pub payload_length: u16,
    pub next_header: IpNextProtocol,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    pub header: Ipv6Header,
    pub extensions: Vec<Ipv6ExtensionHeader>,
    pub payload: Bytes,
}

impl Packet for Ipv6Packet {
    type Header = Ipv6Header;
    
    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPV6_HEADER_LEN {
            return None;
        }

        // --- Parse the header section ---
        let version_traffic_flow = &bytes[..4];
        let version = version_traffic_flow[0] >> 4;
        let traffic_class = ((version_traffic_flow[0] & 0x0F) << 4) | (version_traffic_flow[1] >> 4);
        let flow_label = u32::from(version_traffic_flow[1] & 0x0F) << 16
            | u32::from(version_traffic_flow[2]) << 8
            | u32::from(version_traffic_flow[3]);

        let payload_length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let mut next_header = IpNextProtocol::new(bytes[6]);
        let hop_limit = bytes[7];

        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?);

        let header = Ipv6Header {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source,
            destination,
        };

        // --- Walk through the extension headers ---
        let mut offset = IPV6_HEADER_LEN;
        let mut extensions = Vec::new();

        loop {
            match next_header {
                IpNextProtocol::Hopopt | IpNextProtocol::Ipv6Route | IpNextProtocol::Ipv6Frag
                | IpNextProtocol::Ipv6Opts => {
                    if offset + 2 > bytes.len() {
                        return None;
                    }

                    let nh = IpNextProtocol::new(bytes[offset]);
                    let ext_len = bytes[offset + 1] as usize;

                    match next_header {
                        IpNextProtocol::Hopopt | IpNextProtocol::Ipv6Opts => {
                            let total_len = 8 + ext_len * 8;
                            if offset + total_len > bytes.len() {
                                return None;
                            }

                            let data = Bytes::copy_from_slice(&bytes[offset + 2 .. offset + total_len]);
                            let ext = match next_header {
                                IpNextProtocol::Hopopt => Ipv6ExtensionHeader::HopByHop { next: nh, data },
                                IpNextProtocol::Ipv6Opts => Ipv6ExtensionHeader::Destination { next: nh, data },
                                _ => Ipv6ExtensionHeader::Raw { 
                                    next: nh, 
                                    raw: Bytes::copy_from_slice(&bytes[offset .. offset + total_len]), 
                                },
                            };

                            extensions.push(ext);
                            next_header = nh;
                            offset += total_len;
                        }

                        IpNextProtocol::Ipv6Route => {
                            if offset + 4 > bytes.len() {
                                return None;
                            }

                            let routing_type = bytes[offset + 2];
                            let segments_left = bytes[offset + 3];
                            let total_len = 8 + ext_len * 8;
                            if offset + total_len > bytes.len() {
                                return None;
                            }

                            let data = Bytes::copy_from_slice(&bytes[offset + 4 .. offset + total_len]);
                            extensions.push(Ipv6ExtensionHeader::Routing {
                                next: nh,
                                routing_type,
                                segments_left,
                                data,
                            });

                            next_header = nh;
                            offset += total_len;
                        }

                        IpNextProtocol::Ipv6Frag => {
                            if offset + 8 > bytes.len() {
                                return None;
                            }

                            //let reserved = bytes[offset + 1];
                            let frag_off_flags = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                            let offset_val = frag_off_flags >> 3;
                            let more = (frag_off_flags & 0x1) != 0;
                            let id = u32::from_be_bytes([
                                bytes[offset + 4], bytes[offset + 5],
                                bytes[offset + 6], bytes[offset + 7],
                            ]);

                            extensions.push(Ipv6ExtensionHeader::Fragment {
                                next: nh,
                                offset: offset_val,
                                more,
                                id,
                            });

                            next_header = nh;
                            offset += 8;
                        }

                        _ => break,
                    }
                }

                _ => break,
            }
        }

        let payload = Bytes::copy_from_slice(&bytes[offset..]);
        Some(Ipv6Packet {
            header,
            extensions,
            payload,
        })
    }
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.total_len());

        // --- 1. Basic header (first 40 bytes) ---
        let vtf_1 = (self.header.version << 4) | (self.header.traffic_class >> 4);
        let vtf_2 = ((self.header.traffic_class & 0x0F) << 4) | ((self.header.flow_label >> 16) as u8);
        let vtf_3 = (self.header.flow_label >> 8) as u8;
        let vtf_4 = self.header.flow_label as u8;

        buf.put_u8(vtf_1);
        buf.put_u8(vtf_2);
        buf.put_u8(vtf_3);
        buf.put_u8(vtf_4);
        buf.put_u16(self.header.payload_length);
        // First next_header (first extension header if present)
        let first_next_header = self.extensions.first()
            .map(|ext| ext.next_protocol())
            .unwrap_or(self.header.next_header);
        buf.put_u8(first_next_header.value());
        buf.put_u8(self.header.hop_limit);
        buf.extend_from_slice(&self.header.source.octets());
        buf.extend_from_slice(&self.header.destination.octets());

        // --- 2. Encode the extension header chain ---
        for ext in &self.extensions {
            match ext {
                Ipv6ExtensionHeader::HopByHop { next, data }
                | Ipv6ExtensionHeader::Destination { next, data } => {
                    let hdr_ext_len = ((data.len() + 6) / 8) as u8 - 1;
                    buf.put_u8(next.value());
                    buf.put_u8(hdr_ext_len);
                    buf.extend_from_slice(data);
                    // Padding (8 byte alignment)
                    while (2 + data.len()) % 8 != 0 {
                        buf.put_u8(0);
                    }
                }

                Ipv6ExtensionHeader::Routing {
                    next,
                    routing_type,
                    segments_left,
                    data,
                } => {
                    let hdr_ext_len = ((data.len() + 4 + 6) / 8) as u8 - 1;
                    buf.put_u8(next.value());
                    buf.put_u8(hdr_ext_len);
                    buf.put_u8(*routing_type);
                    buf.put_u8(*segments_left);
                    buf.extend_from_slice(data);
                    while (4 + data.len()) % 8 != 0 {
                        buf.put_u8(0);
                    }
                }

                Ipv6ExtensionHeader::Fragment { next, offset, more, id } => {
                    buf.put_u8(next.value());
                    buf.put_u8(0); // reserved
                    let offset_flags = (offset << 3) | if *more { 1 } else { 0 };
                    buf.put_u16(offset_flags);
                    buf.put_u32(*id);
                }

                Ipv6ExtensionHeader::Raw { next: _, raw } => {
                    // Note: assume the raw header already includes the next field
                    buf.extend_from_slice(&raw[..]);
                }
            }
        }

        // --- 3. Payload ---
        buf.extend_from_slice(&self.payload);

        buf.freeze()
    }

    fn header(&self) -> Bytes {
        self.to_bytes().slice(..IPV6_HEADER_LEN)
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        (self.header, self.payload)
    }
}

impl Ipv6Packet {
    pub fn total_len(&self) -> usize {
        IPV6_HEADER_LEN
            + self.extensions.iter().map(|ext| ext.len()).sum::<usize>()
            + self.payload.len()
    }
    pub fn get_extension(&self, kind: ExtensionHeaderType) -> Option<&Ipv6ExtensionHeader> {
        self.extensions.iter().find(|ext| ext.kind() == kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionHeaderType {
    HopByHop,
    Destination,
    Routing,
    Fragment,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6ExtensionHeader {
    HopByHop { next: IpNextProtocol, data: Bytes },
    Destination { next: IpNextProtocol, data: Bytes },
    Routing { next: IpNextProtocol, routing_type: u8, segments_left: u8, data: Bytes },
    Fragment { next: IpNextProtocol, offset: u16, more: bool, id: u32 },
    Raw { next: IpNextProtocol, raw: Bytes },
}

impl Ipv6ExtensionHeader {
    pub fn next_protocol(&self) -> IpNextProtocol {
        match self {
            Ipv6ExtensionHeader::HopByHop { next, .. } => *next,
            Ipv6ExtensionHeader::Destination { next, .. } => *next,
            Ipv6ExtensionHeader::Routing { next, .. } => *next,
            Ipv6ExtensionHeader::Fragment { next, .. } => *next,
            Ipv6ExtensionHeader::Raw { next, .. } => *next,
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Ipv6ExtensionHeader::HopByHop { data, .. }
            | Ipv6ExtensionHeader::Destination { data, .. } => {
                let base = 2 + data.len();
                (base + 7) / 8 * 8 // padding to multiple of 8
            }
            Ipv6ExtensionHeader::Routing { data, .. } => {
                let base = 4 + data.len();
                (base + 7) / 8 * 8
            }
            Ipv6ExtensionHeader::Fragment { .. } => 8,
            Ipv6ExtensionHeader::Raw { raw, .. } => raw.len(),
        }
    }
    pub fn kind(&self) -> ExtensionHeaderType {
        match self {
            Ipv6ExtensionHeader::HopByHop { .. } => ExtensionHeaderType::HopByHop,
            Ipv6ExtensionHeader::Destination { .. } => ExtensionHeaderType::Destination,
            Ipv6ExtensionHeader::Routing { .. } => ExtensionHeaderType::Routing,
            Ipv6ExtensionHeader::Fragment { .. } => ExtensionHeaderType::Fragment,
            Ipv6ExtensionHeader::Raw { raw, .. } => {
                // Even for Raw we can read the first byte to guess the kind
                let kind = raw.get(0).copied().unwrap_or(0xff);
                match kind {
                    0 => ExtensionHeaderType::HopByHop,
                    43 => ExtensionHeaderType::Routing,
                    44 => ExtensionHeaderType::Fragment,
                    60 => ExtensionHeaderType::Destination,
                    other => ExtensionHeaderType::Unknown(other),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::IpNextProtocol;
    use std::net::Ipv6Addr;

    #[test]
    fn test_ipv6_basic_header_fields() {
        let header = Ipv6Header {
            version: 6,
            traffic_class: 0xaa,
            flow_label: 0x12345,
            payload_length: 0,
            next_header: IpNextProtocol::Udp,
            hop_limit: 64,
            source: Ipv6Addr::LOCALHOST,
            destination: Ipv6Addr::UNSPECIFIED,
        };

        let packet = Ipv6Packet {
            header: header.clone(),
            extensions: vec![],
            payload: Bytes::new(),
        };

        assert_eq!(packet.header.version, 6);
        assert_eq!(packet.header.traffic_class, 0xaa);
        assert_eq!(packet.header.flow_label, 0x12345);
        assert_eq!(packet.header.payload_length, 0);
        assert_eq!(packet.header.next_header, IpNextProtocol::Udp);
        assert_eq!(packet.header.hop_limit, 64);
        assert_eq!(packet.header.source, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.header.destination, Ipv6Addr::UNSPECIFIED);

        let raw = packet.to_bytes();
        assert_eq!(raw.len(), IPV6_HEADER_LEN);
        let reparsed = Ipv6Packet::from_bytes(raw.clone()).unwrap();
        assert_eq!(reparsed.header, packet.header);
    }

    #[test]
    fn test_ipv6_from_bytes_parsing() {
        use bytes::Bytes;

        let raw_bytes = Bytes::from_static(&[
            // Version(6), Traffic Class(0xa), Flow Label(0x12345)
            0x60, 0xA1, 0x23, 0x45,
            // Payload Length: 8 bytes
            0x00, 0x08,
            // Next Header: TCP (6)
            0x06,
            // Hop Limit
            0x40,
            // Source IP
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x1a, 0x2b, 0xff, 0xfe, 0x1a, 0x2b, 0x3c,
            // Destination IP
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            // Payload (dummy 8 bytes)
            b'H', b'e', b'l', b'l', b'o', b'!', b'!', b'\n',
        ]);

        let parsed = Ipv6Packet::from_bytes(raw_bytes.clone()).expect("should parse successfully");

        assert_eq!(parsed.header.version, 6);
        assert_eq!(parsed.header.traffic_class, 0xa);
        assert_eq!(parsed.header.flow_label, 0x12345);
        assert_eq!(parsed.header.payload_length, 8);
        assert_eq!(parsed.header.next_header, IpNextProtocol::Tcp);
        assert_eq!(parsed.header.hop_limit, 0x40);
        assert_eq!(
            parsed.header.source,
            "fe80::21a:2bff:fe1a:2b3c".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            parsed.header.destination,
            "ff02::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(&parsed.payload[..], b"Hello!!\n");
        assert_eq!(parsed.extensions.len(), 0);
        assert_eq!(parsed.to_bytes(), raw_bytes);
    }

    #[test]
    fn test_ipv6_payload_roundtrip() {
        use bytes::Bytes;

        let payload = Bytes::from_static(b"HELLO_WORLDS");
        let packet = Ipv6Packet {
            header: super::Ipv6Header {
                version: 6,
                traffic_class: 0,
                flow_label: 0,
                payload_length: payload.len() as u16,
                next_header: IpNextProtocol::Tcp,
                hop_limit: 32,
                source: Ipv6Addr::LOCALHOST,
                destination: Ipv6Addr::LOCALHOST,
            },
            extensions: vec![],
            payload: payload.clone(),
        };

        let raw = packet.to_bytes();
        let parsed = Ipv6Packet::from_bytes(raw.clone()).unwrap();

        assert_eq!(parsed.header, packet.header);
        assert_eq!(parsed.payload, payload);
        assert_eq!(raw.len(), packet.total_len());
    }

    #[test]
    fn test_ipv6_truncated_packet_rejected() {
        use bytes::Bytes;

        let short = Bytes::from_static(&[0u8; 20]); // insufficient
        assert!(Ipv6Packet::from_bytes(short).is_none());
    }

    #[test]
    fn test_ipv6_total_len_computation() {
        use bytes::Bytes;

        let ext = Ipv6ExtensionHeader::Fragment {
            next: IpNextProtocol::Tcp,
            offset: 1,
            more: true,
            id: 42,
        };

        let packet = Ipv6Packet {
            header: Ipv6Header {
                version: 6,
                traffic_class: 0,
                flow_label: 0,
                payload_length: 8,
                next_header: IpNextProtocol::Tcp,
                hop_limit: 1,
                source: Ipv6Addr::LOCALHOST,
                destination: Ipv6Addr::LOCALHOST,
            },
            extensions: vec![ext],
            payload: Bytes::from_static(b"ABCDEFGH"),
        };

        let expected_len = IPV6_HEADER_LEN + 8 + 8; // header + fragment ext + payload
        assert_eq!(packet.total_len(), expected_len);
        assert_eq!(packet.to_bytes().len(), expected_len);
    }

    #[test]
    fn test_extension_kind_known_variants() {
        let hop = Ipv6ExtensionHeader::HopByHop {
            next: IpNextProtocol::Tcp,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        };
        assert_eq!(hop.kind(), ExtensionHeaderType::HopByHop);

        let dst = Ipv6ExtensionHeader::Destination {
            next: IpNextProtocol::Udp,
            data: Bytes::from_static(&[9, 8, 7]),
        };
        assert_eq!(dst.kind(), ExtensionHeaderType::Destination);

        let route = Ipv6ExtensionHeader::Routing {
            next: IpNextProtocol::Tcp,
            routing_type: 0,
            segments_left: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        };
        assert_eq!(route.kind(), ExtensionHeaderType::Routing);

        let frag = Ipv6ExtensionHeader::Fragment {
            next: IpNextProtocol::Udp,
            offset: 0,
            more: false,
            id: 12345,
        };
        assert_eq!(frag.kind(), ExtensionHeaderType::Fragment);
    }

    #[test]
    fn test_extension_kind_raw_known() {
        let raw_routing = Ipv6ExtensionHeader::Raw {
            next: IpNextProtocol::new(43),
            raw: Bytes::from_static(&[43, 1, 2, 3]),
        };
        assert_eq!(raw_routing.kind(), ExtensionHeaderType::Routing);

        let raw_frag = Ipv6ExtensionHeader::Raw {
            next: IpNextProtocol::new(44),
            raw: Bytes::from_static(&[44, 0, 0, 0]),
        };
        assert_eq!(raw_frag.kind(), ExtensionHeaderType::Fragment);
    }

    #[test]
    fn test_extension_kind_raw_unknown() {
        let raw_unknown = Ipv6ExtensionHeader::Raw {
            next: IpNextProtocol::new(250),
            raw: Bytes::from_static(&[250, 0, 1, 2]),
        };
        assert_eq!(raw_unknown.kind(), ExtensionHeaderType::Unknown(250));
    }
}
