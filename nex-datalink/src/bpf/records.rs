//! Shared BPF record framing and Ethernet presentation for IP-only links.

use crate::bindings::bpf;
use std::{collections::VecDeque, io, mem};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    Null,
    Loop,
    Raw,
}

impl LinkType {
    pub(crate) fn from_dlt(dlt: libc::c_uint) -> io::Result<Self> {
        match dlt {
            1 => Ok(Self::Ethernet),
            bpf::DLT_NULL => Ok(Self::Null),
            108 => Ok(Self::Loop),
            // DLT_RAW is 14 on OpenBSD, 12 on other BPF platforms. It is
            // distinct from the portable save-file LINKTYPE_RAW value 101.
            #[cfg(target_os = "openbsd")]
            14 => Ok(Self::Raw),
            #[cfg(not(target_os = "openbsd"))]
            12 => Ok(Self::Raw),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported BPF datalink type {dlt}"),
            )),
        }
    }

    pub(crate) fn is_ip(self) -> bool {
        self != Self::Ethernet
    }

    pub(crate) fn normalize(self, packet: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let (ip, family) = match self {
            Self::Ethernet => {
                output.clear();
                output.extend_from_slice(packet);
                return Ok(());
            }
            Self::Raw => (packet, None),
            Self::Null | Self::Loop => {
                let bytes: [u8; 4] = packet
                    .get(..4)
                    .ok_or_else(invalid_packet)?
                    .try_into()
                    .unwrap();
                let family = if self == Self::Null {
                    u32::from_ne_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                };
                (&packet[4..], Some(family))
            }
        };
        let (expected_family, ether_type): (u32, u16) = match ip.first().map(|byte| byte >> 4) {
            Some(4) => (libc::AF_INET as u32, 0x0800),
            Some(6) => (libc::AF_INET6 as u32, 0x86dd),
            _ => return Err(invalid_packet()),
        };
        if family.is_some_and(|family| family != expected_family) {
            return Err(invalid_packet());
        }
        // Preserve the captured bytes verbatim, including truncated IP payloads.
        // MAC addresses are unavailable on IP-only links and are represented by zeroes.
        output.clear();
        output.resize(12, 0);
        output.extend_from_slice(&ether_type.to_be_bytes());
        output.extend_from_slice(ip);
        Ok(())
    }
}

fn invalid_packet() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unsupported BPF IP link header",
    )
}

pub(crate) fn parse_records(buffer: &[u8]) -> io::Result<VecDeque<(usize, usize)>> {
    let mut packets = VecDeque::new();
    let mut cursor = 0;
    while cursor < buffer.len() {
        let remaining = buffer.len() - cursor;
        if remaining < bpf::BPF_HDR_FIELD_LEN {
            return Err(invalid_packet());
        }
        // SAFETY: Copy only the actual fields, not repr(C) trailing padding.
        // The source bounds were checked; the destination is a complete, aligned
        // zero-initialized header. The BPF header contains integer fields only.
        let header = unsafe {
            let mut header: bpf::bpf_hdr = mem::zeroed();
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr().add(cursor),
                (&mut header as *mut bpf::bpf_hdr).cast::<u8>(),
                bpf::BPF_HDR_FIELD_LEN,
            );
            header
        };
        let header_len = header.bh_hdrlen as usize;
        let captured_len = header.bh_caplen as usize;
        let record_len = super::validate_record_lengths(header_len, captured_len, remaining, 0)?;
        packets.push_back((cursor + header_len, captured_len));
        let record_len = isize::try_from(record_len).map_err(|_| invalid_packet())?;
        cursor = cursor
            .checked_add(bpf::BPF_WORDALIGN(record_len) as usize)
            .ok_or_else(invalid_packet)?;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_links_preserve_every_byte_and_set_ether_type() {
        for (version, family, ether_type) in [
            (4, libc::AF_INET, [8, 0]),
            (6, libc::AF_INET6, [0x86, 0xdd]),
        ] {
            for len in [1, 20, 54, 255, 4097] {
                let mut ip = vec![0xa5; len];
                ip[0] = version << 4;
                for link in [LinkType::Null, LinkType::Loop, LinkType::Raw] {
                    let mut packet = match link {
                        LinkType::Null => (family as u32).to_ne_bytes().to_vec(),
                        LinkType::Loop => (family as u32).to_be_bytes().to_vec(),
                        _ => vec![],
                    };
                    packet.extend_from_slice(&ip);
                    let original = packet.clone();
                    let mut out = vec![0xff; 9000];
                    link.normalize(&packet, &mut out).unwrap();
                    assert_eq!(out.len(), 14 + len);
                    assert_eq!(&out[..12], &[0; 12]);
                    assert_eq!(&out[12..14], &ether_type);
                    assert_eq!(&out[14..], ip);
                    assert_eq!(packet, original);
                }
            }
        }
    }

    #[test]
    fn rejects_invalid_ip_link_headers() {
        for bytes in [
            &[][..],
            &[0],
            &[0, 0, 0],
            &[0, 0, 0, 0],
            &[0, 0, 0, 0, 0x45],
        ] {
            assert!(LinkType::Null.normalize(bytes, &mut vec![]).is_err());
        }
        assert!(LinkType::Raw.normalize(&[0x30], &mut vec![]).is_err());
        let mut mismatched = (libc::AF_INET as u32).to_ne_bytes().to_vec();
        mismatched.push(0x60);
        assert!(LinkType::Null.normalize(&mismatched, &mut vec![]).is_err());
        assert!(LinkType::from_dlt(9999).is_err());
    }

    #[test]
    fn ethernet_frames_remain_unchanged() {
        let packet: Vec<u8> = (0..200).collect();
        let mut output = vec![0xff; 400];
        LinkType::Ethernet.normalize(&packet, &mut output).unwrap();
        assert_eq!(packet, output);
        assert_eq!(LinkType::from_dlt(1).unwrap(), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(0).unwrap(), LinkType::Null);
        assert_eq!(LinkType::from_dlt(108).unwrap(), LinkType::Loop);
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let len = bpf::BPF_HDR_FIELD_LEN;
        // SAFETY: All fields are integer values; zero initializes valid fields.
        let mut header: bpf::bpf_hdr = unsafe { mem::zeroed() };
        header.bh_hdrlen = len as _;
        header.bh_caplen = payload.len() as _;
        header.bh_datalen = payload.len() as _;
        // SAFETY: Only initialized header fields are copied, excluding padding.
        let mut out = unsafe {
            std::slice::from_raw_parts((&header as *const bpf::bpf_hdr).cast::<u8>(), len)
        }
        .to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn batches_keep_offsets_and_do_not_require_trailing_struct_padding() {
        let mut first = record(&[1, 2, 3]);
        first.resize(bpf::BPF_WORDALIGN(first.len() as isize) as usize, 0);
        let second_start = first.len();
        first.extend(record(&[]));
        let records = parse_records(&first).unwrap();
        assert_eq!(
            records,
            VecDeque::from([
                (bpf::BPF_HDR_FIELD_LEN, 3),
                (second_start + bpf::BPF_HDR_FIELD_LEN, 0)
            ])
        );
        for end in 1..bpf::BPF_HDR_FIELD_LEN {
            assert!(parse_records(&first[..end]).is_err());
        }
        assert!(parse_records(&first[..first.len() - 1]).is_err());
    }
}
