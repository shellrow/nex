//! Shared BPF record framing and Ethernet presentation for IP-only links.

use crate::bindings::bpf;
use std::{borrow::Cow, collections::VecDeque, io, mem};

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

    /// Match header-complete writes to the actual OS/link contract.
    pub(crate) fn header_complete(self) -> bool {
        self == Self::Ethernet || (cfg!(target_os = "macos") && self == Self::Null)
    }

    pub(crate) fn prepare_send(self, packet: &[u8]) -> io::Result<Cow<'_, [u8]>> {
        if self == Self::Ethernet {
            return Ok(Cow::Borrowed(packet));
        }
        let ip = packet.get(14..).ok_or_else(invalid_send_packet)?;
        if cfg!(target_os = "macos") && self == Self::Null {
            let family = match (&packet[12..14], ip.first().map(|byte| byte >> 4)) {
                ([0x08, 0x00], Some(4)) => {
                    if ip.len() < 20 {
                        return Err(invalid_send_packet());
                    }
                    let header_len = (ip[0] & 0x0f) as usize * 4;
                    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
                    if header_len < 20
                        || header_len > ip.len()
                        || total_len < header_len
                        || total_len > ip.len()
                    {
                        return Err(invalid_send_packet());
                    }
                    libc::AF_INET as u32
                }
                ([0x86, 0xdd], Some(6)) => {
                    if ip.len() < 40 {
                        return Err(invalid_send_packet());
                    }
                    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
                    if 40 + payload_len > ip.len() {
                        return Err(invalid_send_packet());
                    }
                    libc::AF_INET6 as u32
                }
                _ => return Err(invalid_send_packet()),
            };
            // XNU's header-complete DLT_NULL path expects a native-endian
            // loopback family header. Preserve all supplied IP bytes verbatim.
            let mut output = Vec::with_capacity(4 + ip.len());
            output.extend_from_slice(&family.to_ne_bytes());
            output.extend_from_slice(ip);
            Ok(Cow::Owned(output))
        } else {
            // Preserve the existing IP-only write contract on other OS/DLTs.
            Ok(Cow::Borrowed(ip))
        }
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

fn invalid_send_packet() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or truncated Ethernet/IP frame for BPF send",
    )
}

/// A packet is one write: never retry a short write as a second packet.
pub(crate) fn write_packet(fd: libc::c_int, packet: &[u8]) -> io::Result<()> {
    write_packet_with(packet, |bytes| {
        // SAFETY: bytes is readable for its entire length during the call;
        // write retains no pointer. The caller owns the descriptor.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    })
}

fn write_packet_with(
    packet: &[u8],
    write: impl FnOnce(&[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let written = write(packet)?;
    if written == packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete BPF packet write",
        ))
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
pub(crate) fn test_ip_frame(version: u8) -> Vec<u8> {
    let mut packet = vec![0; 54];
    if version == 4 {
        packet[12..14].copy_from_slice(&[8, 0]);
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&40u16.to_be_bytes());
    } else {
        packet[12..14].copy_from_slice(&[0x86, 0xdd]);
        packet[14] = 0x60;
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_format_is_scoped_to_os_and_dlt() {
        for version in [4, 6] {
            let packet = test_ip_frame(version);
            for link in [
                LinkType::Ethernet,
                LinkType::Null,
                LinkType::Loop,
                LinkType::Raw,
            ] {
                let prepared = link.prepare_send(&packet).unwrap();
                let expected = if link == LinkType::Ethernet {
                    packet.clone()
                } else if cfg!(target_os = "macos") && link == LinkType::Null {
                    let family = if version == 4 {
                        libc::AF_INET
                    } else {
                        libc::AF_INET6
                    } as u32;
                    let mut expected = family.to_ne_bytes().to_vec();
                    expected.extend_from_slice(&packet[14..]);
                    expected
                } else {
                    packet[14..].to_vec()
                };
                assert_eq!(&*prepared, expected);
                assert_eq!(
                    link.header_complete(),
                    link == LinkType::Ethernet
                        || (cfg!(target_os = "macos") && link == LinkType::Null)
                );
                if cfg!(target_os = "macos") && link == LinkType::Null {
                    let mut normalized = Vec::new();
                    link.normalize(&prepared, &mut normalized).unwrap();
                    assert_eq!(normalized, packet);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn null_send_rejects_truncated_and_mismatched_frames() {
        for version in [4, 6] {
            let packet = test_ip_frame(version);
            for length in 0..packet.len() {
                assert_eq!(
                    LinkType::Null
                        .prepare_send(&packet[..length])
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
            for ether_type in [
                [0, 0],
                [8, 6],
                if version == 4 { [0x86, 0xdd] } else { [8, 0] },
            ] {
                let mut invalid = packet.clone();
                invalid[12..14].copy_from_slice(&ether_type);
                assert!(LinkType::Null.prepare_send(&invalid).is_err());
            }
            let mut invalid = packet.clone();
            invalid[14] = 0x30;
            assert!(LinkType::Null.prepare_send(&invalid).is_err());
            if version == 4 {
                for ihl in [0x44, 0x4f] {
                    invalid = packet.clone();
                    invalid[14] = ihl;
                    assert!(LinkType::Null.prepare_send(&invalid).is_err());
                }
                invalid = packet.clone();
                invalid[16..18].copy_from_slice(&19u16.to_be_bytes());
            } else {
                invalid = packet.clone();
                invalid[18..20].copy_from_slice(&1u16.to_be_bytes());
            }
            assert!(LinkType::Null.prepare_send(&invalid).is_err());
        }
    }

    #[test]
    fn writes_are_atomic_and_errors_are_not_success() {
        let packet = test_ip_frame(6);
        for result in [
            Ok(0),
            Ok(1),
            Ok(packet.len() - 1),
            Ok(packet.len()),
            Err(io::Error::from_raw_os_error(libc::EINTR)),
            Err(io::Error::from_raw_os_error(libc::EWOULDBLOCK)),
            Err(io::Error::from_raw_os_error(libc::EBADF)),
        ] {
            let expected = match &result {
                Ok(n) if *n == packet.len() => None,
                Ok(_) => Some(io::ErrorKind::WriteZero),
                Err(error) => Some(error.kind()),
            };
            let mut calls = 0;
            let actual = write_packet_with(&packet, |bytes| {
                calls += 1;
                assert_eq!(bytes, packet);
                result
            });
            assert_eq!(calls, 1, "never send a remainder or retry a failed write");
            assert_eq!(actual.err().map(|error| error.kind()), expected);
        }
    }

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
