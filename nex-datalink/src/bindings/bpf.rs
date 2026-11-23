#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{collections::VecDeque, io, mem::offset_of};

pub const AF_LINK: libc::c_int = 18;

const IF_NAMESIZE: usize = 16;
const IFNAMSIZ: usize = IF_NAMESIZE;
const IOC_IN: libc::c_ulong = 0x80000000;
const IOC_OUT: libc::c_ulong = 0x40000000;
const IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;
const IOCPARM_SHIFT: libc::c_ulong = 13;
const IOCPARM_MASK: libc::c_ulong = (1 << (IOCPARM_SHIFT as usize)) - 1;

const SIZEOF_TIMEVAL: libc::c_ulong = 16;
const SIZEOF_IFREQ: libc::c_ulong = size_of::<ifreq>() as _;
const SIZEOF_C_UINT: libc::c_ulong = 4;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris"
))]
const SIZEOF_C_LONG: libc::c_int = size_of::<libc::c_long>() as _;

pub const BIOCSETIF: libc::c_ulong =
    IOC_IN | ((SIZEOF_IFREQ & IOCPARM_MASK) << 16usize) | (('B' as libc::c_ulong) << 8usize) | 108;
pub const BIOCIMMEDIATE: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 112;
pub const BIOCGBLEN: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCGDLT: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 106;

pub const BIOCSBLEN: libc::c_ulong =
    IOC_INOUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCSHDRCMPLT: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 117;
pub const BIOCSRTIMEOUT: libc::c_ulong =
    IOC_IN | ((SIZEOF_TIMEVAL & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 109;

#[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "solaris"))]
pub const BIOCFEEDBACK: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 124;
#[cfg(target_os = "netbsd")]
pub const BIOCFEEDBACK: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 125;
// NOTE Could use BIOCSSEESENT on OS X, though set to 1 by default anyway

pub const DLT_NULL: libc::c_uint = 0;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris"
))]
const BPF_ALIGNMENT: libc::c_int = SIZEOF_C_LONG;
#[cfg(any(target_os = "openbsd", target_os = "macos", target_os = "ios", windows))]
const BPF_ALIGNMENT: libc::c_int = 4;

pub fn BPF_WORDALIGN(len: usize) -> usize {
    len.next_multiple_of(BPF_ALIGNMENT as usize)
}

// See /usr/include/net/if.h
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; IFNAMSIZ],
    #[cfg(target_os = "netbsd")]
    pub ifru_space: libc::sockaddr_storage,
    #[cfg(not(target_os = "netbsd"))]
    pub ifru_addr: nex_sys::SockAddr,
}

// See /usr/include/net/if_dl.h
// sdl_data does not match if_dl.h on OS X, since the size of 12 is a minimum.
// Will be unsafe
// when sdl_nlen > 40.
#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios"
))]
#[repr(C)]
pub struct sockaddr_dl {
    pub sdl_len: libc::c_uchar,
    pub sdl_family: libc::c_uchar,
    pub sdl_index: libc::c_ushort,
    pub sdl_type: libc::c_uchar,
    pub sdl_nlen: libc::c_uchar,
    pub sdl_alen: libc::c_uchar,
    pub sdl_slen: libc::c_uchar,
    pub sdl_data: [libc::c_char; 46],
}

// See man 4 bpf or /usr/include/net/bpf.h [windows: or Common/Packet32.h]
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    all(
        any(target_os = "macos", target_os = "ios"),
        target_pointer_width = "32"
    ),
    windows
))]
#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: libc::timeval,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: libc::c_ushort,
}

/// Number of bytes required to contain every defined field in `bpf_hdr`.
///
/// This can be smaller than `size_of::<bpf_hdr>()` because the C ABI may add
/// trailing padding to the Rust representation. In particular, macOS reports
/// an 18-byte BPF header on 64-bit targets even though the structure occupies
/// 20 bytes when stored as a standalone value.
pub const BPF_HDR_FIELD_LEN: usize =
    std::mem::offset_of!(bpf_hdr, bh_hdrlen) + std::mem::size_of::<libc::c_ushort>();

#[repr(C)]
pub struct timeval32 {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[cfg(any(
    target_os = "openbsd",
    all(
        any(target_os = "macos", target_os = "ios"),
        target_pointer_width = "64"
    )
))]
#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: libc::c_ushort,
}

#[cfg(not(windows))]
unsafe extern "C" {
    pub fn ioctl(d: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;
}

pub(crate) fn validate_record_lengths(
    header_len: usize,
    captured_len: usize,
    remaining: usize,
) -> io::Result<usize> {
    let record_len = header_len
        .checked_add(captured_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "BPF record length overflow"))?;
    if header_len < BPF_HDR_FIELD_LEN || record_len > remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid BPF record lengths",
        ));
    }
    Ok(record_len)
}

pub(crate) fn parse_records(buffer: &[u8]) -> io::Result<VecDeque<(usize, usize)>> {
    let mut packets = VecDeque::new();
    let mut cursor = 0;
    while cursor < buffer.len() {
        let remaining = buffer.len() - cursor;
        if remaining < BPF_HDR_FIELD_LEN {
            return Err(invalid_record());
        }
        let record = &buffer[cursor..];
        let header_len = u16::from_ne_bytes(
            *record[offset_of!(bpf_hdr, bh_hdrlen)..]
                .first_chunk()
                .ok_or_else(invalid_record)?,
        ) as usize;
        let captured_len = u32::from_ne_bytes(
            *record[offset_of!(bpf_hdr, bh_caplen)..]
                .first_chunk()
                .ok_or_else(invalid_record)?,
        ) as usize;
        let record_len = validate_record_lengths(header_len, captured_len, remaining)?;
        packets.push_back((cursor + header_len, captured_len));
        cursor = cursor
            .checked_add(BPF_WORDALIGN(record_len))
            .ok_or_else(invalid_record)?;
    }
    Ok(packets)
}

fn invalid_record() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid BPF record")
}
