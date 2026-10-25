//! QUIC wire packets (RFC 8999, RFC 9000, and RFC 9369).
//!
//! Parses public headers without keys, preserving protected packet numbers and
//! ciphertext as one opaque body. This module does not decrypt, authenticate,
//! implement TLS or connection state, or recognize stateless resets. A successful
//! parse establishes structural validity, not that a UDP payload is QUIC.
//!
//! Short headers require the destination connection ID length from connection
//! state. Packet number length, reserved bits, and key phase are protected and
//! deliberately not exposed as decoded fields. [`QuicDatagram`] splits coalesced
//! packets; short headers, Retry, Version Negotiation, and unknown versions
//! consume the remaining datagram because their boundaries are not encoded.

mod varint;
pub use varint::QuicVarInt;

use crate::{packet::Packet, parse::ParseError};
use bytes::Bytes;
use std::ops::Range;

/// QUIC version 1 (RFC 9000).
pub const QUIC_VERSION_1: u32 = 1;
/// QUIC version 2 (RFC 9369).
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;
/// Maximum connection ID length in QUIC v1 and v2.
pub const MAX_CONNECTION_ID_LEN: usize = 20;
/// Size of the Retry integrity tag in QUIC v1 and v2.
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// Versions whose version-specific public headers are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    /// Wire version number.
    pub const fn value(self) -> u32 {
        match self {
            Self::V1 => QUIC_VERSION_1,
            Self::V2 => QUIC_VERSION_2,
        }
    }

    /// Recognize a supported wire version number.
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            QUIC_VERSION_1 => Some(Self::V1),
            QUIC_VERSION_2 => Some(Self::V2),
            _ => None,
        }
    }

    pub(crate) fn packet_type(self, first: u8) -> QuicPacketType {
        let bits = (first >> 4) & 3;
        let v1_bits = match self {
            Self::V1 => bits,
            Self::V2 => (bits + 3) & 3,
        };
        match v1_bits {
            0 => QuicPacketType::Initial,
            1 => QuicPacketType::ZeroRtt,
            2 => QuicPacketType::Handshake,
            _ => QuicPacketType::Retry,
        }
    }

    pub(crate) fn type_bits(self, kind: QuicPacketType) -> Option<u8> {
        let bits = match kind {
            QuicPacketType::Initial => 0,
            QuicPacketType::ZeroRtt => 1,
            QuicPacketType::Handshake => 2,
            QuicPacketType::Retry => 3,
            _ => return None,
        };
        Some(
            match self {
                Self::V1 => bits,
                Self::V2 => (bits + 1) & 3,
            } << 4,
        )
    }
}

/// Publicly identifiable packet type, without removing header protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    /// Short header; its version is supplied by connection state, not the wire.
    OneRtt,
    /// Only the version-independent long header is interpreted.
    UnknownVersion,
}

/// Out-of-band information used to interpret captured QUIC packets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuicParseOptions {
    /// Required for short headers; `Some(0)` explicitly means a zero-length CID.
    pub short_header_dcid_len: Option<usize>,
    /// Accept a cleared fixed bit for known versions (RFC 9287).
    /// Does not affect Version Negotiation or unknown versions.
    pub allow_greased_fixed_bit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Layout {
    kind: QuicPacketType,
    version: Option<u32>,
    dcid: Range<usize>,
    scid: Option<Range<usize>>,
    token: Option<Range<usize>>,
    tag: Option<Range<usize>>,
    header_end: usize,
    end: usize,
    length: Option<u64>,
}

/// Allocation-free view of the first QUIC packet in a UDP payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicPacketSlice<'a> {
    data: &'a [u8],
    layout: Layout,
}

impl<'a> QuicPacketSlice<'a> {
    /// Parse a long-header packet with default options.
    /// Use [`Self::try_from_buf_with_options`] for short headers.
    pub fn try_from_buf(data: &'a [u8]) -> Result<Self, ParseError> {
        Self::try_from_buf_with_options(data, QuicParseOptions::default())
    }

    /// Parse the first packet, using connection context for short headers.
    /// Extra coalesced packets are excluded from [`Self::packet`].
    pub fn try_from_buf_with_options(
        data: &'a [u8],
        options: QuicParseOptions,
    ) -> Result<Self, ParseError> {
        let layout = parse_layout(data, options)?;
        Ok(Self {
            data: &data[..layout.end],
            layout,
        })
    }

    /// Exact packet bytes, including protected fields.
    pub fn packet(&self) -> &'a [u8] {
        self.data
    }
    /// Raw first byte; its low bits may be protected.
    pub fn first_byte(&self) -> u8 {
        self.data[0]
    }
    /// Public packet type.
    pub fn packet_type(&self) -> QuicPacketType {
        self.layout.kind
    }
    /// Wire version; zero means Version Negotiation, and `None` means short header.
    pub fn version(&self) -> Option<u32> {
        self.layout.version
    }
    /// Destination connection ID, possibly empty.
    pub fn destination_connection_id(&self) -> &'a [u8] {
        &self.data[self.layout.dcid.clone()]
    }
    /// Source connection ID; absent in a short header.
    pub fn source_connection_id(&self) -> Option<&'a [u8]> {
        self.layout.scid.clone().map(|r| &self.data[r])
    }
    /// Initial or Retry token; an Initial token may be empty.
    pub fn token(&self) -> Option<&'a [u8]> {
        self.layout.token.clone().map(|r| &self.data[r])
    }
    /// Unverified Retry integrity tag.
    pub fn retry_integrity_tag(&self) -> Option<&'a [u8]> {
        self.layout.tag.clone().map(|r| &self.data[r])
    }
    /// Long-header Length field, including protected packet number and ciphertext.
    pub fn declared_length(&self) -> Option<u64> {
        self.layout.length
    }
    /// Public header bytes. For protected packets this ends before the packet number.
    /// For Retry, VN, and unknown versions this ends after the source CID.
    pub fn header(&self) -> &'a [u8] {
        &self.data[..self.layout.header_end]
    }
    /// Bytes after the public header: opaque protected body, Retry token/tag,
    /// advertised versions, or unknown version-specific data.
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.layout.header_end..]
    }
    /// Offset at which the protected packet number begins, if present.
    pub fn packet_number_offset(&self) -> Option<usize> {
        matches!(
            self.layout.kind,
            QuicPacketType::Initial
                | QuicPacketType::ZeroRtt
                | QuicPacketType::Handshake
                | QuicPacketType::OneRtt
        )
        .then_some(self.layout.header_end)
    }
    /// Advertised versions, without allocating. Only present for VN packets.
    pub fn supported_versions(&self) -> Option<impl ExactSizeIterator<Item = u32> + 'a> {
        (self.layout.kind == QuicPacketType::VersionNegotiation).then(|| {
            self.payload()
                .as_chunks::<4>()
                .0
                .iter()
                .copied()
                .map(u32::from_be_bytes)
        })
    }
    /// Copy this packet into an owned representation.
    pub fn to_owned(&self) -> QuicPacket {
        QuicPacket {
            data: Bytes::copy_from_slice(self.data),
            layout: self.layout.clone(),
        }
    }
}

/// Owned QUIC wire packet. Parsed metadata cannot diverge from the retained bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicPacket {
    data: Bytes,
    layout: Layout,
}

impl QuicPacket {
    /// Copy and parse the first long-header packet.
    pub fn try_from_buf(data: &[u8]) -> Result<Self, ParseError> {
        Self::try_from_buf_with_options(data, QuicParseOptions::default())
    }
    /// Copy and parse the first packet with connection context.
    pub fn try_from_buf_with_options(
        data: &[u8],
        options: QuicParseOptions,
    ) -> Result<Self, ParseError> {
        Ok(QuicPacketSlice::try_from_buf_with_options(data, options)?.to_owned())
    }
    /// Parse owned bytes without copying their allocation.
    pub fn try_from_bytes(data: Bytes) -> Result<Self, ParseError> {
        Self::try_from_bytes_with_options(data, QuicParseOptions::default())
    }
    /// Parse owned bytes with connection context, retaining only the first packet.
    pub fn try_from_bytes_with_options(
        data: Bytes,
        options: QuicParseOptions,
    ) -> Result<Self, ParseError> {
        let layout = parse_layout(&data, options)?;
        Ok(Self {
            data: data.slice(..layout.end),
            layout,
        })
    }
    /// Borrow the decoded view and its public metadata.
    pub fn as_slice(&self) -> QuicPacketSlice<'_> {
        QuicPacketSlice {
            data: &self.data,
            layout: self.layout.clone(),
        }
    }
}

impl Packet for QuicPacket {
    /// Exact public header bytes; protected packet numbers belong to the body.
    type Header = Bytes;
    fn try_from_buf(data: &[u8]) -> Result<Self, ParseError> {
        Self::try_from_buf(data)
    }
    fn try_from_bytes(data: Bytes) -> Result<Self, ParseError> {
        Self::try_from_bytes(data)
    }
    fn to_bytes(&self) -> Bytes {
        self.data.clone()
    }
    fn header(&self) -> Bytes {
        self.data.slice(..self.layout.header_end)
    }
    fn payload(&self) -> Bytes {
        self.data.slice(self.layout.header_end..)
    }
    fn header_len(&self) -> usize {
        self.layout.header_end
    }
    fn payload_len(&self) -> usize {
        self.data.len() - self.layout.header_end
    }
    fn total_len(&self) -> usize {
        self.data.len()
    }
    fn into_parts(self) -> (Bytes, Bytes) {
        (self.header(), self.payload())
    }
}

/// Fused, allocation-free iterator over packets in one complete UDP datagram.
/// Yields one error on malformed or truncated input, then stops. An empty datagram
/// has no packets. This does not enforce connection-level coalescing rules.
#[derive(Clone, Debug)]
pub struct QuicDatagram<'a> {
    remaining: &'a [u8],
    options: QuicParseOptions,
}

impl<'a> QuicDatagram<'a> {
    /// Iterate a UDP payload with explicit short-header and fixed-bit policy.
    pub fn new(payload: &'a [u8], options: QuicParseOptions) -> Self {
        Self {
            remaining: payload,
            options,
        }
    }
}
impl<'a> Iterator for QuicDatagram<'a> {
    type Item = Result<QuicPacketSlice<'a>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match QuicPacketSlice::try_from_buf_with_options(self.remaining, self.options) {
            Ok(packet) => {
                self.remaining = &self.remaining[packet.packet().len()..];
                Some(Ok(packet))
            }
            Err(error) => {
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}
impl std::iter::FusedIterator for QuicDatagram<'_> {}

fn take(
    data: &[u8],
    cursor: &mut usize,
    length: usize,
    context: &'static str,
) -> Result<Range<usize>, ParseError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ParseError::InvalidLength {
            context,
            value: length,
        })?;
    if end > data.len() {
        return Err(ParseError::Truncated {
            context,
            expected: end,
            actual: data.len(),
        });
    }
    let range = *cursor..end;
    *cursor = end;
    Ok(range)
}
fn read_varint(data: &[u8], cursor: &mut usize) -> Result<u64, ParseError> {
    let (value, length) = QuicVarInt::decode(&data[*cursor..])?;
    *cursor += length;
    Ok(value.value())
}
fn size(value: u64, context: &'static str) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::InvalidLength {
        context,
        value: usize::MAX,
    })
}
fn check_fixed(first: u8, options: QuicParseOptions) -> Result<(), ParseError> {
    if first & 0x40 == 0 && !options.allow_greased_fixed_bit {
        return Err(ParseError::Malformed {
            context: "QUIC fixed bit",
        });
    }
    Ok(())
}
fn parse_layout(data: &[u8], options: QuicParseOptions) -> Result<Layout, ParseError> {
    let first = *data.first().ok_or(ParseError::BufferTooShort {
        context: "QUIC packet",
        minimum: 1,
        actual: 0,
    })?;
    let mut cursor = 1;
    if first & 0x80 == 0 {
        check_fixed(first, options)?;
        let length = options.short_header_dcid_len.ok_or(ParseError::Malformed {
            context: "QUIC short header requires destination CID length",
        })?;
        if length > MAX_CONNECTION_ID_LEN {
            return Err(ParseError::InvalidLength {
                context: "QUIC destination CID",
                value: length,
            });
        }
        let dcid = take(data, &mut cursor, length, "QUIC destination CID")?;
        let header_end = cursor;
        take(data, &mut cursor, 1, "QUIC protected packet number")?;
        return Ok(Layout {
            kind: QuicPacketType::OneRtt,
            version: None,
            dcid,
            scid: None,
            token: None,
            tag: None,
            header_end,
            end: data.len(),
            length: None,
        });
    }
    let version_range = take(data, &mut cursor, 4, "QUIC version")?;
    let v = &data[version_range];
    let version = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
    let known = QuicVersion::from_value(version);
    let mut cid = |context| -> Result<Range<usize>, ParseError> {
        let field = take(data, &mut cursor, 1, context)?;
        let length = data[field.start] as usize;
        if known.is_some() && length > MAX_CONNECTION_ID_LEN {
            return Err(ParseError::InvalidLength {
                context,
                value: length,
            });
        }
        take(data, &mut cursor, length, context)
    };
    let dcid = cid("QUIC destination CID")?;
    let scid = cid("QUIC source CID")?;
    let mut layout = Layout {
        kind: QuicPacketType::UnknownVersion,
        version: Some(version),
        dcid,
        scid: Some(scid),
        token: None,
        tag: None,
        header_end: cursor,
        end: data.len(),
        length: None,
    };
    if version == 0 {
        let length = data.len() - cursor;
        if length == 0 || !length.is_multiple_of(4) {
            return Err(ParseError::InvalidLength {
                context: "QUIC supported versions",
                value: length,
            });
        }
        layout.kind = QuicPacketType::VersionNegotiation;
        return Ok(layout);
    }
    let Some(known) = known else {
        return Ok(layout);
    };
    check_fixed(first, options)?;
    layout.kind = known.packet_type(first);
    if layout.kind == QuicPacketType::Retry {
        let length = data.len() - cursor;
        // Retry requires a nonempty token followed by its 16-byte integrity tag.
        if length <= RETRY_INTEGRITY_TAG_LEN {
            return Err(ParseError::InvalidLength {
                context: "QUIC Retry token and tag",
                value: length,
            });
        }
        let tag_start = data.len() - RETRY_INTEGRITY_TAG_LEN;
        layout.token = Some(cursor..tag_start);
        layout.tag = Some(tag_start..data.len());
        return Ok(layout);
    }
    if layout.kind == QuicPacketType::Initial {
        let length = size(read_varint(data, &mut cursor)?, "QUIC token length")?;
        layout.token = Some(take(data, &mut cursor, length, "QUIC Initial token")?);
    }
    let length = read_varint(data, &mut cursor)?;
    if length == 0 {
        return Err(ParseError::InvalidLength {
            context: "QUIC protected body",
            value: 0,
        });
    }
    layout.header_end = cursor;
    layout.length = Some(length);
    take(
        data,
        &mut cursor,
        size(length, "QUIC Length")?,
        "QUIC protected body",
    )?;
    layout.end = cursor;
    Ok(layout)
}
