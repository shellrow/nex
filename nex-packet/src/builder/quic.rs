//! Validated QUIC public-header serialization.
//!
//! Builders do not perform packet/header protection or compute Retry tags.
//! Callers supply the protected packet number plus ciphertext (including its
//! authentication tag), or a Retry integrity tag. These must correspond to the
//! exact emitted header: changing a header invalidates authentication. Lengths
//! use minimal QUIC variable-integer encodings. Use parsed packets for lossless
//! reserialization of captures with other encodings.

use crate::{
    builder::BuildError,
    packet::Packet,
    quic::{
        MAX_CONNECTION_ID_LEN, QuicPacket, QuicPacketType, QuicParseOptions, QuicVarInt,
        QuicVersion,
    },
};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug)]
enum Body {
    Protected { token: Option<Bytes>, data: Bytes },
    Retry { token: Bytes, tag: [u8; 16] },
    Versions(Vec<u32>),
}

/// Builder for QUIC v1/v2 public headers and caller-supplied opaque bodies.
#[derive(Clone, Debug)]
pub struct QuicPacketBuilder {
    version: Option<QuicVersion>,
    kind: QuicPacketType,
    destination: Bytes,
    source: Bytes,
    first_byte: Option<u8>,
    body: Body,
}

impl QuicPacketBuilder {
    fn protected(
        version: Option<QuicVersion>,
        kind: QuicPacketType,
        token: Option<Bytes>,
        data: Bytes,
    ) -> Self {
        Self {
            version,
            kind,
            destination: Bytes::new(),
            source: Bytes::new(),
            first_byte: None,
            body: Body::Protected { token, data },
        }
    }
    /// Initial packet with a possibly empty token and an opaque protected body.
    pub fn initial(version: QuicVersion, token: Bytes, protected_body: Bytes) -> Self {
        Self::protected(
            Some(version),
            QuicPacketType::Initial,
            Some(token),
            protected_body,
        )
    }
    /// 0-RTT packet with an opaque protected body.
    pub fn zero_rtt(version: QuicVersion, protected_body: Bytes) -> Self {
        Self::protected(Some(version), QuicPacketType::ZeroRtt, None, protected_body)
    }
    /// Handshake packet with an opaque protected body.
    pub fn handshake(version: QuicVersion, protected_body: Bytes) -> Self {
        Self::protected(
            Some(version),
            QuicPacketType::Handshake,
            None,
            protected_body,
        )
    }
    /// Short-header packet. The version is not encoded on the wire.
    pub fn one_rtt(protected_body: Bytes) -> Self {
        Self::protected(None, QuicPacketType::OneRtt, None, protected_body)
    }
    /// Retry packet with a nonempty token and caller-computed integrity tag.
    pub fn retry(version: QuicVersion, token: Bytes, integrity_tag: [u8; 16]) -> Self {
        Self {
            version: Some(version),
            kind: QuicPacketType::Retry,
            destination: Bytes::new(),
            source: Bytes::new(),
            first_byte: None,
            body: Body::Retry {
                token,
                tag: integrity_tag,
            },
        }
    }
    /// Version Negotiation packet advertising at least one nonzero version.
    pub fn version_negotiation(versions: Vec<u32>) -> Self {
        Self {
            version: None,
            kind: QuicPacketType::VersionNegotiation,
            destination: Bytes::new(),
            source: Bytes::new(),
            first_byte: None,
            body: Body::Versions(versions),
        }
    }
    /// Destination connection ID (up to 20 bytes, or 255 for VN).
    pub fn destination_connection_id(mut self, id: Bytes) -> Self {
        self.destination = id;
        self
    }
    /// Source connection ID. Must remain empty for short headers.
    pub fn source_connection_id(mut self, id: Bytes) -> Self {
        self.source = id;
        self
    }
    /// Supply the final first byte, including protected/unused bits and spin bit.
    /// Its header form and public type must match the constructor. A cleared
    /// fixed bit is allowed for callers using RFC 9287. The default has fixed
    /// bit set and all protected/unused/spin bits zero; it is not encryption.
    pub fn first_byte(mut self, value: u8) -> Self {
        self.first_byte = Some(value);
        self
    }

    /// Validate public fields and serialize. Does not validate cryptographic
    /// authenticity, minimum datagram size, or connection-level requirements.
    pub fn build(self) -> Result<QuicPacket, BuildError> {
        let short = self.kind == QuicPacketType::OneRtt;
        let max_cid = if self.kind == QuicPacketType::VersionNegotiation {
            255
        } else {
            MAX_CONNECTION_ID_LEN
        };
        for (context, length, maximum) in [
            ("QUIC destination CID", self.destination.len(), max_cid),
            (
                "QUIC source CID",
                self.source.len(),
                if short { 0 } else { max_cid },
            ),
        ] {
            if length > maximum {
                return Err(BuildError::LengthOverflow {
                    context,
                    maximum,
                    actual: length,
                });
            }
        }
        let default_first = if short {
            0x40
        } else {
            0xc0 | self
                .version
                .and_then(|v| v.type_bits(self.kind))
                .unwrap_or(0)
        };
        let first = self.first_byte.unwrap_or(default_first);
        let mask = if self.kind == QuicPacketType::VersionNegotiation || short {
            0x80
        } else {
            0xb0
        };
        if first & mask != default_first & mask {
            return Err(BuildError::SerializationFailed {
                context: "QUIC first byte does not match packet type",
            });
        }
        let mut out = BytesMut::new();
        out.put_u8(first);
        if !short {
            out.put_u32(self.version.map_or(0, QuicVersion::value));
            out.put_u8(self.destination.len() as u8);
        }
        out.extend_from_slice(&self.destination);
        if !short {
            out.put_u8(self.source.len() as u8);
            out.extend_from_slice(&self.source);
        }
        match self.body {
            Body::Protected { token, data } => {
                if data.is_empty() {
                    return Err(BuildError::LengthTooShort {
                        context: "QUIC protected body",
                        minimum: 1,
                        actual: 0,
                    });
                }
                if let Some(token) = token {
                    append_length(&mut out, token.len())?;
                    out.extend_from_slice(&token);
                }
                if !short {
                    append_length(&mut out, data.len())?;
                }
                out.extend_from_slice(&data);
            }
            Body::Retry { token, tag } => {
                if token.is_empty() {
                    return Err(BuildError::LengthTooShort {
                        context: "QUIC Retry token",
                        minimum: 1,
                        actual: 0,
                    });
                }
                out.extend_from_slice(&token);
                out.extend_from_slice(&tag);
            }
            Body::Versions(versions) => {
                if versions.is_empty() {
                    return Err(BuildError::LengthTooShort {
                        context: "QUIC supported versions",
                        minimum: 1,
                        actual: 0,
                    });
                }
                if versions.contains(&0) {
                    return Err(BuildError::SerializationFailed {
                        context: "QUIC advertised version zero",
                    });
                }
                for version in versions {
                    out.put_u32(version);
                }
            }
        }
        QuicPacket::try_from_bytes_with_options(
            out.freeze(),
            QuicParseOptions {
                short_header_dcid_len: short.then_some(self.destination.len()),
                allow_greased_fixed_bit: true,
            },
        )
        .map_err(|_| BuildError::SerializationFailed {
            context: "QUIC packet",
        })
    }
    /// Validate and serialize to exact wire bytes.
    pub fn to_bytes(self) -> Result<Bytes, BuildError> {
        self.build().map(|p| p.to_bytes())
    }
}

fn append_length(out: &mut BytesMut, length: usize) -> Result<(), BuildError> {
    let value = QuicVarInt::new(length as u64).ok_or(BuildError::LengthOverflow {
        context: "QUIC variable length",
        maximum: usize::try_from(QuicVarInt::MAX).unwrap_or(usize::MAX),
        actual: length,
    })?;
    let mut bytes = [0; 8];
    let size = value
        .encode(&mut bytes)
        .map_err(|_| BuildError::SerializationFailed {
            context: "QUIC variable length",
        })?;
    out.extend_from_slice(&bytes[..size]);
    Ok(())
}
