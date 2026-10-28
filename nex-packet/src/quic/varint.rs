use crate::parse::ParseError;

/// A validated QUIC unsigned 62-bit variable-length integer (RFC 9000, Section 16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuicVarInt(u64);

impl QuicVarInt {
    /// Largest representable integer.
    pub const MAX: u64 = (1 << 62) - 1;
    /// Validate a value before encoding it.
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }
    /// Integer value.
    pub const fn value(self) -> u64 {
        self.0
    }
    /// Minimum encoding size in bytes.
    pub const fn encoded_len(self) -> usize {
        match self.0 {
            0..=63 => 1,
            64..=16383 => 2,
            16384..=1073741823 => 4,
            _ => 8,
        }
    }
    /// Decode one integer, returning its actual wire size. Nonminimal encodings
    /// are legal and accepted. Trailing bytes are left to the caller.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), ParseError> {
        let first = *data.first().ok_or(ParseError::BufferTooShort {
            context: "QUIC variable integer",
            minimum: 1,
            actual: 0,
        })?;
        let length = 1usize << (first >> 6);
        if data.len() < length {
            return Err(ParseError::Truncated {
                context: "QUIC variable integer",
                expected: length,
                actual: data.len(),
            });
        }
        let mut value = (first & 0x3f) as u64;
        for byte in &data[1..length] {
            value = (value << 8) | u64::from(*byte);
        }
        Ok((Self(value), length))
    }
    /// Encode in the minimum number of bytes. Returns bytes written, leaving
    /// the rest of the output untouched. A short output is not modified.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ParseError> {
        self.encode_with_len(output, self.encoded_len())
    }
    /// Encode using an explicit legal width, including nonminimal encodings.
    /// Invalid widths or insufficient output leave the buffer untouched.
    pub fn encode_with_len(self, output: &mut [u8], length: usize) -> Result<usize, ParseError> {
        let prefix = match length {
            1 => 0,
            2 => 0x40,
            4 => 0x80,
            8 => 0xc0,
            _ => {
                return Err(ParseError::InvalidLength {
                    context: "QUIC variable integer width",
                    value: length,
                });
            }
        };
        if length < self.encoded_len() {
            return Err(ParseError::InvalidLength {
                context: "QUIC variable integer width",
                value: length,
            });
        }
        if output.len() < length {
            return Err(ParseError::BufferTooShort {
                context: "QUIC variable integer output",
                minimum: length,
                actual: output.len(),
            });
        }
        output[..length].copy_from_slice(&self.0.to_be_bytes()[8 - length..]);
        output[0] |= prefix;
        Ok(length)
    }
}
