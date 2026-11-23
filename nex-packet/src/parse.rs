//! Shared contracts for diagnosable packet parsing APIs.
//!
//! Packet types expose `try_from_buf(&[u8])` for borrowed input and
//! `try_from_bytes(bytes::Bytes)` for owned input. Both return [`ParseError`].
//! Parsers that support alternate validation behavior accept [`ParseMode`]
//! through a `*_with_mode` method instead of adding more method-name suffixes.
//!
//! The deprecated [`crate::packet::Packet::from_buf`] and
//! [`crate::packet::Packet::from_bytes`] methods discard parse errors.

use core::fmt;

/// Controls validation behavior for parsers with length-delimited payloads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseMode {
    /// Preserve captured payload bytes when a declared length is missing or incomplete.
    #[default]
    Lenient,
    /// Reject input whose captured length is shorter than its declared length.
    Strict,
}

impl ParseMode {
    pub(crate) const fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

/// Structured error returned by `try_from_*` parsing APIs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input buffer was shorter than the protocol minimum.
    BufferTooShort {
        /// Human-readable parse context.
        context: &'static str,
        /// Minimum required number of bytes.
        minimum: usize,
        /// Actual number of bytes available.
        actual: usize,
    },
    /// A length-like field contained an invalid value.
    InvalidLength {
        /// Human-readable parse context.
        context: &'static str,
        /// Parsed value that failed validation.
        value: usize,
    },
    /// The packet contains a malformed header field.
    Malformed {
        /// Human-readable parse context.
        context: &'static str,
    },
    /// The packet payload was truncated relative to its header lengths.
    Truncated {
        /// Human-readable parse context.
        context: &'static str,
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes available.
        actual: usize,
    },
    /// Parsing failed because a compression loop or excessive indirection was detected.
    CompressionLoop {
        /// Human-readable parse context.
        context: &'static str,
    },
    /// Parsing failed because an unsupported or invalid pointer/compression form was encountered.
    InvalidCompression {
        /// Human-readable parse context.
        context: &'static str,
    },
    /// A UTF-8 conversion failed while parsing text-like data.
    InvalidUtf8 {
        /// Human-readable parse context.
        context: &'static str,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BufferTooShort {
                context,
                minimum,
                actual,
            } => write!(
                f,
                "{context}: buffer too short (expected at least {minimum} bytes, got {actual})"
            ),
            ParseError::InvalidLength { context, value } => {
                write!(f, "{context}: invalid length value {value}")
            }
            ParseError::Malformed { context } => write!(f, "{context}: malformed packet data"),
            ParseError::Truncated {
                context,
                expected,
                actual,
            } => write!(
                f,
                "{context}: truncated payload (expected {expected} bytes, got {actual})"
            ),
            ParseError::CompressionLoop { context } => {
                write!(f, "{context}: compression pointer loop detected")
            }
            ParseError::InvalidCompression { context } => {
                write!(f, "{context}: invalid compression pointer")
            }
            ParseError::InvalidUtf8 { context } => {
                write!(f, "{context}: invalid UTF-8 sequence")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::ParseError;

    fn assert_error_contract<T: std::error::Error + Send + Sync + 'static>() {}

    #[test]
    fn parse_error_implements_public_error_contract() {
        assert_error_contract::<ParseError>();
    }
}
