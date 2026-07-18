use core::fmt;

/// Error returned when packet builder inputs cannot be encoded safely.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// A packet field cannot represent the supplied number of bytes.
    LengthOverflow {
        /// Protocol field or section that overflowed.
        context: &'static str,
        /// Largest representable value.
        maximum: usize,
        /// Supplied or calculated value.
        actual: usize,
    },
    /// A numeric protocol field is outside its representable range.
    ValueOutOfRange {
        /// Protocol field containing the value.
        context: &'static str,
        /// Largest accepted value.
        maximum: usize,
        /// Supplied value.
        actual: usize,
    },
    /// A variable-size field is shorter than the protocol minimum.
    LengthTooShort {
        /// Protocol field or section that is too short.
        context: &'static str,
        /// Smallest accepted length.
        minimum: usize,
        /// Supplied length.
        actual: usize,
    },
    /// A fixed-size field has an unexpected length.
    InvalidFieldLength {
        /// Protocol field with the invalid length.
        context: &'static str,
        /// Required number of bytes.
        expected: usize,
        /// Supplied number of bytes.
        actual: usize,
    },
    /// Source and destination addresses cannot form a checksum pseudo-header.
    AddressFamilyMismatch {
        /// Transport protocol requiring the pseudo-header.
        context: &'static str,
    },
    /// An internally assembled packet could not be decoded.
    SerializationFailed {
        /// Packet section that failed to round-trip.
        context: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow {
                context,
                maximum,
                actual,
            } => write!(
                f,
                "{context} is too long: maximum is {maximum} bytes, got {actual}"
            ),
            Self::ValueOutOfRange {
                context,
                maximum,
                actual,
            } => write!(
                f,
                "{context} is out of range: maximum is {maximum}, got {actual}"
            ),
            Self::LengthTooShort {
                context,
                minimum,
                actual,
            } => write!(
                f,
                "{context} is too short: minimum is {minimum} bytes, got {actual}"
            ),
            Self::InvalidFieldLength {
                context,
                expected,
                actual,
            } => write!(
                f,
                "{context} has an invalid length: expected {expected} bytes, got {actual}"
            ),
            Self::AddressFamilyMismatch { context } => write!(
                f,
                "{context} checksum requires source and destination addresses from the same family"
            ),
            Self::SerializationFailed { context } => {
                write!(f, "failed to serialize {context}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::BuildError;

    fn assert_error_contract<T: std::error::Error + Send + Sync + 'static>() {}

    #[test]
    fn build_error_implements_public_error_contract() {
        assert_error_contract::<BuildError>();
    }
}
