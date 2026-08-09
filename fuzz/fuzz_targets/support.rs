use std::borrow::Cow;

/// Decode review-friendly `hex:` corpus entries while accepting normal raw
/// libFuzzer inputs without transformation.
pub fn decode_seed(data: &[u8]) -> Cow<'_, [u8]> {
    let Some(hex) = data.strip_prefix(b"hex:") else {
        return Cow::Borrowed(data);
    };
    let digits: Vec<u8> = hex
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Cow::Borrowed(data);
    }

    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let (Some(high), Some(low)) = (hex_value(pair[0]), hex_value(pair[1])) else {
            return Cow::Borrowed(data);
        };
        decoded.push((high << 4) | low);
    }
    Cow::Owned(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
