//! Intrinsic hexadecimal representation support for fixed-size Stacks values.

use core::fmt;

/// Error produced while decoding a hexadecimal value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HexError {
    /// The source contained an unexpected number of characters.
    BadLength(usize),
    /// The source contained a non-hexadecimal character.
    BadCharacter(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength(length) => write!(formatter, "bad length {length} for hex string"),
            Self::BadCharacter(character) => {
                write!(formatter, "bad character {character} for hex string")
            }
        }
    }
}

impl std::error::Error for HexError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        match self {
            Self::BadLength(_) => "hex string non-64 length",
            Self::BadCharacter(_) => "bad hex character",
        }
    }
}

/// Decode an arbitrary-length hexadecimal string.
pub fn decode(value: &str) -> Result<Vec<u8>, HexError> {
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let mut characters = value.chars();

    while let Some(high) = characters.next() {
        let Some(low) = characters.next() else {
            return Err(HexError::BadLength(value.len()));
        };
        let high = high.to_digit(16).ok_or(HexError::BadCharacter(high))?;
        let low = low.to_digit(16).ok_or(HexError::BadCharacter(low))?;
        bytes.push((high * 16 + low) as u8);
    }

    Ok(bytes)
}

/// Decode a hexadecimal string into an array of exactly `N` bytes.
pub fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], HexError> {
    let bytes = decode(value)?;
    bytes
        .try_into()
        .map_err(|_bytes: Vec<u8>| HexError::BadLength(value.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_error_details() {
        assert_eq!(decode_array::<4>("deadbeef"), Ok([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_array::<4>("deadbe"), Err(HexError::BadLength(6)));
        assert_eq!(decode_array::<4>("deadbee"), Err(HexError::BadLength(7)));
        assert_eq!(
            decode_array::<4>("deadbeeg"),
            Err(HexError::BadCharacter('g'))
        );
        assert_eq!(
            HexError::BadLength(8).to_string(),
            "bad length 8 for hex string"
        );

        let error = crate::Hash160::from_hex("deadbeef").unwrap_err();
        assert_eq!(error, HexError::BadLength(8));
        assert_eq!(error.to_string(), "bad length 8 for hex string");
    }
}
