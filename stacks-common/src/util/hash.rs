// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Compatibility facade for canonical hash values and cryptographic behavior.

use std::fmt::Write;

pub use stacks_crypto::hash::*;
pub use stacks_primitives::hex::decode as hex_bytes;

use crate::util::{HexDeser, HexError, HexSer};

macro_rules! impl_common_hex_traits {
    ($type:path, $length:expr) => {
        impl HexDeser for $type {
            fn try_from_hex(value: &str) -> Result<Self, HexError> {
                let bytes = hex_bytes(value)?;
                Self::from_bytes(&bytes).ok_or(HexError::BadLength(value.len()))
            }
        }

        impl HexSer for $type {
            fn fmt_hex(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::LowerHex::fmt(self, formatter)
            }
        }
    };
}

impl_common_hex_traits!(stacks_crypto::hash::Hash160, 20);
impl_common_hex_traits!(stacks_crypto::hash::Keccak256Hash, 32);
impl_common_hex_traits!(stacks_crypto::hash::Sha256Sum, 32);
impl_common_hex_traits!(stacks_crypto::hash::Sha512Sum, 64);
impl_common_hex_traits!(stacks_crypto::hash::Sha512Trunc256Sum, 32);
impl_common_hex_traits!(stacks_crypto::hash::DoubleSha256, 32);
impl_common_hex_traits!(stacks_crypto::hash::Txid, 32);

/// Convert a binary-encoded string to its corresponding bytes.
pub fn bin_bytes(value: &str) -> Result<Vec<u8>, HexError> {
    let mut bytes = Vec::with_capacity(value.len() / 8 + 1);
    let mut next = 0u8;
    for (index, character) in value.chars().rev().enumerate() {
        if character != '0' && character != '1' {
            return Err(HexError::BadCharacter(character));
        }
        if character == '1' {
            next |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            bytes.push(next);
            next = 0;
        }
    }
    if !value.len().is_multiple_of(8) {
        bytes.push(next);
    }
    bytes.reverse();
    Ok(bytes)
}

const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

/// Convert bytes to lowercase hexadecimal, optionally prefixed by `0x`.
pub fn to_hex_prefixed(value: &[u8], prefix: bool) -> String {
    let prefix_len = if prefix { 2 } else { 0 };
    let mut bytes = Vec::with_capacity(value.len() * 2 + prefix_len);

    if prefix {
        bytes.extend_from_slice(b"0x");
    }
    for &byte in value {
        bytes.push(HEX_CHARS[(byte >> 4) as usize]);
        bytes.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }

    String::from_utf8(bytes).expect("hexadecimal ASCII is valid UTF-8")
}

pub fn to_hex(value: &[u8]) -> String {
    to_hex_prefixed(value, false)
}

pub fn to_bin(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len() * 8);
    for byte in value {
        write!(result, "{byte:08b}").expect("writing to a String is infallible");
    }
    result
}

pub fn bytes_to_hex(value: &[u8]) -> String {
    to_hex(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_and_hex_helpers_round_trip() {
        assert_eq!(hex_bytes("00abff").unwrap(), [0x00, 0xab, 0xff]);
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(to_hex_prefixed(&[0xab], true), "0xab");
        assert_eq!(bin_bytes("00101010").unwrap(), [42]);
        assert_eq!(bin_bytes("101010").unwrap(), [42]);
        assert_eq!(to_bin(&[42]), "00101010");
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        assert!(hex_bytes("0").is_err());
        assert!(hex_bytes("zz").is_err());
        assert!(bin_bytes("102").is_err());
    }
}
