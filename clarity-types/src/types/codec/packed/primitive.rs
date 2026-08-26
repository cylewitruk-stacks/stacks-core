// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Primitive packed-value encodings shared by typed decoding and reconstruction.

use std::{slice, str};

use super::PackedValueError;
use crate::representations::{CONTRACT_NAME_REGEX, ContractName, MAX_STRING_LEN};
use crate::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value};

/// Return the packed body length of a principal.
pub fn principal_body_len(principal: &PrincipalData) -> Result<usize, PackedValueError> {
    match principal {
        PrincipalData::Standard(_) => Ok(22),
        PrincipalData::Contract(contract) => 22usize
            .checked_add(contract.name.as_str().len())
            .ok_or(PackedValueError::SizeOverflow),
    }
}

/// Return the minimum unsigned big-endian width, allowing zero width for zero.
pub fn packed_uint_width(value: u128) -> usize {
    if value == 0 {
        0
    } else {
        (u128::BITS as usize - value.leading_zeros() as usize).div_ceil(8)
    }
}

/// Return the minimum two's-complement big-endian width, allowing zero width for zero.
pub fn packed_int_width(value: i128) -> usize {
    if value == 0 {
        return 0;
    }
    let bytes = value.to_be_bytes();
    let mut start = 0usize;
    while start < 15 {
        let byte = bytes[start];
        let next = bytes[start + 1];
        if (byte == 0 && next & 0x80 == 0) || (byte == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    16 - start
}

/// Return the widest active unsigned integer in a homogeneous lane.
pub fn unsigned_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    values.iter().try_fold(0usize, |width, value| match value {
        Value::UInt(value) => Ok(width.max(packed_uint_width(*value))),
        _ => Err(PackedValueError::TypeMismatch),
    })
}

/// Return the widest active signed integer in a homogeneous lane.
pub fn signed_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    values.iter().try_fold(0usize, |width, value| match value {
        Value::Int(value) => Ok(width.max(packed_int_width(*value))),
        _ => Err(PackedValueError::TypeMismatch),
    })
}

/// Append a packed principal body.
pub fn encode_principal(principal: &PrincipalData, output: &mut Vec<u8>) {
    match principal {
        PrincipalData::Standard(principal) => {
            output.push(0);
            output.push(principal.version());
            output.extend_from_slice(&principal.1);
        }
        PrincipalData::Contract(contract) => {
            output.push(1);
            output.push(contract.issuer.version());
            output.extend_from_slice(&contract.issuer.1);
            output.extend_from_slice(contract.name.as_str().as_bytes());
        }
    }
}

/// A validated borrowed view over a packed principal body.
pub enum PackedPrincipal<'a> {
    /// A standard principal's version and hash bytes.
    Standard(&'a [u8; 21]),
    /// A contract principal split into its issuer and validated name.
    Contract {
        /// Standard-principal issuer bytes.
        issuer: &'a [u8; 21],
        /// Validated contract name without its consensus length prefix.
        name: &'a str,
    },
}

impl<'a> PackedPrincipal<'a> {
    /// Parse one complete packed principal body.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackedValueError> {
        let (&kind, body) = bytes
            .split_first()
            .ok_or(PackedValueError::InvalidRecord("missing principal kind"))?;
        match kind {
            0 => Ok(Self::Standard(parse_standard_principal(body)?)),
            1 => {
                let issuer = body.get(..21).ok_or(PackedValueError::InvalidRecord(
                    "invalid contract principal",
                ))?;
                let issuer = parse_standard_principal(issuer)?;
                let name = parse_contract_name(&body[21..])?;
                Ok(Self::Contract { issuer, name })
            }
            _ => Err(PackedValueError::InvalidRecord("invalid principal kind")),
        }
    }

    /// Return this principal's consensus-serialized byte length.
    pub fn consensus_byte_len(&self) -> Result<u32, PackedValueError> {
        match self {
            Self::Standard(_) => Ok(22),
            Self::Contract { name, .. } => checked_logical_add(
                23,
                u32::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?,
            ),
        }
    }

    /// Materialize this packed principal.
    pub fn to_principal_data(&self) -> Result<PrincipalData, PackedValueError> {
        match self {
            Self::Standard(principal) => Ok(PrincipalData::Standard(decode_standard_principal(
                principal,
            )?)),
            Self::Contract { issuer, name } => {
                let issuer = decode_standard_principal(issuer)?;
                let name = ContractName::try_from((*name).to_owned())?;
                Ok(PrincipalData::Contract(QualifiedContractIdentifier {
                    issuer,
                    name,
                }))
            }
        }
    }
}

/// Validate one minimally encoded signed scalar.
pub fn validate_canonical_signed_scalar(bytes: &[u8]) -> Result<(), PackedValueError> {
    if bytes.is_empty() {
        return Err(PackedValueError::InvalidRecord(
            "canonical signed integer is empty",
        ));
    }
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "signed integer exceeds 16 bytes",
        ));
    }
    if bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        return Err(PackedValueError::InvalidRecord(
            "non-minimal signed integer",
        ));
    }
    Ok(())
}

/// Validate one minimally encoded unsigned scalar.
pub fn validate_canonical_unsigned_scalar(bytes: &[u8]) -> Result<(), PackedValueError> {
    if bytes.is_empty() {
        return Err(PackedValueError::InvalidRecord(
            "canonical unsigned integer is empty",
        ));
    }
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "unsigned integer exceeds 16 bytes",
        ));
    }
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(PackedValueError::InvalidRecord(
            "non-minimal unsigned integer",
        ));
    }
    Ok(())
}

/// Return whether a byte is admitted by Clarity's ASCII string grammar.
pub fn valid_ascii_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || byte.is_ascii_punctuation() || byte.is_ascii_whitespace()
}

/// Return a sequence's consensus length, including its prefix and length field.
pub fn logical_sequence_len(data_len: usize) -> Result<u32, PackedValueError> {
    u32::try_from(data_len)
        .map_err(|_| PackedValueError::SizeOverflow)?
        .checked_add(5)
        .ok_or(PackedValueError::SizeOverflow)
}

/// Validate and borrow an exactly sized standard-principal body.
fn parse_standard_principal(bytes: &[u8]) -> Result<&[u8; 21], PackedValueError> {
    let bytes: &[u8; 21] = bytes
        .try_into()
        .map_err(|_| PackedValueError::InvalidRecord("invalid standard principal"))?;
    if bytes[0] >= 32 {
        return Err(PackedValueError::InvalidRecord(
            "invalid standard principal",
        ));
    }
    Ok(bytes)
}

/// Validate and borrow the UTF-8 contract-name suffix of a packed principal.
fn parse_contract_name(bytes: &[u8]) -> Result<&str, PackedValueError> {
    let name = str::from_utf8(bytes)
        .map_err(|_| PackedValueError::InvalidRecord("invalid contract name UTF-8"))?;
    if name.is_empty()
        || name.len() > MAX_STRING_LEN as usize
        || !CONTRACT_NAME_REGEX.is_match(name)
    {
        return Err(PackedValueError::InvalidRecord("invalid contract name"));
    }
    Ok(name)
}

/// Add one tuple field's name and child to its running consensus length.
pub fn tuple_logical_add(
    current: u32,
    name: &str,
    child_len: u32,
) -> Result<u32, PackedValueError> {
    current
        .checked_add(1)
        .and_then(|length| length.checked_add(u32::try_from(name.len()).ok()?))
        .and_then(|length| length.checked_add(child_len))
        .ok_or(PackedValueError::SizeOverflow)
}

/// Split a packed list into its little-endian element count and element region.
pub fn split_list(bytes: &[u8]) -> Result<(usize, &[u8]), PackedValueError> {
    let count = read_u32_le(bytes)? as usize;
    Ok((count, &bytes[4..]))
}

/// A validated borrowed view over a non-empty, fixed-width integer lane.
pub struct IntegerLane<'a> {
    /// Concatenated fixed-width integer elements.
    elements: &'a [u8],
    /// Encoded bytes occupied by each element.
    width: usize,
    /// Number of elements represented by the lane.
    count: usize,
}

impl<'a> IntegerLane<'a> {
    /// Parse a canonical unsigned-integer lane.
    pub fn parse_unsigned(elements: &'a [u8], count: usize) -> Result<Self, PackedValueError> {
        let lane = Self::parse(elements, count, "canonical unsigned lane is empty")?;
        if lane.width > 16 {
            return Err(PackedValueError::InvalidRecord(
                "unsigned lane exceeds 16 bytes",
            ));
        }
        if lane.width > 1 && !lane.iter().any(|value| value[0] != 0) {
            return Err(PackedValueError::InvalidRecord("non-minimal unsigned lane"));
        }
        Ok(lane)
    }

    /// Parse a canonical signed-integer lane.
    pub fn parse_signed(elements: &'a [u8], count: usize) -> Result<Self, PackedValueError> {
        let lane = Self::parse(elements, count, "canonical signed lane is empty")?;
        if lane.width > 16 {
            return Err(PackedValueError::InvalidRecord(
                "signed lane exceeds 16 bytes",
            ));
        }
        if lane.width > 1
            && !lane
                .iter()
                .any(|value| minimal_signed_slice_width(value) == lane.width)
        {
            return Err(PackedValueError::InvalidRecord("non-minimal signed lane"));
        }
        Ok(lane)
    }

    /// Validate common non-empty, evenly-divisible lane framing.
    fn parse(
        elements: &'a [u8],
        count: usize,
        empty_error: &'static str,
    ) -> Result<Self, PackedValueError> {
        if count == 0 || elements.is_empty() {
            return Err(PackedValueError::InvalidRecord(empty_error));
        }
        if !elements.len().is_multiple_of(count) {
            return Err(PackedValueError::InvalidRecord(
                "lane length is not divisible by count",
            ));
        }
        Ok(Self {
            elements,
            width: elements.len() / count,
            count,
        })
    }

    /// Return the width of one packed lane element.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Iterate over exactly `count` validated elements.
    pub fn iter(&self) -> slice::ChunksExact<'a, u8> {
        debug_assert_eq!(self.elements.len(), self.width * self.count);
        self.elements.chunks_exact(self.width)
    }

    /// Return the consensus-serialized length of the lane's elements.
    pub fn consensus_byte_len(&self) -> Result<u32, PackedValueError> {
        u32::try_from(self.count)
            .map_err(|_| PackedValueError::SizeOverflow)?
            .checked_mul(17)
            .ok_or(PackedValueError::SizeOverflow)
    }

    /// Materialize this lane as unsigned Clarity values.
    pub fn decode_unsigned_values(&self) -> Vec<Value> {
        self.iter()
            .map(|element| Value::UInt(decode_padded_u128(element)))
            .collect()
    }

    /// Materialize this lane as signed Clarity values.
    pub fn decode_signed_values(&self) -> Vec<Value> {
        self.iter()
            .map(|element| Value::Int(decode_padded_i128(element)))
            .collect()
    }
}

/// Return the minimum two's-complement width of an already padded byte slice.
pub fn minimal_signed_slice_width(bytes: &[u8]) -> usize {
    if bytes.iter().all(|byte| *byte == 0) {
        return 0;
    }
    let mut start = 0usize;
    while start + 1 < bytes.len() {
        let byte = bytes[start];
        let next = bytes[start + 1];
        if (byte == 0 && next & 0x80 == 0) || (byte == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes.len() - start
}

/// Validate a bit-packed Boolean lane and return its consensus element length.
pub fn validate_bool_lane(elements: &[u8], count: usize) -> Result<u32, PackedValueError> {
    let expected_len = count.checked_add(7).ok_or(PackedValueError::SizeOverflow)? / 8;
    if elements.len() != expected_len {
        return Err(PackedValueError::InvalidRecord(
            "invalid boolean lane length",
        ));
    }
    if !count.is_multiple_of(8) && !elements.is_empty() {
        let used_bits = count % 8;
        let unused_mask = !((1u8 << used_bits) - 1);
        if elements[elements.len() - 1] & unused_mask != 0 {
            return Err(PackedValueError::InvalidRecord(
                "non-zero boolean lane padding",
            ));
        }
    }
    u32::try_from(count).map_err(|_| PackedValueError::SizeOverflow)
}

/// Validate and decode one minimally encoded signed scalar.
pub fn decode_canonical_i128(bytes: &[u8]) -> Result<i128, PackedValueError> {
    validate_canonical_signed_scalar(bytes)?;
    Ok(decode_validated_i128(bytes))
}

/// Decode a signed scalar whose minimal-width grammar has already been validated.
pub fn decode_validated_i128(bytes: &[u8]) -> i128 {
    let mut full = [if bytes[0] & 0x80 == 0 { 0 } else { 0xff }; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    i128::from_be_bytes(full)
}

/// Validate and decode one minimally encoded unsigned scalar.
pub fn decode_canonical_u128(bytes: &[u8]) -> Result<u128, PackedValueError> {
    validate_canonical_unsigned_scalar(bytes)?;
    Ok(decode_validated_u128(bytes))
}

/// Decode an unsigned scalar whose minimal-width grammar has already been validated.
pub fn decode_validated_u128(bytes: &[u8]) -> u128 {
    let mut full = [0u8; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    u128::from_be_bytes(full)
}

/// Materialize a standard principal after its fixed-width body has been validated.
fn decode_standard_principal(bytes: &[u8; 21]) -> Result<StandardPrincipalData, PackedValueError> {
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes[1..]);
    Ok(StandardPrincipalData::new(bytes[0], hash)?)
}

/// Validate and materialize a bit-packed Boolean lane.
pub fn decode_bool_lane(elements: &[u8], count: usize) -> Result<Vec<Value>, PackedValueError> {
    validate_bool_lane(elements, count)?;
    (0..count)
        .map(|index| {
            elements
                .get(index / 8)
                .map(|byte| Value::Bool(byte & (1 << (index % 8)) != 0))
                .ok_or(PackedValueError::InvalidRecord("truncated boolean lane"))
        })
        .collect()
}

/// Zero-extend a validated lane element into an unsigned 128-bit integer.
fn decode_padded_u128(bytes: &[u8]) -> u128 {
    debug_assert!(!bytes.is_empty() && bytes.len() <= 16);
    let mut full = [0u8; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    u128::from_be_bytes(full)
}

/// Sign-extend a validated lane element into a signed 128-bit integer.
fn decode_padded_i128(bytes: &[u8]) -> i128 {
    debug_assert!(!bytes.is_empty() && bytes.len() <= 16);
    let mut full = [if bytes[0] & 0x80 == 0 { 0 } else { 0xff }; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    i128::from_be_bytes(full)
}

/// Split a one-byte discriminant from its child body.
pub fn split_tag(bytes: &[u8]) -> Result<(u8, &[u8]), PackedValueError> {
    let (&tag, child) = bytes
        .split_first()
        .ok_or(PackedValueError::InvalidRecord("missing discriminant"))?;
    Ok((tag, child))
}

/// Read a little-endian `u32` prefix.
pub fn read_u32_le(bytes: &[u8]) -> Result<u32, PackedValueError> {
    let bytes: [u8; 4] = bytes
        .get(..4)
        .ok_or(PackedValueError::InvalidRecord("truncated u32"))?
        .try_into()
        .map_err(|_| PackedValueError::InvalidRecord("truncated u32"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Add two logical consensus lengths without overflow.
pub fn checked_logical_add(left: u32, right: u32) -> Result<u32, PackedValueError> {
    left.checked_add(right)
        .ok_or(PackedValueError::SizeOverflow)
}
