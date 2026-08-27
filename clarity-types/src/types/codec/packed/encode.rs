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

//! Admission, sizing, and canonical packed encoding.

use stacks_common::types::StacksEpochId;

use super::{
    ConsensusLengthValidation, PACKED_VALUE_HEADER_LEN, PackedValue, PackedValueError, ValueShape,
    directory, layout, primitive, shape, validate_packed_body_len,
};
use crate::types::signatures::CallableSubtype;
use crate::types::{
    CharType, QualifiedContractIdentifier, SequenceData, TupleData, TypeSignature, Value,
};

/// Encode a value whose admission or canonical consensus parsing was established by its caller.
pub fn value(
    value: &Value,
    consensus_byte_len: u32,
    validation: ConsensusLengthValidation,
) -> Result<PackedValue, PackedValueError> {
    let bytes = prefixed_value(value, &[], consensus_byte_len, validation)?;
    Ok(PackedValue {
        bytes,
        consensus_byte_len,
    })
}

/// Encode one exact packed record after an opaque prefix in one allocation.
pub fn prefixed_value(
    value: &Value,
    prefix: &[u8],
    consensus_byte_len: u32,
    validation: ConsensusLengthValidation,
) -> Result<Vec<u8>, PackedValueError> {
    let body_len = body_len(value)?;
    validate_packed_body_len(body_len)?;
    let record_len = PACKED_VALUE_HEADER_LEN
        .checked_add(body_len)
        .ok_or(PackedValueError::SizeOverflow)?;
    let total_len = prefix
        .len()
        .checked_add(record_len)
        .ok_or(PackedValueError::SizeOverflow)?;
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(prefix);
    output.extend_from_slice(&consensus_byte_len.to_le_bytes());
    body(value, &mut output)?;
    if output.len() != total_len {
        return Err(PackedValueError::InvalidRecord(
            "canonical encoder length calculation disagrees with output",
        ));
    }
    if validation == ConsensusLengthValidation::Enabled
        && value.serialized_size()? != consensus_byte_len
    {
        return Err(PackedValueError::InvalidRecord(
            "canonical encoder logical length mismatch",
        ));
    }
    Ok(output)
}

/// Transcode one exact self-describing consensus value into canonical packed.
///
/// This correctness-first implementation materializes one bounded Clarity value. The migration API
/// remains streaming at row granularity; a direct cursor implementation can replace this without
/// changing the format.
pub fn transcode(consensus: &[u8]) -> Result<PackedValue, PackedValueError> {
    let value = deserialize_canonical_consensus(consensus)?;
    let consensus_byte_len =
        u32::try_from(consensus.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    self::value(
        &value,
        consensus_byte_len,
        ConsensusLengthValidation::Disabled,
    )
}

/// Require `value` to conform to the declared storage type.
pub fn validate_admission(
    value: &Value,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<(), PackedValueError> {
    let admitted = if matches!(value, Value::CallableContract(_)) {
        callable_admitted(value, expected)?
    } else {
        expected.admits(epoch, value)?
    };
    if admitted {
        Ok(())
    } else {
        Err(PackedValueError::TypeMismatch)
    }
}

/// Check callable admission without allowing the declared callable subtype to affect encoding.
fn callable_admitted(value: &Value, expected: &TypeSignature) -> Result<bool, PackedValueError> {
    let Value::CallableContract(callable) = value else {
        return Ok(false);
    };
    match expected {
        TypeSignature::CallableType(CallableSubtype::Principal(contract)) => {
            Ok(callable.contract_identifier == *contract && callable.trait_identifier.is_none())
        }
        TypeSignature::CallableType(CallableSubtype::Trait(trait_identifier))
        | TypeSignature::TraitReferenceType(trait_identifier) => {
            Ok(callable.trait_identifier.as_deref() == Some(trait_identifier))
        }
        TypeSignature::PrincipalType => Ok(callable.trait_identifier.is_none()),
        _ => Ok(false),
    }
}

/// Measure the exact body size before encoding so the record needs one allocation.
///
/// This intentionally mirrors [`body`]. Keeping sizing separate avoids a temporary
/// body buffer and lets directory encoding reserve its final record capacity up front.
fn body_len(value: &Value) -> Result<usize, PackedValueError> {
    match value {
        Value::Int(value) => Ok(int_width(*value)),
        Value::UInt(value) => Ok(uint_width(*value)),
        Value::Bool(_) => Ok(1),
        Value::Sequence(SequenceData::Buffer(buffer)) => Ok(buffer.data.len()),
        Value::Sequence(SequenceData::String(CharType::ASCII(string))) => Ok(string.data.len()),
        Value::Sequence(SequenceData::String(CharType::UTF8(string))) => {
            string.data.iter().try_fold(0usize, |total, scalar| {
                total
                    .checked_add(scalar.len())
                    .ok_or(PackedValueError::SizeOverflow)
            })
        }
        Value::Principal(principal) => primitive::principal_body_len(principal),
        Value::CallableContract(callable) => contract_body_len(&callable.contract_identifier),
        Value::Optional(optional) => match &optional.data {
            None => Ok(1),
            Some(child) => body_len(child)?
                .checked_add(1)
                .ok_or(PackedValueError::SizeOverflow),
        },
        Value::Response(response) => body_len(&response.data)?
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow),
        Value::Tuple(tuple) => tuple_body_len(tuple),
        Value::Sequence(SequenceData::List(list)) => list_body_len(list),
    }
}

/// Return the packed byte length of a callable contract's canonical principal identity.
fn contract_body_len(contract: &QualifiedContractIdentifier) -> Result<usize, PackedValueError> {
    22usize
        .checked_add(contract.name.as_str().len())
        .ok_or(PackedValueError::SizeOverflow)
}

/// Return the non-zero canonical scalar width used for one unsigned integer.
fn uint_width(value: u128) -> usize {
    primitive::packed_uint_width(value).max(1)
}

/// Return the non-zero canonical scalar width used for one signed integer.
fn int_width(value: i128) -> usize {
    primitive::packed_int_width(value).max(1)
}

/// Select the non-zero element width shared by a canonical unsigned-integer lane.
fn unsigned_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    Ok(primitive::unsigned_lane_width(values)?.max(1))
}

/// Select the non-zero element width shared by a canonical signed-integer lane.
fn signed_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    Ok(primitive::signed_lane_width(values)?.max(1))
}

/// Measure a tuple body, including an offset directory when any child is variable-width.
fn tuple_body_len(tuple: &TupleData) -> Result<usize, PackedValueError> {
    let data_len = tuple.data_map.values().try_fold(0usize, |total, value| {
        total
            .checked_add(body_len(value)?)
            .ok_or(PackedValueError::SizeOverflow)
    })?;
    if tuple
        .data_map
        .values()
        .all(|value| layout::fixed_value_width(value).is_some())
    {
        Ok(data_len)
    } else {
        directory::directory_total_len(tuple.data_map.len(), data_len)
    }
}

/// Measure a list body using the same lane or framing choice as the encoder.
fn list_body_len(list: &crate::types::ListData) -> Result<usize, PackedValueError> {
    let count = list.data.len();
    if count == 0 {
        return Ok(4);
    }
    let elements_len = match layout::list_layout(list) {
        layout::ListLayout::UnsignedLane => unsigned_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        layout::ListLayout::SignedLane => signed_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        layout::ListLayout::BooleanLane => {
            count.checked_add(7).ok_or(PackedValueError::SizeOverflow)? / 8
        }
        layout::ListLayout::Fixed => list.data.iter().try_fold(0usize, |total, value| {
            total
                .checked_add(body_len(value)?)
                .ok_or(PackedValueError::SizeOverflow)
        })?,
        layout::ListLayout::Variable => {
            let data_len = list.data.iter().try_fold(0usize, |total, value| {
                total
                    .checked_add(body_len(value)?)
                    .ok_or(PackedValueError::SizeOverflow)
            })?;
            return 4usize
                .checked_add(directory::directory_total_len(count, data_len)?)
                .ok_or(PackedValueError::SizeOverflow);
        }
    };
    4usize
        .checked_add(elements_len)
        .ok_or(PackedValueError::SizeOverflow)
}

/// Append the schema-independent packed body for one active value.
fn body(value: &Value, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    match value {
        Value::Int(value) => {
            let width = int_width(*value);
            output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
        }
        Value::UInt(value) => {
            let width = uint_width(*value);
            output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
        }
        Value::Bool(value) => output.push(u8::from(*value)),
        Value::Sequence(SequenceData::Buffer(buffer)) => output.extend_from_slice(&buffer.data),
        Value::Sequence(SequenceData::String(CharType::ASCII(string))) => {
            output.extend_from_slice(&string.data);
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(string))) => {
            for scalar in &string.data {
                output.extend_from_slice(scalar);
            }
        }
        Value::Principal(principal) => primitive::encode_principal(principal, output),
        Value::CallableContract(callable) => {
            contract(&callable.contract_identifier, output);
        }
        Value::Optional(optional) => match &optional.data {
            None => output.push(0),
            Some(child) => {
                output.push(1);
                body(child, output)?;
            }
        },
        Value::Response(response) => {
            output.push(u8::from(response.committed));
            body(&response.data, output)?;
        }
        Value::Tuple(tuple_value) => tuple(tuple_value, output)?,
        Value::Sequence(SequenceData::List(list_value)) => list(list_value, output)?,
    }
    Ok(())
}

/// Append the canonical contract-principal representation used by callable values.
fn contract(contract: &QualifiedContractIdentifier, output: &mut Vec<u8>) {
    output.push(1);
    output.push(contract.issuer.version());
    output.extend_from_slice(&contract.issuer.1);
    output.extend_from_slice(contract.name.as_str().as_bytes());
}

/// Append tuple children in consensus field order, framing variable-width children by offset.
fn tuple(tuple: &TupleData, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    // Fixed tuples are self-framing under either the active value or an admitting schema. Any
    // variable child requires a directory so readers can find child boundaries without scanning.
    if tuple
        .data_map
        .values()
        .all(|value| layout::fixed_value_width(value).is_some())
    {
        for value in tuple.data_map.values() {
            body(value, output)?;
        }
        return Ok(());
    }
    let directory = directory::reserve_wide_directory(tuple.data_map.len(), output)?;
    for (index, value) in tuple.data_map.values().enumerate() {
        body(value, output)?;
        directory.write_wide_offset(output, index + 1)?;
    }
    directory.compact(output)
}

/// Append a list count and its canonically selected lane or child framing.
fn list(list: &crate::types::ListData, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    let count = u32::try_from(list.data.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    output.extend_from_slice(&count.to_le_bytes());
    if list.data.is_empty() {
        return Ok(());
    }
    match layout::list_layout(list) {
        // Homogeneous scalar lanes amortize width metadata across the entire list. The active values
        // select the lane width; declared integer bounds never affect physical bytes.
        layout::ListLayout::UnsignedLane => {
            let width = unsigned_lane_width(&list.data)?;
            for value in &list.data {
                let Value::UInt(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
            }
        }
        layout::ListLayout::SignedLane => {
            let width = signed_lane_width(&list.data)?;
            for value in &list.data {
                let Value::Int(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                output.extend_from_slice(&value.to_be_bytes()[16 - width..]);
            }
        }
        layout::ListLayout::BooleanLane => {
            let byte_count = list
                .data
                .len()
                .checked_add(7)
                .ok_or(PackedValueError::SizeOverflow)?
                / 8;
            let start = output.len();
            let end = start
                .checked_add(byte_count)
                .ok_or(PackedValueError::SizeOverflow)?;
            output.resize(end, 0);
            for (index, value) in list.data.iter().enumerate() {
                let Value::Bool(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                if *value {
                    let byte_index = start
                        .checked_add(index / 8)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let byte = output
                        .get_mut(byte_index)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    *byte |= 1 << (index % 8);
                }
            }
        }
        layout::ListLayout::Fixed => {
            for value in &list.data {
                body(value, output)?;
            }
        }
        layout::ListLayout::Variable => {
            let directory = directory::reserve_wide_directory(list.data.len(), output)?;
            for (index, value) in list.data.iter().enumerate() {
                body(value, output)?;
                directory.write_wide_offset(output, index + 1)?;
            }
            directory.compact(output)?;
        }
    }
    Ok(())
}

/// Transcode one exact consensus value into canonical packed bytes and its descriptor.
pub fn transcode_with_shape(
    consensus: &[u8],
) -> Result<(PackedValue, ValueShape), PackedValueError> {
    let value = deserialize_canonical_consensus(consensus)?;
    let consensus_byte_len =
        u32::try_from(consensus.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    let packed = self::value(
        &value,
        consensus_byte_len,
        ConsensusLengthValidation::Disabled,
    )?;
    let shape = shape::encode_value_shape(&value)?;
    Ok((packed, shape))
}

/// Deserialize one exact consensus value and reject accepted-but-non-canonical encodings.
fn deserialize_canonical_consensus(consensus: &[u8]) -> Result<Value, PackedValueError> {
    let value = Value::try_deserialize_slice_exact_untyped(consensus)?;
    if value.serialize_to_vec()? != consensus {
        return Err(PackedValueError::InvalidRecord(
            "consensus value is not canonically serialized",
        ));
    }
    Ok(value)
}
