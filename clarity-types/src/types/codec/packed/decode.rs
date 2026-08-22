// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Schema-aware decoding and logical-length validation.

use std::str;

use stacks_common::types::StacksEpochId;

use super::{DecodedPackedValue, PackedValueError, PackedValueRef, directory, layout, primitive};
use crate::types::signatures::{CallableSubtype, SequenceSubtype, StringSubtype};
use crate::types::{
    ASCIIData, CallableData, CharType, ListTypeData, PrincipalData, QualifiedContractIdentifier,
    SequenceData, TraitIdentifier, TupleData, TupleFieldsBehavior, TypeSignature, UTF8Data, Value,
};

/// Decode and validate one canonical packed record under a declared read schema.
pub fn value(
    packed: PackedValueRef<'_>,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<DecodedPackedValue, PackedValueError> {
    let (value, actual_len) = body(packed.body(), expected, epoch)?;
    if actual_len != packed.consensus_byte_len() {
        return Err(PackedValueError::InvalidRecord(
            "canonical logical consensus length mismatch",
        ));
    }
    Ok(DecodedPackedValue {
        value,
        consensus_byte_len: actual_len,
    })
}

/// Decode one complete packed body under its caller-supplied schema.
///
/// The returned length is the value's consensus-serialized length, used to validate the record
/// header and preserve consensus cost accounting.
fn body(
    bytes: &[u8],
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<(Value, u32), PackedValueError> {
    use TypeSignature::*;

    match expected {
        IntType => Ok((Value::Int(primitive::decode_canonical_i128(bytes)?), 17)),
        UIntType => Ok((Value::UInt(primitive::decode_canonical_u128(bytes)?), 17)),
        BoolType => match bytes {
            [0] => Ok((Value::Bool(false), 1)),
            [1] => Ok((Value::Bool(true), 1)),
            _ => Err(PackedValueError::InvalidRecord("invalid boolean")),
        },
        SequenceType(SequenceSubtype::BufferType(max_len)) => {
            if bytes.len() > u32::from(max_len) as usize {
                return Err(PackedValueError::InvalidRecord(
                    "buffer exceeds declared bound",
                ));
            }
            Ok((
                Value::Sequence(SequenceData::Buffer(crate::types::BuffData {
                    data: bytes.to_vec(),
                })),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(max_len))) => {
            if bytes.len() > u32::from(max_len) as usize
                || !bytes.iter().all(primitive::valid_ascii_byte)
            {
                return Err(PackedValueError::InvalidRecord("invalid ASCII string"));
            }
            Ok((
                Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                    data: bytes.to_vec(),
                }))),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(max_len))) => {
            let string = str::from_utf8(bytes)
                .map_err(|_| PackedValueError::InvalidRecord("invalid UTF-8 string"))?;
            if string.chars().count() > u32::from(max_len) as usize {
                return Err(PackedValueError::InvalidRecord(
                    "UTF-8 string exceeds declared bound",
                ));
            }
            let data = string
                .chars()
                .map(|character| {
                    let mut scalar = vec![0; character.len_utf8()];
                    character.encode_utf8(&mut scalar);
                    scalar
                })
                .collect();
            Ok((
                Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data }))),
                primitive::logical_sequence_len(bytes.len())?,
            ))
        }
        PrincipalType => {
            let principal = primitive::PackedPrincipal::parse(bytes)?;
            let logical_len = principal.consensus_byte_len()?;
            Ok((
                Value::Principal(principal.to_principal_data()?),
                logical_len,
            ))
        }
        CallableType(subtype) => callable(bytes, subtype),
        TraitReferenceType(trait_identifier) => trait_callable(bytes, trait_identifier.clone()),
        OptionalType(inner) => {
            let (tag, child) = primitive::split_tag(bytes)?;
            match tag {
                0 if child.is_empty() => Ok((Value::none(), 1)),
                1 => {
                    let (value, child_len) = body(child, inner, epoch)?;
                    Ok((
                        Value::some(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                _ => Err(PackedValueError::InvalidRecord("invalid optional")),
            }
        }
        ResponseType(types) => {
            let (tag, child) = primitive::split_tag(bytes)?;
            match tag {
                0 => {
                    let (value, child_len) = body(child, &types.1, epoch)?;
                    Ok((
                        Value::error(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                1 => {
                    let (value, child_len) = body(child, &types.0, epoch)?;
                    Ok((
                        Value::okay(value)?,
                        primitive::checked_logical_add(1, child_len)?,
                    ))
                }
                _ => Err(PackedValueError::InvalidRecord("invalid response")),
            }
        }
        TupleType(tuple_type) => tuple(bytes, tuple_type, epoch),
        SequenceType(SequenceSubtype::ListType(list_type)) => list(bytes, list_type, epoch),
        NoType => Err(PackedValueError::InvalidRecord("NoType cannot be active")),
        ListUnionType(_) => Err(PackedValueError::UnsupportedSchema(
            "ListUnionType is analysis-only",
        )),
    }
}

/// Decode the canonical contract-principal body shared by callable schema variants.
fn contract(bytes: &[u8]) -> Result<(QualifiedContractIdentifier, u32), PackedValueError> {
    let principal = primitive::PackedPrincipal::parse(bytes)?;
    let logical_len = principal.consensus_byte_len()?;
    let PrincipalData::Contract(contract) = principal.to_principal_data()? else {
        return Err(PackedValueError::InvalidRecord(
            "callable must contain a contract principal",
        ));
    };
    Ok((contract, logical_len))
}

/// Decode a callable contract and restore the identity implied by its callable subtype.
fn callable(bytes: &[u8], expected: &CallableSubtype) -> Result<(Value, u32), PackedValueError> {
    let (contract_identifier, logical_len) = contract(bytes)?;
    let trait_identifier = match expected {
        CallableSubtype::Principal(expected_contract) => {
            if contract_identifier != *expected_contract {
                return Err(PackedValueError::TypeMismatch);
            }
            None
        }
        CallableSubtype::Trait(trait_identifier) => Some(Box::new(trait_identifier.clone())),
    };
    Ok((
        Value::CallableContract(CallableData {
            contract_identifier,
            trait_identifier,
        }),
        logical_len,
    ))
}

/// Decode a trait-reference callable while restoring its schema-provided trait identifier.
fn trait_callable(
    bytes: &[u8],
    trait_identifier: TraitIdentifier,
) -> Result<(Value, u32), PackedValueError> {
    let (contract_identifier, logical_len) = contract(bytes)?;
    Ok((
        Value::CallableContract(CallableData {
            contract_identifier,
            trait_identifier: Some(Box::new(trait_identifier)),
        }),
        logical_len,
    ))
}

/// Decode a tuple using fixed concatenation or an offset directory selected by its schema.
fn tuple(
    bytes: &[u8],
    expected: &crate::types::TupleTypeSignature,
    epoch: &StacksEpochId,
) -> Result<(Value, u32), PackedValueError> {
    let all_fixed = expected
        .get_type_map()
        .values()
        .try_fold(true, |all_fixed, child| {
            Ok::<_, PackedValueError>(all_fixed && layout::fixed_type_width(child)?.is_some())
        })?;
    let mut fields = Vec::with_capacity(expected.get_type_map().len());
    let mut logical_len = 5u32;
    if all_fixed {
        let mut cursor = 0usize;
        for (name, field_type) in expected.get_type_map() {
            let width = layout::fixed_type_width(field_type)?.ok_or(
                PackedValueError::InvalidRecord("canonical fixed tuple classification changed"),
            )?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let field = bytes
                .get(cursor..end)
                .ok_or(PackedValueError::InvalidRecord("truncated canonical tuple"))?;
            let (value, child_len) = body(field, field_type, epoch)?;
            logical_len = primitive::tuple_logical_add(logical_len, name.as_str(), child_len)?;
            fields.push((name.clone(), value));
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(PackedValueError::InvalidRecord(
                "canonical fixed tuple has trailing bytes",
            ));
        }
    } else {
        let directory = directory::Directory::parse(bytes, expected.get_type_map().len())?;
        for (index, (name, field_type)) in expected.get_type_map().iter().enumerate() {
            let (value, child_len) = body(directory.child(index)?, field_type, epoch)?;
            logical_len = primitive::tuple_logical_add(logical_len, name.as_str(), child_len)?;
            fields.push((name.clone(), value));
        }
    }
    let value = Value::Tuple(TupleData::from_data_typed(
        epoch,
        fields,
        expected,
        TupleFieldsBehavior::from_epoch(epoch),
    )?);
    Ok((value, logical_len))
}

/// Decode a counted list using its scalar lane, fixed-width, or directory-framed layout.
fn list(
    bytes: &[u8],
    expected: &ListTypeData,
    epoch: &StacksEpochId,
) -> Result<(Value, u32), PackedValueError> {
    let (count, elements) = primitive::split_list(bytes)?;
    if count > expected.get_max_len() as usize {
        return Err(PackedValueError::InvalidRecord(
            "list exceeds declared bound",
        ));
    }
    if count == 0 {
        if !elements.is_empty() {
            return Err(PackedValueError::InvalidRecord(
                "empty list has an element region",
            ));
        }
        return Ok((Value::list_with_type(epoch, vec![], expected.clone())?, 5));
    }
    let element_type = expected.get_list_item_type();
    let (values, children_len) = match element_type {
        TypeSignature::UIntType => {
            let lane = primitive::IntegerLane::parse_unsigned(elements, count)?;
            let logical_len = lane.consensus_byte_len()?;
            (lane.decode_unsigned_values(), logical_len)
        }
        TypeSignature::IntType => {
            let lane = primitive::IntegerLane::parse_signed(elements, count)?;
            let logical_len = lane.consensus_byte_len()?;
            (lane.decode_signed_values(), logical_len)
        }
        TypeSignature::BoolType => (
            primitive::decode_bool_lane(elements, count)?,
            u32::try_from(count).map_err(|_| PackedValueError::SizeOverflow)?,
        ),
        _ => match layout::fixed_type_width(element_type)? {
            Some(width) => {
                let expected_len = count
                    .checked_mul(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
                if elements.len() != expected_len {
                    return Err(PackedValueError::InvalidRecord(
                        "canonical fixed list byte length mismatch",
                    ));
                }
                let mut values = Vec::with_capacity(count);
                let mut children_len = 0u32;
                for index in 0..count {
                    let start = index
                        .checked_mul(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let end = start
                        .checked_add(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let child = elements
                        .get(start..end)
                        .ok_or(PackedValueError::InvalidRecord(
                            "truncated canonical fixed list",
                        ))?;
                    let (value, child_len) = body(child, element_type, epoch)?;
                    children_len = primitive::checked_logical_add(children_len, child_len)?;
                    values.push(value);
                }
                (values, children_len)
            }
            None => {
                let directory = directory::Directory::parse(elements, count)?;
                let mut values = Vec::with_capacity(count);
                let mut children_len = 0u32;
                for index in 0..count {
                    let (value, child_len) = body(directory.child(index)?, element_type, epoch)?;
                    children_len = primitive::checked_logical_add(children_len, child_len)?;
                    values.push(value);
                }
                (values, children_len)
            }
        },
    };
    Ok((
        Value::list_with_type(epoch, values, expected.clone())?,
        primitive::checked_logical_add(5, children_len)?,
    ))
}
