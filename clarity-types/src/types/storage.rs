// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Experimental schema-guided physical storage for Clarity values.
//!
//! This is not Clarity's consensus serialization. [`PackedValue`] retains the
//! consensus byte length and can reproduce the same logical [`Value`], while
//! using a compact layout suitable for future borrowed access.

use std::error::Error;
use std::{fmt, str};

use super::signatures::{CallableSubtype, SequenceSubtype, StringSubtype};
use super::{
    ASCIIData, CallableData, CharType, ListTypeData, PrincipalData, QualifiedContractIdentifier,
    SequenceData, StandardPrincipalData, TraitIdentifier, TupleData, TupleFieldsBehavior,
    TypeSignature, UTF8Data, Value,
};
use crate::errors::ClarityTypeError;
use crate::representations::{CONTRACT_NAME_REGEX, ContractName, MAX_STRING_LEN};
use stacks_common::types::StacksEpochId;

/// Number of bytes before a packed V1 value body.
pub const PACKED_VALUE_HEADER_LEN: usize = 4;

const OFFSET_WIDTH_U8: u8 = 0;
const OFFSET_WIDTH_U16: u8 = 1;
const OFFSET_WIDTH_U32: u8 = 2;

/// A validated view of one complete packed value record.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedPackedValue<'bytes, 'schema> {
    body: &'bytes [u8],
    expected: &'schema TypeSignature,
    consensus_byte_len: u32,
}

impl<'bytes, 'schema> ValidatedPackedValue<'bytes, 'schema> {
    /// Return the packed body without its logical-length header.
    pub fn body(&self) -> &'bytes [u8] {
        self.body
    }

    /// Return the length of the equivalent consensus serialization.
    pub fn consensus_byte_len(&self) -> u32 {
        self.consensus_byte_len
    }

    /// Materialize the validated packed value as the current owned [`Value`].
    pub fn to_owned_value(&self, epoch: &StacksEpochId) -> Result<Value, PackedValueError> {
        decode_body(self.body, self.expected, epoch)
    }
}

/// The encoded bytes and logical length produced by the packed codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedValue {
    bytes: Vec<u8>,
    consensus_byte_len: u32,
}

/// Whether an encoded record is structurally validated before it is returned.
///
/// Admission, migration, and test tooling should use
/// [`StructuralValidation::Enabled`]. A persistence path whose encoder output
/// is already covered by those gates may disable the redundant post-encode
/// scan on its ordinary write hot path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StructuralValidation {
    /// Validate the complete record after encoding it.
    #[default]
    Enabled,
    /// Skip the post-encode structural validation pass.
    Disabled,
}

impl PackedValue {
    /// Return the complete packed record bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this record and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the equivalent consensus-serialization length.
    pub fn consensus_byte_len(&self) -> u32 {
        self.consensus_byte_len
    }
}

/// Errors produced by the experimental packed value codec.
#[derive(Debug)]
pub enum PackedValueError {
    /// The value is not admitted by the declared storage type.
    TypeMismatch,
    /// The schema contains a type state that cannot represent a stored value.
    UnsupportedSchema(&'static str),
    /// A packed record violates its byte grammar or canonical encoding.
    InvalidRecord(&'static str),
    /// A checked size or offset calculation overflowed.
    SizeOverflow,
    /// An existing Clarity type invariant failed.
    ClarityType(ClarityTypeError),
    /// The current consensus serializer rejected the value.
    ConsensusSerialization(super::serialization::SerializationError),
}

impl fmt::Display for PackedValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch => write!(f, "value does not match packed storage schema"),
            Self::UnsupportedSchema(reason) => write!(f, "unsupported packed schema: {reason}"),
            Self::InvalidRecord(reason) => write!(f, "invalid packed value: {reason}"),
            Self::SizeOverflow => write!(f, "packed value size overflow"),
            Self::ClarityType(error) => write!(f, "Clarity type error: {error}"),
            Self::ConsensusSerialization(error) => {
                write!(f, "consensus serialization error: {error}")
            }
        }
    }
}

impl Error for PackedValueError {}

impl From<ClarityTypeError> for PackedValueError {
    fn from(error: ClarityTypeError) -> Self {
        Self::ClarityType(error)
    }
}

impl From<super::serialization::SerializationError> for PackedValueError {
    fn from(error: super::serialization::SerializationError) -> Self {
        Self::ConsensusSerialization(error)
    }
}

/// Encode and structurally validate a packed record.
pub fn encode_packed_value(
    value: &Value,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<PackedValue, PackedValueError> {
    encode_packed_value_with_options(value, expected, epoch, StructuralValidation::Enabled)
}

/// Encode with an explicit structural-validation mode.
///
/// Disable validation only for trusted encoder output on a persistence hot
/// path whose admission, import, and test boundaries validate the same format.
pub fn encode_packed_value_with_options(
    value: &Value,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
    validation: StructuralValidation,
) -> Result<PackedValue, PackedValueError> {
    let consensus_byte_len = value.serialized_size()?;
    encode_packed_value_with_consensus_len(value, expected, epoch, consensus_byte_len, validation)
}

/// Encode using a consensus length already computed by the logical write path.
///
/// Callers must pass the length of `value`'s exact current consensus bytes.
/// Structural validation checks that it agrees with the packed value shape.
pub fn encode_packed_value_with_consensus_len(
    value: &Value,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
    consensus_byte_len: u32,
    validation: StructuralValidation,
) -> Result<PackedValue, PackedValueError> {
    let body_len = packed_body_len(value, expected)?;
    let admitted = if matches!(value, Value::CallableContract(_)) {
        // Callable values carry the implementing contract, while their declared
        // type can name the trait or exact contract. The general type-admission
        // relation canonicalizes these differently; the callable encoder below
        // performs the stronger value/schema identity checks directly.
        true
    } else {
        expected.admits(epoch, value)?
    };
    if !admitted {
        return Err(PackedValueError::TypeMismatch);
    }
    let total_len = PACKED_VALUE_HEADER_LEN
        .checked_add(body_len)
        .ok_or(PackedValueError::SizeOverflow)?;
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&consensus_byte_len.to_le_bytes());
    encode_body(value, expected, &mut bytes)?;
    if bytes.len() != total_len {
        return Err(PackedValueError::InvalidRecord(
            "encoder length calculation disagrees with output",
        ));
    }
    if validation == StructuralValidation::Enabled {
        let validated = validate_packed_value(&bytes, expected)?;
        if validated.consensus_byte_len != consensus_byte_len {
            return Err(PackedValueError::InvalidRecord(
                "post-encode validation changed logical length",
            ));
        }
    }
    Ok(PackedValue {
        bytes,
        consensus_byte_len,
    })
}

/// Structurally validate a complete packed record under its declared schema.
pub fn validate_packed_value<'bytes, 'schema>(
    bytes: &'bytes [u8],
    expected: &'schema TypeSignature,
) -> Result<ValidatedPackedValue<'bytes, 'schema>, PackedValueError> {
    let header = bytes
        .get(..PACKED_VALUE_HEADER_LEN)
        .ok_or(PackedValueError::InvalidRecord("truncated packed header"))?;
    let consensus_byte_len = read_u32_le(header)?;
    let body = &bytes[PACKED_VALUE_HEADER_LEN..];
    let validated_consensus_len = validate_body(body, expected)?;
    if validated_consensus_len != consensus_byte_len {
        return Err(PackedValueError::InvalidRecord(
            "logical consensus length mismatch",
        ));
    }
    Ok(ValidatedPackedValue {
        body,
        expected,
        consensus_byte_len,
    })
}

/// Materialize a packed record with checked, schema-guided parsing.
///
/// The ordinary read path deliberately does not repeat the full structural
/// validation scan used at admission. Every byte access remains bounds-checked,
/// and the caller-provided schema determines the physical interpretation.
pub fn decode_packed_value(
    bytes: &[u8],
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<DecodedPackedValue, PackedValueError> {
    let header = bytes
        .get(..PACKED_VALUE_HEADER_LEN)
        .ok_or(PackedValueError::InvalidRecord("truncated packed header"))?;
    let consensus_byte_len = read_u32_le(header)?;
    let value = decode_body(&bytes[PACKED_VALUE_HEADER_LEN..], expected, epoch)?;
    Ok(DecodedPackedValue {
        value,
        consensus_byte_len,
    })
}

/// An owned decoded value paired with its logical serialized length.
#[derive(Debug, PartialEq)]
pub struct DecodedPackedValue {
    /// The materialized Clarity value.
    pub value: Value,
    /// The length of its equivalent consensus serialization.
    pub consensus_byte_len: u32,
}

/// Byte-cost attribution for one validated packed record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackedLayoutStats {
    /// Per-record logical-length header bytes.
    pub header_bytes: usize,
    /// Offset-width codes and offsets added for variable composites.
    pub directory_bytes: usize,
    /// Consensus tuple tags, counts, field-name lengths, and field names omitted.
    pub tuple_metadata_bytes_removed: usize,
}

/// Attribute packed layout overhead after fully validating the record.
pub fn packed_layout_stats(
    bytes: &[u8],
    expected: &TypeSignature,
) -> Result<PackedLayoutStats, PackedValueError> {
    let validated = validate_packed_value(bytes, expected)?;
    let mut stats = PackedLayoutStats {
        header_bytes: PACKED_VALUE_HEADER_LEN,
        ..PackedLayoutStats::default()
    };
    collect_layout_stats(validated.body, expected, &mut stats)?;
    Ok(stats)
}

fn collect_layout_stats(
    bytes: &[u8],
    expected: &TypeSignature,
    stats: &mut PackedLayoutStats,
) -> Result<(), PackedValueError> {
    match expected {
        TypeSignature::TupleType(tuple) => {
            let tuple_metadata = tuple
                .get_type_map()
                .keys()
                .try_fold(5usize, |total, name| {
                    total
                        .checked_add(1 + name.as_str().len())
                        .ok_or(PackedValueError::SizeOverflow)
                })?;
            stats.tuple_metadata_bytes_removed = stats
                .tuple_metadata_bytes_removed
                .checked_add(tuple_metadata)
                .ok_or(PackedValueError::SizeOverflow)?;
            let all_fixed =
                tuple
                    .get_type_map()
                    .values()
                    .try_fold(true, |all_fixed, field_type| {
                        Ok::<_, PackedValueError>(all_fixed && fixed_width(field_type)?.is_some())
                    })?;
            if all_fixed {
                let mut cursor = 0usize;
                for field_type in tuple.get_type_map().values() {
                    let width = fixed_width(field_type)?.ok_or(PackedValueError::InvalidRecord(
                        "tuple fixed-width classification changed",
                    ))?;
                    let end = cursor
                        .checked_add(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let child = bytes
                        .get(cursor..end)
                        .ok_or(PackedValueError::InvalidRecord("truncated fixed tuple"))?;
                    collect_layout_stats(child, field_type, stats)?;
                    cursor = end;
                }
            } else {
                let directory = Directory::parse(bytes, tuple.get_type_map().len())?;
                stats.directory_bytes = stats
                    .directory_bytes
                    .checked_add(bytes.len() - directory.data.len())
                    .ok_or(PackedValueError::SizeOverflow)?;
                for (index, field_type) in tuple.get_type_map().values().enumerate() {
                    collect_layout_stats(directory.child(index)?, field_type, stats)?;
                }
            }
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
            let (count, elements) = split_list(bytes)?;
            let element_type = list.get_list_item_type();
            if matches!(
                element_type,
                TypeSignature::IntType | TypeSignature::UIntType | TypeSignature::BoolType
            ) {
                return Ok(());
            }
            if let Some(width) = fixed_width(element_type)? {
                for index in 0..count {
                    let start = index
                        .checked_mul(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let end = start
                        .checked_add(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let child = elements
                        .get(start..end)
                        .ok_or(PackedValueError::InvalidRecord("truncated fixed list"))?;
                    collect_layout_stats(child, element_type, stats)?;
                }
            } else {
                let directory = Directory::parse(elements, count)?;
                stats.directory_bytes = stats
                    .directory_bytes
                    .checked_add(elements.len() - directory.data.len())
                    .ok_or(PackedValueError::SizeOverflow)?;
                for index in 0..count {
                    collect_layout_stats(directory.child(index)?, element_type, stats)?;
                }
            }
        }
        TypeSignature::OptionalType(inner) => {
            let (tag, child) = split_tag(bytes)?;
            if tag == 1 {
                collect_layout_stats(child, inner, stats)?;
            }
        }
        TypeSignature::ResponseType(types) => {
            let (tag, child) = split_tag(bytes)?;
            collect_layout_stats(child, if tag == 1 { &types.0 } else { &types.1 }, stats)?;
        }
        _ => {}
    }
    Ok(())
}

fn packed_body_len(value: &Value, expected: &TypeSignature) -> Result<usize, PackedValueError> {
    use TypeSignature::*;
    use Value::*;

    match (value, expected) {
        (Int(value), IntType) => Ok(packed_int_width(*value)),
        (UInt(value), UIntType) => Ok(packed_uint_width(*value)),
        (Bool(_), BoolType) => Ok(1),
        (Sequence(SequenceData::Buffer(buffer)), SequenceType(SequenceSubtype::BufferType(_))) => {
            Ok(buffer.data.len())
        }
        (
            Sequence(SequenceData::String(CharType::ASCII(string))),
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_))),
        ) => Ok(string.data.len()),
        (
            Sequence(SequenceData::String(CharType::UTF8(string))),
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))),
        ) => string.data.iter().try_fold(0usize, |total, scalar| {
            total
                .checked_add(scalar.len())
                .ok_or(PackedValueError::SizeOverflow)
        }),
        (Principal(principal), PrincipalType) => principal_body_len(principal),
        (CallableContract(callable), CallableType(subtype)) => callable_body_len(callable, subtype),
        (CallableContract(callable), TraitReferenceType(expected_trait)) => {
            callable_trait_body_len(callable, expected_trait)
        }
        (Optional(optional), OptionalType(inner)) => match &optional.data {
            None => Ok(1),
            Some(value) => packed_body_len(value, inner)?
                .checked_add(1)
                .ok_or(PackedValueError::SizeOverflow),
        },
        (Response(response), ResponseType(types)) => {
            let child_type = if response.committed {
                &types.0
            } else {
                &types.1
            };
            packed_body_len(&response.data, child_type)?
                .checked_add(1)
                .ok_or(PackedValueError::SizeOverflow)
        }
        (Tuple(tuple), TupleType(expected_tuple)) => tuple_body_len(tuple, expected_tuple),
        (
            Sequence(SequenceData::List(list)),
            SequenceType(SequenceSubtype::ListType(expected_list)),
        ) => list_body_len(list, expected_list),
        _ => Err(PackedValueError::TypeMismatch),
    }
}

fn principal_body_len(principal: &PrincipalData) -> Result<usize, PackedValueError> {
    match principal {
        PrincipalData::Standard(_) => Ok(22),
        PrincipalData::Contract(contract) => 22usize
            .checked_add(contract.name.as_str().len())
            .ok_or(PackedValueError::SizeOverflow),
    }
}

fn callable_body_len(
    callable: &CallableData,
    expected: &CallableSubtype,
) -> Result<usize, PackedValueError> {
    match expected {
        CallableSubtype::Principal(expected_contract) => {
            if callable.contract_identifier != *expected_contract
                || callable.trait_identifier.is_some()
            {
                return Err(PackedValueError::TypeMismatch);
            }
            Ok(0)
        }
        CallableSubtype::Trait(expected_trait) => callable_trait_body_len(callable, expected_trait),
    }
}

fn callable_trait_body_len(
    callable: &CallableData,
    expected_trait: &TraitIdentifier,
) -> Result<usize, PackedValueError> {
    if callable.trait_identifier.as_deref() != Some(expected_trait) {
        return Err(PackedValueError::TypeMismatch);
    }
    21usize
        .checked_add(callable.contract_identifier.name.as_str().len())
        .ok_or(PackedValueError::SizeOverflow)
}

fn tuple_body_len(
    tuple: &TupleData,
    expected: &super::TupleTypeSignature,
) -> Result<usize, PackedValueError> {
    if tuple.data_map.len() != expected.get_type_map().len() {
        return Err(PackedValueError::TypeMismatch);
    }
    let mut data_len = 0usize;
    let mut all_fixed = true;
    for (name, field_type) in expected.get_type_map() {
        let value = tuple
            .data_map
            .get(name)
            .ok_or(PackedValueError::TypeMismatch)?;
        let child_len = packed_body_len(value, field_type)?;
        data_len = data_len
            .checked_add(child_len)
            .ok_or(PackedValueError::SizeOverflow)?;
        all_fixed &= fixed_width(field_type)?.is_some();
    }
    if all_fixed {
        Ok(data_len)
    } else {
        directory_total_len(expected.get_type_map().len(), data_len)
    }
}

fn list_body_len(
    list: &super::ListData,
    expected: &ListTypeData,
) -> Result<usize, PackedValueError> {
    let count = list.data.len();
    if count > expected.get_max_len() as usize {
        return Err(PackedValueError::TypeMismatch);
    }
    let element_type = expected.get_list_item_type();
    let elements_len = match element_type {
        TypeSignature::UIntType => unsigned_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        TypeSignature::IntType => signed_lane_width(&list.data)?
            .checked_mul(count)
            .ok_or(PackedValueError::SizeOverflow)?,
        TypeSignature::BoolType => count.checked_add(7).ok_or(PackedValueError::SizeOverflow)? / 8,
        _ => match fixed_width(element_type)? {
            Some(width) => width
                .checked_mul(count)
                .ok_or(PackedValueError::SizeOverflow)?,
            None => {
                let data_len = list.data.iter().try_fold(0usize, |total, value| {
                    total
                        .checked_add(packed_body_len(value, element_type)?)
                        .ok_or(PackedValueError::SizeOverflow)
                })?;
                return 4usize
                    .checked_add(directory_total_len(count, data_len)?)
                    .ok_or(PackedValueError::SizeOverflow);
            }
        },
    };
    4usize
        .checked_add(elements_len)
        .ok_or(PackedValueError::SizeOverflow)
}

fn fixed_width(expected: &TypeSignature) -> Result<Option<usize>, PackedValueError> {
    use TypeSignature::*;

    match expected {
        BoolType => Ok(Some(1)),
        NoType => Ok(Some(0)),
        CallableType(CallableSubtype::Principal(_)) => Ok(Some(0)),
        TupleType(tuple) => {
            let mut total = 0usize;
            for field_type in tuple.get_type_map().values() {
                let Some(width) = fixed_width(field_type)? else {
                    return Ok(None);
                };
                total = total
                    .checked_add(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
            }
            Ok(Some(total))
        }
        OptionalType(inner) => Ok((fixed_width(inner)? == Some(0)).then_some(1)),
        ResponseType(types) => {
            let ok_width = fixed_width(&types.0)?;
            let err_width = fixed_width(&types.1)?;
            match (ok_width, err_width) {
                (Some(ok), Some(err)) if ok == err => ok
                    .checked_add(1)
                    .map(Some)
                    .ok_or(PackedValueError::SizeOverflow),
                _ => Ok(None),
            }
        }
        ListUnionType(_) => Err(PackedValueError::UnsupportedSchema(
            "ListUnionType is analysis-only",
        )),
        _ => Ok(None),
    }
}

fn directory_total_len(count: usize, data_len: usize) -> Result<usize, PackedValueError> {
    let width = offset_width(data_len);
    let offsets = count
        .checked_add(1)
        .and_then(|count| count.checked_mul(width))
        .ok_or(PackedValueError::SizeOverflow)?;
    1usize
        .checked_add(offsets)
        .and_then(|length| length.checked_add(data_len))
        .ok_or(PackedValueError::SizeOverflow)
}

fn offset_width(data_len: usize) -> usize {
    if data_len <= u8::MAX as usize {
        1
    } else if data_len <= u16::MAX as usize {
        2
    } else {
        4
    }
}

fn offset_width_code(width: usize) -> Result<u8, PackedValueError> {
    match width {
        1 => Ok(OFFSET_WIDTH_U8),
        2 => Ok(OFFSET_WIDTH_U16),
        4 => Ok(OFFSET_WIDTH_U32),
        _ => Err(PackedValueError::InvalidRecord("invalid offset width")),
    }
}

fn minimal_unsigned_bytes(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

/// Return the canonical packed width of an unsigned integer.
pub fn packed_uint_width(value: u128) -> usize {
    if value == 0 {
        0
    } else {
        (u128::BITS as usize - value.leading_zeros() as usize).div_ceil(8)
    }
}

/// Return the canonical packed two's-complement width of a signed integer.
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

fn minimal_signed_bytes(value: i128) -> [u8; 16] {
    value.to_be_bytes()
}

fn unsigned_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    values.iter().try_fold(0usize, |width, value| match value {
        Value::UInt(value) => Ok(width.max(packed_uint_width(*value))),
        _ => Err(PackedValueError::TypeMismatch),
    })
}

fn signed_lane_width(values: &[Value]) -> Result<usize, PackedValueError> {
    values.iter().try_fold(0usize, |width, value| match value {
        Value::Int(value) => Ok(width.max(packed_int_width(*value))),
        _ => Err(PackedValueError::TypeMismatch),
    })
}

fn encode_body(
    value: &Value,
    expected: &TypeSignature,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    use TypeSignature::*;
    use Value::*;

    match (value, expected) {
        (Int(value), IntType) => {
            let width = packed_int_width(*value);
            output.extend_from_slice(&minimal_signed_bytes(*value)[16 - width..]);
        }
        (UInt(value), UIntType) => {
            let width = packed_uint_width(*value);
            output.extend_from_slice(&minimal_unsigned_bytes(*value)[16 - width..]);
        }
        (Bool(value), BoolType) => output.push(u8::from(*value)),
        (Sequence(SequenceData::Buffer(buffer)), SequenceType(SequenceSubtype::BufferType(_))) => {
            output.extend_from_slice(&buffer.data);
        }
        (
            Sequence(SequenceData::String(CharType::ASCII(string))),
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_))),
        ) => output.extend_from_slice(&string.data),
        (
            Sequence(SequenceData::String(CharType::UTF8(string))),
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))),
        ) => {
            for scalar in &string.data {
                output.extend_from_slice(scalar);
            }
        }
        (Principal(principal), PrincipalType) => encode_principal(principal, output),
        (CallableContract(callable), CallableType(subtype)) => {
            encode_callable(callable, subtype, output)?;
        }
        (CallableContract(callable), TraitReferenceType(expected_trait)) => {
            encode_callable_trait(callable, expected_trait, output)?;
        }
        (Optional(optional), OptionalType(inner)) => match &optional.data {
            None => output.push(0),
            Some(value) => {
                output.push(1);
                encode_body(value, inner, output)?;
            }
        },
        (Response(response), ResponseType(types)) => {
            output.push(u8::from(response.committed));
            let child_type = if response.committed {
                &types.0
            } else {
                &types.1
            };
            encode_body(&response.data, child_type, output)?;
        }
        (Tuple(tuple), TupleType(expected_tuple)) => {
            encode_tuple(tuple, expected_tuple, output)?;
        }
        (
            Sequence(SequenceData::List(list)),
            SequenceType(SequenceSubtype::ListType(expected_list)),
        ) => encode_list(list, expected_list, output)?,
        _ => return Err(PackedValueError::TypeMismatch),
    }
    Ok(())
}

fn encode_principal(principal: &PrincipalData, output: &mut Vec<u8>) {
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

fn encode_callable(
    callable: &CallableData,
    expected: &CallableSubtype,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    match expected {
        CallableSubtype::Principal(contract) => {
            if callable.contract_identifier != *contract || callable.trait_identifier.is_some() {
                return Err(PackedValueError::TypeMismatch);
            }
        }
        CallableSubtype::Trait(trait_identifier) => {
            encode_callable_trait(callable, trait_identifier, output)?;
        }
    }
    Ok(())
}

fn encode_callable_trait(
    callable: &CallableData,
    expected_trait: &TraitIdentifier,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    if callable.trait_identifier.as_deref() != Some(expected_trait) {
        return Err(PackedValueError::TypeMismatch);
    }
    let contract = &callable.contract_identifier;
    output.push(contract.issuer.version());
    output.extend_from_slice(&contract.issuer.1);
    output.extend_from_slice(contract.name.as_str().as_bytes());
    Ok(())
}

fn encode_tuple(
    tuple: &TupleData,
    expected: &super::TupleTypeSignature,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let all_fixed = expected
        .get_type_map()
        .values()
        .try_fold(true, |all_fixed, field_type| {
            Ok::<_, PackedValueError>(all_fixed && fixed_width(field_type)?.is_some())
        })?;
    if all_fixed {
        for (name, field_type) in expected.get_type_map() {
            let value = tuple
                .data_map
                .get(name)
                .ok_or(PackedValueError::TypeMismatch)?;
            encode_body(value, field_type, output)?;
        }
        return Ok(());
    }

    let directory = reserve_wide_directory(expected.get_type_map().len(), output)?;
    for (index, (name, field_type)) in expected.get_type_map().iter().enumerate() {
        let value = tuple
            .data_map
            .get(name)
            .ok_or(PackedValueError::TypeMismatch)?;
        encode_body(value, field_type, output)?;
        directory.write_wide_offset(output, index + 1)?;
    }
    directory.compact(output)?;
    Ok(())
}

fn encode_list(
    list: &super::ListData,
    expected: &ListTypeData,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let count = u32::try_from(list.data.len()).map_err(|_| PackedValueError::SizeOverflow)?;
    output.extend_from_slice(&count.to_le_bytes());
    let element_type = expected.get_list_item_type();
    match element_type {
        TypeSignature::UIntType => {
            let width = unsigned_lane_width(&list.data)?;
            for value in &list.data {
                let Value::UInt(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                output.extend_from_slice(&minimal_unsigned_bytes(*value)[16 - width..]);
            }
        }
        TypeSignature::IntType => {
            let width = signed_lane_width(&list.data)?;
            for value in &list.data {
                let Value::Int(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                output.extend_from_slice(&minimal_signed_bytes(*value)[16 - width..]);
            }
        }
        TypeSignature::BoolType => {
            let byte_count = list
                .data
                .len()
                .checked_add(7)
                .ok_or(PackedValueError::SizeOverflow)?
                / 8;
            let start = output.len();
            output.resize(start + byte_count, 0);
            for (index, value) in list.data.iter().enumerate() {
                let Value::Bool(value) = value else {
                    return Err(PackedValueError::TypeMismatch);
                };
                if *value {
                    output[start + index / 8] |= 1 << (index % 8);
                }
            }
        }
        _ => match fixed_width(element_type)? {
            Some(_) => {
                for value in &list.data {
                    encode_body(value, element_type, output)?;
                }
            }
            None => encode_variable_list(&list.data, element_type, output)?,
        },
    }
    Ok(())
}

fn encode_variable_list(
    values: &[Value],
    element_type: &TypeSignature,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let directory = reserve_wide_directory(values.len(), output)?;
    for (index, value) in values.iter().enumerate() {
        encode_body(value, element_type, output)?;
        directory.write_wide_offset(output, index + 1)?;
    }
    directory.compact(output)?;
    Ok(())
}

struct WideDirectory {
    start: usize,
    data_start: usize,
    count: usize,
}

fn reserve_wide_directory(
    count: usize,
    output: &mut Vec<u8>,
) -> Result<WideDirectory, PackedValueError> {
    let start = output.len();
    let directory_len = count
        .checked_add(1)
        .and_then(|count| count.checked_mul(4))
        .and_then(|length| length.checked_add(1))
        .ok_or(PackedValueError::SizeOverflow)?;
    let data_start = start
        .checked_add(directory_len)
        .ok_or(PackedValueError::SizeOverflow)?;
    output.resize(data_start, 0);
    Ok(WideDirectory {
        start,
        data_start,
        count,
    })
}

impl WideDirectory {
    fn write_wide_offset(&self, output: &mut [u8], index: usize) -> Result<(), PackedValueError> {
        let offset = output
            .len()
            .checked_sub(self.data_start)
            .ok_or(PackedValueError::SizeOverflow)?;
        write_offset(output, self.start + 1, 4, index, offset)
    }

    fn compact(self, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
        let end = output.len();
        let data_len = end
            .checked_sub(self.data_start)
            .ok_or(PackedValueError::SizeOverflow)?;
        let width = offset_width(data_len);
        output[self.start] = offset_width_code(width)?;
        for index in 0..=self.count {
            let source = self
                .start
                .checked_add(1 + index * 4)
                .ok_or(PackedValueError::SizeOverflow)?;
            let value = read_offset(
                output
                    .get(source..source + 4)
                    .ok_or(PackedValueError::SizeOverflow)?,
                4,
            )?;
            write_offset(output, self.start + 1, width, index, value)?;
        }
        let compact_data_start = self
            .start
            .checked_add(1 + (self.count + 1) * width)
            .ok_or(PackedValueError::SizeOverflow)?;
        output.copy_within(self.data_start..end, compact_data_start);
        output.truncate(
            compact_data_start
                .checked_add(data_len)
                .ok_or(PackedValueError::SizeOverflow)?,
        );
        Ok(())
    }
}

fn write_offset(
    output: &mut [u8],
    directory_start: usize,
    width: usize,
    index: usize,
    value: usize,
) -> Result<(), PackedValueError> {
    let start = directory_start
        .checked_add(
            index
                .checked_mul(width)
                .ok_or(PackedValueError::SizeOverflow)?,
        )
        .ok_or(PackedValueError::SizeOverflow)?;
    let target = output
        .get_mut(start..start + width)
        .ok_or(PackedValueError::SizeOverflow)?;
    match width {
        1 => target[0] = u8::try_from(value).map_err(|_| PackedValueError::SizeOverflow)?,
        2 => target.copy_from_slice(
            &u16::try_from(value)
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_le_bytes(),
        ),
        4 => target.copy_from_slice(
            &u32::try_from(value)
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_le_bytes(),
        ),
        _ => return Err(PackedValueError::InvalidRecord("invalid offset width")),
    }
    Ok(())
}

// Validation and owned decoding are kept separate so write-path structural
// checks do not allocate a Value tree.
fn validate_body(bytes: &[u8], expected: &TypeSignature) -> Result<u32, PackedValueError> {
    use TypeSignature::*;

    let logical_len = match expected {
        IntType => {
            validate_signed_scalar(bytes)?;
            17
        }
        UIntType => {
            validate_unsigned_scalar(bytes)?;
            17
        }
        BoolType => {
            if !matches!(bytes, [0] | [1]) {
                return Err(PackedValueError::InvalidRecord("invalid boolean"));
            }
            1
        }
        SequenceType(SequenceSubtype::BufferType(max_len)) => {
            if bytes.len() > u32::from(max_len) as usize {
                return Err(PackedValueError::InvalidRecord(
                    "buffer exceeds declared bound",
                ));
            }
            logical_sequence_len(bytes.len())?
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(max_len))) => {
            if bytes.len() > u32::from(max_len) as usize || !bytes.iter().all(valid_ascii_byte) {
                return Err(PackedValueError::InvalidRecord("invalid ASCII string"));
            }
            logical_sequence_len(bytes.len())?
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(max_len))) => {
            let string = str::from_utf8(bytes)
                .map_err(|_| PackedValueError::InvalidRecord("invalid UTF-8 string"))?;
            if string.chars().count() > u32::from(max_len) as usize {
                return Err(PackedValueError::InvalidRecord(
                    "UTF-8 string exceeds declared bound",
                ));
            }
            logical_sequence_len(bytes.len())?
        }
        PrincipalType => validate_principal(bytes)?,
        CallableType(subtype) => validate_callable(bytes, subtype)?,
        TraitReferenceType(trait_identifier) => validate_callable_trait(bytes, trait_identifier)?,
        OptionalType(inner) => {
            let (tag, child) = split_tag(bytes)?;
            match tag {
                0 if child.is_empty() => 1,
                1 => checked_logical_add(1, validate_body(child, inner)?)?,
                _ => return Err(PackedValueError::InvalidRecord("invalid optional")),
            }
        }
        ResponseType(types) => {
            let (tag, child) = split_tag(bytes)?;
            match tag {
                0 => checked_logical_add(1, validate_body(child, &types.1)?)?,
                1 => checked_logical_add(1, validate_body(child, &types.0)?)?,
                _ => return Err(PackedValueError::InvalidRecord("invalid response")),
            }
        }
        TupleType(tuple) => validate_tuple(bytes, tuple)?,
        SequenceType(SequenceSubtype::ListType(list)) => validate_list(bytes, list)?,
        NoType => return Err(PackedValueError::InvalidRecord("NoType cannot be active")),
        ListUnionType(_) => {
            return Err(PackedValueError::UnsupportedSchema(
                "ListUnionType is analysis-only",
            ));
        }
    };
    Ok(logical_len)
}

fn validate_signed_scalar(bytes: &[u8]) -> Result<(), PackedValueError> {
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "signed integer exceeds 16 bytes",
        ));
    }
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        return Err(PackedValueError::InvalidRecord(
            "non-minimal signed integer",
        ));
    }
    if bytes == [0] {
        return Err(PackedValueError::InvalidRecord(
            "zero integer must be empty",
        ));
    }
    Ok(())
}

fn validate_unsigned_scalar(bytes: &[u8]) -> Result<(), PackedValueError> {
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "unsigned integer exceeds 16 bytes",
        ));
    }
    if bytes.first() == Some(&0) {
        return Err(PackedValueError::InvalidRecord(
            "non-minimal unsigned integer",
        ));
    }
    Ok(())
}

fn valid_ascii_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || byte.is_ascii_punctuation() || byte.is_ascii_whitespace()
}

fn logical_sequence_len(data_len: usize) -> Result<u32, PackedValueError> {
    u32::try_from(data_len)
        .map_err(|_| PackedValueError::SizeOverflow)?
        .checked_add(5)
        .ok_or(PackedValueError::SizeOverflow)
}

fn validate_principal(bytes: &[u8]) -> Result<u32, PackedValueError> {
    let (&kind, body) = bytes
        .split_first()
        .ok_or(PackedValueError::InvalidRecord("missing principal kind"))?;
    match kind {
        0 => {
            validate_standard_principal(body)?;
            Ok(22)
        }
        1 => {
            let name = validate_contract_body(body)?;
            checked_logical_add(
                23,
                u32::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?,
            )
        }
        _ => Err(PackedValueError::InvalidRecord("invalid principal kind")),
    }
}

fn validate_standard_principal(bytes: &[u8]) -> Result<(), PackedValueError> {
    if bytes.len() != 21 || bytes[0] >= 32 {
        return Err(PackedValueError::InvalidRecord(
            "invalid standard principal",
        ));
    }
    Ok(())
}

fn validate_contract_body(bytes: &[u8]) -> Result<&str, PackedValueError> {
    if bytes.len() < 22 || bytes[0] >= 32 {
        return Err(PackedValueError::InvalidRecord(
            "invalid contract principal",
        ));
    }
    let name = str::from_utf8(&bytes[21..])
        .map_err(|_| PackedValueError::InvalidRecord("invalid contract name UTF-8"))?;
    if name.is_empty()
        || name.len() > MAX_STRING_LEN as usize
        || !CONTRACT_NAME_REGEX.is_match(name)
    {
        return Err(PackedValueError::InvalidRecord("invalid contract name"));
    }
    Ok(name)
}

fn validate_callable(bytes: &[u8], expected: &CallableSubtype) -> Result<u32, PackedValueError> {
    match expected {
        CallableSubtype::Principal(contract) => {
            if !bytes.is_empty() {
                return Err(PackedValueError::InvalidRecord(
                    "schema-known callable must have an empty body",
                ));
            }
            logical_contract_len(contract)
        }
        CallableSubtype::Trait(trait_identifier) => {
            validate_callable_trait(bytes, trait_identifier)
        }
    }
}

fn validate_callable_trait(
    bytes: &[u8],
    _expected_trait: &TraitIdentifier,
) -> Result<u32, PackedValueError> {
    let name = validate_contract_body(bytes)?;
    checked_logical_add(
        23,
        u32::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?,
    )
}

fn logical_contract_len(contract: &QualifiedContractIdentifier) -> Result<u32, PackedValueError> {
    checked_logical_add(
        23,
        u32::try_from(contract.name.as_str().len()).map_err(|_| PackedValueError::SizeOverflow)?,
    )
}

fn validate_tuple(
    bytes: &[u8],
    expected: &super::TupleTypeSignature,
) -> Result<u32, PackedValueError> {
    let mut logical_len = 5u32;
    if expected
        .get_type_map()
        .values()
        .try_fold(true, |all_fixed, field_type| {
            Ok::<_, PackedValueError>(all_fixed && fixed_width(field_type)?.is_some())
        })?
    {
        let mut cursor = 0usize;
        for (name, field_type) in expected.get_type_map() {
            let width = fixed_width(field_type)?.ok_or(PackedValueError::InvalidRecord(
                "tuple fixed-width classification changed",
            ))?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let child = bytes
                .get(cursor..end)
                .ok_or(PackedValueError::InvalidRecord("truncated fixed tuple"))?;
            logical_len = tuple_logical_add(
                logical_len,
                name.as_str(),
                validate_body(child, field_type)?,
            )?;
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(PackedValueError::InvalidRecord(
                "trailing fixed tuple bytes",
            ));
        }
    } else {
        let directory = Directory::parse(bytes, expected.get_type_map().len())?;
        for (index, (name, field_type)) in expected.get_type_map().iter().enumerate() {
            logical_len = tuple_logical_add(
                logical_len,
                name.as_str(),
                validate_body(directory.child(index)?, field_type)?,
            )?;
        }
    }
    Ok(logical_len)
}

fn tuple_logical_add(current: u32, name: &str, child_len: u32) -> Result<u32, PackedValueError> {
    current
        .checked_add(1)
        .and_then(|length| length.checked_add(u32::try_from(name.len()).ok()?))
        .and_then(|length| length.checked_add(child_len))
        .ok_or(PackedValueError::SizeOverflow)
}

fn validate_list(bytes: &[u8], expected: &ListTypeData) -> Result<u32, PackedValueError> {
    let (count, elements) = split_list(bytes)?;
    if count > expected.get_max_len() as usize {
        return Err(PackedValueError::InvalidRecord(
            "list exceeds declared bound",
        ));
    }
    let element_type = expected.get_list_item_type();
    let children_logical = match element_type {
        TypeSignature::UIntType => validate_unsigned_lane(elements, count)?,
        TypeSignature::IntType => validate_signed_lane(elements, count)?,
        TypeSignature::BoolType => validate_bool_lane(elements, count)?,
        _ => match fixed_width(element_type)? {
            Some(width) => validate_fixed_list(elements, count, width, element_type)?,
            None => validate_variable_list(elements, count, element_type)?,
        },
    };
    checked_logical_add(5, children_logical)
}

fn split_list(bytes: &[u8]) -> Result<(usize, &[u8]), PackedValueError> {
    let count = read_u32_le(bytes)? as usize;
    Ok((count, &bytes[4..]))
}

fn validate_unsigned_lane(elements: &[u8], count: usize) -> Result<u32, PackedValueError> {
    let width = lane_width(elements, count)?;
    if width > 16 {
        return Err(PackedValueError::InvalidRecord(
            "unsigned lane exceeds 16 bytes",
        ));
    }
    if width > 0 && !elements.chunks_exact(width).any(|value| value[0] != 0) {
        return Err(PackedValueError::InvalidRecord("non-minimal unsigned lane"));
    }
    logical_lane_len(count)
}

fn validate_signed_lane(elements: &[u8], count: usize) -> Result<u32, PackedValueError> {
    let width = lane_width(elements, count)?;
    if width > 16 {
        return Err(PackedValueError::InvalidRecord(
            "signed lane exceeds 16 bytes",
        ));
    }
    if width > 0
        && !elements
            .chunks_exact(width)
            .any(|value| minimal_signed_slice_width(value) == width)
    {
        return Err(PackedValueError::InvalidRecord("non-minimal signed lane"));
    }
    logical_lane_len(count)
}

fn lane_width(elements: &[u8], count: usize) -> Result<usize, PackedValueError> {
    if count == 0 {
        if elements.is_empty() {
            return Ok(0);
        }
        return Err(PackedValueError::InvalidRecord("empty list has lane bytes"));
    }
    if !elements.len().is_multiple_of(count) {
        return Err(PackedValueError::InvalidRecord(
            "lane length is not divisible by count",
        ));
    }
    Ok(elements.len() / count)
}

fn minimal_signed_slice_width(bytes: &[u8]) -> usize {
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

fn validate_bool_lane(elements: &[u8], count: usize) -> Result<u32, PackedValueError> {
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

fn validate_fixed_list(
    elements: &[u8],
    count: usize,
    width: usize,
    element_type: &TypeSignature,
) -> Result<u32, PackedValueError> {
    let expected_len = count
        .checked_mul(width)
        .ok_or(PackedValueError::SizeOverflow)?;
    if elements.len() != expected_len {
        return Err(PackedValueError::InvalidRecord("invalid fixed list length"));
    }
    let mut logical_len = 0u32;
    for index in 0..count {
        let start = index * width;
        logical_len = checked_logical_add(
            logical_len,
            validate_body(&elements[start..start + width], element_type)?,
        )?;
    }
    Ok(logical_len)
}

fn validate_variable_list(
    elements: &[u8],
    count: usize,
    element_type: &TypeSignature,
) -> Result<u32, PackedValueError> {
    let directory = Directory::parse(elements, count)?;
    let mut logical_len = 0u32;
    for index in 0..count {
        logical_len = checked_logical_add(
            logical_len,
            validate_body(directory.child(index)?, element_type)?,
        )?;
    }
    Ok(logical_len)
}

fn logical_lane_len(count: usize) -> Result<u32, PackedValueError> {
    u32::try_from(count)
        .map_err(|_| PackedValueError::SizeOverflow)?
        .checked_mul(17)
        .ok_or(PackedValueError::SizeOverflow)
}

struct Directory<'a> {
    offsets: &'a [u8],
    data: &'a [u8],
    width: usize,
    count: usize,
}

impl<'a> Directory<'a> {
    fn parse(bytes: &'a [u8], count: usize) -> Result<Self, PackedValueError> {
        let (&code, rest) = bytes
            .split_first()
            .ok_or(PackedValueError::InvalidRecord("missing offset-width code"))?;
        let width = match code {
            OFFSET_WIDTH_U8 => 1,
            OFFSET_WIDTH_U16 => 2,
            OFFSET_WIDTH_U32 => 4,
            _ => return Err(PackedValueError::InvalidRecord("invalid offset-width code")),
        };
        let offset_len = count
            .checked_add(1)
            .and_then(|count| count.checked_mul(width))
            .ok_or(PackedValueError::SizeOverflow)?;
        let (offsets, data) =
            rest.split_at_checked(offset_len)
                .ok_or(PackedValueError::InvalidRecord(
                    "truncated offset directory",
                ))?;
        if width != offset_width(data.len()) {
            return Err(PackedValueError::InvalidRecord("non-minimal offset width"));
        }
        let directory = Self {
            offsets,
            data,
            width,
            count,
        };
        if directory.offset(0)? != 0 || directory.offset(count)? != data.len() {
            return Err(PackedValueError::InvalidRecord(
                "invalid directory endpoints",
            ));
        }
        let mut previous = 0usize;
        for index in 1..=count {
            let offset = directory.offset(index)?;
            if offset < previous || offset > data.len() {
                return Err(PackedValueError::InvalidRecord(
                    "invalid directory ordering",
                ));
            }
            previous = offset;
        }
        Ok(directory)
    }

    fn offset(&self, index: usize) -> Result<usize, PackedValueError> {
        if index > self.count {
            return Err(PackedValueError::InvalidRecord(
                "directory index out of bounds",
            ));
        }
        let start = index
            .checked_mul(self.width)
            .ok_or(PackedValueError::SizeOverflow)?;
        read_offset(&self.offsets[start..start + self.width], self.width)
    }

    fn child(&self, index: usize) -> Result<&'a [u8], PackedValueError> {
        if index >= self.count {
            return Err(PackedValueError::InvalidRecord("child index out of bounds"));
        }
        let start = self.offset(index)?;
        let end = self.offset(index + 1)?;
        Ok(&self.data[start..end])
    }
}

fn read_offset(bytes: &[u8], width: usize) -> Result<usize, PackedValueError> {
    match width {
        1 => Ok(bytes[0] as usize),
        2 => Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as usize),
        4 => Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize),
        _ => Err(PackedValueError::InvalidRecord("invalid offset width")),
    }
}

fn decode_body(
    bytes: &[u8],
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<Value, PackedValueError> {
    use TypeSignature::*;

    match expected {
        IntType => Ok(Value::Int(decode_i128(bytes)?)),
        UIntType => Ok(Value::UInt(decode_u128(bytes)?)),
        BoolType => match bytes {
            [0] => Ok(Value::Bool(false)),
            [1] => Ok(Value::Bool(true)),
            _ => Err(PackedValueError::InvalidRecord("invalid boolean")),
        },
        SequenceType(SequenceSubtype::BufferType(max_len)) => {
            if bytes.len() > u32::from(max_len) as usize {
                return Err(PackedValueError::InvalidRecord(
                    "buffer exceeds declared bound",
                ));
            }
            Ok(Value::Sequence(SequenceData::Buffer(super::BuffData {
                data: bytes.to_vec(),
            })))
        }
        SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(max_len))) => {
            if bytes.len() > u32::from(max_len) as usize || !bytes.iter().all(valid_ascii_byte) {
                return Err(PackedValueError::InvalidRecord("invalid ASCII string"));
            }
            Ok(Value::Sequence(SequenceData::String(CharType::ASCII(
                ASCIIData {
                    data: bytes.to_vec(),
                },
            ))))
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
                    let mut bytes = vec![0; character.len_utf8()];
                    character.encode_utf8(&mut bytes);
                    bytes
                })
                .collect();
            Ok(Value::Sequence(SequenceData::String(CharType::UTF8(
                UTF8Data { data },
            ))))
        }
        PrincipalType => decode_principal(bytes),
        CallableType(subtype) => decode_callable(bytes, subtype),
        TraitReferenceType(trait_identifier) => {
            decode_callable_trait(bytes, trait_identifier.clone())
        }
        OptionalType(inner) => {
            let (tag, child) = split_tag(bytes)?;
            match tag {
                0 if child.is_empty() => Ok(Value::none()),
                1 => Ok(Value::some(decode_body(child, inner, epoch)?)?),
                _ => Err(PackedValueError::InvalidRecord("invalid optional")),
            }
        }
        ResponseType(types) => {
            let (tag, child) = split_tag(bytes)?;
            match tag {
                0 => Ok(Value::error(decode_body(child, &types.1, epoch)?)?),
                1 => Ok(Value::okay(decode_body(child, &types.0, epoch)?)?),
                _ => Err(PackedValueError::InvalidRecord("invalid response")),
            }
        }
        TupleType(tuple) => decode_tuple(bytes, tuple, epoch),
        SequenceType(SequenceSubtype::ListType(list)) => decode_list(bytes, list, epoch),
        NoType => Err(PackedValueError::InvalidRecord("NoType cannot be active")),
        ListUnionType(_) => Err(PackedValueError::UnsupportedSchema(
            "ListUnionType is analysis-only",
        )),
    }
}

fn decode_i128(bytes: &[u8]) -> Result<i128, PackedValueError> {
    validate_signed_scalar(bytes)?;
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut full = [if bytes[0] & 0x80 == 0 { 0 } else { 0xff }; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(i128::from_be_bytes(full))
}

fn decode_u128(bytes: &[u8]) -> Result<u128, PackedValueError> {
    validate_unsigned_scalar(bytes)?;
    let mut full = [0u8; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(full))
}

fn decode_principal(bytes: &[u8]) -> Result<Value, PackedValueError> {
    let (&kind, body) = bytes
        .split_first()
        .ok_or(PackedValueError::InvalidRecord("missing principal kind"))?;
    let principal = match kind {
        0 => PrincipalData::Standard(decode_standard_principal(body)?),
        1 => PrincipalData::Contract(decode_contract_body(body)?),
        _ => return Err(PackedValueError::InvalidRecord("invalid principal kind")),
    };
    Ok(Value::Principal(principal))
}

fn decode_standard_principal(bytes: &[u8]) -> Result<StandardPrincipalData, PackedValueError> {
    validate_standard_principal(bytes)?;
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes[1..]);
    Ok(StandardPrincipalData::new(bytes[0], hash)?)
}

fn decode_contract_body(bytes: &[u8]) -> Result<QualifiedContractIdentifier, PackedValueError> {
    let name = validate_contract_body(bytes)?;
    let issuer = decode_standard_principal(&bytes[..21])?;
    let name = ContractName::try_from(name.to_owned())?;
    Ok(QualifiedContractIdentifier { issuer, name })
}

fn decode_callable(bytes: &[u8], expected: &CallableSubtype) -> Result<Value, PackedValueError> {
    match expected {
        CallableSubtype::Principal(contract) => {
            if !bytes.is_empty() {
                return Err(PackedValueError::InvalidRecord(
                    "schema-known callable must have an empty body",
                ));
            }
            Ok(Value::CallableContract(CallableData {
                contract_identifier: contract.clone(),
                trait_identifier: None,
            }))
        }
        CallableSubtype::Trait(trait_identifier) => {
            decode_callable_trait(bytes, trait_identifier.clone())
        }
    }
}

fn decode_callable_trait(
    bytes: &[u8],
    trait_identifier: TraitIdentifier,
) -> Result<Value, PackedValueError> {
    Ok(Value::CallableContract(CallableData {
        contract_identifier: decode_contract_body(bytes)?,
        trait_identifier: Some(Box::new(trait_identifier)),
    }))
}

fn decode_tuple(
    bytes: &[u8],
    expected: &super::TupleTypeSignature,
    epoch: &StacksEpochId,
) -> Result<Value, PackedValueError> {
    let all_fixed = expected
        .get_type_map()
        .values()
        .try_fold(true, |all_fixed, field_type| {
            Ok::<_, PackedValueError>(all_fixed && fixed_width(field_type)?.is_some())
        })?;
    let mut fields = Vec::with_capacity(expected.get_type_map().len());
    if all_fixed {
        let mut cursor = 0usize;
        for (name, field_type) in expected.get_type_map() {
            let width = fixed_width(field_type)?.ok_or(PackedValueError::InvalidRecord(
                "tuple fixed-width classification changed",
            ))?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let field = bytes
                .get(cursor..end)
                .ok_or(PackedValueError::InvalidRecord("truncated fixed tuple"))?;
            fields.push((name.clone(), decode_body(field, field_type, epoch)?));
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(PackedValueError::InvalidRecord(
                "fixed tuple has trailing bytes",
            ));
        }
    } else {
        let directory = Directory::parse(bytes, expected.get_type_map().len())?;
        for (index, (name, field_type)) in expected.get_type_map().iter().enumerate() {
            fields.push((
                name.clone(),
                decode_body(directory.child(index)?, field_type, epoch)?,
            ));
        }
    }
    Ok(Value::Tuple(TupleData::from_data_typed(
        epoch,
        fields,
        expected,
        TupleFieldsBehavior::from_epoch(epoch),
    )?))
}

fn decode_list(
    bytes: &[u8],
    expected: &ListTypeData,
    epoch: &StacksEpochId,
) -> Result<Value, PackedValueError> {
    let (count, elements) = split_list(bytes)?;
    if count > expected.get_max_len() as usize {
        return Err(PackedValueError::InvalidRecord(
            "list exceeds declared bound",
        ));
    }
    let element_type = expected.get_list_item_type();
    let values = match element_type {
        TypeSignature::UIntType => decode_unsigned_lane(elements, count)?,
        TypeSignature::IntType => decode_signed_lane(elements, count)?,
        TypeSignature::BoolType => decode_bool_lane(elements, count)?,
        _ => match fixed_width(element_type)? {
            Some(width) => {
                let expected_len = count
                    .checked_mul(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
                if elements.len() != expected_len {
                    return Err(PackedValueError::InvalidRecord(
                        "fixed list byte length mismatch",
                    ));
                }
                let mut values = Vec::with_capacity(count);
                for index in 0..count {
                    let start = index
                        .checked_mul(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let end = start
                        .checked_add(width)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let element = elements
                        .get(start..end)
                        .ok_or(PackedValueError::InvalidRecord("truncated fixed list"))?;
                    values.push(decode_body(element, element_type, epoch)?);
                }
                values
            }
            None => {
                let directory = Directory::parse(elements, count)?;
                let mut values = Vec::with_capacity(count);
                for index in 0..count {
                    values.push(decode_body(directory.child(index)?, element_type, epoch)?);
                }
                values
            }
        },
    };
    Ok(Value::list_with_type(epoch, values, expected.clone())?)
}

fn decode_unsigned_lane(elements: &[u8], count: usize) -> Result<Vec<Value>, PackedValueError> {
    let width = lane_width(elements, count)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let start = index
            .checked_mul(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        let end = start
            .checked_add(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        let element = elements
            .get(start..end)
            .ok_or(PackedValueError::InvalidRecord("truncated unsigned lane"))?;
        values.push(Value::UInt(decode_padded_u128(element)?));
    }
    Ok(values)
}

fn decode_signed_lane(elements: &[u8], count: usize) -> Result<Vec<Value>, PackedValueError> {
    let width = lane_width(elements, count)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let start = index
            .checked_mul(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        let end = start
            .checked_add(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        let element = elements
            .get(start..end)
            .ok_or(PackedValueError::InvalidRecord("truncated signed lane"))?;
        values.push(Value::Int(decode_padded_i128(element)?));
    }
    Ok(values)
}

fn decode_bool_lane(elements: &[u8], count: usize) -> Result<Vec<Value>, PackedValueError> {
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

fn decode_padded_u128(bytes: &[u8]) -> Result<u128, PackedValueError> {
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "unsigned lane exceeds 16 bytes",
        ));
    }
    let mut full = [0u8; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(full))
}

fn decode_padded_i128(bytes: &[u8]) -> Result<i128, PackedValueError> {
    if bytes.len() > 16 {
        return Err(PackedValueError::InvalidRecord(
            "signed lane exceeds 16 bytes",
        ));
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut full = [if bytes[0] & 0x80 == 0 { 0 } else { 0xff }; 16];
    full[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(i128::from_be_bytes(full))
}

fn split_tag(bytes: &[u8]) -> Result<(u8, &[u8]), PackedValueError> {
    let (&tag, child) = bytes
        .split_first()
        .ok_or(PackedValueError::InvalidRecord("missing discriminant"))?;
    Ok((tag, child))
}

fn read_u32_le(bytes: &[u8]) -> Result<u32, PackedValueError> {
    let bytes: [u8; 4] = bytes
        .get(..4)
        .ok_or(PackedValueError::InvalidRecord("truncated u32"))?
        .try_into()
        .map_err(|_| PackedValueError::InvalidRecord("truncated u32"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn checked_logical_add(left: u32, right: u32) -> Result<u32, PackedValueError> {
    left.checked_add(right)
        .ok_or(PackedValueError::SizeOverflow)
}
