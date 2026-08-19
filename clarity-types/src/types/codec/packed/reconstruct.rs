// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Schema-free reconstruction of exact consensus bytes from packed values and active shapes.

use std::str;

use super::shape::{self, ActiveShape};
use super::{PACKED_VALUE_HEADER_LEN, PackedValueError, directory, encode, primitive};
use crate::representations::ClarityName;
use crate::types::serialization::TypePrefix;

/// Structurally reconstruct exact consensus bytes without a declared schema.
///
/// This bounded pass validates record framing, shape grammar, scalar encodings, and the declared
/// logical length. Call [`audit_reconstruction`] to additionally prove that the payload and shape
/// are their canonical representations of the reconstructed value.
pub fn reconstruct_consensus(
    packed: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>, PackedValueError> {
    let header = packed
        .get(..PACKED_VALUE_HEADER_LEN)
        .ok_or(PackedValueError::InvalidRecord(
            "truncated canonical header",
        ))?;
    let expected_len = primitive::read_u32_le(header)?;
    if expected_len > crate::types::BOUND_VALUE_SERIALIZATION_BYTES {
        return Err(PackedValueError::InvalidRecord(
            "reconstructed consensus value exceeds maximum size",
        ));
    }
    let shape = shape::parse_value_shape(descriptor)?;
    let expected_capacity =
        usize::try_from(expected_len).map_err(|_| PackedValueError::SizeOverflow)?;
    let mut consensus = Vec::with_capacity(expected_capacity);
    reconstruct_body(&packed[PACKED_VALUE_HEADER_LEN..], &shape, &mut consensus)?;
    if consensus.len() != expected_capacity {
        return Err(PackedValueError::InvalidRecord(
            "reconstructed consensus length mismatch",
        ));
    }
    Ok(consensus)
}

/// Reconstruct consensus bytes and prove the packed payload and shape are canonical.
pub fn audit_reconstruction(packed: &[u8], descriptor: &[u8]) -> Result<Vec<u8>, PackedValueError> {
    let consensus = reconstruct_consensus(packed, descriptor)?;
    let (canonical_packed, canonical_shape) = encode::transcode_consensus_with_shape(&consensus)?;
    if canonical_packed.as_bytes() != packed {
        return Err(PackedValueError::InvalidRecord(
            "reconstructed packed value is not canonical",
        ));
    }
    if canonical_shape.as_bytes() != descriptor {
        return Err(PackedValueError::InvalidRecord(
            "value shape is not canonical for packed value",
        ));
    }
    Ok(consensus)
}

/// Append exact consensus bytes for one packed body and its active shape.
fn reconstruct_body(
    bytes: &[u8],
    shape: &ActiveShape,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    match shape {
        ActiveShape::Int => {
            primitive::validate_canonical_signed_scalar(bytes)?;
            output.push(TypePrefix::Int.to_u8());
            let fill = if bytes[0] & 0x80 == 0 { 0 } else { 0xff };
            append_integer_padding(output, bytes.len(), fill)?;
            output.extend_from_slice(bytes);
        }
        ActiveShape::UInt => {
            primitive::validate_canonical_unsigned_scalar(bytes)?;
            output.push(TypePrefix::UInt.to_u8());
            append_integer_padding(output, bytes.len(), 0)?;
            output.extend_from_slice(bytes);
        }
        ActiveShape::Bool => match bytes {
            [0] => output.push(TypePrefix::BoolFalse.to_u8()),
            [1] => output.push(TypePrefix::BoolTrue.to_u8()),
            _ => return Err(PackedValueError::InvalidRecord("invalid boolean")),
        },
        ActiveShape::Buffer => reconstruct_sequence(TypePrefix::Buffer.to_u8(), bytes, output)?,
        ActiveShape::Ascii => {
            if !bytes.iter().all(primitive::valid_ascii_byte) {
                return Err(PackedValueError::InvalidRecord("invalid ASCII string"));
            }
            reconstruct_sequence(TypePrefix::StringASCII.to_u8(), bytes, output)?;
        }
        ActiveShape::Utf8 => {
            str::from_utf8(bytes)
                .map_err(|_| PackedValueError::InvalidRecord("invalid UTF-8 string"))?;
            reconstruct_sequence(TypePrefix::StringUTF8.to_u8(), bytes, output)?;
        }
        ActiveShape::Principal => reconstruct_principal(bytes, output)?,
        ActiveShape::Optional(child_shape) => {
            let (tag, child) = primitive::split_tag(bytes)?;
            match (tag, child_shape) {
                (0, _) if child.is_empty() => output.push(TypePrefix::OptionalNone.to_u8()),
                (1, Some(shape)) => {
                    output.push(TypePrefix::OptionalSome.to_u8());
                    reconstruct_body(child, shape, output)?;
                }
                _ => {
                    return Err(PackedValueError::InvalidRecord(
                        "packed optional disagrees with value shape",
                    ));
                }
            }
        }
        ActiveShape::Response { ok, err } => {
            let (tag, child) = primitive::split_tag(bytes)?;
            let (prefix, shape) = match tag {
                0 => (TypePrefix::ResponseErr.to_u8(), err.as_deref()),
                1 => (TypePrefix::ResponseOk.to_u8(), ok.as_deref()),
                _ => return Err(PackedValueError::InvalidRecord("invalid response")),
            };
            let shape = shape.ok_or(PackedValueError::InvalidRecord(
                "response branch is absent from value shape",
            ))?;
            output.push(prefix);
            reconstruct_body(child, shape, output)?;
        }
        ActiveShape::Tuple(fields) => reconstruct_tuple(bytes, fields, output)?,
        ActiveShape::List(element_shape) => reconstruct_list(
            bytes,
            element_shape.as_deref().map(ListShapes::Shared),
            output,
        )?,
        ActiveShape::ListElements(element_shapes) => {
            reconstruct_list(bytes, Some(ListShapes::PerElement(element_shapes)), output)?
        }
    }
    Ok(())
}

/// Append a consensus sequence prefix, byte length, and payload.
fn reconstruct_sequence(
    prefix: u8,
    bytes: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    output.push(prefix);
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| PackedValueError::SizeOverflow)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

/// Reconstruct a standard or contract principal consensus value.
fn reconstruct_principal(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    match primitive::PackedPrincipal::parse(bytes)? {
        primitive::PackedPrincipal::Standard(principal) => {
            output.push(TypePrefix::PrincipalStandard.to_u8());
            output.extend_from_slice(principal);
        }
        primitive::PackedPrincipal::Contract { issuer, name } => {
            output.push(TypePrefix::PrincipalContract.to_u8());
            output.extend_from_slice(issuer);
            output.push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?);
            output.extend_from_slice(name.as_bytes());
        }
    }
    Ok(())
}

/// Reconstruct tuple fields from fixed concatenation or directory framing.
fn reconstruct_tuple(
    bytes: &[u8],
    fields: &[(ClarityName, ActiveShape)],
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    output.push(TypePrefix::Tuple.to_u8());
    output.extend_from_slice(
        &u32::try_from(fields.len())
            .map_err(|_| PackedValueError::SizeOverflow)?
            .to_be_bytes(),
    );
    if fields
        .iter()
        .all(|(_, shape)| shape.fixed_width().is_some())
    {
        let mut cursor = 0usize;
        for (name, shape) in fields {
            let width = shape.fixed_width().ok_or(PackedValueError::InvalidRecord(
                "fixed value-shape classification changed",
            ))?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let child = bytes
                .get(cursor..end)
                .ok_or(PackedValueError::InvalidRecord("truncated fixed tuple"))?;
            reconstruct_tuple_field(name, child, shape, output)?;
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(PackedValueError::InvalidRecord(
                "fixed tuple has trailing bytes",
            ));
        }
    } else {
        let directory = directory::Directory::parse(bytes, fields.len())?;
        for (index, (name, shape)) in fields.iter().enumerate() {
            reconstruct_tuple_field(name, directory.child(index)?, shape, output)?;
        }
    }
    Ok(())
}

/// Append one named tuple field in consensus order.
fn reconstruct_tuple_field(
    name: &ClarityName,
    bytes: &[u8],
    shape: &ActiveShape,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let name = name.as_str().as_bytes();
    output.push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?);
    output.extend_from_slice(name);
    reconstruct_body(bytes, shape, output)
}

/// Shape access strategy for homogeneous and historical heterogeneous lists.
#[derive(Clone, Copy)]
enum ListShapes<'a> {
    /// One merged shape applies to every list element.
    Shared(&'a ActiveShape),
    /// Each historical unsanitized element requires its own shape.
    PerElement(&'a [ActiveShape]),
}

impl<'a> ListShapes<'a> {
    /// Check that this shape representation can describe `count` list elements.
    fn matches_count(self, count: usize) -> bool {
        match self {
            Self::Shared(_) => count > 0,
            Self::PerElement(shapes) => shapes.len() == count,
        }
    }

    /// Return the shape applying to one list element.
    fn get(self, index: usize) -> Result<&'a ActiveShape, PackedValueError> {
        match self {
            Self::Shared(shape) => Ok(shape),
            Self::PerElement(shapes) => shapes.get(index).ok_or(PackedValueError::InvalidRecord(
                "missing per-element list shape",
            )),
        }
    }

    /// Return the total directory-free element-region length, when all shapes are fixed-width.
    fn fixed_data_len(self, count: usize) -> Result<Option<usize>, PackedValueError> {
        match self {
            Self::Shared(shape) => shape
                .fixed_width()
                .map(|width| {
                    width
                        .checked_mul(count)
                        .ok_or(PackedValueError::SizeOverflow)
                })
                .transpose(),
            Self::PerElement(shapes) => shapes.iter().try_fold(Some(0usize), |total, shape| {
                let (Some(total), Some(width)) = (total, shape.fixed_width()) else {
                    return Ok(None);
                };
                total
                    .checked_add(width)
                    .map(Some)
                    .ok_or(PackedValueError::SizeOverflow)
            }),
        }
    }
}

/// Reconstruct a list using shared or per-element active shapes.
fn reconstruct_list(
    bytes: &[u8],
    element_shapes: Option<ListShapes<'_>>,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let (count, elements) = primitive::split_list(bytes)?;
    output.push(TypePrefix::List.to_u8());
    output.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| PackedValueError::SizeOverflow)?
            .to_be_bytes(),
    );
    if count == 0 {
        if !elements.is_empty() || matches!(element_shapes, Some(ListShapes::PerElement(_))) {
            return Err(PackedValueError::InvalidRecord(
                "empty list disagrees with value shape",
            ));
        }
        return Ok(());
    }
    let shapes = element_shapes.ok_or(PackedValueError::InvalidRecord(
        "non-empty list has no element shape",
    ))?;
    if !shapes.matches_count(count) {
        return Err(PackedValueError::InvalidRecord(
            "list count disagrees with per-element shapes",
        ));
    }
    match shapes {
        ListShapes::Shared(ActiveShape::UInt) => {
            return reconstruct_unsigned_lane(elements, count, output);
        }
        ListShapes::Shared(ActiveShape::Int) => {
            return reconstruct_signed_lane(elements, count, output);
        }
        ListShapes::Shared(ActiveShape::Bool) => {
            return reconstruct_bool_lane(elements, count, output);
        }
        ListShapes::Shared(_) | ListShapes::PerElement(_) => {}
    }
    if let Some(expected_len) = shapes.fixed_data_len(count)? {
        if elements.len() != expected_len {
            return Err(PackedValueError::InvalidRecord(
                "fixed list byte length mismatch",
            ));
        }
        let mut cursor = 0usize;
        for index in 0..count {
            let shape = shapes.get(index)?;
            let width = shape.fixed_width().ok_or(PackedValueError::InvalidRecord(
                "fixed list-shape classification changed",
            ))?;
            let end = cursor
                .checked_add(width)
                .ok_or(PackedValueError::SizeOverflow)?;
            let child = elements
                .get(cursor..end)
                .ok_or(PackedValueError::InvalidRecord("truncated fixed list"))?;
            reconstruct_body(child, shape, output)?;
            cursor = end;
        }
    } else {
        let directory = directory::Directory::parse(elements, count)?;
        for index in 0..count {
            reconstruct_body(directory.child(index)?, shapes.get(index)?, output)?;
        }
    }
    Ok(())
}

/// Expand a packed unsigned-integer lane into consensus scalar encodings.
fn reconstruct_unsigned_lane(
    elements: &[u8],
    count: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let lane = primitive::IntegerLane::parse_unsigned(elements, count)?;
    let width = lane.width();
    for element in lane.iter() {
        output.push(TypePrefix::UInt.to_u8());
        append_integer_padding(output, width, 0)?;
        output.extend_from_slice(element);
    }
    Ok(())
}

/// Expand a packed signed-integer lane into consensus scalar encodings.
fn reconstruct_signed_lane(
    elements: &[u8],
    count: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    let lane = primitive::IntegerLane::parse_signed(elements, count)?;
    let width = lane.width();
    for element in lane.iter() {
        output.push(TypePrefix::Int.to_u8());
        let fill = if element[0] & 0x80 == 0 { 0 } else { 0xff };
        append_integer_padding(output, width, fill)?;
        output.extend_from_slice(element);
    }
    Ok(())
}

/// Restore a packed integer to the fixed 16-byte consensus representation.
fn append_integer_padding(
    output: &mut Vec<u8>,
    packed_width: usize,
    fill: u8,
) -> Result<(), PackedValueError> {
    let padding = 16usize
        .checked_sub(packed_width)
        .ok_or(PackedValueError::InvalidRecord(
            "packed integer exceeds 16 bytes",
        ))?;
    let end = output
        .len()
        .checked_add(padding)
        .ok_or(PackedValueError::SizeOverflow)?;
    output.resize(end, fill);
    Ok(())
}

/// Expand a bit-packed Boolean lane into consensus Boolean prefixes.
fn reconstruct_bool_lane(
    elements: &[u8],
    count: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackedValueError> {
    primitive::validate_bool_lane(elements, count)?;
    for index in 0..count {
        let byte = elements
            .get(index / 8)
            .ok_or(PackedValueError::InvalidRecord("truncated boolean lane"))?;
        output.push(if byte & (1 << (index % 8)) == 0 {
            TypePrefix::BoolFalse.to_u8()
        } else {
            TypePrefix::BoolTrue.to_u8()
        });
    }
    Ok(())
}
