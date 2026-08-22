// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Schema-free reconstruction of exact consensus bytes from packed values and active shapes.

use std::str;

use super::shape::{self, ActiveShape};
use super::{PackedValueError, PackedValueRef, directory, encode, primitive};
use crate::representations::ClarityName;
use crate::types::serialization::TypePrefix;

/// Structurally reconstruct exact consensus bytes without a declared schema.
///
/// This bounded pass validates record framing, shape grammar, scalar encodings, and the declared
/// logical length. Call [`PackedValueRef::audit_reconstruction`] to additionally prove that the
/// payload and shape are their canonical representations of the reconstructed value.
pub fn reconstruct_consensus(
    packed: PackedValueRef<'_>,
    descriptor: &[u8],
) -> Result<Vec<u8>, PackedValueError> {
    let expected_len = packed.consensus_byte_len();
    if expected_len > crate::types::BOUND_VALUE_SERIALIZATION_BYTES {
        return Err(PackedValueError::InvalidRecord(
            "reconstructed consensus value exceeds maximum size",
        ));
    }
    let shape = shape::parse_value_shape(descriptor)?;
    let expected_capacity =
        usize::try_from(expected_len).map_err(|_| PackedValueError::SizeOverflow)?;
    let mut reconstructor = ConsensusReconstructor::with_capacity(expected_capacity);
    reconstructor.reconstruct_body(packed.body(), &shape)?;
    let consensus = reconstructor.finish();
    if consensus.len() != expected_capacity {
        return Err(PackedValueError::InvalidRecord(
            "reconstructed consensus length mismatch",
        ));
    }
    Ok(consensus)
}

/// Reconstruct consensus bytes and prove the packed payload and shape are canonical.
pub fn audit_reconstruction(
    packed: PackedValueRef<'_>,
    descriptor: &[u8],
) -> Result<Vec<u8>, PackedValueError> {
    let consensus = reconstruct_consensus(packed, descriptor)?;
    let (canonical_packed, canonical_shape) = encode::transcode_with_shape(&consensus)?;
    if canonical_packed.as_bytes() != packed.as_bytes() {
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

/// Stateful writer for exact consensus reconstruction.
struct ConsensusReconstructor {
    /// Reconstructed consensus bytes accumulated in wire order.
    output: Vec<u8>,
}

impl ConsensusReconstructor {
    /// Allocate a reconstructor for the logical length declared by the packed record.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
        }
    }

    /// Consume the reconstructor and return the completed consensus bytes.
    fn finish(self) -> Vec<u8> {
        self.output
    }

    /// Append exact consensus bytes for one packed body and its active shape.
    fn reconstruct_body(
        &mut self,
        bytes: &[u8],
        shape: &ActiveShape,
    ) -> Result<(), PackedValueError> {
        match shape {
            ActiveShape::Int => {
                primitive::validate_canonical_signed_scalar(bytes)?;
                self.output.push(TypePrefix::Int.to_u8());
                let fill = if bytes[0] & 0x80 == 0 { 0 } else { 0xff };
                self.append_integer_padding(bytes.len(), fill)?;
                self.output.extend_from_slice(bytes);
            }
            ActiveShape::UInt => {
                primitive::validate_canonical_unsigned_scalar(bytes)?;
                self.output.push(TypePrefix::UInt.to_u8());
                self.append_integer_padding(bytes.len(), 0)?;
                self.output.extend_from_slice(bytes);
            }
            ActiveShape::Bool => match bytes {
                [0] => self.output.push(TypePrefix::BoolFalse.to_u8()),
                [1] => self.output.push(TypePrefix::BoolTrue.to_u8()),
                _ => return Err(PackedValueError::InvalidRecord("invalid boolean")),
            },
            ActiveShape::Buffer => self.reconstruct_sequence(TypePrefix::Buffer.to_u8(), bytes)?,
            ActiveShape::Ascii => {
                if !bytes.iter().all(primitive::valid_ascii_byte) {
                    return Err(PackedValueError::InvalidRecord("invalid ASCII string"));
                }
                self.reconstruct_sequence(TypePrefix::StringASCII.to_u8(), bytes)?;
            }
            ActiveShape::Utf8 => {
                str::from_utf8(bytes)
                    .map_err(|_| PackedValueError::InvalidRecord("invalid UTF-8 string"))?;
                self.reconstruct_sequence(TypePrefix::StringUTF8.to_u8(), bytes)?;
            }
            ActiveShape::Principal => self.reconstruct_principal(bytes)?,
            ActiveShape::Optional(child_shape) => {
                let (tag, child) = primitive::split_tag(bytes)?;
                match (tag, child_shape) {
                    (0, _) if child.is_empty() => {
                        self.output.push(TypePrefix::OptionalNone.to_u8())
                    }
                    (1, Some(shape)) => {
                        self.output.push(TypePrefix::OptionalSome.to_u8());
                        self.reconstruct_body(child, shape)?;
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
                self.output.push(prefix);
                self.reconstruct_body(child, shape)?;
            }
            ActiveShape::Tuple(fields) => self.reconstruct_tuple(bytes, fields)?,
            ActiveShape::List(element_shape) => {
                self.reconstruct_list(bytes, element_shape.as_deref().map(ListShapes::Shared))?
            }
            ActiveShape::ListElements(element_shapes) => {
                self.reconstruct_list(bytes, Some(ListShapes::PerElement(element_shapes)))?
            }
        }
        Ok(())
    }

    /// Append a consensus sequence prefix, byte length, and payload.
    fn reconstruct_sequence(&mut self, prefix: u8, bytes: &[u8]) -> Result<(), PackedValueError> {
        self.output.push(prefix);
        self.output.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| PackedValueError::SizeOverflow)?
                .to_be_bytes(),
        );
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    /// Reconstruct a standard or contract principal consensus value.
    fn reconstruct_principal(&mut self, bytes: &[u8]) -> Result<(), PackedValueError> {
        match primitive::PackedPrincipal::parse(bytes)? {
            primitive::PackedPrincipal::Standard(principal) => {
                self.output.push(TypePrefix::PrincipalStandard.to_u8());
                self.output.extend_from_slice(principal);
            }
            primitive::PackedPrincipal::Contract { issuer, name } => {
                self.output.push(TypePrefix::PrincipalContract.to_u8());
                self.output.extend_from_slice(issuer);
                self.output
                    .push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?);
                self.output.extend_from_slice(name.as_bytes());
            }
        }
        Ok(())
    }

    /// Reconstruct tuple fields from fixed concatenation or directory framing.
    fn reconstruct_tuple(
        &mut self,
        bytes: &[u8],
        fields: &[(ClarityName, ActiveShape)],
    ) -> Result<(), PackedValueError> {
        self.output.push(TypePrefix::Tuple.to_u8());
        self.output.extend_from_slice(
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
                self.reconstruct_tuple_field(name, child, shape)?;
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
                self.reconstruct_tuple_field(name, directory.child(index)?, shape)?;
            }
        }
        Ok(())
    }

    /// Append one named tuple field in consensus order.
    fn reconstruct_tuple_field(
        &mut self,
        name: &ClarityName,
        bytes: &[u8],
        shape: &ActiveShape,
    ) -> Result<(), PackedValueError> {
        let name = name.as_str().as_bytes();
        self.output
            .push(u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?);
        self.output.extend_from_slice(name);
        self.reconstruct_body(bytes, shape)
    }
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

/// List and scalar-lane reconstruction operations.
impl ConsensusReconstructor {
    /// Reconstruct a list using shared or per-element active shapes.
    fn reconstruct_list(
        &mut self,
        bytes: &[u8],
        element_shapes: Option<ListShapes<'_>>,
    ) -> Result<(), PackedValueError> {
        let (count, elements) = primitive::split_list(bytes)?;
        self.output.push(TypePrefix::List.to_u8());
        self.output.extend_from_slice(
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
                return self.reconstruct_unsigned_lane(elements, count);
            }
            ListShapes::Shared(ActiveShape::Int) => {
                return self.reconstruct_signed_lane(elements, count);
            }
            ListShapes::Shared(ActiveShape::Bool) => {
                return self.reconstruct_bool_lane(elements, count);
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
                self.reconstruct_body(child, shape)?;
                cursor = end;
            }
        } else {
            let directory = directory::Directory::parse(elements, count)?;
            for index in 0..count {
                self.reconstruct_body(directory.child(index)?, shapes.get(index)?)?;
            }
        }
        Ok(())
    }

    /// Expand a packed unsigned-integer lane into consensus scalar encodings.
    fn reconstruct_unsigned_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        let lane = primitive::IntegerLane::parse_unsigned(elements, count)?;
        let width = lane.width();
        for element in lane.iter() {
            self.output.push(TypePrefix::UInt.to_u8());
            self.append_integer_padding(width, 0)?;
            self.output.extend_from_slice(element);
        }
        Ok(())
    }

    /// Expand a packed signed-integer lane into consensus scalar encodings.
    fn reconstruct_signed_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        let lane = primitive::IntegerLane::parse_signed(elements, count)?;
        let width = lane.width();
        for element in lane.iter() {
            self.output.push(TypePrefix::Int.to_u8());
            let fill = if element[0] & 0x80 == 0 { 0 } else { 0xff };
            self.append_integer_padding(width, fill)?;
            self.output.extend_from_slice(element);
        }
        Ok(())
    }

    /// Restore a packed integer to the fixed 16-byte consensus representation.
    fn append_integer_padding(
        &mut self,
        packed_width: usize,
        fill: u8,
    ) -> Result<(), PackedValueError> {
        let padding = 16usize
            .checked_sub(packed_width)
            .ok_or(PackedValueError::InvalidRecord(
                "packed integer exceeds 16 bytes",
            ))?;
        let end = self
            .output
            .len()
            .checked_add(padding)
            .ok_or(PackedValueError::SizeOverflow)?;
        self.output.resize(end, fill);
        Ok(())
    }

    /// Expand a bit-packed Boolean lane into consensus Boolean prefixes.
    fn reconstruct_bool_lane(
        &mut self,
        elements: &[u8],
        count: usize,
    ) -> Result<(), PackedValueError> {
        primitive::validate_bool_lane(elements, count)?;
        for index in 0..count {
            let byte = elements
                .get(index / 8)
                .ok_or(PackedValueError::InvalidRecord("truncated boolean lane"))?;
            self.output.push(if byte & (1 << (index % 8)) == 0 {
                TypePrefix::BoolFalse.to_u8()
            } else {
                TypePrefix::BoolTrue.to_u8()
            });
        }
        Ok(())
    }
}
