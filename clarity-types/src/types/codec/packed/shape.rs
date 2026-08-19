// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Canonical active-value shape descriptors used for schema-free reconstruction.
//!
//! A descriptor records only information omitted from packed bytes, such as tuple field names and
//! active optional/response/list shapes. It is derived from the value itself; declared bounds and
//! the current epoch must never influence these bytes.

use super::{PackedValueError, VALUE_SHAPE_VERSION, ValueShape};
use crate::representations::ClarityName;
use crate::types::{CharType, SequenceData, Value};

/// Opcode identifying one node in a Version 1 active-shape descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ShapeOpcode {
    Int = 0x00,
    UInt = 0x01,
    Bool = 0x02,
    Buffer = 0x03,
    Ascii = 0x04,
    Utf8 = 0x05,
    Principal = 0x06,
    OptionalNone = 0x07,
    OptionalSome = 0x08,
    ResponseOk = 0x09,
    ResponseErr = 0x0a,
    ResponseBoth = 0x0b,
    Tuple = 0x0c,
    EmptyList = 0x0d,
    List = 0x0e,
    ListElements = 0x0f,
}

impl ShapeOpcode {
    /// Parse one descriptor opcode byte.
    fn from_byte(byte: u8) -> Result<Self, PackedValueError> {
        match byte {
            0x00 => Ok(Self::Int),
            0x01 => Ok(Self::UInt),
            0x02 => Ok(Self::Bool),
            0x03 => Ok(Self::Buffer),
            0x04 => Ok(Self::Ascii),
            0x05 => Ok(Self::Utf8),
            0x06 => Ok(Self::Principal),
            0x07 => Ok(Self::OptionalNone),
            0x08 => Ok(Self::OptionalSome),
            0x09 => Ok(Self::ResponseOk),
            0x0a => Ok(Self::ResponseErr),
            0x0b => Ok(Self::ResponseBoth),
            0x0c => Ok(Self::Tuple),
            0x0d => Ok(Self::EmptyList),
            0x0e => Ok(Self::List),
            0x0f => Ok(Self::ListElements),
            _ => Err(PackedValueError::InvalidRecord(
                "unknown value-shape opcode",
            )),
        }
    }

    /// Return this opcode's stable Version 1 wire value.
    const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// In-memory form of the canonical active-shape descriptor grammar.
///
/// Optional and response nodes retain only branches observed in the active value. Ordinary list
/// elements merge into one shared shape. Historical unsanitized lists whose elements cannot merge
/// retain one shape per element so schema-free reconstruction still preserves exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveShape {
    /// Signed integer scalar.
    Int,
    /// Unsigned integer scalar.
    UInt,
    /// Boolean scalar.
    Bool,
    /// Byte buffer sequence.
    Buffer,
    /// ASCII string sequence.
    Ascii,
    /// UTF-8 string sequence.
    Utf8,
    /// Standard, contract, or callable contract principal identity.
    Principal,
    /// Optional with only its active child shape, when present.
    Optional(Option<Box<ActiveShape>>),
    /// Response with one or both observed branch shapes.
    Response {
        /// Observed committed branch shape.
        ok: Option<Box<ActiveShape>>,
        /// Observed error branch shape.
        err: Option<Box<ActiveShape>>,
    },
    /// Canonically ordered tuple field names and active child shapes.
    Tuple(Vec<(ClarityName, ActiveShape)>),
    /// Empty list or non-empty list with one shared element shape.
    List(Option<Box<ActiveShape>>),
    /// Per-element shapes for a historical list whose active shapes cannot merge.
    ListElements(Vec<ActiveShape>),
}

/// Encode the canonical active-shape descriptor for an admitted value.
pub fn encode_value_shape(value: &Value) -> Result<ValueShape, PackedValueError> {
    let shape = ActiveShape::from_value(value)?;
    let mut bytes = Vec::new();
    bytes.push(VALUE_SHAPE_VERSION);
    shape.encode(&mut bytes)?;
    if bytes.len() > crate::types::MAX_VALUE_SIZE as usize {
        return Err(PackedValueError::SizeOverflow);
    }
    Ok(ValueShape(bytes))
}

/// Parse and validate one complete Version 1 active-shape descriptor.
pub fn parse_value_shape(bytes: &[u8]) -> Result<ActiveShape, PackedValueError> {
    if bytes.len() > crate::types::MAX_VALUE_SIZE as usize {
        return Err(PackedValueError::InvalidRecord(
            "value shape exceeds maximum size",
        ));
    }
    let (&version, body) = bytes
        .split_first()
        .ok_or(PackedValueError::InvalidRecord("empty value shape"))?;
    if version != VALUE_SHAPE_VERSION {
        return Err(PackedValueError::InvalidRecord(
            "unsupported value-shape version",
        ));
    }
    let mut cursor = 0usize;
    let shape = ActiveShape::parse(body, &mut cursor, 0)?;
    if cursor != body.len() {
        return Err(PackedValueError::InvalidRecord(
            "value shape has trailing bytes",
        ));
    }
    Ok(shape)
}

impl ActiveShape {
    /// Derive reconstruction metadata solely from an active value.
    fn from_value(value: &Value) -> Result<Self, PackedValueError> {
        match value {
            Value::Int(_) => Ok(Self::Int),
            Value::UInt(_) => Ok(Self::UInt),
            Value::Bool(_) => Ok(Self::Bool),
            Value::Sequence(SequenceData::Buffer(_)) => Ok(Self::Buffer),
            Value::Sequence(SequenceData::String(CharType::ASCII(_))) => Ok(Self::Ascii),
            Value::Sequence(SequenceData::String(CharType::UTF8(_))) => Ok(Self::Utf8),
            Value::Principal(_) | Value::CallableContract(_) => Ok(Self::Principal),
            Value::Optional(optional) => Ok(Self::Optional(
                optional
                    .data
                    .as_deref()
                    .map(Self::from_value)
                    .transpose()?
                    .map(Box::new),
            )),
            Value::Response(response) => {
                let child = Box::new(Self::from_value(&response.data)?);
                if response.committed {
                    Ok(Self::Response {
                        ok: Some(child),
                        err: None,
                    })
                } else {
                    Ok(Self::Response {
                        ok: None,
                        err: Some(child),
                    })
                }
            }
            Value::Tuple(tuple) => tuple
                .data_map
                .iter()
                .map(|(name, value)| Ok((name.clone(), Self::from_value(value)?)))
                .collect::<Result<Vec<_>, PackedValueError>>()
                .map(Self::Tuple),
            Value::Sequence(SequenceData::List(list)) => {
                let elements = list
                    .data
                    .iter()
                    .map(Self::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if elements.is_empty() {
                    return Ok(Self::List(None));
                }
                Ok(list_shape_from_elements(elements))
            }
        }
    }

    /// Merge two active shapes when one canonical shared shape can reconstruct both.
    fn merge(self, other: Self) -> Result<Self, PackedValueError> {
        match (self, other) {
            (Self::Int, Self::Int) => Ok(Self::Int),
            (Self::UInt, Self::UInt) => Ok(Self::UInt),
            (Self::Bool, Self::Bool) => Ok(Self::Bool),
            (Self::Buffer, Self::Buffer) => Ok(Self::Buffer),
            (Self::Ascii, Self::Ascii) => Ok(Self::Ascii),
            (Self::Utf8, Self::Utf8) => Ok(Self::Utf8),
            (Self::Principal, Self::Principal) => Ok(Self::Principal),
            (Self::Optional(left), Self::Optional(right)) => {
                Ok(Self::Optional(merge_optional_shape(left, right)?))
            }
            (
                Self::Response {
                    ok: left_ok,
                    err: left_err,
                },
                Self::Response {
                    ok: right_ok,
                    err: right_err,
                },
            ) => Ok(Self::Response {
                ok: merge_optional_shape(left_ok, right_ok)?,
                err: merge_optional_shape(left_err, right_err)?,
            }),
            (Self::Tuple(left), Self::Tuple(right)) if left.len() == right.len() => {
                let mut merged = Vec::with_capacity(left.len());
                for ((left_name, left_shape), (right_name, right_shape)) in
                    left.into_iter().zip(right)
                {
                    if left_name != right_name {
                        return Err(incompatible_shape_error());
                    }
                    merged.push((left_name, left_shape.merge(right_shape)?));
                }
                Ok(Self::Tuple(merged))
            }
            (Self::List(left), Self::List(right)) => {
                Ok(Self::List(merge_optional_shape(left, right)?))
            }
            (Self::List(Some(shared)), Self::ListElements(elements))
            | (Self::ListElements(elements), Self::List(Some(shared))) => {
                let merged = elements.into_iter().try_fold(*shared, ActiveShape::merge)?;
                Ok(Self::List(Some(Box::new(merged))))
            }
            (Self::ListElements(left), Self::ListElements(right)) if left.len() == right.len() => {
                let elements = left
                    .into_iter()
                    .zip(right)
                    .map(|(left, right)| left.merge(right))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(list_shape_from_elements(elements))
            }
            (Self::ListElements(left), Self::ListElements(right)) => {
                let elements = left.into_iter().chain(right).collect::<Vec<_>>();
                let merged = merge_list_elements(&elements)?;
                Ok(Self::List(Some(Box::new(merged))))
            }
            _ => Err(incompatible_shape_error()),
        }
    }

    /// Append this shape using the canonical Version 1 descriptor grammar.
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
        match self {
            Self::Int => output.push(ShapeOpcode::Int.to_byte()),
            Self::UInt => output.push(ShapeOpcode::UInt.to_byte()),
            Self::Bool => output.push(ShapeOpcode::Bool.to_byte()),
            Self::Buffer => output.push(ShapeOpcode::Buffer.to_byte()),
            Self::Ascii => output.push(ShapeOpcode::Ascii.to_byte()),
            Self::Utf8 => output.push(ShapeOpcode::Utf8.to_byte()),
            Self::Principal => output.push(ShapeOpcode::Principal.to_byte()),
            Self::Optional(None) => output.push(ShapeOpcode::OptionalNone.to_byte()),
            Self::Optional(Some(child)) => {
                output.push(ShapeOpcode::OptionalSome.to_byte());
                child.encode(output)?;
            }
            Self::Response {
                ok: Some(ok),
                err: None,
            } => {
                output.push(ShapeOpcode::ResponseOk.to_byte());
                ok.encode(output)?;
            }
            Self::Response {
                ok: None,
                err: Some(err),
            } => {
                output.push(ShapeOpcode::ResponseErr.to_byte());
                err.encode(output)?;
            }
            Self::Response {
                ok: Some(ok),
                err: Some(err),
            } => {
                output.push(ShapeOpcode::ResponseBoth.to_byte());
                ok.encode(output)?;
                err.encode(output)?;
            }
            Self::Response {
                ok: None,
                err: None,
            } => {
                return Err(PackedValueError::InvalidRecord(
                    "response shape has no active branch",
                ));
            }
            Self::Tuple(fields) => {
                output.push(ShapeOpcode::Tuple.to_byte());
                encode_varuint(fields.len(), output)?;
                for (name, shape) in fields {
                    let name = name.as_str().as_bytes();
                    output.push(
                        u8::try_from(name.len()).map_err(|_| PackedValueError::SizeOverflow)?,
                    );
                    output.extend_from_slice(name);
                    shape.encode(output)?;
                }
            }
            Self::List(None) => output.push(ShapeOpcode::EmptyList.to_byte()),
            Self::List(Some(child)) => {
                output.push(ShapeOpcode::List.to_byte());
                child.encode(output)?;
            }
            Self::ListElements(elements) => {
                if elements.is_empty() {
                    return Err(PackedValueError::InvalidRecord(
                        "per-element list shape is empty",
                    ));
                }
                output.push(ShapeOpcode::ListElements.to_byte());
                encode_varuint(elements.len(), output)?;
                for element in elements {
                    element.encode(output)?;
                }
            }
        }
        Ok(())
    }

    /// Parse one recursive shape node while enforcing depth and canonicality limits.
    fn parse(bytes: &[u8], cursor: &mut usize, depth: u8) -> Result<Self, PackedValueError> {
        if depth > crate::types::MAX_TYPE_DEPTH {
            return Err(PackedValueError::InvalidRecord(
                "value shape exceeds maximum depth",
            ));
        }
        let opcode = ShapeOpcode::from_byte(take_shape_byte(bytes, cursor)?)?;
        let child_depth = depth.checked_add(1).ok_or(PackedValueError::SizeOverflow)?;
        match opcode {
            ShapeOpcode::Int => Ok(Self::Int),
            ShapeOpcode::UInt => Ok(Self::UInt),
            ShapeOpcode::Bool => Ok(Self::Bool),
            ShapeOpcode::Buffer => Ok(Self::Buffer),
            ShapeOpcode::Ascii => Ok(Self::Ascii),
            ShapeOpcode::Utf8 => Ok(Self::Utf8),
            ShapeOpcode::Principal => Ok(Self::Principal),
            ShapeOpcode::OptionalNone => Ok(Self::Optional(None)),
            ShapeOpcode::OptionalSome => Ok(Self::Optional(Some(Box::new(Self::parse(
                bytes,
                cursor,
                child_depth,
            )?)))),
            ShapeOpcode::ResponseOk => Ok(Self::Response {
                ok: Some(Box::new(Self::parse(bytes, cursor, child_depth)?)),
                err: None,
            }),
            ShapeOpcode::ResponseErr => Ok(Self::Response {
                ok: None,
                err: Some(Box::new(Self::parse(bytes, cursor, child_depth)?)),
            }),
            ShapeOpcode::ResponseBoth => Ok(Self::Response {
                ok: Some(Box::new(Self::parse(bytes, cursor, child_depth)?)),
                err: Some(Box::new(Self::parse(bytes, cursor, child_depth)?)),
            }),
            ShapeOpcode::Tuple => {
                let count = decode_varuint(bytes, cursor)?;
                if count == 0 {
                    return Err(PackedValueError::InvalidRecord(
                        "value-shape tuple has no fields",
                    ));
                }
                if count > bytes.len().saturating_sub(*cursor) / 2 {
                    return Err(PackedValueError::InvalidRecord(
                        "value-shape tuple field count exceeds descriptor",
                    ));
                }
                let mut fields = Vec::with_capacity(count);
                for _ in 0..count {
                    let name_len = usize::from(take_shape_byte(bytes, cursor)?);
                    let end = cursor
                        .checked_add(name_len)
                        .ok_or(PackedValueError::SizeOverflow)?;
                    let name_bytes =
                        bytes
                            .get(*cursor..end)
                            .ok_or(PackedValueError::InvalidRecord(
                                "truncated value-shape tuple name",
                            ))?;
                    let name = str::from_utf8(name_bytes)
                        .map_err(|_| PackedValueError::InvalidRecord("invalid tuple name UTF-8"))?;
                    let name = ClarityName::try_from(name.to_owned())
                        .map_err(|_| PackedValueError::InvalidRecord("invalid tuple name"))?;
                    if fields
                        .last()
                        .is_some_and(|(previous, _): &(ClarityName, Self)| previous >= &name)
                    {
                        return Err(PackedValueError::InvalidRecord(
                            "tuple shape fields are not canonical",
                        ));
                    }
                    *cursor = end;
                    let shape = Self::parse(bytes, cursor, child_depth)?;
                    fields.push((name, shape));
                }
                Ok(Self::Tuple(fields))
            }
            ShapeOpcode::EmptyList => Ok(Self::List(None)),
            ShapeOpcode::List => Ok(Self::List(Some(Box::new(Self::parse(
                bytes,
                cursor,
                child_depth,
            )?)))),
            ShapeOpcode::ListElements => {
                let count = decode_varuint(bytes, cursor)?;
                if count == 0 || count > bytes.len().saturating_sub(*cursor) {
                    return Err(PackedValueError::InvalidRecord(
                        "invalid per-element list-shape count",
                    ));
                }
                let mut elements = Vec::with_capacity(count);
                for _ in 0..count {
                    elements.push(Self::parse(bytes, cursor, child_depth)?);
                }
                if merge_list_elements(&elements).is_ok() {
                    return Err(PackedValueError::InvalidRecord(
                        "mergeable list uses per-element shapes",
                    ));
                }
                Ok(Self::ListElements(elements))
            }
        }
    }

    /// Return this active shape's directory-free packed width, if fixed.
    pub fn fixed_width(&self) -> Option<usize> {
        match self {
            Self::Bool => Some(1),
            Self::Tuple(fields) => fields.iter().try_fold(0usize, |total, (_, child)| {
                total.checked_add(child.fixed_width()?)
            }),
            _ => None,
        }
    }
}

/// Merge optional child shapes while preserving an absent branch.
fn merge_optional_shape(
    left: Option<Box<ActiveShape>>,
    right: Option<Box<ActiveShape>>,
) -> Result<Option<Box<ActiveShape>>, PackedValueError> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(shape), None) | (None, Some(shape)) => Ok(Some(shape)),
        (Some(left), Some(right)) => Ok(Some(Box::new(left.merge(*right)?))),
    }
}

/// Reduce every list element to one shared active shape.
fn merge_list_elements(elements: &[ActiveShape]) -> Result<ActiveShape, PackedValueError> {
    let (first, rest) = elements
        .split_first()
        .ok_or(PackedValueError::InvalidRecord(
            "list shape has no elements",
        ))?;
    rest.iter()
        .cloned()
        .try_fold(first.clone(), ActiveShape::merge)
}

/// Select shared or per-element list metadata according to whether all shapes merge.
fn list_shape_from_elements(elements: Vec<ActiveShape>) -> ActiveShape {
    debug_assert!(!elements.is_empty());
    match merge_list_elements(&elements) {
        Ok(merged) => ActiveShape::List(Some(Box::new(merged))),
        Err(_) => ActiveShape::ListElements(elements),
    }
}

/// Construct the internal signal that two active shapes cannot be merged.
fn incompatible_shape_error() -> PackedValueError {
    PackedValueError::InvalidRecord("incompatible active list element shapes")
}

/// Append a minimal unsigned LEB128 descriptor integer.
fn encode_varuint(mut value: usize, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
    loop {
        let mut byte = u8::try_from(value & 0x7f).map_err(|_| PackedValueError::SizeOverflow)?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return Ok(());
        }
    }
}

/// Decode one minimal unsigned LEB128 descriptor integer and advance `cursor`.
fn decode_varuint(bytes: &[u8], cursor: &mut usize) -> Result<usize, PackedValueError> {
    let start = *cursor;
    let mut value = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = take_shape_byte(bytes, cursor)?;
        let part = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(PackedValueError::SizeOverflow)?;
        value = value
            .checked_add(part)
            .ok_or(PackedValueError::SizeOverflow)?;
        if byte & 0x80 == 0 {
            // A multi-byte unsigned LEB128 ending in a zero payload has a redundant high group.
            if *cursor - start > 1 && byte & 0x7f == 0 {
                return Err(PackedValueError::InvalidRecord(
                    "non-canonical value-shape varuint",
                ));
            }
            return Ok(value);
        }
        shift = shift.checked_add(7).ok_or(PackedValueError::SizeOverflow)?;
        if shift >= usize::BITS {
            return Err(PackedValueError::SizeOverflow);
        }
    }
}

/// Read one descriptor byte and advance `cursor` with checked arithmetic.
fn take_shape_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, PackedValueError> {
    let byte = bytes
        .get(*cursor)
        .copied()
        .ok_or(PackedValueError::InvalidRecord("truncated value shape"))?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(PackedValueError::SizeOverflow)?;
    Ok(byte)
}
