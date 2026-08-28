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

//! Canonical active-value shape descriptors used for schema-free reconstruction.
//!
//! A descriptor records only information omitted from packed bytes, such as tuple field names and
//! active optional/response/list shapes. It is derived from the value itself; declared bounds and
//! the current epoch must never influence these bytes.

use super::{BOUND_VALUE_SHAPE_BYTES, PackedValueError, VALUE_SHAPE_VERSION, ValueShape};
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
    if bytes.len() > BOUND_VALUE_SHAPE_BYTES {
        return Err(PackedValueError::SizeOverflow);
    }
    Ok(ValueShape(bytes))
}

/// Parse and validate one complete Version 1 active-shape descriptor.
pub fn parse_value_shape(bytes: &[u8]) -> Result<ActiveShape, PackedValueError> {
    if bytes.len() > BOUND_VALUE_SHAPE_BYTES {
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
    ShapeParser::new(body).parse()
}

/// Stateful reader for one recursive active-shape descriptor body.
struct ShapeParser<'a> {
    /// Descriptor body, excluding its version byte.
    bytes: &'a [u8],
    /// Next unread byte within `bytes`.
    cursor: usize,
}

impl<'a> ShapeParser<'a> {
    /// Begin parsing one descriptor body.
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Parse one complete descriptor body with no trailing bytes.
    fn parse(mut self) -> Result<ActiveShape, PackedValueError> {
        let shape = self.parse_shape(0)?;
        if self.cursor != self.bytes.len() {
            return Err(PackedValueError::InvalidRecord(
                "value shape has trailing bytes",
            ));
        }
        Ok(shape)
    }

    /// Parse one recursive shape node while enforcing depth and canonicality limits.
    fn parse_shape(&mut self, depth: u8) -> Result<ActiveShape, PackedValueError> {
        if depth >= crate::types::MAX_TYPE_DEPTH {
            return Err(PackedValueError::InvalidRecord(
                "value shape exceeds maximum depth",
            ));
        }
        let opcode = ShapeOpcode::from_byte(self.take_byte()?)?;
        let child_depth = depth.checked_add(1).ok_or(PackedValueError::SizeOverflow)?;
        match opcode {
            ShapeOpcode::Int => Ok(ActiveShape::Int),
            ShapeOpcode::UInt => Ok(ActiveShape::UInt),
            ShapeOpcode::Bool => Ok(ActiveShape::Bool),
            ShapeOpcode::Buffer => Ok(ActiveShape::Buffer),
            ShapeOpcode::Ascii => Ok(ActiveShape::Ascii),
            ShapeOpcode::Utf8 => Ok(ActiveShape::Utf8),
            ShapeOpcode::Principal => Ok(ActiveShape::Principal),
            ShapeOpcode::OptionalNone => Ok(ActiveShape::Optional(None)),
            ShapeOpcode::OptionalSome => Ok(ActiveShape::Optional(Some(Box::new(
                self.parse_shape(child_depth)?,
            )))),
            ShapeOpcode::ResponseOk => Ok(ActiveShape::Response {
                ok: Some(Box::new(self.parse_shape(child_depth)?)),
                err: None,
            }),
            ShapeOpcode::ResponseErr => Ok(ActiveShape::Response {
                ok: None,
                err: Some(Box::new(self.parse_shape(child_depth)?)),
            }),
            ShapeOpcode::ResponseBoth => Ok(ActiveShape::Response {
                ok: Some(Box::new(self.parse_shape(child_depth)?)),
                err: Some(Box::new(self.parse_shape(child_depth)?)),
            }),
            ShapeOpcode::Tuple => self.parse_tuple(child_depth),
            ShapeOpcode::EmptyList => Ok(ActiveShape::List(None)),
            ShapeOpcode::List => Ok(ActiveShape::List(Some(Box::new(
                self.parse_shape(child_depth)?,
            )))),
            ShapeOpcode::ListElements => self.parse_list_elements(child_depth),
        }
    }

    /// Parse a non-empty, canonically ordered tuple descriptor.
    fn parse_tuple(&mut self, child_depth: u8) -> Result<ActiveShape, PackedValueError> {
        let count = self.take_varuint()?;
        if count == 0 {
            return Err(PackedValueError::InvalidRecord(
                "value-shape tuple has no fields",
            ));
        }
        if count > self.bytes.len().saturating_sub(self.cursor) / 2 {
            return Err(PackedValueError::InvalidRecord(
                "value-shape tuple field count exceeds descriptor",
            ));
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = usize::from(self.take_byte()?);
            let end = self
                .cursor
                .checked_add(name_len)
                .ok_or(PackedValueError::SizeOverflow)?;
            let name_bytes =
                self.bytes
                    .get(self.cursor..end)
                    .ok_or(PackedValueError::InvalidRecord(
                        "truncated value-shape tuple name",
                    ))?;
            let name = str::from_utf8(name_bytes)
                .map_err(|_| PackedValueError::InvalidRecord("invalid tuple name UTF-8"))?;
            let name = ClarityName::try_from(name.to_owned())
                .map_err(|_| PackedValueError::InvalidRecord("invalid tuple name"))?;
            if fields
                .last()
                .is_some_and(|(previous, _): &(ClarityName, ActiveShape)| previous >= &name)
            {
                return Err(PackedValueError::InvalidRecord(
                    "tuple shape fields are not canonical",
                ));
            }
            self.cursor = end;
            fields.push((name, self.parse_shape(child_depth)?));
        }
        Ok(ActiveShape::Tuple(fields))
    }

    /// Parse non-mergeable per-element list descriptors.
    fn parse_list_elements(&mut self, child_depth: u8) -> Result<ActiveShape, PackedValueError> {
        let count = self.take_varuint()?;
        if count == 0 || count > self.bytes.len().saturating_sub(self.cursor) {
            return Err(PackedValueError::InvalidRecord(
                "invalid per-element list-shape count",
            ));
        }
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(self.parse_shape(child_depth)?);
        }
        if merge_list_elements(&elements).is_ok() {
            return Err(PackedValueError::InvalidRecord(
                "mergeable list uses per-element shapes",
            ));
        }
        Ok(ActiveShape::ListElements(elements))
    }

    /// Decode one minimal unsigned LEB128 descriptor integer.
    fn take_varuint(&mut self) -> Result<usize, PackedValueError> {
        let start = self.cursor;
        let mut value = 0usize;
        let mut shift = 0u32;
        loop {
            let byte = self.take_byte()?;
            let group = usize::from(byte & 0x7f);
            if group > (usize::MAX >> shift) {
                return Err(PackedValueError::SizeOverflow);
            }
            let part = group << shift;
            value = value
                .checked_add(part)
                .ok_or(PackedValueError::SizeOverflow)?;
            if byte & 0x80 == 0 {
                if self.cursor - start > 1 && byte & 0x7f == 0 {
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

    /// Read one descriptor byte and advance the parser.
    fn take_byte(&mut self) -> Result<u8, PackedValueError> {
        let byte = self
            .bytes
            .get(self.cursor)
            .copied()
            .ok_or(PackedValueError::InvalidRecord("truncated value shape"))?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow)?;
        Ok(byte)
    }
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
                let Some((first, rest)) = list.data.split_first() else {
                    return Ok(Self::List(None));
                };
                let first_shape = Self::from_value(first)?;
                if rest
                    .iter()
                    .all(|element| first_shape.matches_value(element))
                {
                    return Ok(Self::List(Some(Box::new(first_shape))));
                }
                let elements = list
                    .data
                    .iter()
                    .map(Self::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(list_shape_from_elements(elements))
            }
        }
    }

    /// Return whether this descriptor can reconstruct one active value without widening.
    fn matches_value(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Int, Value::Int(_))
            | (Self::UInt, Value::UInt(_))
            | (Self::Bool, Value::Bool(_))
            | (Self::Buffer, Value::Sequence(SequenceData::Buffer(_)))
            | (Self::Ascii, Value::Sequence(SequenceData::String(CharType::ASCII(_))))
            | (Self::Utf8, Value::Sequence(SequenceData::String(CharType::UTF8(_))))
            | (Self::Principal, Value::Principal(_) | Value::CallableContract(_)) => true,
            (Self::Optional(_), Value::Optional(optional)) if optional.data.is_none() => true,
            (Self::Optional(Some(shape)), Value::Optional(optional)) => optional
                .data
                .as_deref()
                .is_some_and(|value| shape.matches_value(value)),
            (
                Self::Response {
                    ok: Some(shape), ..
                },
                Value::Response(response),
            ) if response.committed => shape.matches_value(&response.data),
            (
                Self::Response {
                    err: Some(shape), ..
                },
                Value::Response(response),
            ) if !response.committed => shape.matches_value(&response.data),
            (Self::Tuple(fields), Value::Tuple(tuple)) => {
                fields.len() == tuple.data_map.len()
                    && fields.iter().zip(&tuple.data_map).all(
                        |((expected_name, expected_shape), (name, value))| {
                            expected_name == name && expected_shape.matches_value(value)
                        },
                    )
            }
            (Self::List(None), Value::Sequence(SequenceData::List(list))) => list.data.is_empty(),
            (Self::List(Some(shape)), Value::Sequence(SequenceData::List(list))) => {
                list.data.iter().all(|value| shape.matches_value(value))
            }
            (Self::ListElements(shapes), Value::Sequence(SequenceData::List(list))) => {
                shapes.len() == list.data.len()
                    && shapes
                        .iter()
                        .zip(&list.data)
                        .all(|(shape, value)| shape.matches_value(value))
            }
            _ => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BOUND_VALUE_SERIALIZATION_BYTES;

    #[test]
    fn structurally_valid_shape_uses_its_own_stream_bound() {
        const LIST_ELEMENTS: u8 = 0x0f;
        const TUPLE: u8 = 0x0c;
        const BOOL: u8 = 0x02;
        const ELEMENT_COUNT: usize = 131_070;
        const NARROW_CONSENSUS_LEN: usize = 8;
        const WIDE_CONSENSUS_LEN: usize = 14;
        const ELEMENT_COUNT_VARUINT: [u8; 3] = [0xfe, 0xff, 0x07];
        const NARROW_SHAPE: [u8; 5] = [TUPLE, 1, 1, b'a', BOOL];
        const WIDE_SHAPE: [u8; 11] = [TUPLE, 3, 1, b'a', BOOL, 1, b'b', BOOL, 1, b'c', BOOL];

        // This structurally valid descriptor and its corresponding consensus stream fit the
        // storage-format bounds even though the widened list type would exceed Clarity's smaller
        // runtime-value bound. The parser therefore applies the descriptor stream's own resource
        // limit instead of borrowing a limit from an unrelated representation.
        let consensus_len = 5 + NARROW_CONSENSUS_LEN + (ELEMENT_COUNT - 1) * WIDE_CONSENSUS_LEN;
        assert!(consensus_len <= BOUND_VALUE_SERIALIZATION_BYTES as usize);

        let mut descriptor = Vec::with_capacity(
            2 + ELEMENT_COUNT_VARUINT.len()
                + NARROW_SHAPE.len()
                + (ELEMENT_COUNT - 1) * WIDE_SHAPE.len(),
        );
        descriptor.extend([VALUE_SHAPE_VERSION, LIST_ELEMENTS]);
        descriptor.extend(ELEMENT_COUNT_VARUINT);
        descriptor.extend(NARROW_SHAPE);
        for _ in 1..ELEMENT_COUNT {
            descriptor.extend(WIDE_SHAPE);
        }
        assert!(descriptor.len() > crate::types::MAX_VALUE_SIZE as usize);
        assert!(descriptor.len() <= BOUND_VALUE_SHAPE_BYTES);

        let shape = parse_value_shape(&descriptor).unwrap();
        let mut reencoded = vec![VALUE_SHAPE_VERSION];
        shape.encode(&mut reencoded).unwrap();
        assert_eq!(reencoded, descriptor);
        assert_eq!(
            ValueShape::from_bytes(&descriptor).unwrap().as_bytes(),
            descriptor
        );
    }
}
