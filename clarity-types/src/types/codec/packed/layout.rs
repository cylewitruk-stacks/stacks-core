// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Schema-independent fixed-width layout classification.
//!
//! Only Booleans and recursively fixed tuples omit parent offset directories. Declared sequence
//! bounds and inactive response/optional branches never select physical framing.

use super::PackedValueError;
use crate::types::{ListData, TypeSignature, Value};

/// Physical framing selected for a non-empty list's element region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListLayout {
    /// Homogeneous unsigned integers sharing one minimal scalar width.
    UnsignedLane,
    /// Homogeneous signed integers sharing one minimal scalar width.
    SignedLane,
    /// Homogeneous Booleans packed one bit per element.
    BooleanLane,
    /// Directory-free concatenation of fixed-width element bodies.
    Fixed,
    /// Offset-directory framing for variable-width element bodies.
    Variable,
}

/// Classify list framing from active elements only.
///
/// Runtime lists are normally homogeneous. Schema-free migration can also encounter historical
/// unsanitized lists whose elements have incompatible tuple shapes, so classification must inspect
/// every element instead of trusting the list's stored item type or first value.
pub fn list_layout(list: &ListData) -> ListLayout {
    if list
        .data
        .iter()
        .all(|value| matches!(value, Value::UInt(_)))
    {
        ListLayout::UnsignedLane
    } else if list.data.iter().all(|value| matches!(value, Value::Int(_))) {
        ListLayout::SignedLane
    } else if list
        .data
        .iter()
        .all(|value| matches!(value, Value::Bool(_)))
    {
        ListLayout::BooleanLane
    } else if list
        .data
        .iter()
        .all(|value| fixed_value_width(value).is_some())
    {
        ListLayout::Fixed
    } else {
        ListLayout::Variable
    }
}

/// Return the directory-free width selected by an active value, if any.
pub fn fixed_value_width(value: &Value) -> Option<usize> {
    match value {
        Value::Bool(_) => Some(1),
        Value::Tuple(tuple) => tuple.data_map.values().try_fold(0usize, |total, child| {
            total.checked_add(fixed_value_width(child)?)
        }),
        _ => None,
    }
}

/// Return the directory-free width implied by a read schema, if any.
pub fn fixed_type_width(expected: &TypeSignature) -> Result<Option<usize>, PackedValueError> {
    match expected {
        TypeSignature::BoolType => Ok(Some(1)),
        TypeSignature::TupleType(tuple) => {
            let mut total = 0usize;
            for child in tuple.get_type_map().values() {
                let Some(width) = fixed_type_width(child)? else {
                    return Ok(None);
                };
                total = total
                    .checked_add(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
            }
            Ok(Some(total))
        }
        TypeSignature::ListUnionType(_) => Err(PackedValueError::UnsupportedSchema(
            "ListUnionType is analysis-only",
        )),
        _ => Ok(None),
    }
}
