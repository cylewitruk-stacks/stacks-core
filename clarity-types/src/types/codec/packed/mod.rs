// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Canonical packed physical storage for Clarity values.
//!
//! This is not Clarity's consensus serialization. The encompassing SQLite side-store format is
//! Binary V1; this module defines only its packed `Value` payload and reconstruction metadata.
//!
//! Each packed record starts with the equivalent consensus byte length as a little-endian `u32`,
//! followed by a body whose layout is determined by the active value. Scalars use canonical
//! minimal-width encodings. Variable-width tuple fields and list elements use an offset directory;
//! fixed-width children omit it. Integer and Boolean lists use dense homogeneous lanes.
//!
//! Two invariants make content-addressed storage safe:
//!
//! - packed bytes depend only on the active [`Value`], never declared bounds or epoch;
//! - [`ValueShape`] records only information omitted from packed bytes that is needed to reconstruct
//!   the exact consensus serialization without a declared [`crate::types::TypeSignature`].

use std::error::Error;
use std::fmt;

use crate::errors::ClarityTypeError;
use crate::types::Value;

mod decode;
mod directory;
mod encode;
mod layout;
mod primitive;
mod reconstruct;
mod shape;

pub use decode::{decode_canonical_packed, validate_canonical_packed};
pub use encode::{
    encode_canonical_packed_admitted, encode_canonical_packed_value,
    encode_canonical_packed_value_with_consensus_len, transcode_consensus_to_canonical_packed,
    transcode_consensus_with_shape,
};
pub use reconstruct::{audit_reconstruction, reconstruct_consensus};
pub use shape::encode_value_shape;

/// Number of bytes before a packed V1 value body.
pub const PACKED_VALUE_HEADER_LEN: usize = 4;

/// Version byte for the active value-shape descriptor grammar.
pub const VALUE_SHAPE_VERSION: u8 = 1;

/// A Clarity value proven to conform to its declared storage type.
///
/// Construction performs epoch-aware admission once. Commit-time physical encoding accepts this
/// type so it cannot accidentally repeat or omit that check. The type is deliberately move-only
/// to prevent accidental deep copies of retained value trees.
#[derive(Debug)]
pub struct AdmittedValue {
    /// Runtime value admitted by the declared storage type.
    value: Value,
}

impl AdmittedValue {
    /// Borrow the admitted runtime value.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// The encoded bytes and logical length produced by the packed codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedValue {
    /// Complete length-prefixed packed record.
    bytes: Vec<u8>,
    /// Equivalent consensus-serialization length cached from the record header.
    consensus_byte_len: u32,
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

/// Canonical reconstruction metadata for one active Clarity value shape.
///
/// The descriptor contains only information omitted from [`PackedValue`] that is required to
/// reconstruct consensus bytes without a declared schema.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ValueShape(Vec<u8>);

impl ValueShape {
    /// Borrow the complete versioned descriptor.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume this descriptor and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Parse and validate one complete versioned descriptor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PackedValueError> {
        if bytes.len() > crate::types::MAX_VALUE_SIZE as usize {
            return Err(PackedValueError::InvalidRecord(
                "value shape exceeds maximum size",
            ));
        }
        shape::parse_value_shape(bytes)?;
        Ok(Self(bytes.to_vec()))
    }
}

/// Whether to verify a caller-supplied consensus length before returning an encoding.
///
/// Admission, migration, and test tooling should use [`ConsensusLengthValidation::Enabled`]. A
/// persistence path that obtained the length from the same consensus bytes used for the MARF hash
/// may skip this redundant `Value::serialized_size` calculation on its write hot path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConsensusLengthValidation {
    /// Recompute and compare the value's consensus serialization length.
    #[default]
    Enabled,
    /// Trust the caller-supplied consensus length.
    Disabled,
}

/// Errors produced by the packed value codec.
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
    ConsensusSerialization(crate::types::serialization::SerializationError),
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

impl From<crate::types::serialization::SerializationError> for PackedValueError {
    fn from(error: crate::types::serialization::SerializationError) -> Self {
        Self::ConsensusSerialization(error)
    }
}

/// An owned decoded value paired with its logical serialized length.
#[derive(Debug, PartialEq)]
pub struct DecodedPackedValue {
    /// The materialized Clarity value.
    pub value: Value,
    /// The length of its equivalent consensus serialization.
    pub consensus_byte_len: u32,
}
