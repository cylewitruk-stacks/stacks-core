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

//! Fuzz coverage for packed values, shape descriptors, and reconstruction.

#![no_main]

use clarity::vm::representations::ClarityName;
use clarity::vm::types::codec::packed::{
    AdmittedValue, ConsensusLengthValidation, PackedValue, PackedValueRef, ValueShape,
};
use clarity::vm::types::{
    ListTypeData, SequenceSubtype, TupleData, TupleTypeSignature, TypeSignature, Value,
};
use libfuzzer_sys::fuzz_target;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::hex_bytes;

/// Decode reviewable text fixtures while leaving ordinary generated input raw.
fn decode_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    let encoded = std::str::from_utf8(encoded).ok()?;
    let encoded = encoded.trim_end_matches(['\r', '\n']);
    hex_bytes(encoded).ok()
}

/// Deterministically select a bounded declared schema from fuzz input.
fn schema(selector: u8) -> TypeSignature {
    match selector % 8 {
        0 => TypeSignature::IntType,
        1 => TypeSignature::UIntType,
        2 => TypeSignature::BoolType,
        3 => TypeSignature::SequenceType(SequenceSubtype::BufferType(
            4_096u32.try_into().expect("constant buffer bound"),
        )),
        4 => TypeSignature::new_option(TypeSignature::UIntType).expect("constant optional schema"),
        5 => TypeSignature::new_response(
            TypeSignature::BoolType,
            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                256u32.try_into().expect("constant buffer bound"),
            )),
        )
        .expect("constant response schema"),
        6 => TypeSignature::SequenceType(SequenceSubtype::ListType(
            ListTypeData::new_list(TypeSignature::UIntType, 256).expect("constant list schema"),
        )),
        _ => TypeSignature::TupleType(
            TupleTypeSignature::try_from(vec![
                (ClarityName::from_literal("active"), TypeSignature::BoolType),
                (ClarityName::from_literal("amount"), TypeSignature::UIntType),
            ])
            .expect("constant tuple schema"),
        ),
    }
}

/// Check transcode, shape, and reconstruction invariants for candidate consensus bytes.
fn check_consensus(consensus: &[u8], epoch: &StacksEpochId) {
    let Ok(value) = Value::try_deserialize_slice_exact_untyped(consensus) else {
        return;
    };
    let canonical = value
        .serialize_to_vec()
        .expect("a decoded Clarity value must serialize");
    if canonical != consensus {
        assert!(PackedValue::transcode_consensus_with_shape(consensus).is_err());
        return;
    }
    let (packed, shape) = PackedValue::transcode_consensus_with_shape(consensus)
        .expect("every exactly decoded consensus value must transcode");
    assert_eq!(
        packed
            .as_packed_ref()
            .audit_reconstruction(shape.as_bytes())
            .expect("a canonical packed record must reconstruct"),
        consensus
    );
    assert_eq!(canonical, consensus);

    let Ok(expected) = TypeSignature::type_of(&value) else {
        return;
    };
    let value_shape = ValueShape::from_value(&value).expect("an encodable value must have a shape");
    let Ok(admitted) = AdmittedValue::new(value, &expected, epoch) else {
        return;
    };
    let typed = admitted
        .encode_packed(
            u32::try_from(consensus.len()).expect("Clarity consensus value length is bounded"),
            ConsensusLengthValidation::Disabled,
        )
        .expect("an admitted value must pack");
    assert_eq!(typed.as_bytes(), packed.as_bytes());
    assert_eq!(value_shape.as_bytes(), shape.as_bytes());
}

/// Fold at most sixteen fuzz bytes into a deterministic unsigned integer.
fn unsigned(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .take(16)
        .fold(0, |value, byte| (value << 8) | u128::from(*byte))
}

/// Build a valid bounded value/schema pair so every fuzz input exercises successful paths.
fn generated_value(selector: u8, bytes: &[u8], epoch: &StacksEpochId) -> (Value, TypeSignature) {
    let tail = bytes.get(1..).unwrap_or_default();
    match selector % 8 {
        0 => (Value::Int(unsigned(bytes) as i128), TypeSignature::IntType),
        1 => (Value::UInt(unsigned(bytes)), TypeSignature::UIntType),
        2 => (
            Value::Bool(bytes.first().is_some_and(|byte| byte & 1 == 1)),
            TypeSignature::BoolType,
        ),
        3 => (
            Value::buff_from(bytes.to_vec()).expect("fuzzer input respects the value-size bound"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                4_096u32.try_into().expect("constant buffer bound"),
            )),
        ),
        4 => {
            let expected = TypeSignature::new_option(TypeSignature::UIntType)
                .expect("constant optional schema");
            let value = if bytes.first().is_some_and(|byte| byte & 1 == 1) {
                Value::some(Value::UInt(unsigned(tail))).expect("constant optional value")
            } else {
                Value::none()
            };
            (value, expected)
        }
        5 => {
            let buffer_type = TypeSignature::SequenceType(SequenceSubtype::BufferType(
                4_096u32.try_into().expect("constant buffer bound"),
            ));
            let expected = TypeSignature::new_response(buffer_type, TypeSignature::IntType)
                .expect("constant response schema");
            let value = if bytes.first().is_some_and(|byte| byte & 1 == 1) {
                Value::okay(
                    Value::buff_from(tail.to_vec())
                        .expect("fuzzer input respects the value-size bound"),
                )
                .expect("constant response value")
            } else {
                Value::error(Value::Int(unsigned(tail) as i128)).expect("constant response value")
            };
            (value, expected)
        }
        6 => {
            let value = Value::Tuple(
                TupleData::from_data(vec![
                    (
                        ClarityName::from_literal("active"),
                        Value::Bool(bytes.first().is_some_and(|byte| byte & 1 == 1)),
                    ),
                    (
                        ClarityName::from_literal("amount"),
                        Value::UInt(unsigned(bytes)),
                    ),
                    (
                        ClarityName::from_literal("payload"),
                        Value::buff_from(bytes.to_vec())
                            .expect("fuzzer input respects the value-size bound"),
                    ),
                ])
                .expect("constant tuple value"),
            );
            let expected = TypeSignature::type_of(&value).expect("tuple has a concrete type");
            (value, expected)
        }
        _ => {
            let list_type =
                ListTypeData::new_list(TypeSignature::UIntType, 256).expect("constant list schema");
            let values = bytes
                .chunks(16)
                .take(256)
                .map(|chunk| Value::UInt(unsigned(chunk)))
                .collect();
            let value = Value::list_with_type(epoch, values, list_type.clone())
                .expect("generated list matches its schema");
            (
                value,
                TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
            )
        }
    }
}

/// Cross-check typed encoding, transcoding, reconstruction, and decoding for a generated value.
fn check_generated(selector: u8, bytes: &[u8], epoch: &StacksEpochId) {
    let (value, expected) = generated_value(selector, bytes, epoch);
    let consensus = value
        .serialize_to_vec()
        .expect("a generated value must serialize");
    let shape = ValueShape::from_value(&value).expect("a generated value must have a shape");
    let (packed, transcoded_shape) = PackedValue::transcode_consensus_with_shape(&consensus)
        .expect("a generated value must transcode");
    assert_eq!(transcoded_shape.as_bytes(), shape.as_bytes());
    assert_eq!(
        packed
            .as_packed_ref()
            .audit_reconstruction(shape.as_bytes())
            .expect("a generated value must reconstruct"),
        consensus
    );
    let decoded = packed
        .as_packed_ref()
        .decode(&expected, epoch)
        .expect("a generated value must decode");
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consensus_byte_len as usize, consensus.len());
    let admitted = AdmittedValue::new(value, &expected, epoch)
        .expect("a generated value must be admitted by its schema");
    let typed = admitted
        .encode_packed(
            u32::try_from(consensus.len()).expect("Clarity consensus value length is bounded"),
            ConsensusLengthValidation::Disabled,
        )
        .expect("a generated value must pack");
    assert_eq!(typed.as_bytes(), packed.as_bytes());
}

fuzz_target!(|input: &[u8]| {
    let decoded_seed = decode_seed(input);
    let data = decoded_seed.as_deref().unwrap_or(input);
    if data.len() < 4 {
        return;
    }

    let expected = schema(data[0]);
    let epochs = StacksEpochId::ALL;
    let epoch = &epochs[usize::from(data[1]) % epochs.len()];
    let body = &data[4..];
    let requested_split = usize::from(u16::from_le_bytes([data[2], data[3]]));
    let split = requested_split % (body.len() + 1);
    let (packed_bytes, descriptor) = body.split_at(split);

    let generated_body = &body[..body.len().min(4_096)];
    check_generated(data[0], generated_body, epoch);

    let _ = ValueShape::from_bytes(descriptor);

    if let Ok(decoded) =
        PackedValueRef::parse(packed_bytes).and_then(|packed| packed.decode(&expected, epoch))
    {
        let consensus = decoded
            .value
            .serialize_to_vec()
            .expect("a decoded packed value must serialize");
        assert_eq!(decoded.consensus_byte_len as usize, consensus.len());
        let admitted = AdmittedValue::new(decoded.value, &expected, epoch)
            .expect("a decoded packed value must remain admitted");
        let reencoded = admitted
            .encode_packed(
                u32::try_from(consensus.len()).expect("Clarity consensus value length is bounded"),
                ConsensusLengthValidation::Disabled,
            )
            .expect("a decoded packed value must re-encode");
        assert_eq!(reencoded.as_bytes(), packed_bytes);
    }

    if let Ok(consensus) = PackedValueRef::parse(packed_bytes)
        .and_then(|packed| packed.audit_reconstruction(descriptor))
    {
        let value = Value::try_deserialize_slice_exact_untyped(&consensus)
            .expect("reconstruction must produce one exact consensus value");
        assert_eq!(
            value
                .serialize_to_vec()
                .expect("a reconstructed value must serialize"),
            consensus
        );
        let (repacked, reshaped) = PackedValue::transcode_consensus_with_shape(&consensus)
            .expect("a reconstructed value must transcode");
        assert_eq!(repacked.as_bytes(), packed_bytes);
        assert_eq!(reshaped.as_bytes(), descriptor);
    }

    check_consensus(body, epoch);
});
