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

//! End-to-end tests for canonical packed Clarity value storage.

use std::assert_matches;

use proptest::prelude::*;
use stacks_common::types::StacksEpochId;

use crate::representations::{ClarityName, ContractName};
use crate::types::codec::packed::{
    AdmittedValue, ConsensusLengthValidation, PACKED_VALUE_HEADER_LEN, PackedValue,
    PackedValueError, PackedValueRef, VALUE_SHAPE_VERSION, ValueShape,
};
use crate::types::signatures::CallableSubtype;
use crate::types::{
    CallableData, ListTypeData, MAX_TYPE_DEPTH, MAX_VALUE_SIZE, PrincipalData,
    QualifiedContractIdentifier, SequenceSubtype, StandardPrincipalData, StringSubtype,
    TraitIdentifier, TupleData, TupleTypeSignature, TypeSignature, Value,
};

const EPOCH: StacksEpochId = StacksEpochId::Epoch40;

fn standard_principal(seed: u8) -> StandardPrincipalData {
    StandardPrincipalData::new(22, [seed; 20]).unwrap()
}

fn contract(seed: u8, name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(
        standard_principal(seed),
        ContractName::try_from(name.to_owned()).unwrap(),
    )
}

fn assert_canonical_round_trip(value: Value, expected: TypeSignature) -> Vec<u8> {
    let consensus = value.serialize_to_vec().unwrap();
    let consensus_len = u32::try_from(consensus.len()).unwrap();
    let admitted = AdmittedValue::new(value, &expected, &EPOCH).unwrap();
    let packed = admitted
        .encode_packed(consensus_len, ConsensusLengthValidation::Enabled)
        .unwrap();
    packed.as_packed_ref().validate(&expected, &EPOCH).unwrap();
    let decoded = packed.as_packed_ref().decode(&expected, &EPOCH).unwrap();
    assert_eq!(&decoded.value, admitted.value());
    assert_eq!(decoded.value.serialize_to_vec().unwrap(), consensus);
    assert_eq!(decoded.consensus_byte_len, consensus.len() as u32);
    let transcoded = PackedValue::transcode_consensus(&consensus).unwrap();
    assert_eq!(transcoded.as_bytes(), packed.as_bytes());
    let shape = ValueShape::from_value(admitted.value()).unwrap();
    assert_eq!(
        ValueShape::from_bytes(shape.as_bytes()).unwrap().as_bytes(),
        shape.as_bytes()
    );
    assert_eq!(
        packed
            .as_packed_ref()
            .audit_reconstruction(shape.as_bytes())
            .unwrap(),
        consensus
    );
    let (transcoded, transcoded_shape) =
        PackedValue::transcode_consensus_with_shape(&consensus).unwrap();
    assert_eq!(transcoded.as_bytes(), packed.as_bytes());
    assert_eq!(transcoded_shape, shape);
    packed.into_bytes()
}

#[test]
fn admitted_value_rejects_mismatched_schema_and_preserves_encoding() {
    let value = Value::UInt(42);
    assert_matches!(
        AdmittedValue::new(value.clone(), &TypeSignature::BoolType, &EPOCH),
        Err(PackedValueError::TypeMismatch)
    );

    let admitted = AdmittedValue::new(value.clone(), &TypeSignature::UIntType, &EPOCH).unwrap();
    assert_eq!(admitted.value(), &value);
    let consensus_len = u32::try_from(value.serialize_to_vec().unwrap().len()).unwrap();
    let encoded_admitted = admitted
        .encode_packed(consensus_len, ConsensusLengthValidation::Enabled)
        .unwrap();
    let encoded_trusted = admitted
        .encode_packed(consensus_len, ConsensusLengthValidation::Disabled)
        .unwrap();
    assert_eq!(encoded_admitted, encoded_trusted);
    let prefixed = admitted
        .encode_packed_with_prefix(
            &[0xa5, 0x5a],
            consensus_len,
            ConsensusLengthValidation::Disabled,
        )
        .unwrap();
    assert_eq!(&prefixed[..2], &[0xa5, 0x5a]);
    assert_eq!(&prefixed[2..], encoded_trusted.as_bytes());
}

#[test]
fn canonical_wire_format_has_stable_golden_vectors() {
    assert_eq!(
        assert_canonical_round_trip(Value::UInt(256), TypeSignature::UIntType),
        [17, 0, 0, 0, 1, 0]
    );

    let list_type = ListTypeData::new_list(TypeSignature::UIntType, 3).unwrap();
    let list = Value::list_with_type(
        &EPOCH,
        vec![Value::UInt(0), Value::UInt(255), Value::UInt(256)],
        list_type.clone(),
    )
    .unwrap();
    assert_eq!(
        assert_canonical_round_trip(
            list,
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
        ),
        [56, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 255, 1, 0]
    );

    let tuple = TupleData::from_data(vec![
        (ClarityName::from_literal("a"), Value::UInt(1)),
        (ClarityName::from_literal("b"), Value::Bool(true)),
    ])
    .unwrap();
    let tuple_type = TupleTypeSignature::try_from(vec![
        (ClarityName::from_literal("a"), TypeSignature::UIntType),
        (ClarityName::from_literal("b"), TypeSignature::BoolType),
    ])
    .unwrap();
    let tuple = Value::Tuple(tuple);
    assert_eq!(
        assert_canonical_round_trip(tuple.clone(), TypeSignature::TupleType(tuple_type)),
        [27, 0, 0, 0, 0, 0, 1, 2, 1, 1]
    );
    assert_eq!(
        ValueShape::from_value(&tuple).unwrap().as_bytes(),
        [VALUE_SHAPE_VERSION, 0x0c, 2, 1, b'a', 1, 1, b'b', 2]
    );
}

#[test]
fn value_shape_merges_active_list_branches() {
    let response_type = TypeSignature::new_response(
        TypeSignature::new_option(TypeSignature::UIntType).unwrap(),
        TypeSignature::BoolType,
    )
    .unwrap();
    let list_type = ListTypeData::new_list(response_type, 8).unwrap();
    let value = Value::list_with_type(
        &EPOCH,
        vec![
            Value::okay(Value::none()).unwrap(),
            Value::okay(Value::some(Value::UInt(17)).unwrap()).unwrap(),
            Value::error(Value::Bool(true)).unwrap(),
        ],
        list_type.clone(),
    )
    .unwrap();
    assert_canonical_round_trip(
        value,
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
    );
}

#[test]
fn homogeneous_list_reuses_one_active_shape() {
    let element = || {
        Value::Tuple(
            TupleData::from_data(vec![(ClarityName::from_literal("a"), Value::UInt(1))]).unwrap(),
        )
    };
    let value = Value::cons_list_unsanitized(vec![element(), element(), element()]).unwrap();
    assert_eq!(
        ValueShape::from_value(&value).unwrap().as_bytes(),
        [VALUE_SHAPE_VERSION, 0x0e, 0x0c, 1, 1, b'a', 1]
    );
}

#[test]
fn value_shape_rejects_noncanonical_and_mismatched_descriptors() {
    let empty_tuple_shape = [1, 0x0c, 0];
    assert!(ValueShape::from_bytes(&empty_tuple_shape).is_err());
    assert!(
        PackedValueRef::parse(&[5, 0, 0, 0])
            .and_then(|packed| packed.reconstruct_consensus(&empty_tuple_shape))
            .is_err()
    );

    // A merged response descriptor is valid within a heterogeneous list, but
    // is not canonical for one response value with only one active branch.
    let overgeneralized_response_shape = [VALUE_SHAPE_VERSION, 0x0b, 0x00, 0x04];
    let overgeneralized_response = [10, 0, 0, 0, 0, 64, 123, 123, 123];
    assert!(
        PackedValueRef::parse(&overgeneralized_response)
            .and_then(|packed| packed.reconstruct_consensus(&overgeneralized_response_shape))
            .is_ok()
    );
    assert!(
        PackedValueRef::parse(&overgeneralized_response)
            .and_then(|packed| packed.audit_reconstruction(&overgeneralized_response_shape))
            .is_err()
    );

    let value = Value::UInt(7);
    let consensus = value.serialize_to_vec().unwrap();
    let (packed, shape) = PackedValue::transcode_consensus_with_shape(&consensus).unwrap();

    let mut trailing = shape.as_bytes().to_vec();
    trailing.push(0);
    assert!(ValueShape::from_bytes(&trailing).is_err());
    assert!(
        packed
            .as_packed_ref()
            .reconstruct_consensus(&[1, 2])
            .is_err()
    );
    assert!(
        packed
            .as_packed_ref()
            .reconstruct_consensus(&[2, 1])
            .is_err()
    );

    let nonminimal_tuple_count = [1, 0x0c, 0x80, 0x00];
    assert!(ValueShape::from_bytes(&nonminimal_tuple_count).is_err());
}

#[test]
fn consensus_transcoder_rejects_noncanonical_tuple_order() {
    const TUPLE_HEADER_LEN: usize = 5;
    const ONE_CHAR_UINT_FIELD_LEN: usize = 19;

    let canonical = Value::Tuple(
        TupleData::from_data(vec![
            (ClarityName::from_literal("a"), Value::UInt(1)),
            (ClarityName::from_literal("b"), Value::UInt(2)),
        ])
        .unwrap(),
    )
    .serialize_to_vec()
    .unwrap();
    assert_eq!(
        canonical.len(),
        TUPLE_HEADER_LEN + 2 * ONE_CHAR_UINT_FIELD_LEN
    );

    let mut noncanonical = canonical[..TUPLE_HEADER_LEN].to_vec();
    noncanonical.extend_from_slice(&canonical[TUPLE_HEADER_LEN + ONE_CHAR_UINT_FIELD_LEN..]);
    noncanonical.extend_from_slice(
        &canonical[TUPLE_HEADER_LEN..TUPLE_HEADER_LEN + ONE_CHAR_UINT_FIELD_LEN],
    );
    assert!(Value::try_deserialize_slice_exact_untyped(&noncanonical).is_ok());
    assert!(PackedValue::transcode_consensus(&noncanonical).is_err());
    assert!(PackedValue::transcode_consensus_with_shape(&noncanonical).is_err());
}

#[test]
fn value_shape_enforces_depth_and_size_bounds() {
    const OPTIONAL_SOME_SHAPE: u8 = 0x08;
    const BOOL_SHAPE: u8 = 0x02;

    let mut too_deep = vec![VALUE_SHAPE_VERSION];
    too_deep.extend(std::iter::repeat_n(
        OPTIONAL_SOME_SHAPE,
        usize::from(MAX_TYPE_DEPTH) + 1,
    ));
    too_deep.push(BOOL_SHAPE);
    assert!(ValueShape::from_bytes(&too_deep).is_err());

    let oversized = vec![0; MAX_VALUE_SIZE as usize + 1];
    assert!(ValueShape::from_bytes(&oversized).is_err());
}

#[test]
fn value_shape_rejects_varuint_groups_that_exceed_usize() {
    const TUPLE_SHAPE: u8 = 0x0c;
    const BOOL_SHAPE: u8 = 0x02;

    let continuation_groups = (usize::BITS - 1) / 7;
    let final_shift = continuation_groups * 7;
    let overflowing_group = 1u8 << (usize::BITS - final_shift);
    let mut overflowing_count = vec![VALUE_SHAPE_VERSION, TUPLE_SHAPE, 0x81];
    overflowing_count.extend(std::iter::repeat_n(
        0x80,
        usize::try_from(continuation_groups - 1).unwrap(),
    ));
    overflowing_count.extend([overflowing_group, 1, b'a', BOOL_SHAPE]);

    assert_matches!(
        ValueShape::from_bytes(&overflowing_count),
        Err(PackedValueError::SizeOverflow)
    );
}

#[test]
fn canonical_storage_bytes_are_epoch_independent() {
    let value = Value::Tuple(
        TupleData::from_data(vec![
            (ClarityName::from_literal("active"), Value::Bool(true)),
            (ClarityName::from_literal("amount"), Value::UInt(42)),
        ])
        .unwrap(),
    );
    let expected = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![
            (ClarityName::from_literal("active"), TypeSignature::BoolType),
            (ClarityName::from_literal("amount"), TypeSignature::UIntType),
        ])
        .unwrap(),
    );
    let consensus_len = u32::try_from(value.serialize_to_vec().unwrap().len()).unwrap();
    let mut reference = None;
    for epoch in StacksEpochId::ALL {
        let admitted = AdmittedValue::new(value.clone(), &expected, epoch).unwrap();
        let packed = admitted
            .encode_packed(consensus_len, ConsensusLengthValidation::Enabled)
            .unwrap();
        let decoded = packed.as_packed_ref().decode(&expected, epoch).unwrap();
        assert_eq!(decoded.value, value);
        match &reference {
            Some(bytes) => assert_eq!(packed.as_bytes(), bytes),
            None => reference = Some(packed.into_bytes()),
        }
    }
}

#[test]
fn canonical_storage_preserves_historically_sanitized_tuples() {
    let historical = Value::Tuple(
        TupleData::from_data(vec![
            (ClarityName::from_literal("active"), Value::Bool(true)),
            (ClarityName::from_literal("obsolete"), Value::UInt(42)),
        ])
        .unwrap(),
    )
    .serialize_to_vec()
    .unwrap();
    let expected = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![(
            ClarityName::from_literal("active"),
            TypeSignature::BoolType,
        )])
        .unwrap(),
    );

    let sanitized = Value::try_deserialize_bytes_at_epoch(&historical, &expected, &EPOCH).unwrap();
    let sanitized_consensus = sanitized.serialize_to_vec().unwrap();
    assert_ne!(sanitized_consensus, historical);

    let strict =
        Value::try_deserialize_bytes_at_epoch(&historical, &expected, &StacksEpochId::Epoch41)
            .unwrap();
    assert_eq!(strict, sanitized);
    assert_canonical_round_trip(sanitized, expected);
}

#[test]
fn schema_free_reconstruction_preserves_unsanitized_list_elements() {
    let narrow = Value::Tuple(
        TupleData::from_data(vec![(ClarityName::from_literal("a"), Value::UInt(1))]).unwrap(),
    );
    let wide = Value::Tuple(
        TupleData::from_data(vec![
            (ClarityName::from_literal("a"), Value::UInt(1)),
            (ClarityName::from_literal("b"), Value::Bool(true)),
        ])
        .unwrap(),
    );
    let historical = Value::cons_list_unsanitized(vec![narrow, wide]).unwrap();
    let consensus = historical.serialize_to_vec().unwrap();

    let (packed, shape) = PackedValue::transcode_consensus_with_shape(&consensus).unwrap();
    assert_eq!(shape.as_bytes()[..2], [VALUE_SHAPE_VERSION, 0x0f]);
    assert_eq!(
        packed
            .as_packed_ref()
            .audit_reconstruction(shape.as_bytes())
            .unwrap(),
        consensus
    );

    // Per-element framing is non-canonical when every element admits one shared shape.
    assert!(ValueShape::from_bytes(&[VALUE_SHAPE_VERSION, 0x0f, 2, 1, 1]).is_err());
}

#[test]
fn canonical_round_trips_all_runtime_shapes() {
    assert_canonical_round_trip(Value::Int(-129), TypeSignature::IntType);
    assert_canonical_round_trip(Value::UInt(65_536), TypeSignature::UIntType);
    assert_canonical_round_trip(Value::Bool(true), TypeSignature::BoolType);

    let buffer_type =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(32u32.try_into().unwrap()));
    assert_canonical_round_trip(Value::buff_from(vec![1, 2, 3]).unwrap(), buffer_type);

    let optional = TypeSignature::new_option(TypeSignature::UIntType).unwrap();
    assert_canonical_round_trip(Value::none(), optional.clone());
    assert_canonical_round_trip(Value::some(Value::UInt(7)).unwrap(), optional);

    let response =
        TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::UIntType).unwrap();
    assert_canonical_round_trip(Value::okay(Value::Bool(true)).unwrap(), response.clone());
    assert_canonical_round_trip(Value::error(Value::UInt(9)).unwrap(), response);

    let tuple = TupleData::from_data(vec![
        (ClarityName::from_literal("active"), Value::Bool(true)),
        (ClarityName::from_literal("amount"), Value::UInt(42)),
    ])
    .unwrap();
    let tuple_type = TupleTypeSignature::try_from(vec![
        (ClarityName::from_literal("active"), TypeSignature::BoolType),
        (ClarityName::from_literal("amount"), TypeSignature::UIntType),
    ])
    .unwrap();
    assert_canonical_round_trip(Value::Tuple(tuple), TypeSignature::TupleType(tuple_type));

    let list_type = ListTypeData::new_list(TypeSignature::UIntType, 8).unwrap();
    let list = Value::list_with_type(
        &EPOCH,
        vec![Value::UInt(0), Value::UInt(255), Value::UInt(256)],
        list_type.clone(),
    )
    .unwrap();
    assert_canonical_round_trip(
        list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
    );

    let int_list_type = ListTypeData::new_list(TypeSignature::IntType, 4).unwrap();
    let int_list = Value::list_with_type(
        &EPOCH,
        vec![Value::Int(i128::MIN), Value::Int(0), Value::Int(i128::MAX)],
        int_list_type.clone(),
    )
    .unwrap();
    assert_canonical_round_trip(
        int_list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(int_list_type)),
    );

    let bool_list_type = ListTypeData::new_list(TypeSignature::BoolType, 9).unwrap();
    let bool_list = Value::list_with_type(
        &EPOCH,
        (0..9).map(|index| Value::Bool(index % 2 == 0)).collect(),
        bool_list_type.clone(),
    )
    .unwrap();
    assert_canonical_round_trip(
        bool_list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(bool_list_type)),
    );

    let ascii = Value::string_ascii_from_bytes(b"packed-codec".to_vec()).unwrap();
    assert_canonical_round_trip(
        ascii,
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            32u32.try_into().unwrap(),
        ))),
    );
    let utf8 = Value::string_utf8_from_bytes("Hej, 世界".as_bytes().to_vec()).unwrap();
    assert_canonical_round_trip(
        utf8,
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
            32u32.try_into().unwrap(),
        ))),
    );

    assert_canonical_round_trip(
        Value::Principal(PrincipalData::Standard(standard_principal(1))),
        TypeSignature::PrincipalType,
    );
    assert_canonical_round_trip(
        Value::Principal(PrincipalData::Contract(contract(2, "pool"))),
        TypeSignature::PrincipalType,
    );

    let trait_id = TraitIdentifier::new(
        standard_principal(4),
        ContractName::from_literal("trait-contract"),
        ClarityName::from_literal("transferable"),
    );
    let callable = Value::CallableContract(CallableData {
        contract_identifier: contract(5, "implementation"),
        trait_identifier: Some(Box::new(trait_id.clone())),
    });
    let callable_bytes = assert_canonical_round_trip(
        callable.clone(),
        TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone())),
    );
    assert_eq!(
        callable_bytes,
        assert_canonical_round_trip(callable, TypeSignature::TraitReferenceType(trait_id))
    );
}

#[test]
fn canonical_bytes_ignore_bounds_inactive_branches_and_callable_view() {
    let value = Value::buff_from(vec![1, 2, 3]).unwrap();
    let short = TypeSignature::SequenceType(SequenceSubtype::BufferType(3u32.try_into().unwrap()));
    let long =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(1024u32.try_into().unwrap()));
    let short_bytes = assert_canonical_round_trip(value.clone(), short);
    let long_bytes = assert_canonical_round_trip(value, long);
    assert_eq!(short_bytes, long_bytes);

    let value = Value::okay(Value::Bool(true)).unwrap();
    let narrow =
        TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::BoolType).unwrap();
    let wide = TypeSignature::new_response(
        TypeSignature::BoolType,
        TypeSignature::SequenceType(SequenceSubtype::BufferType(1024u32.try_into().unwrap())),
    )
    .unwrap();
    assert_eq!(
        assert_canonical_round_trip(value.clone(), narrow),
        assert_canonical_round_trip(value, wide)
    );

    let contract = contract(9, "canonical-callable");
    let principal = Value::Principal(PrincipalData::Contract(contract.clone()));
    let callable = Value::CallableContract(CallableData {
        contract_identifier: contract.clone(),
        trait_identifier: None,
    });
    let principal_bytes = assert_canonical_round_trip(principal, TypeSignature::PrincipalType);
    let callable_bytes = assert_canonical_round_trip(
        callable,
        TypeSignature::CallableType(CallableSubtype::Principal(contract)),
    );
    assert_eq!(principal_bytes, callable_bytes);
}

#[test]
fn canonical_empty_lists_and_parent_framing_are_schema_independent() {
    let bool_list = ListTypeData::new_list(TypeSignature::BoolType, 8).unwrap();
    let uint_list = ListTypeData::new_list(TypeSignature::UIntType, 1024).unwrap();
    let bool_value = Value::list_with_type(&EPOCH, vec![], bool_list.clone()).unwrap();
    let uint_value = Value::list_with_type(&EPOCH, vec![], uint_list.clone()).unwrap();
    assert_eq!(
        bool_value.serialize_to_vec().unwrap(),
        uint_value.serialize_to_vec().unwrap()
    );
    assert_eq!(
        assert_canonical_round_trip(
            bool_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(bool_list)),
        ),
        assert_canonical_round_trip(
            uint_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(uint_list)),
        )
    );

    let value = Value::Tuple(
        TupleData::from_data(vec![
            (
                ClarityName::from_literal("a"),
                Value::okay(Value::Bool(true)).unwrap(),
            ),
            (ClarityName::from_literal("b"), Value::Bool(true)),
        ])
        .unwrap(),
    );
    let narrow = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from_literal("a"),
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::BoolType).unwrap(),
        ),
        (ClarityName::from_literal("b"), TypeSignature::BoolType),
    ])
    .unwrap();
    let wide = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from_literal("a"),
            TypeSignature::new_response(
                TypeSignature::BoolType,
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    1024u32.try_into().unwrap(),
                )),
            )
            .unwrap(),
        ),
        (ClarityName::from_literal("b"), TypeSignature::BoolType),
    ])
    .unwrap();
    assert_eq!(
        assert_canonical_round_trip(value.clone(), TypeSignature::TupleType(narrow)),
        assert_canonical_round_trip(value, TypeSignature::TupleType(wide))
    );
}

#[test]
fn canonical_zero_integers_use_one_byte_scalars_and_lanes() {
    let uint_zero = assert_canonical_round_trip(Value::UInt(0), TypeSignature::UIntType);
    assert_eq!(uint_zero, [17, 0, 0, 0, 0]);

    let int_zero = assert_canonical_round_trip(Value::Int(0), TypeSignature::IntType);
    assert_eq!(int_zero, [17, 0, 0, 0, 0]);

    for (element_type, values) in [
        (TypeSignature::UIntType, vec![Value::UInt(0); 2]),
        (TypeSignature::IntType, vec![Value::Int(0); 2]),
    ] {
        let list_type = ListTypeData::new_list(element_type, 2).unwrap();
        let value = Value::list_with_type(&EPOCH, values, list_type.clone()).unwrap();
        let expected = TypeSignature::SequenceType(SequenceSubtype::ListType(list_type));
        let packed = assert_canonical_round_trip(value, expected);
        assert_eq!(packed, [39, 0, 0, 0, 2, 0, 0, 0, 0, 0]);
    }
}

#[test]
fn canonical_decoder_rejects_empty_and_non_minimal_zero_integers() {
    let empty_scalar = 17u32.to_le_bytes();
    for expected in [TypeSignature::UIntType, TypeSignature::IntType] {
        assert!(
            PackedValueRef::parse(&empty_scalar)
                .and_then(|packed| packed.decode(&expected, &EPOCH))
                .is_err()
        );

        let mut wide_scalar = empty_scalar.to_vec();
        wide_scalar.extend_from_slice(&[0, 0]);
        assert!(
            PackedValueRef::parse(&wide_scalar)
                .and_then(|packed| packed.decode(&expected, &EPOCH))
                .is_err()
        );

        let list_type = ListTypeData::new_list(expected, 2).unwrap();
        let expected = TypeSignature::SequenceType(SequenceSubtype::ListType(list_type));
        let mut wide_lane = 39u32.to_le_bytes().to_vec();
        wide_lane.extend_from_slice(&2u32.to_le_bytes());
        wide_lane.extend_from_slice(&[0, 0, 0, 0]);
        assert!(
            PackedValueRef::parse(&wide_lane)
                .and_then(|packed| packed.decode(&expected, &EPOCH))
                .is_err()
        );
    }
}

#[test]
fn canonical_transcoder_requires_exact_consensus_consumption() {
    let mut consensus = Value::UInt(1).serialize_to_vec().unwrap();
    consensus.push(0);
    assert!(PackedValue::transcode_consensus(&consensus).is_err());
}

#[test]
fn admitted_encoding_validates_supplied_consensus_length() {
    let value = Value::some(Value::UInt(7)).unwrap();
    let expected = TypeSignature::new_option(TypeSignature::UIntType).unwrap();
    let consensus_len = value.serialize_to_vec().unwrap().len() as u32;
    let admitted = AdmittedValue::new(value, &expected, &EPOCH).unwrap();
    let checked = admitted
        .encode_packed(consensus_len, ConsensusLengthValidation::Enabled)
        .unwrap();
    let trusted = admitted
        .encode_packed(consensus_len, ConsensusLengthValidation::Disabled)
        .unwrap();
    assert_eq!(checked, trusted);

    assert!(
        admitted
            .encode_packed(consensus_len - 1, ConsensusLengthValidation::Enabled,)
            .is_err()
    );
}

#[test]
fn canonical_decoder_rejects_header_and_body_corruption() {
    let value = Value::some(Value::UInt(7)).unwrap();
    let expected = TypeSignature::new_option(TypeSignature::UIntType).unwrap();
    let packed = assert_canonical_round_trip(value, expected.clone());

    let mut wrong_length = packed.clone();
    wrong_length[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        PackedValueRef::parse(&wrong_length)
            .and_then(|packed| packed.decode(&expected, &EPOCH))
            .is_err()
    );

    let mut invalid_tag = packed.clone();
    invalid_tag[PACKED_VALUE_HEADER_LEN] = 2;
    assert!(
        PackedValueRef::parse(&invalid_tag)
            .and_then(|packed| packed.decode(&expected, &EPOCH))
            .is_err()
    );

    assert!(
        PackedValueRef::parse(&packed[..packed.len() - 1])
            .and_then(|packed| packed.decode(&expected, &EPOCH))
            .is_err()
    );
}

proptest! {
    #[test]
    fn property_round_trips_scalar_and_lane_values(
        signed in any::<i128>(),
        unsigned in any::<u128>(),
        signed_lane in prop::collection::vec(any::<i128>(), 0..64),
        unsigned_lane in prop::collection::vec(any::<u128>(), 0..64),
        bool_lane in prop::collection::vec(any::<bool>(), 0..128),
    ) {
        assert_canonical_round_trip(Value::Int(signed), TypeSignature::IntType);
        assert_canonical_round_trip(Value::UInt(unsigned), TypeSignature::UIntType);

        let signed_type = ListTypeData::new_list(TypeSignature::IntType, 64).unwrap();
        let signed_value = Value::list_with_type(
            &EPOCH,
            signed_lane.into_iter().map(Value::Int).collect(),
            signed_type.clone(),
        ).unwrap();
        assert_canonical_round_trip(
            signed_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(signed_type)),
        );

        let unsigned_type = ListTypeData::new_list(TypeSignature::UIntType, 64).unwrap();
        let unsigned_value = Value::list_with_type(
            &EPOCH,
            unsigned_lane.into_iter().map(Value::UInt).collect(),
            unsigned_type.clone(),
        ).unwrap();
        assert_canonical_round_trip(
            unsigned_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(unsigned_type)),
        );

        let bool_type = ListTypeData::new_list(TypeSignature::BoolType, 128).unwrap();
        let bool_value = Value::list_with_type(
            &EPOCH,
            bool_lane.into_iter().map(Value::Bool).collect(),
            bool_type.clone(),
        ).unwrap();
        assert_canonical_round_trip(
            bool_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(bool_type)),
        );
    }


    #[test]
    fn arbitrary_packed_and_shape_bytes_fail_closed(
        packed in prop::collection::vec(any::<u8>(), 0..512),
        descriptor in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        if let Ok(consensus) = PackedValueRef::parse(&packed)
            .and_then(|packed| packed.audit_reconstruction(&descriptor))
        {
            let value = Value::try_deserialize_slice_exact_untyped(&consensus).unwrap();
            let transcoded = PackedValue::transcode_consensus(&consensus).unwrap();
            prop_assert_eq!(transcoded.as_bytes(), packed.as_slice());
            prop_assert_eq!(value.serialize_to_vec().unwrap(), consensus);
        }
    }
}
