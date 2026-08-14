// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::BTreeMap;

use proptest::prelude::*;
use stacks_common::types::StacksEpochId;

use crate::representations::{ClarityName, ContractName};
use crate::types::signatures::CallableSubtype;
use crate::types::storage::{
    PACKED_VALUE_HEADER_LEN, decode_packed_value, encode_packed_value, packed_int_width,
    packed_uint_width, validate_packed_value,
};
use crate::types::{
    CallableData, ListTypeData, PrincipalData, QualifiedContractIdentifier, SequenceSubtype,
    StandardPrincipalData, StringSubtype, TraitIdentifier, TupleData, TupleTypeSignature,
    TypeSignature, Value,
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

fn assert_round_trip(value: Value, expected: TypeSignature) -> Vec<u8> {
    let consensus = value.serialize_to_vec().unwrap();
    let packed = encode_packed_value(&value, &expected, &EPOCH).unwrap();
    assert_eq!(packed.consensus_byte_len(), consensus.len() as u32);
    let validated = validate_packed_value(packed.as_bytes(), &expected).unwrap();
    assert_eq!(validated.consensus_byte_len(), consensus.len() as u32);
    let decoded = decode_packed_value(packed.as_bytes(), &expected, &EPOCH).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.value.serialize_to_vec().unwrap(), consensus);
    packed.into_bytes()
}

#[test]
fn round_trips_integer_boundaries() {
    let mut signed = vec![i128::MIN, -1, 0, 1, i128::MAX];
    for width in 1..16 {
        let sign_bit = 8 * width - 1;
        let minimum = -(1i128 << sign_bit);
        let maximum = (1i128 << sign_bit) - 1;
        signed.extend([minimum - 1, minimum, maximum, maximum + 1]);
        assert_eq!(packed_int_width(minimum), width);
        assert_eq!(packed_int_width(maximum), width);
        assert_eq!(packed_int_width(minimum - 1), width + 1);
        assert_eq!(packed_int_width(maximum + 1), width + 1);
    }
    for value in signed {
        let bytes = assert_round_trip(Value::Int(value), TypeSignature::IntType);
        assert!(bytes.len() <= PACKED_VALUE_HEADER_LEN + 16);
    }

    let mut unsigned = vec![0, 1, u128::MAX];
    for width in 1..16 {
        let next_width = 1u128 << (8 * width);
        unsigned.extend([next_width - 1, next_width]);
        assert_eq!(packed_uint_width(next_width - 1), width);
        assert_eq!(packed_uint_width(next_width), width + 1);
    }
    for value in unsigned {
        let bytes = assert_round_trip(Value::UInt(value), TypeSignature::UIntType);
        assert!(bytes.len() <= PACKED_VALUE_HEADER_LEN + 16);
    }
}

#[test]
fn round_trips_integer_lane_extremes() {
    let uint_type = ListTypeData::new_list(TypeSignature::UIntType, 4).unwrap();
    for values in [
        vec![],
        vec![Value::UInt(0); 4],
        vec![Value::UInt(0), Value::UInt(256), Value::UInt(u128::MAX)],
    ] {
        let value = Value::list_with_type(&EPOCH, values, uint_type.clone()).unwrap();
        assert_round_trip(
            value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(uint_type.clone())),
        );
    }

    let int_type = ListTypeData::new_list(TypeSignature::IntType, 4).unwrap();
    for values in [
        vec![],
        vec![Value::Int(0); 4],
        vec![Value::Int(i128::MIN), Value::Int(0), Value::Int(i128::MAX)],
    ] {
        let value = Value::list_with_type(&EPOCH, values, int_type.clone()).unwrap();
        assert_round_trip(
            value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(int_type.clone())),
        );
    }
}

#[test]
fn round_trips_scalars_sequences_and_principals() {
    assert_round_trip(Value::Bool(false), TypeSignature::BoolType);
    assert_round_trip(Value::Bool(true), TypeSignature::BoolType);

    let buffer = Value::buff_from((0..=255).collect()).unwrap();
    let buffer_type =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(512u32.try_into().unwrap()));
    assert_round_trip(buffer, buffer_type);

    let ascii = Value::string_ascii_from_bytes(b"borrow-compatible".to_vec()).unwrap();
    let ascii_type = TypeSignature::SequenceType(SequenceSubtype::StringType(
        StringSubtype::ASCII(64u32.try_into().unwrap()),
    ));
    assert_round_trip(ascii, ascii_type);

    let utf8 = Value::string_utf8_from_bytes("Hej, 世界 👋".as_bytes().to_vec()).unwrap();
    let utf8_type = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
        64u32.try_into().unwrap(),
    )));
    assert_round_trip(utf8, utf8_type);

    assert_round_trip(
        Value::Principal(PrincipalData::Standard(standard_principal(1))),
        TypeSignature::PrincipalType,
    );
    assert_round_trip(
        Value::Principal(PrincipalData::Contract(contract(2, "pool"))),
        TypeSignature::PrincipalType,
    );
}

#[test]
fn round_trips_wrappers_tuples_and_lists() {
    assert_round_trip(
        Value::none(),
        TypeSignature::new_option(TypeSignature::UIntType).unwrap(),
    );
    assert_round_trip(
        Value::some(Value::UInt(123)).unwrap(),
        TypeSignature::new_option(TypeSignature::UIntType).unwrap(),
    );
    assert_round_trip(
        Value::okay(Value::Bool(true)).unwrap(),
        TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::UIntType).unwrap(),
    );
    assert_round_trip(
        Value::error(Value::UInt(9)).unwrap(),
        TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::UIntType).unwrap(),
    );

    let tuple = TupleData::from_data(vec![
        (ClarityName::from_literal("active"), Value::Bool(true)),
        (
            ClarityName::from_literal("memo"),
            Value::string_ascii_from_bytes(b"hello".to_vec()).unwrap(),
        ),
        (ClarityName::from_literal("sequence"), Value::UInt(255)),
    ])
    .unwrap();
    let mut type_map = BTreeMap::new();
    type_map.insert(ClarityName::from_literal("active"), TypeSignature::BoolType);
    type_map.insert(
        ClarityName::from_literal("memo"),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            32u32.try_into().unwrap(),
        ))),
    );
    type_map.insert(
        ClarityName::from_literal("sequence"),
        TypeSignature::UIntType,
    );
    let tuple_type = TupleTypeSignature::try_from(type_map).unwrap();
    assert_round_trip(Value::Tuple(tuple), TypeSignature::TupleType(tuple_type));

    let uints = vec![0u128, 1, 255, 256, u16::MAX as u128]
        .into_iter()
        .map(Value::UInt)
        .collect();
    let uint_list_type = ListTypeData::new_list(TypeSignature::UIntType, 10).unwrap();
    let uint_list = Value::list_with_type(&EPOCH, uints, uint_list_type.clone()).unwrap();
    assert_round_trip(
        uint_list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(uint_list_type)),
    );

    let ints = vec![i128::MIN, -129, -1, 0, 128, i128::MAX]
        .into_iter()
        .map(Value::Int)
        .collect();
    let int_list_type = ListTypeData::new_list(TypeSignature::IntType, 10).unwrap();
    let int_list = Value::list_with_type(&EPOCH, ints, int_list_type.clone()).unwrap();
    assert_round_trip(
        int_list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(int_list_type)),
    );

    let bools = (0..73).map(|index| Value::Bool(index % 3 == 0)).collect();
    let bool_list_type = ListTypeData::new_list(TypeSignature::BoolType, 100).unwrap();
    let bool_list = Value::list_with_type(&EPOCH, bools, bool_list_type.clone()).unwrap();
    assert_round_trip(
        bool_list,
        TypeSignature::SequenceType(SequenceSubtype::ListType(bool_list_type)),
    );
}

#[test]
fn round_trips_callable_variants() {
    let known_contract = contract(3, "known");
    let principal_value = Value::CallableContract(CallableData {
        contract_identifier: known_contract.clone(),
        trait_identifier: None,
    });
    let packed = assert_round_trip(
        principal_value,
        TypeSignature::CallableType(CallableSubtype::Principal(known_contract)),
    );
    assert_eq!(packed.len(), PACKED_VALUE_HEADER_LEN);

    let trait_id = TraitIdentifier::new(
        standard_principal(4),
        ContractName::from_literal("trait-contract"),
        ClarityName::from_literal("transferable"),
    );
    let trait_value = Value::CallableContract(CallableData {
        contract_identifier: contract(5, "implementation"),
        trait_identifier: Some(Box::new(trait_id.clone())),
    });
    assert_round_trip(
        trait_value.clone(),
        TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone())),
    );
    assert_round_trip(trait_value, TypeSignature::TraitReferenceType(trait_id));
}

#[test]
fn caller_schema_controls_schema_free_records() {
    let short = TypeSignature::SequenceType(SequenceSubtype::BufferType(16u32.try_into().unwrap()));
    let long = TypeSignature::SequenceType(SequenceSubtype::BufferType(32u32.try_into().unwrap()));
    let value = Value::buff_from(vec![1, 2, 3]).unwrap();
    let packed = encode_packed_value(&value, &short, &EPOCH).unwrap();
    assert_eq!(
        decode_packed_value(packed.as_bytes(), &long, &EPOCH)
            .unwrap()
            .value,
        value
    );
    let too_short =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(2u32.try_into().unwrap()));
    assert!(decode_packed_value(packed.as_bytes(), &too_short, &EPOCH).is_err());

    let left = TupleTypeSignature::try_from(vec![(
        ClarityName::from_literal("left"),
        TypeSignature::UIntType,
    )])
    .unwrap();
    let right = TupleTypeSignature::try_from(vec![(
        ClarityName::from_literal("right"),
        TypeSignature::UIntType,
    )])
    .unwrap();
    let value = Value::Tuple(
        TupleData::from_data(vec![(ClarityName::from_literal("left"), Value::UInt(1))]).unwrap(),
    );
    let packed = encode_packed_value(&value, &TypeSignature::TupleType(left), &EPOCH).unwrap();
    let decoded =
        decode_packed_value(packed.as_bytes(), &TypeSignature::TupleType(right), &EPOCH).unwrap();
    assert_eq!(
        decoded.value,
        Value::Tuple(
            TupleData::from_data(vec![(ClarityName::from_literal("right"), Value::UInt(1),)])
                .unwrap()
        )
    );
}

#[test]
fn rejects_corrupt_headers_scalars_lanes_and_directories() {
    let expected = TypeSignature::UIntType;
    let mut packed = assert_round_trip(Value::UInt(1), expected.clone());
    packed[0] ^= 1;
    assert!(validate_packed_value(&packed, &expected).is_err());

    let mut packed = assert_round_trip(Value::UInt(1), expected.clone());
    packed[PACKED_VALUE_HEADER_LEN] = 0;
    assert!(validate_packed_value(&packed, &expected).is_err());
    assert!(decode_packed_value(&packed, &expected, &EPOCH).is_err());

    let list_type = ListTypeData::new_list(TypeSignature::UIntType, 10).unwrap();
    let expected = TypeSignature::SequenceType(SequenceSubtype::ListType(list_type.clone()));
    let value =
        Value::list_with_type(&EPOCH, vec![Value::UInt(1), Value::UInt(256)], list_type).unwrap();
    let mut packed = assert_round_trip(value, expected.clone());
    packed.pop();
    assert!(validate_packed_value(&packed, &expected).is_err());
    assert!(decode_packed_value(&packed, &expected, &EPOCH).is_err());

    let item_type =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(16u32.try_into().unwrap()));
    let list_type = ListTypeData::new_list(item_type.clone(), 4).unwrap();
    let expected = TypeSignature::SequenceType(SequenceSubtype::ListType(list_type.clone()));
    let value = Value::list_with_type(
        &EPOCH,
        vec![
            Value::buff_from(vec![1]).unwrap(),
            Value::buff_from(vec![2, 3]).unwrap(),
        ],
        list_type,
    )
    .unwrap();
    let mut packed = assert_round_trip(value, expected.clone());
    packed[PACKED_VALUE_HEADER_LEN + 4] = 9;
    assert!(validate_packed_value(&packed, &expected).is_err());
    assert!(decode_packed_value(&packed, &expected, &EPOCH).is_err());
}

#[test]
fn logical_length_matches_consensus_for_large_integer_list() {
    let list_type = ListTypeData::new_list(TypeSignature::UIntType, 1001).unwrap();
    let values = (0..1001).map(|value| Value::UInt(value as u128)).collect();
    let value = Value::list_with_type(&EPOCH, values, list_type.clone()).unwrap();
    let consensus_len = value.serialize_to_vec().unwrap().len();
    let packed = encode_packed_value(
        &value,
        &TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
        &EPOCH,
    )
    .unwrap();
    assert_eq!(consensus_len, 17_022);
    assert_eq!(packed.as_bytes().len(), 2_010);
    assert_eq!(PACKED_VALUE_HEADER_LEN, 4);
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
        assert_round_trip(Value::Int(signed), TypeSignature::IntType);
        assert_round_trip(Value::UInt(unsigned), TypeSignature::UIntType);

        let signed_type = ListTypeData::new_list(TypeSignature::IntType, 64).unwrap();
        let signed_value = Value::list_with_type(
            &EPOCH,
            signed_lane.into_iter().map(Value::Int).collect(),
            signed_type.clone(),
        ).unwrap();
        assert_round_trip(
            signed_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(signed_type)),
        );

        let unsigned_type = ListTypeData::new_list(TypeSignature::UIntType, 64).unwrap();
        let unsigned_value = Value::list_with_type(
            &EPOCH,
            unsigned_lane.into_iter().map(Value::UInt).collect(),
            unsigned_type.clone(),
        ).unwrap();
        assert_round_trip(
            unsigned_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(unsigned_type)),
        );

        let bool_type = ListTypeData::new_list(TypeSignature::BoolType, 128).unwrap();
        let bool_value = Value::list_with_type(
            &EPOCH,
            bool_lane.into_iter().map(Value::Bool).collect(),
            bool_type.clone(),
        ).unwrap();
        assert_round_trip(
            bool_value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(bool_type)),
        );
    }

    #[test]
    fn arbitrary_bytes_never_escape_structural_validation(
        body in prop::collection::vec(any::<u8>(), 0..512),
        logical_len in any::<u32>(),
        schema_selector in 0u8..5,
    ) {
        let expected = match schema_selector {
            0 => TypeSignature::IntType,
            1 => TypeSignature::UIntType,
            2 => TypeSignature::BoolType,
            3 => TypeSignature::new_option(TypeSignature::UIntType).unwrap(),
            _ => TypeSignature::SequenceType(SequenceSubtype::BufferType(
                256u32.try_into().unwrap(),
            )),
        };
        let mut bytes = Vec::with_capacity(PACKED_VALUE_HEADER_LEN + body.len());
        bytes.extend_from_slice(&logical_len.to_le_bytes());
        bytes.extend_from_slice(&body);
        if let Ok(validated) = validate_packed_value(&bytes, &expected) {
            let decoded = validated.to_owned_value(&EPOCH).unwrap();
            let reencoded = encode_packed_value(&decoded, &expected, &EPOCH).unwrap();
            prop_assert_eq!(reencoded.as_bytes(), bytes.as_slice());
        }
    }
}
