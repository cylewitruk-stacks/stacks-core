// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Rusqlite adapters for persistence-agnostic Stacks domain types.
//!
//! [`SqlRef`] wraps a borrowed value for query parameters. [`SqlValue`] owns a
//! value decoded from a row. Wrappers should exist only at the persistence
//! boundary; repository APIs should continue to accept and return domain types.

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, Value, ValueRef};
use stacks_crypto::vrf::VRFProof;
use stacks_primitives::vrf::VRFSeed;
use stacks_primitives::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, Hash160, Sha512Trunc256Sum, SortitionId,
    StacksAddress, StacksBlockId, TrieHash, Txid,
};

/// Empty rusqlite parameter list retained as a convenience for storage code.
pub const NO_PARAMS: &[&dyn ToSql] = &[];

mod private {
    pub trait Sealed {}
}

/// A borrowed domain value adapted for use as a rusqlite query parameter.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SqlRef<'a, T>(&'a T);

impl<'a, T> SqlRef<'a, T> {
    pub const fn new(value: &'a T) -> Self {
        Self(value)
    }

    pub const fn as_inner(&self) -> &'a T {
        self.0
    }
}

impl<'a, T> From<&'a T> for SqlRef<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::new(value)
    }
}

/// An owned domain value adapted for rusqlite row decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct SqlValue<T>(T);

impl<T> SqlValue<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    pub const fn as_inner(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for SqlValue<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// A Stacks domain type with a canonical SQLite scalar representation.
///
/// This trait is sealed so representations remain controlled by this adapter
/// crate and cannot silently diverge between consumers.
pub trait SqliteScalar: private::Sealed + Sized {
    #[doc(hidden)]
    fn encode_sqlite(&self) -> String;

    #[doc(hidden)]
    fn decode_sqlite(value: &str) -> FromSqlResult<Self>;
}

impl<T: SqliteScalar> ToSql for SqlRef<'_, T> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Text(self.0.encode_sqlite())))
    }
}

impl<T: SqliteScalar> ToSql for SqlValue<T> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Text(self.0.encode_sqlite())))
    }
}

impl<T: SqliteScalar> FromSql for SqlValue<T> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        T::decode_sqlite(value.as_str()?).map(Self)
    }
}

/// Internal autoref-dispatch used by [`domain_params!`].
#[doc(hidden)]
pub trait AdaptSqlParam {
    fn adapt_sql_param(self) -> DeferredSqlParam;
}

#[doc(hidden)]
pub struct SqlParamDispatch<T>(T);

impl<T> SqlParamDispatch<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

#[doc(hidden)]
pub trait DomainSqlParam {
    fn encode_domain_param(&self) -> String;
}

macro_rules! impl_domain_sql_param {
    ($($type:ty),+ $(,)?) => {
        $(
            impl DomainSqlParam for &$type {
                fn encode_domain_param(&self) -> String {
                    (*self).encode_sqlite()
                }
            }

            impl DomainSqlParam for &&$type {
                fn encode_domain_param(&self) -> String {
                    (**self).encode_sqlite()
                }
            }
        )+
    };
}

impl_domain_sql_param!(
    ConsensusHash,
    Hash160,
    BlockHeaderHash,
    BurnchainHeaderHash,
    VRFProof,
    VRFSeed,
    TrieHash,
    Sha512Trunc256Sum,
    SortitionId,
    StacksBlockId,
    Txid,
    StacksAddress,
);

impl<T: DomainSqlParam> AdaptSqlParam for SqlParamDispatch<T> {
    fn adapt_sql_param(self) -> DeferredSqlParam {
        DeferredSqlParam::from_value(Value::Text(self.0.encode_domain_param()))
    }
}

impl<T: ToSql> AdaptSqlParam for &SqlParamDispatch<T> {
    fn adapt_sql_param(self) -> DeferredSqlParam {
        DeferredSqlParam::from_to_sql(&self.0)
    }
}

#[doc(hidden)]
pub enum DeferredSqlParam {
    Value(Value),
    ZeroBlob(i32),
    Error(String),
}

impl DeferredSqlParam {
    fn from_value(value: Value) -> Self {
        Self::Value(value)
    }

    fn from_to_sql<T: ToSql + ?Sized>(value: &T) -> Self {
        match value.to_sql() {
            Ok(ToSqlOutput::Borrowed(value)) => Self::Value(value.into()),
            Ok(ToSqlOutput::Owned(value)) => Self::Value(value),
            Ok(ToSqlOutput::ZeroBlob(length)) => Self::ZeroBlob(length),
            Ok(_) => Self::Error("unsupported rusqlite parameter representation".into()),
            Err(error) => Self::Error(error.to_string()),
        }
    }
}

impl ToSql for DeferredSqlParam {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Self::Value(value) => value.to_sql(),
            Self::ZeroBlob(length) => Ok(ToSqlOutput::ZeroBlob(*length)),
            Self::Error(message) => Err(rusqlite::Error::ToSqlConversionFailure(
                std::io::Error::other(message.clone()).into(),
            )),
        }
    }
}

/// Construct positional rusqlite parameters while automatically adapting
/// persistence-agnostic Stacks domain values.
#[macro_export]
macro_rules! domain_params {
    () => {
        ::rusqlite::params_from_iter(::std::iter::empty::<$crate::DeferredSqlParam>())
    };
    ($($parameter:expr),+ $(,)?) => {{
        use $crate::AdaptSqlParam as _;
        ::rusqlite::params_from_iter([
            $({
                let value = &$parameter;
                let parameter = $crate::SqlParamDispatch::new(value);
                parameter.adapt_sql_param()
            }),+
        ])
    }};
}

fn decode_hex(value: &str) -> FromSqlResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(FromSqlError::InvalidType);
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]).ok_or(FromSqlError::InvalidType)?;
            let low = decode_nibble(pair[1]).ok_or(FromSqlError::InvalidType)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

macro_rules! impl_hex_sqlite_scalar {
    ($($type:ty),+ $(,)?) => {
        $(
            impl private::Sealed for $type {}

            impl SqliteScalar for $type {
                fn encode_sqlite(&self) -> String {
                    self.to_hex()
                }

                fn decode_sqlite(value: &str) -> FromSqlResult<Self> {
                    let bytes = decode_hex(value)?;
                    Self::from_bytes(&bytes).ok_or(FromSqlError::InvalidType)
                }
            }
        )+
    };
}

// These mappings intentionally match `impl_byte_array_rusqlite_only!` from
// stacks-common: fixed-byte values are stored as lowercase hexadecimal TEXT.
impl_hex_sqlite_scalar!(
    ConsensusHash,
    Hash160,
    BlockHeaderHash,
    BurnchainHeaderHash,
    VRFProof,
    VRFSeed,
    TrieHash,
    Sha512Trunc256Sum,
    SortitionId,
    StacksBlockId,
    Txid,
);

impl private::Sealed for StacksAddress {}

impl SqliteScalar for StacksAddress {
    fn encode_sqlite(&self) -> String {
        self.to_string()
    }

    fn decode_sqlite(value: &str) -> FromSqlResult<Self> {
        StacksAddress::from_c32(value).map_err(|_| FromSqlError::InvalidType)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use rusqlite::{Connection, params};

    use super::*;

    fn check_text_round_trip<T>(value: T, expected: &str)
    where
        T: SqliteScalar + Debug + PartialEq,
    {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute("CREATE TABLE values_table (value TEXT NOT NULL)", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO values_table (value) VALUES (?1)",
                params![SqlRef::new(&value)],
            )
            .unwrap();

        let stored: String = connection
            .query_row("SELECT value FROM values_table", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, expected);

        let decoded: SqlValue<T> = connection
            .query_row("SELECT value FROM values_table", [], |row| row.get(0))
            .unwrap();
        assert_eq!(decoded.into_inner(), value);
    }

    #[test]
    fn domain_params_adapts_domain_and_native_values_together() {
        let connection = Connection::open_in_memory().unwrap();
        let block_id = StacksBlockId([0x12; 32]);
        let native = 7i64;
        let (stored_id, stored_native): (SqlValue<StacksBlockId>, i64) = connection
            .query_row("SELECT ?1, ?2", domain_params![block_id, native], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();

        assert_eq!(stored_id.into_inner(), block_id);
        assert_eq!(stored_native, native);
    }

    #[test]
    fn domain_params_own_temporary_native_values() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute("CREATE TABLE values_test (value TEXT)", [])
            .unwrap();

        let parameters = domain_params!["temporary".to_string()];
        connection
            .execute("INSERT INTO values_test VALUES (?1)", parameters)
            .unwrap();
    }

    macro_rules! check_type {
        ($name:ident, $type:ident, $length:expr, $byte:expr) => {
            #[test]
            fn $name() {
                let value = $type([$byte; $length]);
                check_text_round_trip(value, &format!("{:02x}", $byte).repeat($length));
            }
        };
    }

    check_type!(consensus_hash_round_trip, ConsensusHash, 20, 0x01);
    check_type!(hash160_round_trip, Hash160, 20, 0x12);
    check_type!(block_header_hash_round_trip, BlockHeaderHash, 32, 0x23);
    check_type!(
        burnchain_header_hash_round_trip,
        BurnchainHeaderHash,
        32,
        0x34
    );
    check_type!(trie_hash_round_trip, TrieHash, 32, 0x56);
    check_type!(sha512_trunc256_sum_round_trip, Sha512Trunc256Sum, 32, 0x67);
    check_type!(sortition_id_round_trip, SortitionId, 32, 0x78);
    check_type!(stacks_block_id_round_trip, StacksBlockId, 32, 0x89);
    check_type!(txid_round_trip, Txid, 32, 0x9a);
    check_type!(vrf_seed_round_trip, VRFSeed, 32, 0xab);

    #[test]
    fn vrf_proof_round_trip_preserves_validated_value() {
        let encoded = "9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a";
        let proof = VRFProof::from_hex(encoded).unwrap();
        check_text_round_trip(proof, encoded);
    }

    #[test]
    fn vrf_proof_rejects_invalid_database_bytes() {
        let invalid = "00".repeat(80);
        let error =
            <SqlValue<VRFProof> as FromSql>::column_result(ValueRef::Text(invalid.as_bytes()))
                .unwrap_err();
        assert!(matches!(error, FromSqlError::InvalidType));
    }

    #[test]
    fn stacks_address_round_trip_preserves_c32_text() {
        let value = StacksAddress::new(
            22,
            Hash160::from_hex("a46ff88886c2ef9762d970b4d2c63678835bd39d").unwrap(),
        )
        .unwrap();
        check_text_round_trip(value, "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7");
    }

    #[test]
    fn accepts_uppercase_legacy_hex() {
        let value = "AB".repeat(32);
        let decoded =
            <SqlValue<Txid> as FromSql>::column_result(ValueRef::Text(value.as_bytes())).unwrap();
        assert_eq!(decoded.into_inner(), Txid([0xab; 32]));
    }

    #[test]
    fn rejects_non_text_values() {
        let error =
            <SqlValue<Txid> as FromSql>::column_result(ValueRef::Blob(&[0; 32])).unwrap_err();
        assert!(matches!(error, FromSqlError::InvalidType));
    }

    #[test]
    fn rejects_malformed_hex_values() {
        for invalid in ["0", "zz", "00", &"00".repeat(33)] {
            let error =
                <SqlValue<Txid> as FromSql>::column_result(ValueRef::Text(invalid.as_bytes()))
                    .unwrap_err();
            assert!(matches!(error, FromSqlError::InvalidType));
        }
    }

    #[test]
    fn rejects_malformed_stacks_addresses() {
        for invalid in [
            "not-an-address",
            "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ0",
        ] {
            let error = <SqlValue<StacksAddress> as FromSql>::column_result(ValueRef::Text(
                invalid.as_bytes(),
            ))
            .unwrap_err();
            assert!(matches!(error, FromSqlError::InvalidType));
        }
    }

    #[test]
    fn owned_values_can_be_query_parameters() {
        let value = SqlValue::new(Txid([0xcd; 32]));
        let connection = Connection::open_in_memory().unwrap();
        let stored: String = connection
            .query_row("SELECT ?1", params![value], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, "cd".repeat(32));
    }
}
