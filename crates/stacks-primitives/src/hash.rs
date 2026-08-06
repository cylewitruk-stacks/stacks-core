use serde::{Deserialize, Serialize};
use stacks_macros::{impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype};

macro_rules! impl_serde_json_hex_string {
    ($name:ident, $len:expr) => {
        pub struct $name {}
        impl $name {
            pub fn json_serialize<S: serde::Serializer>(
                inst: &[u8; $len],
                s: S,
            ) -> Result<S::Ok, S::Error> {
                s.serialize_str(&const_hex::encode(inst))
            }

            pub fn json_deserialize<'de, D: serde::Deserializer<'de>>(
                d: D,
            ) -> Result<[u8; $len], D::Error> {
                let hex_inst = String::deserialize(d)?;
                const_hex::decode_to_array(hex_inst).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_serde_json_hex_string!(Hash20, 20);
impl_serde_json_hex_string!(Hash32, 32);
impl_serde_json_hex_string!(Hash64, 64);

#[derive(Serialize, Deserialize)]
pub struct Hash160(
    #[serde(
        serialize_with = "Hash20::json_serialize",
        deserialize_with = "Hash20::json_deserialize"
    )]
    pub [u8; 20],
);
impl_array_newtype!(Hash160, u8, 20);
impl_array_hexstring_fmt!(Hash160);
impl_byte_array_newtype!(Hash160, u8, 20, crate::HexError, crate::hex::decode_array);
pub const HASH160_ENCODED_SIZE: u32 = 20;

#[derive(Serialize, Deserialize)]
pub struct Keccak256Hash(
    #[serde(
        serialize_with = "Hash32::json_serialize",
        deserialize_with = "Hash32::json_deserialize"
    )]
    pub [u8; 32],
);
impl_array_newtype!(Keccak256Hash, u8, 32);
impl_array_hexstring_fmt!(Keccak256Hash);
impl_byte_array_newtype!(
    Keccak256Hash,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);

#[derive(Default, Serialize, Deserialize)]
pub struct Sha256Sum(
    #[serde(
        serialize_with = "Hash32::json_serialize",
        deserialize_with = "Hash32::json_deserialize"
    )]
    pub [u8; 32],
);
impl_array_newtype!(Sha256Sum, u8, 32);
impl_array_hexstring_fmt!(Sha256Sum);
impl_byte_array_newtype!(Sha256Sum, u8, 32, crate::HexError, crate::hex::decode_array);

#[derive(Serialize, Deserialize)]
pub struct Sha512Sum(
    #[serde(
        serialize_with = "Hash64::json_serialize",
        deserialize_with = "Hash64::json_deserialize"
    )]
    pub [u8; 64],
);
impl_array_newtype!(Sha512Sum, u8, 64);
impl_array_hexstring_fmt!(Sha512Sum);
impl_byte_array_newtype!(Sha512Sum, u8, 64, crate::HexError, crate::hex::decode_array);

#[derive(Serialize, Deserialize)]
pub struct Sha512Trunc256Sum(
    #[serde(
        serialize_with = "Hash32::json_serialize",
        deserialize_with = "Hash32::json_deserialize"
    )]
    pub [u8; 32],
);
impl_array_newtype!(Sha512Trunc256Sum, u8, 32);
impl_array_hexstring_fmt!(Sha512Trunc256Sum);
impl_byte_array_newtype!(
    Sha512Trunc256Sum,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);

#[derive(Serialize, Deserialize)]
pub struct DoubleSha256(
    #[serde(
        serialize_with = "Hash32::json_serialize",
        deserialize_with = "Hash32::json_deserialize"
    )]
    pub [u8; 32],
);
impl_array_newtype!(DoubleSha256, u8, 32);
impl_array_hexstring_fmt!(DoubleSha256);
impl_byte_array_newtype!(
    DoubleSha256,
    u8,
    32,
    crate::HexError,
    crate::hex::decode_array
);
pub const DOUBLE_SHA256_ENCODED_SIZE: u32 = 32;

pub struct Txid(pub [u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32, crate::HexError, crate::hex::decode_array);
stacks_macros::impl_byte_array_serde!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;
