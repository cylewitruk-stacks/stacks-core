use core::fmt;

use serde::{Deserialize, Serialize};
use stacks_macros::{
    impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype, impl_byte_array_serde,
};

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 65;
pub const SCHNORR_SIGNATURE_ENCODED_SIZE: u32 = 65;
pub const COMPRESSED_PUBLIC_KEY_ENCODED_SIZE: usize = 33;
pub const UNCOMPRESSED_PUBLIC_KEY_ENCODED_SIZE: usize = 65;

/// A compressed secp256k1 public key byte buffer.
pub struct CompressedSecp256k1PublicKeyBytes(pub [u8; 33]);
impl_array_newtype!(CompressedSecp256k1PublicKeyBytes, u8, 33);
impl_array_hexstring_fmt!(CompressedSecp256k1PublicKeyBytes);
impl_byte_array_newtype!(CompressedSecp256k1PublicKeyBytes, u8, 33);
impl_byte_array_serde!(CompressedSecp256k1PublicKeyBytes);

pub struct MessageSignature(pub [u8; 65]);
impl_array_newtype!(MessageSignature, u8, 65);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 65);
impl_byte_array_serde!(MessageSignature);

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        MessageSignature([0u8; 65])
    }

    pub fn from_raw(sig: &[u8]) -> MessageSignature {
        let mut buf = [0u8; 65];
        if sig.len() < 65 {
            buf[..sig.len()].copy_from_slice(sig);
        } else {
            buf.copy_from_slice(&sig[..65]);
        }
        MessageSignature(buf)
    }

    /// Convert from VRS to RSV.
    pub fn to_rsv(&self) -> Vec<u8> {
        [&self.0[1..], &self.0[0..1]].concat()
    }

    /// Convert from RSV (used by Clarity) to VRS (used by Stacks transaction code).
    pub fn from_rsv(source: &[u8]) -> Option<Self> {
        if source.len() != 65 {
            return None;
        }
        let mut signature = [0u8; 65];
        signature[0] = source[64];
        signature[1..].copy_from_slice(&source[..64]);
        Some(Self(signature))
    }
}

pub struct SchnorrSignature(pub [u8; 65]);
impl_array_newtype!(SchnorrSignature, u8, 65);
impl_array_hexstring_fmt!(SchnorrSignature);
impl_byte_array_newtype!(SchnorrSignature, u8, 65);
impl_byte_array_serde!(SchnorrSignature);

impl Default for SchnorrSignature {
    /// Creates a default Schnorr Signature. Note this is not a valid signature.
    fn default() -> Self {
        Self([0u8; 65])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyError {
    InvalidLength(usize),
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyError::InvalidLength(len) => {
                write!(f, "Invalid secp256k1 public key length: {len}")
            }
        }
    }
}

impl std::error::Error for PublicKeyError {}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Secp256k1PublicKeyBytes {
    bytes: Vec<u8>,
}

impl Secp256k1PublicKeyBytes {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        match bytes.len() {
            COMPRESSED_PUBLIC_KEY_ENCODED_SIZE | UNCOMPRESSED_PUBLIC_KEY_ENCODED_SIZE => Ok(Self {
                bytes: bytes.to_vec(),
            }),
            len => Err(PublicKeyError::InvalidLength(len)),
        }
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, PublicKeyError> {
        let bytes = const_hex::decode(hex_str).map_err(|_| PublicKeyError::InvalidLength(0))?;
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn to_hex(&self) -> String {
        const_hex::encode(&self.bytes)
    }

    pub fn compressed(&self) -> bool {
        self.bytes.len() == COMPRESSED_PUBLIC_KEY_ENCODED_SIZE
    }
}

impl fmt::Debug for Secp256k1PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for Secp256k1PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::LowerHex for Secp256k1PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Secp256k1PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let inst_str = String::deserialize(d)?;
        Self::from_hex(&inst_str).map_err(serde::de::Error::custom)
    }
}
