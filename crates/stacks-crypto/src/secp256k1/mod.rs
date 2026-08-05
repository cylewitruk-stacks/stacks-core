use core::fmt;

#[cfg(not(target_family = "wasm"))]
use native::{
    LibSecp256k1PrivateKey, LibSecp256k1PublicKey, secp256k1_privkey_deserialize,
    secp256k1_privkey_serialize, secp256k1_pubkey_deserialize, secp256k1_pubkey_serialize,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stacks_primitives::secp256k1::{MessageSignature, Secp256k1PublicKeyBytes};
#[cfg(target_family = "wasm")]
use wasm::{
    LibSecp256k1PrivateKey, LibSecp256k1PublicKey, secp256k1_privkey_deserialize,
    secp256k1_privkey_serialize, secp256k1_pubkey_deserialize, secp256k1_pubkey_serialize,
};

#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(not(target_family = "wasm"))]
pub use self::native::*;

#[cfg(target_family = "wasm")]
mod wasm;
#[cfg(target_family = "wasm")]
pub use self::wasm::*;

pub trait VerifyingKey: Clone + fmt::Debug + serde::Serialize + DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str>;
}

pub trait SigningKey: Clone + fmt::Debug + serde::Serialize + DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str>;

    #[cfg(any(test, feature = "testing"))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str>;
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(not(target_family = "wasm"), derive(Hash))]
pub struct Secp256k1PublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_pubkey_serialize",
        deserialize_with = "secp256k1_pubkey_deserialize"
    )]
    key: LibSecp256k1PublicKey,
    compressed: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(target_family = "wasm", derive(Copy))]
pub struct Secp256k1PrivateKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_privkey_serialize",
        deserialize_with = "secp256k1_privkey_deserialize"
    )]
    key: LibSecp256k1PrivateKey,
    compress_public: bool,
}

impl Secp256k1PublicKey {
    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PublicKey, &'static str> {
        let data = const_hex::decode(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256k1PublicKey::from_slice(&data).map_err(|_e| "Invalid public key hex string")
    }

    pub fn from_public_key_bytes(
        pubkey: &Secp256k1PublicKeyBytes,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(pubkey.as_bytes())
    }

    pub fn to_hex(&self) -> String {
        const_hex::encode(<Self as VerifyingKey>::to_bytes(self))
    }

    pub fn to_public_key_bytes(&self) -> Secp256k1PublicKeyBytes {
        Secp256k1PublicKeyBytes::from_bytes(&<Self as VerifyingKey>::to_bytes(self))
            .expect("FATAL: infallible: serialized secp256k1 public key has invalid length")
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn set_compressed(&mut self, value: bool) {
        self.compressed = value;
    }
}

impl Secp256k1PrivateKey {
    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PrivateKey, &'static str> {
        let data =
            const_hex::decode(hex_string).map_err(|_e| "Failed to decode hex private key")?;
        Secp256k1PrivateKey::from_slice(&data).map_err(|_e| "Invalid private key hex string")
    }

    pub fn to_hex(&self) -> String {
        const_hex::encode(<Self as SigningKey>::to_bytes(self))
    }

    pub fn compress_public(&self) -> bool {
        self.compress_public
    }

    pub fn set_compress_public(&mut self, value: bool) {
        self.compress_public = value;
    }
}

fn private_key_bytes_and_compression(data: &[u8]) -> Result<(&[u8], bool), &'static str> {
    if data.len() < 32 {
        return Err("Invalid private key: shorter than 32 bytes");
    }
    if data.len() > 33 {
        return Err("Invalid private key: greater than 33 bytes");
    }

    let compress_public = if data.len() == 33 {
        if data[32] != 0x01 {
            return Err("Invalid private key: invalid compressed byte marker");
        }
        true
    } else {
        false
    };

    Ok((&data[0..32], compress_public))
}

#[cfg_attr(
    all(target_family = "wasm", feature = "wasm-deterministic"),
    allow(dead_code)
)]
fn message_signature_from_recovery_id_and_compact(
    recovery_id: u8,
    compact_signature: &[u8; 64],
) -> MessageSignature {
    let mut ret_bytes = [0u8; 65];
    ret_bytes[0] = recovery_id;
    ret_bytes[1..=64].copy_from_slice(compact_signature);
    MessageSignature(ret_bytes)
}

fn message_signature_compact_bytes(sig: &MessageSignature) -> [u8; 64] {
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.0[1..=64]);
    sig_bytes
}
