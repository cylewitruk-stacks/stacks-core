// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

#[cfg(not(feature = "wasm-deterministic"))]
use ::libsecp256k1::ECMULT_GEN_CONTEXT;
pub use ::libsecp256k1::Error;
#[cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))]
use ::libsecp256k1::curve::Scalar;
use ::libsecp256k1::{
    self, RecoveryId as LibSecp256k1RecoveryId, Signature as LibSecp256k1Signature,
};
#[cfg(not(feature = "wasm-deterministic"))]
use ::libsecp256k1::{Error as LibSecp256k1Error, Message as LibSecp256k1Message};
use serde::Deserialize;
use serde::de::Error as de_Error;

#[cfg(not(feature = "wasm-deterministic"))]
use super::message_signature_from_recovery_id_and_compact;
use super::{
    MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey, SigningKey, VerifyingKey,
    message_signature_compact_bytes, private_key_bytes_and_compression,
};

pub(super) type LibSecp256k1PublicKey = ::libsecp256k1::PublicKey;
pub(super) type LibSecp256k1PrivateKey = ::libsecp256k1::SecretKey;

pub const PUBLIC_KEY_SIZE: usize = 33;

impl Secp256k1PublicKey {
    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PublicKey, &'static str> {
        let (format, compressed) = if data.len() == PUBLIC_KEY_SIZE {
            (libsecp256k1::PublicKeyFormat::Compressed, true)
        } else {
            (libsecp256k1::PublicKeyFormat::Full, false)
        };
        match LibSecp256k1PublicKey::parse_slice(data, Some(format)) {
            Ok(pubkey_res) => Ok(Secp256k1PublicKey {
                key: pubkey_res,
                compressed,
            }),
            Err(_e) => Err("Invalid public key: failed to load"),
        }
    }

    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        self.key.serialize_compressed().to_vec()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.compressed {
            self.key.serialize_compressed().to_vec()
        } else {
            self.key.serialize().to_vec()
        }
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        let key =
            LibSecp256k1PublicKey::from_secret_key_with_context(&privk.key, &ECMULT_GEN_CONTEXT);
        Secp256k1PublicKey {
            key,
            compressed: privk.compress_public,
        }
    }

    #[cfg(feature = "wasm-deterministic")]
    pub fn from_private(_privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        panic!("Not implemented for wasm-deterministic")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    /// recover message and signature to public key (will be compressed)
    pub fn recover_to_pubkey(
        msg: &[u8],
        sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        let secp256k1_sig = secp256k1_recover(msg, sig.as_bytes())
            .map_err(|_e| "Invalid signature: failed to recover public key")?;

        Secp256k1PublicKey::from_slice(&secp256k1_sig)
    }

    #[cfg(feature = "wasm-deterministic")]
    pub fn recover_to_pubkey(
        _msg: &[u8],
        _sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }
}

impl Secp256k1PrivateKey {
    #[cfg(feature = "rand")]
    pub fn new() -> Secp256k1PrivateKey {
        use rand::RngCore as _;

        let mut rng = rand::thread_rng();
        loop {
            // keep trying to generate valid bytes
            let mut random_32_bytes = [0u8; 32];
            rng.fill_bytes(&mut random_32_bytes);
            let pk_res = LibSecp256k1PrivateKey::parse_slice(&random_32_bytes);
            match pk_res {
                Ok(pk) => {
                    return Secp256k1PrivateKey {
                        key: pk,
                        compress_public: true,
                    };
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PrivateKey, &'static str> {
        let (key_bytes, compress_public) = private_key_bytes_and_compression(data)?;
        match LibSecp256k1PrivateKey::parse_slice(key_bytes) {
            Ok(privkey_res) => Ok(Secp256k1PrivateKey {
                key: privkey_res,
                compress_public,
            }),
            Err(_e) => Err("Invalid private key: failed to load"),
        }
    }
}

#[cfg(not(feature = "wasm-deterministic"))]
pub fn secp256k1_recover(
    message_arr: &[u8],
    serialized_signature: &[u8],
) -> Result<[u8; 33], LibSecp256k1Error> {
    let recovery_id = libsecp256k1::RecoveryId::parse(serialized_signature[64] as u8)?;
    let message = LibSecp256k1Message::parse_slice(message_arr)?;
    let signature = LibSecp256k1Signature::parse_standard_slice(&serialized_signature[..64])?;
    let recovered_pub_key = libsecp256k1::recover(&message, &signature, &recovery_id)?;
    Ok(recovered_pub_key.serialize_compressed())
}

#[cfg(not(feature = "wasm-deterministic"))]
pub fn secp256k1_verify(
    message_arr: &[u8],
    serialized_signature: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), LibSecp256k1Error> {
    let message = LibSecp256k1Message::parse_slice(message_arr)?;
    let signature = LibSecp256k1Signature::parse_standard_slice(&serialized_signature[..64])?; // ignore 65th byte if present
    let pubkey = LibSecp256k1PublicKey::parse_slice(
        pubkey_arr,
        Some(libsecp256k1::PublicKeyFormat::Compressed),
    )?;

    let res = libsecp256k1::verify(&message, &signature, &pubkey);
    if res {
        Ok(())
    } else {
        Err(LibSecp256k1Error::InvalidPublicKey)
    }
}

pub(super) fn secp256k1_pubkey_serialize<S: serde::Serializer>(
    pubk: &LibSecp256k1PublicKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = const_hex::encode(pubk.serialize());
    s.serialize_str(&key_hex.as_str())
}

pub(super) fn secp256k1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = const_hex::decode(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PublicKey::parse_slice(&key_bytes[..], None).map_err(de_Error::custom)
}

pub(super) fn secp256k1_privkey_serialize<S: serde::Serializer>(
    privk: &LibSecp256k1PrivateKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = const_hex::encode(privk.serialize());
    s.serialize_str(key_hex.as_str())
}

pub(super) fn secp256k1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PrivateKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = const_hex::decode(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PrivateKey::parse_slice(&key_bytes[..]).map_err(de_Error::custom)
}

#[cfg(not(feature = "wasm-deterministic"))]
fn message_signature_from_secp256k1_recoverable(
    sig: &LibSecp256k1Signature,
    recid: LibSecp256k1RecoveryId,
) -> MessageSignature {
    let bytes = sig.serialize();
    let recovery_id_byte = recid.serialize(); // recovery ID will be 0, 1, 2, or 3
    message_signature_from_recovery_id_and_compact(recovery_id_byte, &bytes)
}

#[allow(dead_code)]
fn message_signature_to_secp256k1_recoverable(
    sig: &MessageSignature,
) -> Option<(LibSecp256k1Signature, LibSecp256k1RecoveryId)> {
    let recovery_id = match LibSecp256k1RecoveryId::parse(sig.0[0]) {
        Ok(rid) => rid,
        Err(_) => {
            return None;
        }
    };
    let signature =
        LibSecp256k1Signature::parse_standard_slice(&message_signature_compact_bytes(sig)).ok()?;
    Some((signature, recovery_id))
}

impl VerifyingKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    #[cfg(feature = "wasm-deterministic")]
    fn verify(&self, _data_hash: &[u8], _sig: &MessageSignature) -> Result<bool, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        let pub_key = Secp256k1PublicKey::recover_to_pubkey(data_hash, sig)?;
        Ok(self.eq(&pub_key))
    }
}

impl SigningKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key.serialize().to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    #[cfg(feature = "wasm-deterministic")]
    fn sign(&self, _data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        let message = LibSecp256k1Message::parse_slice(data_hash)
            .map_err(|_e| "Invalid message: failed to decode data hash: must be a 32-byte hash")?;
        let (sig, recid) = libsecp256k1::sign(&message, &self.key);
        let rec_sig = message_signature_from_secp256k1_recoverable(&sig, recid);
        Ok(rec_sig)
    }

    #[cfg(all(feature = "wasm-deterministic", any(test, feature = "testing")))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str> {
        let message = LibSecp256k1Message::parse_slice(data_hash)
            .map_err(|_e| "Invalid message: failed to decode data hash: must be a 32-byte hash")?;
        let mut nonce = Scalar::default();
        let _ = nonce.set_b32(&noncedata);

        // we need this as the key raw data are private
        let mut key = Scalar::default();
        let _ = key.set_b32(&self.key.serialize());

        let (sigr, sigs, recid) = match ECMULT_GEN_CONTEXT.sign_raw(&key, &message.0, &nonce) {
            Ok(result) => result,
            Err(_) => return Err("unable to sign message"),
        };

        let recid = match LibSecp256k1RecoveryId::parse(recid) {
            Ok(recid) => recid,
            Err(_) => return Err("invalid recovery id"),
        };

        let (sig, recid) = (LibSecp256k1Signature { r: sigr, s: sigs }, recid);
        let rec_sig = message_signature_from_secp256k1_recoverable(&sig, recid);
        Ok(rec_sig)
    }
}
