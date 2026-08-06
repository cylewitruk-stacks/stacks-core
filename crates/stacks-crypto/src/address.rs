//! Cryptographic derivation of Stacks address hashes.

use bitcoin::blockdata::opcodes::all as bitcoin_opcodes;
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use stacks_primitives::secp256k1::COMPRESSED_PUBLIC_KEY_ENCODED_SIZE;
use stacks_primitives::{AddressHashMode, Hash160, StacksAddress};

use crate::hash::{Hash160Digest as _, Sha256Digest as _, Sha256Sum};
use crate::secp256k1::{Secp256k1PublicKey, VerifyingKey};

/// Address construction that depends on public-key hashing and script rules.
pub trait StacksAddressCryptoExt {
    fn from_public_keys(
        version: u8,
        hash_mode: AddressHashMode,
        signatures_required: usize,
        public_keys: &[Secp256k1PublicKey],
    ) -> Option<Self>
    where
        Self: Sized;
}

impl StacksAddressCryptoExt for StacksAddress {
    fn from_public_keys(
        version: u8,
        hash_mode: AddressHashMode,
        signatures_required: usize,
        public_keys: &[Secp256k1PublicKey],
    ) -> Option<Self> {
        let hash = public_keys_to_address_hash(hash_mode, signatures_required, public_keys)?;
        Self::new(version, hash).ok()
    }
}

pub fn public_keys_to_address_hash<K>(
    hash_mode: AddressHashMode,
    signatures_required: usize,
    public_keys: &[K],
) -> Option<Hash160>
where
    K: VerifyingKey,
{
    if public_keys.len() < signatures_required {
        return None;
    }
    if matches!(
        hash_mode,
        AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH
    ) && (signatures_required != 1 || public_keys.len() != 1)
    {
        return None;
    }
    if matches!(
        hash_mode,
        AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH
    ) && public_keys
        .iter()
        .any(|key| key.to_bytes().len() != COMPRESSED_PUBLIC_KEY_ENCODED_SIZE)
    {
        return None;
    }

    Some(match hash_mode {
        AddressHashMode::SerializeP2PKH => Hash160::from_data(&public_keys[0].to_bytes()),
        AddressHashMode::SerializeP2SH => p2sh(signatures_required, public_keys),
        AddressHashMode::SerializeP2WPKH => p2sh_p2wpkh(&public_keys[0]),
        AddressHashMode::SerializeP2WSH => p2sh_p2wsh(signatures_required, public_keys),
    })
}

fn multisig_script<K>(signatures_required: usize, public_keys: &[K]) -> bitcoin::ScriptBuf
where
    K: VerifyingKey,
{
    let mut builder = Builder::new().push_int(signatures_required as i64);
    for public_key in public_keys {
        builder = builder.push_slice(push_bytes(public_key.to_bytes()));
    }
    builder
        .push_int(public_keys.len() as i64)
        .push_opcode(bitcoin_opcodes::OP_CHECKMULTISIG)
        .into_script()
}

fn p2sh<K>(signatures_required: usize, public_keys: &[K]) -> Hash160
where
    K: VerifyingKey,
{
    Hash160::from_data(multisig_script(signatures_required, public_keys).as_bytes())
}

fn p2sh_p2wpkh<K>(public_key: &K) -> Hash160
where
    K: VerifyingKey,
{
    let key_hash = Hash160::from_data(&public_key.to_bytes());
    let script = Builder::new()
        .push_int(0)
        .push_slice(key_hash.as_bytes())
        .into_script();
    Hash160::from_data(script.as_bytes())
}

fn p2sh_p2wsh<K>(signatures_required: usize, public_keys: &[K]) -> Hash160
where
    K: VerifyingKey,
{
    let script_hash =
        Sha256Sum::from_data(multisig_script(signatures_required, public_keys).as_bytes());
    let witness_script = Builder::new()
        .push_int(0)
        .push_slice(script_hash.as_bytes())
        .into_script();
    Hash160::from_data(witness_script.as_bytes())
}

fn push_bytes(bytes: Vec<u8>) -> PushBytesBuf {
    PushBytesBuf::try_from(bytes).expect("public-key encodings fit in a Bitcoin script push")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::Secp256k1PublicKey;

    #[test]
    fn known_single_key_hash_is_preserved() {
        let key = Secp256k1PublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap();
        let hash = public_keys_to_address_hash(AddressHashMode::SerializeP2PKH, 1, &[key]).unwrap();
        assert_eq!(hash.to_hex(), "395f3643cea07ec4eec73b4d9a973dcce56b9bf1");
    }
}
