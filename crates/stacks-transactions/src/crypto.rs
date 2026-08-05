use core::{error, fmt};

use bitcoin::blockdata::opcodes::all as btc_opcodes;
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use stacks_crypto::hash::{Hash160Digest, Sha256Digest, Sha256Sum, TxidDigest};
use stacks_crypto::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey, SigningKey, VerifyingKey};
use stacks_primitives::address::AddressHashMode;
use stacks_primitives::hash::{Hash160, Txid};
use stacks_primitives::secp256k1::{
    COMPRESSED_PUBLIC_KEY_ENCODED_SIZE, MESSAGE_SIGNATURE_ENCODED_SIZE, MessageSignature,
    Secp256k1PublicKeyBytes,
};

use crate::spend_condition::{
    MultisigHashMode, MultisigSpendingCondition, OrderIndependentMultisigHashMode,
    OrderIndependentMultisigSpendingCondition, SinglesigHashMode, SinglesigSpendingCondition,
    TransactionSpendingCondition,
};
use crate::{TransactionAuthField, TransactionAuthFlags, TransactionPublicKeyEncoding};

/// Errors raised by transaction auth signing and cryptographic verification.
#[derive(Debug)]
pub enum AuthError {
    SigningError(String),
    VerifyingError(String),
    IncompatibleSpendingConditionError,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::SigningError(s) => write!(f, "Signing error: {s}"),
            AuthError::VerifyingError(s) => write!(f, "Verifying error: {s}"),
            AuthError::IncompatibleSpendingConditionError => {
                write!(f, "Spending condition is incompatible with this operation")
            }
        }
    }
}

impl error::Error for AuthError {}

pub trait DeriveSpendingCondition {
    fn singlesig_p2pkh(pubkey: Secp256k1PublicKey) -> Option<TransactionSpendingCondition>;
    fn singlesig_p2wpkh(pubkey: Secp256k1PublicKey) -> Option<TransactionSpendingCondition>;
    fn multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition>;
    fn multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition>;
    fn order_independent_multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition>;
    fn order_independent_multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition>;
}

impl DeriveSpendingCondition for TransactionSpendingCondition {
    fn singlesig_p2pkh(pubkey: Secp256k1PublicKey) -> Option<TransactionSpendingCondition> {
        let key_encoding = if pubkey.compressed() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };
        let signer = public_keys_to_signer(AddressHashMode::SerializeP2PKH, 1, &[pubkey])?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding,
                signature: MessageSignature::empty(),
            },
        ))
    }

    fn singlesig_p2wpkh(pubkey: Secp256k1PublicKey) -> Option<TransactionSpendingCondition> {
        let signer = public_keys_to_signer(AddressHashMode::SerializeP2WPKH, 1, &[pubkey])?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature::empty(),
            },
        ))
    }

    fn multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer = public_keys_to_signer(
            AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    fn multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer = public_keys_to_signer(
            AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    fn order_independent_multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer = public_keys_to_signer(
            AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    fn order_independent_multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<Secp256k1PublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer = public_keys_to_signer(
            AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }
}

pub fn public_keys_to_signer(
    hash_mode: AddressHashMode,
    signatures_required: usize,
    pubkeys: &[Secp256k1PublicKey],
) -> Option<Hash160> {
    public_keys_to_address_hash(hash_mode, signatures_required, pubkeys)
}

pub trait RecoverAuthFieldPublicKey {
    fn recover_public_key(&self, sighash_bytes: &[u8]) -> Result<Secp256k1PublicKey, AuthError>;
}

impl RecoverAuthFieldPublicKey for TransactionAuthField {
    fn recover_public_key(&self, sighash_bytes: &[u8]) -> Result<Secp256k1PublicKey, AuthError> {
        match self {
            TransactionAuthField::PublicKey(pubk) => decode_public_key(pubk),
            TransactionAuthField::Signature(key_fmt, sig) => {
                let mut pubk = Secp256k1PublicKey::recover_to_pubkey(sighash_bytes, sig)
                    .map_err(|e| AuthError::VerifyingError(e.to_string()))?;
                pubk.set_compressed(*key_fmt == TransactionPublicKeyEncoding::Compressed);
                Ok(pubk)
            }
        }
    }
}

pub fn make_sighash_presign(
    cur_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
    tx_fee: u64,
    nonce: u64,
) -> Txid {
    // new hash combines the previous hash and all the new data this signature will add.  This
    // includes:
    // * the previous hash
    // * the auth flag
    // * the fee rate (big-endian 8-byte number)
    // * nonce (big-endian 8-byte number)
    let new_tx_hash_bits_len = 32 + 1 + 8 + 8;
    let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);

    new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
    new_tx_hash_bits.extend_from_slice(&[*cond_code as u8]);
    new_tx_hash_bits.extend_from_slice(&tx_fee.to_be_bytes());
    new_tx_hash_bits.extend_from_slice(&nonce.to_be_bytes());

    assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

    Txid::from_sighash_bytes(&new_tx_hash_bits)
}

pub fn make_sighash_postsign(
    cur_sighash: &Txid,
    pubkey: &Secp256k1PublicKey,
    sig: &MessageSignature,
) -> Txid {
    // new hash combines the previous hash and all the new data this signature will add.  This
    // includes:
    // * the public key compression flag
    // * the signature
    let new_tx_hash_bits_len = 32 + 1 + MESSAGE_SIGNATURE_ENCODED_SIZE;
    let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);
    let pubkey_encoding = if pubkey.compressed() {
        TransactionPublicKeyEncoding::Compressed
    } else {
        TransactionPublicKeyEncoding::Uncompressed
    };

    new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
    new_tx_hash_bits.extend_from_slice(&[pubkey_encoding as u8]);
    new_tx_hash_bits.extend_from_slice(sig.as_bytes());

    assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

    Txid::from_sighash_bytes(&new_tx_hash_bits)
}

/// Linear-complexity signing algorithm over the rolling auth sighash.
pub fn next_signature(
    cur_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
    tx_fee: u64,
    nonce: u64,
    privk: &Secp256k1PrivateKey,
) -> Result<(MessageSignature, Txid), AuthError> {
    let sighash_presign = make_sighash_presign(cur_sighash, cond_code, tx_fee, nonce);

    let sig = privk
        .sign(sighash_presign.as_bytes())
        .map_err(|se| AuthError::SigningError(se.to_string()))?;

    let pubk = Secp256k1PublicKey::from_private(privk);
    let next_sighash = make_sighash_postsign(&sighash_presign, &pubk, &sig);

    Ok((sig, next_sighash))
}

/// Linear-complexity verification algorithm over the rolling auth sighash.
pub fn next_verification(
    cur_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
    tx_fee: u64,
    nonce: u64,
    key_encoding: &TransactionPublicKeyEncoding,
    sig: &MessageSignature,
) -> Result<(Secp256k1PublicKey, Txid), AuthError> {
    let sighash_presign = make_sighash_presign(cur_sighash, cond_code, tx_fee, nonce);

    let mut pubk = Secp256k1PublicKey::recover_to_pubkey(sighash_presign.as_bytes(), sig)
        .map_err(|ve| AuthError::VerifyingError(ve.to_string()))?;

    match key_encoding {
        TransactionPublicKeyEncoding::Compressed => pubk.set_compressed(true),
        TransactionPublicKeyEncoding::Uncompressed => pubk.set_compressed(false),
    };

    let next_sighash = make_sighash_postsign(&sighash_presign, &pubk, sig);
    Ok((pubk, next_sighash))
}

pub trait VerifySpendingConditionSignatures {
    fn verify_signatures(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError>;
}

impl VerifySpendingConditionSignatures for TransactionSpendingCondition {
    fn verify_signatures(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, AuthError> {
        match self {
            TransactionSpendingCondition::Singlesig(data) => {
                verify_singlesig(data, initial_sighash, cond_code)
            }
            TransactionSpendingCondition::Multisig(data) => {
                verify_multisig(data, initial_sighash, cond_code)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(data) => {
                verify_order_independent_multisig(data, initial_sighash, cond_code)
            }
        }
    }
}

fn verify_singlesig(
    condition: &SinglesigSpendingCondition,
    initial_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
) -> Result<Txid, AuthError> {
    let (pubkey, next_sighash) = next_verification(
        initial_sighash,
        cond_code,
        condition.tx_fee,
        condition.nonce,
        &condition.key_encoding,
        &condition.signature,
    )?;

    let signer =
        public_keys_to_address_hash(condition.hash_mode.to_address_hash_mode(), 1, &[pubkey])
            .ok_or_else(|| {
                AuthError::VerifyingError("Failed to generate address from public key".to_string())
            })?;

    if signer.as_bytes() != condition.signer.as_bytes() {
        return Err(AuthError::VerifyingError(format!(
            "Signer hash does not equal hash of public key(s): {} != {}",
            signer, &condition.signer
        )));
    }

    Ok(next_sighash)
}

fn verify_multisig(
    condition: &MultisigSpendingCondition,
    initial_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
) -> Result<Txid, AuthError> {
    let mut pubkeys = vec![];
    let mut cur_sighash = initial_sighash.clone();
    let mut num_sigs: u16 = 0;
    let mut have_uncompressed = false;
    for field in condition.fields.iter() {
        let pubkey = match field {
            TransactionAuthField::PublicKey(pubkey) => {
                if !pubkey.compressed() {
                    have_uncompressed = true;
                }
                decode_public_key(pubkey)?
            }
            TransactionAuthField::Signature(pubkey_encoding, sigbuf) => {
                if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                    have_uncompressed = true;
                }

                let (pubkey, next_sighash) = next_verification(
                    &cur_sighash,
                    cond_code,
                    condition.tx_fee,
                    condition.nonce,
                    pubkey_encoding,
                    sigbuf,
                )?;
                cur_sighash = next_sighash;
                num_sigs = num_sigs
                    .checked_add(1)
                    .ok_or(AuthError::VerifyingError("Too many signatures".to_string()))?;
                pubkey
            }
        };
        pubkeys.push(pubkey);
    }

    if num_sigs != condition.signatures_required {
        return Err(AuthError::VerifyingError(
            "Incorrect number of signatures".to_string(),
        ));
    }

    if have_uncompressed && condition.hash_mode == MultisigHashMode::P2WSH {
        return Err(AuthError::VerifyingError(
            "Uncompressed keys are not allowed in this hash mode".to_string(),
        ));
    }

    verify_multisig_address(
        &condition.hash_mode.to_address_hash_mode(),
        condition.signatures_required,
        &condition.signer,
        &pubkeys,
    )?;

    Ok(cur_sighash)
}

fn verify_order_independent_multisig(
    condition: &OrderIndependentMultisigSpendingCondition,
    initial_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
) -> Result<Txid, AuthError> {
    let mut pubkeys = vec![];
    let mut num_sigs: u16 = 0;
    let mut have_uncompressed = false;
    for field in condition.fields.iter() {
        let pubkey = match field {
            TransactionAuthField::PublicKey(pubkey) => {
                if !pubkey.compressed() {
                    have_uncompressed = true;
                }
                decode_public_key(pubkey)?
            }
            TransactionAuthField::Signature(pubkey_encoding, sigbuf) => {
                if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                    have_uncompressed = true;
                }

                let (pubkey, _next_sighash) = next_verification(
                    initial_sighash,
                    cond_code,
                    condition.tx_fee,
                    condition.nonce,
                    pubkey_encoding,
                    sigbuf,
                )?;
                num_sigs = num_sigs
                    .checked_add(1)
                    .ok_or(AuthError::VerifyingError("Too many signatures".to_string()))?;
                pubkey
            }
        };
        pubkeys.push(pubkey);
    }

    if num_sigs < condition.signatures_required {
        return Err(AuthError::VerifyingError(format!(
            "Not enough signatures. Got {num_sigs}, expected at least {req}",
            req = condition.signatures_required
        )));
    }

    if have_uncompressed && condition.hash_mode == OrderIndependentMultisigHashMode::P2WSH {
        return Err(AuthError::VerifyingError(
            "Uncompressed keys are not allowed in this hash mode".to_string(),
        ));
    }

    verify_multisig_address(
        &condition.hash_mode.to_address_hash_mode(),
        condition.signatures_required,
        &condition.signer,
        &pubkeys,
    )?;

    Ok(initial_sighash.clone())
}

fn verify_multisig_address(
    hash_mode: &AddressHashMode,
    signatures_required: u16,
    signer: &Hash160,
    pubkeys: &[Secp256k1PublicKey],
) -> Result<(), AuthError> {
    let signer_hash =
        public_keys_to_address_hash(*hash_mode, signatures_required as usize, pubkeys).ok_or_else(
            || AuthError::VerifyingError("Failed to generate address from public keys".to_string()),
        )?;

    if signer_hash.as_bytes() != signer.as_bytes() {
        return Err(AuthError::VerifyingError(format!(
            "Signer hash does not equal hash of public key(s): {} != {}",
            signer_hash, signer
        )));
    }

    Ok(())
}

fn decode_public_key(pubkey: &Secp256k1PublicKeyBytes) -> Result<Secp256k1PublicKey, AuthError> {
    Secp256k1PublicKey::from_public_key_bytes(pubkey)
        .map_err(|e| AuthError::VerifyingError(e.to_string()))
}

pub fn public_keys_to_address_hash<K>(
    hash_mode: AddressHashMode,
    signatures_required: usize,
    pubkeys: &[K],
) -> Option<Hash160>
where
    K: VerifyingKey,
{
    if pubkeys.len() < signatures_required {
        return None;
    }

    match hash_mode {
        AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH => {
            if signatures_required != 1 || pubkeys.len() != 1 {
                return None;
            }
        }
        _ => {}
    }

    match hash_mode {
        AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH => {
            for pubkey in pubkeys {
                if !is_compressed_public_key(pubkey) {
                    return None;
                }
            }
        }
        _ => {}
    }

    Some(match hash_mode {
        AddressHashMode::SerializeP2PKH => to_bits_p2pkh(&pubkeys[0]),
        AddressHashMode::SerializeP2SH => to_bits_p2sh(signatures_required, pubkeys),
        AddressHashMode::SerializeP2WPKH => to_bits_p2sh_p2wpkh(&pubkeys[0]),
        AddressHashMode::SerializeP2WSH => to_bits_p2sh_p2wsh(signatures_required, pubkeys),
    })
}

fn is_compressed_public_key<K>(pubkey: &K) -> bool
where
    K: VerifyingKey,
{
    pubkey.to_bytes().len() == COMPRESSED_PUBLIC_KEY_ENCODED_SIZE
}

fn to_bits_p2pkh<K>(pubkey: &K) -> Hash160
where
    K: VerifyingKey,
{
    Hash160::from_data(&pubkey.to_bytes())
}

fn to_bits_p2sh<K>(signatures_required: usize, pubkeys: &[K]) -> Hash160
where
    K: VerifyingKey,
{
    let mut bldr = Builder::new();
    bldr = bldr.push_int(signatures_required as i64);
    for pubkey in pubkeys {
        bldr = bldr.push_slice(push_bytes(pubkey.to_bytes()));
    }
    bldr = bldr.push_int(pubkeys.len() as i64);
    bldr = bldr.push_opcode(btc_opcodes::OP_CHECKMULTISIG);

    Hash160::from_data(bldr.into_script().as_bytes())
}

fn to_bits_p2sh_p2wpkh<K>(pubkey: &K) -> Hash160
where
    K: VerifyingKey,
{
    let key_hash = Hash160::from_data(&pubkey.to_bytes());
    let script = Builder::new()
        .push_int(0)
        .push_slice(key_hash.as_bytes())
        .into_script();

    Hash160::from_data(script.as_bytes())
}

fn to_bits_p2sh_p2wsh<K>(signatures_required: usize, pubkeys: &[K]) -> Hash160
where
    K: VerifyingKey,
{
    let mut bldr = Builder::new();
    bldr = bldr.push_int(signatures_required as i64);
    for pubkey in pubkeys {
        bldr = bldr.push_slice(push_bytes(pubkey.to_bytes()));
    }
    bldr = bldr.push_int(pubkeys.len() as i64);
    bldr = bldr.push_opcode(btc_opcodes::OP_CHECKMULTISIG);

    let script_hash = Sha256Sum::from_data(bldr.into_script().as_bytes());
    let witness_script = Builder::new()
        .push_int(0)
        .push_slice(script_hash.as_bytes())
        .into_script();

    Hash160::from_data(witness_script.as_bytes())
}

fn push_bytes(bytes: Vec<u8>) -> PushBytesBuf {
    PushBytesBuf::try_from(bytes).expect("public key bytes should fit in a Bitcoin push")
}
