use core::{error, fmt};

pub use stacks_crypto::address::public_keys_to_address_hash;
use stacks_crypto::hash::TxidDigest;
use stacks_crypto::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey, SigningKey};
use stacks_primitives::address::AddressHashMode;
use stacks_primitives::hash::{Hash160, Txid};
use stacks_primitives::secp256k1::{MESSAGE_SIGNATURE_ENCODED_SIZE, MessageSignature};

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

/// Selects whether transaction signature verification enforces normalized low-S signatures.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TransactionAuthVerificationMode {
    EnforceLowS,
    AllowHighS,
}

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
            TransactionAuthField::PublicKey(pubk) => Ok(pubk.clone()),
            TransactionAuthField::Signature(key_fmt, sig) => {
                let mut pubk = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
                    sighash_bytes,
                    sig,
                )
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
    mode: TransactionAuthVerificationMode,
) -> Result<(Secp256k1PublicKey, Txid), AuthError> {
    let sighash_presign = make_sighash_presign(cur_sighash, cond_code, tx_fee, nonce);

    let pubk = match mode {
        TransactionAuthVerificationMode::EnforceLowS => {
            Secp256k1PublicKey::recover_to_pubkey(sighash_presign.as_bytes(), sig)
        }
        TransactionAuthVerificationMode::AllowHighS => {
            Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
                sighash_presign.as_bytes(),
                sig,
            )
        }
    };
    let mut pubk = pubk.map_err(|ve| AuthError::VerifyingError(ve.to_string()))?;

    match key_encoding {
        TransactionPublicKeyEncoding::Compressed => pubk.set_compressed(true),
        TransactionPublicKeyEncoding::Uncompressed => pubk.set_compressed(false),
    };

    let next_sighash = make_sighash_postsign(&sighash_presign, &pubk, sig);
    Ok((pubk, next_sighash))
}

impl TransactionSpendingCondition {
    pub fn make_sighash_presign(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
    ) -> Txid {
        make_sighash_presign(cur_sighash, cond_code, tx_fee, nonce)
    }

    pub fn make_sighash_postsign(
        cur_sighash: &Txid,
        public_key: &Secp256k1PublicKey,
        signature: &MessageSignature,
    ) -> Txid {
        make_sighash_postsign(cur_sighash, public_key, signature)
    }

    pub fn next_signature(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        private_key: &Secp256k1PrivateKey,
    ) -> Result<(MessageSignature, Txid), AuthError> {
        next_signature(cur_sighash, cond_code, tx_fee, nonce, private_key)
    }

    pub fn next_verification(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        key_encoding: &TransactionPublicKeyEncoding,
        signature: &MessageSignature,
        mode: TransactionAuthVerificationMode,
    ) -> Result<(Secp256k1PublicKey, Txid), AuthError> {
        next_verification(
            cur_sighash,
            cond_code,
            tx_fee,
            nonce,
            key_encoding,
            signature,
            mode,
        )
    }
}

pub trait VerifySpendingConditionSignatures {
    fn verify_signatures(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        mode: TransactionAuthVerificationMode,
    ) -> Result<Txid, AuthError>;
}

impl VerifySpendingConditionSignatures for TransactionSpendingCondition {
    fn verify_signatures(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        mode: TransactionAuthVerificationMode,
    ) -> Result<Txid, AuthError> {
        match self {
            TransactionSpendingCondition::Singlesig(data) => {
                verify_singlesig(data, initial_sighash, cond_code, mode)
            }
            TransactionSpendingCondition::Multisig(data) => {
                verify_multisig(data, initial_sighash, cond_code, mode)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(data) => {
                verify_order_independent_multisig(data, initial_sighash, cond_code, mode)
            }
        }
    }
}

fn verify_singlesig(
    condition: &SinglesigSpendingCondition,
    initial_sighash: &Txid,
    cond_code: &TransactionAuthFlags,
    mode: TransactionAuthVerificationMode,
) -> Result<Txid, AuthError> {
    let (pubkey, next_sighash) = next_verification(
        initial_sighash,
        cond_code,
        condition.tx_fee,
        condition.nonce,
        &condition.key_encoding,
        &condition.signature,
        mode,
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
    mode: TransactionAuthVerificationMode,
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
                pubkey.clone()
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
                    mode,
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
    mode: TransactionAuthVerificationMode,
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
                pubkey.clone()
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
                    mode,
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

#[cfg(all(test, feature = "testing"))]
mod tests {
    use stacks_crypto::secp256k1::MessageSignatureCryptoExt as _;

    use super::*;

    #[test]
    fn high_s_verification_is_selected_by_mode() {
        let private_key = Secp256k1PrivateKey::from_seed(&[7; 32]);
        let initial_sighash = Txid([3; 32]);
        let auth_flag = TransactionAuthFlags::AuthStandard;
        let (signature, _) = next_signature(&initial_sighash, &auth_flag, 10, 11, &private_key)
            .expect("signature generation should succeed");
        let high_s_signature = signature.with_negated_s();

        assert!(
            next_verification(
                &initial_sighash,
                &auth_flag,
                10,
                11,
                &TransactionPublicKeyEncoding::Compressed,
                &high_s_signature,
                TransactionAuthVerificationMode::EnforceLowS,
            )
            .is_err()
        );
        assert!(
            next_verification(
                &initial_sighash,
                &auth_flag,
                10,
                11,
                &TransactionPublicKeyEncoding::Compressed,
                &high_s_signature,
                TransactionAuthVerificationMode::AllowHighS,
            )
            .is_ok()
        );
    }
}
