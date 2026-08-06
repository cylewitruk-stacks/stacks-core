use std::io::{Read, Write};

use clarity_types::types::Value;
use clarity_types::version::ClarityVersion;
use stacks_codec::{
    BoundReader, Error as CodecError, MAX_MESSAGE_LEN, StacksMessageCodec,
    impl_byte_array_message_codec, read_next, write_next,
};
use stacks_crypto::block::BlockHeaderHashDigest as _;
use stacks_crypto::hash::{Hash160Digest as _, Sha512Trunc256Digest as _, TxidDigest as _};
use stacks_crypto::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey, SigningKey as _};
use stacks_crypto::vrf::VRFProof;
use stacks_primitives::block::{BlockHeaderHash, StacksMicroblockHeader};
use stacks_primitives::hash::{Hash160, Sha512Trunc256Sum, Txid};
use stacks_primitives::secp256k1::{COMPRESSED_PUBLIC_KEY_ENCODED_SIZE, MessageSignature};

use crate::auth::TransactionAuth;
use crate::auth_field::{
    TransactionAuthField, TransactionAuthFieldID, TransactionAuthFlags,
    TransactionPublicKeyEncoding,
};
use crate::payload::{
    CoinbasePayload, TokenTransferMemo, TransactionContractCall, TransactionPayload,
    TransactionPayloadID, TransactionSmartContract,
};
use crate::post_condition::{
    AssetInfo, AssetInfoID, FungibleConditionCode, NonfungibleConditionCode,
    PostConditionPrincipal, PostConditionPrincipalID, PoxConditionCode, TransactionPostCondition,
};
use crate::spend_condition::{
    MultisigHashMode, MultisigSpendingCondition, OrderIndependentMultisigHashMode,
    OrderIndependentMultisigSpendingCondition, SinglesigHashMode, SinglesigSpendingCondition,
    TransactionSpendingCondition,
};
use crate::tenure::{TenureChangeCause, TenureChangePayload};
use crate::transaction::{
    MAX_TRANSACTION_LEN, StacksTransaction, TransactionAnchorMode, TransactionPostConditionMode,
    TransactionVersion,
};
use crate::{AuthError, TransactionAuthVerificationMode};

impl_byte_array_message_codec!(CoinbasePayload, 32);
impl_byte_array_message_codec!(TokenTransferMemo, 34);

impl StacksMessageCodec for TenureChangeCause {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.as_u8())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let byte: u8 = read_next(fd)?;
        TenureChangeCause::try_from(byte).map_err(|_| {
            CodecError::DeserializeError(format!("Invalid tenure change cause: {byte}"))
        })
    }
}

impl StacksMessageCodec for TenureChangePayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.tenure_consensus_hash)?;
        write_next(fd, &self.prev_tenure_consensus_hash)?;
        write_next(fd, &self.burn_view_consensus_hash)?;
        write_next(fd, &self.previous_tenure_end)?;
        write_next(fd, &self.previous_tenure_blocks)?;
        write_next(fd, &self.cause)?;
        write_next(fd, &self.pubkey_hash)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(TenureChangePayload {
            tenure_consensus_hash: read_next(fd)?,
            prev_tenure_consensus_hash: read_next(fd)?,
            burn_view_consensus_hash: read_next(fd)?,
            previous_tenure_end: read_next(fd)?,
            previous_tenure_blocks: read_next(fd)?,
            cause: read_next(fd)?,
            pubkey_hash: read_next(fd)?,
        })
    }
}

impl StacksMessageCodec for TransactionAuthField {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            TransactionAuthField::PublicKey(pubkey) => {
                let field_id = if pubkey.compressed() {
                    TransactionAuthFieldID::PublicKeyCompressed
                } else {
                    TransactionAuthFieldID::PublicKeyUncompressed
                };
                write_next(fd, &(field_id as u8))?;
                write_compressed_public_key(fd, pubkey)
            }
            TransactionAuthField::Signature(key_encoding, sig) => {
                let field_id = if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                    TransactionAuthFieldID::SignatureCompressed
                } else {
                    TransactionAuthFieldID::SignatureUncompressed
                };
                write_next(fd, &(field_id as u8))?;
                write_next(fd, sig)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let field_id: u8 = read_next(fd)?;
        match field_id {
            x if x == TransactionAuthFieldID::PublicKeyCompressed as u8 => {
                let pubkey = read_compressed_public_key(fd, true)?;
                Ok(TransactionAuthField::PublicKey(pubkey))
            }
            x if x == TransactionAuthFieldID::PublicKeyUncompressed as u8 => {
                let pubkey = read_compressed_public_key(fd, false)?;
                Ok(TransactionAuthField::PublicKey(pubkey))
            }
            x if x == TransactionAuthFieldID::SignatureCompressed as u8 => {
                Ok(TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    read_next(fd)?,
                ))
            }
            x if x == TransactionAuthFieldID::SignatureUncompressed as u8 => {
                Ok(TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Uncompressed,
                    read_next(fd)?,
                ))
            }
            _ => Err(CodecError::DeserializeError(format!(
                "Failed to parse auth field: unknown auth field ID {field_id}"
            ))),
        }
    }
}

fn write_compressed_public_key<W: Write>(
    fd: &mut W,
    pubkey: &Secp256k1PublicKey,
) -> Result<(), CodecError> {
    fd.write_all(&pubkey.to_bytes_compressed())
        .map_err(CodecError::WriteError)
}

fn read_compressed_public_key<R: Read>(
    fd: &mut R,
    compressed: bool,
) -> Result<Secp256k1PublicKey, CodecError> {
    let mut buf = [0u8; COMPRESSED_PUBLIC_KEY_ENCODED_SIZE];
    fd.read_exact(&mut buf).map_err(CodecError::ReadError)?;
    let mut crypto_key = Secp256k1PublicKey::from_slice(&buf)
        .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
    crypto_key.set_compressed(compressed);
    Ok(crypto_key)
}

impl StacksMessageCodec for SinglesigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &(self.key_encoding as u8))?;
        write_next(fd, &self.signature)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = SinglesigHashMode::from_u8(hash_mode_u8).ok_or_else(|| {
            CodecError::DeserializeError(format!(
                "Failed to parse singlesig spending condition: unknown hash mode {hash_mode_u8}"
            ))
        })?;
        let signer = read_next(fd)?;
        let nonce = read_next(fd)?;
        let tx_fee = read_next(fd)?;
        let key_encoding_u8: u8 = read_next(fd)?;
        let key_encoding =
            TransactionPublicKeyEncoding::from_u8(key_encoding_u8).ok_or_else(|| {
                CodecError::DeserializeError(format!(
                    "Failed to parse singlesig spending condition: unknown key encoding {key_encoding_u8}"
                ))
            })?;
        let signature = read_next(fd)?;

        if hash_mode == SinglesigHashMode::P2WPKH
            && key_encoding != TransactionPublicKeyEncoding::Compressed
        {
            return Err(CodecError::DeserializeError(
                "Failed to parse singlesig spending condition: incompatible hash mode and key encoding"
                    .to_string(),
            ));
        }

        Ok(SinglesigSpendingCondition {
            hash_mode,
            signer,
            nonce,
            tx_fee,
            key_encoding,
            signature,
        })
    }
}

impl StacksMessageCodec for MultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = MultisigHashMode::from_u8(hash_mode_u8).ok_or_else(|| {
            CodecError::DeserializeError(format!(
                "Failed to parse multisig spending condition: unknown hash mode {hash_mode_u8}"
            ))
        })?;
        let signer = read_next(fd)?;
        let nonce = read_next(fd)?;
        let tx_fee = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;
        let signatures_required = read_next(fd)?;

        validate_multisig_fields(
            &fields,
            signatures_required,
            hash_mode == MultisigHashMode::P2WSH,
            true,
            "multisig",
        )?;

        Ok(MultisigSpendingCondition {
            hash_mode,
            signer,
            nonce,
            tx_fee,
            fields,
            signatures_required,
        })
    }
}

impl StacksMessageCodec for OrderIndependentMultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode =
            OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).ok_or_else(|| {
                CodecError::DeserializeError(format!(
                    "Failed to parse order independent multisig spending condition: unknown hash mode {hash_mode_u8}"
                ))
            })?;
        let signer = read_next(fd)?;
        let nonce = read_next(fd)?;
        let tx_fee = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;
        let signatures_required = read_next(fd)?;

        validate_multisig_fields(
            &fields,
            signatures_required,
            hash_mode == OrderIndependentMultisigHashMode::P2WSH,
            false,
            "order independent multisig",
        )?;

        Ok(OrderIndependentMultisigSpendingCondition {
            hash_mode,
            signer,
            nonce,
            tx_fee,
            fields,
            signatures_required,
        })
    }
}

fn validate_multisig_fields(
    fields: &[TransactionAuthField],
    signatures_required: u16,
    require_compressed: bool,
    exact_signature_count: bool,
    label: &str,
) -> Result<(), CodecError> {
    let mut num_sigs_given = 0u16;
    let mut have_uncompressed = false;
    for field in fields {
        match field {
            TransactionAuthField::Signature(key_encoding, _) => {
                num_sigs_given = num_sigs_given.checked_add(1).ok_or_else(|| {
                    CodecError::DeserializeError(format!(
                        "Failed to parse {label} spending condition: too many signatures"
                    ))
                })?;
                have_uncompressed |= *key_encoding == TransactionPublicKeyEncoding::Uncompressed;
            }
            TransactionAuthField::PublicKey(pubkey) => {
                have_uncompressed |= !pubkey.compressed();
            }
        }
    }

    let signature_count_ok = if exact_signature_count {
        num_sigs_given == signatures_required
    } else {
        num_sigs_given >= signatures_required
    };
    if !signature_count_ok {
        return Err(CodecError::DeserializeError(format!(
            "Failed to parse {label} spending condition: got {num_sigs_given} sigs, expected {signatures_required}"
        )));
    }
    if require_compressed && have_uncompressed {
        return Err(CodecError::DeserializeError(format!(
            "Failed to parse {label} spending condition: expected compressed keys only"
        )));
    }
    Ok(())
}

impl StacksMessageCodec for TransactionSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            TransactionSpendingCondition::Singlesig(data) => data.consensus_serialize(fd),
            TransactionSpendingCondition::Multisig(data) => data.consensus_serialize(fd),
            TransactionSpendingCondition::OrderIndependentMultisig(data) => {
                data.consensus_serialize(fd)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let peek_buf = [hash_mode_u8];
        let mut replay = peek_buf.chain(fd);
        if SinglesigHashMode::from_u8(hash_mode_u8).is_some() {
            Ok(TransactionSpendingCondition::Singlesig(read_next(
                &mut replay,
            )?))
        } else if MultisigHashMode::from_u8(hash_mode_u8).is_some() {
            Ok(TransactionSpendingCondition::Multisig(read_next(
                &mut replay,
            )?))
        } else if OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).is_some() {
            Ok(TransactionSpendingCondition::OrderIndependentMultisig(
                read_next(&mut replay)?,
            ))
        } else {
            Err(CodecError::DeserializeError(format!(
                "Failed to parse spending condition: invalid hash mode {hash_mode_u8}"
            )))
        }
    }
}

impl StacksMessageCodec for TransactionAuth {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            TransactionAuth::Standard(origin_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthStandard as u8))?;
                write_next(fd, origin_condition)
            }
            TransactionAuth::Sponsored(origin_condition, sponsor_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthSponsored as u8))?;
                write_next(fd, origin_condition)?;
                write_next(fd, sponsor_condition)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_id: u8 = read_next(fd)?;
        match type_id {
            x if x == TransactionAuthFlags::AuthStandard as u8 => {
                Ok(TransactionAuth::Standard(read_next(fd)?))
            }
            x if x == TransactionAuthFlags::AuthSponsored as u8 => {
                Ok(TransactionAuth::Sponsored(read_next(fd)?, read_next(fd)?))
            }
            _ => Err(CodecError::DeserializeError(format!(
                "Failed to parse transaction authorization: unknown auth type {type_id}"
            ))),
        }
    }
}

impl StacksMessageCodec for TransactionContractCall {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.function_name)?;
        write_next(fd, &self.function_args)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let address = read_next(fd)?;
        let contract_name = read_next(fd)?;
        let function_name = read_next(fd)?;
        let function_args = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        Ok(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args,
        })
    }
}

impl StacksMessageCodec for TransactionSmartContract {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.name)?;
        write_next(fd, &self.code_body)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(TransactionSmartContract {
            name: read_next(fd)?,
            code_body: read_next(fd)?,
        })
    }
}

impl StacksMessageCodec for AssetInfo {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.contract_address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.asset_name)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(AssetInfo {
            contract_address: read_next(fd)?,
            contract_name: read_next(fd)?,
            asset_name: read_next(fd)?,
        })
    }
}

impl StacksMessageCodec for PostConditionPrincipal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            PostConditionPrincipal::Origin => {
                write_next(fd, &(PostConditionPrincipalID::Origin as u8))
            }
            PostConditionPrincipal::Standard(address) => {
                write_next(fd, &(PostConditionPrincipalID::Standard as u8))?;
                write_next(fd, address)
            }
            PostConditionPrincipal::Contract(address, contract_name) => {
                write_next(fd, &(PostConditionPrincipalID::Contract as u8))?;
                write_next(fd, address)?;
                write_next(fd, contract_name)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let principal_id: u8 = read_next(fd)?;
        match principal_id {
            x if x == PostConditionPrincipalID::Origin as u8 => Ok(PostConditionPrincipal::Origin),
            x if x == PostConditionPrincipalID::Standard as u8 => {
                Ok(PostConditionPrincipal::Standard(read_next(fd)?))
            }
            x if x == PostConditionPrincipalID::Contract as u8 => Ok(
                PostConditionPrincipal::Contract(read_next(fd)?, read_next(fd)?),
            ),
            _ => Err(CodecError::DeserializeError(format!(
                "Failed to parse post-condition principal: unknown principal ID {principal_id}"
            ))),
        }
    }
}

impl StacksMessageCodec for TransactionPostCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            TransactionPostCondition::STX(principal, condition, amount) => {
                write_next(fd, &(AssetInfoID::STX as u8))?;
                write_next(fd, principal)?;
                write_next(fd, &(*condition as u8))?;
                write_next(fd, amount)
            }
            TransactionPostCondition::Fungible(principal, asset_info, condition, amount) => {
                write_next(fd, &(AssetInfoID::FungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, &(*condition as u8))?;
                write_next(fd, amount)
            }
            TransactionPostCondition::Nonfungible(
                principal,
                asset_info,
                asset_value,
                condition,
            ) => {
                write_next(fd, &(AssetInfoID::NonfungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, asset_value)?;
                write_next(fd, &(*condition as u8))
            }
            TransactionPostCondition::Staking(principal, condition, amount) => {
                write_next(fd, &(AssetInfoID::Staking as u8))?;
                write_next(fd, principal)?;
                write_next(fd, &(*condition as u8))?;
                write_next(fd, amount)
            }
            TransactionPostCondition::Pox(principal, condition) => {
                write_next(fd, &(AssetInfoID::Pox as u8))?;
                write_next(fd, principal)?;
                write_next(fd, &(*condition as u8))
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let asset_info_id: u8 = read_next(fd)?;
        match AssetInfoID::from_u8(asset_info_id) {
            Some(AssetInfoID::STX) => {
                let principal = read_next(fd)?;
                let condition_u8 = read_next(fd)?;
                let condition = FungibleConditionCode::from_u8(condition_u8).ok_or_else(|| {
                    CodecError::DeserializeError(format!(
                        "Failed to parse STX post-condition: unknown condition code {condition_u8}"
                    ))
                })?;
                Ok(TransactionPostCondition::STX(
                    principal,
                    condition,
                    read_next(fd)?,
                ))
            }
            Some(AssetInfoID::FungibleAsset) => {
                let principal = read_next(fd)?;
                let asset = read_next(fd)?;
                let condition_u8 = read_next(fd)?;
                let condition = FungibleConditionCode::from_u8(condition_u8).ok_or_else(|| {
                    CodecError::DeserializeError(format!(
                        "Failed to parse fungible post-condition: unknown condition code {condition_u8}"
                    ))
                })?;
                Ok(TransactionPostCondition::Fungible(
                    principal,
                    asset,
                    condition,
                    read_next(fd)?,
                ))
            }
            Some(AssetInfoID::NonfungibleAsset) => {
                let principal = read_next(fd)?;
                let asset = read_next(fd)?;
                let asset_value = read_next(fd)?;
                let condition_u8 = read_next(fd)?;
                let condition =
                    NonfungibleConditionCode::from_u8(condition_u8).ok_or_else(|| {
                        CodecError::DeserializeError(format!(
                            "Failed to parse non-fungible post-condition: unknown condition code {condition_u8}"
                        ))
                    })?;
                Ok(TransactionPostCondition::Nonfungible(
                    principal,
                    asset,
                    asset_value,
                    condition,
                ))
            }
            Some(AssetInfoID::Staking) => {
                let principal = read_next(fd)?;
                let condition_u8 = read_next(fd)?;
                let condition = FungibleConditionCode::from_u8(condition_u8).ok_or_else(|| {
                    CodecError::DeserializeError(format!(
                        "Failed to parse staking post-condition: unknown condition code {condition_u8}"
                    ))
                })?;
                Ok(TransactionPostCondition::Staking(
                    principal,
                    condition,
                    read_next(fd)?,
                ))
            }
            Some(AssetInfoID::Pox) => {
                let principal = read_next(fd)?;
                let condition_u8 = read_next(fd)?;
                let condition = PoxConditionCode::from_u8(condition_u8).ok_or_else(|| {
                    CodecError::DeserializeError(format!(
                        "Failed to parse PoX post-condition: unknown condition code {condition_u8}"
                    ))
                })?;
                Ok(TransactionPostCondition::Pox(principal, condition))
            }
            None => Err(CodecError::DeserializeError(format!(
                "Failed to parse post-condition: unknown asset info ID {asset_info_id}"
            ))),
        }
    }
}

impl StacksMessageCodec for TransactionPayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            TransactionPayload::TokenTransfer(address, amount, memo) => {
                write_next(fd, &(TransactionPayloadID::TokenTransfer as u8))?;
                write_next(fd, address)?;
                write_next(fd, amount)?;
                write_next(fd, memo)
            }
            TransactionPayload::ContractCall(contract_call) => {
                write_next(fd, &(TransactionPayloadID::ContractCall as u8))?;
                write_next(fd, contract_call)
            }
            TransactionPayload::SmartContract(smart_contract, version_opt) => {
                if let Some(version) = version_opt {
                    write_next(fd, &(TransactionPayloadID::VersionedSmartContract as u8))?;
                    clarity_version_consensus_serialize(version, fd)?;
                } else {
                    write_next(fd, &(TransactionPayloadID::SmartContract as u8))?;
                }
                write_next(fd, smart_contract)
            }
            TransactionPayload::PoisonMicroblock(header_1, header_2) => {
                write_next(fd, &(TransactionPayloadID::PoisonMicroblock as u8))?;
                write_next(fd, header_1)?;
                write_next(fd, header_2)
            }
            TransactionPayload::Coinbase(payload, recipient_opt, vrf_proof_opt) => {
                match (recipient_opt, vrf_proof_opt) {
                    (None, None) => {
                        write_next(fd, &(TransactionPayloadID::Coinbase as u8))?;
                        write_next(fd, payload)
                    }
                    (Some(recipient), None) => {
                        write_next(fd, &(TransactionPayloadID::CoinbaseToAltRecipient as u8))?;
                        write_next(fd, payload)?;
                        write_next(fd, &Value::Principal(recipient.clone()))
                    }
                    (recipient_opt, Some(vrf_proof)) => {
                        write_next(fd, &(TransactionPayloadID::NakamotoCoinbase as u8))?;
                        write_next(fd, payload)?;
                        match recipient_opt {
                            Some(recipient) => {
                                let recipient = Value::some(Value::Principal(recipient.clone()))
                                    .map_err(|e| CodecError::SerializeError(e.to_string()))?;
                                write_next(fd, &recipient)?
                            }
                            None => write_next(fd, &Value::none())?,
                        }
                        write_next(fd, vrf_proof)
                    }
                }
            }
            TransactionPayload::TenureChange(payload) => {
                write_next(fd, &(TransactionPayloadID::TenureChange as u8))?;
                write_next(fd, payload)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_id_u8: u8 = read_next(fd)?;
        let type_id = TransactionPayloadID::from_u8(type_id_u8).ok_or_else(|| {
            CodecError::DeserializeError(format!(
                "Failed to parse transaction -- unknown payload ID {type_id_u8}"
            ))
        })?;
        let payload = match type_id {
            TransactionPayloadID::TokenTransfer => {
                TransactionPayload::TokenTransfer(read_next(fd)?, read_next(fd)?, read_next(fd)?)
            }
            TransactionPayloadID::ContractCall => {
                TransactionPayload::ContractCall(read_next::<TransactionContractCall, _>(fd)?)
            }
            TransactionPayloadID::SmartContract => TransactionPayload::SmartContract(
                read_next::<TransactionSmartContract, _>(fd)?,
                None,
            ),
            TransactionPayloadID::VersionedSmartContract => {
                let version = clarity_version_consensus_deserialize(fd)?;
                TransactionPayload::SmartContract(
                    read_next::<TransactionSmartContract, _>(fd)?,
                    Some(version),
                )
            }
            TransactionPayloadID::PoisonMicroblock => {
                let header_1 = read_next::<StacksMicroblockHeader, _>(fd)?;
                let header_2 = read_next::<StacksMicroblockHeader, _>(fd)?;
                if header_1 == header_2 {
                    return Err(CodecError::DeserializeError(
                        "Failed to parse transaction -- microblock headers match".into(),
                    ));
                }
                if header_1.sequence != header_2.sequence
                    && header_1.prev_block != header_2.prev_block
                {
                    return Err(CodecError::DeserializeError(
                        "Failed to parse transaction -- microblock headers do not identify a fork"
                            .into(),
                    ));
                }
                TransactionPayload::PoisonMicroblock(header_1, header_2)
            }
            TransactionPayloadID::Coinbase => {
                TransactionPayload::Coinbase(read_next::<CoinbasePayload, _>(fd)?, None, None)
            }
            TransactionPayloadID::CoinbaseToAltRecipient => {
                let payload = read_next(fd)?;
                let principal_value: Value = read_next(fd)?;
                let Value::Principal(principal) = principal_value else {
                    return Err(CodecError::DeserializeError(
                        "Failed to parse coinbase transaction -- did not receive a recipient principal value".into(),
                    ));
                };
                TransactionPayload::Coinbase(payload, Some(principal), None)
            }
            TransactionPayloadID::NakamotoCoinbase => {
                let payload = read_next(fd)?;
                let principal_value_opt: Value = read_next(fd)?;
                let recipient_opt = if let Value::Optional(optional_data) = principal_value_opt {
                    match optional_data.data {
                        Some(value) => match *value {
                            Value::Principal(principal) => Some(principal),
                            _ => None,
                        },
                        None => None,
                    }
                } else {
                    return Err(CodecError::DeserializeError(
                        "Failed to parse nakamoto coinbase transaction -- did not receive an optional recipient principal value".into(),
                    ));
                };
                TransactionPayload::Coinbase(
                    payload,
                    recipient_opt,
                    Some(read_next::<VRFProof, _>(fd)?),
                )
            }
            TransactionPayloadID::TenureChange => TransactionPayload::TenureChange(read_next(fd)?),
        };
        Ok(payload)
    }
}

fn clarity_version_consensus_serialize<W: Write>(
    version: &ClarityVersion,
    fd: &mut W,
) -> Result<(), CodecError> {
    match version {
        ClarityVersion::Clarity1 => write_next(fd, &1u8),
        ClarityVersion::Clarity2 => write_next(fd, &2u8),
        ClarityVersion::Clarity3 => write_next(fd, &3u8),
        ClarityVersion::Clarity4 => write_next(fd, &4u8),
        ClarityVersion::Clarity5 => write_next(fd, &5u8),
        ClarityVersion::Clarity6 => write_next(fd, &6u8),
    }
}

fn clarity_version_consensus_deserialize<R: Read>(
    fd: &mut R,
) -> Result<ClarityVersion, CodecError> {
    let version_byte: u8 = read_next(fd)?;
    match version_byte {
        1 => Ok(ClarityVersion::Clarity1),
        2 => Ok(ClarityVersion::Clarity2),
        3 => Ok(ClarityVersion::Clarity3),
        4 => Ok(ClarityVersion::Clarity4),
        5 => Ok(ClarityVersion::Clarity5),
        6 => Ok(ClarityVersion::Clarity6),
        _ => Err(CodecError::DeserializeError(format!(
            "Failed to parse clarity version: {version_byte}"
        ))),
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(self.version as u8))?;
        write_next(fd, &self.chain_id)?;
        write_next(fd, &self.auth)?;
        write_next(fd, &(self.anchor_mode as u8))?;
        write_next(fd, &(self.post_condition_mode as u8))?;
        write_next(fd, &self.post_conditions)?;
        write_next(fd, &self.payload)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        StacksTransaction::consensus_deserialize_with_len(fd).map(|(tx, _)| tx)
    }
}

impl StacksTransaction {
    pub fn txid(&self) -> Txid {
        let mut bytes = Vec::new();
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize transaction");
        Txid::from_stacks_tx(&bytes)
    }

    pub fn sign_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    pub fn verify_begin(&self) -> Txid {
        self.sign_begin()
    }

    pub fn verify(&self, mode: TransactionAuthVerificationMode) -> Result<(), AuthError> {
        self.auth.verify(&self.verify_begin(), mode)
    }

    pub fn verify_origin(&self, mode: TransactionAuthVerificationMode) -> Result<Txid, AuthError> {
        self.auth.verify_origin(&self.verify_begin(), mode)
    }

    fn sign_and_append(
        condition: &mut TransactionSpendingCondition,
        current_sighash: &Txid,
        auth_flag: TransactionAuthFlags,
        private_key: &Secp256k1PrivateKey,
    ) -> Result<Txid, AuthError> {
        let (signature, next_sighash) = crate::next_signature(
            current_sighash,
            &auth_flag,
            condition.tx_fee(),
            condition.nonce(),
            private_key,
        )?;
        let encoding = if private_key.compress_public() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };

        match condition {
            TransactionSpendingCondition::Singlesig(condition) => {
                condition.set_signature(signature);
                Ok(next_sighash)
            }
            TransactionSpendingCondition::Multisig(condition) => {
                condition.push_signature(encoding, signature);
                Ok(next_sighash)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(condition) => {
                condition.push_signature(encoding, signature);
                Ok(current_sighash.clone())
            }
        }
    }

    fn append_public_key(
        condition: &mut TransactionSpendingCondition,
        public_key: &Secp256k1PublicKey,
    ) -> Result<(), AuthError> {
        let public_key = public_key.clone();
        match condition {
            TransactionSpendingCondition::Multisig(condition) => {
                condition.push_public_key(public_key);
                Ok(())
            }
            TransactionSpendingCondition::OrderIndependentMultisig(condition) => {
                condition.push_public_key(public_key);
                Ok(())
            }
            TransactionSpendingCondition::Singlesig(_) => Err(AuthError::SigningError(
                "Not a multisig condition".to_owned(),
            )),
        }
    }

    pub fn sign_next_origin(
        &mut self,
        current_sighash: &Txid,
        private_key: &Secp256k1PrivateKey,
    ) -> Result<Txid, AuthError> {
        Self::sign_and_append(
            self.auth.origin_mut(),
            current_sighash,
            TransactionAuthFlags::AuthStandard,
            private_key,
        )
    }

    pub fn append_next_origin(&mut self, public_key: &Secp256k1PublicKey) -> Result<(), AuthError> {
        Self::append_public_key(self.auth.origin_mut(), public_key)
    }

    pub fn sign_next_sponsor(
        &mut self,
        current_sighash: &Txid,
        private_key: &Secp256k1PrivateKey,
    ) -> Result<Txid, AuthError> {
        let sponsor = self.auth.sponsor_mut().ok_or_else(|| {
            AuthError::SigningError(
                "Cannot sign standard authorization with a sponsoring private key".to_owned(),
            )
        })?;
        Self::sign_and_append(
            sponsor,
            current_sighash,
            TransactionAuthFlags::AuthSponsored,
            private_key,
        )
    }

    pub fn append_next_sponsor(
        &mut self,
        public_key: &Secp256k1PublicKey,
    ) -> Result<(), AuthError> {
        let sponsor = self.auth.sponsor_mut().ok_or_else(|| {
            AuthError::SigningError(
                "Cannot appned a public key to the sponsor of a standard auth condition".to_owned(),
            )
        })?;
        Self::append_public_key(sponsor, public_key)
    }

    pub fn consensus_deserialize_with_len<R: Read>(
        fd: &mut R,
    ) -> Result<(StacksTransaction, u64), CodecError> {
        let mut bound_read = BoundReader::from_reader(fd, MAX_TRANSACTION_LEN.into());

        let version_u8: u8 = read_next(&mut bound_read)?;
        let chain_id = read_next(&mut bound_read)?;
        let auth = read_next(&mut bound_read)?;
        let anchor_mode_u8: u8 = read_next(&mut bound_read)?;
        let post_condition_mode_u8: u8 = read_next(&mut bound_read)?;
        let post_conditions = read_next(&mut bound_read)?;
        let payload = read_next(&mut bound_read)?;

        let version = if version_u8 & 0x80 == 0 {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let anchor_mode = match anchor_mode_u8 {
            1 => TransactionAnchorMode::OnChainOnly,
            2 => TransactionAnchorMode::OffChainOnly,
            3 => TransactionAnchorMode::Any,
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse transaction: invalid anchor mode {anchor_mode_u8}"
                )));
            }
        };

        match &payload {
            TransactionPayload::PoisonMicroblock(..)
                if anchor_mode != TransactionAnchorMode::OnChainOnly =>
            {
                return Err(CodecError::DeserializeError(
                    "Failed to parse transaction: invalid anchor mode for PoisonMicroblock".into(),
                ));
            }
            TransactionPayload::Coinbase(..)
                if anchor_mode != TransactionAnchorMode::OnChainOnly =>
            {
                return Err(CodecError::DeserializeError(
                    "Failed to parse transaction: invalid anchor mode for Coinbase".into(),
                ));
            }
            _ => {}
        }

        let post_condition_mode = match post_condition_mode_u8 {
            1 => TransactionPostConditionMode::Allow,
            2 => TransactionPostConditionMode::Deny,
            3 => TransactionPostConditionMode::Originator,
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse transaction: invalid post-condition mode {post_condition_mode_u8}"
                )));
            }
        };

        let num_read = bound_read.num_read();

        Ok((
            StacksTransaction {
                version,
                chain_id,
                auth,
                anchor_mode,
                post_condition_mode,
                post_conditions,
                payload,
            },
            num_read,
        ))
    }

    pub fn tx_len(&self) -> u64 {
        let mut bytes = Vec::new();
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize transaction");
        u64::try_from(bytes.len()).expect("transaction length exceeds u64")
    }
}

impl std::hash::Hash for StacksTransaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.txid().hash(state);
    }
}

/// Transaction-specific signing and hashing behavior for microblock headers.
pub trait StacksMicroblockHeaderExt {
    fn sign(&mut self, private_key: &Secp256k1PrivateKey) -> Result<(), AuthError>;
    fn check_recover_pubkey(&self) -> Result<Hash160, AuthError>;
    fn verify(&self, public_key_hash: &Hash160) -> Result<(), AuthError>;
    fn block_hash(&self) -> BlockHeaderHash;
    fn from_parent_unsigned(
        parent: &Self,
        transaction_merkle_root: &Sha512Trunc256Sum,
    ) -> Option<Self>
    where
        Self: Sized;
}

fn serialize_microblock_header<W: Write>(
    header: &StacksMicroblockHeader,
    writer: &mut W,
    empty_signature: bool,
) -> Result<(), CodecError> {
    write_next(writer, &header.version)?;
    write_next(writer, &header.sequence)?;
    write_next(writer, &header.prev_block)?;
    write_next(writer, &header.tx_merkle_root)?;
    let empty = MessageSignature::empty();
    write_next(
        writer,
        if empty_signature {
            &empty
        } else {
            &header.signature
        },
    )
}

impl StacksMicroblockHeaderExt for StacksMicroblockHeader {
    fn sign(&mut self, private_key: &Secp256k1PrivateKey) -> Result<(), AuthError> {
        let mut bytes = Vec::new();
        serialize_microblock_header(self, &mut bytes, true)
            .expect("BUG: failed to serialize microblock header");
        let digest = Sha512Trunc256Sum::from_data(&bytes);
        self.signature = private_key
            .sign(digest.as_bytes())
            .map_err(|error| AuthError::SigningError(error.to_owned()))?;
        Ok(())
    }

    fn check_recover_pubkey(&self) -> Result<Hash160, AuthError> {
        let mut bytes = Vec::new();
        serialize_microblock_header(self, &mut bytes, true)
            .expect("BUG: failed to serialize microblock header");
        let digest = Sha512Trunc256Sum::from_data(&bytes);
        let mut public_key = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
            digest.as_bytes(),
            &self.signature,
        )
        .map_err(|_| {
            AuthError::VerifyingError(
                "Failed to verify signature: failed to recover public key".to_owned(),
            )
        })?;
        public_key.set_compressed(true);
        Ok(Hash160::from_node_public_key(&public_key))
    }

    fn verify(&self, public_key_hash: &Hash160) -> Result<(), AuthError> {
        let recovered = self.check_recover_pubkey()?;
        if recovered == *public_key_hash {
            Ok(())
        } else {
            Err(AuthError::VerifyingError(format!(
                "Failed to verify signature: public key did not recover to expected hash {}",
                recovered.to_hex()
            )))
        }
    }

    fn block_hash(&self) -> BlockHeaderHash {
        let mut bytes = Vec::new();
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize microblock header");
        BlockHeaderHash::from_serialized_header(&bytes)
    }

    fn from_parent_unsigned(
        parent: &Self,
        transaction_merkle_root: &Sha512Trunc256Sum,
    ) -> Option<Self> {
        Some(Self {
            version: 0,
            sequence: parent.sequence.checked_add(1)?,
            prev_block: parent.block_hash(),
            tx_merkle_root: transaction_merkle_root.clone(),
            signature: MessageSignature::empty(),
        })
    }
}

#[cfg(test)]
mod tests {
    use clarity_types::representations::{ClarityName, ContractName};
    use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
    use stacks_codec::testing::check_codec_and_corruption;
    use stacks_primitives::StacksString;
    use stacks_primitives::address::StacksAddress;
    use stacks_primitives::block::{ConsensusHash, StacksBlockId};

    use super::*;

    const EMPTY_MICROBLOCK_PARENT_HASH: BlockHeaderHash = BlockHeaderHash([0; 32]);

    fn test_auth() -> TransactionAuth {
        let private_key = Secp256k1PrivateKey::from_seed(&[0x42; 32]);
        TransactionAuth::from_p2pkh(&private_key).unwrap()
    }

    fn check_roundtrip(post_condition: TransactionPostCondition, expected: &[u8]) {
        assert_eq!(post_condition.serialize_to_vec(), expected);
        let mut bytes = expected;
        assert_eq!(
            TransactionPostCondition::consensus_deserialize(&mut bytes).unwrap(),
            post_condition
        );
    }

    fn create_token_transfer_bytes(
        recipient: &PrincipalData,
        amount: u64,
        memo: &TokenTransferMemo,
    ) -> Vec<u8> {
        let mut bytes = vec![TransactionPayloadID::TokenTransfer as u8];
        recipient.consensus_serialize(&mut bytes).unwrap();
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&memo.0);
        bytes
    }

    fn sample_contract_call() -> TransactionContractCall {
        TransactionContractCall {
            address: StacksAddress::new(1, Hash160([0xff; 20])).unwrap(),
            contract_name: ContractName::try_from("hello-contract-name").unwrap(),
            function_name: ClarityName::try_from("hello-function-name").unwrap(),
            function_args: vec![Value::Int(0)],
        }
    }

    fn sample_smart_contract() -> TransactionSmartContract {
        TransactionSmartContract {
            name: ContractName::try_from("hello-contract-name").unwrap(),
            code_body: StacksString::try_from_str("hello contract code body").unwrap(),
        }
    }

    fn serialize_contract_call(contract_call: &TransactionContractCall) -> Vec<u8> {
        let mut bytes = vec![];
        contract_call
            .address
            .consensus_serialize(&mut bytes)
            .unwrap();
        contract_call
            .contract_name
            .consensus_serialize(&mut bytes)
            .unwrap();
        contract_call
            .function_name
            .consensus_serialize(&mut bytes)
            .unwrap();
        contract_call
            .function_args
            .consensus_serialize(&mut bytes)
            .unwrap();
        bytes
    }

    fn serialize_smart_contract(
        smart_contract: &TransactionSmartContract,
        version: Option<ClarityVersion>,
    ) -> Vec<u8> {
        let mut bytes = vec![];
        if let Some(version) = version {
            clarity_version_consensus_serialize(&version, &mut bytes).unwrap();
        }
        smart_contract.name.consensus_serialize(&mut bytes).unwrap();
        smart_contract
            .code_body
            .consensus_serialize(&mut bytes)
            .unwrap();
        bytes
    }

    fn payload_bytes(id: TransactionPayloadID, payload: impl IntoIterator<Item = u8>) -> Vec<u8> {
        std::iter::once(id as u8).chain(payload).collect()
    }

    #[test]
    fn test_transaction_payload_token_transfer() {
        let standard = PrincipalData::from(StacksAddress::new(1, Hash160([0xff; 20])).unwrap());
        let contract = PrincipalData::from(QualifiedContractIdentifier {
            issuer: StacksAddress::new(1, Hash160([0xff; 20])).unwrap().into(),
            name: ContractName::from_literal("foo-contract"),
        });

        for recipient in [standard, contract] {
            let memo = TokenTransferMemo([1; 34]);
            let payload = TransactionPayload::TokenTransfer(recipient.clone(), 123, memo.clone());
            let expected = create_token_transfer_bytes(&recipient, 123, &memo);
            check_codec_and_corruption(&payload, &expected);
        }
    }

    #[test]
    fn test_transaction_contract_call_codec() {
        let contract_call = sample_contract_call();
        check_codec_and_corruption(&contract_call, &serialize_contract_call(&contract_call));
    }

    #[test]
    fn test_transaction_smart_contract_codec() {
        let smart_contract = sample_smart_contract();
        check_codec_and_corruption(
            &smart_contract,
            &serialize_smart_contract(&smart_contract, None),
        );
    }

    #[test]
    fn test_transaction_payload_versioned_contracts_codec() {
        for &version in ClarityVersion::ALL {
            let smart_contract = sample_smart_contract();
            let payload = TransactionPayload::SmartContract(smart_contract.clone(), Some(version));
            let expected = payload_bytes(
                TransactionPayloadID::VersionedSmartContract,
                serialize_smart_contract(&smart_contract, Some(version)),
            );
            check_codec_and_corruption(&payload, &expected);
        }
    }

    #[test]
    fn tx_stacks_transaction_payload_coinbase() {
        let payload = TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, None);
        let expected = payload_bytes(TransactionPayloadID::Coinbase, [0x12; 32]);
        check_codec_and_corruption(&payload, &expected);
    }

    #[test]
    fn tx_stacks_transaction_payload_nakamoto_coinbase() {
        let proof_bytes = const_hex::decode("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes).unwrap();
        let payload = TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof));

        let mut expected = payload_bytes(TransactionPayloadID::NakamotoCoinbase, [0x12; 32]);
        expected.push(0x09); // Clarity `none`
        expected.extend_from_slice(&proof_bytes);
        check_codec_and_corruption(&payload, &expected);
    }

    #[test]
    fn tx_stacks_transaction_payload_nakamoto_coinbase_alt_recipient() {
        let proof_bytes = const_hex::decode("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes).unwrap();
        let recipient = PrincipalData::from(QualifiedContractIdentifier {
            issuer: StacksAddress::new(1, Hash160([0xff; 20])).unwrap().into(),
            name: ContractName::from_literal("foo-contract"),
        });
        let payload =
            TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), Some(recipient), Some(proof));

        let mut expected = payload_bytes(TransactionPayloadID::NakamotoCoinbase, [0x12; 32]);
        expected.extend_from_slice(&[
            0x0a, // Clarity `some`
            0x06, // contract principal
            0x01, // address version
        ]);
        expected.extend_from_slice(&[0xff; 20]);
        expected.push(12);
        expected.extend_from_slice(b"foo-contract");
        expected.extend_from_slice(&proof_bytes);
        check_codec_and_corruption(&payload, &expected);
    }

    #[test]
    fn tx_stacks_transaction_payload_microblock_poison() {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH,
            tx_merkle_root: Sha512Trunc256Sum([1; 32]),
            signature: MessageSignature([2; 65]),
        };
        let header_2 = StacksMicroblockHeader {
            tx_merkle_root: Sha512Trunc256Sum([2; 32]),
            signature: MessageSignature([3; 65]),
            ..header_1.clone()
        };
        let payload = TransactionPayload::PoisonMicroblock(header_1, header_2);

        let header_bytes = |merkle: u8, signature: u8| {
            let mut bytes = vec![0x12, 0x00, 0x34];
            bytes.extend_from_slice(&[0; 32]);
            bytes.extend_from_slice(&[merkle; 32]);
            bytes.extend_from_slice(&[signature; 65]);
            bytes
        };
        let mut expected = vec![TransactionPayloadID::PoisonMicroblock as u8];
        expected.extend(header_bytes(1, 2));
        expected.extend(header_bytes(2, 3));
        check_codec_and_corruption(&payload, &expected);
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid() {
        let mut bytes = vec![u8::MAX];
        bytes.extend(serialize_contract_call(&sample_contract_call()));
        assert!(
            TransactionPayload::consensus_deserialize(&mut &bytes[..])
                .unwrap_err()
                .to_string()
                .contains("unknown payload ID")
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid_contract_name() {
        let address = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
        let invalid_name = "hello\0contract-name";
        let function_name = ClarityName::try_from("hello-function-name").unwrap();
        let arguments = vec![Value::Int(0)];

        let mut bytes = vec![TransactionPayloadID::ContractCall as u8];
        address.consensus_serialize(&mut bytes).unwrap();
        bytes.push(invalid_name.len() as u8);
        bytes.extend_from_slice(invalid_name.as_bytes());
        function_name.consensus_serialize(&mut bytes).unwrap();
        arguments.consensus_serialize(&mut bytes).unwrap();

        assert!(
            TransactionPayload::consensus_deserialize(&mut &bytes[..])
                .unwrap_err()
                .to_string()
                .contains("Failed to parse Contract name")
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid_function_name() {
        let address = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
        let contract_name = ContractName::try_from("hello-contract-name").unwrap();
        let invalid_name = "hello\0function-name";
        let arguments = vec![Value::Int(0)];

        let mut bytes = vec![TransactionPayloadID::ContractCall as u8];
        address.consensus_serialize(&mut bytes).unwrap();
        contract_name.consensus_serialize(&mut bytes).unwrap();
        bytes.push(invalid_name.len() as u8);
        bytes.extend_from_slice(invalid_name.as_bytes());
        arguments.consensus_serialize(&mut bytes).unwrap();

        assert!(
            TransactionPayload::consensus_deserialize(&mut &bytes[..])
                .unwrap_err()
                .to_string()
                .contains("Failed to parse Clarity name")
        );
    }

    #[test]
    fn tx_stacks_asset() {
        let asset = AssetInfo {
            contract_address: StacksAddress::new(1, Hash160([0xff; 20])).unwrap(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("hello-asset").unwrap(),
        };
        let mut expected = vec![0x01];
        expected.extend_from_slice(&[0xff; 20]);
        expected.push(11);
        expected.extend_from_slice(b"hello-world");
        expected.push(11);
        expected.extend_from_slice(b"hello-asset");
        check_codec_and_corruption(&asset, &expected);
    }

    #[test]
    fn tx_stacks_postcondition() {
        let principals = [
            PostConditionPrincipal::Origin,
            PostConditionPrincipal::Standard(StacksAddress::new(1, Hash160([1; 20])).unwrap()),
            PostConditionPrincipal::Contract(
                StacksAddress::new(2, Hash160([2; 20])).unwrap(),
                ContractName::try_from("hello-world").unwrap(),
            ),
        ];

        for principal in principals {
            let asset = AssetInfo {
                contract_address: StacksAddress::new(1, Hash160([0xff; 20])).unwrap(),
                contract_name: ContractName::try_from("contract-name").unwrap(),
                asset_name: ClarityName::try_from("hello-asset").unwrap(),
            };
            let mut encoded_principal = vec![];
            principal
                .consensus_serialize(&mut encoded_principal)
                .unwrap();

            let mut stx_bytes = vec![AssetInfoID::STX as u8];
            stx_bytes.extend_from_slice(&encoded_principal);
            stx_bytes.push(FungibleConditionCode::SentGt as u8);
            stx_bytes.extend_from_slice(&12345_u64.to_be_bytes());
            check_codec_and_corruption(
                &TransactionPostCondition::STX(
                    principal.clone(),
                    FungibleConditionCode::SentGt,
                    12345,
                ),
                &stx_bytes,
            );

            let mut fungible_bytes = vec![AssetInfoID::FungibleAsset as u8];
            fungible_bytes.extend_from_slice(&encoded_principal);
            asset.consensus_serialize(&mut fungible_bytes).unwrap();
            fungible_bytes.push(FungibleConditionCode::SentGt as u8);
            fungible_bytes.extend_from_slice(&23456_u64.to_be_bytes());
            check_codec_and_corruption(
                &TransactionPostCondition::Fungible(
                    principal.clone(),
                    asset.clone(),
                    FungibleConditionCode::SentGt,
                    23456,
                ),
                &fungible_bytes,
            );

            let asset_value = Value::buff_from(vec![0, 1, 2, 3]).unwrap();
            let mut nonfungible_bytes = vec![AssetInfoID::NonfungibleAsset as u8];
            nonfungible_bytes.extend_from_slice(&encoded_principal);
            asset.consensus_serialize(&mut nonfungible_bytes).unwrap();
            asset_value
                .consensus_serialize(&mut nonfungible_bytes)
                .unwrap();
            nonfungible_bytes.push(NonfungibleConditionCode::NotSent as u8);
            check_codec_and_corruption(
                &TransactionPostCondition::Nonfungible(
                    principal.clone(),
                    asset.clone(),
                    asset_value,
                    NonfungibleConditionCode::NotSent,
                ),
                &nonfungible_bytes,
            );

            let mut staking_bytes = vec![AssetInfoID::Staking as u8];
            staking_bytes.extend_from_slice(&encoded_principal);
            staking_bytes.push(FungibleConditionCode::SentLe as u8);
            staking_bytes.extend_from_slice(&31337_u64.to_be_bytes());
            check_codec_and_corruption(
                &TransactionPostCondition::Staking(
                    principal.clone(),
                    FungibleConditionCode::SentLe,
                    31337,
                ),
                &staking_bytes,
            );

            let mut pox_bytes = vec![AssetInfoID::Pox as u8];
            pox_bytes.extend_from_slice(&encoded_principal);
            pox_bytes.push(PoxConditionCode::NotPerformed as u8);
            check_codec_and_corruption(
                &TransactionPostCondition::Pox(principal.clone(), PoxConditionCode::NotPerformed),
                &pox_bytes,
            );
        }
    }

    #[test]
    fn tx_stacks_postcondition_nft_maybe_sent_codec() {
        let post_condition = TransactionPostCondition::Nonfungible(
            PostConditionPrincipal::Origin,
            AssetInfo {
                contract_address: StacksAddress::new(1, Hash160([0x11; 20])).unwrap(),
                contract_name: ContractName::try_from("contract-name").unwrap(),
                asset_name: ClarityName::try_from("hello-asset").unwrap(),
            },
            Value::buff_from(vec![0, 1, 2, 3]).unwrap(),
            NonfungibleConditionCode::MaybeSent,
        );

        #[rustfmt::skip]
        let expected = [
            0x02, 0x01, 0x01,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x0d, b'c', b'o', b'n', b't', b'r', b'a', b'c', b't', b'-', b'n', b'a', b'm', b'e',
            0x0b, b'h', b'e', b'l', b'l', b'o', b'-', b'a', b's', b's', b'e', b't',
            0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03,
            0x12,
        ];
        check_codec_and_corruption(&post_condition, &expected);
    }

    #[test]
    fn tx_stacks_transaction_codec_originator_mode_and_nft_maybe_sent() {
        let mut transaction = StacksTransaction::new(
            TransactionVersion::Testnet,
            test_auth(),
            TransactionPayload::new_contract_call(
                StacksAddress::new(1, Hash160([0x22; 20])).unwrap(),
                "hello",
                "world",
                vec![Value::Int(1)],
            )
            .unwrap(),
        );
        transaction.post_condition_mode = TransactionPostConditionMode::Originator;
        transaction
            .post_conditions
            .push(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                AssetInfo {
                    contract_address: StacksAddress::new(1, Hash160([0x33; 20])).unwrap(),
                    contract_name: ContractName::try_from("contract-name").unwrap(),
                    asset_name: ClarityName::try_from("hello-asset").unwrap(),
                },
                Value::buff_from(vec![4, 5, 6, 7]).unwrap(),
                NonfungibleConditionCode::MaybeSent,
            ));

        let bytes = transaction.serialize_to_vec();
        #[rustfmt::skip]
        let expected_post_conditions = [
            0x03,
            0x00, 0x00, 0x00, 0x01,
            0x02, 0x01, 0x01,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x0d, b'c', b'o', b'n', b't', b'r', b'a', b'c', b't', b'-', b'n', b'a', b'm', b'e',
            0x0b, b'h', b'e', b'l', b'l', b'o', b'-', b'a', b's', b's', b'e', b't',
            0x02, 0x00, 0x00, 0x00, 0x04, 0x04, 0x05, 0x06, 0x07,
            0x12,
        ];
        assert!(
            bytes
                .windows(expected_post_conditions.len())
                .any(|window| window == expected_post_conditions)
        );
        check_codec_and_corruption(&transaction, &bytes);
    }

    #[test]
    fn tx_stacks_postcondition_invalid() {
        let asset = AssetInfo {
            contract_address: StacksAddress::new(1, Hash160([0xff; 20])).unwrap(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("hello-asset").unwrap(),
        };
        let asset_value = Value::buff_from(vec![0, 1, 2, 3]).unwrap();

        let mut stx_bad_condition = vec![
            AssetInfoID::STX as u8,
            PostConditionPrincipalID::Origin as u8,
            NonfungibleConditionCode::NotSent as u8,
        ];
        stx_bad_condition.extend_from_slice(&12345_u64.to_be_bytes());

        let mut fungible_bad_condition = vec![
            AssetInfoID::FungibleAsset as u8,
            PostConditionPrincipalID::Origin as u8,
        ];
        asset
            .consensus_serialize(&mut fungible_bad_condition)
            .unwrap();
        fungible_bad_condition.push(NonfungibleConditionCode::Sent as u8);
        fungible_bad_condition.extend_from_slice(&23456_u64.to_be_bytes());

        let mut nonfungible_bad_condition = vec![
            AssetInfoID::NonfungibleAsset as u8,
            PostConditionPrincipalID::Origin as u8,
        ];
        asset
            .consensus_serialize(&mut nonfungible_bad_condition)
            .unwrap();
        asset_value
            .consensus_serialize(&mut nonfungible_bad_condition)
            .unwrap();
        nonfungible_bad_condition.push(FungibleConditionCode::SentGt as u8);

        let mut stx_bad_principal = vec![AssetInfoID::STX as u8, u8::MAX];
        stx_bad_principal.push(FungibleConditionCode::SentGt as u8);
        stx_bad_principal.extend_from_slice(&12345_u64.to_be_bytes());

        let mut fungible_bad_principal = vec![AssetInfoID::FungibleAsset as u8, u8::MAX];
        asset
            .consensus_serialize(&mut fungible_bad_principal)
            .unwrap();
        fungible_bad_principal.push(FungibleConditionCode::SentGt as u8);
        fungible_bad_principal.extend_from_slice(&23456_u64.to_be_bytes());

        let mut nonfungible_bad_principal = vec![AssetInfoID::NonfungibleAsset as u8, u8::MAX];
        asset
            .consensus_serialize(&mut nonfungible_bad_principal)
            .unwrap();
        asset_value
            .consensus_serialize(&mut nonfungible_bad_principal)
            .unwrap();
        nonfungible_bad_principal.push(NonfungibleConditionCode::NotSent as u8);

        for invalid in [
            stx_bad_condition,
            fungible_bad_condition,
            nonfungible_bad_condition,
            stx_bad_principal,
            fungible_bad_principal,
            nonfungible_bad_principal,
        ] {
            assert!(TransactionPostCondition::consensus_deserialize(&mut &invalid[..]).is_err());
        }
    }

    #[test]
    fn epoch_40_post_condition_codec() {
        let mut staking = vec![
            AssetInfoID::Staking as u8,
            PostConditionPrincipalID::Origin as u8,
            FungibleConditionCode::SentEq as u8,
        ];
        staking.extend_from_slice(&123_u64.to_be_bytes());
        check_roundtrip(
            TransactionPostCondition::Staking(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                123,
            ),
            &staking,
        );

        check_roundtrip(
            TransactionPostCondition::Pox(
                PostConditionPrincipal::Origin,
                PoxConditionCode::NotPerformed,
            ),
            &[
                AssetInfoID::Pox as u8,
                PostConditionPrincipalID::Origin as u8,
                PoxConditionCode::NotPerformed as u8,
            ],
        );
    }

    #[test]
    fn transaction_codec_rejects_unanchored_coinbase() {
        let mut transaction = StacksTransaction::new(
            TransactionVersion::Testnet,
            test_auth(),
            TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, None),
        );
        transaction.anchor_mode = TransactionAnchorMode::OffChainOnly;

        let error =
            StacksTransaction::consensus_deserialize(&mut &transaction.serialize_to_vec()[..])
                .unwrap_err()
                .to_string();
        assert!(error.contains("invalid anchor mode for Coinbase"));
    }

    #[test]
    fn poison_microblock_codec_requires_a_fork() {
        let header = StacksMicroblockHeader {
            version: 0,
            sequence: 1,
            prev_block: BlockHeaderHash([1; 32]),
            tx_merkle_root: Sha512Trunc256Sum([2; 32]),
            signature: MessageSignature::empty(),
        };
        let payload = TransactionPayload::PoisonMicroblock(header.clone(), header);
        let error = TransactionPayload::consensus_deserialize(&mut &payload.serialize_to_vec()[..])
            .unwrap_err()
            .to_string();
        assert!(error.contains("microblock headers match"));
    }

    #[test]
    fn transaction_version_preserves_legacy_high_bit_interpretation() {
        let transaction = StacksTransaction::new(
            TransactionVersion::Mainnet,
            test_auth(),
            TransactionPayload::TokenTransfer(
                stacks_primitives::StacksAddress::new(0, Hash160([0; 20]))
                    .unwrap()
                    .into(),
                1,
                TokenTransferMemo([0; 34]),
            ),
        );
        let mut bytes = transaction.serialize_to_vec();

        bytes[0] = 0x01;
        assert_eq!(
            StacksTransaction::consensus_deserialize(&mut &bytes[..])
                .unwrap()
                .version,
            TransactionVersion::Mainnet
        );
        bytes[0] = 0x81;
        assert_eq!(
            StacksTransaction::consensus_deserialize(&mut &bytes[..])
                .unwrap()
                .version,
            TransactionVersion::Testnet
        );
    }

    /// Keep Clarity's explicit transaction wire mapping exhaustive and
    /// round-trippable as new language versions are introduced.
    #[test]
    fn clarity_version_codec_is_consistent() {
        for &version in ClarityVersion::ALL {
            let mut bytes = vec![];
            clarity_version_consensus_serialize(&version, &mut bytes).unwrap();
            let decoded = clarity_version_consensus_deserialize(&mut &bytes[..]).unwrap();
            assert_eq!(version, decoded, "roundtrip mismatch for {version:?}");
        }
    }

    #[test]
    fn transaction_anchor_mode_byte_values() {
        assert_eq!(TransactionAnchorMode::OnChainOnly as u8, 0x01);
        assert_eq!(TransactionAnchorMode::OffChainOnly as u8, 0x02);
        assert_eq!(TransactionAnchorMode::Any as u8, 0x03);
    }

    #[test]
    fn transaction_post_condition_mode_byte_values() {
        assert_eq!(TransactionPostConditionMode::Allow as u8, 0x01);
        assert_eq!(TransactionPostConditionMode::Deny as u8, 0x02);
        assert_eq!(TransactionPostConditionMode::Originator as u8, 0x03);
    }

    #[test]
    fn transaction_version_byte_values() {
        assert_eq!(TransactionVersion::Mainnet as u8, 0x00);
        assert_eq!(TransactionVersion::Testnet as u8, 0x80);
    }

    #[test]
    fn fungible_condition_code_from_u8_roundtrip() {
        for &code in FungibleConditionCode::ALL {
            assert_eq!(FungibleConditionCode::from_u8(code as u8), Some(code));
        }
    }

    #[test]
    fn nonfungible_condition_code_from_u8_roundtrip() {
        for &code in NonfungibleConditionCode::ALL {
            assert_eq!(NonfungibleConditionCode::from_u8(code as u8), Some(code));
        }
    }

    #[test]
    fn tenure_change_cause_codec() {
        for &cause in TenureChangeCause::ALL {
            let mut bytes = vec![];
            cause.consensus_serialize(&mut bytes).unwrap();
            assert_eq!(bytes, vec![cause.as_u8()]);

            let decoded = TenureChangeCause::consensus_deserialize(&mut &bytes[..]).unwrap();
            assert!(decoded.is_eq(&cause));
        }
    }

    #[test]
    fn tenure_change_cause_rejects_unknown_byte() {
        for invalid in [TenureChangeCause::ALL.len() as u8, u8::MAX] {
            assert!(TenureChangeCause::consensus_deserialize(&mut &[invalid][..]).is_err());
        }
    }

    #[test]
    fn tenure_change_payload_codec() {
        let payload = TenureChangePayload {
            tenure_consensus_hash: ConsensusHash([0xaa; 20]),
            prev_tenure_consensus_hash: ConsensusHash([0xbb; 20]),
            burn_view_consensus_hash: ConsensusHash([0xcc; 20]),
            previous_tenure_end: StacksBlockId([0xdd; 32]),
            previous_tenure_blocks: 42,
            cause: TenureChangeCause::Extended,
            pubkey_hash: Hash160([0xee; 20]),
        };

        let bytes = payload.serialize_to_vec();
        let decoded = TenureChangePayload::consensus_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.tenure_consensus_hash, payload.tenure_consensus_hash);
        assert_eq!(
            decoded.prev_tenure_consensus_hash,
            payload.prev_tenure_consensus_hash
        );
        assert_eq!(
            decoded.burn_view_consensus_hash,
            payload.burn_view_consensus_hash
        );
        assert_eq!(decoded.previous_tenure_end, payload.previous_tenure_end);
        assert_eq!(
            decoded.previous_tenure_blocks,
            payload.previous_tenure_blocks
        );
        assert!(decoded.cause.is_eq(&payload.cause));
        assert_eq!(decoded.pubkey_hash, payload.pubkey_hash);
    }

    #[test]
    fn stacks_microblock_header_codec() {
        let header = StacksMicroblockHeader {
            version: 0x09,
            sequence: 0x1234,
            prev_block: BlockHeaderHash([0x77; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x88; 32]),
            signature: MessageSignature([0x99; 65]),
        };

        let bytes = header.serialize_to_vec();
        let decoded = StacksMicroblockHeader::consensus_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn transaction_auth_flags_byte_values() {
        assert_eq!(TransactionAuthFlags::AuthStandard as u8, 0x04);
        assert_eq!(TransactionAuthFlags::AuthSponsored as u8, 0x05);
    }

    #[test]
    fn stacks_transaction_empty_post_conditions_codec() {
        let transaction = StacksTransaction::new(
            TransactionVersion::Testnet,
            test_auth(),
            TransactionPayload::TokenTransfer(
                stacks_primitives::StacksAddress::new(0, Hash160([0xaa; 20]))
                    .unwrap()
                    .into(),
                1,
                TokenTransferMemo([0; 34]),
            ),
        );

        let bytes = transaction.serialize_to_vec();
        let decoded = StacksTransaction::consensus_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, transaction);
        assert!(decoded.post_conditions.is_empty());
    }

    #[test]
    fn token_transfer_memo_fixed_size() {
        let memo = TokenTransferMemo([0xab; 34]);
        let bytes = memo.serialize_to_vec();
        assert_eq!(bytes, vec![0xab; 34]);

        let decoded = TokenTransferMemo::consensus_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.0, memo.0);
    }

    #[test]
    fn coinbase_payload_fixed_size() {
        let payload = CoinbasePayload([0xcd; 32]);
        let bytes = payload.serialize_to_vec();
        assert_eq!(bytes.len(), 32);

        let decoded = CoinbasePayload::consensus_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.0, payload.0);
    }

    #[test]
    fn post_condition_principal_id_byte_values() {
        assert_eq!(PostConditionPrincipalID::Origin as u8, 0x01);
        assert_eq!(PostConditionPrincipalID::Standard as u8, 0x02);
        assert_eq!(PostConditionPrincipalID::Contract as u8, 0x03);
    }

    #[test]
    fn asset_info_id_byte_values() {
        assert_eq!(AssetInfoID::STX as u8, 0x00);
        assert_eq!(AssetInfoID::FungibleAsset as u8, 0x01);
        assert_eq!(AssetInfoID::NonfungibleAsset as u8, 0x02);
        assert_eq!(AssetInfoID::Staking as u8, 0x03);
        assert_eq!(AssetInfoID::Pox as u8, 0x04);
    }

    #[test]
    fn transaction_payload_id_byte_values() {
        assert_eq!(TransactionPayloadID::TokenTransfer as u8, 0x00);
        assert_eq!(TransactionPayloadID::SmartContract as u8, 0x01);
        assert_eq!(TransactionPayloadID::ContractCall as u8, 0x02);
        assert_eq!(TransactionPayloadID::PoisonMicroblock as u8, 0x03);
        assert_eq!(TransactionPayloadID::Coinbase as u8, 0x04);
        assert_eq!(TransactionPayloadID::CoinbaseToAltRecipient as u8, 0x05);
        assert_eq!(TransactionPayloadID::VersionedSmartContract as u8, 0x06);
        assert_eq!(TransactionPayloadID::TenureChange as u8, 0x07);
        assert_eq!(TransactionPayloadID::NakamotoCoinbase as u8, 0x08);
    }

    #[test]
    fn stacks_transaction_header_layout() {
        let mut transaction = StacksTransaction::new(
            TransactionVersion::Mainnet,
            test_auth(),
            TransactionPayload::TokenTransfer(
                stacks_primitives::StacksAddress::new(1, Hash160([0; 20]))
                    .unwrap()
                    .into(),
                0,
                TokenTransferMemo([0; 34]),
            ),
        );
        transaction.chain_id = 0x01020304;

        let bytes = transaction.serialize_to_vec();
        assert_eq!(bytes[0], TransactionVersion::Mainnet as u8);
        assert_eq!(&bytes[1..5], &[0x01, 0x02, 0x03, 0x04]);
    }
}
