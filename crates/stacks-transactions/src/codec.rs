use std::io::{Read, Write};

use clarity_types::types::Value;
use clarity_types::version::ClarityVersion;
use stacks_codec::{
    BoundReader, Error as CodecError, MAX_MESSAGE_LEN, StacksMessageCodec,
    impl_byte_array_message_codec, read_next, write_next,
};
use stacks_crypto::hash::TxidDigest as _;
use stacks_crypto::secp256k1::Secp256k1PublicKey;
use stacks_primitives::block::StacksMicroblockHeader;
use stacks_primitives::hash::Txid;
use stacks_primitives::secp256k1::{COMPRESSED_PUBLIC_KEY_ENCODED_SIZE, Secp256k1PublicKeyBytes};
use stacks_primitives::vrf::VRFProof;

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
    pubkey: &Secp256k1PublicKeyBytes,
) -> Result<(), CodecError> {
    let crypto_key = Secp256k1PublicKey::from_public_key_bytes(pubkey)
        .map_err(|e| CodecError::SerializeError(e.to_string()))?;
    fd.write_all(&crypto_key.to_bytes_compressed())
        .map_err(CodecError::WriteError)
}

fn read_compressed_public_key<R: Read>(
    fd: &mut R,
    compressed: bool,
) -> Result<Secp256k1PublicKeyBytes, CodecError> {
    let mut buf = [0u8; COMPRESSED_PUBLIC_KEY_ENCODED_SIZE];
    fd.read_exact(&mut buf).map_err(CodecError::ReadError)?;
    let mut crypto_key = Secp256k1PublicKey::from_slice(&buf)
        .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
    crypto_key.set_compressed(compressed);
    Ok(crypto_key.to_public_key_bytes())
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
        match TransactionPayloadID::from_u8(type_id_u8) {
            Some(TransactionPayloadID::TokenTransfer) => Ok(TransactionPayload::TokenTransfer(
                read_next(fd)?,
                read_next(fd)?,
                read_next(fd)?,
            )),
            Some(TransactionPayloadID::ContractCall) => {
                Ok(TransactionPayload::ContractCall(read_next::<
                    TransactionContractCall,
                    _,
                >(fd)?))
            }
            Some(TransactionPayloadID::SmartContract) => Ok(TransactionPayload::SmartContract(
                read_next::<TransactionSmartContract, _>(fd)?,
                None,
            )),
            Some(TransactionPayloadID::VersionedSmartContract) => {
                let version = clarity_version_consensus_deserialize(fd)?;
                Ok(TransactionPayload::SmartContract(
                    read_next::<TransactionSmartContract, _>(fd)?,
                    Some(version),
                ))
            }
            Some(TransactionPayloadID::PoisonMicroblock) => {
                Ok(TransactionPayload::PoisonMicroblock(
                    read_next::<StacksMicroblockHeader, _>(fd)?,
                    read_next::<StacksMicroblockHeader, _>(fd)?,
                ))
            }
            Some(TransactionPayloadID::Coinbase) => Ok(TransactionPayload::Coinbase(
                read_next::<CoinbasePayload, _>(fd)?,
                None,
                None,
            )),
            Some(TransactionPayloadID::CoinbaseToAltRecipient) => {
                let payload = read_next(fd)?;
                let principal_value: Value = read_next(fd)?;
                let Value::Principal(principal) = principal_value else {
                    return Err(CodecError::DeserializeError(
                        "Failed to parse coinbase payload: expected principal recipient".into(),
                    ));
                };
                Ok(TransactionPayload::Coinbase(payload, Some(principal), None))
            }
            Some(TransactionPayloadID::NakamotoCoinbase) => {
                let payload = read_next(fd)?;
                let principal_value_opt: Value = read_next(fd)?;
                let recipient_opt = match principal_value_opt {
                    Value::Optional(optional_data) => match optional_data.data {
                        Some(value) => match *value {
                            Value::Principal(principal) => Some(principal),
                            _ => {
                                return Err(CodecError::DeserializeError(
                                    "Failed to parse nakamoto coinbase payload: expected optional principal recipient".into(),
                                ));
                            }
                        },
                        None => None,
                    },
                    _ => {
                        return Err(CodecError::DeserializeError(
                            "Failed to parse nakamoto coinbase payload: expected optional principal recipient".into(),
                        ));
                    }
                };
                Ok(TransactionPayload::Coinbase(
                    payload,
                    recipient_opt,
                    Some(read_next::<VRFProof, _>(fd)?),
                ))
            }
            Some(TransactionPayloadID::TenureChange) => {
                Ok(TransactionPayload::TenureChange(read_next(fd)?))
            }
            None => Err(CodecError::DeserializeError(format!(
                "Failed to parse transaction payload: unknown payload type {type_id_u8}"
            ))),
        }
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

    pub fn consensus_deserialize_with_len<R: Read>(
        fd: &mut R,
    ) -> Result<(StacksTransaction, u64), CodecError> {
        let mut bound_read = BoundReader::from_reader(fd, MAX_TRANSACTION_LEN.into());

        let version_u8: u8 = read_next(&mut bound_read)?;
        let version = match version_u8 {
            0x00 => TransactionVersion::Mainnet,
            0x80 => TransactionVersion::Testnet,
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse transaction: unknown version {version_u8}"
                )));
            }
        };

        let chain_id = read_next(&mut bound_read)?;
        let auth = read_next(&mut bound_read)?;
        let anchor_mode_u8: u8 = read_next(&mut bound_read)?;
        let anchor_mode = match anchor_mode_u8 {
            1 => TransactionAnchorMode::OnChainOnly,
            2 => TransactionAnchorMode::OffChainOnly,
            3 => TransactionAnchorMode::Any,
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse transaction: unknown anchor mode {anchor_mode_u8}"
                )));
            }
        };

        let post_condition_mode_u8: u8 = read_next(&mut bound_read)?;
        let post_condition_mode = match post_condition_mode_u8 {
            1 => TransactionPostConditionMode::Allow,
            2 => TransactionPostConditionMode::Deny,
            3 => TransactionPostConditionMode::Originator,
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse transaction: unknown post-condition mode {post_condition_mode_u8}"
                )));
            }
        };

        let post_conditions = read_next(&mut bound_read)?;
        let payload = read_next(&mut bound_read)?;
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

    pub fn tx_len(&self) -> Result<u64, CodecError> {
        let mut bytes = Vec::new();
        self.consensus_serialize(&mut bytes)?;
        Ok(bytes.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_roundtrip(post_condition: TransactionPostCondition, expected: &[u8]) {
        assert_eq!(post_condition.serialize_to_vec(), expected);
        let mut bytes = expected;
        assert_eq!(
            TransactionPostCondition::consensus_deserialize(&mut bytes).unwrap(),
            post_condition
        );
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
}
