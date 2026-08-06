use clarity_types::types::PrincipalData;
use serde::{Deserialize, Serialize};
use stacks_primitives::address::StacksAddress;
use stacks_primitives::vrf::VRFProof;
use stacks_protocol::address::burn_address;

use crate::auth::{TransactionAuth, TransactionAuthError};
use crate::payload::{CoinbasePayload, TransactionPayload};
use crate::post_condition::TransactionPostCondition;
use crate::principal::principal_from_address;
use crate::spend_condition::TransactionSpendingCondition;
use crate::tenure::TenureChangePayload;

/// Max size of a serialized Stacks transaction.
pub const MAX_TRANSACTION_LEN: u32 = stacks_primitives::block::MAX_BLOCK_LEN;
pub const MIN_TRANSACTION_LEN: u32 = 180;

/// Stacks transaction versions.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

/// How a transaction may be appended to the Stacks blockchain.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,
    OffChainOnly = 2,
    Any = 3,
}

/// Post-condition modes for unspecified assets.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPostConditionMode {
    /// allow any other changes not specified
    Allow = 0x01,
    /// deny any other changes not specified
    Deny = 0x02,
    /// deny mode for originator's assets, allow for others
    Originator = 0x03,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksTransaction {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub auth: TransactionAuth,
    pub anchor_mode: TransactionAnchorMode,
    pub post_condition_mode: TransactionPostConditionMode,
    pub post_conditions: Vec<TransactionPostCondition>,
    pub payload: TransactionPayload,
}

impl Eq for StacksTransaction {}

impl StacksTransaction {
    /// Try to convert to a coinbase payload.
    pub fn try_as_coinbase(
        &self,
    ) -> Option<(&CoinbasePayload, Option<&PrincipalData>, Option<&VRFProof>)> {
        match &self.payload {
            TransactionPayload::Coinbase(payload, recipient_opt, vrf_proof_opt) => {
                Some((payload, recipient_opt.as_ref(), vrf_proof_opt.as_ref()))
            }
            _ => None,
        }
    }

    /// Try to convert to a tenure change payload.
    pub fn try_as_tenure_change(&self) -> Option<&TenureChangePayload> {
        match &self.payload {
            TransactionPayload::TenureChange(tc_payload) => Some(tc_payload),
            _ => None,
        }
    }

    /// Create a new, unsigned transaction with no post-conditions.
    pub fn new(
        version: TransactionVersion,
        auth: TransactionAuth,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let anchor_mode = match payload {
            TransactionPayload::Coinbase(..) | TransactionPayload::PoisonMicroblock(_, _) => {
                TransactionAnchorMode::OnChainOnly
            }
            _ => TransactionAnchorMode::Any,
        };

        StacksTransaction {
            version,
            chain_id: 0,
            auth,
            anchor_mode,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload,
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        self.auth.get_tx_fee()
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        self.auth.set_tx_fee(tx_fee);
    }

    pub fn get_origin_nonce(&self) -> u64 {
        self.auth.get_origin_nonce()
    }

    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        self.auth.get_sponsor_nonce()
    }

    pub fn set_origin_nonce(&mut self, n: u64) {
        self.auth.set_origin_nonce(n);
    }

    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), TransactionAuthError> {
        self.auth.set_sponsor_nonce(n)
    }

    pub fn set_anchor_mode(&mut self, anchor_mode: TransactionAnchorMode) {
        self.anchor_mode = anchor_mode;
    }

    pub fn set_post_condition_mode(&mut self, postcond_mode: TransactionPostConditionMode) {
        self.post_condition_mode = postcond_mode;
    }

    pub fn add_post_condition(&mut self, post_condition: TransactionPostCondition) {
        self.post_conditions.push(post_condition);
    }

    pub fn borrow_auth(&mut self) -> &mut TransactionAuth {
        &mut self.auth
    }

    pub fn auth(&self) -> &TransactionAuth {
        &self.auth
    }

    pub fn origin_address(&self) -> StacksAddress {
        match (&self.version, &self.auth) {
            (TransactionVersion::Mainnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_mainnet()
            }
            (TransactionVersion::Testnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_testnet()
            }
            (TransactionVersion::Mainnet, TransactionAuth::Sponsored(origin_condition, _)) => {
                origin_condition.address_mainnet()
            }
            (TransactionVersion::Testnet, TransactionAuth::Sponsored(origin_condition, _)) => {
                origin_condition.address_testnet()
            }
        }
    }

    pub fn sponsor_address(&self) -> Option<StacksAddress> {
        match (&self.version, &self.auth) {
            (_, TransactionAuth::Standard(_)) => None,
            (TransactionVersion::Mainnet, TransactionAuth::Sponsored(_, sponsor_condition)) => {
                Some(sponsor_condition.address_mainnet())
            }
            (TransactionVersion::Testnet, TransactionAuth::Sponsored(_, sponsor_condition)) => {
                Some(sponsor_condition.address_testnet())
            }
        }
    }

    pub fn get_origin(&self) -> TransactionSpendingCondition {
        self.auth.origin().clone()
    }

    pub fn get_payer(&self) -> TransactionSpendingCondition {
        self.auth
            .sponsor()
            .cloned()
            .unwrap_or_else(|| self.auth.origin().clone())
    }

    pub fn is_mainnet(&self) -> bool {
        self.version == TransactionVersion::Mainnet
    }

    pub fn is_phantom(&self) -> bool {
        let boot_address = principal_from_address(burn_address(self.is_mainnet()));
        matches!(
            &self.payload,
            TransactionPayload::TokenTransfer(address, 0, _) if *address == boot_address
        )
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn with_negated_s_in_signature(&self) -> StacksTransaction {
        high_s::tx_with_negated_s_in_signature(self)
    }
}

#[cfg(any(test, feature = "testing"))]
mod high_s {
    use stacks_crypto::secp256k1::MessageSignatureCryptoExt as _;

    use crate::{
        StacksTransaction, TransactionAuth, TransactionAuthField, TransactionSpendingCondition,
    };

    fn auth_fields_with_negated_s_signature(
        fields: Vec<TransactionAuthField>,
    ) -> Vec<TransactionAuthField> {
        let mut handled_one = false;
        let mut result: Vec<_> = fields
            .iter()
            .rev()
            .map(|field| {
                if handled_one {
                    return field.clone();
                }
                match field {
                    TransactionAuthField::PublicKey(_) => field.clone(),
                    TransactionAuthField::Signature(encoding, signature) => {
                        handled_one = true;
                        TransactionAuthField::Signature(*encoding, signature.with_negated_s())
                    }
                }
            })
            .collect();
        result.reverse();
        result
    }

    fn spending_condition_with_negated_s_signature(
        condition: &TransactionSpendingCondition,
    ) -> TransactionSpendingCondition {
        match condition {
            TransactionSpendingCondition::Singlesig(condition) => {
                let mut condition = condition.clone();
                condition.signature = condition.signature.with_negated_s();
                TransactionSpendingCondition::Singlesig(condition)
            }
            TransactionSpendingCondition::Multisig(condition) => {
                let mut condition = condition.clone();
                condition.fields = auth_fields_with_negated_s_signature(condition.fields);
                TransactionSpendingCondition::Multisig(condition)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(condition) => {
                let mut condition = condition.clone();
                condition.fields = auth_fields_with_negated_s_signature(condition.fields);
                TransactionSpendingCondition::OrderIndependentMultisig(condition)
            }
        }
    }

    pub fn tx_with_negated_s_in_signature(tx: &StacksTransaction) -> StacksTransaction {
        let auth = match tx.auth() {
            TransactionAuth::Standard(condition) => {
                TransactionAuth::Standard(spending_condition_with_negated_s_signature(condition))
            }
            TransactionAuth::Sponsored(origin, sponsor) => TransactionAuth::Sponsored(
                origin.clone(),
                spending_condition_with_negated_s_signature(sponsor),
            ),
        };
        let mut result = tx.clone();
        result.auth = auth;
        result
    }
}
