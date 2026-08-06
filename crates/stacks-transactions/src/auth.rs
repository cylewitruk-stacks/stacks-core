use serde::{Deserialize, Serialize};
use stacks_crypto::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_primitives::StacksEpochId;
use stacks_primitives::hash::Txid;

use crate::spend_condition::TransactionSpendingCondition;
use crate::{
    AuthError, TransactionAuthFlags, TransactionAuthVerificationMode,
    VerifySpendingConditionSignatures,
};

/// Types of transaction authorizations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuth {
    Standard(TransactionSpendingCondition),
    /// The second account pays on behalf of the first account.
    Sponsored(TransactionSpendingCondition, TransactionSpendingCondition),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionAuthError {
    IncompatibleSpendingCondition,
}

impl TransactionAuth {
    pub fn from_p2pkh(private_key: &Secp256k1PrivateKey) -> Option<Self> {
        TransactionSpendingCondition::new_singlesig_p2pkh(Secp256k1PublicKey::from_private(
            private_key,
        ))
        .map(Self::Standard)
    }

    pub fn from_p2wpkh(private_key: &Secp256k1PrivateKey) -> Option<Self> {
        TransactionSpendingCondition::new_singlesig_p2wpkh(Secp256k1PublicKey::from_private(
            private_key,
        ))
        .map(Self::Standard)
    }

    pub fn from_p2sh(
        private_keys: &[Secp256k1PrivateKey],
        signatures_required: u16,
    ) -> Option<Self> {
        let public_keys = private_keys
            .iter()
            .map(Secp256k1PublicKey::from_private)
            .collect();
        TransactionSpendingCondition::new_multisig_p2sh(signatures_required, public_keys)
            .map(Self::Standard)
    }

    pub fn from_p2wsh(
        private_keys: &[Secp256k1PrivateKey],
        signatures_required: u16,
    ) -> Option<Self> {
        let public_keys = private_keys
            .iter()
            .map(Secp256k1PublicKey::from_private)
            .collect();
        TransactionSpendingCondition::new_multisig_p2wsh(signatures_required, public_keys)
            .map(Self::Standard)
    }

    pub fn from_order_independent_p2sh(
        private_keys: &[Secp256k1PrivateKey],
        signatures_required: u16,
    ) -> Option<Self> {
        let public_keys = private_keys
            .iter()
            .map(Secp256k1PublicKey::from_private)
            .collect();
        TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            signatures_required,
            public_keys,
        )
        .map(Self::Standard)
    }

    pub fn from_order_independent_p2wsh(
        private_keys: &[Secp256k1PrivateKey],
        signatures_required: u16,
    ) -> Option<Self> {
        let public_keys = private_keys
            .iter()
            .map(Secp256k1PublicKey::from_private)
            .collect();
        TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            signatures_required,
            public_keys,
        )
        .map(Self::Standard)
    }

    /// Merge two standard auths into a sponsored auth.
    pub fn into_sponsored(self, sponsor_auth: TransactionAuth) -> Option<TransactionAuth> {
        match (self, sponsor_auth) {
            (TransactionAuth::Standard(sc), TransactionAuth::Standard(sp)) => {
                Some(TransactionAuth::Sponsored(sc, sp))
            }
            (_, _) => None,
        }
    }

    /// Directly set the sponsor spending condition.
    pub fn set_sponsor(
        &mut self,
        sponsor_spending_cond: TransactionSpendingCondition,
    ) -> Result<(), AuthError> {
        match *self {
            TransactionAuth::Sponsored(_, ref mut ssc) => {
                *ssc = sponsor_spending_cond;
                Ok(())
            }
            _ => Err(AuthError::IncompatibleSpendingConditionError),
        }
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, TransactionAuth::Standard(_))
    }

    pub fn is_sponsored(&self) -> bool {
        matches!(self, TransactionAuth::Sponsored(..))
    }

    /// When beginning to sign a sponsored transaction, the origin account will not commit to any
    /// information about the sponsor (only that it is sponsored). It does so by using sentinel
    /// sponsored account information.
    pub fn into_initial_sighash_auth(self) -> TransactionAuth {
        match self {
            TransactionAuth::Standard(mut origin) => {
                origin.clear();
                TransactionAuth::Standard(origin)
            }
            TransactionAuth::Sponsored(mut origin, _) => {
                origin.clear();
                TransactionAuth::Sponsored(
                    origin,
                    TransactionSpendingCondition::new_initial_sighash(),
                )
            }
        }
    }

    pub fn origin(&self) -> &TransactionSpendingCondition {
        match *self {
            TransactionAuth::Standard(ref s) => s,
            TransactionAuth::Sponsored(ref s, _) => s,
        }
    }

    pub fn origin_mut(&mut self) -> &mut TransactionSpendingCondition {
        match *self {
            TransactionAuth::Standard(ref mut s) => s,
            TransactionAuth::Sponsored(ref mut s, _) => s,
        }
    }

    pub fn get_origin_nonce(&self) -> u64 {
        self.origin().nonce()
    }

    pub fn set_origin_nonce(&mut self, n: u64) {
        self.origin_mut().set_nonce(n);
    }

    pub fn sponsor(&self) -> Option<&TransactionSpendingCondition> {
        match *self {
            TransactionAuth::Standard(_) => None,
            TransactionAuth::Sponsored(_, ref s) => Some(s),
        }
    }

    pub fn sponsor_mut(&mut self) -> Option<&mut TransactionSpendingCondition> {
        match *self {
            TransactionAuth::Standard(_) => None,
            TransactionAuth::Sponsored(_, ref mut s) => Some(s),
        }
    }

    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        self.sponsor().map(TransactionSpendingCondition::nonce)
    }

    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), AuthError> {
        match self.sponsor_mut() {
            None => Err(AuthError::IncompatibleSpendingConditionError),
            Some(s) => {
                s.set_nonce(n);
                Ok(())
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionAuth::Standard(ref mut s) => s.set_tx_fee(tx_fee),
            TransactionAuth::Sponsored(_, ref mut s) => s.set_tx_fee(tx_fee),
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionAuth::Standard(ref s) => s.get_tx_fee(),
            TransactionAuth::Sponsored(_, ref s) => s.get_tx_fee(),
        }
    }

    pub fn verify_origin(
        &self,
        initial_sighash: &Txid,
        mode: TransactionAuthVerificationMode,
    ) -> Result<Txid, AuthError> {
        self.origin()
            .verify_signatures(initial_sighash, &TransactionAuthFlags::AuthStandard, mode)
    }

    pub fn verify(
        &self,
        initial_sighash: &Txid,
        mode: TransactionAuthVerificationMode,
    ) -> Result<(), AuthError> {
        let origin_sighash = self.verify_origin(initial_sighash, mode)?;
        match self {
            TransactionAuth::Standard(_) => Ok(()),
            TransactionAuth::Sponsored(_, sponsor) => sponsor
                .verify_signatures(&origin_sighash, &TransactionAuthFlags::AuthSponsored, mode)
                .map(|_| ()),
        }
    }

    /// Clear out all transaction auth fields, nonces, and fee rates from the spending condition(s).
    pub fn clear(&mut self) {
        match *self {
            TransactionAuth::Standard(ref mut origin_condition) => {
                origin_condition.clear();
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                origin_condition.clear();
                sponsor_condition.clear();
            }
        }
    }

    /// Whether all spending conditions are available in the given epoch.
    pub fn is_supported_in_epoch(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            Self::Standard(origin) => origin.is_supported_in_epoch(epoch_id),
            Self::Sponsored(origin, sponsor) => {
                origin.is_supported_in_epoch(epoch_id) && sponsor.is_supported_in_epoch(epoch_id)
            }
        }
    }
}
