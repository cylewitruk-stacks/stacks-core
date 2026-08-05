use serde::{Deserialize, Serialize};
use stacks_primitives::address::StacksAddress;
use stacks_primitives::hash::Hash160;
use stacks_primitives::secp256k1::MessageSignature;
use stacks_primitives::{AddressHashMode, Secp256k1PublicKeyBytes};
use stacks_protocol::{AddressNetwork, Mainnet, Testnet};

use crate::{TransactionAuthField, TransactionPublicKeyEncoding};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionSpendingCondition {
    Singlesig(SinglesigSpendingCondition),
    Multisig(MultisigSpendingCondition),
    OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition),
}

impl TransactionSpendingCondition {
    /// When committing to the fact that a transaction is sponsored, the origin doesn't know
    /// anything else.  Instead, it commits to this sentinel value as its sponsor.
    /// It is intractable to calculate a private key that could generate this.
    pub fn new_initial_sighash() -> TransactionSpendingCondition {
        TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: Hash160([0u8; 20]),
            nonce: 0,
            tx_fee: 0,
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            signature: MessageSignature::empty(),
        })
    }

    pub fn num_signatures(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                if data.signature != MessageSignature::empty() {
                    1
                } else {
                    0
                }
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
        }
    }

    pub fn signatures_required(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(_) => 1,
            TransactionSpendingCondition::Multisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.nonce,
            TransactionSpendingCondition::Multisig(ref data) => data.nonce,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.nonce,
        }
    }

    pub fn tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.tx_fee,
            TransactionSpendingCondition::Multisig(ref data) => data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.tx_fee,
        }
    }

    pub fn set_nonce(&mut self, n: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.nonce = n;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref singlesig_data) => singlesig_data.tx_fee,
            TransactionSpendingCondition::Multisig(ref multisig_data) => multisig_data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.tx_fee
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_mainnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_mainnet()
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_testnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_testnet()
            }
        }
    }

    /// Get the address for an account, given the network flag
    pub fn get_address(&self, mainnet: bool) -> StacksAddress {
        if mainnet {
            self.address_mainnet()
        } else {
            self.address_testnet()
        }
    }

    /// Clear fee rate, nonces, signatures, and public keys
    pub fn clear(&mut self) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = 0;
                singlesig_data.nonce = 0;
                singlesig_data.signature = MessageSignature::empty();
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MultisigHashMode {
    P2SH = 0x01,
    P2WSH = 0x03,
}

impl MultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            MultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            MultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<MultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(MultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<MultisigHashMode> {
        match n {
            x if x == MultisigHashMode::P2SH as u8 => Some(MultisigHashMode::P2SH),
            x if x == MultisigHashMode::P2WSH as u8 => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }
}

/// A structure that encodes enough state to authenticate
/// a transaction's execution against a Stacks address.
/// public_keys + signatures_required determines the Principal.
/// nonce is the "check number" for the Principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultisigSpendingCondition {
    pub hash_mode: MultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offered by this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

impl MultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: Secp256k1PublicKeyBytes) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address<Network>(&self) -> StacksAddress
    where
        Network: AddressNetwork,
    {
        StacksAddress::new(Network::C32_ADDRESS_VERSION_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant address byte is not supported")
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        self.address::<Mainnet>()
    }

    pub fn address_testnet(&self) -> StacksAddress {
        self.address::<Testnet>()
    }
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SinglesigHashMode {
    P2PKH = 0x00,
    P2WPKH = 0x02,
}

impl SinglesigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            SinglesigHashMode::P2PKH => AddressHashMode::SerializeP2PKH,
            SinglesigHashMode::P2WPKH => AddressHashMode::SerializeP2WPKH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<SinglesigHashMode> {
        match hm {
            AddressHashMode::SerializeP2PKH => Some(SinglesigHashMode::P2PKH),
            AddressHashMode::SerializeP2WPKH => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<SinglesigHashMode> {
        match n {
            x if x == SinglesigHashMode::P2PKH as u8 => Some(SinglesigHashMode::P2PKH),
            x if x == SinglesigHashMode::P2WPKH as u8 => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinglesigSpendingCondition {
    pub hash_mode: SinglesigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offerred by this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature,
}

impl SinglesigSpendingCondition {
    pub fn set_signature(&mut self, signature: MessageSignature) {
        self.signature = signature;
    }

    pub fn pop_signature(&mut self) -> Option<TransactionAuthField> {
        if self.signature == MessageSignature::empty() {
            return None;
        }

        let ret = self.signature.clone();
        self.signature = MessageSignature::empty();

        Some(TransactionAuthField::Signature(self.key_encoding, ret))
    }

    pub fn address<Network>(&self) -> StacksAddress
    where
        Network: AddressNetwork,
    {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => Network::C32_ADDRESS_VERSION_SINGLESIG,
            SinglesigHashMode::P2WPKH => Network::C32_ADDRESS_VERSION_MULTISIG,
        };
        StacksAddress::new(version, self.signer.clone())
            .expect("FATAL: infallible: supported address constant is not valid")
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        self.address::<Mainnet>()
    }

    pub fn address_testnet(&self) -> StacksAddress {
        self.address::<Testnet>()
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderIndependentMultisigHashMode {
    P2SH = 0x05,
    P2WSH = 0x07,
}

impl OrderIndependentMultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            OrderIndependentMultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            OrderIndependentMultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<OrderIndependentMultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(OrderIndependentMultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(OrderIndependentMultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<OrderIndependentMultisigHashMode> {
        match n {
            x if x == OrderIndependentMultisigHashMode::P2SH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2SH)
            }
            x if x == OrderIndependentMultisigHashMode::P2WSH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2WSH)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderIndependentMultisigSpendingCondition {
    pub hash_mode: OrderIndependentMultisigHashMode,
    pub signer: Hash160,
    pub nonce: u64,  // nth authorization from this account
    pub tx_fee: u64, // microSTX/compute rate offered by this account
    pub fields: Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

impl OrderIndependentMultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: Secp256k1PublicKeyBytes) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address<Network>(&self) -> StacksAddress
    where
        Network: AddressNetwork,
    {
        StacksAddress::new(Network::C32_ADDRESS_VERSION_MULTISIG, self.signer.clone())
            .expect("FATAL: infallible: constant address byte is not supported")
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        self.address::<Mainnet>()
    }

    pub fn address_testnet(&self) -> StacksAddress {
        self.address::<Testnet>()
    }
}
