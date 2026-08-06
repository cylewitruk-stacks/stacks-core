use std::fmt;

use clarity_types::representations::{ClarityName, ContractName};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, Value};
use clarity_types::version::ClarityVersion;
use serde::{Deserialize, Serialize};
use stacks_crypto::vrf::VRFProof;
use stacks_macros::{
    define_u8_enum, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype,
    impl_byte_array_serde,
};
use stacks_primitives::StacksString;
use stacks_primitives::address::StacksAddress;
use stacks_primitives::block::StacksMicroblockHeader;

use crate::principal::standard_principal_from_address;
use crate::tenure::{TenureChangeCause, TenureChangePayload};

define_u8_enum!(TransactionPayloadID {
    TokenTransfer = 0,
    SmartContract = 1,
    ContractCall = 2,
    PoisonMicroblock = 3,
    Coinbase = 4,
    // has an alt principal, but no VRF proof
    CoinbaseToAltRecipient = 5,
    VersionedSmartContract = 6,
    TenureChange = 7,
    // has a VRF proof, and may have an alt principal
    NakamotoCoinbase = 8
});

/// A coinbase commits to 32 bytes of control-plane information.
pub struct CoinbasePayload(pub [u8; 32]);
impl_array_newtype!(CoinbasePayload, u8, 32);
impl_array_hexstring_fmt!(CoinbasePayload);
impl_byte_array_newtype!(
    CoinbasePayload,
    u8,
    32,
    stacks_primitives::HexError,
    stacks_primitives::hex::decode_array
);
impl_byte_array_serde!(CoinbasePayload);

/// Token-transfer memo bytes. This is the same length as in Stacks v1.
pub struct TokenTransferMemo(pub [u8; 34]);
impl_array_newtype!(TokenTransferMemo, u8, 34);
impl_array_hexstring_fmt!(TokenTransferMemo);
impl_byte_array_newtype!(
    TokenTransferMemo,
    u8,
    34,
    stacks_primitives::HexError,
    stacks_primitives::hex::decode_array
);
impl_byte_array_serde!(TokenTransferMemo);

/// A transaction that calls into a smart contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionContractCall {
    pub address: StacksAddress,
    pub contract_name: ContractName,
    pub function_name: ClarityName,
    pub function_args: Vec<Value>,
}

impl fmt::Display for TransactionContractCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arguments = self
            .function_args
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            formatter,
            "{}.{}::{}({arguments})",
            self.address, self.contract_name, self.function_name
        )
    }
}

impl TransactionContractCall {
    pub fn contract_identifier(&self) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            standard_principal_from_address(self.address.clone()),
            self.contract_name.clone(),
        )
    }

    pub fn to_clarity_contract_id(&self) -> QualifiedContractIdentifier {
        self.contract_identifier()
    }
}

/// A transaction that instantiates a smart contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionSmartContract {
    pub name: ContractName,
    pub code_body: StacksString,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    TokenTransfer(PrincipalData, u64, TokenTransferMemo),
    ContractCall(TransactionContractCall),
    SmartContract(TransactionSmartContract, Option<ClarityVersion>),
    /// The previous epoch leader sent two microblocks with the same sequence, and this is proof.
    PoisonMicroblock(StacksMicroblockHeader, StacksMicroblockHeader),
    Coinbase(CoinbasePayload, Option<PrincipalData>, Option<VRFProof>),
    TenureChange(TenureChangePayload),
}

impl TransactionPayload {
    pub fn name(&self) -> &'static str {
        match self {
            TransactionPayload::TokenTransfer(..) => "TokenTransfer",
            TransactionPayload::ContractCall(..) => "ContractCall",
            TransactionPayload::SmartContract(_, version_opt) => {
                if version_opt.is_some() {
                    "SmartContract(Versioned)"
                } else {
                    "SmartContract"
                }
            }
            TransactionPayload::PoisonMicroblock(..) => "PoisonMicroblock",
            TransactionPayload::Coinbase(_, _, vrf_opt) => {
                if vrf_opt.is_some() {
                    "Coinbase(Nakamoto)"
                } else {
                    "Coinbase"
                }
            }
            TransactionPayload::TenureChange(payload) => match payload.cause {
                TenureChangeCause::BlockFound => "TenureChange(BlockFound)",
                TenureChangeCause::Extended => "TenureChange(ExtendAll)",
                TenureChangeCause::ExtendedRuntime => "TenureChange(ExtendRuntime)",
                TenureChangeCause::ExtendedReadCount => "TenureChange(ExtendReadCount)",
                TenureChangeCause::ExtendedReadLength => "TenureChange(ExtendReadLength)",
                TenureChangeCause::ExtendedWriteCount => "TenureChange(ExtendWriteCount)",
                TenureChangeCause::ExtendedWriteLength => "TenureChange(ExtendWriteLength)",
            },
        }
    }

    pub fn new_contract_call(
        contract_address: StacksAddress,
        contract_name: &str,
        function_name: &str,
        args: Vec<Value>,
    ) -> Option<TransactionPayload> {
        let contract_name = ContractName::try_from(contract_name.to_string()).ok()?;
        let function_name = ClarityName::try_from(function_name.to_string()).ok()?;

        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address,
            contract_name,
            function_name,
            function_args: args,
        }))
    }

    pub fn new_smart_contract(
        name: &str,
        contract: &str,
        version_opt: Option<ClarityVersion>,
    ) -> Option<TransactionPayload> {
        Some(TransactionPayload::SmartContract(
            TransactionSmartContract {
                name: ContractName::try_from(name.to_string()).ok()?,
                code_body: StacksString::try_from_str(contract)?,
            },
            version_opt,
        ))
    }
}

impl From<TransactionSmartContract> for TransactionPayload {
    fn from(value: TransactionSmartContract) -> Self {
        TransactionPayload::SmartContract(value, None)
    }
}

impl From<TransactionContractCall> for TransactionPayload {
    fn from(value: TransactionContractCall) -> Self {
        TransactionPayload::ContractCall(value)
    }
}
