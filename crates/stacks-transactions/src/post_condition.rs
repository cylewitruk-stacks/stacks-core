use clarity_types::representations::{ClarityName, ContractName};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, Value};
use serde::{Deserialize, Serialize};
use stacks_primitives::address::StacksAddress;

use crate::principal::standard_principal_from_address;

/// Numeric wire-format ID of an asset info type variant.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum AssetInfoID {
    STX = 0,
    FungibleAsset = 1,
    NonfungibleAsset = 2,
}

impl AssetInfoID {
    pub fn from_u8(b: u8) -> Option<AssetInfoID> {
        match b {
            0 => Some(AssetInfoID::STX),
            1 => Some(AssetInfoID::FungibleAsset),
            2 => Some(AssetInfoID::NonfungibleAsset),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum FungibleConditionCode {
    SentEq = 0x01,
    SentGt = 0x02,
    SentGe = 0x03,
    SentLt = 0x04,
    SentLe = 0x05,
}

impl FungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<FungibleConditionCode> {
        match b {
            0x01 => Some(FungibleConditionCode::SentEq),
            0x02 => Some(FungibleConditionCode::SentGt),
            0x03 => Some(FungibleConditionCode::SentGe),
            0x04 => Some(FungibleConditionCode::SentLt),
            0x05 => Some(FungibleConditionCode::SentLe),
            _ => None,
        }
    }

    pub fn check(&self, amount_sent_condition: u128, amount_sent: u128) -> bool {
        match *self {
            FungibleConditionCode::SentEq => amount_sent == amount_sent_condition,
            FungibleConditionCode::SentGt => amount_sent > amount_sent_condition,
            FungibleConditionCode::SentGe => amount_sent >= amount_sent_condition,
            FungibleConditionCode::SentLt => amount_sent < amount_sent_condition,
            FungibleConditionCode::SentLe => amount_sent <= amount_sent_condition,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum PostConditionPrincipalID {
    Origin = 0x01,
    Standard = 0x02,
    Contract = 0x03,
}

/// Encoding of an asset type identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub contract_address: StacksAddress,
    pub contract_name: ContractName,
    pub asset_name: ClarityName,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum NonfungibleConditionCode {
    Sent = 0x10,
    NotSent = 0x11,
    MaybeSent = 0x12,
}

impl NonfungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<NonfungibleConditionCode> {
        match b {
            0x10 => Some(NonfungibleConditionCode::Sent),
            0x11 => Some(NonfungibleConditionCode::NotSent),
            0x12 => Some(NonfungibleConditionCode::MaybeSent),
            _ => None,
        }
    }

    pub fn was_sent(nft_sent_condition: &Value, nfts_sent: &[Value]) -> bool {
        for asset_sent in nfts_sent.iter() {
            if *asset_sent == *nft_sent_condition {
                return true;
            }
        }
        false
    }

    pub fn check(&self, nft_sent_condition: &Value, nfts_sent: &[Value]) -> bool {
        match *self {
            NonfungibleConditionCode::Sent => {
                NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent)
            }
            NonfungibleConditionCode::NotSent => {
                !NonfungibleConditionCode::was_sent(nft_sent_condition, nfts_sent)
            }
            NonfungibleConditionCode::MaybeSent => true,
        }
    }
}

/// Post-condition principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PostConditionPrincipal {
    Origin,
    Standard(StacksAddress),
    Contract(StacksAddress, ContractName),
}

impl PostConditionPrincipal {
    pub fn to_principal_data(&self, origin_principal: &PrincipalData) -> PrincipalData {
        match *self {
            PostConditionPrincipal::Origin => origin_principal.clone(),
            PostConditionPrincipal::Standard(ref addr) => {
                PrincipalData::Standard(standard_principal_from_address(addr.clone()))
            }
            PostConditionPrincipal::Contract(ref addr, ref contract_name) => {
                PrincipalData::Contract(QualifiedContractIdentifier::new(
                    standard_principal_from_address(addr.clone()),
                    contract_name.clone(),
                ))
            }
        }
    }

    pub fn id(&self) -> PostConditionPrincipalID {
        match self {
            PostConditionPrincipal::Origin => PostConditionPrincipalID::Origin,
            PostConditionPrincipal::Standard(_) => PostConditionPrincipalID::Standard,
            PostConditionPrincipal::Contract(..) => PostConditionPrincipalID::Contract,
        }
    }
}

/// Post-condition on a transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionPostCondition {
    STX(PostConditionPrincipal, FungibleConditionCode, u64),
    Fungible(
        PostConditionPrincipal,
        AssetInfo,
        FungibleConditionCode,
        u64,
    ),
    Nonfungible(
        PostConditionPrincipal,
        AssetInfo,
        Value,
        NonfungibleConditionCode,
    ),
}
