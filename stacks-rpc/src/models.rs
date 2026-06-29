use serde::Serialize;
use stacks::net::api::getinfo::{RPCLastPoxAnchorData, RPCPeerInfoData};
use stacks::net::rpc_services::{AccountView, BlockProposalAccepted, ProofBytes};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{to_hex, Hash160, Sha256Sum};

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub peer_version: u32,
    pub server_version: String,
    pub network_id: u32,
    pub parent_network_id: u32,
    pub burn_block: BurnBlockInfo,
    pub stacks_tip: StacksTipInfo,
    pub genesis_chainstate_hash: Sha256Sum,
    pub exit_at_block_height: Option<u64>,
    pub is_fully_synced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key: Option<StacksPublicKeyBuffer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key_hash: Option<Hash160>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_pox_anchor: Option<RPCLastPoxAnchorData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stackerdbs: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct BurnBlockInfo {
    pub height: u64,
    pub pox_consensus: ConsensusHash,
    pub stable_height: u64,
    pub stable_pox_consensus: ConsensusHash,
}

#[derive(Debug, Serialize)]
pub struct StacksTipInfo {
    pub height: u64,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub unanchored_tip: Option<StacksBlockId>,
    pub unanchored_seq: Option<u16>,
    pub tenure_height: u64,
}

impl From<RPCPeerInfoData> for InfoResponse {
    fn from(info: RPCPeerInfoData) -> Self {
        Self {
            peer_version: info.peer_version,
            server_version: info.server_version,
            network_id: info.network_id,
            parent_network_id: info.parent_network_id,
            burn_block: BurnBlockInfo {
                height: info.burn_block_height,
                pox_consensus: info.pox_consensus,
                stable_height: info.stable_burn_block_height,
                stable_pox_consensus: info.stable_pox_consensus,
            },
            stacks_tip: StacksTipInfo {
                height: info.stacks_tip_height,
                block_hash: info.stacks_tip,
                consensus_hash: info.stacks_tip_consensus_hash,
                unanchored_tip: info.unanchored_tip,
                unanchored_seq: info.unanchored_seq,
                tenure_height: info.tenure_height,
            },
            genesis_chainstate_hash: info.genesis_chainstate_hash,
            exit_at_block_height: info.exit_at_block_height,
            is_fully_synced: info.is_fully_synced,
            node_public_key: info.node_public_key,
            node_public_key_hash: info.node_public_key_hash,
            last_pox_anchor: info.last_pox_anchor,
            stackerdbs: info.stackerdbs,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub balance: String,
    pub locked: String,
    pub unlock_height: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<AccountProofs>,
}

#[derive(Debug, Serialize)]
pub struct AccountProofs {
    pub balance: String,
    pub nonce: String,
}

impl From<AccountView> for AccountResponse {
    fn from(account: AccountView) -> Self {
        let proofs = match (account.balance_proof, account.nonce_proof) {
            (ProofBytes::Present(balance), ProofBytes::Present(nonce)) => Some(AccountProofs {
                balance: hex_bytes(&balance),
                nonce: hex_bytes(&nonce),
            }),
            _ => None,
        };

        Self {
            balance: hex_u128(account.balance),
            locked: hex_u128(account.locked),
            unlock_height: account.unlock_height,
            nonce: account.nonce,
            proofs,
        }
    }
}

fn hex_u128(value: u128) -> String {
    format!("0x{}", to_hex(&value.to_be_bytes()))
}

fn hex_bytes(value: &[u8]) -> String {
    format!("0x{}", to_hex(value))
}

#[derive(Debug, Serialize)]
pub struct BlockProposalSubmitResponse {
    pub status: BlockProposalStatus,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockProposalStatus {
    Accepted,
}

impl From<BlockProposalAccepted> for BlockProposalSubmitResponse {
    fn from(_response: BlockProposalAccepted) -> Self {
        Self {
            status: BlockProposalStatus::Accepted,
            message: "Block proposal is processing, result will be returned via the event observer"
                .to_string(),
        }
    }
}
