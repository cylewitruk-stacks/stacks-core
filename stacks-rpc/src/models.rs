use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use serde::{Deserialize, Serialize};
use stacks::chainstate::nakamoto::NakamotoBlockHeader;
use stacks::chainstate::stacks::boot::RewardSet;
use stacks::chainstate::stacks::db::{ExtendedStacksHeader, StacksBlockHeaderTypes};
use stacks::chainstate::stacks::StacksBlockHeader;
use stacks::net::api::get_tenures_fork_info::TenureForkingInfo;
use stacks::net::api::getinfo::{RPCLastPoxAnchorData, RPCPeerInfoData};
use stacks::net::api::getsortition::SortitionInfo;
use stacks::net::api::gettenureblocks::RPCTenureBlock;
use stacks::net::rpc_services::{
    AccountView, BlockProposalAccepted, ClarityValueView, ConfirmedTransactionView,
    ContractSourceView, ProofBytes, TenureBlocksPage, TenureTipView,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId,
};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Option<String>>,
}

impl From<AccountView> for AccountResponse {
    fn from(account: AccountView) -> Self {
        let balance_proof = proof_response(account.balance_proof);
        let nonce_proof = proof_response(account.nonce_proof);
        let proofs = if balance_proof.is_some() || nonce_proof.is_some() {
            Some(AccountProofs {
                balance: balance_proof,
                nonce: nonce_proof,
            })
        } else {
            None
        };

        Self {
            balance: account.balance.to_string(),
            locked: account.locked.to_string(),
            unlock_height: account.unlock_height,
            nonce: account.nonce,
            proofs,
        }
    }
}

#[cfg(test)]
mod tests {
    use stacks::chainstate::nakamoto::NakamotoBlockHeader;
    use stacks::chainstate::stacks::db::StacksBlockHeaderTypes;
    use stacks::net::rpc_services::{AccountView, ProofBytes, TenureTipView};
    use stacks_common::types::chainstate::ConsensusHash;

    use super::{AccountResponse, TenureTipResponse};

    #[test]
    fn account_response_preserves_independent_proofs() {
        let response = AccountResponse::from(AccountView {
            balance: 42,
            locked: 0,
            unlock_height: 0,
            nonce: 3,
            balance_proof: ProofBytes::Present(vec![0xab, 0xcd]),
            nonce_proof: ProofBytes::Missing,
        });
        let value = serde_json::to_value(response).unwrap();

        assert_eq!(value["proofs"]["balance"], "0xabcd");
        assert!(value["proofs"]["nonce"].is_null());
    }

    #[test]
    fn tenure_tip_response_does_not_expose_rust_enum_tags() {
        let response = TenureTipResponse::from(TenureTipView {
            header: StacksBlockHeaderTypes::Nakamoto(NakamotoBlockHeader::empty()),
            burn_view: Some(ConsensusHash([1; 20])),
        });
        let value = serde_json::to_value(response).unwrap();

        assert_eq!(value["header_type"], "nakamoto");
        assert!(value.get("header").is_none());
        assert!(value.get("Nakamoto").is_none());
        assert!(value.get("version").is_some());
    }
}

fn proof_response(proof: ProofBytes) -> Option<Option<String>> {
    match proof {
        ProofBytes::NotRequested => None,
        ProofBytes::Missing => Some(None),
        ProofBytes::Present(bytes) => Some(Some(hex_bytes(&bytes))),
    }
}

#[derive(Debug, Serialize)]
pub struct ContractSourceResponse {
    pub source: String,
    pub publish_height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Option<String>>,
}

impl From<ContractSourceView> for ContractSourceResponse {
    fn from(source: ContractSourceView) -> Self {
        Self {
            source: source.source,
            publish_height: source.publish_height,
            proof: proof_response(source.proof),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceResponse {
    pub interface: ContractInterface,
}

#[derive(Debug, Serialize)]
pub struct ClarityValueResponse {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Option<String>>,
}

impl From<ClarityValueView> for ClarityValueResponse {
    fn from(value: ClarityValueView) -> Self {
        Self {
            value: value.value,
            proof: proof_response(value.proof),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TraitImplementationResponse {
    pub implemented: bool,
}

#[derive(Debug, Serialize)]
pub struct ClarityMetadataResponse {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ReadOnlyCallRequest {
    pub sender: String,
    #[serde(default)]
    pub sponsor: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReadOnlyCallResponse {
    pub result: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmedTransactionResponse {
    pub block_id: StacksBlockId,
    pub transaction: String,
    pub result: String,
    pub block_height: Option<u64>,
    pub canonical: bool,
}

impl From<ConfirmedTransactionView> for ConfirmedTransactionResponse {
    fn from(transaction: ConfirmedTransactionView) -> Self {
        Self {
            block_id: transaction.block_id,
            transaction: transaction.transaction,
            result: transaction.result,
            block_height: transaction.block_height,
            canonical: transaction.canonical,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SignerActivityResponse {
    pub blocks_signed: u64,
}

#[derive(Debug, Serialize)]
pub struct StackerSetResponse {
    pub reward_cycle: u64,
    pub reward_set: RewardSet,
}

#[derive(Debug, Serialize)]
pub struct SortitionsResponse {
    pub sortitions: Vec<SortitionInfo>,
}

#[derive(Debug, Serialize)]
pub struct HeadersResponse {
    pub headers: Vec<ExtendedStacksHeader>,
}

#[derive(Debug, Serialize)]
pub struct TenureForkInfoResponse {
    pub tenures: Vec<TenureForkingInfo>,
}

#[derive(Debug, Serialize)]
pub struct TenureTipResponse {
    pub header_type: BlockHeaderType,
    #[serde(flatten)]
    pub header: BlockHeaderResponse,
    pub burn_view: Option<ConsensusHash>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockHeaderType {
    Epoch2,
    Nakamoto,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BlockHeaderResponse {
    Epoch2(StacksBlockHeader),
    Nakamoto(NakamotoBlockHeader),
}

impl From<TenureTipView> for TenureTipResponse {
    fn from(tip: TenureTipView) -> Self {
        let (header_type, header) = match tip.header {
            StacksBlockHeaderTypes::Epoch2(header) => {
                (BlockHeaderType::Epoch2, BlockHeaderResponse::Epoch2(header))
            }
            StacksBlockHeaderTypes::Nakamoto(header) => (
                BlockHeaderType::Nakamoto,
                BlockHeaderResponse::Nakamoto(header),
            ),
        };
        Self {
            header_type,
            header,
            burn_view: tip.burn_view,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TenureBlocksPageResponse {
    pub consensus_hash: ConsensusHash,
    pub last_sortition_consensus_hash: ConsensusHash,
    pub burn_block_height: u64,
    pub burn_block_hash: BurnchainHeaderHash,
    pub blocks: Vec<RPCTenureBlock>,
    pub next_cursor: Option<StacksBlockId>,
}

impl From<TenureBlocksPage> for TenureBlocksPageResponse {
    fn from(page: TenureBlocksPage) -> Self {
        Self {
            consensus_hash: page.consensus_hash,
            last_sortition_consensus_hash: page.last_sortition_consensus_hash,
            burn_block_height: page.burn_block_height,
            burn_block_hash: page.burn_block_hash,
            blocks: page.blocks,
            next_cursor: page.next_cursor,
        }
    }
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
