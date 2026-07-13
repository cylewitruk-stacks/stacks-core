use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use axum::Router;
use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use stacks::burnchains::Txid;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::boot::RewardSet;
use stacks::chainstate::stacks::db::ExtendedStacksHeader;
use stacks::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use stacks::core::{StacksEpoch, StacksEpochId};
use stacks::net::api::get_tenures_fork_info::TenureForkingInfo;
use stacks::net::api::getinfo::RPCPeerInfoData;
use stacks::net::api::getpoxinfo::RPCPoxInfoData;
use stacks::net::api::getsortition::SortitionInfo;
use stacks::net::api::postblock_proposal::NakamotoBlockProposal;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_bridge::{BlockProposalQuery, MempoolQuery, RpcEndpoints, RpcNodeHandle};
use stacks::net::rpc_services::{
    AccountView, BlockProposalAccepted, BlockProposalError, ClarityValueView,
    ConfirmedTransactionView, ContractSourceView, CurrentTenureView, FeeEstimateTier,
    FeeEstimateView, MempoolTransactionView, MempoolTransactionsPage, NodeHealthView,
    NodeStateSnapshot, ProofBytes, ReadOnlyCallView, SortitionQuery, TenureBlocksPage,
    TenureSelector, TenureTipView, TransactionSubmission, TransactionSubmissionStatus,
};
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha256Sum;

use super::super::chainstate::{ChainstateReadExecutor, ChainstateReadService};
use super::super::fees::{FeeEstimationExecutor, FeeEstimationService};
use super::super::mempool::{MempoolReadExecutor, MempoolReadService};
use super::*;
use crate::error::{ApiError, ApiErrorCode};

fn sample_info() -> RPCPeerInfoData {
    RPCPeerInfoData {
        peer_version: 1,
        pox_consensus: ConsensusHash([1; 20]),
        burn_block_height: 2,
        stable_pox_consensus: ConsensusHash([3; 20]),
        stable_burn_block_height: 4,
        server_version: "stacks-node-test".to_string(),
        network_id: 5,
        parent_network_id: 6,
        stacks_tip_height: 7,
        stacks_tip: BlockHeaderHash([8; 32]),
        stacks_tip_consensus_hash: ConsensusHash([9; 20]),
        genesis_chainstate_hash: Sha256Sum([10; 32]),
        unanchored_tip: Some(StacksBlockId([11; 32])),
        unanchored_seq: Some(12),
        tenure_height: 13,
        exit_at_block_height: None,
        is_fully_synced: true,
        node_public_key: None,
        node_public_key_hash: None,
        last_pox_anchor: None,
        stackerdbs: Some(vec!["ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.test".into()]),
    }
}

pub fn sample_snapshot() -> NodeStateSnapshot {
    NodeStateSnapshot {
        observed_at: 1234,
        peer_info: sample_info(),
        health: NodeHealthView {
            difference_from_max_peer: 2,
            max_peer_height: 8,
            max_peer_address: Some("127.0.0.1:20444".parse().unwrap()),
            node_tip_height: 6,
        },
        current_tenure: Some(CurrentTenureView {
            consensus_hash: ConsensusHash([10; 20]),
            tenure_start_block_id: StacksBlockId([11; 32]),
            parent_consensus_hash: ConsensusHash([12; 20]),
            parent_tenure_start_block_id: StacksBlockId([13; 32]),
            tip_block_id: StacksBlockId([14; 32]),
            tip_height: 6,
            reward_cycle: 4,
        }),
    }
}

fn sample_account() -> AccountView {
    AccountView {
        balance: 42,
        locked: 0,
        unlock_height: 0,
        nonce: 3,
        balance_proof: ProofBytes::NotRequested,
        nonce_proof: ProofBytes::NotRequested,
    }
}

pub fn sample_block_proposal() -> NakamotoBlockProposal {
    let mut header = NakamotoBlockHeader::empty();
    header.timestamp = get_epoch_time_secs();
    NakamotoBlockProposal {
        block: NakamotoBlock {
            header,
            txs: vec![],
        },
        chain_id: 0x80000000,
        replay_txs: None,
    }
}

pub fn sample_transaction() -> StacksTransaction {
    let private_key = StacksPrivateKey::from_hex(
        "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
    )
    .unwrap();
    let address = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let mut transaction = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::new_contract_call(address, "hello-world", "read", vec![]).unwrap(),
    );
    transaction.chain_id = 0x80000000;
    transaction.auth.set_origin_nonce(2);
    transaction.set_tx_fee(123);
    let mut signer = StacksTransactionSigner::new(&transaction);
    signer.sign_origin(&private_key).unwrap();
    signer.get_tx().unwrap()
}

pub fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

pub fn wait_get(client: &reqwest::blocking::Client, url: &str) -> reqwest::blocking::Response {
    for _ in 0..50 {
        match client.get(url).send() {
            Ok(response) => return response,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    client.get(url).send().unwrap()
}

pub fn spawn_test_router(
    addr: SocketAddr,
    router: Router,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router).await.unwrap();
        });
    }))
}

pub fn spawn_axum_rpc_server(
    bind_addr: SocketAddr,
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
) -> std::io::Result<thread::JoinHandle<()>> {
    spawn_test_router(
        bind_addr,
        router(
            node,
            chainstate_reads,
            mock_mempool_reads(),
            FeeEstimationService::new(None),
            auth_token,
        ),
    )
}

pub fn spawn_test_node(node: &RpcNodeHandle, endpoints: RpcEndpoints) {
    node.snapshot.publish(sample_snapshot());

    let RpcEndpoints {
        snapshot: _,
        block_proposal,
        mempool: _,
    } = endpoints;

    thread::spawn(move || {
        if let Ok(BlockProposalQuery::Validate { proposal, reply }) =
            block_proposal.recv_timeout(Duration::from_secs(5))
        {
            assert_eq!(proposal.chain_id, 0x80000000);
            let _ = reply.try_send(Ok(BlockProposalAccepted));
        }
    });
}

pub fn spawn_block_proposal_rejection_endpoint(endpoints: RpcEndpoints, error: BlockProposalError) {
    let RpcEndpoints {
        snapshot: _,
        block_proposal,
        mempool: _,
    } = endpoints;

    thread::spawn(move || {
        if let Ok(BlockProposalQuery::Validate { reply, .. }) =
            block_proposal.recv_timeout(Duration::from_secs(5))
        {
            let _ = reply.try_send(Err(error));
        }
    });
}

pub fn spawn_transaction_endpoint(node: &RpcNodeHandle, endpoints: RpcEndpoints) {
    node.snapshot.publish(sample_snapshot());
    thread::spawn(move || {
        if let Ok(MempoolQuery::SubmitTransaction {
            transaction, reply, ..
        }) = endpoints.mempool.recv_timeout(Duration::from_secs(5))
        {
            let _ = reply.try_send(Ok(TransactionSubmission {
                txid: transaction.txid(),
                status: TransactionSubmissionStatus::Accepted,
            }));
        }
    });
}

pub fn mock_chainstate_reads() -> ChainstateReadService {
    mock_chainstate_reads_with_tip(None)
}

pub fn mock_mempool_reads() -> MempoolReadService {
    MempoolReadService::test_from_executor(MockMempoolReads)
}

struct MockMempoolReads;

pub struct MockFeeEstimator;

impl FeeEstimationExecutor for MockFeeEstimator {
    fn estimate(
        &self,
        _payload: TransactionPayload,
        estimated_len: u64,
        _epoch: StacksEpoch,
    ) -> Result<FeeEstimateView, ApiError> {
        assert_eq!(estimated_len, 512);
        Ok(FeeEstimateView {
            estimated_cost: ExecutionCost::ZERO,
            estimated_cost_scalar: 7,
            estimations: vec![FeeEstimateTier {
                fee_rate: 2.0,
                fee: 512,
            }],
            cost_scalar_change_by_byte: 0.5,
        })
    }
}

impl MempoolReadExecutor for MockMempoolReads {
    fn get_transaction(&self, txid: Txid) -> Result<MempoolTransactionView, ApiError> {
        Ok(sample_mempool_transaction(txid))
    }

    fn get_transactions_page(
        &self,
        cursor: Option<Txid>,
        _limit: u64,
    ) -> Result<MempoolTransactionsPage, ApiError> {
        Ok(MempoolTransactionsPage {
            transactions: vec![sample_mempool_transaction(Txid([7; 32]))],
            next_cursor: cursor.or(Some(Txid([8; 32]))),
        })
    }
}

fn sample_mempool_transaction(txid: Txid) -> MempoolTransactionView {
    let address = StacksAddress::burn_address(false);
    MempoolTransactionView {
        txid,
        transaction: "0x00".into(),
        fee: 123,
        length: 180,
        accepted_at: 1_700_000_000,
        coinbase_height: 42,
        tenure_consensus_hash: ConsensusHash([9; 20]),
        tenure_block_hash: BlockHeaderHash([10; 32]),
        origin_address: address.clone(),
        origin_nonce: 3,
        sponsor_address: address,
        sponsor_nonce: 4,
        time_estimate_ms: Some(500),
    }
}

pub fn mock_chainstate_reads_with_tip(expected_tip: Option<TipRequest>) -> ChainstateReadService {
    ChainstateReadService::from_executor(
        MockChainstateReads {
            expected_tip,
            saturated: false,
            delay: None,
        },
        u32::MAX,
        true,
    )
}

pub fn mock_chainstate_reads_without_txindex() -> ChainstateReadService {
    ChainstateReadService::from_executor(
        MockChainstateReads {
            expected_tip: None,
            saturated: false,
            delay: None,
        },
        u32::MAX,
        false,
    )
}

pub fn saturated_chainstate_reads() -> ChainstateReadService {
    ChainstateReadService::from_executor(
        MockChainstateReads {
            expected_tip: None,
            saturated: true,
            delay: None,
        },
        u32::MAX,
        true,
    )
}

pub fn slow_chainstate_reads(delay: Duration) -> ChainstateReadService {
    ChainstateReadService::from_executor(
        MockChainstateReads {
            expected_tip: None,
            saturated: false,
            delay: Some(delay),
        },
        u32::MAX,
        true,
    )
}

struct MockChainstateReads {
    expected_tip: Option<TipRequest>,
    saturated: bool,
    delay: Option<Duration>,
}

impl ChainstateReadExecutor for MockChainstateReads {
    fn get_current_epoch(&self) -> Result<StacksEpoch, ApiError> {
        Ok(StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: 0,
        })
    }

    fn get_account(
        &self,
        _principal: PrincipalData,
        tip: TipRequest,
        _with_proof: bool,
    ) -> Result<AccountView, ApiError> {
        if let Some(delay) = self.delay {
            thread::sleep(delay);
        }
        if self.saturated {
            return Err(ApiError::unavailable(
                ApiErrorCode::ReadQueueFull,
                "RPC chainstate read pool is busy",
            ));
        }
        if let Some(expected_tip) = &self.expected_tip {
            assert_eq!(&tip, expected_tip);
        }
        Ok(sample_account())
    }

    fn get_nakamoto_block(
        &self,
        block_id: StacksBlockId,
    ) -> Result<stacks::net::rpc_services::NakamotoBlockStreamDescriptor, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            format!("No such block {block_id:?}"),
        ))
    }

    fn get_contract_source(
        &self,
        _contract: QualifiedContractIdentifier,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ContractSourceView, ApiError> {
        self.check_tip(&tip);
        Ok(ContractSourceView {
            source: "(define-constant answer u42)".into(),
            publish_height: 123,
            proof: if with_proof {
                ProofBytes::Present(vec![0xab, 0xcd])
            } else {
                ProofBytes::NotRequested
            },
        })
    }

    fn get_contract_interface(
        &self,
        _contract: QualifiedContractIdentifier,
        _tip: TipRequest,
    ) -> Result<ContractInterface, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            "Contract interface not found",
        ))
    }

    fn get_data_var(
        &self,
        _contract: QualifiedContractIdentifier,
        _name: ClarityName,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        self.check_tip(&tip);
        Ok(sample_clarity_value(with_proof))
    }

    fn get_map_entry(
        &self,
        _contract: QualifiedContractIdentifier,
        _map: ClarityName,
        _key: Value,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        self.check_tip(&tip);
        Ok(sample_clarity_value(with_proof))
    }

    fn get_constant(
        &self,
        _contract: QualifiedContractIdentifier,
        _name: ClarityName,
        tip: TipRequest,
    ) -> Result<ClarityValueView, ApiError> {
        self.check_tip(&tip);
        Ok(sample_clarity_value(false))
    }

    fn is_trait_implemented(
        &self,
        _contract: QualifiedContractIdentifier,
        _trait_contract: QualifiedContractIdentifier,
        _trait_name: ClarityName,
        tip: TipRequest,
    ) -> Result<bool, ApiError> {
        self.check_tip(&tip);
        Ok(true)
    }

    fn get_clarity_metadata(
        &self,
        _contract: QualifiedContractIdentifier,
        key: String,
        tip: TipRequest,
    ) -> Result<String, ApiError> {
        self.check_tip(&tip);
        Ok(format!("metadata:{key}"))
    }

    fn get_nakamoto_block_by_height(
        &self,
        height: u64,
        _tip: TipRequest,
    ) -> Result<stacks::net::rpc_services::NakamotoBlockStreamDescriptor, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            format!("No block at height {height}"),
        ))
    }

    fn get_confirmed_transaction(
        &self,
        txid: Txid,
        tip: TipRequest,
    ) -> Result<ConfirmedTransactionView, ApiError> {
        self.check_tip(&tip);
        Ok(ConfirmedTransactionView {
            block_id: StacksBlockId([0x11; 32]),
            transaction: format!("0x{txid}"),
            result: "0x0703".into(),
            block_height: Some(42),
            canonical: true,
        })
    }

    fn get_signer_block_count(
        &self,
        _signer: Secp256k1PublicKey,
        _reward_cycle: u64,
    ) -> Result<u64, ApiError> {
        Ok(7)
    }

    fn get_tenure_tip(&self, _consensus_hash: ConsensusHash) -> Result<TenureTipView, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            "No blocks in tenure",
        ))
    }

    fn get_pox_info(&self, _tip: TipRequest) -> Result<RPCPoxInfoData, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            "PoX unavailable",
        ))
    }

    fn get_stacker_set(&self, _reward_cycle: u64, _tip: TipRequest) -> Result<RewardSet, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            "Stacker set unavailable",
        ))
    }

    fn get_sortitions(&self, _query: SortitionQuery) -> Result<Vec<SortitionInfo>, ApiError> {
        Err(ApiError::not_found(
            ApiErrorCode::NotFound,
            "Sortition unavailable",
        ))
    }

    fn call_read_only(
        &self,
        _contract: QualifiedContractIdentifier,
        _function: ClarityName,
        _sender: PrincipalData,
        _sponsor: Option<PrincipalData>,
        _arguments: Vec<Value>,
        tip: TipRequest,
    ) -> Result<ReadOnlyCallView, ApiError> {
        self.check_tip(&tip);
        Ok(ReadOnlyCallView::Success("0x0703".into()))
    }

    fn get_headers(
        &self,
        _quantity: u32,
        tip: TipRequest,
    ) -> Result<Vec<ExtendedStacksHeader>, ApiError> {
        self.check_tip(&tip);
        Ok(vec![])
    }

    fn get_tenure_blocks_page(
        &self,
        selector: TenureSelector,
        _cursor: Option<StacksBlockId>,
        _limit: usize,
    ) -> Result<TenureBlocksPage, ApiError> {
        let consensus_hash = match selector {
            TenureSelector::ConsensusHash(hash) => hash,
            _ => ConsensusHash([1; 20]),
        };
        Ok(TenureBlocksPage {
            consensus_hash,
            last_sortition_consensus_hash: ConsensusHash([2; 20]),
            burn_block_height: 100,
            burn_block_hash: stacks_common::types::chainstate::BurnchainHeaderHash([3; 32]),
            blocks: vec![stacks::net::api::gettenureblocks::RPCTenureBlock {
                block_id: StacksBlockId([4; 32]),
                header_type: "nakamoto".into(),
                block_hash: BlockHeaderHash([5; 32]),
                parent_block_id: StacksBlockId([6; 32]),
                height: 99,
            }],
            next_cursor: Some(StacksBlockId([6; 32])),
        })
    }

    fn get_tenure_fork_info(
        &self,
        _start: ConsensusHash,
        _end: ConsensusHash,
    ) -> Result<Vec<TenureForkingInfo>, ApiError> {
        Ok(vec![])
    }
}

impl MockChainstateReads {
    fn check_tip(&self, tip: &TipRequest) {
        if let Some(expected_tip) = &self.expected_tip {
            assert_eq!(tip, expected_tip);
        }
    }
}

fn sample_clarity_value(with_proof: bool) -> ClarityValueView {
    ClarityValueView {
        value: "0x010000000000000000000000000000002a".into(),
        proof: if with_proof {
            ProofBytes::Present(vec![0xab, 0xcd])
        } else {
            ProofBytes::NotRequested
        },
    }
}
