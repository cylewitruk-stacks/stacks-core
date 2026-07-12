use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use stacks::burnchains::Txid;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::boot::RewardSet;
use stacks::chainstate::stacks::db::ExtendedStacksHeader;
use stacks::net::api::get_tenures_fork_info::TenureForkingInfo;
use stacks::net::api::getinfo::RPCPeerInfoData;
use stacks::net::api::getpoxinfo::RPCPoxInfoData;
use stacks::net::api::getsortition::SortitionInfo;
use stacks::net::api::postblock_proposal::NakamotoBlockProposal;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_bridge::{rpc_bridge, BlockProposalQuery, RpcEndpoints, RpcNodeHandle};
use stacks::net::rpc_services::{
    AccountView, BlockProposalAccepted, BlockProposalError, ClarityValueView,
    ConfirmedTransactionView, ContractSourceView, ProofBytes, ReadOnlyCallView, SortitionQuery,
    TenureBlocksPage, TenureSelector, TenureTipView,
};
use stacks_common::codec::MAX_PAYLOAD_LEN;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha256Sum;

use super::super::chainstate::{ChainstateReadExecutor, ChainstateReadService};
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

fn sample_block_proposal() -> NakamotoBlockProposal {
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

fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn wait_get(client: &reqwest::blocking::Client, url: &str) -> reqwest::blocking::Response {
    for _ in 0..50 {
        match client.get(url).send() {
            Ok(response) => return response,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    client.get(url).send().unwrap()
}

fn spawn_test_router(addr: SocketAddr, router: Router) -> std::io::Result<thread::JoinHandle<()>> {
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

fn spawn_axum_rpc_server(
    bind_addr: SocketAddr,
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
) -> std::io::Result<thread::JoinHandle<()>> {
    spawn_test_router(bind_addr, router(node, chainstate_reads, auth_token))
}

fn spawn_test_node(node: &RpcNodeHandle, endpoints: RpcEndpoints) {
    node.peer_info.publish(sample_info());

    let RpcEndpoints {
        peer_info: _,
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

fn spawn_block_proposal_rejection_endpoint(endpoints: RpcEndpoints, error: BlockProposalError) {
    let RpcEndpoints {
        peer_info: _,
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

fn mock_chainstate_reads() -> ChainstateReadService {
    mock_chainstate_reads_with_tip(None)
}

fn mock_chainstate_reads_with_tip(expected_tip: Option<TipRequest>) -> ChainstateReadService {
    ChainstateReadService::test_from_executor(MockChainstateReads {
        expected_tip,
        saturated: false,
        delay: None,
    })
}

fn mock_chainstate_reads_without_txindex() -> ChainstateReadService {
    ChainstateReadService::test_from_executor_without_txindex(MockChainstateReads {
        expected_tip: None,
        saturated: false,
        delay: None,
    })
}

fn saturated_chainstate_reads() -> ChainstateReadService {
    ChainstateReadService::test_from_executor(MockChainstateReads {
        expected_tip: None,
        saturated: true,
        delay: None,
    })
}

fn slow_chainstate_reads(delay: Duration) -> ChainstateReadService {
    ChainstateReadService::test_from_executor(MockChainstateReads {
        expected_tip: None,
        saturated: false,
        delay: Some(delay),
    })
}

struct MockChainstateReads {
    expected_tip: Option<TipRequest>,
    saturated: bool,
    delay: Option<Duration>,
}

impl ChainstateReadExecutor for MockChainstateReads {
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

#[test]
fn rejects_bad_principal() {
    assert!(PrincipalData::parse("not-a-principal").is_err());
}

#[test]
fn serves_info_through_snapshot_and_account_through_read_service() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let info_url = format!("http://{addr}/rpc/v1/info");
    let info_response = wait_get(&client, &info_url);
    assert_eq!(info_response.status().as_u16(), StatusCode::OK.as_u16());
    let info: serde_json::Value = info_response.json().unwrap();
    assert_eq!(info["server_version"], "stacks-node-test");
    assert_eq!(info["stacks_tip"]["height"], 7);
    assert_eq!(info["burn_block"]["height"], 2);

    let account_url = format!(
        "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?proof=false"
    );
    let account_response = wait_get(&client, &account_url);
    assert_eq!(account_response.status().as_u16(), StatusCode::OK.as_u16());
    let account: serde_json::Value = account_response.json().unwrap();
    assert_eq!(account["balance"], "42");
    assert_eq!(account["nonce"], 3);
    assert!(account.get("proofs").is_none());

    let bad_block_response = wait_get(&client, &format!("http://{addr}/rpc/v1/blocks/not-a-block"));
    assert_eq!(
        bad_block_response.status().as_u16(),
        StatusCode::BAD_REQUEST.as_u16()
    );
    let bad_block: serde_json::Value = bad_block_response.json().unwrap();
    assert_eq!(bad_block["error"]["code"], "invalid_block_id");
}

#[test]
fn serves_contract_state_resources_through_read_pool() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();
    let base =
        format!("http://{addr}/rpc/v1/contracts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/sample");

    let source = wait_get(&client, &format!("{base}/source?proof=true"));
    assert_eq!(source.status().as_u16(), StatusCode::OK.as_u16());
    let source: serde_json::Value = source.json().unwrap();
    assert_eq!(source["publish_height"], 123);
    assert_eq!(source["proof"], "0xabcd");

    let data_var = wait_get(&client, &format!("{base}/data-vars/answer"));
    assert_eq!(data_var.status().as_u16(), StatusCode::OK.as_u16());
    let data_var: serde_json::Value = data_var.json().unwrap();
    assert_eq!(data_var["value"], "0x010000000000000000000000000000002a");
    assert!(data_var.get("proof").is_none());

    let constant = wait_get(&client, &format!("{base}/constants/answer"));
    assert_eq!(constant.status().as_u16(), StatusCode::OK.as_u16());

    let metadata = wait_get(&client, &format!("{base}/metadata/analysis"));
    assert_eq!(metadata.status().as_u16(), StatusCode::OK.as_u16());
    let metadata: serde_json::Value = metadata.json().unwrap();
    assert_eq!(metadata["value"], "metadata:analysis");

    let map = client
        .post(format!("{base}/maps/entries/entries?proof=true"))
        .json(&serde_json::json!({ "key": "0x03" }))
        .send()
        .unwrap();
    assert_eq!(map.status().as_u16(), StatusCode::OK.as_u16());
    let map: serde_json::Value = map.json().unwrap();
    assert_eq!(map["proof"], "0xabcd");

    let trait_response = wait_get(
        &client,
        &format!("{base}/traits/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/traits/sample-trait"),
    );
    assert_eq!(trait_response.status().as_u16(), StatusCode::OK.as_u16());
    let trait_response: serde_json::Value = trait_response.json().unwrap();
    assert_eq!(trait_response["implemented"], true);

    let call = client
        .post(format!("{base}/functions/read-answer/call-read"))
        .json(&serde_json::json!({
            "sender": "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R",
            "arguments": ["0x03"]
        }))
        .send()
        .unwrap();
    assert_eq!(call.status().as_u16(), StatusCode::OK.as_u16());
    let call: serde_json::Value = call.json().unwrap();
    assert_eq!(call["result"], "0x0703");
}

#[test]
fn contract_state_routes_reject_invalid_identifiers_and_values() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let bad_contract = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/contracts/not-an-address/sample/source"),
    );
    assert_eq!(
        bad_contract.status().as_u16(),
        StatusCode::BAD_REQUEST.as_u16()
    );
    let bad_contract: serde_json::Value = bad_contract.json().unwrap();
    assert_eq!(bad_contract["error"]["code"], "invalid_contract");

    let bad_key = client
        .post(format!(
            "http://{addr}/rpc/v1/contracts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/sample/maps/entries/entries"
        ))
        .json(&serde_json::json!({ "key": "not-hex" }))
        .send()
        .unwrap();
    assert_eq!(bad_key.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
    let bad_key: serde_json::Value = bad_key.json().unwrap();
    assert_eq!(bad_key["error"]["code"], "invalid_clarity_value");

    let bad_metadata = wait_get(&client, &format!(
        "http://{addr}/rpc/v1/contracts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/sample/metadata/arbitrary"
    ));
    assert_eq!(
        bad_metadata.status().as_u16(),
        StatusCode::BAD_REQUEST.as_u16()
    );
    let bad_metadata: serde_json::Value = bad_metadata.json().unwrap();
    assert_eq!(bad_metadata["error"]["code"], "invalid_metadata_key");
}

#[test]
fn malformed_json_uses_the_api_error_envelope() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();
    let contract =
        format!("http://{addr}/rpc/v1/contracts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/sample");

    for path in ["maps/entries/entries", "functions/read-answer/call-read"] {
        let response = client
            .post(format!("{contract}/{path}"))
            .header("content-type", "application/json")
            .body("{")
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_json");
    }

    let response = client
        .post(format!("{contract}/maps/entries/entries"))
        .body(r#"{"key":"0x03"}"#)
        .send()
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "invalid_content_type");
}

#[test]
fn serves_confirmed_transaction_and_signer_activity_from_read_pool() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let txid = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let transaction = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/transactions/{txid}"),
    );
    assert_eq!(transaction.status().as_u16(), StatusCode::OK.as_u16());
    let transaction: serde_json::Value = transaction.json().unwrap();
    assert_eq!(transaction["block_height"], 42);
    assert_eq!(transaction["canonical"], true);

    let signer = "0243311589af63c2adda04fcd7792c038a05c12a4fe40351b3eb1612ff6b2e5a0e";
    let activity = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/signers/{signer}/cycles/12"),
    );
    assert_eq!(activity.status().as_u16(), StatusCode::OK.as_u16());
    let activity: serde_json::Value = activity.json().unwrap();
    assert_eq!(activity["blocks_signed"], 7);
}

#[test]
fn transaction_lookup_reports_when_indexing_is_disabled() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        node,
        mock_chainstate_reads_without_txindex(),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();
    let txid = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    let response = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/transactions/{txid}"),
    );
    assert_eq!(
        response.status().as_u16(),
        StatusCode::NOT_IMPLEMENTED.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "transaction_index_disabled");
}

#[test]
fn database_read_routes_return_typed_parameter_errors() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let cases = [
        ("transactions/not-a-txid", "invalid_transaction_id"),
        ("blocks/by-height/not-a-height", "invalid_block_height"),
        (
            "signers/not-a-public-key/cycles/1",
            "invalid_signer_public_key",
        ),
        ("tenures/not-a-consensus-hash/tip", "invalid_consensus_hash"),
    ];
    for (path, code) in cases {
        let response = wait_get(&client, &format!("http://{addr}/rpc/v1/{path}"));
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let response: serde_json::Value = response.json().unwrap();
        assert_eq!(response["error"]["code"], code);
    }
}

#[test]
fn serves_bounded_header_and_tenure_fork_queries() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let headers = wait_get(&client, &format!("http://{addr}/rpc/v1/headers?limit=25"));
    assert_eq!(headers.status().as_u16(), StatusCode::OK.as_u16());
    let headers: serde_json::Value = headers.json().unwrap();
    assert_eq!(headers["headers"], serde_json::json!([]));

    let start = "0101010101010101010101010101010101010101";
    let end = "0202020202020202020202020202020202020202";
    let forks = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/tenures/forks/{start}/{end}"),
    );
    assert_eq!(forks.status().as_u16(), StatusCode::OK.as_u16());
    let forks: serde_json::Value = forks.json().unwrap();
    assert_eq!(forks["tenures"], serde_json::json!([]));

    let tenure = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/tenures/by-consensus/{start}/blocks?limit=1"),
    );
    assert_eq!(tenure.status().as_u16(), StatusCode::OK.as_u16());
    let tenure: serde_json::Value = tenure.json().unwrap();
    assert_eq!(tenure["burn_block_height"], 100);
    assert_eq!(tenure["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(
        tenure["next_cursor"],
        "0606060606060606060606060606060606060606060606060606060606060606"
    );
}

#[test]
fn rejects_invalid_proof_and_pagination_as_json_errors() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let proof = wait_get(
        &client,
        &format!("http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?proof=1"),
    );
    assert_eq!(proof.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
    let proof: serde_json::Value = proof.json().unwrap();
    assert_eq!(proof["error"]["code"], "bad_request");

    let pagination = wait_get(&client, &format!("http://{addr}/rpc/v1/headers?limit=0"));
    assert_eq!(
        pagination.status().as_u16(),
        StatusCode::BAD_REQUEST.as_u16()
    );
    let pagination: serde_json::Value = pagination.json().unwrap();
    assert_eq!(pagination["error"]["code"], "invalid_pagination");
}

#[test]
fn info_without_peer_snapshot_returns_503() {
    let (node, _endpoints) = rpc_bridge();
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let info_url = format!("http://{addr}/rpc/v1/info");
    let response = wait_get(&client, &info_url);
    assert_eq!(
        response.status().as_u16(),
        StatusCode::SERVICE_UNAVAILABLE.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "peer_info_unavailable");
}

#[test]
fn account_latest_tip_uses_chainstate_read_service() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        node,
        mock_chainstate_reads_with_tip(Some(TipRequest::UseLatestUnconfirmedTip)),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let account_url = format!(
        "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?tip=latest"
    );
    let account_response = wait_get(&client, &account_url);
    assert_eq!(account_response.status().as_u16(), StatusCode::OK.as_u16());
    let account: serde_json::Value = account_response.json().unwrap();
    assert_eq!(account["balance"], "42");
}

#[test]
fn account_invalid_tip_returns_400() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let account_url = format!(
        "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?tip=not-a-tip"
    );
    let response = wait_get(&client, &account_url);
    assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "invalid_tip");
}

#[test]
fn saturated_chainstate_read_queue_returns_503() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        node,
        saturated_chainstate_reads(),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let account_url =
        format!("http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R");
    let response = wait_get(&client, &account_url);
    assert_eq!(
        response.status().as_u16(),
        StatusCode::SERVICE_UNAVAILABLE.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "read_queue_full");
}

#[test]
fn block_stream_limit_returns_503() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server = spawn_test_router(
        addr,
        router_with_block_stream_limit(node, mock_chainstate_reads(), Some("password".into()), 0),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let block_id = "00".repeat(32);
    let response = wait_get(&client, &format!("http://{addr}/rpc/v1/blocks/{block_id}"));
    assert_eq!(
        response.status().as_u16(),
        StatusCode::SERVICE_UNAVAILABLE.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "block_stream_queue_full");
}

#[test]
fn request_timeout_layer_returns_json_error() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server = spawn_test_router(
        addr,
        router_with_limits(
            node,
            slow_chainstate_reads(Duration::from_millis(100)),
            Some("password".into()),
            RouterLimits {
                request_timeout: Duration::from_millis(10),
                ..RouterLimits::default()
            },
        ),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let account_url =
        format!("http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R");
    let response = wait_get(&client, &account_url);
    assert_eq!(
        response.status().as_u16(),
        StatusCode::SERVICE_UNAVAILABLE.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "request_timeout");
}

#[test]
fn rejects_block_proposal_without_auth() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .json(&sample_block_proposal())
        .send()
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        StatusCode::UNAUTHORIZED.as_u16()
    );
}

#[test]
fn rejects_block_proposal_without_bearer_auth_scheme() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "password")
        .json(&sample_block_proposal())
        .send()
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        StatusCode::UNAUTHORIZED.as_u16()
    );
}

#[test]
fn rejects_oversized_block_proposal() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "Bearer password")
        .header("content-type", "application/json")
        .body(vec![0u8; MAX_PAYLOAD_LEN as usize + 1])
        .send()
        .unwrap();
    assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "body_too_large");
    assert_eq!(
        body["error"]["message"],
        format!("Block proposal body exceeds {MAX_PAYLOAD_LEN} bytes")
    );
}

#[test]
fn serves_block_proposal_through_rpc_bridge() {
    let (node, endpoints) = rpc_bridge();
    spawn_test_node(&node, endpoints);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "Bearer password")
        .json(&sample_block_proposal())
        .send()
        .unwrap();
    assert_eq!(response.status().as_u16(), StatusCode::ACCEPTED.as_u16());
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["status"], "accepted");
    assert_eq!(
        body["message"],
        "Block proposal is processing, result will be returned via the event observer"
    );
}

#[test]
fn block_proposal_rejection_uses_new_api_error_framing() {
    let (node, endpoints) = rpc_bridge();
    spawn_block_proposal_rejection_endpoint(endpoints, BlockProposalError::AlreadyValidating);
    let addr = free_addr();
    let _server =
        spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
            .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "Bearer password")
        .json(&sample_block_proposal())
        .send()
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        StatusCode::TOO_MANY_REQUESTS.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "block_proposal_rejected");
    assert_eq!(
        body["error"]["message"],
        "Proposal currently being evaluated"
    );
}
