use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use axum::http::StatusCode;
use clarity::vm::types::PrincipalData;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::net::api::getinfo::RPCPeerInfoData;
use stacks::net::api::postblock_proposal::NakamotoBlockProposal;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_domains::{
    domain_channels, BlockProposalQuery, PeerQuery, RpcDomainReceivers,
};
use stacks::net::rpc_services::{
    AccountView, BlockProposalAccepted, BlockProposalError, ProofBytes,
};
use stacks_common::codec::MAX_PAYLOAD_LEN;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha256Sum;

use crate::chainstate_read::{ChainstateReadExecutor, ChainstateReadService};
use crate::error::{ApiError, ApiErrorCode};
use crate::routes::parse_proof;
use crate::server::spawn_axum_rpc_server;

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

fn spawn_test_domains(receivers: RpcDomainReceivers) {
    let RpcDomainReceivers {
        peer,
        block_proposal,
        mempool: _,
    } = receivers;

    thread::spawn(move || {
        if let Ok(PeerQuery::GetInfo { reply }) = peer.recv_timeout(Duration::from_secs(5)) {
            let _ = reply.try_send(Ok(sample_info()));
        }
    });

    thread::spawn(move || {
        if let Ok(BlockProposalQuery::Validate { proposal, reply }) =
            block_proposal.recv_timeout(Duration::from_secs(5))
        {
            assert_eq!(proposal.chain_id, 0x80000000);
            let _ = reply.try_send(Ok(BlockProposalAccepted));
        }
    });
}

fn spawn_block_proposal_rejection_domain(receivers: RpcDomainReceivers, error: BlockProposalError) {
    let RpcDomainReceivers {
        peer: _,
        block_proposal,
        mempool: _,
    } = receivers;

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
    })
}

fn saturated_chainstate_reads() -> ChainstateReadService {
    ChainstateReadService::test_from_executor(MockChainstateReads {
        expected_tip: None,
        saturated: true,
    })
}

struct MockChainstateReads {
    expected_tip: Option<TipRequest>,
    saturated: bool,
}

impl ChainstateReadExecutor for MockChainstateReads {
    fn get_account(
        &self,
        _principal: PrincipalData,
        tip: TipRequest,
        _with_proof: bool,
    ) -> Result<AccountView, ApiError> {
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
}

#[test]
fn parses_account_query_flags() {
    assert!(parse_proof(Some("1".into())));
    assert!(parse_proof(None));
    assert!(!parse_proof(Some("0".into())));
    assert!(!parse_proof(Some("true".into())));
}

#[test]
fn rejects_bad_principal() {
    assert!(PrincipalData::parse("not-a-principal").is_err());
}

#[test]
fn serves_info_through_peer_channel_and_account_through_read_service() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
        mock_chainstate_reads(),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let info_url = format!("http://{addr}/rpc/v1/info");
    let info_response = wait_get(&client, &info_url);
    assert_eq!(info_response.status().as_u16(), StatusCode::OK.as_u16());
    let info: serde_json::Value = info_response.json().unwrap();
    assert_eq!(info["server_version"], "stacks-node-test");
    assert_eq!(info["stacks_tip"]["height"], 7);
    assert_eq!(info["burn_block"]["height"], 2);

    let account_url =
        format!("http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?proof=0");
    let account_response = wait_get(&client, &account_url);
    assert_eq!(account_response.status().as_u16(), StatusCode::OK.as_u16());
    let account: serde_json::Value = account_response.json().unwrap();
    assert_eq!(account["balance"], "0x0000000000000000000000000000002a");
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
fn account_latest_tip_uses_chainstate_read_service() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
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
    assert_eq!(account["balance"], "0x0000000000000000000000000000002a");
}

#[test]
fn saturated_chainstate_read_queue_returns_503() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
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
fn rejects_block_proposal_without_auth() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
        mock_chainstate_reads(),
        Some("password".into()),
    )
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
fn rejects_oversized_block_proposal() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
        mock_chainstate_reads(),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "password")
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
fn serves_block_proposal_through_domain_channel() {
    let (channels, receivers) = domain_channels();
    spawn_test_domains(receivers);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
        mock_chainstate_reads(),
        Some("password".into()),
    )
    .unwrap();
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("http://{addr}/rpc/v1/block-proposals"))
        .header("authorization", "password")
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
    let (channels, receivers) = domain_channels();
    spawn_block_proposal_rejection_domain(receivers, BlockProposalError::AlreadyValidating);
    let addr = free_addr();
    let _server = spawn_axum_rpc_server(
        addr,
        channels,
        mock_chainstate_reads(),
        Some("password".into()),
    )
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
        StatusCode::TOO_MANY_REQUESTS.as_u16()
    );
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(body["error"]["code"], "block_proposal_rejected");
    assert_eq!(
        body["error"]["message"],
        "Proposal currently being evaluated"
    );
}
