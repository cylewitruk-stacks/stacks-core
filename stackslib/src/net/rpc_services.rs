// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::time::Duration;

use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use clarity::vm::analysis::RuntimeCheckErrorKind;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::clarity_store::{make_contract_hash_key, ContractCommitment};
use clarity::vm::database::{ClarityDatabase, STXBalance, StoreType};
use clarity::vm::errors::ClarityEvalError;
use clarity::vm::errors::VmExecutionError::{self, RuntimeCheck};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, TraitIdentifier};
use clarity::vm::{ClarityName, SymbolicExpression, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{to_hex, Sha256Sum};

use crate::burnchains::{Burnchain, Txid};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::coordinator::Error as CoordinatorError;
use crate::chainstate::nakamoto::miner::make_mem_abort_callback;
use crate::chainstate::nakamoto::{NakamotoChainState, NakamotoStagingBlocksConn, StacksDBIndexed};
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::db::{
    ExtendedStacksHeader, StacksBlockHeaderTypes, StacksChainState,
};
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction, TransactionPayload};
use crate::core::mempool::MemPoolDB;
use crate::core::StacksEpoch;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::{CostEstimator, EstimatorError, FeeEstimator};
use crate::net::api::get_tenures_fork_info::TenureForkingInfo;
use crate::net::api::getinfo::RPCPeerInfoData;
use crate::net::api::getpoxinfo::RPCPoxInfoData;
use crate::net::api::getsortition::{GetSortitionHandler, SortitionInfo};
use crate::net::api::getstackers::{GetStackersErrors, GetStackersResponse};
use crate::net::api::gettenureblocks::RPCTenureBlock;
use crate::net::api::postblock_proposal::NakamotoBlockProposal;
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{Attachment, Error as NetError, RPCHandlerArgs, TipRequest};

#[derive(Debug)]
pub enum RpcServiceError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl RpcServiceError {
    pub fn internal<E: std::fmt::Debug>(context: &str, error: E) -> Self {
        Self::Internal(format!("{context}: {error:?}"))
    }
}

pub type RpcServiceResult<T> = Result<T, RpcServiceError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofBytes {
    NotRequested,
    Missing,
    Present(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub balance: u128,
    pub locked: u128,
    pub unlock_height: u64,
    pub nonce: u64,
    pub balance_proof: ProofBytes,
    pub nonce_proof: ProofBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractSourceView {
    pub source: String,
    pub publish_height: u32,
    pub proof: ProofBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClarityValueView {
    pub value: String,
    pub proof: ProofBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedTransactionView {
    pub block_id: StacksBlockId,
    pub transaction: String,
    pub result: String,
    pub block_height: Option<u64>,
    pub canonical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolTransactionView {
    pub txid: Txid,
    pub transaction: String,
    pub fee: u64,
    pub length: u64,
    pub accepted_at: u64,
    pub coinbase_height: u64,
    pub tenure_consensus_hash: stacks_common::types::chainstate::ConsensusHash,
    pub tenure_block_hash: stacks_common::types::chainstate::BlockHeaderHash,
    pub origin_address: StacksAddress,
    pub origin_nonce: u64,
    pub sponsor_address: StacksAddress,
    pub sponsor_nonce: u64,
    pub time_estimate_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolTransactionsPage {
    pub transactions: Vec<MempoolTransactionView>,
    pub next_cursor: Option<Txid>,
}

#[derive(Debug, Clone)]
pub struct TenureTipView {
    pub header: StacksBlockHeaderTypes,
    pub burn_view: Option<stacks_common::types::chainstate::ConsensusHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SortitionQuery {
    ConsensusHash(stacks_common::types::chainstate::ConsensusHash),
    BurnBlockHash(stacks_common::types::chainstate::BurnchainHeaderHash),
    BurnBlockHeight(u64),
    Latest,
    LatestAndLast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyCallView {
    Success(String),
    NotReadOnly,
    ExecutionTimedOut,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenureSelector {
    ConsensusHash(stacks_common::types::chainstate::ConsensusHash),
    BurnBlockHash(stacks_common::types::chainstate::BurnchainHeaderHash),
    BurnBlockHeight(u64),
}

#[derive(Debug, Clone)]
pub struct TenureBlocksPage {
    pub consensus_hash: stacks_common::types::chainstate::ConsensusHash,
    pub last_sortition_consensus_hash: stacks_common::types::chainstate::ConsensusHash,
    pub burn_block_height: u64,
    pub burn_block_hash: stacks_common::types::chainstate::BurnchainHeaderHash,
    pub blocks: Vec<RPCTenureBlock>,
    pub next_cursor: Option<StacksBlockId>,
}

#[derive(Debug, Clone)]
pub struct BlockProposalAccepted;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSubmission {
    pub txid: Txid,
    pub status: TransactionSubmissionStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FeeEstimateView {
    pub estimated_cost: ExecutionCost,
    pub estimated_cost_scalar: u64,
    pub estimations: Vec<FeeEstimateTier>,
    pub cost_scalar_change_by_byte: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FeeEstimateTier {
    pub fee_rate: f64,
    pub fee: u64,
}

#[derive(Debug)]
pub enum FeeEstimationError {
    NoEstimate(String),
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct NodeStateSnapshot {
    pub observed_at: u64,
    pub peer_info: RPCPeerInfoData,
    pub health: NodeHealthView,
    pub current_tenure: Option<CurrentTenureView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealthView {
    pub difference_from_max_peer: u64,
    pub max_peer_height: u64,
    pub max_peer_address: Option<SocketAddr>,
    pub node_tip_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentTenureView {
    pub consensus_hash: stacks_common::types::chainstate::ConsensusHash,
    pub tenure_start_block_id: StacksBlockId,
    pub parent_consensus_hash: stacks_common::types::chainstate::ConsensusHash,
    pub parent_tenure_start_block_id: StacksBlockId,
    pub tip_block_id: StacksBlockId,
    pub tip_height: u64,
    pub reward_cycle: u64,
}

pub fn estimate_transaction_fee(
    cost_estimator: &dyn CostEstimator,
    fee_estimator: &dyn FeeEstimator,
    metric: &dyn CostMetric,
    payload: &TransactionPayload,
    estimated_len: u64,
    epoch: &StacksEpoch,
) -> Result<FeeEstimateView, FeeEstimationError> {
    use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;

    let estimated_cost = cost_estimator
        .estimate_cost(payload, &epoch.epoch_id)
        .map_err(map_estimator_error)?;
    let scalar = metric.from_cost_and_len(&estimated_cost, &epoch.block_limit, estimated_len);
    let rates = fee_estimator
        .get_rate_estimates()
        .map_err(map_estimator_error)?
        .to_vec();
    let minimum_fee = estimated_len.saturating_mul(MINIMUM_TX_FEE_RATE_PER_BYTE);
    let estimations = rates
        .into_iter()
        .map(|fee_rate| FeeEstimateTier {
            fee_rate,
            fee: ((fee_rate * scalar as f64) as u64).max(minimum_fee),
        })
        .collect();

    Ok(FeeEstimateView {
        estimated_cost,
        estimated_cost_scalar: scalar,
        estimations,
        cost_scalar_change_by_byte: metric.change_per_byte(),
    })
}

fn map_estimator_error(error: EstimatorError) -> FeeEstimationError {
    match error {
        EstimatorError::NoEstimateAvailable => FeeEstimationError::NoEstimate(error.to_string()),
        EstimatorError::SqliteError(_) => {
            FeeEstimationError::Internal(format!("Fee estimator database failed: {error}"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionSubmissionStatus {
    Accepted,
    AlreadyKnown,
}

#[derive(Debug, Clone)]
pub enum TransactionSubmissionError {
    Problematic,
    Rejected(serde_json::Value),
    Internal(String),
}

impl std::fmt::Display for TransactionSubmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Problematic => f.write_str("Transaction failed static problematic checks"),
            Self::Rejected(error) => write!(f, "Transaction rejected by mempool: {error}"),
            Self::Internal(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BlockProposalError {
    AlreadyValidating,
    TooOld,
    Reopen(String),
    NoObserver,
    SpawnFailed,
}

impl std::fmt::Display for BlockProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyValidating => write!(f, "Proposal currently being evaluated"),
            Self::TooOld => write!(f, "Block proposal is too old to process."),
            Self::Reopen(message) => f.write_str(message),
            Self::NoObserver => {
                write!(
                    f,
                    "No `observer` registered for receiving proposal callbacks"
                )
            }
            Self::SpawnFailed => write!(f, "IO error while spawning proposal callback thread"),
        }
    }
}

pub fn get_peer_info(
    network: &PeerNetwork,
    chainstate: &StacksChainState,
    exit_at_block_height: Option<u64>,
    genesis_chainstate_hash: &Sha256Sum,
    ibd: bool,
) -> RPCPeerInfoData {
    RPCPeerInfoData::from_network(
        network,
        chainstate,
        exit_at_block_height,
        genesis_chainstate_hash,
        network.stacks_tip.coinbase_height,
        ibd,
    )
}

pub fn get_node_state_snapshot(
    network: &PeerNetwork,
    chainstate: &StacksChainState,
    exit_at_block_height: Option<u64>,
    genesis_chainstate_hash: &Sha256Sum,
    ibd: bool,
) -> NodeStateSnapshot {
    let (max_peer_address, max_peer_height) = network
        .highest_stacks_neighbor
        .map(|(address, height)| (Some(address), height))
        .unwrap_or((None, 0));
    let node_tip_height = network.stacks_tip.height;
    let current_tenure = network
        .burnchain
        .block_height_to_reward_cycle(network.burnchain_tip.block_height)
        .map(|reward_cycle| CurrentTenureView {
            consensus_hash: network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: network.tenure_start_block_id.clone(),
            parent_consensus_hash: network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &network.parent_stacks_tip.consensus_hash,
                &network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &network.stacks_tip.consensus_hash,
                &network.stacks_tip.block_hash,
            ),
            tip_height: node_tip_height,
            reward_cycle,
        });

    NodeStateSnapshot {
        observed_at: get_epoch_time_secs(),
        peer_info: get_peer_info(
            network,
            chainstate,
            exit_at_block_height,
            genesis_chainstate_hash,
            ibd,
        ),
        health: NodeHealthView {
            difference_from_max_peer: max_peer_height.saturating_sub(node_tip_height),
            max_peer_height,
            max_peer_address,
            node_tip_height,
        },
        current_tenure,
    }
}

/// Trigger block proposal validation.
///
/// The RPC service only starts validation. The eventual validation result is delivered through the
/// node's existing event-observer path, so transports should return an accepted/processing response
/// and not wait for validation completion here.
pub fn start_block_proposal_validation(
    network: &mut PeerNetwork,
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    rpc_args: &RPCHandlerArgs,
    block_proposal: NakamotoBlockProposal,
) -> Result<BlockProposalAccepted, BlockProposalError> {
    if network.is_proposal_thread_running() {
        return Err(BlockProposalError::AlreadyValidating);
    }

    if block_proposal
        .block
        .header
        .timestamp
        .saturating_add(network.get_connection_opts().block_proposal_max_age_secs)
        < get_epoch_time_secs()
    {
        return Err(BlockProposalError::TooOld);
    }

    let (chainstate, _) = chainstate
        .reopen()
        .map_err(|e| BlockProposalError::Reopen(format!("{}", NetError::from(e))))?;
    let sortdb = sortdb
        .reopen()
        .map_err(|e| BlockProposalError::Reopen(format!("{}", NetError::from(e))))?;
    let receiver = rpc_args
        .event_observer
        .and_then(|observer| observer.get_proposal_callback_receiver())
        .ok_or(BlockProposalError::NoObserver)?;
    let thread_info = block_proposal
        .spawn_validation_thread(sortdb, chainstate, receiver, network.get_connection_opts())
        .map_err(|_e| BlockProposalError::SpawnFailed)?;
    network.set_proposal_thread(thread_info);
    Ok(BlockProposalAccepted)
}

pub fn submit_transaction(
    network: &mut PeerNetwork,
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    mempool: &mut MemPoolDB,
    rpc_args: &RPCHandlerArgs,
    transaction: &StacksTransaction,
    attachment: Option<&Attachment>,
) -> Result<TransactionSubmission, TransactionSubmissionError> {
    let txid = transaction.txid();
    if mempool.has_tx(&txid) {
        return Ok(TransactionSubmission {
            txid,
            status: TransactionSubmissionStatus::AlreadyKnown,
        });
    }

    let burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).map_err(|e| {
        TransactionSubmissionError::Internal(format!("Failed to load canonical burn tip: {e}"))
    })?;
    let epoch = SortitionDB::get_stacks_epoch(sortdb.conn(), burn_tip.block_height)
        .map_err(|e| {
            TransactionSubmissionError::Internal(format!("Failed to load Stacks epoch: {e}"))
        })?
        .ok_or_else(|| {
            TransactionSubmissionError::Internal(
                "No Stacks epoch for canonical burn tip".to_string(),
            )
        })?;

    if Relayer::do_static_problematic_checks()
        && Relayer::static_check_problematic_relayed_tx(
            chainstate.mainnet,
            epoch.epoch_id,
            transaction,
        )
        .is_err()
    {
        return Err(TransactionSubmissionError::Problematic);
    }

    mempool
        .submit(
            chainstate,
            sortdb,
            &network.stacks_tip.consensus_hash,
            &network.stacks_tip.block_hash,
            transaction,
            rpc_args.event_observer.as_deref(),
            &epoch.block_limit,
            &epoch.epoch_id,
        )
        .map_err(|error| TransactionSubmissionError::Rejected(error.into_json(&txid)))?;

    if let (Some(attachment), TransactionPayload::ContractCall(contract_call)) =
        (attachment, &transaction.payload)
    {
        if network
            .get_atlasdb()
            .should_keep_attachment(&contract_call.to_clarity_contract_id(), attachment)
        {
            network
                .get_atlasdb_mut()
                .insert_uninstantiated_attachment(attachment)
                .map_err(|e| {
                    TransactionSubmissionError::Internal(format!(
                        "Failed to store contract-call attachment: {e:?}"
                    ))
                })?;
        }
    }

    Ok(TransactionSubmission {
        txid,
        status: TransactionSubmissionStatus::Accepted,
    })
}

pub fn load_stacks_chain_tip(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    tip_req: &TipRequest,
) -> RpcServiceResult<StacksBlockId> {
    match tip_req {
        TipRequest::UseLatestUnconfirmedTip => {
            let unconfirmed_chain_tip_opt = match &mut chainstate.unconfirmed_state {
                Some(unconfirmed_state) => unconfirmed_state
                    .get_unconfirmed_state_if_exists()
                    .map_err(|msg| {
                        RpcServiceError::NotFound(format!("No unconfirmed tip: {msg}"))
                    })?,
                None => None,
            };

            if let Some(unconfirmed_chain_tip) = unconfirmed_chain_tip_opt {
                Ok(unconfirmed_chain_tip)
            } else {
                load_canonical_chain_tip(sortdb, chainstate)
            }
        }
        TipRequest::SpecificTip(tip) => Ok(tip.clone()),
        TipRequest::UseLatestAnchoredTip => load_canonical_chain_tip(sortdb, chainstate),
    }
}

fn load_canonical_chain_tip(
    sortdb: &SortitionDB,
    chainstate: &StacksChainState,
) -> RpcServiceResult<StacksBlockId> {
    match NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb) {
        Ok(Some(tip)) => Ok(StacksBlockId::new(
            &tip.consensus_hash,
            &tip.anchored_header.block_hash(),
        )),
        Ok(None) => Err(RpcServiceError::NotFound(
            "No stacks chain tip exists at this point in time.".to_string(),
        )),
        Err(e) => Err(RpcServiceError::internal("Failed to load chain tip", e)),
    }
}

pub fn get_account(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    account: &PrincipalData,
    tip_req: &TipRequest,
    with_proof: bool,
) -> RpcServiceResult<AccountView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let account_opt_res = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let key = ClarityDatabase::make_key_for_account_balance(account);
                let burn_block_height =
                    clarity_db.get_current_burnchain_block_height().ok()? as u64;
                let v1_unlock_height = clarity_db.get_v1_unlock_height();
                let v2_unlock_height = clarity_db.get_v2_unlock_height().ok()?;
                let v3_unlock_height = clarity_db.get_v3_unlock_height().ok()?;
                let v4_unlock_height = clarity_db.get_v4_unlock_height().ok()?;
                let (balance, balance_proof) = if with_proof {
                    clarity_db
                        .get_data_with_proof::<STXBalance>(&key)
                        .ok()
                        .flatten()
                        .map(|(a, b)| (a, ProofBytes::Present(b)))
                        .unwrap_or_else(|| (STXBalance::zero(), ProofBytes::Missing))
                } else {
                    clarity_db
                        .get_data::<STXBalance>(&key)
                        .ok()
                        .flatten()
                        .map(|a| (a, ProofBytes::NotRequested))
                        .unwrap_or_else(|| (STXBalance::zero(), ProofBytes::NotRequested))
                };

                let key = ClarityDatabase::make_key_for_account_nonce(account);
                let (nonce, nonce_proof) = if with_proof {
                    clarity_db
                        .get_data_with_proof(&key)
                        .ok()
                        .flatten()
                        .map(|(a, b)| (a, ProofBytes::Present(b)))
                        .unwrap_or_else(|| (0, ProofBytes::Missing))
                } else {
                    clarity_db
                        .get_data(&key)
                        .ok()
                        .flatten()
                        .map(|a| (a, ProofBytes::NotRequested))
                        .unwrap_or_else(|| (0, ProofBytes::NotRequested))
                };

                let unlocked = balance
                    .get_available_balance_at_burn_block(
                        burn_block_height,
                        v1_unlock_height,
                        v2_unlock_height,
                        v3_unlock_height,
                        v4_unlock_height,
                    )
                    .ok()?;

                let (locked, unlock_height) = balance.get_locked_balance_at_burn_block(
                    burn_block_height,
                    v1_unlock_height,
                    v2_unlock_height,
                    v3_unlock_height,
                    v4_unlock_height,
                );

                Some(AccountView {
                    balance: unlocked,
                    locked,
                    unlock_height,
                    nonce,
                    balance_proof,
                    nonce_proof,
                })
            })
        },
    );

    match account_opt_res {
        Ok(Some(Some(account))) => Ok(account),
        Ok(Some(None)) | Ok(None) => Err(RpcServiceError::NotFound(format!(
            "Chain tip '{tip}' not found"
        ))),
        Err(e) => Err(RpcServiceError::internal("Failed to read account", e)),
    }
}

pub fn get_contract_source(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    tip_req: &TipRequest,
    with_proof: bool,
) -> RpcServiceResult<ContractSourceView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|db| {
                let source = db.get_contract_src(contract)?;
                let key = make_contract_hash_key(contract);
                let (commitment, proof) = if with_proof {
                    db.get_data_with_proof::<ContractCommitment>(&key)
                        .ok()
                        .flatten()
                        .map(|(commitment, proof)| (commitment, ProofBytes::Present(proof)))?
                } else {
                    db.get_data::<ContractCommitment>(&key)
                        .ok()
                        .flatten()
                        .map(|commitment| (commitment, ProofBytes::NotRequested))?
                };
                Some(ContractSourceView {
                    source,
                    publish_height: commitment.block_height,
                    proof,
                })
            })
        },
    );
    required_clarity_result(result, &tip, "Contract source not found", "contract source")
}

pub fn get_contract_interface(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    tip_req: &TipRequest,
) -> RpcServiceResult<ContractInterface> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            let epoch = clarity_tx.get_epoch();
            clarity_tx.with_analysis_db_readonly(|db| {
                db.load_contract(contract, &epoch)
                    .ok()?
                    .and_then(|analysis| analysis.contract_interface)
            })
        },
    );
    required_clarity_result(
        result,
        &tip,
        "Contract interface not found",
        "contract interface",
    )
}

pub fn get_data_var(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    name: &ClarityName,
    tip_req: &TipRequest,
    with_proof: bool,
) -> RpcServiceResult<ClarityValueView> {
    let key = ClarityDatabase::make_key_for_trip(contract, StoreType::Variable, name);
    get_clarity_db_value(
        sortdb,
        chainstate,
        &key,
        tip_req,
        with_proof,
        "Data variable",
    )
}

pub fn get_map_entry(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    map: &ClarityName,
    key_value: &Value,
    tip_req: &TipRequest,
    with_proof: bool,
) -> RpcServiceResult<ClarityValueView> {
    let key = ClarityDatabase::make_key_for_data_map_entry(contract, map, key_value)
        .map_err(|e| RpcServiceError::BadRequest(format!("Invalid map key: {e:?}")))?;
    let none = Value::none()
        .serialize_to_hex()
        .map_err(|e| RpcServiceError::internal("Failed to serialize Clarity none value", e))?;
    get_optional_clarity_db_value(
        sortdb,
        chainstate,
        &key,
        tip_req,
        with_proof,
        format!("0x{none}"),
    )
}

pub fn get_constant(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    name: &ClarityName,
    tip_req: &TipRequest,
) -> RpcServiceResult<ClarityValueView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|db| {
                let contract = db.get_contract(contract).ok()?;
                let value = contract.lookup_variable(name.as_str())?;
                let value = value.serialize_to_hex().ok()?;
                Some(ClarityValueView {
                    value: format!("0x{value}"),
                    proof: ProofBytes::NotRequested,
                })
            })
        },
    );
    required_clarity_result(result, &tip, "Constant not found", "constant")
}

pub fn is_trait_implemented(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    trait_contract: QualifiedContractIdentifier,
    trait_name: ClarityName,
    tip_req: &TipRequest,
) -> RpcServiceResult<bool> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let trait_id = TraitIdentifier::new(trait_contract.issuer, trait_contract.name, trait_name);
    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|db| {
                let analysis = db.load_contract_analysis(contract).ok().flatten()?;
                if analysis.implemented_traits.contains(&trait_id) {
                    return Some(true);
                }
                let defining_contract = db
                    .load_contract_analysis(&trait_id.contract_identifier)
                    .ok()
                    .flatten()?;
                let definition = defining_contract.get_defined_trait(&trait_id.name)?;
                Some(
                    analysis
                        .check_trait_compliance(
                            &db.get_clarity_epoch_version().ok()?,
                            &trait_id,
                            definition,
                        )
                        .is_ok(),
                )
            })
        },
    );
    required_clarity_result(
        result,
        &tip,
        "Contract analysis or trait definition not found",
        "trait implementation",
    )
}

pub fn get_clarity_metadata(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    key: &str,
    tip_req: &TipRequest,
) -> RpcServiceResult<String> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            clarity_tx
                .with_clarity_db_readonly(|db| db.store.get_metadata(contract, key).ok().flatten())
        },
    );
    required_clarity_result(
        result,
        &tip,
        "Contract metadata not found",
        "contract metadata",
    )
}

fn get_clarity_db_value(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    key: &str,
    tip_req: &TipRequest,
    with_proof: bool,
    resource: &str,
) -> RpcServiceResult<ClarityValueView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let result = read_clarity_db_value(sortdb, chainstate, key, &tip, with_proof, None);
    required_clarity_result(
        result,
        &tip,
        &format!("{resource} not found"),
        &resource.to_lowercase(),
    )
}

fn get_optional_clarity_db_value(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    key: &str,
    tip_req: &TipRequest,
    with_proof: bool,
    missing_value: String,
) -> RpcServiceResult<ClarityValueView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    match read_clarity_db_value(
        sortdb,
        chainstate,
        key,
        &tip,
        with_proof,
        Some(missing_value),
    ) {
        Ok(Some(Some(value))) => Ok(value),
        Ok(Some(None)) => unreachable!("map reads always provide a missing value"),
        Ok(None) => Err(RpcServiceError::NotFound(format!(
            "Chain tip '{tip}' not found"
        ))),
        Err(e) => Err(RpcServiceError::internal("Failed to read map entry", e)),
    }
}

fn read_clarity_db_value(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    key: &str,
    tip: &StacksBlockId,
    with_proof: bool,
    missing_value: Option<String>,
) -> Result<Option<Option<ClarityValueView>>, ChainError> {
    chainstate.maybe_read_only_clarity_tx(
        &sortdb.index_handle_at_block(chainstate, tip)?,
        tip,
        |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|db| {
                if with_proof {
                    db.get_data_with_proof::<String>(key)
                        .ok()
                        .flatten()
                        .map(|(value, proof)| ClarityValueView {
                            value: format!("0x{value}"),
                            proof: ProofBytes::Present(proof),
                        })
                        .or_else(|| {
                            missing_value.clone().map(|value| ClarityValueView {
                                value,
                                proof: ProofBytes::Missing,
                            })
                        })
                } else {
                    db.get_data::<String>(key)
                        .ok()
                        .flatten()
                        .map(|value| ClarityValueView {
                            value: format!("0x{value}"),
                            proof: ProofBytes::NotRequested,
                        })
                        .or_else(|| {
                            missing_value.clone().map(|value| ClarityValueView {
                                value,
                                proof: ProofBytes::NotRequested,
                            })
                        })
                }
            })
        },
    )
}

fn required_clarity_result<T>(
    result: Result<Option<Option<T>>, ChainError>,
    tip: &StacksBlockId,
    missing_message: &str,
    operation: &str,
) -> RpcServiceResult<T> {
    match result {
        Ok(Some(Some(value))) => Ok(value),
        Ok(Some(None)) => Err(RpcServiceError::NotFound(missing_message.to_string())),
        Ok(None) => Err(RpcServiceError::NotFound(format!(
            "Chain tip '{tip}' not found"
        ))),
        Err(e) => Err(RpcServiceError::internal(
            &format!("Failed to read {operation}"),
            e,
        )),
    }
}

pub struct NakamotoBlockStreamDescriptor {
    pub block_id: StacksBlockId,
    staging_db_conn: NakamotoStagingBlocksConn,
    rowid: i64,
    offset: u64,
}

impl NakamotoBlockStreamDescriptor {
    #[cfg(not(test))]
    const CHUNK_SIZE: usize = 64 * 1024;

    #[cfg(test)]
    const CHUNK_SIZE: usize = 32;

    pub fn generate_next_chunks(&mut self, max_bytes: usize) -> RpcServiceResult<Vec<Vec<u8>>> {
        if max_bytes == 0 {
            return Ok(vec![]);
        }

        let mut blob_fd = self
            .staging_db_conn
            .open_nakamoto_block(self.rowid, false)
            .map_err(|e| RpcServiceError::internal("Failed to open Nakamoto block", e))?;

        blob_fd
            .seek(SeekFrom::Start(self.offset))
            .map_err(|e| RpcServiceError::internal("Failed to seek Nakamoto block", e))?;

        let mut chunks = vec![];
        let mut remaining = max_bytes;

        while remaining > 0 {
            let mut buf = vec![0u8; Self::CHUNK_SIZE.min(remaining)];
            let num_read = blob_fd
                .read(&mut buf)
                .map_err(|e| RpcServiceError::internal("Failed to read Nakamoto block", e))?;
            if num_read == 0 {
                break;
            }
            buf.truncate(num_read);
            self.offset += num_read as u64;
            remaining -= num_read;
            chunks.push(buf);
        }

        Ok(chunks)
    }
}

pub fn get_nakamoto_block_stream(
    chainstate: &StacksChainState,
    block_id: StacksBlockId,
) -> RpcServiceResult<NakamotoBlockStreamDescriptor> {
    if chainstate
        .nakamoto_blocks_db()
        .get_tenure_and_parent_block_id(&block_id)
        .map_err(|e| RpcServiceError::internal("Failed to query Nakamoto block metadata", e))?
        .is_none()
    {
        return Err(RpcServiceError::NotFound(format!(
            "No such block {block_id:?}"
        )));
    }

    let staging_db_path = chainstate
        .get_nakamoto_staging_blocks_path()
        .map_err(|e| RpcServiceError::internal("Failed to get Nakamoto staging DB path", e))?;
    let db_conn = StacksChainState::open_nakamoto_staging_blocks(&staging_db_path, false)
        .map_err(|e| RpcServiceError::internal("Failed to open Nakamoto staging DB", e))?;
    let rowid = db_conn
        .conn()
        .get_nakamoto_block_rowid(&block_id)
        .map_err(|e| RpcServiceError::internal("Failed to query Nakamoto block rowid", e))?
        .ok_or(ChainError::NoSuchBlockError)
        .map_err(|_| RpcServiceError::NotFound(format!("No such block {block_id:?}")))?;

    Ok(NakamotoBlockStreamDescriptor {
        block_id,
        staging_db_conn: db_conn,
        rowid,
        offset: 0,
    })
}

pub fn get_nakamoto_block_stream_by_height(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    height: u64,
    tip_req: &TipRequest,
) -> RpcServiceResult<NakamotoBlockStreamDescriptor> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let block_id = chainstate
        .index_conn()
        .get_ancestor_block_hash(height, &tip)
        .map_err(|e| RpcServiceError::internal("Failed to query block height", e))?
        .ok_or_else(|| RpcServiceError::NotFound(format!("No block at height {height}")))?;
    get_nakamoto_block_stream(chainstate, block_id)
}

pub fn get_confirmed_transaction(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    txid: &Txid,
    tip_req: &TipRequest,
) -> RpcServiceResult<ConfirmedTransactionView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let (block_id, transaction, result) =
        NakamotoChainState::get_tx_info_from_txid(chainstate.index_conn().conn(), txid)
            .map_err(|e| RpcServiceError::internal("Failed to query transaction", e))?
            .ok_or_else(|| RpcServiceError::NotFound(format!("No confirmed transaction {txid}")))?;
    let block_height = chainstate
        .index_conn()
        .get_ancestor_block_height(&block_id, &tip)
        .map_err(|e| RpcServiceError::internal("Failed to query transaction block height", e))?;

    Ok(ConfirmedTransactionView {
        block_id,
        transaction,
        result,
        canonical: block_height.is_some(),
        block_height,
    })
}

pub fn get_mempool_transaction(
    conn: &crate::util_lib::db::DBConn,
    txid: &Txid,
) -> RpcServiceResult<MempoolTransactionView> {
    MemPoolDB::get_tx(conn, txid)
        .map_err(|e| RpcServiceError::internal("Failed to query mempool transaction", e))?
        .map(MempoolTransactionView::from)
        .ok_or_else(|| RpcServiceError::NotFound(format!("No mempool transaction {txid}")))
}

pub fn get_mempool_transactions_page(
    conn: &crate::util_lib::db::DBConn,
    cursor: Option<&Txid>,
    limit: u64,
) -> RpcServiceResult<MempoolTransactionsPage> {
    let (transactions, next_cursor) =
        MemPoolDB::get_txs_page(conn, cursor, limit).map_err(|e| {
            if matches!(e, crate::util_lib::db::Error::NotFoundError) && cursor.is_some() {
                RpcServiceError::BadRequest("Mempool cursor does not exist".to_string())
            } else {
                RpcServiceError::internal("Failed to query mempool transactions", e)
            }
        })?;
    Ok(MempoolTransactionsPage {
        transactions: transactions
            .into_iter()
            .map(MempoolTransactionView::from)
            .collect(),
        next_cursor,
    })
}

impl From<crate::core::mempool::MemPoolTxInfo> for MempoolTransactionView {
    fn from(info: crate::core::mempool::MemPoolTxInfo) -> Self {
        Self {
            txid: info.metadata.txid,
            transaction: format!("0x{}", to_hex(&info.tx.serialize_to_vec())),
            fee: info.metadata.tx_fee,
            length: info.metadata.len,
            accepted_at: info.metadata.accept_time,
            coinbase_height: info.metadata.coinbase_height,
            tenure_consensus_hash: info.metadata.tenure_consensus_hash,
            tenure_block_hash: info.metadata.tenure_block_header_hash,
            origin_address: info.metadata.origin_address,
            origin_nonce: info.metadata.origin_nonce,
            sponsor_address: info.metadata.sponsor_address,
            sponsor_nonce: info.metadata.sponsor_nonce,
            time_estimate_ms: info.metadata.time_estimate_ms,
        }
    }
}

pub fn get_signer_block_count(
    chainstate: &StacksChainState,
    signer: &Secp256k1PublicKey,
    reward_cycle: u64,
) -> RpcServiceResult<u64> {
    NakamotoChainState::get_signer_block_count(&chainstate.index_conn(), signer, reward_cycle)
        .map_err(|e| RpcServiceError::NotFound(format!("Signer activity not found: {e}")))
}

pub fn get_tenure_tip(
    sortdb: &SortitionDB,
    chainstate: &StacksChainState,
    consensus_hash: &stacks_common::types::chainstate::ConsensusHash,
) -> RpcServiceResult<TenureTipView> {
    let header = NakamotoChainState::find_highest_known_block_header_in_tenure(
        chainstate,
        sortdb,
        consensus_hash,
    )
    .map_err(|e| RpcServiceError::internal("Failed to query tenure tip", e))?
    .ok_or_else(|| RpcServiceError::NotFound(format!("No blocks in tenure {consensus_hash}")))?;
    Ok(TenureTipView {
        header: header.anchored_header,
        burn_view: header.burn_view,
    })
}

pub fn get_pox_info(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    burnchain: &Burnchain,
    tip_req: &TipRequest,
) -> RpcServiceResult<RPCPoxInfoData> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    RPCPoxInfoData::from_db(sortdb, chainstate, &tip, burnchain, &BTreeMap::new())
        .map_err(|e| RpcServiceError::internal("Failed to load PoX information", e))
}

pub fn get_stacker_set(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    burnchain: &Burnchain,
    reward_cycle: u64,
    tip_req: &TipRequest,
) -> RpcServiceResult<RewardSet> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    GetStackersResponse::load(sortdb, chainstate, &tip, burnchain, reward_cycle)
        .map(|response| response.stacker_set)
        .map_err(map_stacker_set_error)
}

fn map_stacker_set_error(error: GetStackersErrors) -> RpcServiceError {
    match &error {
        GetStackersErrors::NotAvailableYet(
            CoordinatorError::NotPrepareEndBlock
            | CoordinatorError::NotInPreparePhase
            | CoordinatorError::PoXNotProcessedYet,
        )
        | GetStackersErrors::Other(_) => RpcServiceError::BadRequest(error.to_string()),
        GetStackersErrors::NotAvailableYet(_) => {
            RpcServiceError::Internal(format!("Failed to load stacker set: {error}"))
        }
    }
}

pub fn get_sortitions(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    query: &SortitionQuery,
) -> RpcServiceResult<Vec<SortitionInfo>> {
    let tip = load_canonical_chain_tip(sortdb, chainstate)?;
    let burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .map_err(|e| RpcServiceError::internal("Failed to load canonical burn tip", e))?;
    let snapshot = match query {
        SortitionQuery::Latest => Some(burn_tip.clone()),
        SortitionQuery::ConsensusHash(consensus_hash) => {
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash)
                .map_err(|e| RpcServiceError::internal("Failed to query sortition", e))?
        }
        SortitionQuery::BurnBlockHash(burn_hash) => sortdb
            .index_handle_at_tip()
            .get_block_snapshot(burn_hash)
            .map_err(|e| RpcServiceError::internal("Failed to query sortition", e))?,
        SortitionQuery::BurnBlockHeight(height) => sortdb
            .index_handle_at_tip()
            .get_block_snapshot_by_height(*height)
            .map_err(|e| RpcServiceError::internal("Failed to query sortition", e))?,
        SortitionQuery::LatestAndLast => {
            if burn_tip.sortition {
                Some(burn_tip.clone())
            } else {
                Some(
                    sortdb
                        .index_handle_at_tip()
                        .get_last_snapshot_with_sortition(burn_tip.block_height)
                        .map_err(|e| {
                            RpcServiceError::internal("Failed to query latest sortition", e)
                        })?,
                )
            }
        }
    }
    .ok_or_else(|| RpcServiceError::NotFound(format!("Sortition not found: {query:?}")))?;

    let first = GetSortitionHandler::get_sortition_info(snapshot, sortdb, chainstate, &tip)
        .map_err(|e| RpcServiceError::internal("Failed to load sortition details", e))?;
    let last_sortition = first.last_sortition_ch.clone();
    let mut result = vec![first];
    if matches!(query, SortitionQuery::LatestAndLast) {
        if let Some(last_sortition) = last_sortition {
            let snapshot =
                SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &last_sortition)
                    .map_err(|e| RpcServiceError::internal("Failed to query last sortition", e))?
                    .ok_or_else(|| {
                        RpcServiceError::NotFound(format!(
                            "Last sortition {last_sortition} not found"
                        ))
                    })?;
            result.push(
                GetSortitionHandler::get_sortition_info(snapshot, sortdb, chainstate, &tip)
                    .map_err(|e| {
                        RpcServiceError::internal("Failed to load last sortition details", e)
                    })?,
            );
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub fn call_read_only(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    contract: &QualifiedContractIdentifier,
    function: &ClarityName,
    sender: PrincipalData,
    sponsor: Option<PrincipalData>,
    arguments: Vec<Value>,
    tip_req: &TipRequest,
    mut cost_limit: ExecutionCost,
    max_execution_time: Duration,
    max_memory_bytes: u64,
) -> RpcServiceResult<ReadOnlyCallView> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let args: Vec<_> = arguments
        .into_iter()
        .map(SymbolicExpression::atom_value)
        .collect();
    let mainnet = chainstate.mainnet;
    let chain_id = chainstate.chain_id;
    cost_limit.write_length = 0;
    cost_limit.write_count = 0;

    let result = chainstate.maybe_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(chainstate, &tip)
            .map_err(|e| RpcServiceError::internal("Failed to open sortition index", e))?,
        &tip,
        |clarity_tx| {
            let epoch = clarity_tx.get_epoch();
            let cost_track = clarity_tx
                .with_clarity_db_readonly(|db| {
                    LimitedCostTracker::new_mid_block(mainnet, chain_id, cost_limit, db, epoch)
                })
                .map_err(VmExecutionError::from)?;
            clarity_tx.with_readonly_clarity_env(
                mainnet,
                chain_id,
                sender,
                sponsor,
                cost_track,
                |exec_state, invoke_ctx| {
                    exec_state
                        .global_context
                        .set_abort_callback(make_mem_abort_callback(max_memory_bytes));
                    exec_state
                        .global_context
                        .set_max_execution_time(max_execution_time);
                    // Deliberately allow any public function, not only `define-read-only`
                    // functions. The zero write budget still rejects state changes, while this
                    // permits read-only execution paths that use `contract-call?`.
                    exec_state
                        .execute_contract(invoke_ctx, contract, function.as_str(), &args, false)
                        .map_err(ClarityEvalError::from)
                },
            )
        },
    );

    match result {
        Ok(Some(Ok(value))) => value
            .serialize_to_hex()
            .map(|value| ReadOnlyCallView::Success(format!("0x{value}")))
            .map_err(|e| RpcServiceError::internal("Failed to serialize call result", e)),
        Ok(Some(Err(ClarityEvalError::Vm(RuntimeCheck(
            RuntimeCheckErrorKind::CostBalanceExceeded(actual, _),
        )))))
            if actual.write_count > 0 =>
        {
            Ok(ReadOnlyCallView::NotReadOnly)
        }
        Ok(Some(Err(ClarityEvalError::Vm(RuntimeCheck(
            RuntimeCheckErrorKind::ExecutionTimeExpired,
        ))))) => Ok(ReadOnlyCallView::ExecutionTimedOut),
        Ok(Some(Err(e))) => Ok(ReadOnlyCallView::Failed(e.to_string())),
        Ok(None) => Err(RpcServiceError::NotFound(format!(
            "Chain tip '{tip}' not found"
        ))),
        Err(e) => Err(RpcServiceError::internal(
            "Failed to execute read-only call",
            e,
        )),
    }
}

pub fn get_headers(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    quantity: u32,
    tip_req: &TipRequest,
) -> RpcServiceResult<Vec<ExtendedStacksHeader>> {
    let tip = load_stacks_chain_tip(sortdb, chainstate, tip_req)?;
    let header = StacksChainState::load_staging_block_info(chainstate.db(), &tip)
        .map_err(|e| RpcServiceError::internal("Failed to query header tip", e))?
        .ok_or_else(|| RpcServiceError::NotFound(format!("No header for tip {tip}")))?;
    let quantity = quantity.min(header.height as u32);
    let db = chainstate
        .reopen_db()
        .map_err(|e| RpcServiceError::internal("Failed to open header database", e))?;
    let mut block_id = tip;
    let mut headers = Vec::with_capacity(quantity as usize);
    for _ in 0..quantity {
        match StacksChainState::read_extended_header(&db, &chainstate.blocks_path, &block_id) {
            Ok(header) => {
                block_id = header.parent_block_id.clone();
                headers.push(header);
            }
            Err(ChainError::DBError(crate::util_lib::db::Error::NotFoundError)) => break,
            Err(e) => return Err(RpcServiceError::internal("Failed to read header", e)),
        }
    }
    Ok(headers)
}

pub fn get_tenure_blocks_page(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    selector: &TenureSelector,
    cursor: Option<StacksBlockId>,
    limit: usize,
) -> RpcServiceResult<TenureBlocksPage> {
    let tip = load_canonical_chain_tip(sortdb, chainstate)?;
    let snapshot = get_tenure_snapshot(sortdb, selector)?;
    let last_sortition_consensus_hash = get_prior_sortition(sortdb, chainstate, &snapshot, &tip)?;
    let highest = match selector {
        TenureSelector::ConsensusHash(consensus_hash) => {
            NakamotoChainState::find_highest_known_block_header_in_tenure(
                chainstate,
                sortdb,
                consensus_hash,
            )
        }
        TenureSelector::BurnBlockHash(hash) => {
            NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_hash(
                chainstate, sortdb, hash,
            )
        }
        TenureSelector::BurnBlockHeight(height) => {
            NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_height(
                chainstate, sortdb, *height,
            )
        }
    }
    .map_err(|e| RpcServiceError::internal("Failed to query tenure blocks", e))?;

    let had_cursor = cursor.is_some();
    let mut next_block_id = match cursor {
        Some(cursor) => Some(cursor),
        None => highest.map(|header| header.index_block_hash()),
    };
    let mut blocks = Vec::with_capacity(limit);
    while blocks.len() < limit {
        let Some(block_id) = next_block_id.take() else {
            break;
        };
        let Some(header) = NakamotoChainState::get_block_header(chainstate.db(), &block_id)
            .map_err(|e| RpcServiceError::internal("Failed to read tenure block header", e))?
        else {
            return Err(RpcServiceError::NotFound(format!(
                "Tenure block cursor {block_id} not found"
            )));
        };
        if header.consensus_hash != snapshot.consensus_hash {
            if blocks.is_empty() && had_cursor {
                return Err(RpcServiceError::BadRequest(
                    "Tenure cursor does not belong to the requested tenure".into(),
                ));
            }
            break;
        }
        let parent_block_id = match &header.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(nakamoto) => nakamoto.parent_block_id.clone(),
            StacksBlockHeaderTypes::Epoch2(epoch2) => {
                StacksBlockId::new(&header.consensus_hash, &epoch2.parent_block)
            }
        };
        blocks.push(RPCTenureBlock {
            block_id: header.index_block_hash(),
            header_type: header.header_type_name().into(),
            block_hash: header.anchored_header.block_hash(),
            parent_block_id: parent_block_id.clone(),
            height: header.stacks_block_height,
        });
        next_block_id = Some(parent_block_id);
    }

    let next_cursor = if let Some(next) = next_block_id {
        NakamotoChainState::get_block_header(chainstate.db(), &next)
            .map_err(|e| RpcServiceError::internal("Failed to query tenure page cursor", e))?
            .filter(|header| header.consensus_hash == snapshot.consensus_hash)
            .map(|_| next)
    } else {
        None
    };

    Ok(TenureBlocksPage {
        consensus_hash: snapshot.consensus_hash,
        last_sortition_consensus_hash,
        burn_block_height: snapshot.block_height,
        burn_block_hash: snapshot.burn_header_hash,
        blocks,
        next_cursor,
    })
}

pub fn get_tenure_fork_info(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    start: &stacks_common::types::chainstate::ConsensusHash,
    end: &stacks_common::types::chainstate::ConsensusHash,
) -> RpcServiceResult<Vec<TenureForkingInfo>> {
    const DEPTH_LIMIT: usize = 10;
    let tip = load_canonical_chain_tip(sortdb, chainstate)?;
    let end_snapshot = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), end)
        .map_err(|e| RpcServiceError::internal("Failed to query end tenure", e))?
        .ok_or_else(|| RpcServiceError::NotFound(format!("Tenure {end} not found")))?;
    let height_bound = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), start)
        .map_err(|e| RpcServiceError::internal("Failed to query start tenure", e))?
        .ok_or_else(|| RpcServiceError::NotFound(format!("Tenure {start} not found")))?
        .block_height;
    let mut cursor = end_snapshot;
    let mut result = vec![];
    let mut depth = 0;
    loop {
        if cursor.sortition
            || chainstate
                .nakamoto_blocks_db()
                .is_shadow_tenure(&cursor.consensus_hash)
                .map_err(|e| RpcServiceError::internal("Failed to query shadow tenure", e))?
        {
            result.push(
                TenureForkingInfo::from_snapshot(&cursor, sortdb, chainstate, &tip)
                    .map_err(|e| RpcServiceError::internal("Failed to load tenure fork info", e))?,
            );
        }
        if cursor.consensus_hash == *start || depth >= DEPTH_LIMIT {
            break;
        }
        if height_bound >= cursor.block_height {
            return Err(RpcServiceError::BadRequest(
                "Tenures are not in the same sortition fork".into(),
            ));
        }
        cursor = SortitionDB::get_block_snapshot(sortdb.conn(), &cursor.parent_sortition_id)
            .map_err(|e| RpcServiceError::internal("Failed to walk tenure fork", e))?
            .ok_or_else(|| RpcServiceError::NotFound("Parent tenure not found".into()))?;
        if cursor.sortition {
            depth += 1;
        }
    }
    Ok(result)
}

fn get_tenure_snapshot(
    sortdb: &SortitionDB,
    selector: &TenureSelector,
) -> RpcServiceResult<BlockSnapshot> {
    let snapshot = match selector {
        TenureSelector::ConsensusHash(consensus_hash) => {
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash)
                .map_err(|e| RpcServiceError::internal("Failed to query tenure", e))?
        }
        TenureSelector::BurnBlockHash(hash) => {
            let handle = sortdb.index_handle_at_tip();
            let sortition_id = handle
                .get_sortition_id_for_bhh(hash)
                .map_err(|e| RpcServiceError::internal("Failed to query burn block", e))?
                .ok_or_else(|| RpcServiceError::NotFound(format!("Burn block {hash} not found")))?;
            SortitionDB::get_block_snapshot(handle.conn(), &sortition_id)
                .map_err(|e| RpcServiceError::internal("Failed to query tenure snapshot", e))?
        }
        TenureSelector::BurnBlockHeight(height) => sortdb
            .index_handle_at_tip()
            .get_block_snapshot_by_height(*height)
            .map_err(|e| RpcServiceError::internal("Failed to query burn height", e))?,
    };
    snapshot.ok_or_else(|| RpcServiceError::NotFound(format!("Tenure not found: {selector:?}")))
}

fn get_prior_sortition(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    snapshot: &BlockSnapshot,
    tip: &StacksBlockId,
) -> RpcServiceResult<stacks_common::types::chainstate::ConsensusHash> {
    let is_shadow = chainstate
        .nakamoto_blocks_db()
        .is_shadow_tenure(&snapshot.consensus_hash)
        .map_err(|e| RpcServiceError::internal("Failed to query shadow tenure", e))?;
    if is_shadow {
        return chainstate
            .index_conn()
            .get_parent_tenure_consensus_hash(tip, &snapshot.consensus_hash)
            .map_err(|e| RpcServiceError::internal("Failed to query parent tenure", e))?
            .ok_or_else(|| RpcServiceError::NotFound("Parent tenure not found".into()));
    }
    sortdb
        .index_handle_at_ch(&snapshot.consensus_hash)
        .map_err(|e| RpcServiceError::internal("Failed to open tenure sortition", e))?
        .get_last_snapshot_with_sortition(snapshot.block_height.saturating_sub(1))
        .map(|snapshot| snapshot.consensus_hash)
        .map_err(|e| RpcServiceError::internal("Failed to query prior sortition", e))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::params;
    use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash};

    use super::*;

    #[test]
    fn stacker_set_errors_distinguish_availability_from_internal_failures() {
        assert!(matches!(
            map_stacker_set_error(GetStackersErrors::NotAvailableYet(
                CoordinatorError::NotInPreparePhase
            )),
            RpcServiceError::BadRequest(_)
        ));
        assert!(matches!(
            map_stacker_set_error(GetStackersErrors::NotAvailableYet(
                CoordinatorError::NoSortitions
            )),
            RpcServiceError::Internal(_)
        ));
    }

    fn unique_staging_db_path(test_name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let dir = "/tmp/stacks-node-tests/rpc-services";
        fs::create_dir_all(dir).unwrap();
        format!("{dir}/{test_name}-{nanos}.sqlite")
    }

    #[test]
    fn nakamoto_block_stream_batches_chunks_from_one_offset() {
        let path = unique_staging_db_path("nakamoto-block-stream-batch");
        let conn = StacksChainState::open_nakamoto_staging_blocks(&path, true).unwrap();
        let block_id = StacksBlockId([1; 32]);
        let data: Vec<u8> = (0..95).collect();

        conn.execute(
            "INSERT INTO nakamoto_staging_blocks (
                block_hash,
                consensus_hash,
                parent_block_id,
                is_tenure_start,
                burn_attachable,
                orphaned,
                processed,
                height,
                index_block_hash,
                processed_time,
                obtain_method,
                signing_weight,
                data
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &BlockHeaderHash([2; 32]),
                &ConsensusHash([3; 20]),
                &StacksBlockId([4; 32]),
                0,
                1,
                0,
                0,
                1,
                &block_id,
                0,
                "Pushed",
                0,
                &data,
            ],
        )
        .unwrap();

        let rowid = conn.last_insert_rowid();
        let mut descriptor = NakamotoBlockStreamDescriptor {
            block_id,
            staging_db_conn: conn,
            rowid,
            offset: 0,
        };

        let first_batch = descriptor.generate_next_chunks(70).unwrap();
        assert_eq!(first_batch.len(), 3);
        assert_eq!(first_batch.concat(), data[..70]);

        let second_batch = descriptor.generate_next_chunks(70).unwrap();
        assert_eq!(second_batch.concat(), data[70..]);

        assert!(descriptor.generate_next_chunks(70).unwrap().is_empty());
    }
}
