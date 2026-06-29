// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::io::{Read, Seek, SeekFrom};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::database::{ClarityDatabase, STXBalance};
use clarity::vm::types::PrincipalData;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha256Sum;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::{NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::net::api::getinfo::RPCPeerInfoData;
use crate::net::api::postblock_proposal::NakamotoBlockProposal;
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, RPCHandlerArgs, TipRequest};

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

#[derive(Debug, Clone)]
pub struct BlockProposalAccepted;

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
                    )
                    .ok()?;

                let (locked, unlock_height) = balance.get_locked_balance_at_burn_block(
                    burn_block_height,
                    v1_unlock_height,
                    v2_unlock_height,
                    v3_unlock_height,
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

pub struct NakamotoBlockStreamDescriptor {
    pub block_id: StacksBlockId,
    staging_db_conn: NakamotoStagingBlocksConn,
    rowid: i64,
    offset: u64,
}

impl NakamotoBlockStreamDescriptor {
    #[cfg(test)]
    fn hint_chunk_size(&self) -> usize {
        32
    }

    #[cfg(not(test))]
    fn hint_chunk_size(&self) -> usize {
        4096
    }

    pub fn generate_next_chunk(&mut self) -> RpcServiceResult<Vec<u8>> {
        let mut blob_fd = self
            .staging_db_conn
            .open_nakamoto_block(self.rowid, false)
            .map_err(|e| RpcServiceError::internal("Failed to open Nakamoto block", e))?;

        blob_fd
            .seek(SeekFrom::Start(self.offset))
            .map_err(|e| RpcServiceError::internal("Failed to seek Nakamoto block", e))?;

        let mut buf = vec![0u8; self.hint_chunk_size()];
        let num_read = blob_fd
            .read(&mut buf)
            .map_err(|e| RpcServiceError::internal("Failed to read Nakamoto block", e))?;
        buf.truncate(num_read);
        self.offset += num_read as u64;
        Ok(buf)
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
