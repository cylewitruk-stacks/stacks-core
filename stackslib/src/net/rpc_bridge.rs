// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use crate::chainstate::stacks::StacksTransaction;
use crate::net::api::postblock_proposal::NakamotoBlockProposal;
use crate::net::rpc_services::{
    BlockProposalAccepted, BlockProposalError, NodeStateSnapshot, TransactionSubmission,
    TransactionSubmissionError,
};
use crate::net::Attachment;

pub const DEFAULT_RPC_BRIDGE_QUEUE_SIZE: usize = 128;

#[derive(Clone)]
/// The RPC server's handle to node-owned state and request queues.
pub struct RpcNodeHandle {
    pub snapshot: NodeSnapshot,
    pub block_proposal: SyncSender<BlockProposalQuery>,
    pub mempool: SyncSender<MempoolQuery>,
}

/// P2P-owned endpoints for receiving RPC requests and publishing peer-owned data.
pub struct RpcEndpoints {
    pub snapshot: NodeSnapshot,
    pub block_proposal: Receiver<BlockProposalQuery>,
    pub mempool: Receiver<MempoolQuery>,
}

#[derive(Clone)]
pub struct NodeSnapshot {
    inner: Arc<ArcSwapOption<NodeStateSnapshot>>,
}

impl NodeSnapshot {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::empty()),
        }
    }

    pub fn publish(&self, snapshot: NodeStateSnapshot) {
        self.inner.store(Some(Arc::new(snapshot)));
    }

    pub fn load(&self) -> Option<Arc<NodeStateSnapshot>> {
        self.inner.load_full()
    }
}

impl Default for NodeSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

pub fn rpc_bridge() -> (RpcNodeHandle, RpcEndpoints) {
    let (block_proposal_tx, block_proposal_rx) = sync_channel(DEFAULT_RPC_BRIDGE_QUEUE_SIZE);
    let (mempool_tx, mempool_rx) = sync_channel(DEFAULT_RPC_BRIDGE_QUEUE_SIZE);
    let snapshot = NodeSnapshot::new();
    (
        RpcNodeHandle {
            snapshot: snapshot.clone(),
            block_proposal: block_proposal_tx,
            mempool: mempool_tx,
        },
        RpcEndpoints {
            snapshot,
            block_proposal: block_proposal_rx,
            mempool: mempool_rx,
        },
    )
}

pub enum BlockProposalQuery {
    Validate {
        proposal: NakamotoBlockProposal,
        reply: SyncSender<Result<BlockProposalAccepted, BlockProposalError>>,
    },
}

pub enum MempoolQuery {
    SubmitTransaction {
        transaction: StacksTransaction,
        attachment: Option<Attachment>,
        reply: SyncSender<Result<TransactionSubmission, TransactionSubmissionError>>,
    },
}

pub fn status_reply_channel<T, E>() -> (SyncSender<Result<T, E>>, Receiver<Result<T, E>>) {
    sync_channel(1)
}
