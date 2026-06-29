// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::net::api::getinfo::RPCPeerInfoData;
use crate::net::api::postblock_proposal::NakamotoBlockProposal;
use crate::net::rpc_services::{BlockProposalAccepted, BlockProposalError, RpcServiceResult};

pub const DEFAULT_DOMAIN_QUEUE_SIZE: usize = 128;

#[derive(Clone)]
pub struct RpcDomainChannels {
    pub peer: SyncSender<PeerQuery>,
    pub block_proposal: SyncSender<BlockProposalQuery>,
    pub mempool: SyncSender<MempoolQuery>,
}

pub struct RpcDomainReceivers {
    pub peer: Receiver<PeerQuery>,
    pub block_proposal: Receiver<BlockProposalQuery>,
    pub mempool: Receiver<MempoolQuery>,
}

pub fn domain_channels() -> (RpcDomainChannels, RpcDomainReceivers) {
    let (peer_tx, peer_rx) = sync_channel(DEFAULT_DOMAIN_QUEUE_SIZE);
    let (block_proposal_tx, block_proposal_rx) = sync_channel(DEFAULT_DOMAIN_QUEUE_SIZE);
    let (mempool_tx, mempool_rx) = sync_channel(DEFAULT_DOMAIN_QUEUE_SIZE);
    (
        RpcDomainChannels {
            peer: peer_tx,
            block_proposal: block_proposal_tx,
            mempool: mempool_tx,
        },
        RpcDomainReceivers {
            peer: peer_rx,
            block_proposal: block_proposal_rx,
            mempool: mempool_rx,
        },
    )
}

pub enum PeerQuery {
    GetInfo {
        reply: SyncSender<RpcServiceResult<RPCPeerInfoData>>,
    },
}

pub enum BlockProposalQuery {
    Validate {
        proposal: NakamotoBlockProposal,
        reply: SyncSender<Result<BlockProposalAccepted, BlockProposalError>>,
    },
}

pub enum MempoolQuery {}

pub fn reply_channel<T>() -> (
    SyncSender<RpcServiceResult<T>>,
    Receiver<RpcServiceResult<T>>,
) {
    sync_channel(1)
}

pub fn status_reply_channel<T, E>() -> (SyncSender<Result<T, E>>, Receiver<Result<T, E>>) {
    sync_channel(1)
}
