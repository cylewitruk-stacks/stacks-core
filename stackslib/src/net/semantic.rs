// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Transport-independent application services and relayer ingress.
//!
//! Legacy HTTP and native libp2p adapters intentionally use different wire
//! formats and cursors. They share bounded consensus decoding, relayer staging,
//! database snapshots, filtering, and materialization policy here instead of
//! independently reconstructing it in protocol handlers. This module does not
//! own fork choice or chainstate writes; those remain in the canonical relayer.

use std::io::Cursor;

use stacks_common::codec::{read_next_at_most, write_next, StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::Hash160;
use stacks_network_types::{ContentId, NetworkObject, ObjectKind};

use crate::burnchains::Txid;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::{
    StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction, MAX_BLOCK_LEN,
    MAX_TRANSACTION_LEN,
};
use crate::core::mempool::{MemPoolDB, MemPoolSyncData};
use crate::net::atlas::{AtlasDB, Attachment, AttachmentPage};
use crate::net::{Downloaded, NeighborKey, NetworkResult};
use crate::util_lib::db::{DBConn, Error as DbError};

const CONSENSUS_HASH_BYTES: usize = 20;
const MAX_MICROBLOCK_STREAM_ITEMS: u32 = 1024;
const ATTACHMENT_ID_PREFIX: &[u8; 12] = b"STXATTACHV1!";
const MAX_ATTACHMENT_OBJECT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct MempoolInventoryPage {
    pub transactions: Vec<(Txid, StacksTransaction)>,
    pub next_cursor: Option<Txid>,
    pub complete: bool,
}

pub struct MempoolSyncService;

impl MempoolSyncService {
    pub fn inventory_page(
        conn: &DBConn,
        cursor: Option<&Txid>,
        max_items: usize,
        max_id_bytes: usize,
    ) -> Result<MempoolInventoryPage, DbError> {
        let limit = max_items.min(max_id_bytes / 32);
        // Pin ID selection and transaction materialization to one SQLite read
        // snapshot. WAL writers may evict concurrently, but this page cannot
        // advertise from one database view and materialize from another.
        let snapshot = conn.unchecked_transaction()?;
        let (txids, complete) = MemPoolDB::get_txid_page(&snapshot, cursor, limit)?;
        // Advance by the immutable identifier page, even if one of its rows is
        // concurrently evicted before materialization. Advancing by the last
        // materialized transaction would otherwise repeat the page forever
        // when every selected row disappears.
        let next_cursor = txids.last().cloned();
        let mut transactions = Vec::with_capacity(txids.len());
        for txid in txids {
            // A missing row can only predate this snapshot (for example, a
            // repaired/corrupt fixture); omit it but retain cursor progress.
            if let Some(info) = MemPoolDB::get_tx(&snapshot, &txid)? {
                transactions.push((txid, info.tx));
            }
        }
        Ok(MempoolInventoryPage {
            transactions,
            next_cursor,
            complete,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn next_missing_transactions(
        conn: &DBConn,
        query: &MemPoolSyncData,
        coinbase_height: u64,
        cursor: &Txid,
        max_txs: u64,
        max_rows: u64,
    ) -> Result<(Vec<StacksTransaction>, Option<Txid>, u64), DbError> {
        MemPoolDB::static_find_next_missing_transactions(
            conn,
            query,
            coinbase_height,
            cursor,
            max_txs,
            max_rows,
        )
    }
}

#[derive(Debug)]
pub struct AttachmentInventoryPage {
    pub attachments: Vec<(Hash160, Attachment)>,
    pub next_cursor: Option<Hash160>,
    pub complete: bool,
}

pub struct AttachmentSyncService;

impl AttachmentSyncService {
    pub fn inventory_page(
        atlas: &AtlasDB,
        cursor: Option<&Hash160>,
        max_items: usize,
    ) -> Result<AttachmentInventoryPage, DbError> {
        let (attachments, complete) = atlas.get_instantiated_attachment_page(cursor, max_items)?;
        let next_cursor = attachments.last().map(|(hash, _)| hash.clone());
        Ok(AttachmentInventoryPage {
            attachments,
            next_cursor,
            complete,
        })
    }

    pub fn legacy_inventory_pages(
        atlas: &AtlasDB,
        block_id: &StacksBlockId,
        page_indexes: &[u32],
        max_pages: usize,
    ) -> Result<Vec<AttachmentPage>, DbError> {
        if page_indexes.is_empty() || page_indexes.len() > max_pages {
            return Err(DbError::Overflow);
        }
        page_indexes
            .iter()
            .map(|index| {
                atlas
                    .get_attachments_available_at_page_index(*index, block_id)
                    .map(|inventory| AttachmentPage {
                        inventory,
                        index: *index,
                    })
            })
            .collect()
    }
}

/// A canonical Stacks object after bounded consensus decoding, but before
/// contextual chainstate, mempool, or Atlas admission.
///
/// This type deliberately contains no transport identity. Legacy and native
/// adapters must converge here so the relayer remains the only contextual
/// validation and chainstate-writing boundary.
#[derive(Debug)]
pub enum DecodedNetworkObject {
    Transaction(StacksTransaction),
    NakamotoBlock(NakamotoBlock),
    AnchoredBlock(ConsensusHash, StacksBlock),
    ConfirmedMicroblocks(ConsensusHash, Vec<StacksMicroblock>),
    Attachment(Attachment),
}

/// Result of translating one transport object into the shared relayer ingress
/// representation. Atlas retains its own database admission path, so callers
/// must apply its configured size/existence policy before acknowledging it.
#[derive(Debug)]
pub enum RelayerIngressOutcome {
    Staged,
    Attachment(Attachment),
}

/// Explicit compatibility boundary between wire transports and the incumbent
/// relayer. It owns only translation and rollout selection; it never validates
/// fork choice, writes chainstate, selects peers, or assigns punishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayerIngressAdapter {
    accept_legacy_application_data: bool,
}

impl RelayerIngressAdapter {
    pub fn new(accept_legacy_application_data: bool) -> Self {
        Self {
            accept_legacy_application_data,
        }
    }

    /// Remove only incumbent peer application data when native transport is
    /// authoritative. HTTP uploads, generic StackerDB traffic, and progress
    /// counters are intentionally preserved for their separate lifecycles.
    pub fn prepare_pass(&self, result: &mut NetworkResult) {
        if !self.accept_legacy_application_data {
            result.clear_legacy_application_data();
        }
    }

    /// Decode and translate one already authenticated native object into the
    /// same `NetworkResult` fields consumed by the incumbent relayer.
    pub fn stage_object(
        &self,
        result: &mut NetworkResult,
        object: &NetworkObject,
    ) -> Result<RelayerIngressOutcome, String> {
        let decoded = decode_network_object(object)?;
        match decoded {
            DecodedNetworkObject::Transaction(transaction) => {
                result
                    .pushed_transactions
                    .entry(NeighborKey::empty())
                    .or_default()
                    .push((Vec::new(), transaction));
            }
            DecodedNetworkObject::NakamotoBlock(block) => {
                result
                    .nakamoto_blocks
                    .entry(block.block_id())
                    .or_insert(block);
            }
            DecodedNetworkObject::AnchoredBlock(consensus_hash, block) => {
                result.blocks.push(Downloaded {
                    consensus_hash,
                    data: block,
                    download_time_secs: 0,
                });
            }
            DecodedNetworkObject::ConfirmedMicroblocks(consensus_hash, stream) => {
                result.confirmed_microblocks.push(Downloaded {
                    consensus_hash,
                    data: stream,
                    download_time_secs: 0,
                });
            }
            DecodedNetworkObject::Attachment(attachment) => {
                return Ok(RelayerIngressOutcome::Attachment(attachment));
            }
        }
        result
            .libp2p_object_ids
            .push((object.kind, object.content_id));
        Ok(RelayerIngressOutcome::Staged)
    }
}

pub fn decode_network_object(object: &NetworkObject) -> Result<DecodedNetworkObject, String> {
    let decoded = match object.kind {
        ObjectKind::Transaction => DecodedNetworkObject::Transaction(decode_transaction(object)?),
        ObjectKind::NakamotoBlock => {
            DecodedNetworkObject::NakamotoBlock(decode_nakamoto_block(object)?)
        }
        ObjectKind::AnchoredBlock => {
            let (consensus_hash, block) = decode_anchored_block(object)?;
            DecodedNetworkObject::AnchoredBlock(consensus_hash, block)
        }
        ObjectKind::Microblock => {
            let (consensus_hash, stream) = decode_microblock_stream(object)?;
            DecodedNetworkObject::ConfirmedMicroblocks(consensus_hash, stream)
        }
        ObjectKind::Attachment => DecodedNetworkObject::Attachment(decode_attachment(object)?),
        ObjectKind::BlockProposal => {
            return Err("block-proposal objects belong to the private signer plane".to_owned());
        }
    };
    let expected = content_id_for_decoded(&decoded)?;
    if object.content_id != expected {
        return Err("object content ID does not match its consensus payload".to_owned());
    }
    Ok(decoded)
}

fn content_id_for_decoded(object: &DecodedNetworkObject) -> Result<ContentId, String> {
    Ok(match object {
        DecodedNetworkObject::Transaction(transaction) => {
            ContentId::from_bytes(transaction.txid().0)
        }
        DecodedNetworkObject::NakamotoBlock(block) => {
            ContentId::from_bytes(block.header.block_id().0)
        }
        DecodedNetworkObject::AnchoredBlock(consensus_hash, block) => {
            ContentId::from_bytes(StacksBlockId::new(consensus_hash, &block.block_hash()).0)
        }
        DecodedNetworkObject::ConfirmedMicroblocks(consensus_hash, stream) => {
            let tail = stream
                .last()
                .ok_or_else(|| "confirmed microblock stream is empty".to_owned())?;
            ContentId::from_bytes(
                StacksBlockHeader::make_index_block_hash(consensus_hash, &tail.block_hash()).0,
            )
        }
        DecodedNetworkObject::Attachment(attachment) => attachment_content_id(attachment),
    })
}

pub fn decode_attachment(object: &NetworkObject) -> Result<Attachment, String> {
    if object.kind != ObjectKind::Attachment {
        return Err("network object is not an Atlas attachment".to_owned());
    }
    if object.bytes.len() > MAX_ATTACHMENT_OBJECT_BYTES {
        return Err(format!(
            "Atlas attachment exceeds the {MAX_ATTACHMENT_OBJECT_BYTES}-byte transport limit"
        ));
    }
    Ok(Attachment::new(object.bytes.clone()))
}

pub fn attachment_content_id(attachment: &Attachment) -> ContentId {
    let mut id = [0u8; 32];
    id[..ATTACHMENT_ID_PREFIX.len()].copy_from_slice(ATTACHMENT_ID_PREFIX);
    id[ATTACHMENT_ID_PREFIX.len()..].copy_from_slice(&attachment.hash().0);
    ContentId::from_bytes(id)
}

pub fn attachment_hash_from_content_id(content_id: &ContentId) -> Option<Hash160> {
    let bytes = content_id.as_bytes();
    (bytes[..ATTACHMENT_ID_PREFIX.len()] == ATTACHMENT_ID_PREFIX[..])
        .then(|| Hash160::from_bytes(&bytes[ATTACHMENT_ID_PREFIX.len()..]))
        .flatten()
}

pub fn decode_transaction(object: &NetworkObject) -> Result<StacksTransaction, String> {
    if object.kind != ObjectKind::Transaction {
        return Err("network object is not a transaction".to_owned());
    }
    decode_exact(
        &object.bytes,
        MAX_TRANSACTION_LEN as usize,
        "Stacks transaction",
    )
}

pub fn decode_nakamoto_block(object: &NetworkObject) -> Result<NakamotoBlock, String> {
    if object.kind != ObjectKind::NakamotoBlock {
        return Err("network object is not a Nakamoto block".to_owned());
    }
    decode_exact(&object.bytes, MAX_BLOCK_LEN as usize, "Nakamoto block")
}

pub fn decode_anchored_block(
    object: &NetworkObject,
) -> Result<(ConsensusHash, StacksBlock), String> {
    if object.kind != ObjectKind::AnchoredBlock {
        return Err("network object is not an Epoch 2.x anchored block".to_owned());
    }
    let max_object_bytes = MAX_BLOCK_LEN as usize + CONSENSUS_HASH_BYTES;
    if object.bytes.len() > max_object_bytes {
        return Err(format!(
            "Epoch 2.x anchored block object exceeds {max_object_bytes} bytes"
        ));
    }
    let mut cursor = Cursor::new(object.bytes.as_slice());
    let consensus_hash = ConsensusHash::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("invalid anchored block consensus hash: {error}"))?;
    let block = StacksBlock::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("invalid Epoch 2.x anchored block: {error}"))?;
    if cursor.position() != object.bytes.len() as u64 {
        return Err("Epoch 2.x anchored block has trailing bytes".to_owned());
    }
    Ok((consensus_hash, block))
}

pub fn decode_microblock_stream(
    object: &NetworkObject,
) -> Result<(ConsensusHash, Vec<StacksMicroblock>), String> {
    if object.kind != ObjectKind::Microblock {
        return Err("network object is not a confirmed microblock stream".to_owned());
    }
    if object.bytes.len() > MAX_MESSAGE_LEN as usize {
        return Err(format!(
            "confirmed microblock stream exceeds {MAX_MESSAGE_LEN} bytes"
        ));
    }
    let mut cursor = Cursor::new(object.bytes.as_slice());
    let consensus_hash = ConsensusHash::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("invalid microblock parent consensus hash: {error}"))?;
    let stream: Vec<StacksMicroblock> = read_next_at_most(&mut cursor, MAX_MICROBLOCK_STREAM_ITEMS)
        .map_err(|error| format!("invalid confirmed microblock stream: {error}"))?;
    if cursor.position() != object.bytes.len() as u64 {
        return Err("confirmed microblock stream has trailing bytes".to_owned());
    }
    let Some(first) = stream.first() else {
        return Err("confirmed microblock stream is empty".to_owned());
    };
    if first.header.sequence != 0 {
        return Err("confirmed microblock stream does not start at sequence zero".to_owned());
    }
    for pair in stream.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if next.header.sequence != previous.header.sequence.saturating_add(1)
            || next.header.prev_block != previous.block_hash()
        {
            return Err("confirmed microblock stream is not contiguous".to_owned());
        }
    }
    Ok((consensus_hash, stream))
}

pub fn transaction_object(transaction: &StacksTransaction) -> NetworkObject {
    NetworkObject {
        kind: ObjectKind::Transaction,
        content_id: ContentId::from_bytes(transaction.txid().0),
        bytes: transaction.serialize_to_vec(),
    }
}

pub fn nakamoto_block_object(block: &NakamotoBlock) -> NetworkObject {
    NetworkObject {
        kind: ObjectKind::NakamotoBlock,
        content_id: ContentId::from_bytes(block.header.block_id().0),
        bytes: block.serialize_to_vec(),
    }
}

pub fn anchored_block_object(consensus_hash: &ConsensusHash, block: &StacksBlock) -> NetworkObject {
    let mut bytes = consensus_hash.serialize_to_vec();
    bytes.extend(block.serialize_to_vec());
    NetworkObject {
        kind: ObjectKind::AnchoredBlock,
        content_id: ContentId::from_bytes(
            StacksBlockId::new(consensus_hash, &block.block_hash()).0,
        ),
        bytes,
    }
}

pub fn microblock_stream_object(
    parent_consensus_hash: &ConsensusHash,
    stream: &[StacksMicroblock],
) -> Result<NetworkObject, String> {
    if stream.is_empty() || stream.len() > MAX_MICROBLOCK_STREAM_ITEMS as usize {
        return Err("confirmed microblock stream item count is outside policy".to_owned());
    }
    let mut bytes = parent_consensus_hash.serialize_to_vec();
    write_next(&mut bytes, &stream.to_vec())
        .map_err(|error| format!("encode confirmed microblock stream: {error}"))?;
    if bytes.len() > MAX_MESSAGE_LEN as usize {
        return Err(format!(
            "confirmed microblock stream exceeds {MAX_MESSAGE_LEN} bytes"
        ));
    }
    Ok(NetworkObject {
        kind: ObjectKind::Microblock,
        content_id: ContentId::from_bytes(
            StacksBlockHeader::make_index_block_hash(
                parent_consensus_hash,
                &stream
                    .last()
                    .expect("non-empty stream checked above")
                    .block_hash(),
            )
            .0,
        ),
        bytes,
    })
}

pub fn attachment_object(attachment: &Attachment) -> NetworkObject {
    NetworkObject {
        kind: ObjectKind::Attachment,
        content_id: attachment_content_id(attachment),
        bytes: attachment.content.clone(),
    }
}

fn decode_exact<T: StacksMessageCodec>(
    bytes: &[u8],
    limit: usize,
    name: &'static str,
) -> Result<T, String> {
    if bytes.len() > limit {
        return Err(format!("{name} exceeds {limit} bytes"));
    }
    let mut cursor = Cursor::new(bytes);
    let value = T::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(format!("{name} has trailing bytes"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use stacks_common::util::secp256k1::Secp256k1PrivateKey;

    use super::*;
    use crate::core::test_util::make_coinbase_tx;

    fn empty_result() -> NetworkResult {
        NetworkResult::new(
            StacksBlockId([0x11; 32]),
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            ConsensusHash([0x22; 20]),
            HashMap::new(),
        )
    }

    #[test]
    fn relayer_ingress_rejects_mismatched_content_before_mutation() {
        let key = Secp256k1PrivateKey::from_seed(b"semantic-ingress-mismatch");
        let transaction = make_coinbase_tx(&key, 0, 0, 0x8000_0000);
        let mut object = transaction_object(&transaction);
        object.content_id = ContentId::from_bytes([0x99; 32]);
        let mut result = empty_result();

        assert!(RelayerIngressAdapter::new(true)
            .stage_object(&mut result, &object)
            .is_err());
        assert!(result.libp2p_object_ids.is_empty());
        assert!(result.pushed_transactions.is_empty());
    }

    #[test]
    fn native_translation_matches_the_shared_relayer_shape() {
        let key = Secp256k1PrivateKey::from_seed(b"semantic-ingress-transaction");
        let transaction = make_coinbase_tx(&key, 0, 0, 0x8000_0000);
        let object = transaction_object(&transaction);
        let mut result = empty_result();

        assert!(matches!(
            RelayerIngressAdapter::new(true)
                .stage_object(&mut result, &object)
                .unwrap(),
            RelayerIngressOutcome::Staged
        ));
        assert_eq!(
            result.libp2p_object_ids,
            vec![(ObjectKind::Transaction, object.content_id)]
        );
        let staged = result
            .pushed_transactions
            .get(&NeighborKey::empty())
            .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].1, transaction);
    }

    #[test]
    fn native_only_selection_preserves_non_peer_compatibility_inputs() {
        let key = Secp256k1PrivateKey::from_seed(b"semantic-ingress-rollout");
        let transaction = make_coinbase_tx(&key, 0, 0, 0x8000_0000);
        let mut result = empty_result();
        result.pushed_transactions.insert(
            NeighborKey::empty(),
            vec![(Vec::new(), transaction.clone())],
        );
        result.uploaded_transactions.push(transaction.clone());

        RelayerIngressAdapter::new(false).prepare_pass(&mut result);

        assert!(result.pushed_transactions.is_empty());
        assert_eq!(result.uploaded_transactions, vec![transaction]);
        assert_eq!(result.num_state_machine_passes, 7);
        assert_eq!(result.num_inv_sync_passes, 8);
        assert_eq!(result.num_download_passes, 9);
        assert_eq!(result.num_connected_peers, 10);
    }
}
