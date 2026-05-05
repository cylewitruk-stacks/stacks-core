// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Byte-level scanner over a single block's encoded trie blob.
//!
//! Walks the trie depth-first from the root and emits, for every reachable
//! `TriePtr` embedded in the encoding, the absolute file offset of its 4-byte
//! `ptr` field along with the decoded value. Used by Phase B's promotion
//! machinery:
//!
//! - The merger consumes [`NodeVisit`] events to build the per-source-block
//!   translation map (old hot-layout offset → new merged-blob offset).
//! - The descendant rewriter consumes [`ScannedPtr`] events to find every
//!   in-descendant ptr field whose `back_block` is in the squash range, so
//!   it can pwrite the post-promotion offset over it.
//!
//! See `.docs/squashing-v1.5-phase-b.md` §5 for the design.
//!
//! # Encoding sites covered
//!
//! - Uncompressed normal-node ptrs ([`crate::chainstate::stacks::index::node::TriePtr::write_bytes`]):
//!   10-byte slots, `ptr` field at relative offset `2..=5`.
//! - Compressed normal-node ptrs ([`crate::chainstate::stacks::index::node::TriePtr::write_bytes_compressed`]):
//!   6-byte non-backptr or 10-byte backptr slots, `ptr` field at relative
//!   offset `2..=5`.
//! - Sparse-list framing (with [`crate::chainstate::stacks::index::bits::SPARSE_PTR_BITMAP_MARKER`]
//!   prefix + bitmap).
//! - `TrieNodePatch` body (base ptr + variable-count diff ptrs).
//!
//! Both production write paths (`write_trie_indirect` /
//! `write_trie_indirect_compressed` in `storage.rs`) are covered.

use std::collections::HashSet;

use crate::chainstate::stacks::index::bits::{
    get_sparse_ptrs_bitmap_size, SPARSE_PTR_BITMAP_MARKER,
};
use crate::chainstate::stacks::index::node::{
    clear_compressed, clear_ctrl_bits, is_backptr, is_compressed, TrieNodeID, TriePtr,
    TRIEPTR_SIZE, TRIEPTR_SIZE_COMPRESSED,
};
use crate::chainstate::stacks::index::Error;
use crate::types::chainstate::{BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE};

/// Header bytes preceding the root node in a serialized block trie blob:
/// `BLOCK_HEADER_HASH_ENCODED_SIZE` bytes of parent block hash + 4 bytes of
/// zero-identifier. The root node's hash starts at exactly this offset.
///
/// Mirrors the `BLOB_HEADER_SIZE` constant in `squash.rs`; redeclared here
/// to keep this module decoupled from the squash pipeline.
const BLOB_HEADER_SIZE: usize = BLOCK_HEADER_HASH_ENCODED_SIZE + 4;

/// One scanner event for a visited node. Emitted before any of the node's
/// own [`ScannedPtr`] events so the consumer can establish per-node context
/// before processing children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeVisit {
    /// Offset of the node's hash within `block_bytes` (i.e. relative to the
    /// start of the block blob). The merger uses this as the translation-map
    /// key for `X.block_id → old_offset → new_offset`.
    pub block_offset: u32,
    /// Decoded node kind. The `Patch` variant indicates a `TrieNodePatch`
    /// body; all other variants are normal trie nodes.
    pub node_kind: TrieNodeID,
}

/// One scanner event for a `TriePtr` field embedded in the encoding. The
/// descendant rewriter pwrite-s `new_value.to_be_bytes()` at
/// `ptr_field_file_offset` to apply a post-promotion offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannedPtr {
    /// Absolute file offset of the 4-byte `ptr` field within the hot file.
    /// Suitable as a `pwrite` target.
    pub ptr_field_file_offset: u64,
    /// The decoded `TriePtr` value. The rewriter inspects `ptr.id` (for the
    /// backptr bit) and `ptr.back_block` to decide whether this entry needs
    /// a rewrite plan entry.
    pub ptr: TriePtr,
}

/// Walk the trie encoded in `block_bytes` depth-first from the root and
/// emit events for every visited node and every embedded `TriePtr`.
///
/// `file_base` is the absolute file offset of `block_bytes[0]` — every
/// `ScannedPtr.ptr_field_file_offset` is computed as `file_base +
/// within_block_offset` so the consumer doesn't have to add the base.
///
/// `on_node` fires once per visited node, before any of the node's own
/// `on_ptr` events. `on_ptr` fires once per non-empty `TriePtr` in the
/// node's body (and additionally per non-empty diff ptr inside `Patch`
/// bodies). Empty `TriePtr` slots are skipped.
///
/// The walker only follows in-block child pointers (those with
/// `back_block == 0` and the backptr bit clear). Backptrs are emitted as
/// `ScannedPtr` events but not recursed into; resolving them would require
/// the full storage stack and is out of scope.
///
/// # Errors
///
/// Returns `Error::CorruptionError` if the encoding is malformed: missing
/// header bytes, invalid node ID, ptr-list runs past EOF, etc. Returns
/// `Error::OverflowError` only on arithmetic overflow when computing
/// offsets, which would require a several-exabyte block.
pub fn scan_block_trie<N, P>(
    block_bytes: &[u8],
    file_base: u64,
    mut on_node: N,
    mut on_ptr: P,
) -> Result<(), Error>
where
    N: FnMut(NodeVisit),
    P: FnMut(ScannedPtr),
{
    if block_bytes.len() < BLOB_HEADER_SIZE {
        return Err(Error::CorruptionError(format!(
            "byte_scanner: block_bytes too short for blob header \
             ({} < {BLOB_HEADER_SIZE})",
            block_bytes.len(),
        )));
    }

    // Trie root always lives at the first byte after the blob header.
    // Walk depth-first via an explicit stack so the recursion depth is
    // bounded by trie depth (in practice <= 32, but explicit is safer).
    //
    // **Cycle guard**: a well-formed trie is acyclic (each node has
    // exactly one parent), but a malformed on-disk blob can carry
    // self-pointing or cyclic in-block ptrs. Without a visited set the
    // walker would loop forever; with one we fail with a clear
    // corruption error on the first revisit.
    let mut stack: Vec<u32> = Vec::with_capacity(64);
    let mut visited: HashSet<u32> = HashSet::new();
    stack.push(BLOB_HEADER_SIZE as u32);

    while let Some(node_offset) = stack.pop() {
        if !visited.insert(node_offset) {
            return Err(Error::CorruptionError(format!(
                "byte_scanner: cyclic trie detected — node at offset {node_offset} \
                 visited twice (self-pointer or in-block back-edge in the encoding)",
            )));
        }
        scan_one_node(
            block_bytes,
            file_base,
            node_offset,
            &mut on_node,
            &mut on_ptr,
            &mut stack,
        )?;
    }

    Ok(())
}

/// Convenience wrapper matching the signature in `.docs/squashing-v1.5-phase-b.md` §5.3.
/// Discards `NodeVisit` events; only emits `ScannedPtr`s. Use this when only
/// the descendant-rewrite use case is needed (no translation-map building).
pub fn scan_serialized_trie_ptr_fields<E>(
    block_bytes: &[u8],
    file_base: u64,
    mut emit: E,
) -> Result<(), Error>
where
    E: FnMut(ScannedPtr),
{
    scan_block_trie(block_bytes, file_base, |_| {}, &mut emit)
}

/// Scan a single node at `node_offset` (offset of its hash within
/// `block_bytes`), emitting one [`NodeVisit`] and zero-or-more
/// [`ScannedPtr`] events. Pushes any in-block child offsets onto `stack`.
fn scan_one_node(
    block_bytes: &[u8],
    file_base: u64,
    node_offset: u32,
    on_node: &mut impl FnMut(NodeVisit),
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    let body_offset = (node_offset as usize)
        .checked_add(TRIEHASH_ENCODED_SIZE)
        .ok_or(Error::OverflowError)?;
    let id_byte = *block_bytes.get(body_offset).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: node body at {body_offset} runs past EOF (len={})",
            block_bytes.len(),
        ))
    })?;

    let cleared = clear_ctrl_bits(id_byte);
    let node_kind = TrieNodeID::from_u8(cleared).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: invalid node ID 0x{id_byte:02x} at offset {body_offset}",
        ))
    })?;

    on_node(NodeVisit {
        block_offset: node_offset,
        node_kind,
    });

    match node_kind {
        TrieNodeID::Leaf | TrieNodeID::LeafSquashed | TrieNodeID::Empty => {
            // Leaves carry no embedded TriePtrs. `Empty` shouldn't occur as
            // a stored node — it only appears as an unoccupied slot inside
            // a parent's ptr list — but treat it as a leaf for scanner
            // purposes (no children).
            Ok(())
        }
        TrieNodeID::Patch => scan_patch_body(block_bytes, file_base, body_offset, on_ptr, stack),
        TrieNodeID::Node4 | TrieNodeID::Node16 | TrieNodeID::Node48 | TrieNodeID::Node256 => {
            scan_normal_node_body(
                block_bytes,
                file_base,
                body_offset,
                id_byte,
                node_kind,
                on_ptr,
                stack,
            )
        }
    }
}

/// Scan the body of a normal (non-patch, non-leaf) node, dispatching by
/// the layout signaled in the id byte: uncompressed dense, compressed
/// dense, or compressed sparse.
fn scan_normal_node_body(
    block_bytes: &[u8],
    file_base: u64,
    body_offset: usize,
    id_byte: u8,
    node_kind: TrieNodeID,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    let slot_count = node_slot_count(node_kind);
    // First byte of the body is the id byte; ptrs (or sparse marker) start
    // at body_offset + 1.
    let ptrs_start = body_offset.checked_add(1).ok_or(Error::OverflowError)?;

    if !is_compressed(id_byte) {
        scan_uncompressed_dense_ptrs(
            block_bytes,
            file_base,
            ptrs_start,
            slot_count,
            on_ptr,
            stack,
        )?;
        return Ok(());
    }

    // Compressed: peek at the first byte of the ptr-list. If it's the
    // sparse marker, decode bitmap-driven; otherwise dense compressed.
    let first = *block_bytes.get(ptrs_start).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: compressed ptr list at {ptrs_start} runs past EOF",
        ))
    })?;

    if first == SPARSE_PTR_BITMAP_MARKER {
        let bitmap_size = get_sparse_ptrs_bitmap_size(id_byte).ok_or_else(|| {
            Error::CorruptionError(format!(
                "byte_scanner: no bitmap size defined for node id 0x{id_byte:02x}",
            ))
        })?;
        let bitmap_start = ptrs_start.checked_add(1).ok_or(Error::OverflowError)?;
        let ptrs_after_bitmap = bitmap_start
            .checked_add(bitmap_size)
            .ok_or(Error::OverflowError)?;
        let bitmap = block_bytes
            .get(bitmap_start..ptrs_after_bitmap)
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "byte_scanner: sparse bitmap at {bitmap_start}..{ptrs_after_bitmap} \
                     runs past EOF (block_len={})",
                    block_bytes.len(),
                ))
            })?
            .to_vec();
        scan_sparse_compressed_ptrs(
            block_bytes,
            file_base,
            ptrs_after_bitmap,
            &bitmap,
            slot_count,
            on_ptr,
            stack,
        )?;
        return Ok(());
    }

    scan_dense_compressed_ptrs(
        block_bytes,
        file_base,
        ptrs_start,
        slot_count,
        on_ptr,
        stack,
    )?;
    Ok(())
}

/// Scan an uncompressed ptr list: `slot_count` slots, each 10 bytes,
/// laid out contiguously. Empty slots are skipped (no event emitted) but
/// still consume their 10 bytes.
fn scan_uncompressed_dense_ptrs(
    block_bytes: &[u8],
    file_base: u64,
    ptrs_start: usize,
    slot_count: usize,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    let mut cursor = ptrs_start;
    for _ in 0..slot_count {
        let end = cursor
            .checked_add(TRIEPTR_SIZE)
            .ok_or(Error::OverflowError)?;
        let slot = block_bytes.get(cursor..end).ok_or_else(|| {
            Error::CorruptionError(format!(
                "byte_scanner: uncompressed ptr at {cursor}..{end} runs past EOF",
            ))
        })?;
        let ptr = TriePtr::from_bytes(slot);
        emit_ptr_and_maybe_recurse(file_base, cursor, &ptr, on_ptr, stack)?;
        cursor = end;
    }
    Ok(())
}

/// Scan a compressed dense ptr list: `slot_count` slots, each 6 (non-backptr)
/// or 10 (backptr) bytes. Empty slots take the 6-byte form.
fn scan_dense_compressed_ptrs(
    block_bytes: &[u8],
    file_base: u64,
    ptrs_start: usize,
    slot_count: usize,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    let mut cursor = ptrs_start;
    for _ in 0..slot_count {
        let (ptr, len) = decode_compressed_ptr_at(block_bytes, cursor)?;
        emit_ptr_and_maybe_recurse(file_base, cursor, &ptr, on_ptr, stack)?;
        cursor = cursor.checked_add(len).ok_or(Error::OverflowError)?;
    }
    Ok(())
}

/// Scan a compressed sparse ptr list: only set bits in `bitmap` have a
/// corresponding compressed ptr. The ptrs follow the bitmap in slot-index
/// order (low bit of byte 0 = slot 0).
fn scan_sparse_compressed_ptrs(
    block_bytes: &[u8],
    file_base: u64,
    ptrs_start: usize,
    bitmap: &[u8],
    slot_count: usize,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    let mut cursor = ptrs_start;
    let mut emitted_slots = 0usize;
    for (byte_index, byte) in bitmap.iter().copied().enumerate() {
        let mut bits = byte;
        while bits != 0 {
            let bit_index = bits.trailing_zeros() as usize;
            let slot_index = byte_index
                .checked_mul(8)
                .and_then(|base| base.checked_add(bit_index))
                .ok_or(Error::OverflowError)?;
            bits &= bits - 1;

            // Defensive: bitmap may be padded past slot_count for sub-byte
            // bitmaps (e.g. Node4 with 1-byte bitmap covers 8 bits but only
            // 4 slots are valid). Skip set bits past the valid range.
            if slot_index >= slot_count {
                continue;
            }

            let (ptr, len) = decode_compressed_ptr_at(block_bytes, cursor)?;
            emit_ptr_and_maybe_recurse(file_base, cursor, &ptr, on_ptr, stack)?;
            cursor = cursor.checked_add(len).ok_or(Error::OverflowError)?;
            emitted_slots = emitted_slots.checked_add(1).ok_or(Error::OverflowError)?;
        }
    }
    let _ = emitted_slots;
    Ok(())
}

/// Scan a `TrieNodePatch` body. Layout:
///
/// ```text
/// [id: 1][base_ptr: compressed (always backptr → 10 bytes)]
///   [diff_len_minus_1: 1][diff_ptrs: compressed × N]
/// ```
///
/// All embedded ptr fields are emitted via `on_ptr`. The base ptr is
/// always a backptr (per `TrieRAM::dump_compressed_consume` which sets
/// the backptr bit when constructing the patch's base) so it is not
/// recursed into. Diff ptrs with `back_block == 0` are recursed into.
fn scan_patch_body(
    block_bytes: &[u8],
    file_base: u64,
    body_offset: usize,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    // Base ptr starts immediately after the id byte.
    let base_ptr_start = body_offset.checked_add(1).ok_or(Error::OverflowError)?;
    let (base_ptr, base_ptr_len) = decode_compressed_ptr_at(block_bytes, base_ptr_start)?;
    emit_ptr_and_maybe_recurse(file_base, base_ptr_start, &base_ptr, on_ptr, stack)?;

    // diff_len_minus_1 byte sits right after the base ptr.
    let diff_len_offset = base_ptr_start
        .checked_add(base_ptr_len)
        .ok_or(Error::OverflowError)?;
    let diff_len_byte = *block_bytes.get(diff_len_offset).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: patch diff_len byte at {diff_len_offset} runs past EOF",
        ))
    })?;
    // Wire format normalizes `len - 1` into a u8; on read we add 1 back.
    let diff_count = (diff_len_byte as usize)
        .checked_add(1)
        .ok_or(Error::OverflowError)?;

    let mut cursor = diff_len_offset.checked_add(1).ok_or(Error::OverflowError)?;
    for _ in 0..diff_count {
        let (diff_ptr, diff_len) = decode_compressed_ptr_at(block_bytes, cursor)?;
        emit_ptr_and_maybe_recurse(file_base, cursor, &diff_ptr, on_ptr, stack)?;
        cursor = cursor.checked_add(diff_len).ok_or(Error::OverflowError)?;
    }
    Ok(())
}

/// Decode a compressed `TriePtr` whose first byte sits at `block_bytes[at]`.
/// Returns the decoded ptr and its byte length (6 or 10).
fn decode_compressed_ptr_at(block_bytes: &[u8], at: usize) -> Result<(TriePtr, usize), Error> {
    // Need at least the minimum compressed length to read.
    let min_end = at
        .checked_add(TRIEPTR_SIZE_COMPRESSED)
        .ok_or(Error::OverflowError)?;
    if block_bytes.len() < min_end {
        return Err(Error::CorruptionError(format!(
            "byte_scanner: compressed ptr at {at} runs past EOF (need >= {min_end}, have {})",
            block_bytes.len(),
        )));
    }

    let id_with_bits = *block_bytes.get(at).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: compressed ptr id byte at {at} runs past EOF",
        ))
    })?;
    let id = clear_compressed(id_with_bits);
    let len = TriePtr::compressed_size_for_id(id);
    let end = at.checked_add(len).ok_or(Error::OverflowError)?;
    let bytes = block_bytes.get(at..end).ok_or_else(|| {
        Error::CorruptionError(format!(
            "byte_scanner: compressed ptr at {at}..{end} runs past EOF",
        ))
    })?;

    // Hand off to the canonical decoder so the scanner stays bug-compatible
    // with the encoder/decoder pair.
    let (ptr, decoded_len) = TriePtr::from_slice_compressed(bytes)?;
    debug_assert_eq!(decoded_len, len);
    Ok((ptr, decoded_len))
}

/// Emit a `ScannedPtr` for the slot at `slot_offset` (within `block_bytes`)
/// and, if the ptr is in-block (non-empty, non-backptr, `back_block == 0`),
/// push its target onto the depth-first walk stack.
fn emit_ptr_and_maybe_recurse(
    file_base: u64,
    slot_offset: usize,
    ptr: &TriePtr,
    on_ptr: &mut impl FnMut(ScannedPtr),
    stack: &mut Vec<u32>,
) -> Result<(), Error> {
    if ptr.is_empty() {
        // Empty slot — emit nothing, no recursion.
        return Ok(());
    }

    // The 4-byte `ptr` field always sits at byte offset 2 within both
    // compressed and uncompressed encodings.
    let ptr_field_block_offset = slot_offset.checked_add(2).ok_or(Error::OverflowError)?;
    let ptr_field_file_offset = file_base
        .checked_add(ptr_field_block_offset as u64)
        .ok_or(Error::OverflowError)?;

    on_ptr(ScannedPtr {
        ptr_field_file_offset,
        ptr: *ptr,
    });

    // Recurse only into in-block targets.
    if !is_backptr(ptr.id()) && ptr.back_block() == 0 {
        stack.push(ptr.ptr());
    }
    Ok(())
}

/// Number of child slots in a normal trie node of the given kind. Patch
/// and leaf kinds have no fixed slot count and aren't valid inputs here.
fn node_slot_count(kind: TrieNodeID) -> usize {
    match kind {
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        // Caller-side dispatch should never reach these; return 0 as a
        // defensive fallback if they do.
        TrieNodeID::Leaf | TrieNodeID::LeafSquashed | TrieNodeID::Empty | TrieNodeID::Patch => 0,
    }
}
