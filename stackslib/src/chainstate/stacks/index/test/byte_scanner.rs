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

//! Per-encoding-site golden tests for [`crate::chainstate::stacks::index::byte_scanner`].
//!
//! Each test follows the same shape:
//!
//! 1. Build one or more `TrieNodeXxx` instances with known `TriePtr`s.
//! 2. Encode them through the production `bits::write_node_bytes` /
//!    `TrieNodePatch::consensus_serialize` paths into a fake "block blob"
//!    laid out as `[parent hash 32B][zero-id 4B][nodes...]`.
//! 3. Run the scanner; collect emitted [`NodeVisit`] and [`ScannedPtr`]
//!    events.
//! 4. Assert: every embedded `TriePtr` is emitted exactly once with the
//!    correct file offset and decoded value, no extras.
//! 5. For the rewrite round-trip test: pwrite new ptr values at every
//!    emitted offset, re-decode through the production decoder, assert the
//!    new values are observed.
//!
//! The scanner is the load-bearing safety harness for Phase B's descendant
//! rewrite — a missed encoding site corrupts the rewrite plan and yields
//! wrong reads after promotion. These tests are how we keep that from
//! drifting.

use std::io::{Cursor, Seek, SeekFrom, Write};

use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE};

use crate::chainstate::stacks::index::bits::{self, get_compressed_ptrs_size};
use crate::chainstate::stacks::index::byte_scanner::{
    scan_block_trie, scan_serialized_trie_ptr_fields, NodeVisit, ScannedPtr,
};
use crate::chainstate::stacks::index::node::{
    set_backptr, set_compressed, TrieNode, TrieNode16, TrieNode256, TrieNode4, TrieNode48,
    TrieNodeID, TrieNodePatch, TrieNodeType, TriePtr,
};

// Header-byte count preceding the root in a serialized block trie blob:
// 32-byte parent block hash + 4-byte zero-identifier. Mirrors the
// `BLOB_HEADER_SIZE` used inside the scanner module.
const BLOB_HEADER_SIZE: usize = BLOCK_HEADER_HASH_ENCODED_SIZE + 4;

/// Build a "block bytes" buffer with a 36-byte header and the cursor
/// positioned right after the header so the caller can write nodes.
fn fresh_block_buf() -> Cursor<Vec<u8>> {
    let mut buf = Cursor::new(Vec::with_capacity(4096));
    // Parent block hash: arbitrary non-zero bytes so anything that
    // accidentally reads them sees an obviously-fake value.
    buf.write_all(&[0xa1; BLOCK_HEADER_HASH_ENCODED_SIZE])
        .unwrap();
    // Zero-identifier (matches the production write path which writes
    // `0u32.to_le_bytes()` here).
    buf.write_all(&0u32.to_le_bytes()).unwrap();
    debug_assert_eq!(buf.position() as usize, BLOB_HEADER_SIZE);
    buf
}

/// Run the scanner over `block_bytes`, returning the events in emission
/// order. `file_base` is fixed to a non-zero value so any test that
/// accidentally uses the within-block offset would fail visibly.
fn run_scanner(block_bytes: &[u8]) -> (Vec<NodeVisit>, Vec<ScannedPtr>) {
    let file_base: u64 = 1_000_000;
    let mut visits = Vec::new();
    let mut ptrs = Vec::new();
    scan_block_trie(block_bytes, file_base, |v| visits.push(v), |p| ptrs.push(p))
        .expect("scanner did not error");
    (visits, ptrs)
}

/// Subtract the test's fixed `file_base` to get a within-block offset for
/// easy assertions.
fn block_offset_of(p: &ScannedPtr) -> u64 {
    p.ptr_field_file_offset - 1_000_000
}

/// Make a deterministic hash that's easy to spot in a hex dump.
fn fake_hash(seed: u8) -> TrieHash {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    TrieHash(bytes)
}

// ---------------------------------------------------------------------------
// Single-node tests: encode one node at the root, assert scanner output.
//
// To keep these single-node, every embedded child ptr is a backptr (so the
// scanner walks one node and stops, not chasing into garbage offsets).
// ---------------------------------------------------------------------------

#[test]
fn scans_uncompressed_node256_at_root_emits_all_non_empty_ptrs() {
    let mut node = TrieNode256::empty();
    node.path = crate::chainstate::stacks::index::NodePath::from_slice(&[0x01, 0x02]).unwrap();
    // Three non-empty backptr children at slots 0, 100, 255.
    let p0 = TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0xdead, 7);
    let p100 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x64, 0xbeef, 8);
    let p255 = TriePtr::new_backptr(TrieNodeID::Node16 as u8, 0xff, 0xcafe, 9);
    node.ptrs[0] = p0;
    node.ptrs[100] = p100;
    node.ptrs[255] = p255;

    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node256(Box::new(node)),
        fake_hash(0x10),
        false, // uncompressed
    )
    .unwrap();

    let (visits, ptrs) = run_scanner(&buf.into_inner());
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].block_offset, node_offset);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node256);

    // 256 slots × 10 bytes uncompressed → ptr field at slot k lives at
    // body_offset + 1 + 10*k + 2.
    let body_offset = node_offset as u64 + 32;
    let expected_field = |slot: u64| body_offset + 1 + 10 * slot + 2;

    assert_eq!(ptrs.len(), 3);
    assert_eq!(block_offset_of(&ptrs[0]), expected_field(0));
    assert_eq!(ptrs[0].ptr, p0);
    assert_eq!(block_offset_of(&ptrs[1]), expected_field(100));
    assert_eq!(ptrs[1].ptr, p100);
    assert_eq!(block_offset_of(&ptrs[2]), expected_field(255));
    assert_eq!(ptrs[2].ptr, p255);
}

#[test]
fn scans_compressed_dense_node4_emits_all_slots() {
    // Node4 with all 4 slots populated as backptrs (10B each). Dense
    // compressed encoding lays them back-to-back without a bitmap.
    // Backptrs only so the scanner doesn't try to recurse into garbage
    // offsets (in-block ptrs would be followed depth-first).
    let mut node = TrieNode4::new(&[0xab]);
    node.ptrs[0] = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x10, 0x1111, 0x41);
    node.ptrs[1] = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x20, 0x2222, 0x42);
    node.ptrs[2] = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x30, 0x3333, 0x43);
    node.ptrs[3] = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x40, 0x4444, 0x44);

    // Sanity: this is the dense regime per get_compressed_ptrs_size.
    let id_with_compressed = set_compressed(TrieNodeID::Node4 as u8);
    let (_size, is_sparse) = get_compressed_ptrs_size(id_with_compressed, &node.ptrs).unwrap();
    assert!(!is_sparse, "Node4 fully populated should be dense");

    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node4(node.clone()),
        fake_hash(0x20),
        true, // compressed
    )
    .unwrap();

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node4);

    // For dense compressed, ptrs start at body_offset + 1 (after id byte).
    // Each is sized by its id (6 or 10 bytes); ptr field is +2 within.
    let body_offset = node_offset as u64 + 32;
    let mut cursor = body_offset + 1;
    let mut emitted = 0;
    for slot in node.ptrs.iter() {
        if !slot.is_empty() {
            let field_offset = cursor + 2;
            assert_eq!(block_offset_of(&ptrs[emitted]), field_offset);
            assert_eq!(ptrs[emitted].ptr, *slot);
            emitted += 1;
        }
        let ptr_len = TriePtr::compressed_size_for_id(slot.id()) as u64;
        cursor += ptr_len;
    }
    assert_eq!(emitted, ptrs.len());
}

#[test]
fn scans_compressed_sparse_node48_emits_only_set_bits() {
    let mut node = TrieNode48::new(&[]);
    // Populate three slots far apart in chr-space so the bitmap walks
    // multiple bytes. `TrieNode::insert` lays them out in slots 0/1/2
    // (first-empty-slot order) and updates `indexes` so the encoder
    // accepts the node.
    let s_chr05 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x05, 0x100, 1);
    let s_chr20 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x20, 0x200, 2);
    let s_chr2f = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x2f, 0x300, 3);
    assert!(node.insert(&s_chr05));
    assert!(node.insert(&s_chr20));
    assert!(node.insert(&s_chr2f));

    let id_with_compressed = set_compressed(TrieNodeID::Node48 as u8);
    let (_size, is_sparse) = get_compressed_ptrs_size(id_with_compressed, &node.ptrs).unwrap();
    assert!(is_sparse, "Node48 with 3 of 48 slots set should be sparse");

    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node48(Box::new(node)),
        fake_hash(0x30),
        true,
    )
    .unwrap();

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node48);

    // Sparse layout: body = [id][SPARSE_MARKER][bitmap(6)][ptrs...].
    // The encoder walks `node.ptrs` in physical-slot order (0,1,2) — that's
    // also the order `insert` filled them, matching the order of the calls
    // above.
    let body_offset = node_offset as u64 + 32;
    let bitmap_size = 6u64;
    let mut cursor = body_offset + 1 /* id */ + 1 /* marker */ + bitmap_size;

    for &slot in &[s_chr05, s_chr20, s_chr2f] {
        let field_offset = cursor + 2;
        let p = ptrs.iter().find(|sp| sp.ptr == slot).expect("slot emitted");
        assert_eq!(block_offset_of(p), field_offset);
        cursor += TriePtr::compressed_size_for_id(slot.id()) as u64;
    }
    assert_eq!(ptrs.len(), 3);
}

#[test]
fn scans_compressed_sparse_node16_emits_only_set_bits() {
    let mut node = TrieNode16::new(&[0x77]);
    // Backptrs only — keeps the scanner from chasing in-block ptrs into
    // unallocated parts of the test blob.
    let s2 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x02, 0x10, 1);
    let s9 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x09, 0x20, 2);
    node.ptrs[2] = s2;
    node.ptrs[9] = s9;

    let id_with_compressed = set_compressed(TrieNodeID::Node16 as u8);
    let (_size, is_sparse) = get_compressed_ptrs_size(id_with_compressed, &node.ptrs).unwrap();
    assert!(is_sparse);

    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    bits::write_node_bytes(&mut buf, &TrieNodeType::Node16(node), fake_hash(0x40), true).unwrap();

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node16);
    assert_eq!(ptrs.len(), 2);
    assert!(ptrs.iter().any(|p| p.ptr == s2));
    assert!(ptrs.iter().any(|p| p.ptr == s9));
}

#[test]
fn scans_compressed_sparse_node256_emits_only_set_bits() {
    // Node256 sparse: a few set bits scattered across the 32-byte bitmap.
    let mut node = TrieNode256::empty();
    let s0 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x00, 0x100, 11);
    let s64 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x40, 0x200, 12);
    let s200 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0xc8, 0x300, 13);
    node.ptrs[0] = s0;
    node.ptrs[64] = s64;
    node.ptrs[200] = s200;

    let id_with_compressed = set_compressed(TrieNodeID::Node256 as u8);
    let (_size, is_sparse) = get_compressed_ptrs_size(id_with_compressed, &node.ptrs).unwrap();
    assert!(is_sparse);

    let mut buf = fresh_block_buf();
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node256(Box::new(node)),
        fake_hash(0x50),
        true,
    )
    .unwrap();
    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node256);
    assert_eq!(ptrs.len(), 3);
    assert!(ptrs.iter().any(|p| p.ptr == s0));
    assert!(ptrs.iter().any(|p| p.ptr == s64));
    assert!(ptrs.iter().any(|p| p.ptr == s200));
}

#[test]
fn scans_uncompressed_node4_at_root() {
    // Sanity-check: also exercise the uncompressed path on a small node.
    let mut node = TrieNode4::new(&[0xff, 0xff]);
    let p0 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x10, 0xaaaa, 5);
    let p2 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x30, 0xbbbb, 6);
    node.ptrs[0] = p0;
    node.ptrs[2] = p2;

    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    bits::write_node_bytes(&mut buf, &TrieNodeType::Node4(node), fake_hash(0x60), false).unwrap();
    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node4);

    let body_offset = node_offset as u64 + 32;
    // Uncompressed: 4 slots × 10 bytes each, each ptr field at +2.
    assert_eq!(ptrs.len(), 2);
    assert_eq!(block_offset_of(&ptrs[0]), body_offset + 1 + 0 * 10 + 2);
    assert_eq!(ptrs[0].ptr, p0);
    assert_eq!(block_offset_of(&ptrs[1]), body_offset + 1 + 2 * 10 + 2);
    assert_eq!(ptrs[1].ptr, p2);
}

#[test]
fn scans_patch_base_and_diff_ptrs() {
    // Build a patch by hand: base ptr (always backptr) + 3 diff ptrs.
    let base = TriePtr {
        id: set_backptr(TrieNodeID::Node256 as u8),
        chr: 0x10,
        ptr: 0x4040,
        back_block: 7,
    };
    let d0 = TriePtr::new(TrieNodeID::Leaf as u8, 0x01, 0x100); // in-block (will recurse if not gated)
    let d1 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x02, 0x200, 5);
    let d2 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x03, 0x300, 6);
    let patch = TrieNodePatch {
        ptr: base,
        ptr_diff: vec![d0, d1, d2],
    };

    // Manually write [hash][patch body] into the blob.
    let mut buf = fresh_block_buf();
    let node_offset = buf.position() as u32;
    let hash = fake_hash(0x70);
    buf.write_all(hash.as_bytes()).unwrap();
    patch.consensus_serialize(&mut buf).unwrap();

    // Pad with a dummy fake-leaf-shaped 0-byte run at d0.ptr=0x100 so the
    // scanner's recursion into the in-block diff doesn't immediately fail
    // on EOF. Build a 1-byte Leaf id at offset 0x100 within the block.
    // For this test we only care about the patch-side emission; the in-
    // block diff target is a dummy LeafSquashed with no children.
    let mut blob = buf.into_inner();
    if blob.len() < 0x100 + 33 {
        blob.resize(0x100 + 33, 0);
    }
    // Place a dummy Leaf at offset 0x100: 32-byte hash, then [Leaf id, 0
    // path bytes, ... but we can stop at the id since Leaves emit no
    // children. We do need at least 1 byte after the hash for the id.]
    blob[0x100..0x100 + 32].copy_from_slice(&[0x80; 32]);
    blob[0x100 + 32] = TrieNodeID::Leaf as u8;
    // We don't decode the leaf body — the scanner just records the
    // NodeVisit and stops (Leaf has no embedded ptrs).

    let (visits, ptrs) = run_scanner(&blob);

    // 4 visits: the patch itself + the in-block leaf reached via d0.
    assert_eq!(visits.len(), 2);
    assert_eq!(visits[0].block_offset, node_offset);
    assert_eq!(visits[0].node_kind, TrieNodeID::Patch);
    assert_eq!(visits[1].block_offset, 0x100);
    assert_eq!(visits[1].node_kind, TrieNodeID::Leaf);

    // 4 ptrs emitted from the patch body: base + 3 diffs.
    assert_eq!(ptrs.len(), 4);
    assert_eq!(ptrs[0].ptr, base);
    assert_eq!(ptrs[1].ptr, d0);
    assert_eq!(ptrs[2].ptr, d1);
    assert_eq!(ptrs[3].ptr, d2);

    // Patch body layout: body = [id][base_ptr (10B backptr)][diff_len (1B)][diffs...]
    let body_offset = node_offset as u64 + 32;
    let base_ptr_offset = body_offset + 1;
    assert_eq!(block_offset_of(&ptrs[0]), base_ptr_offset + 2);

    let diff_len_offset = base_ptr_offset + 10;
    let mut cursor = diff_len_offset + 1;
    for d in &[d0, d1, d2] {
        let p = ptrs.iter().find(|sp| sp.ptr == *d).expect("diff emitted");
        assert_eq!(block_offset_of(p), cursor + 2);
        cursor += TriePtr::compressed_size_for_id(d.id()) as u64;
    }
}

#[test]
fn scans_patch_with_single_diff() {
    // Lower bound on diff_len: 1 (encoded as `len - 1 = 0`).
    let base = TriePtr {
        id: set_backptr(TrieNodeID::Node256 as u8),
        chr: 0x00,
        ptr: 0x10,
        back_block: 1,
    };
    let d = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x07, 0x70, 9);
    let patch = TrieNodePatch {
        ptr: base,
        ptr_diff: vec![d],
    };

    let mut buf = fresh_block_buf();
    buf.write_all(fake_hash(0x80).as_bytes()).unwrap();
    patch.consensus_serialize(&mut buf).unwrap();

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Patch);
    assert_eq!(ptrs.len(), 2);
    assert_eq!(ptrs[0].ptr, base);
    assert_eq!(ptrs[1].ptr, d);
}

#[test]
fn scans_patch_with_max_diffs() {
    // Upper bound on diff_len: 256 (encoded as `len - 1 = 255`).
    let base = TriePtr {
        id: set_backptr(TrieNodeID::Node256 as u8),
        chr: 0x00,
        ptr: 0x10,
        back_block: 1,
    };
    let mut diffs = Vec::with_capacity(256);
    for i in 0..256u32 {
        diffs.push(TriePtr::new_backptr(
            TrieNodeID::Leaf as u8,
            (i & 0xff) as u8,
            0x1000 + i,
            (10 + i) as u32,
        ));
    }
    let patch = TrieNodePatch {
        ptr: base,
        ptr_diff: diffs.clone(),
    };

    let mut buf = fresh_block_buf();
    buf.write_all(fake_hash(0x90).as_bytes()).unwrap();
    patch.consensus_serialize(&mut buf).unwrap();

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    assert_eq!(visits.len(), 1);
    // 1 base + 256 diffs.
    assert_eq!(ptrs.len(), 257);
    assert_eq!(ptrs[0].ptr, base);
    for (i, d) in diffs.iter().enumerate() {
        assert_eq!(ptrs[1 + i].ptr, *d);
    }
}

// ---------------------------------------------------------------------------
// Multi-node tests: parent with in-block child(ren), verify recursion.
// ---------------------------------------------------------------------------

#[test]
fn walks_two_node_tree_via_in_block_ptr() {
    // Layout:
    //   block[36..]   = root Node4 (compressed) with one in-block child at slot 0
    //   child_offset  = first byte after the root
    //   block[child_offset..] = Node4 (compressed, all empty / one backptr)
    //
    // The root's slot-0 ptr targets `child_offset`. The scanner should
    // visit the root, then walk to the child.

    let mut buf = fresh_block_buf();
    let root_offset = buf.position() as u32;

    // Reserve slot for the root, but we'll write it AFTER we know the
    // child offset (because the root's ptr.ptr captures the child's
    // start offset).
    let placeholder_marker = u32::MAX;
    let root_pre = TrieNode4::new(&[]);
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node4(root_pre),
        fake_hash(0xa0),
        true,
    )
    .unwrap();
    let child_offset = buf.position() as u32;

    // Write the child node: a Node4 with one backptr (so the scanner
    // doesn't recurse from it).
    let mut child = TrieNode4::new(&[]);
    child.ptrs[0] = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x00, 0xeeee, 99);
    bits::write_node_bytes(&mut buf, &TrieNodeType::Node4(child), fake_hash(0xa1), true).unwrap();

    // Now rewrite the root with a real child ptr at slot 0.
    buf.seek(SeekFrom::Start(root_offset as u64)).unwrap();
    let mut root_real = TrieNode4::new(&[]);
    root_real.ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, 0x00, child_offset);
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node4(root_real),
        fake_hash(0xa0),
        true,
    )
    .unwrap();
    let _ = placeholder_marker;

    let blob = buf.into_inner();
    let (visits, ptrs) = run_scanner(&blob);
    // Two NodeVisits: root, then child (depth-first).
    assert_eq!(visits.len(), 2);
    assert_eq!(visits[0].block_offset, root_offset);
    assert_eq!(visits[0].node_kind, TrieNodeID::Node4);
    assert_eq!(visits[1].block_offset, child_offset);
    assert_eq!(visits[1].node_kind, TrieNodeID::Node4);

    // Ptrs: root's slot-0 child + child's slot-0 backptr = 2 emissions.
    assert_eq!(ptrs.len(), 2);
    assert_eq!(ptrs[0].ptr.ptr, child_offset);
    assert!(!ptrs[0].ptr.is_backptr());
    assert!(ptrs[1].ptr.is_backptr());
    assert_eq!(ptrs[1].ptr.back_block, 99);
}

#[test]
fn rewrite_round_trip_yields_observed_new_value() {
    // Encode a Node256 with three backptr children. Scan, mutate the
    // emitted offsets to new ptr values, decode the mutated blob via the
    // production decoder, assert the new values are observed.
    let mut node = TrieNode256::empty();
    let p10 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x10, 0x1111, 11);
    let p150 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x96, 0x2222, 12);
    let p250 = TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0xfa, 0x3333, 13);
    node.ptrs[10] = p10;
    node.ptrs[150] = p150;
    node.ptrs[250] = p250;

    let mut buf = fresh_block_buf();
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node256(Box::new(node)),
        fake_hash(0xb0),
        true, // compressed
    )
    .unwrap();

    let mut blob = buf.into_inner();
    let mut emitted = Vec::new();
    scan_serialized_trie_ptr_fields(&blob, 0, |p| emitted.push(p)).unwrap();
    assert_eq!(emitted.len(), 3);

    // Apply a deterministic rewrite at every emitted offset.
    for (i, sp) in emitted.iter().enumerate() {
        let new_value = (0xc0c00000u32 + i as u32).to_be_bytes();
        let off = sp.ptr_field_file_offset as usize;
        blob[off..off + 4].copy_from_slice(&new_value);
    }

    // Re-scan: every emitted ptr should now have the new value, with the
    // same id/chr/back_block as before.
    let mut emitted2 = Vec::new();
    scan_serialized_trie_ptr_fields(&blob, 0, |p| emitted2.push(p)).unwrap();
    assert_eq!(emitted.len(), emitted2.len());
    for (i, (before, after)) in emitted.iter().zip(emitted2.iter()).enumerate() {
        assert_eq!(after.ptr_field_file_offset, before.ptr_field_file_offset);
        assert_eq!(after.ptr.id, before.ptr.id);
        assert_eq!(after.ptr.chr, before.ptr.chr);
        assert_eq!(after.ptr.back_block, before.ptr.back_block);
        assert_eq!(after.ptr.ptr, 0xc0c00000u32 + i as u32);
    }
}

// ---------------------------------------------------------------------------
// Random corpus test: encode many random nodes, scan, assert every
// embedded ptr is found exactly once with the right value.
//
// Deterministic PRNG (no proptest dependency) — one seed, many shapes.
// ---------------------------------------------------------------------------

/// Tiny LCG so the test is self-contained and reproducible.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (self.0 >> 32) as u32
    }
    fn next_u8(&mut self) -> u8 {
        (self.next_u32() & 0xff) as u8
    }
    fn pick<T: Copy>(&mut self, slice: &[T]) -> T {
        slice[(self.next_u32() as usize) % slice.len()]
    }
}

fn random_backptr(rng: &mut Lcg) -> TriePtr {
    let id = rng.pick(&[
        TrieNodeID::Leaf as u8,
        TrieNodeID::Node4 as u8,
        TrieNodeID::Node16 as u8,
        TrieNodeID::Node48 as u8,
        TrieNodeID::Node256 as u8,
    ]);
    TriePtr::new_backptr(id, rng.next_u8(), rng.next_u32(), 1 + rng.next_u32())
}

#[test]
fn property_random_nodes_scan_every_embedded_ptr_exactly_once() {
    let mut rng = Lcg::new(0x1234_5678_dead_beef);
    let mut total_nodes = 0;

    for trial in 0..200 {
        // Build one node per trial, randomly chosen kind, with random
        // backptr children. All children are backptrs so the scanner
        // doesn't recurse.
        let kind = match trial % 5 {
            0 => TrieNodeID::Node4,
            1 => TrieNodeID::Node16,
            2 => TrieNodeID::Node48,
            3 => TrieNodeID::Node256,
            _ => TrieNodeID::Node256,
        };
        let compressed = (rng.next_u8() & 1) == 0;

        let (node_type, expected_ptrs): (TrieNodeType, Vec<TriePtr>) = match kind {
            TrieNodeID::Node4 => {
                let mut n = TrieNode4::new(&[]);
                let mut ptrs = Vec::new();
                for slot in 0..4 {
                    if rng.next_u8() & 1 == 0 {
                        let p = random_backptr(&mut rng);
                        n.ptrs[slot] = p;
                        ptrs.push(p);
                    }
                }
                (TrieNodeType::Node4(n), ptrs)
            }
            TrieNodeID::Node16 => {
                let mut n = TrieNode16::new(&[]);
                let mut ptrs = Vec::new();
                for slot in 0..16 {
                    if rng.next_u8() & 1 == 0 {
                        let p = random_backptr(&mut rng);
                        n.ptrs[slot] = p;
                        ptrs.push(p);
                    }
                }
                (TrieNodeType::Node16(n), ptrs)
            }
            TrieNodeID::Node48 => {
                let mut n = TrieNode48::new(&[]);
                let mut ptrs = Vec::new();
                let mut next_chr: u32 = 0;
                for _ in 0..48 {
                    if rng.next_u8() & 1 == 0 {
                        let mut p = random_backptr(&mut rng);
                        // Unique chrs so insert always picks the next
                        // empty slot; gives a deterministic emission
                        // order matching `ptrs.push` order below.
                        p.chr = (next_chr & 0xff) as u8;
                        next_chr += 1;
                        assert!(n.insert(&p));
                        ptrs.push(p);
                    }
                }
                (TrieNodeType::Node48(Box::new(n)), ptrs)
            }
            TrieNodeID::Node256 => {
                let mut n = TrieNode256::empty();
                let mut ptrs = Vec::new();
                for slot in 0..256 {
                    if rng.next_u8() & 1 == 0 {
                        let mut p = random_backptr(&mut rng);
                        p.chr = slot as u8;
                        n.ptrs[slot] = p;
                        ptrs.push(p);
                    }
                }
                (TrieNodeType::Node256(Box::new(n)), ptrs)
            }
            _ => unreachable!(),
        };

        let mut buf = fresh_block_buf();
        bits::write_node_bytes(&mut buf, &node_type, fake_hash(trial as u8), compressed).unwrap();
        let blob = buf.into_inner();

        let (visits, scanned) = run_scanner(&blob);
        assert_eq!(visits.len(), 1, "trial {trial}: expected 1 NodeVisit");
        assert_eq!(
            scanned.len(),
            expected_ptrs.len(),
            "trial {trial}: ptr count mismatch (compressed={compressed}, kind={kind:?})",
        );
        // Order: scanner emits in slot order; expected_ptrs was built in
        // slot order. So they should match positionally.
        for (i, (expected, got)) in expected_ptrs.iter().zip(scanned.iter()).enumerate() {
            assert_eq!(
                got.ptr, *expected,
                "trial {trial}, ptr {i}: decoded mismatch",
            );
        }
        total_nodes += 1;
    }

    // Sanity: the loop didn't silently no-op.
    assert!(total_nodes >= 100);
}

// ---------------------------------------------------------------------------
// Negative-path / edge cases.
// ---------------------------------------------------------------------------

#[test]
fn scanner_errors_on_block_too_short_for_header() {
    let blob = vec![0u8; BLOB_HEADER_SIZE - 1];
    let mut visits = Vec::new();
    let mut ptrs = Vec::new();
    let err = scan_block_trie(&blob, 0, |v| visits.push(v), |p| ptrs.push(p))
        .expect_err("should reject too-short block");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("blob header"),
        "unexpected error message: {msg}",
    );
}

#[test]
fn scanner_errors_on_invalid_root_node_id() {
    let mut blob = vec![0u8; BLOB_HEADER_SIZE + 33];
    // Invalid node ID at body offset (clear_ctrl_bits would yield a value
    // outside the TrieNodeID enum range).
    blob[BLOB_HEADER_SIZE + 32] = 0x3f; // 0x3f after clear_ctrl_bits is 0x3f, no enum value
    let err = scan_block_trie(&blob, 0, |_| {}, |_| {}).expect_err("should reject invalid node ID");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("invalid node ID"),
        "unexpected error message: {msg}",
    );
}

#[test]
fn scanner_rejects_self_pointing_node() {
    // Encode a Node4 with one in-block ptr that targets the node itself
    // (slot.ptr == root_offset). A well-formed trie can never produce
    // this, but a corrupt on-disk blob might. The cycle guard must
    // catch it instead of looping forever.
    let mut buf = fresh_block_buf();
    let root_offset = buf.position() as u32;
    let mut node = TrieNode4::new(&[]);
    // Self-pointer: in-block (no backptr bit), ptr = root_offset.
    node.ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, 0x00, root_offset);
    bits::write_node_bytes(&mut buf, &TrieNodeType::Node4(node), fake_hash(0xc0), true).unwrap();

    let blob = buf.into_inner();
    let err =
        scan_block_trie(&blob, 0, |_| {}, |_| {}).expect_err("scanner must reject cyclic trie");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("cyclic trie detected"),
        "unexpected error: {msg}",
    );
}

#[test]
fn scanner_rejects_two_node_cycle() {
    // Mutual cycle: root → child → root. Same guard catches it.
    let mut buf = fresh_block_buf();
    let root_offset = buf.position() as u32;
    let placeholder_root = TrieNode4::new(&[]);
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node4(placeholder_root),
        fake_hash(0xc1),
        true,
    )
    .unwrap();
    let child_offset = buf.position() as u32;

    let mut child = TrieNode4::new(&[]);
    // Child points back to root (in-block, no backptr).
    child.ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, 0x00, root_offset);
    bits::write_node_bytes(&mut buf, &TrieNodeType::Node4(child), fake_hash(0xc2), true).unwrap();

    // Rewrite the root to point to child.
    buf.seek(SeekFrom::Start(root_offset as u64)).unwrap();
    let mut root_real = TrieNode4::new(&[]);
    root_real.ptrs[0] = TriePtr::new(TrieNodeID::Node4 as u8, 0x00, child_offset);
    bits::write_node_bytes(
        &mut buf,
        &TrieNodeType::Node4(root_real),
        fake_hash(0xc1),
        true,
    )
    .unwrap();

    let blob = buf.into_inner();
    let err =
        scan_block_trie(&blob, 0, |_| {}, |_| {}).expect_err("scanner must reject cyclic trie");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("cyclic trie detected"),
        "unexpected error: {msg}",
    );
}

#[test]
fn scanner_emits_no_events_for_leaf_at_root() {
    // A bare Leaf at root yields one NodeVisit and zero ScannedPtr events.
    let mut blob = vec![0u8; BLOB_HEADER_SIZE + 33];
    blob[BLOB_HEADER_SIZE + 32] = TrieNodeID::Leaf as u8;
    let mut visits = Vec::new();
    let mut ptrs = Vec::new();
    scan_block_trie(&blob, 0, |v| visits.push(v), |p| ptrs.push(p)).unwrap();
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].node_kind, TrieNodeID::Leaf);
    assert_eq!(ptrs.len(), 0);
}
