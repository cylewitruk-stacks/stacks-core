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

/// This file contains low-level methods for reading and manipulating Trie node data.
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha512_256 as TrieHasher};

use crate::chainstate::stacks::index::node::{
    self, clear_compressed, clear_ctrl_bits, is_compressed, ptrs_fmt, set_backptr,
    ConsensusSerializable, TrieLeafSquashed, TrieNode, TrieNode16, TrieNode256, TrieNode4,
    TrieNode48, TrieNodeID, TrieNodePatch, TrieNodeType, TriePtr, TRIEPTR_SIZE,
};
use crate::chainstate::stacks::index::{
    BlockMap, Error, MarfTrieId, NodeDecodeScratch, NodePath, ReadTrieItem, ReadTrieNode, TrieLeaf,
    TrieReadStorage,
};
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use crate::util::hash::to_hex;

/// Magic byte value indicating a sparse compressed pointer list.
/// This value cannot be a valid [`TrieNodeID`], making it safe to use as a marker.
pub const SPARSE_PTR_BITMAP_MARKER: u8 = 0xff;

/// Get the size of a Trie path (note that a Trie path is 32 bytes long, and can definitely _not_
/// be over 255 bytes).
pub fn get_path_byte_len(p: &[u8]) -> usize {
    assert!(p.len() < 255);
    let path_len_byte_len = 1;
    path_len_byte_len + p.len()
}

/// Decode a trie path from a Readable object.
/// This is up to 32 bytes, and must be prefixed by a 1-byte length.
///
/// Returns Ok(()) on success and writes the decoded path into `dst`
/// Returns Err(CorruptionError) if the path doesn't decode, or if the length prefix is invalid
/// Returns Err(IOError) on disk I/O failure
pub fn path_from_bytes_slice_into(bytes: &[u8], dst: &mut NodePath) -> Result<usize, Error> {
    let path_len = *bytes
        .first()
        .ok_or_else(|| Error::CorruptionError("Failed to read len buf".to_string()))?
        as usize;

    if path_len > TRIEHASH_ENCODED_SIZE {
        trace!(
            "Path length is {} (expected <= {})",
            path_len,
            TRIEHASH_ENCODED_SIZE
        );
        return Err(Error::CorruptionError(format!(
            "Node path is longer than {} bytes (got {})",
            TRIEHASH_ENCODED_SIZE, path_len
        )));
    }

    let path_bytes = bytes.get(1..1 + path_len).ok_or_else(|| {
        Error::CorruptionError(format!("Failed to read {} bytes of path", path_len))
    })?;

    dst.set_from_slice(path_bytes).ok_or_else(|| {
        Error::CorruptionError(format!("Node path length {} exceeds 32", path_len))
    })?;
    Ok(1 + path_len)
}

/// Helper to determine the maximum number of bytes a Trie node's child pointers will take to encode.
pub fn get_ptrs_byte_len(ptrs: &[TriePtr]) -> usize {
    let node_id_len = 1;
    node_id_len + TRIEPTR_SIZE * ptrs.len()
}

/// Helper to determine a sparse TriePtr list's bitmap size, given the node ID's numeric value.
///
/// Returns:
/// * `Some(size)` if the node identified node type has ptrs
/// * `None` if `id` is a `Leaf`, `Patch`, or `Empty` node, or is unrecognized.
pub fn get_sparse_ptrs_bitmap_size(id: u8) -> Option<usize> {
    match TrieNodeID::from_u8(clear_ctrl_bits(id))? {
        TrieNodeID::Leaf => None,
        TrieNodeID::Node4 => Some(1),
        TrieNodeID::Node16 => Some(2),
        TrieNodeID::Node48 => Some(6),
        TrieNodeID::Node256 => Some(32),
        TrieNodeID::Empty => None,
        TrieNodeID::Patch => None,
        TrieNodeID::LeafSquashed => None,
    }
}

/// Helper to determine what the compressed size of a ptrs list will be, depending on whether or
/// not it's sparse or dense.
///
/// Returns:
/// * `Some((size, is-sparse?))` on success
/// * `None` if the node doesn't have ptrs
pub fn get_compressed_ptrs_size(id: u8, ptrs: &[TriePtr]) -> Option<(usize, bool)> {
    let bitmap_size = get_sparse_ptrs_bitmap_size(id)?;

    // compute stored ptrs size
    let mut sparse_ptrs_size = 0;
    let mut ptrs_size = 0;
    for ptr in ptrs.iter() {
        if ptr.id() != TrieNodeID::Empty as u8 {
            sparse_ptrs_size += ptr.compressed_size();
        }
        ptrs_size += ptr.compressed_size();
    }

    // +1 is for the SPARSE_PTR_BITMAP_MARKER bitmap marker
    let sparse_size = usize::try_from(1 + bitmap_size + sparse_ptrs_size).expect("infallible");
    if sparse_size < ptrs_size {
        return Some((sparse_size, true));
    } else {
        return Some((ptrs_size, false));
    }
}

/// Helper to determine how many bytes a Trie node's child pointers will take to encode.
///
/// Size is `id` + `ptrs` encoded size.
pub fn get_ptrs_byte_len_compressed(id: u8, ptrs: &[TriePtr]) -> usize {
    1 + get_compressed_ptrs_size(id, ptrs)
        .map(|(sz, _)| sz)
        .unwrap_or(0)
}

pub fn get_node_body_max_byte_len(node_id: u8) -> Result<usize, Error> {
    let cleared_node_id = clear_ctrl_bits(node_id);
    let path_max_len = get_path_byte_len(&[0; TRIEHASH_ENCODED_SIZE]);
    let patch_ptr_max_len = TriePtr::compressed_size_for_id(set_backptr(TrieNodeID::Node256 as u8));

    let max_len = match TrieNodeID::from_u8(cleared_node_id)
        .ok_or_else(|| Error::CorruptionError(format!("Bad node ID: {:x}", node_id)))?
    {
        TrieNodeID::Leaf => 1 + path_max_len + 40,
        TrieNodeID::Node4 => get_ptrs_byte_len(&[TriePtr::default(); 4]) + path_max_len,
        TrieNodeID::Node16 => get_ptrs_byte_len(&[TriePtr::default(); 16]) + path_max_len,
        TrieNodeID::Node48 => get_ptrs_byte_len(&[TriePtr::default(); 48]) + 256 + path_max_len,
        TrieNodeID::Node256 => get_ptrs_byte_len(&[TriePtr::default(); 256]) + path_max_len,
        TrieNodeID::Patch => 1 + patch_ptr_max_len + 1 + 256 * patch_ptr_max_len,
        // LeafSquashed (multipurpose carrier per `.docs/full-history-history-blob-design.md` §5.1).
        // The new format has a fixed-bounded body — no inline transitions —
        // so the upper bound is tiny. v1 emits subtype 2 (INLINE_FIXED +
        // has_history); the only emit shape with the maximum-overhead header
        // is INLINE_FIXED + has_history + has_hash. Worst case:
        //   node-id(1) + type(1) + flags(1) + path_len(1)        = 4
        //   + hash(32)                                            = 36
        //   + history_offset(8) + byte_len(4) + entry_count(4)    = 52
        //   + path (bounded ≤ 32B per MARF nibble-pair)           = ≤84
        //   + tip_value (40B fixed for INLINE_FIXED)              = ≤124
        // The non-mmap slow-path read buffer was previously sized for the
        // legacy ~2.8 MB inline-history bound; the new format uses ≤124 B,
        // a ~22000× shrink in the slow-path buffer alloc.
        TrieNodeID::LeafSquashed => 4 + 32 + 16 + path_max_len + 40,
        TrieNodeID::Empty => {
            return Err(Error::CorruptionError(format!(
                "Unsupported node ID for node-body read: {:x}",
                node_id
            )))
        }
    };

    Ok(max_len)
}

pub fn get_node_max_byte_len(node_id: u8) -> Result<usize, Error> {
    TRIEHASH_ENCODED_SIZE
        .checked_add(get_node_body_max_byte_len(node_id)?)
        .ok_or(Error::OverflowError)
}

/// Decode a non-patch node from a byte slice into scratch storage.
///
/// Callers must ensure `ptr_id` is a valid, non-Patch node type and that `bytes` does not begin
/// with a Patch marker. both conditions are checked by callers before dispatch.
fn decode_nodetype_ref_from_slice_at_head(
    bytes: &[u8],
    ptr_id: u8,
    scratch: &mut impl NodeDecodeScratch,
) -> Result<usize, Error> {
    debug_assert_ne!(
        TrieNodeID::from_u8(clear_ctrl_bits(ptr_id)),
        Some(TrieNodeID::Patch),
        "callers must handle Patch before dispatch"
    );
    debug_assert_ne!(
        stored_node_id_from_bytes(bytes).ok(),
        Some(TrieNodeID::Patch),
        "callers must check stored node ID for Patch before dispatch"
    );

    let node_id = TrieNodeID::from_u8(ptr_id).ok_or_else(|| {
        Error::CorruptionError(format!(
            "inner_read_nodetype_at_head: Unknown trie node type {ptr_id}"
        ))
    })?;

    scratch.decode_node_from_slice(node_id, bytes)
}

pub fn stored_node_id_from_bytes(bytes: &[u8]) -> Result<TrieNodeID, Error> {
    let first_byte = *bytes.first().ok_or_else(|| {
        Error::CorruptionError("Failed to read 1st byte from bytes array".to_string())
    })?;
    TrieNodeID::from_u8(clear_ctrl_bits(first_byte)).ok_or_else(|| {
        // Log surrounding bytes for diagnosis — helps distinguish "reading
        // hash bytes as node body" from "wrong file offset entirely".
        let preview_len = bytes.len().min(40);
        let preview: Vec<String> = bytes
            .iter()
            .take(preview_len)
            .map(|b| format!("{b:02x}"))
            .collect();
        error!(
            "stored_node_id_from_bytes: invalid node ID byte=0x{:02x} cleared=0x{:02x}, \
             slice_len={}, first {} bytes=[{}]",
            first_byte,
            clear_ctrl_bits(first_byte),
            bytes.len(),
            preview_len,
            preview.join(" "),
        );
        Error::CorruptionError(format!(
            "Failed to read expected node ID -- not a valid ID (byte=0x{:02x}, cleared=0x{:02x})",
            first_byte,
            clear_ctrl_bits(first_byte)
        ))
    })
}

pub fn decode_nodetype_from_slice_at_head(
    bytes: &[u8],
    ptr_id: u8,
) -> Result<(TrieNodeType, usize), Error> {
    let node_id = TrieNodeID::from_u8(ptr_id).ok_or_else(|| {
        Error::CorruptionError(format!(
            "inner_read_nodetype_at_head: Unknown trie node type {}",
            ptr_id
        ))
    })?;

    let stored_node_id = TrieNodeID::from_u8(clear_ctrl_bits(*bytes.first().ok_or_else(|| {
        Error::CorruptionError("Failed to read 1st byte from bytes array".to_string())
    })?))
    .ok_or_else(|| {
        Error::CorruptionError("Failed to read expected node ID -- not a valid ID".to_string())
    })?;

    if stored_node_id == TrieNodeID::Patch {
        return Err(Error::Patch(None, TrieNodePatch::from_slice(bytes)?.0));
    }

    match node_id {
        TrieNodeID::Node4 => {
            let (node, consumed) = TrieNode4::from_bytes(bytes)?;
            Ok((TrieNodeType::Node4(node), consumed))
        }
        TrieNodeID::Node16 => {
            let (node, consumed) = TrieNode16::from_bytes(bytes)?;
            Ok((TrieNodeType::Node16(node), consumed))
        }
        TrieNodeID::Node48 => {
            let (node, consumed) = TrieNode48::from_bytes(bytes)?;
            Ok((TrieNodeType::Node48(Box::new(node)), consumed))
        }
        TrieNodeID::Node256 => {
            let (node, consumed) = TrieNode256::from_bytes(bytes)?;
            Ok((TrieNodeType::Node256(Box::new(node)), consumed))
        }
        TrieNodeID::Leaf => {
            let (node, consumed) = TrieLeaf::from_bytes(bytes)?;
            Ok((TrieNodeType::Leaf(node), consumed))
        }
        TrieNodeID::LeafSquashed => {
            let (node, consumed) = TrieLeafSquashed::from_bytes(bytes)?;
            Ok((TrieNodeType::LeafSquashed(node), consumed))
        }
        TrieNodeID::Empty => Err(Error::CorruptionError(
            "inner_read_nodetype_at_head: stored empty node type".to_string(),
        )),
        TrieNodeID::Patch => unreachable!("BUG: direct patch nodes are handled before dispatch"),
    }
}

fn read_node_bytes_into<R: Read + Seek>(
    r: &mut R,
    bytes: &mut Vec<u8>,
    node_id: u8,
) -> Result<u64, Error> {
    let max_len = get_node_max_byte_len(node_id)?;

    let start_disk_ptr = r
        .stream_position()
        .inspect_err(|e| error!("Failed to ftell the read handle: {e:?}"))?;

    bytes.clear();
    bytes.resize(max_len, 0);

    let mut offset = 0;
    loop {
        let nr = match r.read(
            bytes
                .get_mut(offset..)
                .ok_or_else(|| Error::OverflowError)?,
        ) {
            Ok(nr) => nr,
            Err(e) => match e.kind() {
                ErrorKind::UnexpectedEof => 0,
                ErrorKind::Interrupted => continue,
                _ => {
                    error!("Failed to read trie node: {e:?}");
                    return Err(Error::IOError(e));
                }
            },
        };
        if nr == 0 {
            break;
        }
        offset = offset.checked_add(nr).ok_or_else(|| Error::OverflowError)?;
        if offset >= max_len {
            break;
        }
    }

    bytes.truncate(offset);
    Ok(start_disk_ptr)
}

pub fn parse_hash_from_bytes(bytes: &[u8]) -> Result<(TrieHash, &[u8]), Error> {
    let hash_bytes = bytes.get(..TRIEHASH_ENCODED_SIZE).ok_or_else(|| {
        Error::CorruptionError("Failed to read hash in full from node bytes".to_string())
    })?;
    let hash_array: [u8; TRIEHASH_ENCODED_SIZE] = hash_bytes
        .try_into()
        .map_err(|_| Error::CorruptionError("Failed to decode node hash bytes".to_string()))?;
    let remaining = bytes.get(TRIEHASH_ENCODED_SIZE..).ok_or_else(|| {
        Error::CorruptionError("Failed to read remaining node bytes after hash".to_string())
    })?;
    Ok((TrieHash(hash_array), remaining))
}

fn parse_node_from_bytes<R, T, F>(
    r: &mut R,
    start_disk_ptr: u64,
    bytes: &[u8],
    parse: F,
) -> Result<T, Error>
where
    R: Seek,
    F: FnOnce(&[u8]) -> Result<(T, usize), Error>,
{
    let (result, consumed) = parse(bytes)?;
    r.seek(SeekFrom::Start(
        start_disk_ptr
            .checked_add(u64::try_from(consumed).expect("infallible"))
            .expect("FATAL: read far too many node bytes"),
    ))
    .inspect_err(|e| error!("Failed to seek to the end of the node bytes: {e:?}"))?;
    Ok(result)
}

fn read_expected_node_id_from_bytes(expected_node_id: u8, bytes: &[u8]) -> Result<u8, Error> {
    let nid = *bytes
        .first()
        .ok_or_else(|| Error::CorruptionError("Failed to read 1st byte from bytes array".into()))?;

    let cleared_nid = clear_ctrl_bits(nid);
    let cleared_expected = clear_ctrl_bits(expected_node_id);
    if cleared_nid == cleared_expected {
        return Ok(nid);
    }

    let Some(nid_node_id) = TrieNodeID::from_u8(cleared_nid) else {
        return Err(Error::CorruptionError(
            "Failed to read expected node ID -- not a valid ID".to_string(),
        ));
    };

    if nid_node_id == TrieNodeID::Patch {
        let patch = TrieNodePatch::from_slice(bytes).map(|(patch, _)| patch)?;
        return Err(Error::Patch(None, patch));
    }

    error!("Bad idbuf: {:x} != {:x}", nid, expected_node_id);
    Err(Error::CorruptionError(
        "Failed to read expected node ID".to_string(),
    ))
}

fn decode_uncompressed_ptrs_from_bytes(
    ptr_bytes: &[u8],
    ptrs_buf: &mut [TriePtr],
) -> Result<usize, Error> {
    let expected_len = TRIEPTR_SIZE
        .checked_mul(ptrs_buf.len())
        .ok_or_else(|| Error::OverflowError)?;
    if ptr_bytes.len() < expected_len {
        return Err(Error::CorruptionError(
            "Tried to read uncompressed ptrs but not enough bytes".to_string(),
        ));
    }

    let reading_ptrs = ptr_bytes
        .chunks_exact(TRIEPTR_SIZE)
        .zip(ptrs_buf.iter_mut());
    for (next_ptr_bytes, ptr_slot) in reading_ptrs {
        *ptr_slot = TriePtr::from_bytes(next_ptr_bytes);
    }
    Ok(expected_len)
}

fn decode_sparse_compressed_ptrs_from_bytes(
    cleared_nid: u8,
    ptr_bytes: &[u8],
    ptrs_buf: &mut [TriePtr],
) -> Result<usize, Error> {
    let bitmap_size = get_sparse_ptrs_bitmap_size(cleared_nid).ok_or_else(|| {
        Error::CorruptionError(format!(
            "Unable to determine bitmap size for node type {}",
            cleared_nid
        ))
    })?;

    if ptr_bytes.len() < bitmap_size {
        return Err(Error::CorruptionError(
            "Tried to read a bitmap but not enough bytes".to_string(),
        ));
    }
    let bitmap_slice = ptr_bytes
        .get(..bitmap_size)
        .ok_or_else(|| Error::CorruptionError("bitmap not long enough".into()))?;

    trace!(
        "Node {} has sparse compressed ptrs bitmap {}",
        cleared_nid,
        to_hex(bitmap_slice)
    );

    let ptr_bytes = ptr_bytes.get(bitmap_size..).ok_or_else(|| {
        Error::CorruptionError("Failed to read bitmap_size bytes from bytes array".into())
    })?;

    for ptr in ptrs_buf.iter_mut() {
        *ptr = TriePtr::default();
    }

    let mut cursor = 0;
    for (byte_index, bitmap_byte) in bitmap_slice.iter().copied().enumerate() {
        let mut set_bits = bitmap_byte;
        while set_bits != 0 {
            let bit_index = usize::try_from(set_bits.trailing_zeros()).expect("infallible");
            let index = byte_index
                .checked_mul(8)
                .and_then(|base| base.checked_add(bit_index))
                .ok_or_else(|| Error::OverflowError)?;
            set_bits &= set_bits - 1;

            let Some(ptr_slot) = ptrs_buf.get_mut(index) else {
                continue;
            };
            let ptr_slice = ptr_bytes
                .get(cursor..)
                .ok_or_else(|| Error::CorruptionError("ptr_bytes runs short".into()))?;
            let (ptr, ptr_len) = TriePtr::from_slice_compressed(ptr_slice)?;
            *ptr_slot = ptr;
            cursor = cursor
                .checked_add(ptr_len)
                .ok_or_else(|| Error::OverflowError)?;
        }
    }

    trace!(
        "Node {} sparse compressed ptrs ({} bytes): {}",
        cleared_nid,
        cursor,
        &ptrs_fmt(ptrs_buf)
    );

    Ok(cursor)
}

fn decode_dense_compressed_ptrs_from_bytes(
    ptr_bytes: &[u8],
    ptrs_buf: &mut [TriePtr],
) -> Result<usize, Error> {
    let mut cursor = 0;
    for ptr_slot in ptrs_buf.iter_mut() {
        let ptr_slice = ptr_bytes
            .get(cursor..)
            .ok_or_else(|| Error::CorruptionError("ptr_bytes runs short".into()))?;
        let (ptr, ptr_len) = TriePtr::from_slice_compressed(ptr_slice)?;
        *ptr_slot = ptr;
        cursor = cursor
            .checked_add(ptr_len)
            .ok_or_else(|| Error::OverflowError)?;
    }

    Ok(cursor)
}

/// Read a trie node's children pointers from a byte slice, and write them to the given `ptrs_buf`
/// slice. The `node_id` will indicate whether or not the pointers list is compressed (via its
/// compressed bit).
///
/// An uncompressed list of `TriePtr`s is simply a sequence of uncompressed `TriePtr`s.  They are
/// read verbatim into the `ptrs_buf` slice.
///
/// A compressed list of `TriePtr`s has either a sparse form or a dense form, and is comprised of
/// compressed `TriePtr`s (which have variable length).  In the sparse form, the byte encoding is
/// as follows:
///
/// ```text
/// 0   1         1+B                                     1+B+N
/// |---|-----------|---------------------------------------|
///  0xff   bitmap    list of compressed `TriePtr`s
/// ```
///
/// Where
/// * 0xff ([`SPARSE_PTR_BITMAP_MARKER`]) is a marker bit that cannot be the first byte of a
///   `TriePtr`, and indicates that a bitmap follows
/// * `bitmap` is a bit field in which the ith bit is set if the ith `TriePtr` is not empty.  All
///   other `TriePtr`s in `ptrs_buf` will be considered empty, and initialized as such.
///
/// The remaining bytes 1+B through 1+B+N contain the list of compressed `TriePtr`s -- one for each
/// set bit in `bitmap`.
///
/// If the dense form is used, then the byte encoding is as follows:
///
/// ```text
/// 0                                     N
/// |-------------------------------------|
///   list of compressed `TriePtr`s
/// ```
///
/// The dense form includes empty `TriePtr`s.  The dense form is used if the size of using the
/// sparse form (with the bitmap) exceeds the size of using the dense form.  The dense form is used
/// for tries that are full or nearly full.
///
/// Returns Ok((node-id, bytes-consumed)) on success, where the compressed bit in `node-id` is NOT
/// set.  However, the backptr bit MAY be set (it is preserved).
///
/// Returns Err(CorruptionError(..)) if the node ID is invalid, the read node ID is missing, the
/// read node ID does not match the given node ID, or the byte encoding is invalid given the
/// expected pointers encoding.
pub fn ptrs_from_slice_into(
    node_id: u8,
    bytes: &[u8],
    ptrs_buf: &mut [TriePtr],
) -> Result<(u8, usize), Error> {
    let cleared_node_id = clear_ctrl_bits(node_id);
    if TrieNodeID::from_u8(cleared_node_id).is_none() {
        error!("Bad node ID {node_id:x}");
        return Err(Error::CorruptionError(format!("Bad node ID: {node_id:x}",)));
    };

    let nid = read_expected_node_id_from_bytes(node_id, bytes)?;
    if is_compressed(nid) {
        trace!("Node {cleared_node_id} has compressed ptrs");

        let ptr_bytes = bytes.get(1..).ok_or_else(|| {
            Error::CorruptionError("Failed to read >1 bytes from bytes array".into())
        })?;

        let sparse_flag = ptr_bytes.get(0).ok_or_else(|| {
            Error::CorruptionError("Failed to read 2nd byte from bytes array".into())
        })?;

        if *sparse_flag == SPARSE_PTR_BITMAP_MARKER {
            trace!("Node {cleared_node_id} has sparse compressed ptrs");
            let ptr_bytes = ptr_bytes.get(1..).ok_or_else(|| {
                Error::CorruptionError("Failed to read >2 bytes from bytes array".into())
            })?;
            let bitmap_size = get_sparse_ptrs_bitmap_size(cleared_node_id).expect("infallible");
            let consumed =
                decode_sparse_compressed_ptrs_from_bytes(cleared_node_id, ptr_bytes, ptrs_buf)?;
            return Ok((clear_compressed(nid), 2 + bitmap_size + consumed));
        }

        trace!("Node {cleared_node_id} has dense compressed ptrs");
        let consumed = decode_dense_compressed_ptrs_from_bytes(ptr_bytes, ptrs_buf)?;
        trace!(
            "Node {cleared_node_id} dense compressed ptrs: {}",
            &ptrs_fmt(ptrs_buf)
        );
        return Ok((clear_compressed(nid), 1 + consumed));
    }

    trace!("Node {cleared_node_id} has uncompressed ptrs");
    let ptr_bytes = bytes
        .get(1..)
        .ok_or_else(|| Error::CorruptionError("Failed to read >1 bytes from bytes array".into()))?;
    let consumed = decode_uncompressed_ptrs_from_bytes(ptr_bytes, ptrs_buf)?;
    Ok((clear_compressed(nid), 1 + consumed))
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
/// Returns the TrieHash
pub fn get_node_hash<M: ?Sized, T: ConsensusSerializable<M> + std::fmt::Debug>(
    node: &T,
    child_hashes: &[TrieHash],
    map: &mut M,
) -> TrieHash {
    let mut hasher = TrieHasher::new();

    node.write_consensus_bytes(map, &mut hasher)
        .expect("IO Failure pushing to hasher.");

    for child_hash in child_hashes {
        hasher.update(child_hash.as_ref());
    }

    let res = hasher.finalize().into();
    let ret = TrieHash(res);

    trace!(
        "get_node_hash: hash {:?} = {:?} + {:?}",
        &ret,
        node,
        child_hashes
    );
    ret
}

/// Calculate the hash of a TrieLeaf
/// Returns the TrieHash
pub fn get_leaf_hash(node: &TrieLeaf) -> TrieHash {
    let mut hasher = TrieHasher::new();
    node.write_bytes(&mut hasher)
        .expect("IO Failure pushing to hasher.");

    let res = hasher.finalize().into();
    let ret = TrieHash(res);

    trace!("get_leaf_hash: hash {:?} = {:?} + []", &ret, node);
    ret
}

/// Given a `TrieNodeType`, a slice of `TrieHash`, and a `BlockMap` for converting back-block
/// pointers to block hashes, compute the hash of the node.
pub fn get_nodetype_hash_bytes<T: MarfTrieId, M: BlockMap>(
    node: &TrieNodeType,
    child_hash_bytes: &[TrieHash],
    map: &mut M,
) -> Result<TrieHash, Error> {
    Ok(match node {
        TrieNodeType::Node4(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node16(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node48(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Node256(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Leaf(ref data) => get_node_hash(data, child_hash_bytes, map),
        // LeafSquashed hashes as a plain Leaf using the tip value
        TrieNodeType::LeafSquashed(ref data) => {
            let leaf = TrieLeaf {
                path: data.path,
                data: data.tip_value()?.clone(),
            };
            get_node_hash(&leaf, child_hash_bytes, map)
        }
    })
}

/// Low-level method for reading a TrieHash into a byte buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_hash_bytes<F: Read>(f: &mut F) -> Result<[u8; TRIEHASH_ENCODED_SIZE], Error> {
    let mut hashbytes = [0u8; TRIEHASH_ENCODED_SIZE];
    f.read_exact(&mut hashbytes).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!(
                "Failed to read hash in full from {}",
                to_hex(&hashbytes)
            ))
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(hashbytes)
}

/// Low-level method for reading a node's hash bytes into a buffer from a Read-able and Seek-able struct.
/// This function is only concerned with getting the bytes, not casting it to a TrieHash.
///
/// Returns Ok(32-byte hash) on success.
/// Returns Err(IOError(..)) on seek error or disk I/O error
pub fn read_node_hash_bytes<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<[u8; TRIEHASH_ENCODED_SIZE], Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    read_hash_bytes(f)
}

/// Read the root hash from a TrieFileStorage instance.
/// This is always at the same location (s.root_trieptr())
/// Returns Ok(root hash) on success
/// Returns Err(NotFoundError) if, for some reason, the storage medium doesn't have the root node
/// (should never happen)
/// Returns Err(IOError(..)) on storage I/O failure
pub fn read_root_hash<T: MarfTrieId, R: TrieReadStorage<T> + ?Sized>(
    s: &mut R,
) -> Result<TrieHash, Error> {
    let ptr = s.root_trieptr();
    Ok(s.read_node_hash(&ptr)?)
}

/// Decode the node body from `remaining` into `scratch`, dispatching to patch or node decode.
/// Returns `(stored_node_id, bytes_consumed)`.
fn decode_trie_item_into_scratch(
    remaining: &[u8],
    _ptr_id: u8,
    scratch: &mut impl NodeDecodeScratch,
) -> Result<(TrieNodeID, usize), Error> {
    let stored_node_id = stored_node_id_from_bytes(remaining)?;
    let consumed = if stored_node_id == TrieNodeID::Patch {
        scratch.decode_patch_from_slice(remaining)?
    } else {
        // Use the stored node ID from the actual bytes, not the TriePtr hint.
        // The TriePtr may carry a stale type (e.g. Leaf when the on-disk node
        // is actually LeafSquashed in a FullHistory squash blob).
        decode_nodetype_ref_from_slice_at_head(remaining, stored_node_id as u8, scratch)?
    };
    Ok((stored_node_id, consumed))
}

/// Build a [`ReadTrieItem`] from scratch state that was populated by [`decode_trie_item_into_scratch`].
fn build_read_trie_item<'a>(
    stored_node_id: TrieNodeID,
    hash: TrieHash,
    scratch: &'a impl NodeDecodeScratch,
) -> ReadTrieItem<'a> {
    if stored_node_id == TrieNodeID::Patch {
        ReadTrieItem::from_patch(scratch.patch(), Some(hash))
    } else {
        ReadTrieItem::from_node(ReadTrieNode::from_state_borrowed(
            scratch.get_ref(),
            Some(hash),
        ))
    }
}

/// Read a trie item from a byte slice (no Read+Seek needed).
/// Used by the mmap path where bytes are already in memory.
pub fn read_trie_item_from_slice<'a>(
    bytes: &[u8],
    ptr_id: u8,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieItem<'a>, Error> {
    let (hash, remaining) = parse_hash_from_bytes(bytes)?;
    let (stored_node_id, _) = decode_trie_item_into_scratch(remaining, ptr_id, scratch)?;
    Ok(build_read_trie_item(stored_node_id, hash, scratch))
}

/// Like [`read_trie_item_from_slice`] but for squash blobs where leaf nodes
/// are stored without a 32-byte hash prefix. `ptr_id` is the node type hint
/// from the parent pointer. When the ptr hints a leaf type, the bytes are
/// decoded directly as a node body (hash = None).
pub fn read_trie_item_from_slice_leaf_hash_free<'a>(
    bytes: &[u8],
    ptr_id: u8,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieItem<'a>, Error> {
    if node::is_leaf_type(ptr_id) {
        // Leaf: body starts at byte 0, no hash prefix.
        let (_stored_node_id, _) = decode_trie_item_into_scratch(bytes, ptr_id, scratch)?;
        Ok(ReadTrieItem::from_node(ReadTrieNode::from_state_borrowed(
            scratch.get_ref(),
            None,
        )))
    } else {
        // Non-leaf: standard [hash(32)][body] layout.
        read_trie_item_from_slice(bytes, ptr_id, scratch)
    }
}

/// Read a stored node type and hash from a byte slice (no Read+Seek needed).
pub fn read_stored_node_type_from_slice(bytes: &[u8]) -> Result<(TrieNodeID, TrieHash), Error> {
    let (hash, remaining) = parse_hash_from_bytes(bytes)?;
    let stored_id = stored_node_id_from_bytes(remaining)?;
    Ok((stored_id, hash))
}

/// Like [`read_stored_node_type_from_slice`] but for squash blobs where leaf
/// nodes lack a hash prefix. `ptr_id` is the type hint from the parent pointer.
pub fn read_stored_node_type_from_slice_leaf_hash_free(
    bytes: &[u8],
    ptr_id: u8,
) -> Result<(TrieNodeID, Option<TrieHash>), Error> {
    if node::is_leaf_type(ptr_id) {
        let stored_id = stored_node_id_from_bytes(bytes)?;
        Ok((stored_id, None))
    } else {
        let (hash, remaining) = parse_hash_from_bytes(bytes)?;
        let stored_id = stored_node_id_from_bytes(remaining)?;
        Ok((stored_id, Some(hash)))
    }
}

/// Read a trie item and its hash into scratch.
pub fn read_trie_item<'a, F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieItem<'a>, Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    trace!("read_nodetype at {:?}", ptr);
    read_trie_item_at_head_ref(f, ptr.id(), scratch)
}

pub fn read_stored_node_type_at_head<F: Read + Seek>(
    f: &mut F,
) -> Result<(TrieNodeID, TrieHash), Error> {
    let hash = TrieHash(read_hash_bytes(f)?);
    let mut id_bytes = [0u8; 1];
    f.read_exact(&mut id_bytes).map_err(Error::IOError)?;
    let stored_id = stored_node_id_from_bytes(&id_bytes)?;
    Ok((stored_id, hash))
}

pub fn decode_stable_node_bytes(
    bytes: &[u8],
    node_type: TrieNodeID,
) -> Result<TrieNodeType, Error> {
    let (node, consumed) = decode_nodetype_from_slice_at_head(bytes, node_type as u8)?;
    if consumed != bytes.len() {
        return Err(Error::CorruptionError(format!(
            "Stable node bytes length mismatch for {node_type:?}: decoded {consumed} bytes from {}",
            bytes.len()
        )));
    }
    Ok(node)
}

/// Deserialize a TrieNodeType and optionally its hash from the given Read+Seek object.
/// The given `ptr_id` identifies the expected node type.
///
/// Node wire format for non-patch ("normal") nodes:
///
/// 0               32 33               33+X         33+X+Y
/// |---------------|--|------------------|-----------|
///   node hash      id  ptrs & ptr data      path
///
/// Node wire format for patch nodes:
///
/// 0               32 33               33+X
/// |---------------|--|------------------|
///   base node hash id  compressed ptrs
pub fn read_trie_item_at_head_ref<'a, F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieItem<'a>, Error> {
    let mut node_bytes = scratch.take_node_bytes();
    let start_disk_ptr = read_node_bytes_into(f, &mut node_bytes, ptr_id)?;

    let result = parse_node_from_bytes(f, start_disk_ptr, node_bytes.as_slice(), |bytes| {
        let (hash, remaining) = parse_hash_from_bytes(bytes)?;
        let (stored_node_id, consumed) = decode_trie_item_into_scratch(remaining, ptr_id, scratch)?;
        let total_consumed = TRIEHASH_ENCODED_SIZE
            .checked_add(consumed)
            .ok_or(Error::OverflowError)?;
        Ok(((hash, stored_node_id), total_consumed))
    });

    scratch.restore_node_bytes(node_bytes);

    let (hash, stored_node_id) = result?;
    Ok(build_read_trie_item(stored_node_id, hash, scratch))
}

/// Calculate how many bytes a node will be when serialized, including its hash.
/// This assumes that none of the trie nodes will be compressed
pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len();
    hash_len + node_byte_len
}

/// calculate how many bytes a node will be when serialized, including its hash, using a compressed
/// representation.  This includes considering whether or not the compressed representation will be
/// dense or sparse.
pub fn get_node_byte_len_compressed(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len_compressed();
    hash_len + node_byte_len
}

/// Write all the bytes for a node, including its hash, to the given Writeable object.
///
/// If `compressed` is true, child pointers will be compressed as best as possible.
///
/// ## Returns
/// * `Ok(nw)` on success, where `nw` is the number of bytes written.
/// * `Err(IOError(..))` on disk I/O error
pub fn write_node_bytes<F: Write + Seek>(
    f: &mut F,
    node: &TrieNodeType,
    hash: TrieHash,
    compressed: bool,
) -> Result<u64, Error> {
    let start = f.stream_position().map_err(Error::IOError)?;
    f.write_all(hash.as_bytes())?;
    if compressed {
        node.write_bytes_compressed(f)?;
    } else {
        node.write_bytes(f)?;
    }
    let end = f.stream_position().map_err(Error::IOError)?;
    trace!("write_nodetype_bytes: {node:?} {hash:?} at {start}-{end}");
    Ok(end - start)
}

/// Write out the path to the given writable object.
/// This includes the length prefix and path bytes
///
/// ## Returns
/// * `Ok(())` on success
/// * `Err(CorruptionError(..))` if `path.len()` is greater than 32.
/// * `Err(IOError(..))` on disk I/O error
pub fn write_path_to_bytes<W: Write>(path: &[u8], w: &mut W) -> Result<(), Error> {
    if path.len() > 32 {
        return Err(Error::CorruptionError(
            "Invali path -- greater than 32 bytes".into(),
        ));
    }
    w.write_all(&[path.len() as u8])?;
    w.write_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::chainstate::stacks::index::node::{
        set_compressed, TrieLeafRef, TrieNode, TrieNode4, TrieNodeRef,
    };
    use crate::chainstate::stacks::index::scratch::MarfReadState;
    use crate::chainstate::stacks::index::ReadTrieItemKind;
    use crate::codec::StacksMessageCodec;

    #[test]
    fn ptrs_from_slice_into_decodes_node4_dense_compressed() {
        let ptrs = [
            TriePtr::new(TrieNodeID::Leaf as u8, 0x11, 0x1234),
            TriePtr::default(),
            TriePtr::new_backptr(TrieNodeID::Node16 as u8, 0x22, 0x4567, 0x89ab),
            TriePtr::default(),
        ];
        let mut bytes = vec![set_compressed(TrieNodeID::Node4 as u8)];
        for ptr in ptrs {
            ptr.write_bytes_compressed(&mut bytes).unwrap();
        }

        let mut decoded = [TriePtr::default(); 4];
        let (decoded_id, consumed) =
            ptrs_from_slice_into(TrieNodeID::Node4 as u8, &bytes, &mut decoded).unwrap();

        assert_eq!(decoded_id, TrieNodeID::Node4 as u8);
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, ptrs);
    }

    #[test]
    fn ptrs_from_slice_into_decodes_node48_sparse_compressed() {
        let ptrs = [
            TriePtr::new(TrieNodeID::Leaf as u8, 0x01, 0x1234),
            TriePtr::new_backptr(TrieNodeID::Node16 as u8, 0x11, 0x4567, 0x89ab),
            TriePtr::new(TrieNodeID::Node4 as u8, 0x2f, 0xcdef),
            TriePtr::new_backptr(TrieNodeID::Node256 as u8, 0x30, 0x1111, 0x2222),
        ];
        let bitmap = [0x02, 0x02, 0x00, 0x00, 0x00, 0x81];

        let mut bytes = vec![
            set_compressed(TrieNodeID::Node48 as u8),
            SPARSE_PTR_BITMAP_MARKER,
        ];
        bytes.extend_from_slice(&bitmap);
        for ptr in ptrs {
            ptr.write_bytes_compressed(&mut bytes).unwrap();
        }

        let mut decoded = [TriePtr::default(); 48];
        let (decoded_id, consumed) =
            ptrs_from_slice_into(TrieNodeID::Node48 as u8, &bytes, &mut decoded).unwrap();

        assert_eq!(decoded_id, TrieNodeID::Node48 as u8);
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded[1], ptrs[0]);
        assert_eq!(decoded[9], ptrs[1]);
        assert_eq!(decoded[40], ptrs[2]);
        assert_eq!(decoded[47], ptrs[3]);
    }

    #[test]
    fn read_trie_item_at_head_ref_decodes_node4_from_bulk_buffer() {
        let hash = TrieHash([0x11; TRIEHASH_ENCODED_SIZE]);
        let mut node = TrieNode4::new(&[0xaa, 0xbb, 0xcc]);
        node.insert(&TriePtr::new(TrieNodeID::Leaf as u8, 0x21, 0x1234));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(hash.as_bytes());
        node.write_bytes_compressed(&mut bytes).unwrap();
        let expected_len = bytes.len();

        let mut cursor = Cursor::new(bytes);
        let mut scratch = MarfReadState::new();
        let read =
            read_trie_item_at_head_ref(&mut cursor, TrieNodeID::Node4 as u8, &mut scratch).unwrap();
        let read = read.into_node().unwrap();
        let (node_ref, got_hash) = read.as_node_ref().unwrap();
        let got_hash = got_hash.expect("missing hash");

        assert_eq!(got_hash, hash);
        match node_ref {
            TrieNodeRef::Node4 { path, ptrs } => {
                assert_eq!(path, node.path.as_slice());
                assert_eq!(ptrs, &node.ptrs);
            }
            other => panic!("unexpected node ref: {other:?}"),
        }
        assert_eq!(cursor.position() as usize, expected_len);
    }

    #[test]
    fn read_trie_item_at_head_ref_decodes_patch_from_bulk_buffer() {
        let hash = TrieHash([0x22; TRIEHASH_ENCODED_SIZE]);
        let patch = TrieNodePatch {
            ptr: TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x33, 0x4567, 0x89ab),
            ptr_diff: vec![
                TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x44, 0x1111, 0x2222),
                TriePtr::new(TrieNodeID::Node16 as u8, 0x55, 0x3333),
            ],
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(hash.as_bytes());
        patch.consensus_serialize(&mut bytes).unwrap();
        let expected_len = bytes.len();

        let mut cursor = Cursor::new(bytes);
        let mut scratch = MarfReadState::new();
        let read =
            read_trie_item_at_head_ref(&mut cursor, TrieNodeID::Patch as u8, &mut scratch).unwrap();
        match read.kind {
            ReadTrieItemKind::Patch(got_patch) => {
                let got_hash = read.hash.expect("missing hash");
                assert_eq!(got_hash, hash);
                assert_eq!(got_patch, &patch);
            }
            other => panic!("unexpected artifact: {other:?}"),
        }
        assert_eq!(cursor.position() as usize, expected_len);
    }

    #[test]
    fn read_trie_item_at_head_ref_returns_patch_view_from_bulk_buffer() {
        let hash = TrieHash([0x24; TRIEHASH_ENCODED_SIZE]);
        let patch = TrieNodePatch {
            ptr: TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x33, 0x4567, 0x89ab),
            ptr_diff: vec![TriePtr::new(TrieNodeID::Node16 as u8, 0x55, 0x3333)],
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(hash.as_bytes());
        patch.consensus_serialize(&mut bytes).unwrap();
        let expected_len = bytes.len();

        let mut cursor = Cursor::new(bytes);
        let mut scratch = MarfReadState::new();
        let result =
            read_trie_item_at_head_ref(&mut cursor, TrieNodeID::Patch as u8, &mut scratch).unwrap();

        match result.kind {
            ReadTrieItemKind::Patch(got_patch) => {
                let got_hash = result.hash.expect("missing hash");
                assert_eq!(got_hash, hash);
                assert_eq!(got_patch, &patch);
            }
            other => panic!("unexpected borrowed result: {other:?}"),
        }
        assert_eq!(cursor.position() as usize, expected_len);
    }

    #[test]
    fn read_trie_item_at_head_ref_decodes_leaf_from_bulk_buffer() {
        let hash = TrieHash([0x35; TRIEHASH_ENCODED_SIZE]);
        let leaf = TrieLeaf::new(&[0xca, 0xfe, 0xba, 0xbe], &[0x77; 40]);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(hash.as_bytes());
        leaf.write_bytes_compressed(&mut bytes).unwrap();
        let expected_len = bytes.len();

        let mut cursor = Cursor::new(bytes);
        let mut scratch = MarfReadState::new();
        let read =
            read_trie_item_at_head_ref(&mut cursor, TrieNodeID::Leaf as u8, &mut scratch).unwrap();
        let read = read.into_node().unwrap();
        let (node_ref, got_hash) = read.as_node_ref().unwrap();
        let got_hash = got_hash.expect("missing hash");

        assert_eq!(got_hash, hash);
        match node_ref {
            TrieNodeRef::Leaf(TrieLeafRef { path, data }) => {
                assert_eq!(path, leaf.path.as_slice());
                assert_eq!(data, &leaf.data);
            }
            other => panic!("unexpected node ref: {other:?}"),
        }
        assert_eq!(cursor.position() as usize, expected_len);
    }

    #[test]
    fn patch_node_body_max_len_covers_max_patch_encoding() {
        let patch = TrieNodePatch {
            ptr: TriePtr::new_backptr(TrieNodeID::Node256 as u8, 0x01, 0x0203, 0x0405),
            ptr_diff: vec![TriePtr::new_backptr(TrieNodeID::Leaf as u8, 0x7f, 0x0809, 0x0a0b); 256],
        };

        let encoded = patch.serialize_to_vec();
        let max_len = get_node_body_max_byte_len(TrieNodeID::Patch as u8).unwrap();
        assert!(max_len >= encoded.len());
        assert_eq!(max_len, 1 + 10 + 1 + 256 * 10);
        assert_eq!(
            clear_ctrl_bits(set_backptr(TrieNodeID::Patch as u8)),
            TrieNodeID::Patch as u8
        );
    }

    /// Regression: NodePath equality must compare only the active prefix, not stale tail bytes.
    /// A shorter path decoded into a scratch slot after a longer one must compare equal to a
    /// freshly-constructed NodePath with the same active bytes.
    #[test]
    fn nodepath_equality_ignores_stale_tail_bytes() {
        use crate::chainstate::stacks::index::NodePath;

        // Simulate scratch reuse: first decode a long path, then a short one into the same slot.
        let mut path = NodePath::from_slice(&[0xaa; 20]).unwrap();
        assert_eq!(path.len(), 20);

        // Overwrite with a shorter path (as set_from_slice does in decode).
        path.set_from_slice(&[0xbb; 5]).unwrap();

        // A freshly-constructed path with the same active content must be equal.
        let fresh = NodePath::from_slice(&[0xbb; 5]).unwrap();
        assert_eq!(path, fresh);
        assert_eq!(path.as_slice(), fresh.as_slice());

        // Same test via read_from (the Read-based decode path).
        let mut path2 = NodePath::from_slice(&[0xcc; 32]).unwrap();
        let short_data = [0xdd; 3];
        path2
            .read_from(3, &mut std::io::Cursor::new(&short_data))
            .unwrap();
        let fresh2 = NodePath::from_slice(&[0xdd; 3]).unwrap();
        assert_eq!(path2, fresh2);

        // from_slice rejects oversized input
        assert!(NodePath::from_slice(&[0xff; 33]).is_none());

        // set_from_slice rejects oversized input
        let mut p = NodePath::default();
        assert!(p.set_from_slice(&[0xff; 33]).is_none());
    }

    /// Regression: TrieLeaf::consensus_deserialize must return an error (not panic) when the
    /// wire path exceeds 32 bytes.
    #[test]
    fn trieleaf_deserialize_rejects_oversized_path() {
        use crate::chainstate::stacks::index::TrieLeaf;

        // Build a valid-looking wire payload with a 33-byte path.
        let mut wire = Vec::new();
        // 4-byte big-endian length prefix = 33
        wire.extend_from_slice(&33u32.to_be_bytes());
        // 33 bytes of path data
        wire.extend_from_slice(&[0xaa; 33]);
        // 40 bytes of MARFValue (would follow in a valid leaf)
        wire.extend_from_slice(&[0x00; 40]);

        let result = TrieLeaf::consensus_deserialize(&mut std::io::Cursor::new(&wire));
        assert!(
            result.is_err(),
            "Expected DeserializeError for oversized path, got Ok"
        );
    }
}
