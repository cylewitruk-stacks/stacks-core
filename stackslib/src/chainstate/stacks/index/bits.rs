// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use stacks_common::util::hash::to_hex;

use crate::chainstate::stacks::index::node::{
    clear_backptr, ConsensusSerializable, TrieNode, TrieNode16, TrieNode256, TrieNode4, TrieNode48,
    TrieNodeID, TrieNodePath, TrieNodeType, TriePtr, TRIEPTR_SIZE,
};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::{BlockMap, Error, MarfTrieId, TrieLeaf};

/// Get the size of a Trie path (note that a Trie path is 32 bytes long, and can definitely _not_
/// be over 255 bytes).
#[inline]
pub fn get_path_byte_len(p: &[u8]) -> usize {
    assert!(p.len() < 255);
    let path_len_byte_len = 1;
    path_len_byte_len + p.len()
}

/// Decode a trie path from a Readable object.
/// Returns Error::CorruptionError if the path doesn't decode.
pub fn path_from_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
    Ok(path_from_bytes_inline(r)?.to_vec())
}

/// Decode a trie path from a Readable object into fixed-size inline storage.
/// Returns Error::CorruptionError if the path doesn't decode.
pub fn path_from_bytes_inline<R: Read>(r: &mut R) -> Result<TrieNodePath, Error> {
    let mut lenbuf = [0u8; 1];
    r.read_exact(&mut lenbuf).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError("Failed to read len buf".to_string())
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    if lenbuf[0] as usize > TRIEHASH_ENCODED_SIZE {
        trace!(
            "Path length is {} (expected <= {})",
            lenbuf[0],
            TRIEHASH_ENCODED_SIZE
        );
        return Err(Error::CorruptionError(format!(
            "Node path is longer than {} bytes (got {})",
            TRIEHASH_ENCODED_SIZE, lenbuf[0]
        )));
    }

    let path_len = lenbuf[0] as usize;
    if path_len == 0 {
        return Ok(TrieNodePath::default());
    }

    let mut path_bytes = [0u8; TRIEHASH_ENCODED_SIZE];
    r.read_exact(&mut path_bytes[..path_len]).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!("Failed to read {} bytes of path", lenbuf[0]))
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(TrieNodePath::from_array_len(path_bytes, path_len))
}

/// Helper to verify that a Trie node's ID byte is valid.
#[inline]
pub fn check_node_id(nid: u8) -> bool {
    let node_id = clear_backptr(nid);
    TrieNodeID::from_u8(node_id).is_some()
}

/// Helper to return the number of children in a Trie, given its ID.
#[inline]
pub fn node_id_to_ptr_count(node_id: u8) -> usize {
    match TrieNodeID::from_u8(clear_backptr(node_id))
        .unwrap_or_else(|| panic!("Unknown node ID {}", node_id))
    {
        TrieNodeID::Leaf => 1,
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        TrieNodeID::Empty => panic!("node_id_to_ptr_count: tried getting empty node pointer count"),
    }
}

/// Helper to determine how many bytes a Trie node's child pointers will take to encode.
#[inline]
pub fn get_ptrs_byte_len(ptrs: &[TriePtr]) -> usize {
    let node_id_len = 1;
    node_id_len + TRIEPTR_SIZE * ptrs.len()
}

/// Helper to map an error from trying to read a Trie node's child pointers into an appropriate
/// Error variant.
#[inline]
fn map_ptrs_read_error(e: std::io::Error, num_ptrs: usize) -> Error {
    if e.kind() == ErrorKind::UnexpectedEof {
        Error::CorruptionError(format!(
            "Failed to read 1 + {} bytes of ptrs",
            num_ptrs * TRIEPTR_SIZE
        ))
    } else {
        eprintln!("failed: {:?}", &e);
        Error::IOError(e)
    }
}

/// Helper to decode a Trie node's child pointers from a byte slice, and write them to the given
/// ptrs_buf slice.
#[inline]
fn decode_ptrs_bytes(
    expected_node_id: u8,
    bytes: &[u8],
    ptrs_buf: &mut [TriePtr],
) -> Result<u8, Error> {
    // caller guarantees this invariant when allocating `bytes`
    debug_assert!(!bytes.is_empty());

    let nid = bytes[0];
    if clear_backptr(nid) != expected_node_id {
        trace!("Bad idbuf: {:x} != {:x}", nid, expected_node_id);
        return Err(Error::CorruptionError(
            "Failed to read expected node ID".to_string(),
        ));
    }

    let ptr_bytes = &bytes[1..];
    // iterate over the read-in bytes in chunks of TRIEPTR_SIZE and store them to `ptrs_buf`
    for (next_ptr_bytes, ptr_slot) in ptr_bytes
        .chunks_exact(TRIEPTR_SIZE)
        .zip(ptrs_buf.iter_mut())
    {
        *ptr_slot = TriePtr {
            id: next_ptr_bytes[0],
            chr: next_ptr_bytes[1],
            ptr: u32::from_be_bytes([
                next_ptr_bytes[2],
                next_ptr_bytes[3],
                next_ptr_bytes[4],
                next_ptr_bytes[5],
            ]),
            back_block: u32::from_be_bytes([
                next_ptr_bytes[6],
                next_ptr_bytes[7],
                next_ptr_bytes[8],
                next_ptr_bytes[9],
            ]),
        };
    }
    Ok(nid)
}

/// Read a Trie node's children from a Readable object, and write them to the given ptrs_buf slice.
/// Returns the Trie node ID detected.
pub fn ptrs_from_bytes<R: Read>(
    node_id: u8,
    r: &mut R,
    ptrs_buf: &mut [TriePtr],
) -> Result<u8, Error> {
    if !check_node_id(node_id) {
        trace!("Bad node ID {:x}", node_id);
        return Err(Error::CorruptionError(format!(
            "Bad node ID: {:x}",
            node_id
        )));
    }

    // Keep original behavior for invalid enum variants (`Empty` panics through
    // `node_id_to_ptr_count`), while optimizing the read/decode path below.
    let num_ptrs = node_id_to_ptr_count(node_id);
    let expected_node_id = clear_backptr(node_id);

    // Fast path for small node variants: avoid heap allocation and keep zero-init size tight for
    // each concrete node kind.
    const LEAF_PTR_BUF_LEN: usize = 1 + TRIEPTR_SIZE;
    const NODE4_PTR_BUF_LEN: usize = 1 + 4 * TRIEPTR_SIZE;
    const NODE16_PTR_BUF_LEN: usize = 1 + 16 * TRIEPTR_SIZE;
    const NODE48_PTR_BUF_LEN: usize = 1 + 48 * TRIEPTR_SIZE;
    const NODE256_PTR_BUF_LEN: usize = 1 + 256 * TRIEPTR_SIZE;

    match num_ptrs {
        1 => {
            let mut stack_bytes = [0u8; LEAF_PTR_BUF_LEN];
            r.read_exact(&mut stack_bytes)
                .map_err(|e| map_ptrs_read_error(e, num_ptrs))?;
            decode_ptrs_bytes(expected_node_id, &stack_bytes, ptrs_buf)
        }
        4 => {
            let mut stack_bytes = [0u8; NODE4_PTR_BUF_LEN];
            r.read_exact(&mut stack_bytes)
                .map_err(|e| map_ptrs_read_error(e, num_ptrs))?;
            decode_ptrs_bytes(expected_node_id, &stack_bytes, ptrs_buf)
        }
        16 => {
            let mut stack_bytes = [0u8; NODE16_PTR_BUF_LEN];
            r.read_exact(&mut stack_bytes)
                .map_err(|e| map_ptrs_read_error(e, num_ptrs))?;
            decode_ptrs_bytes(expected_node_id, &stack_bytes, ptrs_buf)
        }
        48 => {
            let mut stack_bytes = [0u8; NODE48_PTR_BUF_LEN];
            r.read_exact(&mut stack_bytes)
                .map_err(|e| map_ptrs_read_error(e, num_ptrs))?;
            decode_ptrs_bytes(expected_node_id, &stack_bytes, ptrs_buf)
        }
        256 => {
            let mut stack_bytes = [0u8; NODE256_PTR_BUF_LEN];
            r.read_exact(&mut stack_bytes)
                .map_err(|e| map_ptrs_read_error(e, num_ptrs))?;
            decode_ptrs_bytes(expected_node_id, &stack_bytes, ptrs_buf)
        }
        _ => unreachable!("invalid pointer count for trie node id"),
    }
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
pub fn get_node_hash<M, T: ConsensusSerializable<M> + std::fmt::Debug>(
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
pub fn get_leaf_hash(node: &TrieLeaf) -> TrieHash {
    let mut hasher = TrieHasher::new();
    node.write_bytes(&mut hasher)
        .expect("IO Failure pushing to hasher.");

    let res = hasher.finalize().into();
    let ret = TrieHash(res);

    trace!("get_leaf_hash: hash {:?} = {:?} + []", &ret, node);
    ret
}

pub fn get_nodetype_hash_bytes<T: MarfTrieId, M: BlockMap>(
    node: &TrieNodeType,
    child_hash_bytes: &[TrieHash],
    map: &mut M,
) -> TrieHash {
    match node {
        TrieNodeType::Node4(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node16(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node48(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Node256(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Leaf(ref data) => get_node_hash(data, child_hash_bytes, map),
    }
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

pub fn read_block_identifier<F: Read + Seek>(f: &mut F) -> Result<u32, Error> {
    let mut bytes = [0u8; 4];
    f.read_exact(&mut bytes).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!(
                "Failed to read hash in full from {}",
                f.seek(SeekFrom::Current(0)).unwrap()
            ))
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(u32::from_le_bytes(bytes))
}

/// Low-level method for reading a node's hash bytes into a buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_node_hash_bytes<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<[u8; TRIEHASH_ENCODED_SIZE], Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    read_hash_bytes(f)
}

/// Read the root hash from a TrieFileStorage instance
pub fn read_root_hash<T: MarfTrieId>(s: &mut TrieStorageConnection<T>) -> Result<TrieHash, Error> {
    let ptr = s.root_trieptr();
    Ok(s.read_node_hash_bytes(&ptr)?)
}

/// Count the number of allocated children in a list of a node's children pointers.
#[inline]
pub fn count_children(children: &[TriePtr]) -> usize {
    let mut cnt = 0;
    for child in children.iter() {
        if child.id() != TrieNodeID::Empty as u8 {
            cnt += 1;
        }
    }
    cnt
}

/// Read a node and its hash
pub fn read_nodetype<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    trace!("read_nodetype at {:?}", ptr);
    read_nodetype_at_head(f, ptr.id())
}

/// Read a node
pub fn read_nodetype_nohash<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<TrieNodeType, Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    trace!("read_nodetype_nohash at {:?}", ptr);
    read_nodetype_at_head_nohash(f, ptr.id())
}

/// Read a node and hash at the stream's current position
pub fn read_nodetype_at_head<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
) -> Result<(TrieNodeType, TrieHash), Error> {
    inner_read_nodetype_at_head(f, ptr_id, true).map(|(node, hash_opt)| {
        (
            node,
            hash_opt.expect("FATAL: queried hash but received None"),
        )
    })
}

/// Read a node at the stream's current position
pub fn read_nodetype_at_head_nohash<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
) -> Result<TrieNodeType, Error> {
    inner_read_nodetype_at_head(f, ptr_id, false).map(|(node, _)| node)
}

/// Deserialize a node.
/// Node wire format:
/// 0               32 33               33+X         33+X+Y
/// |---------------|--|------------------|-----------|
///   node hash      id  ptrs & ptr data      path
///
/// X is fixed and determined by the TrieNodeType variant.
/// Y is variable, but no more than TrieHash::len().
///
/// If `read_hash` is false, then the contents of the node hash are undefined.
fn inner_read_nodetype_at_head<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
    read_hash: bool,
) -> Result<(TrieNodeType, Option<TrieHash>), Error> {
    let h = if read_hash {
        let h = read_hash_bytes(f)?;
        Some(TrieHash(h))
    } else {
        f.seek(SeekFrom::Current(TRIEHASH_ENCODED_SIZE as i64))?;
        None
    };

    let node = match TrieNodeID::from_u8(ptr_id).ok_or_else(|| {
        Error::CorruptionError(format!("read_node_type: Unknown trie node type {}", ptr_id))
    })? {
        TrieNodeID::Node4 => {
            let node = TrieNode4::from_bytes(f)?;
            TrieNodeType::Node4(node)
        }
        TrieNodeID::Node16 => {
            let node = TrieNode16::from_bytes(f)?;
            TrieNodeType::Node16(node)
        }
        TrieNodeID::Node48 => {
            let node = TrieNode48::from_bytes(f)?;
            TrieNodeType::Node48(Box::new(node))
        }
        TrieNodeID::Node256 => {
            let node = TrieNode256::from_bytes(f)?;
            TrieNodeType::Node256(Box::new(node))
        }
        TrieNodeID::Leaf => {
            let node = TrieLeaf::from_bytes(f)?;
            TrieNodeType::Leaf(node)
        }
        TrieNodeID::Empty => {
            return Err(Error::CorruptionError(
                "read_node_type: stored empty node type".to_string(),
            ))
        }
    };

    Ok((node, h))
}

/// Calculate how many bytes a node will be when serialized, including its hash.
#[inline]
pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len();
    hash_len + node_byte_len
}

/// Write all the bytes for a node, including its hash, to the given Writeable object.
/// Returns the number of bytes written.
pub fn write_nodetype_bytes<F: Write + Seek>(
    f: &mut F,
    node: &TrieNodeType,
    hash: TrieHash,
) -> Result<u64, Error> {
    let bytes_written = (TRIEHASH_ENCODED_SIZE + node.byte_len()) as u64;
    f.write_all(hash.as_bytes())?;
    node.write_bytes(f)?;
    trace!(
        "write_nodetype: {:?} {:?} ({} bytes)",
        node,
        &hash,
        bytes_written
    );
    Ok(bytes_written)
}

pub fn write_path_to_bytes<W: Write>(path: &[u8], w: &mut W) -> Result<(), Error> {
    w.write_all(&[path.len() as u8])?;
    w.write_all(path)?;
    Ok(())
}
