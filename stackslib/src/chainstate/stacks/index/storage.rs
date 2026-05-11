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

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::{fmt, fs, io};

use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, OpenFlags, Transaction};
use sha2::Digest;

use crate::chainstate::stacks::index::cache::*;
use crate::chainstate::stacks::index::file::{TrieFile, TrieFileNodeHashReader};
use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::node::{
    clear_ctrl_bits, is_backptr, is_leaf_type, set_backptr, TrieCowPtr, TrieNode, TrieNodeID,
    TrieNodePatch, TrieNodeRef, TrieNodeTransientMeta, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::profile::TrieBenchmark;
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::squash::{HistoryBlobState, SquashTrailer};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    bits, marf_squash_trace_enabled_for_height, trie_sql, BlockMap, ClarityMarfTrieId, Error,
    MARFValue, MarfTrieId, NodePatching, NodePath, ReadTrieItem, ReadTrieItemKind, ReadTrieNode,
    TrieHasher, TrieLeaf, TrieNodeReadState, TrieReadStorage, WalkIntent, MAX_PATCH_DEPTH,
};
use crate::codec::StacksMessageCodec;
use crate::types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE};
use crate::util::hash::to_hex;
use crate::util_lib::db::{
    sql_pragma, sqlite_open, tx_begin_immediate, Error as db_error, SQLITE_MARF_PAGE_SIZE,
    SQLITE_MMAP_SIZE,
};

/// Byte offset of a trie's root node when stored on disk.
/// The block header hash (32 bytes) and block identifier (4 bytes) precede node data.
pub const ROOT_PTR_DISK: u32 = (BLOCK_HEADER_HASH_ENCODED_SIZE as u32) + 4;

pub struct BlockCtx<T: MarfTrieId> {
    pub block_id: Option<u32>,
    pub block_hash: T,
}

/// A trait for reading the hash of a node into a given Write impl, given the pointer to a node in
/// a trie.
pub trait NodeHashReader {
    fn read_node_hash<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error>;
}

impl<T: MarfTrieId> BlockMap for TrieFileStorage<T> {
    type TrieId = T;

    fn get_block_hash(&self, id: u32) -> Result<T, Error> {
        trie_sql::get_block_hash(&self.db, id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, Error> {
        self.cache
            .get_block_hash_caching(id, |id| trie_sql::get_block_hash(&self.db, id))
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &T) -> Result<u32, Error> {
        trie_sql::get_block_identifier(&self.db, block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &T) -> Result<u32, Error> {
        get_block_id_caching_impl(self.data.unconfirmed, &mut self.cache, &self.db, block_hash)
    }
}

impl<T: MarfTrieId, Db: Deref<Target = Connection>> BlockMap for TrieStorageConnection<'_, T, Db> {
    type TrieId = T;

    fn get_block_hash(&self, id: u32) -> Result<T, Error> {
        trie_sql::get_block_hash(&self.db, id)
    }

    fn get_block_hash_caching<'a>(&'a mut self, id: u32) -> Result<&'a T, Error> {
        self.cache
            .get_block_hash_caching(id, |id| trie_sql::get_block_hash(&self.db, id))
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &T) -> Result<u32, Error> {
        trie_sql::get_block_identifier(&self.db, block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &T) -> Result<u32, Error> {
        get_block_id_caching_impl(self.data.unconfirmed, self.cache, &self.db, block_hash)
    }
}

impl<T: MarfTrieId> BlockMap for TrieSqlHashMapCursor<'_, T> {
    type TrieId = T;

    fn get_block_hash(&self, id: u32) -> Result<T, Error> {
        trie_sql::get_block_hash(self.db, id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, Error> {
        self.cache
            .get_block_hash_caching(id, |id| trie_sql::get_block_hash(self.db, id))
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &T) -> Result<u32, Error> {
        trie_sql::get_block_identifier(self.db, block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &T) -> Result<u32, Error> {
        get_block_id_caching_impl(self.unconfirmed, self.cache, self.db, block_hash)
    }
}

impl<T: MarfTrieId> BlockMap for ReopenedTrieStorageConnection<'_, T> {
    type TrieId = T;

    fn get_block_hash(&self, id: u32) -> Result<T, Error> {
        trie_sql::get_block_hash(self.db, id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, Error> {
        self.cache
            .get_block_hash_caching(id, |id| trie_sql::get_block_hash(self.db, id))
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &T) -> Result<u32, Error> {
        trie_sql::get_block_identifier(self.db, block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &T) -> Result<u32, Error> {
        get_block_id_caching_impl(self.unconfirmed(), &mut self.cache, self.db, block_hash)
    }
}

enum FlushOptions<'a, T: MarfTrieId> {
    CurrentHeader,
    NewHeader(&'a T),
    MinedTable(&'a T),
    UnconfirmedTable,
}

impl<T: MarfTrieId> fmt::Display for FlushOptions<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FlushOptions::CurrentHeader => write!(f, "self"),
            FlushOptions::MinedTable(bhh) => write!(f, "{}.mined", bhh),
            FlushOptions::NewHeader(bhh) => write!(f, "{}", bhh),
            FlushOptions::UnconfirmedTable => write!(f, "self.unconfirmed"),
        }
    }
}

/// Uncommitted storage state to be flushed
#[derive(Clone)]
pub enum UncommittedState<T: MarfTrieId> {
    /// read-write
    RW(TrieRAM<T>),
    /// read-only, sealed, with root hash
    Sealed(TrieRAM<T>, TrieHash),
}

impl<T: MarfTrieId> UncommittedState<T> {
    /// Clear the contents
    pub fn format(&mut self) -> Result<(), Error> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram.format(),
            _ => {
                panic!("FATAL: cannot format a sealed TrieRAM");
            }
        }
    }

    /// Get a hint as to how big the uncommitted state is
    pub fn size_hint(&self) -> usize {
        match self {
            UncommittedState::RW(ref trie_ram) => trie_ram.size_hint(),
            UncommittedState::Sealed(ref trie_ram, _) => trie_ram.size_hint(),
        }
    }

    /// Get an immutable reference to the inner TrieRAM
    pub fn trie_ram_ref(&self) -> &TrieRAM<T> {
        match self {
            UncommittedState::RW(ref trie_ram) => trie_ram,
            UncommittedState::Sealed(ref trie_ram, ..) => trie_ram,
        }
    }

    /// Get a mutable reference to the inner TrieRAM
    pub fn trie_ram_mut(&mut self) -> &mut TrieRAM<T> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram,
            UncommittedState::Sealed(ref mut trie_ram, ..) => trie_ram,
        }
    }

    /// Read a node's hash
    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash, Error> {
        self.trie_ram_ref().read_node_hash(ptr)
    }

    /// Read a node's hash and the node itself by reference.
    pub fn read_node(&mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'_>, Error> {
        self.trie_ram_mut().read_node(ptr)
    }

    /// Write a node and its hash to a particular slot in the TrieRAM.
    /// Panics of the UncommittedState is sealed already.
    pub fn write_nodetype(
        &mut self,
        node_array_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => {
                trie_ram.write_nodetype(node_array_ptr, node, hash)
            }
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to write to a sealed TrieRAM");
            }
        }
    }

    /// Take a node+hash out of the TrieRAM, leaving a placeholder.
    /// Panics if the UncommittedState is sealed.
    pub fn take_node(&mut self, ptr: u32) -> Result<(TrieNodeType, TrieHash), Error> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram.take_node(ptr),
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to take from a sealed TrieRAM");
            }
        }
    }

    /// Restore a node+hash into a TrieRAM slot.
    /// Panics if the UncommittedState is sealed.
    pub fn restore_node(
        &mut self,
        ptr: u32,
        node: TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram.restore_node(ptr, node, hash),
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to restore to a sealed TrieRAM");
            }
        }
    }

    /// Write a node hash to a particular slot in the TrieRAM.
    /// Panics of the UncommittedState is sealed already.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<(), Error> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => {
                trie_ram.write_node_hash(node_array_ptr, hash)
            }
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to write to a sealed TrieRAM");
            }
        }
    }

    /// Get the last pointer (i.e. last slot) of the TrieRAM
    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        self.trie_ram_mut().last_ptr()
    }

    /// Seal the TrieRAM.  Calculate its root hash and prevent any subsequent writes from
    /// succeeding.
    fn seal(
        self,
        storage_tx: &mut TrieStorageTransaction<T>,
    ) -> Result<UncommittedState<T>, Error> {
        match self {
            UncommittedState::RW(mut trie_ram) => {
                let root_hash = trie_ram.inner_seal(storage_tx)?;
                Ok(UncommittedState::Sealed(trie_ram, root_hash))
            }
            _ => {
                panic!("FATAL: tried to re-seal a sealed TrieRAM");
            }
        }
    }

    /// Dump the TrieRAM to the given writeable `f`.  If the TrieRAM is not sealed yet, then seal
    /// it first and then dump it.
    fn dump<F: Write + Seek>(
        self,
        storage_tx: &mut TrieStorageTransaction<T>,
        f: &mut F,
        bhh: &T,
    ) -> Result<(), Error> {
        if self.trie_ram_ref().block_header != *bhh {
            error!("Failed to dump {:?}: not the current block", bhh);
            return Err(Error::NotFoundError);
        }

        match self {
            UncommittedState::RW(mut trie_ram) => {
                // seal it first, then dump it
                debug!("Seal and dump trie for {}", bhh);
                trie_ram.inner_seal_dump(storage_tx)?;
                trie_ram.dump_consume(f)?;
                Ok(())
            }
            UncommittedState::Sealed(trie_ram, _rh) => {
                // already sealed
                debug!(
                    "Dump already-sealed trie for {} (root hash was {})",
                    bhh, _rh
                );
                trie_ram.dump_consume(f)?;
                Ok(())
            }
        }
    }

    /// Dump the TrieRAM to the given writeable `f`.  If the TrieRAM is not sealed yet, then seal
    /// it first and then dump it.  The nodes in the trie will be compressed before writing.
    fn dump_compressed<F: Write + Seek>(
        self,
        storage_tx: &mut TrieStorageTransaction<T>,
        f: &mut F,
        bhh: &T,
    ) -> Result<(), Error> {
        if self.trie_ram_ref().block_header != *bhh {
            error!("Failed to dump {:?}: not the current block", bhh);
            return Err(Error::NotFoundError);
        }

        match self {
            UncommittedState::RW(mut trie_ram) => {
                // seal it first, then dump it
                debug!("Seal and dump trie for {}", bhh);
                trie_ram.inner_seal_dump(storage_tx)?;
                trie_ram.dump_compressed_consume(storage_tx, f)?;
                Ok(())
            }
            UncommittedState::Sealed(trie_ram, _rh) => {
                // already sealed
                debug!(
                    "Dump already-sealed trie for {} (root hash was {})",
                    bhh, _rh
                );
                trie_ram.dump_compressed_consume(storage_tx, f)?;
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn print_to_stderr(&self) {
        self.trie_ram_ref().print_to_stderr()
    }
}

/// In-RAM trie storage.
/// Used by TrieFileStorage to buffer the next trie being built.
#[derive(Clone)]
pub struct TrieRAM<T: MarfTrieId> {
    data: Vec<(TrieNodeType, TrieHash)>,
    block_header: T,
    readonly: bool,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    total_bytes: usize,

    /// does this TrieRAM represent data temporarily moved out of another TrieRAM?
    is_moved: bool,

    parent: T,
}

pub enum DumpPtr {
    Normal(u32),
    Patch(u32, [u8; 32], TrieNodePatch),
}

impl DumpPtr {
    pub fn ptr(&self) -> u32 {
        match self {
            Self::Normal(ptr) => *ptr,
            Self::Patch(ptr, ..) => *ptr,
        }
    }

    pub fn hash_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Normal(..) => None,
            Self::Patch(_, bytes, _) => Some(bytes),
        }
    }

    pub fn patch(&self) -> Option<&TrieNodePatch> {
        match self {
            Self::Normal(..) => None,
            Self::Patch(_, _, patch) => Some(patch),
        }
    }

    pub fn hash_and_patch(&self) -> Option<(&[u8; 32], &TrieNodePatch)> {
        match self {
            Self::Normal(..) => None,
            Self::Patch(_, hash_bytes, patch) => Some((hash_bytes, patch)),
        }
    }

    pub fn patch_mut(&mut self) -> Option<&mut TrieNodePatch> {
        match self {
            Self::Normal(..) => None,
            Self::Patch(_, _, patch) => Some(patch),
        }
    }
}

/// Trie in RAM without the serialization overhead
impl<T: MarfTrieId> TrieRAM<T> {
    pub fn new(block_header: &T, capacity_hint: usize, parent: &T) -> TrieRAM<T> {
        TrieRAM {
            data: Vec::with_capacity(capacity_hint),
            block_header: block_header.clone(),
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent: parent.clone(),
        }
    }

    /// Inner method to instantiate a TrieRAM from existing Trie data.
    fn from_data(block_header: T, data: Vec<(TrieNodeType, TrieHash)>, parent: T) -> TrieRAM<T> {
        TrieRAM {
            data,
            block_header,
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent,
        }
    }

    /// Instantiate a `TrieRAM` from this `TrieRAM`'s `data` and `block_header`.  This TrieRAM will
    /// have its data set to an empty list.  The new TrieRAM will have its `is_moved` field set to
    /// `true`.
    /// The purpose of this method is to temporarily "re-instate" a `TrieRAM` into a
    /// `TrieFileStorage` while it is being flushed, so that all of the `TrieFileStorage` methods
    /// will continue to work on it.
    ///
    /// Do not call directly; instead, use `with_reinstated_data()`.
    fn move_to(&mut self) -> TrieRAM<T> {
        let moved_data = std::mem::replace(&mut self.data, vec![]);
        TrieRAM {
            data: moved_data,
            block_header: self.block_header.clone(),
            readonly: self.readonly,

            read_count: self.read_count,
            read_backptr_count: self.read_backptr_count,
            read_node_count: self.read_node_count,
            read_leaf_count: self.read_leaf_count,

            write_count: self.write_count,
            write_node_count: self.write_node_count,
            write_leaf_count: self.write_leaf_count,

            total_bytes: self.total_bytes,

            is_moved: true,

            parent: self.parent.clone(),
        }
    }

    /// Take a given `TrieRAM` and move its `data` to this `TrieRAM`'s data.
    /// The given `TrieRAM` *must* have been created with a prior call to `self.move_to()`.
    ///
    /// Do not call directly; instead use `with_reinstated_data()`.
    fn replace_from(&mut self, other: TrieRAM<T>) {
        assert!(!self.is_moved);
        assert!(other.is_moved);
        assert_eq!(self.block_header, other.block_header);
        let _ = std::mem::replace(&mut self.data, other.data);
    }

    /// Temporarily re-instate this TrieRAM's data as the `uncommitted_writes` field in a given storage
    /// connection, run the closure `f` with it, and then restore the original `uncommitted_writes` data.
    /// This method does not compose -- calling `with_reinstated_data` within the given closure `f`
    /// will lead to a runtime panic.
    ///
    /// The purpose of this method is to calculate the trie root hash from a trie that is in the
    /// process of being flushed.
    fn with_reinstated_data<F, R>(&mut self, storage: &mut TrieStorageTransaction<T>, f: F) -> R
    where
        F: FnOnce(&mut TrieRAM<T>, &mut TrieStorageTransaction<T>) -> R,
    {
        // do NOT call this function within another instance of this function.  Only tears and
        // misery would result.
        assert!(
            !self.is_moved,
            "FATAL: tried to move a TrieRAM after it had been moved"
        );

        let old_uncommitted_writes = storage.data.uncommitted_writes.take();

        let moved_trie_ram = self.move_to();
        storage.data.uncommitted_writes = Some((
            self.block_header.clone(),
            UncommittedState::RW(moved_trie_ram),
        ));

        let result = f(self, storage);

        // restore
        let (_, moved_extended) = storage
            .data
            .uncommitted_writes
            .take()
            .expect("FATAL: unable to retake moved TrieRAM");

        match moved_extended {
            UncommittedState::RW(trie_ram) => {
                self.replace_from(trie_ram);
            }
            _ => {
                unreachable!()
            }
        };

        storage.data.uncommitted_writes = old_uncommitted_writes;
        result
    }

    #[cfg(test)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.read_node_count;
        let br = self.read_backptr_count;
        let nw = self.write_node_count;

        self.read_node_count = 0;
        self.read_backptr_count = 0;
        self.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.read_leaf_count;
        let lw = self.write_leaf_count;

        self.read_leaf_count = 0;
        self.write_leaf_count = 0;

        (lr, lw)
    }

    /// write the trie data to f, using node_data_order to
    ///   iterate over node_data
    pub fn write_trie_indirect<F: Write + Seek>(
        f: &mut F,
        node_data_order: &[u32],
        node_data: &[(TrieNodeType, TrieHash)],
        offsets: &[u32],
        parent_hash: &T,
    ) -> Result<(), Error> {
        assert_eq!(node_data_order.len(), offsets.len());

        // write parent block ptr
        f.rewind()?;
        f.write_all(parent_hash.as_bytes())
            .map_err(Error::IOError)?;

        // write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        //    identifier from the trie data blob)
        f.seek(SeekFrom::Start(BLOCK_HEADER_HASH_ENCODED_SIZE as u64))?;
        f.write_all(&0u32.to_le_bytes()).map_err(Error::IOError)?;

        for (ix, indirect) in node_data_order.iter().enumerate() {
            // dump the node to storage
            let node = node_data
                .get(*indirect as usize)
                .ok_or_else(|| Error::CorruptionError("node_data_order pointer invalid".into()))?;
            bits::write_node_bytes(f, &node.0, node.1, false)?;

            // next node
            let next_offset = *offsets.get(ix).ok_or_else(|| {
                Error::CorruptionError("node_data_order.len() != offsets.len()".into())
            })?;
            f.seek(SeekFrom::Start(next_offset.into()))?;
        }

        Ok(())
    }

    /// Write the trie data to `f`, using `node_data_order` to iterate over `node_data`.
    ///
    /// ## Compression Improvements
    ///
    /// * Do not store backptr 0's if the node isn't a backptr
    /// * Store a compact representation for sparse child pointer lists
    /// * If a node was copied from another, then only store the difference in ptrs (TrieNodePatch)
    pub fn write_trie_indirect_compressed<F: Write + Seek>(
        f: &mut F,
        node_data_order: &[DumpPtr],
        node_data: &[(TrieNodeType, TrieHash)],
        offsets: &[u32],
        parent_hash: &T,
    ) -> Result<(), Error> {
        assert_eq!(node_data_order.len(), offsets.len());

        // Write parent block ptr
        f.rewind()?;
        f.write_all(parent_hash.as_bytes())
            .map_err(Error::IOError)?;

        // Write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        // identifier from the trie data blob)
        f.seek(SeekFrom::Start(BLOCK_HEADER_HASH_ENCODED_SIZE as u64))?;
        f.write_all(&0u32.to_le_bytes()).map_err(Error::IOError)?;

        for (ix, indirect) in node_data_order.iter().enumerate() {
            if let Some((hash_bytes, patch)) = indirect.hash_and_patch() {
                let f_pos_before = f.stream_position()?;
                f.write_all(hash_bytes)?;
                patch.consensus_serialize(f).map_err(|e| {
                    Error::CorruptionError(format!("Failed to serialize patch: {e:?}"))
                })?;

                let f_pos_after = f.stream_position()?;
                trace!(
                    "write {patch:?} {hash} at {f_pos_before}-{f_pos_after}",
                    hash = to_hex(hash_bytes),
                );
            } else {
                // dump the node to storage
                let node = node_data.get(indirect.ptr() as usize).ok_or_else(|| {
                    Error::CorruptionError("node_data_order pointer invalid".into())
                })?;

                bits::write_node_bytes(f, &node.0, node.1, true)?;
            }
            // next node
            let next_offset = *offsets.get(ix).ok_or_else(|| {
                Error::CorruptionError("node_data_order.len() != offsets.len()".into())
            })?;
            f.seek(SeekFrom::Start(u64::from(next_offset)))?;
        }

        Ok(())
    }

    /// Calculate the MARF root hash from a trie root hash.
    ///
    /// This hashes the trie root hash with a geometric series of prior trie hashes.
    fn calculate_marf_root_hash(
        &mut self,
        storage: &mut TrieStorageTransaction<T>,
        root_hash: &TrieHash,
    ) -> TrieHash {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        storage.data.set_block(self.block_header.clone(), None);

        let mut cursor = None;
        let mut decode_scratch = MarfReadState::new();
        let marf_root_hash =
            Trie::get_trie_root_hash(storage, root_hash, &mut cursor, &mut decode_scratch)
                .expect("FATAL: unable to calculate MARF root hash from moved TrieRAM");

        test_debug!("cur_block_hash = {}, cur_block_id = {:?}, self.block_header = {}, have last extended? {}, root_hash: {}, trie_root_hash = {}", &cur_block_hash, &cur_block_id, &self.block_header, storage.data.uncommitted_writes.is_some(), root_hash, &marf_root_hash);

        storage.data.set_block(cur_block_hash, cur_block_id);

        marf_root_hash
    }

    /// Calculate and store the MARF root hash, as well as any necessary intermediate nodes.
    ///
    /// This should only be used when in deferred hashing mode.
    fn inner_seal_marf(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<T>,
    ) -> Result<TrieHash, Error> {
        // find trie root hash
        debug!("Calculate trie root hash");
        let root_trie_hash = self.calculate_node_hashes(storage_tx, 0)?;

        // find marf root hash -- the hash of the trie root node hash, and the hashes of the
        // geometric series of ancestor tries.  Because the trie is already in the process of
        // being flushed, we have to temporarily reinstate its data into `storage_tx` so we can
        // use it to walk down the various MARF paths needed to query ancestor tries.
        let marf_root_hash = self.with_reinstated_data(storage_tx, |moved_trieram, storage| {
            debug!("Calculate marf root hash");
            moved_trieram.calculate_marf_root_hash(storage, &root_trie_hash)
        });

        if TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode {
            // If we are doing both eager and deferred hashing (i.e. via a test), then verify
            // that we get the same marf hash either way.
            let (_, expected_root_hash) = self.get_nodetype(0)?;
            assert_eq!(expected_root_hash, &marf_root_hash);
        }

        // need to store this hash too, since we deferred calculation
        self.write_node_hash(0, marf_root_hash)?;
        Ok(marf_root_hash)
    }

    /// Get the trie root hash of the trie ram, and update all nodes' root hashes if we're in
    /// deferred hash mode.  Returns the resulting MARF root.  This is part of the seal operation.
    fn inner_seal(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<T>,
    ) -> Result<TrieHash, Error> {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            self.inner_seal_marf(storage_tx)
        } else {
            // already available
            let marf_root_hash =
                Self::read_node_hash(self, &TriePtr::new(TrieNodeID::Node256 as u8, 0, 0))?;

            Ok(marf_root_hash)
        }
    }

    #[cfg(test)]
    pub fn test_inner_seal(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<T>,
    ) -> Result<TrieHash, Error> {
        self.inner_seal(storage_tx)
    }

    /// Seal a trie ram while in the process of dumping it.  If the storage's hash calculation mode
    /// is Deferred, then this updates all the node hashes as well and stores the new node hash.
    /// Otherwise, this is a no-op.
    /// This part of the seal operation.
    fn inner_seal_dump(&mut self, storage_tx: &mut TrieStorageTransaction<T>) -> Result<(), Error> {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            let marf_root_hash = self.inner_seal_marf(storage_tx)?;
            debug!("Deferred root hash calculation is {}", &marf_root_hash);
        }
        Ok(())
    }

    /// Recursively calculate all node hashes in this `TrieRAM`.
    ///
    /// The top-most call to this method should pass `0` for `node_ptr`, since this is the pointer
    /// to the root node.  Returns the node hash for the `TrieNode` at `node_ptr`.
    ///
    /// If the given `storage_tx`'s hash calculation mode is set to
    /// `TrieHashCalculationMode::Deferred`, then this method will also store each non-leaf node's
    /// hash.
    fn calculate_node_hashes(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<T>,
        node_ptr: u64,
    ) -> Result<TrieHash, Error> {
        let start_time = storage_tx.bench.write_children_hashes_start();
        let mut start_node_time = Some(storage_tx.bench.write_children_hashes_same_block_start());
        let (node, node_hash) = self.get_nodetype(node_ptr as u32)?.to_owned();
        if node.is_leaf() {
            // base case: we already have the hash of the leaf, so return it.
            Ok(node_hash)
        } else {
            // inductive case: calculate children hashes, hash them, and return that hash.
            let mut hasher = TrieHasher::new();
            let empty_node_hash = TrieHash::EMPTY;

            node.write_consensus_bytes(storage_tx, &mut hasher)
                .expect("IO Failure pushing to hasher.");

            // count get_nodetype load time for write_children_hashes_same_block benchmark, but
            // only if that code path will be exercised.
            for ptr in node.ptrs().iter() {
                if !is_backptr(ptr.id()) && !ptr.is_empty() {
                    if let Some(start_node_time) = start_node_time.take() {
                        // count the time taken to load the root node in this case,
                        // but only do so once.
                        storage_tx
                            .bench
                            .write_children_hashes_same_block_finish(start_node_time);
                        break;
                    }
                }
            }

            // calculate the hashes of this node's children, and store them if they're in the
            // same trie.
            for ptr in node.ptrs().iter() {
                if ptr.is_empty() {
                    // hash of empty string
                    let start_time = storage_tx.bench.write_children_hashes_empty_start();

                    hasher.write_all(empty_node_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_empty_finish(start_time);
                } else if !is_backptr(ptr.id()) {
                    // hash is the hash of this node's children
                    let node_hash = self.calculate_node_hashes(storage_tx, ptr.ptr() as u64)?;

                    // count the time taken to store the hash towards the
                    // write_children_hashes_same_benchmark
                    let start_time = storage_tx.bench.write_children_hashes_same_block_start();
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} ptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &node_hash,
                        node
                    );
                    hasher.write_all(node_hash.as_bytes())?;

                    if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
                        && ptr.id() != TrieNodeID::Leaf as u8
                    {
                        // need to store this hash too, since we deferred calculation
                        self.write_node_hash(ptr.ptr(), node_hash)?;
                    }

                    storage_tx
                        .bench
                        .write_children_hashes_same_block_finish(start_time);
                } else {
                    // hash is that of the block that contains this node
                    let start_time = storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_start();

                    let block_hash = storage_tx.get_block_hash_caching(ptr.back_block())?;
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} bkptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &block_hash,
                        node
                    );
                    hasher.write_all(block_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_finish(start_time);
                }
            }

            // only measure full trie
            if node_ptr == 0 {
                storage_tx
                    .bench
                    .write_children_hashes_finish(start_time, true);
            }

            let node_hash = {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(hasher.finalize().as_slice());
                TrieHash(buf)
            };

            Ok(node_hash)
        }
    }

    /// Walk through the buffered [`TrieNodeType`]s and dump them to `f`, consuming this `TrieRAM`
    /// instance.
    fn dump_consume<F: Write + Seek>(mut self, f: &mut F) -> Result<u64, Error> {
        // step 1: write out each node in breadth-first order to get their ptr offsets
        let mut frontier: VecDeque<u32> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        let start = TriePtr::new(TrieNodeID::Node256 as u8, 0, 0).ptr();
        frontier.push_back(start);

        // first 32 bytes is reserved for the parent block hash
        //    next 4 bytes is the local block identifier
        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        while let Some(pointer) = frontier.pop_front() {
            let (node, _node_hash) = self.get_nodetype(pointer)?;
            // calculate size
            let num_written = bits::get_node_byte_len(node);
            ptr += num_written as u64;

            // queue each child
            if !node.is_leaf() {
                for ptr in node.ptrs().iter() {
                    if !ptr.is_empty() && !is_backptr(ptr.id) {
                        frontier.push_back(ptr.ptr());
                    }
                }
            }

            node_data.push(pointer);
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for node_data_ptr in node_data.iter() {
            let next_node = &mut self
                .data
                .get_mut(*node_data_ptr as usize)
                .ok_or_else(|| Error::CorruptionError("Miscalculated dump_consume pointer".into()))?
                .0;
            if !next_node.is_leaf() {
                let ptrs = next_node.ptrs_mut();
                for ptr in ptrs.iter_mut() {
                    if !ptr.is_empty() && !is_backptr(ptr.id) {
                        ptr.ptr = *offsets.get(i).ok_or_else(|| {
                            Error::CorruptionError("Miscalculated dump_consume offsets".into())
                        })?;
                        i += 1;
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        TrieRAM::write_trie_indirect(
            f,
            &node_data,
            self.data.as_slice(),
            offsets.as_slice(),
            &self.parent,
        )?;

        Ok(ptr)
    }

    fn make_node_patch(
        storage_tx: &mut TrieStorageTransaction<T>,
        base_ptr: TrieCowPtr,
        node: &TrieNodeType,
        source_snapshot_context: Option<(usize, u32)>,
        decode_scratch: &mut impl TrieNodeReadState,
    ) -> Result<Option<TrieNodePatch>, Error> {
        // Save block state. We use `set_block` to restore instead of `open_block` because the
        // current block may be the uncommitted trie (which has been `.take()`'d from storage during
        // `dump_compressed_consume`), making it unreachable via `open_block`.
        let (cur_block, cur_block_id) = storage_tx.get_cur_block_and_id();
        let cur_block_trie_offset = storage_tx.data.cur_block_trie_offset;
        let cur_leaf_hashes_omitted = storage_tx.data.leaf_hashes_omitted;
        let cur_squash_opened_height = storage_tx.data.squash_opened_height;
        let cur_squash_opened_level_idx = storage_tx.data.squash_opened_level_idx;
        if storage_tx.data.squash_opened_level_idx.is_none() {
            if let Some((source_level_idx, source_height)) = source_snapshot_context {
                let source_leaf_hashes_omitted = *storage_tx
                    .data
                    .squash_meta
                    .level_reads_redirected
                    .get(source_level_idx)
                    .ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.level_reads_redirected missing entry for \
                             source_level_idx={source_level_idx}"
                        ))
                    })?;

                // `dump_compressed_consume` temporarily removes the uncommitted trie from
                // storage, so the current block can no longer be opened normally. Preserve the
                // snapshot context of the block being dumped explicitly; inherited COW ptrs may
                // name shared-ancestor block IDs that also exist in the active replacement level,
                // and patch-base reads must stay in the source level's blob/sidecar.
                storage_tx.data.squash_opened_height = Some(source_height);
                storage_tx.data.squash_opened_level_idx = Some(source_level_idx);
                storage_tx.data.leaf_hashes_omitted = source_leaf_hashes_omitted;
            }
        }
        let restore_current_block = |data: &mut TrieStorageTransientData<T>| {
            data.set_block(cur_block.clone(), cur_block_id);
            data.cur_block_trie_offset = cur_block_trie_offset;
            data.leaf_hashes_omitted = cur_leaf_hashes_omitted;
            data.squash_opened_height = cur_squash_opened_height;
            data.squash_opened_level_idx = cur_squash_opened_level_idx;
        };
        let base_block_id = base_ptr.ptr().back_block();
        open_block_known_id_impl(
            storage_tx.data,
            &storage_tx.db,
            storage_tx.blobs.as_deref(),
            &base_ptr.block_id(),
            base_block_id,
        )?;
        let base_trie_offset = storage_tx.data.cur_block_trie_offset;
        let base_leaf_hashes_omitted = storage_tx.data.leaf_hashes_omitted;

        let base_trie_ptr = base_ptr.ptr().from_backptr();
        let base_is_orphan_sidecar = match storage_tx.data.squash_opened_level_idx {
            Some(level_idx) => {
                let split = storage_tx
                    .data
                    .squash_meta
                    .orphan_split_offset
                    .get(level_idx)
                    .copied()
                    .unwrap_or(0);
                split != 0 && base_trie_ptr.ptr() >= split
            }
            None => false,
        };
        if base_is_orphan_sidecar {
            // PR2 keeps orphan structural nodes exclusively in the sidecar. Patch nodes only
            // encode a block id and logical trie ptr, and `read_patched_persisted_node` follows
            // that ptr through the merged-blob/SQL path without orphan-sidecar routing. A patch
            // against an orphan-only base would later chase into reclaimed blob space, so keep
            // this node self-contained.
            restore_current_block(storage_tx.data);
            return Ok(None);
        }

        match storage_tx.read_node_with_state(base_ptr.ptr(), decode_scratch) {
            Ok(read) => {
                if read.patch_depth >= MAX_PATCH_DEPTH as usize {
                    restore_current_block(storage_tx.data);
                    return Ok(None);
                }
                if read.path_bytes()? != node.path_bytes() {
                    restore_current_block(storage_tx.data);
                    return Ok(None);
                }

                let (old_node, _) = read.as_node_ref()?;

                trace!(
                    "Make patch from old node from block {:?} to new node {:?}",
                    &old_node,
                    node
                );
                let result = TrieNodePatch::try_from_noderef(*base_ptr.ptr(), old_node, &node);
                restore_current_block(storage_tx.data);
                return Ok(result);
            }
            Err(Error::Patch(_, _old_patch)) => {
                restore_current_block(storage_tx.data);

                // building atop an existing patch.
                // Make sure that the base node's path isn't different from this node
                let scratch = &mut MarfReadState::new();
                let read = read_patched_persisted_node(
                    &storage_tx.db,
                    storage_tx.db_path,
                    storage_tx.blobs.as_deref(),
                    storage_tx.data.unconfirmed_block_id,
                    base_block_id,
                    *base_ptr.ptr(),
                    base_trie_offset,
                    base_leaf_hashes_omitted,
                    source_snapshot_context,
                    &storage_tx.data.squash_meta,
                    storage_tx.data.squash_root_snapshot_retention_blocks,
                    scratch,
                )?;
                if read.patch_depth >= MAX_PATCH_DEPTH as usize {
                    return Ok(None);
                }

                if read.path_bytes()? != node.path_bytes() {
                    return Ok(None);
                }

                let (base_node, _) = read.as_node_ref()?;
                trace!("Make patch from reconstructed node {base_node:?} to new node {node:?}");

                return Ok(TrieNodePatch::try_from_noderef(
                    *base_ptr.ptr(),
                    base_node,
                    &node,
                ));
            }
            Err(e) => {
                restore_current_block(storage_tx.data);
                return Err(e);
            }
        }
    }

    /// Walk through the buffered TrieNodes and dump them to f, compressing the trie.
    /// This consumes this TrieRAM instance.
    /// The trie will already have been sealed.
    ///
    /// ## Space improvements
    ///
    /// * Do not store backptr 0's if the node isn't a backptr
    /// * Store a compact representation for sparse child pointer lists
    /// * If a node was copied from another, then only store the difference in ptrs (TrieNodePatch)
    ///
    /// ## Returns
    /// * `Ok(len)` to report number of bytes written
    /// * `Err(..)` if we fail to write
    fn dump_compressed_consume<F: Write + Seek>(
        mut self,
        storage_tx: &mut TrieStorageTransaction<T>,
        f: &mut F,
    ) -> Result<u64, Error> {
        // step 1: write out each node in breadth-first order to get their ptr offsets
        let mut frontier: VecDeque<u32> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        let start = TriePtr::new(TrieNodeID::Node256 as u8, 0, 0).ptr();
        frontier.push_back(start);

        // first 32 bytes is reserved for the parent block hash
        //    next 4 bytes is the local block identifier
        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        let mut decode_scratch = MarfReadState::new();
        let source_snapshot_context = patch_source_context_for_block_hash(
            storage_tx.data,
            &storage_tx.db,
            storage_tx.blobs.as_deref(),
            &self.parent,
        );

        while let Some(pointer) = frontier.pop_front() {
            let (node, node_hash) = self.get_nodetype(pointer)?;

            // IMPROVEMENT: if we can, store a patch node instead of the whole node.
            // Only applies to non-leaf nodes, and only if doing so results in a stack of patches
            // that's less than MAX_PATCH_DEPTH. Also, only patch a node if the path is the same.
            let mut patch_node_opt =
                if !node.is_leaf() && node.patch_depth() < MAX_PATCH_DEPTH as usize {
                    if let Some((last_patch_block_id, last_patch_ptr)) = node.last_patch_source() {
                        // this node is a patch to a node in a previous trie.  Try to amend a patch
                        // atop it.
                        let block_hash = storage_tx.get_block_hash_caching(last_patch_block_id)?;

                        // construct a COW pointer to this patch node
                        let mut patch_ptr = TriePtr::new(
                            set_backptr(TrieNodeID::Patch as u8),
                            last_patch_ptr.chr(),
                            last_patch_ptr.ptr(),
                        );
                        patch_ptr.back_block = last_patch_block_id;

                        let base_ptr = TrieCowPtr::new(block_hash.clone(), patch_ptr);
                        let patch_node_opt = Self::make_node_patch(
                            storage_tx,
                            base_ptr,
                            &node,
                            source_snapshot_context,
                            &mut decode_scratch,
                        )?;
                        if let Some(patch_node) = patch_node_opt {
                            trace!(
                                "Create amendment patch for node at {:?}: {:?}",
                                &base_ptr,
                                &node
                            );
                            Some((node_hash.to_bytes(), patch_node))
                        } else {
                            None
                        }
                    } else if let Some(cowptr) = node.get_cow_ptr() {
                        // this node was a COW node for this trie
                        let patch_node_opt = Self::make_node_patch(
                            storage_tx,
                            *cowptr,
                            &node,
                            source_snapshot_context,
                            &mut decode_scratch,
                        )?;
                        if let Some(patch_node) = patch_node_opt {
                            trace!("Create COW patch for node at {:?}: {:?}", &cowptr, &node);
                            Some((node_hash.to_bytes(), patch_node))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

            // calculate size
            if let Some((_, patch_node)) = patch_node_opt.as_ref() {
                // IMPROVEMENT: don't store a copy of a node that was copied forward via
                // MARF::walk_cow(). Instead, store only the new ptrs in the copied node, and store
                // a pointer to the original node in the ancestral trie.
                // TRIEHASH_ENCODED_SIZE accounts for the trie hash bytes written before the patch
                trace!(
                    "Patch node {:?} for {:?} to be written at {}",
                    &patch_node,
                    &node,
                    ptr
                );
                let num_written = TRIEHASH_ENCODED_SIZE + patch_node.size();
                ptr += num_written as u64;

                let mut num_new_nodes = 0;
                if !node.is_leaf() {
                    for ptr in node.ptrs().iter() {
                        if !ptr.is_empty() && !is_backptr(ptr.id) {
                            num_new_nodes += 1;
                        }
                    }
                }
                assert_eq!(num_new_nodes, patch_node.ptr_diff.len());
            } else {
                // IMPROVEMENT: don't store backptr block ID if it's 0
                trace!("Normal node {:?} to be written at {}", &node, ptr);
                let num_written = bits::get_node_byte_len_compressed(node);
                ptr += num_written as u64;
            }

            // queue each child
            if !node.is_leaf() {
                for ptr in node.ptrs().iter() {
                    if !ptr.is_empty() && !is_backptr(ptr.id) {
                        frontier.push_back(ptr.ptr());
                    }
                }
            }

            if let Some((hash_bytes, patch)) = patch_node_opt.take() {
                node_data.push(DumpPtr::Patch(pointer, hash_bytes, patch));
            } else {
                node_data.push(DumpPtr::Normal(pointer));
            }
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for node_data_ptr in node_data.iter_mut() {
            if let Some(patch) = node_data_ptr.patch_mut() {
                for ptr in patch.ptr_diff.iter_mut() {
                    if !ptr.is_empty() && !is_backptr(ptr.id) {
                        ptr.ptr = *offsets.get(i).ok_or_else(|| {
                            Error::CorruptionError(
                                "Miscalculated dump_compressed_consume offsets".into(),
                            )
                        })?;
                        i += 1;
                    }
                }
            } else {
                let next_node = &mut self
                    .data
                    .get_mut(node_data_ptr.ptr() as usize)
                    .ok_or_else(|| {
                        Error::CorruptionError(
                            "Miscalculated dump_compressed_consume pointer".into(),
                        )
                    })?
                    .0;
                if !next_node.is_leaf() {
                    let ptrs = next_node.ptrs_mut();
                    for ptr in ptrs.iter_mut() {
                        if !ptr.is_empty() && !is_backptr(ptr.id) {
                            ptr.ptr = *offsets.get(i).ok_or_else(|| {
                                Error::CorruptionError(
                                    "Miscalculated dump_compressed_consume offsets".into(),
                                )
                            })?;
                            i += 1;
                        }
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        TrieRAM::write_trie_indirect_compressed(
            f,
            &node_data,
            self.data.as_slice(),
            offsets.as_slice(),
            &self.parent,
        )?;

        Ok(ptr)
    }

    /// Load the trie from `f`.
    ///
    /// The trie will have the same structure as the on-disk trie, but it may have nodes in a
    /// different order.
    pub fn load<F: Read + Seek>(f: &mut F, bhh: &T) -> Result<TrieRAM<T>, Error> {
        let mut data = vec![];
        let mut frontier = VecDeque::new();

        // read parent
        f.rewind()?;
        let parent_hash_bytes = bits::read_hash_bytes(f)?;
        let parent_hash = T::from_bytes(parent_hash_bytes);

        let root_disk_ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        let root_ptr = TriePtr::new(TrieNodeID::Node256 as u8, 0, root_disk_ptr as u32);
        // TODO: Thread scratch through load() all the way from its top-level caller
        let mut decode_scratch = MarfReadState::new();
        let (mut root_node, root_hash) = bits::read_trie_item(f, &root_ptr, &mut decode_scratch)
            .and_then(|read| {
                read.into_node()?
                    .into_owned_node()
                    .and_then(|(node, hash)| {
                        hash.map(|hash| (node, hash)).ok_or_else(|| {
                            Error::CorruptionError("Missing node hash in trie read".to_string())
                        })
                    })
            })
            .inspect_err(|e| error!("Failed to read root node info for {bhh:?}: {e:?}"))?;

        let mut next_index = 1;

        if let TrieNodeType::Node256(ref mut data) = root_node {
            // queue children in the same order we stored them
            for ptr in data.ptrs.iter_mut() {
                if ptr.id() != TrieNodeID::Empty as u8 && !is_backptr(ptr.id()) {
                    frontier.push_back(*ptr);

                    // fix up ptrs
                    ptr.ptr = next_index;
                    next_index += 1;
                }
            }
        } else {
            return Err(Error::CorruptionError(
                "First TrieRAM node is not a Node256".to_string(),
            ));
        }

        data.push((root_node, root_hash));

        while !frontier.is_empty() {
            let next_ptr = frontier
                .pop_front()
                .expect("BUG: no ptr in non-empty frontier");
            let (mut next_node, next_hash) =
                bits::read_trie_item(f, &next_ptr, &mut decode_scratch)
                    .and_then(|read| {
                        read.into_node()?
                            .into_owned_node()
                            .and_then(|(node, hash)| {
                                hash.map(|hash| (node, hash)).ok_or_else(|| {
                                    Error::CorruptionError(
                                        "Missing node hash in trie read".to_string(),
                                    )
                                })
                            })
                    })
                    .inspect_err(|e| error!("Failed to read node at {next_ptr:?}: {e:?}"))?;

            if !next_node.is_leaf() {
                // queue children in the same order we stored them
                let ptrs: &mut [TriePtr] = match next_node {
                    TrieNodeType::Node4(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node16(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node48(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node256(ref mut data) => &mut data.ptrs,
                    _ => {
                        unreachable!();
                    }
                };

                for ptr in ptrs {
                    if ptr.id() != TrieNodeID::Empty as u8 && !is_backptr(ptr.id()) {
                        frontier.push_back(*ptr);

                        // fix up ptrs
                        ptr.ptr = next_index;
                        next_index += 1;
                    }
                }
            }

            data.push((next_node, next_hash));
        }

        Ok(TrieRAM::from_data((*bhh).clone(), data, parent_hash))
    }

    /// Hint as to how many entries to allocate for the inner Vec when creating a TrieRAM
    fn size_hint(&self) -> usize {
        self.write_count as usize
        // the size hint is used for a capacity guess on the data vec, which is _nodes_
        //  NOT bytes. this led to enormous over-allocations
    }

    /// Clear the TrieRAM contents
    pub fn format(&mut self) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        self.data.clear();
        Ok(())
    }

    /// Read a node's hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash, Error> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            Error::NotFoundError
        })?;

        Ok(*node_trie_hash)
    }

    /// Get an immutable reference to a node and its hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn get_nodetype(&self, ptr: u32) -> Result<&(TrieNodeType, TrieHash), Error> {
        self.data.get(ptr as usize).ok_or_else(|| {
            error!(
                "TrieRAM get_nodetype({:?}): Failed to read node: {ptr} >= {}",
                &self.block_header,
                self.data.len()
            );
            Error::NotFoundError
        })
    }

    /// Take a node+hash out of the TrieRAM at the given slot, leaving a cheap placeholder.
    ///
    /// The caller MUST call [`restore_node()`](Self::restore_node) to put a node back before the
    /// TrieRAM is read at this slot again. This is used by the hash-recalculation path to avoid
    /// cloning nodes while still allowing `&mut self` access to storage for hash computation.
    pub fn take_node(&mut self, ptr: u32) -> Result<(TrieNodeType, TrieHash), Error> {
        let data_len = self.data.len();
        let bhh = &self.block_header;
        let slot = self.data.get_mut(ptr as usize).ok_or_else(|| {
            error!("TrieRAM take_node({bhh:?}): {ptr} >= {data_len}");
            Error::NotFoundError
        })?;
        Ok(std::mem::replace(slot, Self::slot_placeholder()))
    }

    /// Restore a node+hash into a `TrieRAM` slot previously emptied by
    /// [`take_node()`](Self::take_node).
    pub fn restore_node(
        &mut self,
        ptr: u32,
        node: TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        let data_len = self.data.len();
        let bhh = &self.block_header;
        let slot = self.data.get_mut(ptr as usize).ok_or_else(|| {
            error!("TrieRAM restore_node({bhh:?}): {ptr} >= {data_len}");
            Error::NotFoundError
        })?;
        *slot = (node, hash);
        Ok(())
    }

    /// Cheap placeholder value for a temporarily-empty `TrieRAM` slot.
    fn slot_placeholder() -> (TrieNodeType, TrieHash) {
        (
            TrieNodeType::Leaf(TrieLeaf {
                path: NodePath::default(),
                data: MARFValue([0u8; 40]),
            }),
            TrieHash([0u8; TRIEHASH_ENCODED_SIZE]),
        )
    }

    pub fn read_node(&mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'_>, Error> {
        let bhh = &self.block_header;
        trace!("TrieRAM: read_node({bhh:?}): at {ptr:?}");

        self.read_count += 1;
        if is_backptr(ptr.id()) {
            self.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.read_leaf_count += 1;
        } else {
            self.read_node_count += 1;
        }

        if let Some((node, hash)) = self.data.get(ptr.ptr() as usize) {
            Ok(
                ReadTrieNode::from_borrowed(TrieNodeRef::from(node), Some(*hash))
                    .with_transient_meta(TrieNodeTransientMeta::from_node(node)),
            )
        } else {
            error!(
                "TrieRAM read_node({bhh:?}): Failed to read node {ptr:?}: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            Err(Error::NotFoundError)
        }
    }

    /// Store a node and its hash to the `TrieRAM` at the given slot.
    pub fn write_nodetype(
        &mut self,
        node_array_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        let bhh = &self.block_header;
        trace!("TrieRAM: write_nodetype({bhh:?}): at {node_array_ptr}: {hash:?} {node:?}");

        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            }
            _ => {
                self.write_node_count += 1;
            }
        }

        if let Some(existing_node) = self.data.get_mut(node_array_ptr as usize) {
            *existing_node = (node.clone(), hash);
            Ok(())
        } else if node_array_ptr == (self.data.len() as u32) {
            self.data.push((node.clone(), hash));
            self.total_bytes += bits::get_node_byte_len(node);
            Ok(())
        } else {
            error!("Failed to write node bytes: off the end of the buffer");
            Err(Error::NotFoundError)
        }
    }

    /// Store a node hash into the `TrieRAM` at a given node slot.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        let bhh = &self.block_header;
        trace!("TrieRAM: write_node_hash({bhh:?}): at {node_array_ptr}: {hash:?}",);

        // can only set the hash of an existing node
        if let Some(existing_node) = self.data.get_mut(node_array_ptr as usize) {
            existing_node.1 = hash;
            Ok(())
        } else {
            error!("Failed to write node hash bytes: off the end of the buffer");
            Err(Error::NotFoundError)
        }
    }

    /// Get the next ptr value for a node to store.
    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        Ok(self.data.len() as u32)
    }

    #[cfg(test)]
    pub fn print_to_stderr(&self) {
        for dat in self.data.iter() {
            eprintln!("{}: {:?}", &dat.1, &dat.0);
        }
    }

    #[cfg(test)]
    pub fn data(&self) -> &Vec<(TrieNodeType, TrieHash)> {
        &self.data
    }
}

impl<T: MarfTrieId> NodeHashReader for TrieRAM<T> {
    fn read_node_hash<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            Error::NotFoundError
        })?;
        w.write_all(node_trie_hash.as_bytes())?;
        Ok(())
    }
}

pub struct TrieSqlCursor<'a> {
    db: &'a Connection,
    block_id: u32,
}

pub struct TrieSqlHashMapCursor<'a, T: MarfTrieId> {
    db: &'a Connection,
    cache: &'a mut BlockCache<T>,
    unconfirmed: bool,
}

impl NodeHashReader for TrieSqlCursor<'_> {
    fn read_node_hash<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        trie_sql::read_node_hash_bytes(self.db, w, self.block_id, ptr)
    }
}

/// `TrieStorageTransaction` is an alias for [`TrieStorageConnection`] specialized with
/// [`Transaction<'a>`]. Any storage methods that require a live write transaction are defined only
/// for [`TrieStorageConnection<'a, T, Transaction<'a>>`] (e.g.,
/// [`flush()`](TrieStorageConnection::flush), [`commit_tx()`](TrieStorageConnection::commit_tx)).
pub type TrieStorageTransaction<'a, T> = TrieStorageConnection<'a, T, Transaction<'a>>;

/// Hash calculation mode
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TrieHashCalculationMode {
    /// Calculate all trie node hashes as we insert leaves
    Immediate,
    /// Do not calculate trie node hashes until we dump the trie to disk
    Deferred,
    /// Calculate trie hashes both on leaf insert and on trie dump.  Used for testing.
    All,
}

///
///  TrieStorageConnection is a pointer to an open TrieFileStorage.
///  The `Db` type parameter encodes the connection state: `&'a Connection`
///  for read-only access, `Transaction<'a>` for a live write transaction.
///  Mutations on TrieStorageConnection's `data` field propagate to the
///  TrieFileStorage that created the connection.
///  This is the main interface to the storage methods, and defines most
///    of the storage functionality.
///
pub struct TrieStorageConnection<'a, T: MarfTrieId, Db: Deref<Target = Connection> = &'a Connection>
{
    pub db_path: &'a str,
    db: Db,
    blobs: Option<&'a mut TrieFile>,
    data: &'a mut TrieStorageTransientData<T>,
    cache: &'a mut BlockCache<T>,
    bench: &'a mut TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,
    compress: bool,
    mmap: bool,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: &'a mut Option<T>,
}

/// Immutable squash metadata snapshot. Cheap to clone (held behind `Arc`),
/// replaced wholesale by writers via [`SharedSquashState`].
///
/// **B6.3 simplification.** Pre-B6.3 this struct carried both active and retired
/// levels (the latter produced by the now-deleted `Replace`/`re_squash` path) and
/// a parallel `is_retired: Vec<bool>` flag distinguished them. With retired-row
/// emission gone, every level here is canonical; iteration is unconditional.
pub struct SquashMeta {
    /// Loaded squash level trailers. Empty for non-squashed MARFs.
    pub levels: Vec<SquashTrailer>,
    /// O(1) block-hash → (level_index, height, blob_offset, reads_redirected, block_id) index built
    /// from all trailers.
    pub block_index: HashMap<[u8; 32], (usize, u32, u64, bool, u32)>,
    /// Set of block_ids whose blobs have leaf hashes omitted (reclaimed squash levels).
    pub leaf_hash_omitted_blocks: HashSet<u32>,
    /// Per-level `root_sidecar_present` flag, parallel to `levels`. True
    /// once the level's per-height root snapshot sidecar file has been
    /// atomically published. Used by the fork-extension read path to
    /// distinguish "sidecar should exist" from "level predates sidecars".
    pub root_sidecar_present: Vec<bool>,
    /// Per-level `root_sidecar_trimmed` flag, parallel to `levels`. v1
    /// (PR 1) always false; iteration 2's trim policy will set it to true
    /// after `unlink`-ing the corresponding sidecar.
    pub root_sidecar_trimmed: Vec<bool>,
    /// Per-level orphan split offset, parallel to `levels`. The
    /// `TriePtr.ptr()`-style logical offset (relative to the level's
    /// `BLOB_HEADER_SIZE`) at which orphan structural nodes begin in the
    /// level's address space. Tip-reachable nodes only reference
    /// `[BLOB_HEADER_SIZE .. orphan_split_offset[i])`; PR2 routes
    /// `ptr >= orphan_split_offset[i]` reads into the level's orphan
    /// sidecar section. 0 means no split (no orphans / pre-PR1 levels);
    /// the routing check `ptr < orphan_split_offset` always picks the
    /// merged blob in that case.
    pub orphan_split_offset: Vec<u32>,
    /// Per-level merged-blob offset, parallel to `levels`. Required for
    /// resolving the level's versioned sidecar path
    /// (`marf-roots-level-...-blob-{blob_offset:016x}.dat`). The same
    /// `blob_offset` value is what `block_index` entries carry as their
    /// third tuple element, but a per-level array makes it accessible
    /// without a block-index round-trip when only a `level_idx` is in
    /// hand (e.g. inside `squash_opened_root_node_bytes`).
    pub level_blob_offsets: Vec<u64>,
    /// Per-level `block_id → height` map, parallel to `levels`. Required
    /// by per-level-context backptr resolution: when a read inside
    /// squash level `level_idx` follows a backptr whose
    /// `back_block` (a `marf_data.rowid`) is also recorded in level
    /// `level_idx`'s trailer, the resolution must stay inside that
    /// same level — its merged-blob offsets are the layout the backptr
    /// was written for. Only when the target block_id is **not** in
    /// the current level's trailer (cross-level backptr) does
    /// resolution fall back to the global `block_index`.
    pub level_block_id_to_height: Vec<HashMap<u32, u32>>,
    /// Per-level `reads_redirected` flag, parallel to `levels`. Mirrors
    /// the `reads_redirected` column on each row of `marf_squash_levels`.
    /// Required for per-level-context backptr resolution: when a backptr
    /// stays within squash level `L`, the leaf-hash policy that applies
    /// to the read is `L`'s — NOT the global
    /// [`Self::leaf_hash_omitted_blocks`] union.
    pub level_reads_redirected: Vec<bool>,
    /// Block IDs that appear in two or more squash levels — historically
    /// the shared-ancestor case where a block_id appeared in both an
    /// active and a retired level. With retired-row emission removed
    /// (B6.3), this set is effectively empty for all freshly-built
    /// metas, but the field stays because the parent-chain context walk
    /// in `open_block_known_id_impl` still uses it as a fast-path gate
    /// (always-empty set → walk is always skipped, which is the correct
    /// outcome). Retained on the struct so reading code stays unchanged
    /// across the deletion.
    pub ambiguous_block_ids: HashSet<u32>,
    /// Per-level FullHistory history-blob state, parallel to `levels`. Mirrors
    /// `marf_squash_levels.history_blob_state` per
    /// `.docs/full-history-history-blob-design.md` §10.1. Consulted by the
    /// at-block read path (§8.2) to decide whether to open/consult the
    /// per-level history blob.
    pub level_history_blob_state: Vec<HistoryBlobState>,
    /// Per-level min_height, parallel to `levels`. Mirrors
    /// `marf_squash_levels.min_height`. Used by [`Self::history_blob_reader`]
    /// to derive the canonical history-blob filename for lazy opens
    /// (which depends on min_height, max_height, and blob_offset).
    pub level_min_heights: Vec<u32>,
    /// Per-level max_height, parallel to `levels`. Mirrors
    /// `marf_squash_levels.max_height`. See `level_min_heights`.
    pub level_max_heights: Vec<u32>,
    /// Per-level lazy cache of `Arc<HistoryBlobReader>`. Populated on
    /// first at-block read against a level whose state is `Present`.
    /// Wrapped in `Mutex` so the at-block read path (which takes
    /// `&SquashMeta` through the `Arc`) can lazily mutate the cache
    /// without contending on the global `meta: RwLock<Arc<SquashMeta>>`
    /// snapshot lock.
    ///
    /// Lifecycle (per design doc §8.3): the reader is opened once at
    /// MARF level-load time AND validates the file's footer at open
    /// (per §9.4 step 4). It stays alive for the lifetime of this
    /// `SquashMeta` instance — `build_squash_meta_from_sql` rebuilds
    /// the whole `SquashMeta` on every publish, which is the natural
    /// invalidation point for the cache.
    pub history_blob_readers: std::sync::Mutex<
        HashMap<
            usize,
            std::sync::Arc<crate::chainstate::stacks::index::history_blob::HistoryBlobReader>,
        >,
    >,
}

impl SquashMeta {
    pub fn empty() -> Self {
        Self {
            levels: Vec::new(),
            block_index: HashMap::new(),
            leaf_hash_omitted_blocks: HashSet::new(),
            root_sidecar_present: Vec::new(),
            root_sidecar_trimmed: Vec::new(),
            orphan_split_offset: Vec::new(),
            level_blob_offsets: Vec::new(),
            level_block_id_to_height: Vec::new(),
            level_reads_redirected: Vec::new(),
            ambiguous_block_ids: HashSet::new(),
            level_history_blob_state: Vec::new(),
            level_min_heights: Vec::new(),
            level_max_heights: Vec::new(),
            history_blob_readers: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Resolve the per-level history blob reader for `level_idx`, lazily
    /// opening + footer-validating the file on first use. Three outcomes
    /// per design doc §8.2 / §10.1:
    ///
    /// * `Ok(None)` — `NeverWritten` (TipOnly-mode level, or FullHistory
    ///   with no squashable leaves). At-block reads should not reach this
    ///   path with a `has_history` leaf; if they do, that's a corruption
    ///   between the SQL row and the on-disk leaf.
    /// * `Err(Error::HistoryTrimmed { level_id })` — `Trimmed`. The file
    ///   has been unlinked; at-block reads on this level fail by design.
    /// * `Ok(Some(reader))` — `Present`. The reader is opened once and
    ///   shared across all callers for the lifetime of this `SquashMeta`.
    pub fn history_blob_reader(
        &self,
        marf_dir: &std::path::Path,
        level_idx: usize,
    ) -> Result<
        Option<std::sync::Arc<crate::chainstate::stacks::index::history_blob::HistoryBlobReader>>,
        Error,
    > {
        let state = self
            .level_history_blob_state
            .get(level_idx)
            .copied()
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "SquashMeta::history_blob_reader: level_idx {level_idx} out of range \
                         ({} levels)",
                    self.level_history_blob_state.len()
                ))
            })?;

        match state {
            HistoryBlobState::NeverWritten => Ok(None),
            HistoryBlobState::Trimmed => {
                let level_id = self
                    .levels
                    .get(level_idx)
                    .map(|t| t.info.level_id)
                    .unwrap_or(u32::MAX);
                Err(Error::HistoryTrimmed { level_id })
            }
            HistoryBlobState::Present => {
                // Fast path: cache hit.
                {
                    let cache = self.history_blob_readers.lock().map_err(|_| {
                        Error::CorruptionError("history_blob_readers cache poisoned".into())
                    })?;
                    if let Some(existing) = cache.get(&level_idx) {
                        return Ok(Some(existing.clone()));
                    }
                }
                // Slow path: open + validate. Computed outside the lock so
                // we don't hold it across the file-open.
                let trailer = self.levels.get(level_idx).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "SquashMeta::history_blob_reader: levels[{level_idx}] missing"
                    ))
                })?;
                let blob_offset = *self.level_blob_offsets.get(level_idx).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "SquashMeta::history_blob_reader: level_blob_offsets[{level_idx}] missing"
                    ))
                })?;
                let min_h = *self.level_min_heights.get(level_idx).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "SquashMeta::history_blob_reader: level_min_heights[{level_idx}] missing"
                    ))
                })?;
                let max_h = *self.level_max_heights.get(level_idx).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "SquashMeta::history_blob_reader: level_max_heights[{level_idx}] missing"
                    ))
                })?;
                let path = crate::chainstate::stacks::index::history_blob::history_blob_path(
                    marf_dir,
                    trailer.info.level_id,
                    min_h,
                    max_h,
                    blob_offset,
                );
                let reader =
                    crate::chainstate::stacks::index::history_blob::HistoryBlobReader::open(
                        &path,
                        Some(trailer.info.level_id),
                    )?;
                let arc = std::sync::Arc::new(reader);
                // Re-acquire the lock to insert. Another thread may have
                // raced us to open the same level; if so, return their
                // reader (deterministic — both are valid views of the
                // same immutable file) and let ours drop.
                let mut cache = self.history_blob_readers.lock().map_err(|_| {
                    Error::CorruptionError("history_blob_readers cache poisoned".into())
                })?;
                Ok(Some(cache.entry(level_idx).or_insert(arc).clone()))
            }
        }
    }
}

/// Process-wide storage coordination object shared by every `MARF<T>` handle opened against a
/// given database path (via [`shared_storage_state_for`]).
///
/// Owns two co-located concerns that MUST be observable across independent handles of the same
/// file:
///
/// 1. **Squash metadata** (`meta` / `generation`): writers publish a fresh [`SquashMeta`]
///    atomically via [`SharedStorageState::publish_squash`]; readers detect staleness with a
///    single `AtomicU64` load and re-snapshot via a brief `parking_lot::RwLock` read.
/// 2. **Blob-file mutation quiesce** (`active_reads` / `truncate_pending`): the squash path's
///    `ftruncate` + `pwrite` window invalidates every live mmap to the file — including ones
///    held on other threads. Readers acquire a [`BlobReadGuard`] before touching mmap-backed
///    bytes; writers set `truncate_pending` and spin-wait for `active_reads` to drain before
///    mutating the file, then publish the new metadata and clear `truncate_pending`.
///
/// The two concerns are co-located because a single [`publish_squash`](Self::publish_squash)
/// call must drain readers, mutate the file, install the new metadata, and release waiters —
/// all under one ordering discipline.
pub struct SharedStorageState {
    /// Squash metadata snapshot. Replaced wholesale under the write lock during
    /// [`publish_squash`](Self::publish_squash); readers read-lock briefly and `Arc::clone`.
    meta: RwLock<Arc<SquashMeta>>,

    /// Monotonically-increasing generation. Bumped on every publish so readers can detect
    /// staleness with a single atomic load without acquiring the `meta` lock.
    generation: AtomicU64,

    /// Count of in-flight mmap-backed reads across all handles of this file. Each
    /// [`BlobReadGuard`] increments on acquire and decrements on drop; the writer waits for
    /// this to drain before `ftruncate`.
    active_reads: AtomicU64,

    /// Writer flag: when `true`, new readers must back off and retry (spin-yield) rather than
    /// entering the mmap region. Set on entering the squash critical section and cleared
    /// AFTER the generation bump, so any reader observing `false` is guaranteed to see the
    /// post-publish generation on its next check.
    truncate_pending: AtomicBool,
}

/// RAII guard returned by [`SharedStorageState::acquire_blob_read`]. Keeps `active_reads`
/// incremented for the duration of its lifetime, blocking the writer from entering the
/// `ftruncate` window while any borrowed mmap bytes are in use.
///
/// Owns an `Arc<SharedStorageState>` rather than borrowing one — that decouples the guard's
/// lifetime from any `&MARF` borrow, so callers can hold the guard alongside `&mut` methods
/// on the same storage without tripping the borrow checker.
pub struct BlobReadGuard {
    state: Arc<SharedStorageState>,
}

impl std::fmt::Debug for BlobReadGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlobReadGuard")
    }
}

impl Clone for BlobReadGuard {
    /// Cloning a guard bumps `active_reads` again, so each clone keeps the writer from
    /// entering the ftruncate window until its own `Drop` fires. This lets
    /// `ReadTrieItem<'a>` / `ReadTrieNode<'a>` stay `Clone`-able (which the existing
    /// `#[derive(Clone)]` relies on) without losing the quiesce protection.
    fn clone(&self) -> Self {
        self.state.active_reads.fetch_add(1, Ordering::Acquire);
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl Drop for BlobReadGuard {
    fn drop(&mut self) {
        self.state.active_reads.fetch_sub(1, Ordering::Release);
    }
}

impl SharedStorageState {
    /// Wrap an existing `SquashMeta` in a shareable container at generation 0.
    pub fn new(initial: SquashMeta) -> Arc<Self> {
        Arc::new(Self {
            meta: RwLock::new(Arc::new(initial)),
            generation: AtomicU64::new(0),
            active_reads: AtomicU64::new(0),
            truncate_pending: AtomicBool::new(false),
        })
    }

    /// Empty shared state (no squash levels). Convenience for non-squashed MARFs.
    pub fn empty() -> Arc<Self> {
        Self::new(SquashMeta::empty())
    }

    /// Snapshot the current metadata. Takes a brief `parking_lot` read lock and clones the
    /// inner `Arc` (just a reference-count bump).
    pub fn snapshot(&self) -> Arc<SquashMeta> {
        Arc::clone(&self.meta.read())
    }

    /// Current generation. Readers cache this per-handle and re-snapshot their local state
    /// when it changes.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Acquire a [`BlobReadGuard`] that enforces the blob-mutation quiesce contract.
    ///
    /// Spins while `truncate_pending` is set. After incrementing `active_reads`, re-checks
    /// `truncate_pending` to close the race where a writer sets the flag between our first
    /// read and our increment.
    ///
    /// Callers **must** hold the returned guard for the entire lifetime of any borrowed bytes
    /// they obtain from the mmap — otherwise the writer could `ftruncate` the file out from
    /// under them and SIGBUS on next access.
    ///
    /// Prefer [`try_acquire_blob_read`](Self::try_acquire_blob_read) for per-read acquisition
    /// inside traversals; spinning here from inside a traversal that already has parked
    /// state (ReadTrieNode guards) deadlocks against a writer waiting for drain.
    pub fn acquire_blob_read(self: &Arc<Self>) -> BlobReadGuard {
        loop {
            if let Some(guard) = self.try_acquire_blob_read() {
                return guard;
            }
            std::hint::spin_loop();
        }
    }

    /// Block the calling thread until no publisher is in its mutation window. Used by the
    /// retry wrapper between attempts to avoid hammering a busy writer — without this wait,
    /// a reader with its state already cleared can burn its entire retry budget spinning on
    /// [`try_acquire_blob_read`](Self::try_acquire_blob_read) while the writer's brief
    /// exclusive window (ftruncate + pwrite + trailer build) is still in flight.
    ///
    /// Safe to call only when the caller holds no [`BlobReadGuard`]s — otherwise deadlock:
    /// the writer is waiting for `active_reads` to drain.
    pub fn wait_for_publish_complete(&self) {
        while self.truncate_pending.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    }

    /// Non-spinning variant of [`acquire_blob_read`](Self::acquire_blob_read). Returns `None`
    /// immediately if a writer has set `truncate_pending`; otherwise increments `active_reads`
    /// and returns a fresh guard.
    ///
    /// This is the primitive the read pipeline uses for per-read guard acquisition: on `None`,
    /// the caller returns [`Error::RetryAfterSquash`] up the stack and the top-level retry
    /// wrapper resets per-traversal state (dropping any held guards) so the writer can drain
    /// and publish. After publish completes, the retry re-enters traversal against fresh
    /// metadata.
    ///
    /// The spin variant would deadlock here: a reader with parked `ReadTrieNode`s holds guards
    /// that keep `active_reads > 0`, so the writer waits forever while the reader spins on
    /// `truncate_pending`.
    pub fn try_acquire_blob_read(self: &Arc<Self>) -> Option<BlobReadGuard> {
        #[cfg(test)]
        if fault_inject::consume_failed_acquire() {
            return None;
        }
        if self.truncate_pending.load(Ordering::Acquire) {
            return None;
        }
        self.active_reads.fetch_add(1, Ordering::Acquire);
        if self.truncate_pending.load(Ordering::Acquire) {
            self.active_reads.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(BlobReadGuard {
            state: Arc::clone(self),
        })
    }

    /// Check whether this handle's `seen_squash_generation` watermark is still current
    /// relative to the shared state. Returns `true` when fresh (safe to proceed), `false`
    /// when a concurrent publish has bumped the generation (caller MUST return
    /// [`Error::RetryAfterSquash`] so the outer wrapper can re-sync and restart).
    ///
    /// Co-located with [`try_acquire_blob_read`](Self::try_acquire_blob_read) so both
    /// freshness checks share a single fault-injection surface in tests.
    pub fn squash_state_fresh(&self, seen_generation: u64) -> bool {
        #[cfg(test)]
        if fault_inject::consume_failed_gen_check() {
            return false;
        }
        self.generation() == seen_generation
    }

    /// Publish a new [`SquashMeta`] under the blob-mutation quiesce protocol. The `rebuild` closure
    /// runs inside the exclusive window — after all in-flight readers have drained — and is
    /// responsible for the actual file mutation (pwrite new blob bytes, ftruncate, re-mmap, clear
    /// local offset caches, etc.) plus producing the new [`SquashMeta`] that becomes the shared
    /// snapshot on success.
    ///
    /// Strict ordering (do not reorder):
    ///
    /// 1. `truncate_pending = true` — new readers back off.
    /// 2. spin-wait for `active_reads == 0` — drain in-flight readers.
    /// 3. call `rebuild` — exclusive file + metadata mutation.
    /// 4. install the new `Arc<SquashMeta>` under the write lock.
    /// 5. `generation += 1` — readers observing this re-sync per-handle state.
    /// 6. `truncate_pending = false` — release waiters.
    ///
    /// The generation bump MUST precede clearing `truncate_pending`: otherwise a reader that just
    /// unblocked could load the old generation, think it's fresh, and read the file through a stale
    /// per-handle mmap.
    pub fn publish_squash<F>(&self, rebuild: F) -> Result<(), Error>
    where
        F: FnOnce(&PublishMutationGuard) -> Result<SquashMeta, Error>,
    {
        // 1. Claim the mutation window.
        self.truncate_pending.store(true, Ordering::Release);

        // 2. Drain in-flight readers. Bounded: readers hold guards only for the duration of
        //    a single traversal / borrowed-read lifetime.
        while self.active_reads.load(Ordering::Acquire) > 0 {
            std::thread::yield_now();
        }

        // 3. Run the entire mutation phase (file mutation + metadata install + generation
        //    bump) inside `catch_unwind` so that a panic anywhere in this window aborts the
        //    process instead of releasing readers against an inconsistent file/metadata pair.
        //
        //    The unsafe window is real: `rebuild` typically does `pwrite` + `ftruncate` +
        //    `remap_and_invalidate` BEFORE returning the new `SquashMeta`. A panic — or an
        //    `Err` return — between the truncate and the meta install would leave the
        //    on-disk file mutated but the in-memory `meta` still describing the pre-truncate
        //    layout. If we cleared `truncate_pending` on that path, every subsequent reader
        //    would consult the old metadata against the new file (truncated offsets, stale
        //    block index), serving wrong bytes or hitting decode errors. There is no
        //    transactional rollback for `ftruncate`, so a partial mutation is unrecoverable
        //    in-process — `process::abort` is the only safe response.
        //
        //    To distinguish safe pre-mutation `Err` returns from unsafe post-mutation ones
        //    we hand the closure a [`PublishMutationGuard`] which it MUST `arm()`
        //    immediately before its first irreversible operation. After arming, any `Err`
        //    returned from the closure is treated like a panic and aborts the process.
        //    Before arming, an `Err` is safe to surface to the caller (the file is
        //    untouched).
        let mutation_guard = PublishMutationGuard {
            armed: AtomicBool::new(false),
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let new_meta = rebuild(&mutation_guard)?;
            // 4. Install the new metadata snapshot.
            *self.meta.write() = Arc::new(new_meta);
            // 5. Bump generation BEFORE clearing `truncate_pending` (step 6, below the
            //    catch). Readers that observe `!truncate_pending` are guaranteed to see the
            //    bumped generation on their next check, which forces a per-handle resync.
            self.generation.fetch_add(1, Ordering::Release);
            Ok::<(), Error>(())
        }));
        let armed = mutation_guard.armed.load(Ordering::Acquire);

        match outcome {
            Ok(Ok(())) => {
                // 6. Successful publish: release waiters.
                self.truncate_pending.store(false, Ordering::Release);
                Ok(())
            }
            Ok(Err(e)) if !armed => {
                // Pre-mutation failure: the closure errored before arming the guard, so the
                // blob/file is untouched. Releasing readers is safe.
                self.truncate_pending.store(false, Ordering::Release);
                Err(e)
            }
            Ok(Err(e)) => {
                // Post-mutation failure: the closure had armed the mutation guard, meaning
                // the blob has already been pwritten/ftruncated/remapped. The metadata
                // snapshot has NOT been installed and the generation has NOT been bumped, so
                // releasing readers here would re-enter the same inconsistent
                // file/metadata state we abort on for panics. Same response: log and abort.
                error!(
                    "FATAL: squash rebuild returned Err({e:?}) after arming the mutation \
                     guard — aborting process to avoid serving stale squash metadata against \
                     a possibly-truncated blob"
                );
                std::process::abort();
            }
            Err(_panic) => {
                // Unrecoverable: the file may be partly mutated and metadata stale. Aborting
                // is the only path that doesn't risk serving wrong data. Readers blocked on
                // `wait_for_publish_complete` are released by process exit.
                error!(
                    "FATAL: squash mutation panicked inside publish_squash — aborting process \
                     to avoid serving stale squash metadata against a possibly-truncated blob"
                );
                std::process::abort();
            }
        }
    }
}

/// Marker handed to the `rebuild` closure of [`SharedStorageState::publish_squash`].
///
/// The closure MUST call [`Self::arm`] immediately before its first irreversible operation.
/// "Irreversible" includes both file mutations (`pwrite_blob_chunk`, `finish_blob_write`'s
/// optional `ftruncate`, `remap_and_invalidate`) AND in-place SQL mutations that have no
/// transactional rollback in the surrounding code path — notably
/// `prune_orphaned_external_refs` (zeroes `external_offset`/`length` on non-canonical
/// `marf_data` rows) and the post-write `write_squash_level` /
/// `update_external_trie_blob_by_hash` updates that depend on the new blob layout.
///
/// After arming, any `Err` returned by the closure — or any panic that escapes — aborts
/// the process rather than releasing readers against a half-mutated file/SQL pair with
/// stale published metadata.
///
/// This converts an implicit convention ("don't return `Err` after mutation") into a
/// runtime check that catches violations rather than silently corrupting the index.
pub struct PublishMutationGuard {
    armed: AtomicBool,
}

impl PublishMutationGuard {
    /// Mark the mutation phase as begun. Call this immediately before the first irreversible
    /// operation in the rebuild closure — that includes irreversible SQL mutations
    /// (`prune_orphaned_external_refs`, post-write row updates) as well as blob writes
    /// (`pwrite`, `ftruncate`, `remap_and_invalidate`). After arming, the only safe
    /// outcomes for the closure are `Ok(SquashMeta)` (publish succeeds) or process abort
    /// (via `Err` or panic).
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

/// Transition alias. All new code should use [`SharedStorageState`]; this keeps existing
/// call sites compiling while the rename rolls through the tree.
pub type SharedSquashState = SharedStorageState;

/// Test-only fault injection hooks for the blob-mutation quiesce protocol.
///
/// The two counters inject synthetic instances of the two `RetryAfterSquash`-emitting
/// conditions without requiring an actual concurrent squash: each counter, when positive,
/// is decremented on the next matching check and forces a retry signal. This lets unit
/// tests exercise the retry wrapper's reset + re-entry logic deterministically.
///
/// Counters are **thread-local** so they do not leak across parallel tests — `cargo test`
/// runs each `#[test]` on its own thread. For multi-threaded tests that need to inject
/// failures on another thread, set the counters on that thread before entering the read
/// path. The hooks are `#[cfg(test)]` and compile out entirely in production builds.
#[cfg(test)]
pub mod fault_inject {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT_ACQUIRES: Cell<usize> = const { Cell::new(0) };
        static FAIL_NEXT_GEN_CHECKS: Cell<usize> = const { Cell::new(0) };
    }

    /// Force the next `n` calls to [`SharedStorageState::try_acquire_blob_read`] on the
    /// current thread to return `None` as if a writer had set `truncate_pending`. Each
    /// real acquire consumes one "credit"; once the counter hits zero, acquires behave
    /// normally again.
    pub fn fail_next_acquires(n: usize) {
        FAIL_NEXT_ACQUIRES.with(|c| c.set(n));
    }

    /// Force the next `n` calls to [`SharedStorageState::squash_state_fresh`] on the
    /// current thread to return `false` as if a publisher had bumped the generation.
    /// Each real check consumes one "credit"; once the counter hits zero, checks behave
    /// normally again.
    pub fn fail_next_gen_checks(n: usize) {
        FAIL_NEXT_GEN_CHECKS.with(|c| c.set(n));
    }

    /// Clear both counters on the current thread. Tests should call this at start and
    /// end as a defense against earlier panics leaking injected failures into later
    /// assertions on the same thread.
    pub fn reset() {
        FAIL_NEXT_ACQUIRES.with(|c| c.set(0));
        FAIL_NEXT_GEN_CHECKS.with(|c| c.set(0));
    }

    pub(super) fn consume_failed_acquire() -> bool {
        consume(&FAIL_NEXT_ACQUIRES)
    }

    pub(super) fn consume_failed_gen_check() -> bool {
        consume(&FAIL_NEXT_GEN_CHECKS)
    }

    fn consume(counter: &'static std::thread::LocalKey<Cell<usize>>) -> bool {
        counter.with(|c| {
            let cur = c.get();
            if cur == 0 {
                false
            } else {
                c.set(cur - 1);
                true
            }
        })
    }
}

/// Process-wide registry mapping canonicalized MARF database paths to their
/// live [`SharedSquashState`]. Entries are held as `Weak` so state is freed
/// when the last `MARF` handle for a given path is dropped.
///
/// Two independent `MARF::from_path` opens against the same file return the
/// same `Arc<SharedSquashState>`, which is the mechanism that lets the
/// Stacks 2.x P2P thread and runloop threads — each holding their own
/// chainstate — observe each other's `refresh_after_squash` publishes.
fn shared_squash_registry() -> &'static Mutex<HashMap<PathBuf, std::sync::Weak<SharedSquashState>>>
{
    static REGISTRY: std::sync::OnceLock<
        Mutex<HashMap<PathBuf, std::sync::Weak<SharedSquashState>>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Normalize a MARF db path for use as a registry key. Canonicalizing
/// resolves relative paths and symlinks so two `open_opts` calls spelled
/// differently but targeting the same file share one `SharedSquashState`.
/// Falls back to the input path if canonicalize fails (e.g. path doesn't
/// exist yet during creation).
fn registry_key(db_path: &str) -> PathBuf {
    fs::canonicalize(db_path).unwrap_or_else(|_| PathBuf::from(db_path))
}

/// Obtain the [`SharedSquashState`] associated with `db_path`, constructing
/// one from `build_initial` if no live entry is present.
///
/// `:memory:` paths are NOT shared — every SQLite `:memory:` connection is
/// an independent database, so each MARF gets its own freshly-built state.
fn shared_squash_state_for<F>(
    db_path: &str,
    build_initial: F,
) -> Result<Arc<SharedSquashState>, Error>
where
    F: FnOnce() -> Result<SquashMeta, Error>,
{
    if db_path == ":memory:" {
        return Ok(SharedSquashState::new(build_initial()?));
    }

    let key = registry_key(db_path);
    let mut registry = shared_squash_registry().lock();

    if let Some(weak) = registry.get(&key) {
        if let Some(existing) = weak.upgrade() {
            return Ok(existing);
        }
        // Weak is dead (last Arc dropped). Fall through to rebuild below.
    }

    let arc = SharedSquashState::new(build_initial()?);
    registry.insert(key, Arc::downgrade(&arc));
    Ok(arc)
}

/// Per-path recovery state, held by every live `TrieFileStorage` for a given path. The `Arc` is
/// stored on the storage instance and dropped when the storage is closed; the registry holds only
/// a `Weak` so a path with no live handles ages out automatically.
///
/// `rw_recovery_done` distinguishes "some handle is open" from "an RW handle has completed
/// truncate-on-startup + Phase B reconciliation." Readonly handles intentionally don't run those
/// (truncate-on-startup is gated on `!readonly`; Phase B's readonly contract is fail-hard, not
/// reconciliation), so the flag must NOT flip when a readonly opener is the first to claim the
/// slot. Otherwise a later RW opener would observe the slot as alive, conclude recovery had run,
/// and skip clearing a torn append left by a prior process crash.
pub(crate) struct RecoveryState {
    rw_recovery_done: Mutex<bool>,
}

impl RecoveryState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            rw_recovery_done: Mutex::new(false),
        })
    }
}

/// Process-wide registry of canonicalized MARF database paths to live [`RecoveryState`] entries.
///
/// **Why this exists.** Startup recovery (hot-file torn-append truncation + Phase B promotion-plan
/// reconciliation in [`TrieFileStorage::open`]) is correct only against a process-cold MARF — i.e.
/// no other handle is currently writing. In a `stacks-node` process, the chains-coordinator and
/// the p2p threads each open their own MARF handles. If the second opener runs recovery while the
/// first is mid-flight on a write transaction, it observes:
///
/// * `committed_len` (from a fresh SQL snapshot) at the value committed *before* the writer's
///   in-progress transaction.
/// * `on_disk_len` from the file, which already includes the writer's appended-but-uncommitted
///   bytes (`append_to_active` fsyncs each append).
///
/// The recovery code then concludes "torn append" and truncates the in-flight bytes — destroying
/// data the writer is about to point at via SQL once its transaction commits. The registry's
/// `rw_recovery_done` flag, gated by a per-path mutex, ensures the truncate-on-startup runs at
/// most once across all RW openers of a given path while at least one handle stays alive.
/// Sequential open/close/reopen still re-runs recovery — each fully-closed cycle drops the last
/// `Arc`, the `Weak` becomes dead, and the next opener mints a fresh `RecoveryState`.
fn recovery_registry() -> &'static Mutex<HashMap<PathBuf, std::sync::Weak<RecoveryState>>> {
    static REGISTRY: std::sync::OnceLock<Mutex<HashMap<PathBuf, std::sync::Weak<RecoveryState>>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve the [`RecoveryState`] for `db_path` in this process, minting one if no live entry
/// exists. The returned `Arc` MUST be retained on the resulting `TrieFileStorage` so the live
/// count stays accurate while the handle is open.
///
/// `:memory:` paths are never registered — each `:memory:` SQLite connection is an independent
/// database that can't share state with another handle anyway. The returned state is a fresh
/// `Arc<RecoveryState>` so the caller has a uniform interface.
fn recovery_state_for(db_path: &str) -> Arc<RecoveryState> {
    if db_path == ":memory:" {
        return RecoveryState::new();
    }
    let key = registry_key(db_path);
    let mut registry = recovery_registry().lock();
    if let Some(weak) = registry.get(&key) {
        if let Some(existing) = weak.upgrade() {
            return existing;
        }
        // Weak is dead (last Arc dropped). Fall through to mint fresh state.
    }
    let state = RecoveryState::new();
    registry.insert(key, Arc::downgrade(&state));
    state
}

/// Build a [`SquashMeta`] by reading `marf_squash_levels` and
/// `marf_retired_squash_levels` from SQLite and parsing each level's
/// trailer from the blob file.
///
/// Loads each level's trailer + parallel-array metadata from `marf_squash_levels`.
///
/// **B6.3 simplification.** Pre-B6.3 also loaded `marf_retired_squash_levels` and
/// produced an `is_retired` flag + ambiguous-block-id tracking for the shared-
/// ancestor case. With retired-row emission gone (`Replace` / `re_squash` were
/// deleted in B6.1), only active levels exist. The `ambiguous_block_ids` field
/// stays on `SquashMeta` (consumers still gate on it; an empty set yields the
/// correct fast-path behavior) but is unconditionally empty here.
///
/// Returns an empty `SquashMeta` if no squash levels have been recorded
/// or if all present levels are stubs (blob_length == 0) with no
/// trailers.
pub(crate) fn build_squash_meta_from_sql(
    db: &Connection,
    blobs: Option<&TrieFile>,
) -> Result<SquashMeta, Error> {
    let squash_level_rows = trie_sql::read_squash_levels(db)?;
    if squash_level_rows.is_empty() {
        return Ok(SquashMeta::empty());
    }

    let total_levels = squash_level_rows.len();
    let mut levels = Vec::with_capacity(total_levels);
    let mut block_index = HashMap::new();
    let mut leaf_hash_omitted = HashSet::new();
    let mut root_sidecar_present = Vec::with_capacity(total_levels);
    let mut root_sidecar_trimmed = Vec::with_capacity(total_levels);
    let mut orphan_split_offset = Vec::with_capacity(total_levels);
    let mut level_blob_offsets = Vec::with_capacity(total_levels);
    let mut level_block_id_to_height: Vec<HashMap<u32, u32>> = Vec::with_capacity(total_levels);
    let mut level_reads_redirected = Vec::with_capacity(total_levels);
    let mut level_history_blob_state = Vec::with_capacity(total_levels);
    let mut level_min_heights = Vec::with_capacity(total_levels);
    let mut level_max_heights = Vec::with_capacity(total_levels);

    for row in &squash_level_rows {
        let trailer_opt = if row.blob_length == 0 {
            None
        } else {
            blobs
                .map(|b| read_level_trailer(b, row.blob_offset, row.blob_length))
                .transpose()?
        };
        let trailer = trailer_opt.unwrap_or_else(SquashTrailer::empty);

        let level_idx = levels.len();
        let mut per_level_block_ids: HashMap<u32, u32> = HashMap::new();
        if row.blob_length > 0 {
            for &(bhh, height, block_id) in &trailer.sorted_block_entries {
                block_index.insert(
                    bhh,
                    (
                        level_idx,
                        height,
                        row.blob_offset,
                        row.reads_redirected,
                        block_id,
                    ),
                );
                per_level_block_ids.insert(block_id, height);
                if row.reads_redirected {
                    leaf_hash_omitted.insert(block_id);
                }
            }
        }
        levels.push(trailer);
        root_sidecar_present.push(row.root_sidecar_present);
        root_sidecar_trimmed.push(row.root_sidecar_trimmed);
        orphan_split_offset.push(row.orphan_split_offset);
        level_blob_offsets.push(row.blob_offset);
        level_block_id_to_height.push(per_level_block_ids);
        level_reads_redirected.push(row.reads_redirected);
        level_history_blob_state.push(row.history_blob_state);
        level_min_heights.push(row.min_height);
        level_max_heights.push(row.max_height);
    }

    Ok(SquashMeta {
        levels,
        block_index,
        leaf_hash_omitted_blocks: leaf_hash_omitted,
        root_sidecar_present,
        root_sidecar_trimmed,
        orphan_split_offset,
        level_blob_offsets,
        level_block_id_to_height,
        level_reads_redirected,
        ambiguous_block_ids: HashSet::new(),
        level_history_blob_state,
        level_min_heights,
        level_max_heights,
        history_blob_readers: std::sync::Mutex::new(HashMap::new()),
    })
}

/// Parse a squash trailer from disk for a level whose `(blob_offset,
/// blob_length)` describe a non-stub on-disk extent. Used by
/// [`build_squash_meta_from_sql`] for each `marf_squash_levels` row.
/// (Pre-B6.3 also called for `marf_retired_squash_levels` rows; that
/// table is no longer read at runtime.)
fn read_level_trailer(
    blobs: &TrieFile,
    blob_offset: u64,
    blob_length: u64,
) -> Result<SquashTrailer, Error> {
    let footer_offset = blob_offset + blob_length
        - crate::chainstate::stacks::index::squash::SQUASH_FOOTER_SIZE as u64;
    let footer_bytes = blobs.read_blob_range(footer_offset, 12)?;
    let trailer_rel_offset = SquashTrailer::read_footer(&footer_bytes).ok_or_else(|| {
        Error::CorruptionError("Squash level blob has no valid trailer footer".into())
    })?;

    let trailer_abs_offset = blob_offset + trailer_rel_offset;
    let trailer_length = blob_offset + blob_length - trailer_abs_offset;
    let trailer_bytes = blobs.read_blob_range(trailer_abs_offset, trailer_length)?;
    SquashTrailer::read_from(&trailer_bytes, trailer_abs_offset)
}

/// TrieStorageTransientData holds all the data that _isn't_ committed to the underlying SQL
/// storage.
///
/// Used internally to simplify the TrieStorageConnection/TrieFileStorage interactions
pub struct TrieStorageTransientData<T: MarfTrieId> {
    /// This is all the nodes written but not yet committed to disk.
    pub uncommitted_writes: Option<(T, UncommittedState<T>)>,

    /// Currently-open block (may be `uncommitted_writes.unwrap().0`)
    pub(crate) cur_block: T,
    /// Tracks the `row_id` for `cur_block`.
    ///
    /// If `cur_block == uncommitted_writes`, this value should always be `None`.
    cur_block_id: Option<u32>,

    /// Runtime statistics on reading nodes
    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    /// Runtime statistics on writing nodes
    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    /// List of ancestral trie root hashes that must be hashed with the `uncommitted_writes` root
    /// node hash to produce the [`MarfTrieId`] for the trie when it gets written to disk.
    ///
    /// This is maintained by the MARF whenever it needs to update the trie root hash after a leaf
    /// insert, so that a batch of leaf inserts into `uncommitted_writes` don't require an ancestor
    /// trie hash query more than once.
    trie_ancestor_hash_bytes_cache: Option<(T, Vec<TrieHash>)>,

    /// Is the trie opened read-only?
    readonly: bool,

    /// Does this trie represent unconfirmed state?
    unconfirmed: bool,

    /// row ID of a trie that represents unconfirmed state (i.e. trie state that will never become
    /// part of the MARF, but nevertheless represents a persistent scratch space).
    ///
    /// If this field is `Some(..)`, then the storage was used to (re-)open an unconfirmed trie (via
    /// `open_unconfirmed()` or `open_block()` when `self.unconfirmed` is `true`), or used to create
    /// an unconfirmed trie (via `extend_to_unconfirmed_block()`).
    unconfirmed_block_id: Option<u32>,

    /// Cached external blob file offset for `cur_block_id`.
    ///
    /// Populated when a committed block is opened, so that hot-path reads for the current block can
    /// bypass the `RefCell<HashMap>` offset cache in `TrieFile`.
    pub(crate) cur_block_trie_offset: Option<u64>,

    /// Local snapshot of squash metadata, refreshed on-demand from
    /// `shared_squash` whenever `seen_squash_generation` falls behind
    /// `shared_squash.generation()`. Kept as an owned `Arc` so all existing
    /// access patterns (`data.squash_meta.block_index.get(...)`) work
    /// without taking a lock on every read.
    pub squash_meta: Arc<SquashMeta>,

    /// Shared source of truth for squash metadata across all handles
    /// spawned off the same MARF. Updated by writers via `publish`;
    /// readers observe via the generation counter.
    pub shared_squash: Arc<SharedSquashState>,

    /// Generation of the shared squash state that this handle's
    /// `squash_meta` snapshot was last synchronized with. When this falls
    /// behind `shared_squash.generation()`, the handle-local blob mmap,
    /// block cache, and current-block context are stale and must be
    /// invalidated before the next read.
    pub seen_squash_generation: u64,

    /// When a block within a squash range is opened, records the height for
    /// point-in-time value lookups via `TrieLeafSquashed::value_at_height()`.
    pub squash_opened_height: Option<u32>,

    /// Index into `squash_levels` for the currently-opened block's squash level.
    /// Set alongside `squash_opened_height` in the `open_block_impl` fast path;
    /// used by `read_node_hash` for O(1) trailer lookup instead of scanning.
    pub squash_opened_level_idx: Option<usize>,

    /// True when the currently-opened block reads from a squash blob where
    /// leaf nodes are stored without a 32-byte hash prefix. This is only set when
    /// `reads_redirected` is true for the squash level (i.e. the marf_data rows
    /// point to the squash blob, not original per-block blobs).
    pub leaf_hashes_omitted: bool,

    /// PR2 read-path overlay for the currently-opened squashed level: a
    /// long-lived positional-read handle to that level's orphan-section
    /// sidecar bytes. Populated in `open_block_impl` whenever the opened
    /// block lives in a squashed level whose `orphan_split_offset > 0`
    /// and whose sidecar isn't trimmed; `None` otherwise (no orphans, no
    /// sidecar, or trimmed). When `Some`, reads of `TriePtr.ptr() >=
    /// handle.split_offset` route into the sidecar via `pread_at` instead
    /// of into the merged blob — which after PR2 no longer contains
    /// those bytes.
    pub orphan_sidecar: Option<crate::chainstate::stacks::index::sidecar::OrphanSidecarHandle>,

    /// Reusable scratch buffer for orphan-sidecar reads. The merged-blob
    /// slow path borrows from `NodeDecodeScratch::take_node_bytes`; the
    /// orphan path mirrors that pattern by drawing from this storage-
    /// scoped buffer instead of allocating a fresh `Vec` per call. Empty
    /// at default, grown on demand to the largest orphan-record size
    /// observed on this connection. Cleared (capacity preserved) when
    /// returned by [`Self::orphan_scratch_restore`].
    pub orphan_read_scratch: Vec<u8>,

    /// Configured retention window for squash-root snapshot sidecars, in
    /// **Stacks blocks**. Resolved at handle-open time via
    /// [`crate::chainstate::stacks::index::squash::resolve_retention_blocks`]
    /// from `MARFOpenOpts`'s `squash_root_snapshot_retention_blocks`
    /// (preferred) or legacy `squash_root_snapshot_retention_levels`
    /// (converted via the legacy global cadence constant). Drives the
    /// `Error::SnapshotTrimmed` policy reported by the read path: callers
    /// attempting to fork-extend off a trimmed level see this value
    /// embedded in the error, so they can distinguish "policy-trimmed;
    /// re-sync to recover" from generic corruption. Defaults to
    /// [`crate::chainstate::stacks::index::squash::MARF_ROOT_SNAPSHOT_RETENTION_BLOCKS`]
    /// for handles built via [`Self::new`] / `Self::default`.
    pub squash_root_snapshot_retention_blocks: u32,

    /// Memoized result of `compute_snapshot_context_via_parent_chain`, keyed by the
    /// resolved block's id. The parent-chain walk is lazy — it only runs when
    /// `snapshot_height_for_block()` is called from a `LeafSquashed` resolution in
    /// the marf walk, or when a committed non-squash descendant follows an
    /// **ambiguous** backptr (target id present in multiple squash levels).
    ///
    /// Stored as `(block_id, walk_result)`. The cache deliberately survives
    /// `set_block` (cache key is `block_id`, not `cur_block_id`), so repeated
    /// reads of the same descendant — and multi-call read paths within a single
    /// user query — avoid re-walking. Only `squash_meta` replacement
    /// (`refresh_squash_state` / `refresh_after_squash`) invalidates it, since
    /// that's the only event that can change which level a `block_id` resolves
    /// into.
    ///
    /// Inner walk result: `Some((level_idx, h))` = squashed ancestor in `level_idx` at height
    /// `h`; `None` = sentinel/cap-exhaustion/pruned-ancestor.
    pub resolved_snapshot_context: Cell<Option<(u32, Option<(usize, u32)>)>>,

    /// **Experimental — for squash-internal read-only handles only.**
    ///
    /// When `true`, all `BlobReadGuard` acquisitions in the read pipeline are
    /// skipped (and the zero-copy mmap fast path is bypassed in favor of the
    /// scratch-decode slow path, which doesn't return mmap-borrowed bytes).
    /// This eliminates atomic contention on `shared_squash.active_reads` —
    /// the per-read fetch_add/fetch_sub pair that bounces a single cache line
    /// between worker cores during heavy parallel reads.
    ///
    /// **Safety**: only safe to set on read-only MARF handles created inside
    /// `squash_level_incremental` for its own pre-publish read phases
    /// (`collect_history_parallel`, baseline lookups). During those phases:
    ///   - The squash thread itself hasn't called `publish_squash` yet, so no
    ///     `ftruncate` / `remap_and_invalidate` can fire on this MARF.
    ///   - `squash_level_incremental` is single-threaded per MARF (no other
    ///     squash on this MARF can run concurrently).
    /// Both guard purposes (SIGBUS protection from concurrent truncate, and
    /// staleness detection from a mid-walk publish) are therefore moot.
    ///
    /// Setting this on any external handle (RPC reader, chainstate read, etc.)
    /// would expose the handle to SIGBUS or stale-state reads and is unsafe.
    pub bypass_blob_guard: bool,

    /// Read-path intent: controls whether `ROOT_PTR_DISK` reads against blocks inside a
    /// reclaim-squash level route through the per-height root sidecar
    /// ([`WalkIntent::ForkExtend`]) or through the merged tip's root + `value_at_height`
    /// ([`WalkIntent::AtBlock`], the default). See the [`WalkIntent`] doc for the contract;
    /// note that orphan-section reads are not gated by this field.
    ///
    /// `AtBlock` is the default for ordinary `MARF::get(historical_block, key)` style walks
    /// — these must not depend on the sidecar's per-height root so retention-trimmed levels
    /// remain readable for value lookups. `ForkExtend` is set transiently by
    /// [`crate::chainstate::stacks::index::marf::MARF::root_copy`] (and only there) so
    /// that the historical root shape is reconstructed from the sidecar; trimmed levels
    /// surface [`Error::SnapshotTrimmed`] as documented.
    pub walk_intent: WalkIntent,

    /// Perf-shape counter: number of `LeafSquashed` reads where snapshot-height resolved
    /// to `None` and the walk used `tip_value` directly (no `entries` materialization, no
    /// node re-read). Asserted in tests to prove the dormant-tip-read fast path works.
    #[cfg(test)]
    pub squashed_tip_fallback_count: Cell<u64>,

    /// Perf-shape counter: number of `LeafSquashed` reads where snapshot-height resolved
    /// to `Some(h)` and the walk re-read the leaf node to look up `entries[h]`. Asserted
    /// in tests to prove the historical/fork path still exercises the value-at-height
    /// lookup correctly.
    #[cfg(test)]
    pub squashed_entries_reread_count: Cell<u64>,

    /// Sum of `marf_data.external_length` for confirmed commits since the
    /// latest squash level published. Backs the per-MARF squash-work counter
    /// surfaced through `MARF::stats`. Reconstructed at handle-open time and
    /// after [`Self::sync_after_published_squash`] / [`Self::refresh_after_squash`]
    /// from `marf_data WHERE block_id > MAX(published_max_block_id) AND unconfirmed = 0`.
    /// Mutated incrementally in `inner_flush` for `CurrentHeader` / `NewHeader` writes
    /// (the only `FlushOptions` variants that produce confirmed `marf_data` rows).
    /// Reset to 0 by [`MARF::squash`] / [`MARF::re_squash`] after a successful publish.
    pub external_bytes_since_last_squash: u64,
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage<T: MarfTrieId> {
    pub db_path: String,

    db: Connection,
    pub(crate) blobs: Option<TrieFile>,
    pub(crate) data: TrieStorageTransientData<T>,
    cache: BlockCache<T>,
    bench: TrieBenchmark,
    hash_calculation_mode: TrieHashCalculationMode,
    compress: bool,
    mmap: bool,

    /// Process-wide recovery state for `db_path`. Held to keep the live count alive in
    /// [`recovery_registry`]; the `rw_recovery_done` flag inside coordinates RW recovery across
    /// concurrent openers (preventing the multi-handle race that would truncate the writer's
    /// in-flight bytes). Dropped when this storage instance is dropped.
    _recovery_state: Arc<RecoveryState>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<T>,
}

/// Helper to open a MARF
fn marf_sqlite_open<P: AsRef<Path>>(
    db_path: P,
    open_flags: OpenFlags,
    foreign_keys: bool,
) -> Result<Connection, db_error> {
    let db = sqlite_open(db_path, open_flags, foreign_keys)?;
    sql_pragma(&db, "mmap_size", &SQLITE_MMAP_SIZE)?;
    sql_pragma(&db, "page_size", &SQLITE_MARF_PAGE_SIZE)?;
    Ok(db)
}

impl<T: MarfTrieId> Default for TrieStorageTransientData<T> {
    fn default() -> Self {
        Self {
            uncommitted_writes: None,
            cur_block: T::sentinel(),
            cur_block_id: None,
            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,
            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,
            trie_ancestor_hash_bytes_cache: None,
            readonly: false,
            unconfirmed: false,
            unconfirmed_block_id: None,
            cur_block_trie_offset: None,
            squash_meta: Arc::new(SquashMeta::empty()),
            shared_squash: SharedSquashState::empty(),
            seen_squash_generation: 0,
            squash_opened_height: None,
            squash_opened_level_idx: None,
            leaf_hashes_omitted: false,
            orphan_sidecar: None,
            orphan_read_scratch: Vec::new(),
            squash_root_snapshot_retention_blocks:
                crate::chainstate::stacks::index::squash::MARF_ROOT_SNAPSHOT_RETENTION_BLOCKS,
            resolved_snapshot_context: Cell::new(None),
            bypass_blob_guard: false,
            walk_intent: WalkIntent::AtBlock,
            #[cfg(test)]
            squashed_tip_fallback_count: Cell::new(0),
            #[cfg(test)]
            squashed_entries_reread_count: Cell::new(0),
            external_bytes_since_last_squash: 0,
        }
    }
}

impl<T: MarfTrieId> TrieStorageTransientData<T> {
    /// Construct transient data targeting a specific block, with the given read/write flags.
    /// All stat counters start at zero and caches start empty.
    pub fn new(cur_block: T, cur_block_id: Option<u32>, readonly: bool, unconfirmed: bool) -> Self {
        Self {
            cur_block,
            cur_block_id,
            readonly,
            unconfirmed,
            ..Self::default()
        }
    }

    /// Target the transient data to a particular block, and optionally its block ID.
    ///
    /// Clears the cached trie offset (it will be re-populated on first read).
    ///
    /// Note: `resolved_snapshot_context` is **not** cleared here. The cache is
    /// keyed by block_id and remains valid as long as `squash_meta` itself has
    /// not been replaced — invalidation is tied to squash-meta refreshes
    /// (`refresh_squash_state` / `refresh_after_squash`), not per-block
    /// transitions. Keeping it across `set_block` lets repeated reads of the
    /// same descendant block (and multi-call read paths within a single user
    /// query) avoid re-walking the parent chain.
    fn set_block(&mut self, bhh: T, id: Option<u32>) {
        trace!("set_block({},{:?})", &bhh, &id);
        self.cur_block_id = id;
        self.cur_block = bhh;
        self.cur_block_trie_offset = None;
        self.squash_opened_height = None;
        self.squash_opened_level_idx = None;
        self.leaf_hashes_omitted = false;
        // Drop the orphan-sidecar handle; the next `open_block_impl` will
        // populate a fresh one if the new block lives in a level that has
        // an orphan section.
        self.orphan_sidecar = None;
    }

    fn clear_block_id(&mut self) {
        self.cur_block_id = None;
    }

    pub fn set_ancestor_hashes_bytes(&mut self, bhh: &T, bytes: Vec<TrieHash>) {
        self.trie_ancestor_hash_bytes_cache = Some((bhh.clone(), bytes));
    }

    pub fn get_ancestor_hashes_bytes(&self, bhh: &T) -> Option<Vec<TrieHash>> {
        if let Some((ref cached_bhh, ref cached_bytes)) = self.trie_ancestor_hash_bytes_cache {
            if cached_bhh == bhh {
                return Some(cached_bytes.clone());
            }
        }
        None
    }

    pub fn clear_ancestor_hashes_bytes(&mut self) {
        self.trie_ancestor_hash_bytes_cache = None;
    }
}

pub struct ReopenedTrieStorageConnection<'a, T: MarfTrieId> {
    pub db_path: &'a str,
    db: &'a Connection,
    blobs: Option<TrieFile>,
    data: TrieStorageTransientData<T>,
    cache: BlockCache<T>,
    bench: TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,
    compress: bool,
    mmap: bool,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<T>,
}

impl<'a, T: MarfTrieId> ReopenedTrieStorageConnection<'a, T> {
    pub fn db_conn(&self) -> &Connection {
        self.db
    }

    pub fn readonly(&self) -> bool {
        self.data.readonly
    }

    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    pub fn connection(&mut self) -> TrieStorageConnection<'_, T> {
        // Guards are now acquired per-read inside the storage layer (see
        // `read_node_with_state` and siblings) rather than held for the connection's
        // lifetime. Between reads, no guard is held — letting a concurrent squash
        // writer enter its drain-and-truncate window promptly. Mid-traversal
        // publishes surface as `Error::RetryAfterSquash`, which the top-level retry
        // wrappers absorb.
        TrieStorageConnection {
            db: &self.db,
            db_path: self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            compress: self.compress,
            mmap: self.mmap,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        }
    }
}

#[cfg(test)]
impl<T: MarfTrieId> ReopenedTrieStorageConnection<'_, T> {
    pub fn read_node<'b>(
        &'b mut self,
        ptr: &TriePtr,
        scratch: &'b mut impl NodePatching,
    ) -> Result<ReadTrieNode<'b>, Error> {
        let block_id = self.data.cur_block_id.ok_or(Error::NotFoundError)?;
        let patch_source_context = patch_source_context_for_open_block(
            &self.data,
            self.db,
            self.blobs.as_ref(),
            &self.data.cur_block,
            block_id,
        );
        read_patched_persisted_node(
            self.db,
            self.db_path,
            self.blobs.as_ref(),
            self.data.unconfirmed_block_id,
            block_id,
            ptr.from_backptr(),
            self.data.cur_block_trie_offset,
            self.data.leaf_hashes_omitted,
            patch_source_context,
            &self.data.squash_meta,
            self.data.squash_root_snapshot_retention_blocks,
            scratch,
        )
    }
}

/// Rebuild squash metadata, remap the blob file mmap, and reset per-connection
/// caches after an external squash has modified the `.blobs` file and
/// `marf_squash_levels` table via a different handle.
///
/// Factored out so that both the explicit [`TrieFileStorage::refresh_after_squash`]
/// entry point and the automatic staleness recovery in [`open_block_impl`]
/// can share the same logic.
///
/// Reader-side staleness recovery: check the shared generation counter and,
/// if a writer has published a new [`SquashMeta`] since this handle last
/// synced, re-snapshot the shared metadata and invalidate the handle-local
/// blob mmap, block cache, and current-block context.
///
/// No SQL, no trailer parsing — those were already done by the publishing
/// writer. This path is a single atomic load in the fast case (unchanged
/// generation) and a short critical section in the slow case.
/// Sync this handle's local squash state to the shared snapshot when a
/// writer has bumped the generation. Invoked by the peer-handle read path
/// (`TrieStorageConnection::sync_shared_squash_state`) and by the writer's
/// post-publish path (`TrieFileStorage::sync_after_published_squash`).
///
/// All inputs come from the same `TrieFileStorage` / `TrieStorageConnection`
/// — the caller passes them split so this helper can be called from inside
/// `with_trie_blobs`-style closures that have already partial-borrowed.
///
/// Reconstructs the per-MARF squash-work counter from SQL when the
/// generation bumps. That's what keeps [`MARF::stats`] authoritative on
/// peer / reopened read-only handles after another handle publishes a
/// squash: without the resync, the peer's counter would still reflect the
/// pre-publish watermark and over-count rows that have just been absorbed.
fn sync_from_shared_squash_state<T: MarfTrieId>(
    data: &mut TrieStorageTransientData<T>,
    mut blobs: Option<&mut TrieFile>,
    cache: &mut BlockCache<T>,
    db: &Connection,
) -> Result<(), Error> {
    let current_gen = data.shared_squash.generation();
    if current_gen == data.seen_squash_generation {
        return Ok(());
    }

    // Snapshot the fresh metadata first; subsequent mutations are local-only.
    data.squash_meta = data.shared_squash.snapshot();

    // The blob file has been truncated/extended by the publishing writer, so any mmap region and
    // cached offsets we hold are stale.
    if let Some(b) = blobs.as_deref_mut() {
        b.remap_and_invalidate()?;
    }

    // The block cache may reference block_ids whose blobs moved.
    *cache = BlockCache::new("noop");

    // Force the next open_block() through a fresh resolve against the new squash metadata rather
    // than short-circuiting on the cached cur_block.
    data.set_block(T::sentinel(), None);
    data.trie_ancestor_hash_bytes_cache = None;
    // Cached level_idx values reference the *prior* squash_meta; replacing meta
    // can change which level a block_id resolves into.
    data.resolved_snapshot_context.set(None);

    // Resync the per-MARF squash-work counter to the just-published
    // watermark. Cheap (one indexed `SUM(external_length)` query) and
    // necessary for `MARF::stats()` to stay authoritative on peer /
    // reopened read-only handles after another handle publishes — without
    // it, the peer's counter would still reflect the old watermark and
    // include rows that have just been absorbed below the new one.
    data.external_bytes_since_last_squash = trie_sql::current_external_bytes_since_last_squash(db)?;

    data.seen_squash_generation = current_gen;
    Ok(())
}

/// Shared implementation for `TrieReadStorage::open_block`, used by both `TrieStorageConnection`
/// and `ReopenedTrieStorageConnection`.
///
/// `cache` is required because `get_block_id_caching` accesses `TrieCache<T>`, which lives on the
/// storage struct alongside (not inside) `TrieStorageTransientData`.
fn open_block_impl<T: MarfTrieId>(
    data: &mut TrieStorageTransientData<T>,
    db: &Connection,
    cache: &mut BlockCache<T>,
    bench: &mut TrieBenchmark,
    bhh: &T,
) -> Result<(), Error> {
    bench.open_block_start();

    if *bhh == data.cur_block && data.cur_block_id.is_some() {
        if data.unconfirmed
            && data.cur_block_id == trie_sql::get_unconfirmed_block_identifier(db, bhh)?
        {
            test_debug!(
                "{} unconfirmed trie block ID is {:?}",
                bhh,
                &data.cur_block_id
            );
            data.unconfirmed_block_id = data.cur_block_id;
        }
        bench.open_block_finish(true);
        return Ok(());
    }

    let sentinel = T::sentinel();
    if *bhh == sentinel {
        let block_id_opt = get_block_id_caching_impl(data.unconfirmed, cache, db, bhh).ok();
        data.set_block(sentinel, block_id_opt);
        bench.open_block_finish(true);
        return Ok(());
    }

    if let Some((ref uncommitted_bhh, ref uncommitted_state)) = data.uncommitted_writes {
        if uncommitted_bhh == bhh {
            if data.unconfirmed
                && data.cur_block_id == trie_sql::get_unconfirmed_block_identifier(db, bhh)?
            {
                test_debug!(
                    "{} unconfirmed trie block ID is {:?}",
                    bhh,
                    &data.cur_block_id
                );
                data.unconfirmed_block_id = data.cur_block_id;
            }

            // Snapshot-height propagation for sibling-fork reads.
            //
            // Without this, opening a freshly-begun sibling block whose canonical sibling has been
            // squashed leaves `squash_opened_height` as `None`. When the read pipeline later hits a
            // `LeafSquashed` (because the sibling's trie falls through to the squashed canonical
            // state), the absent height context drops it into the "tip read" branch in `marf::walk`
            // — which returns the canonical sibling's value instead of the parent's. That is the
            // exact bug Tier 10 documents and the production stall at block 11000 hit.
            //
            // Fix: if this uncommitted block's parent is in the squash, capture the parent's squash
            // height here so subsequent squashed-leaf lookups via `value_at_height` resolve to the
            // parent's view (the fork point) rather than the canonical sibling's tip value.
            //
            // For uncommitted blocks whose parent is a late-arriving committed-non-squash block
            // that itself extends a squashed ancestor, the lazy fallback in `marf::walk` calls
            // `snapshot_height_for_uncommitted_parent`, which walks the parent's blob-header chain
            // on-demand (only when a `LeafSquashed` is hit). That keeps the begin/open hot path
            // free of an unconditional 64-step parent walk for canonical chains far past the last
            // squash, where the walk is wasted work (canonical reads correctly use tip-read).
            let parent_bhh = uncommitted_state.trie_ram_ref().parent.clone();
            let parent_key: [u8; 32] = parent_bhh
                .as_bytes()
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
            let parent_squash_entry = data.squash_meta.block_index.get(&parent_key).copied();

            data.set_block(bhh.clone(), None);

            if let Some((level_idx, parent_height, _, reads_redirected, _)) = parent_squash_entry {
                data.squash_opened_height = Some(parent_height);
                data.squash_opened_level_idx = Some(level_idx);
                data.leaf_hashes_omitted = reads_redirected;
            }

            bench.open_block_finish(true);
            return Ok(());
        }
    }

    if data.unconfirmed {
        if let Some(block_id) = trie_sql::get_unconfirmed_block_identifier(db, bhh)? {
            data.set_block(bhh.clone(), Some(block_id));
            bench.open_block_finish(false);
            test_debug!("{} unconfirmed trie block ID is {}", bhh, block_id);
            data.unconfirmed_block_id = Some(block_id);
            return Ok(());
        }
    }

    // Squash-aware fast path: if this block is in a squash level, record the opened height and
    // level index so that root-hash lookups can consult the squash trailer via O(1) index.
    //
    // When `reads_redirected` is true, marf_data has been redirected to the squash blob
    // (originals truncated), so we seed `cur_block_trie_offset` for fast offset resolution.
    // When false (append-only squash), marf_data still points to the original per-block blobs.
    let bhh_key: [u8; 32] = bhh
        .as_bytes()
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 32]);
    if let Some(&(level_idx, height, squash_blob_offset, reads_redirected, block_id)) =
        data.squash_meta.block_index.get(&bhh_key)
    {
        data.set_block(bhh.clone(), Some(block_id));
        data.squash_opened_height = Some(height);
        data.squash_opened_level_idx = Some(level_idx);
        data.leaf_hashes_omitted = reads_redirected;

        // * For reclaimed levels, marf_data rows point to the squash blob — seed the trie-offset
        // hint so reads skip the offset cache/SQL lookup.
        // * For append-only squash, leave it None so reads go through the original per-block blobs.
        if reads_redirected {
            data.cur_block_trie_offset = Some(squash_blob_offset);
        }

        bench.open_block_finish(false);
        return Ok(());
    }

    let block_id = get_block_id_caching_impl(data.unconfirmed, cache, db, bhh).map_err(|e| {
        test_debug!("Failed to open {:?}: {:?}", bhh, e);
        e
    })?;

    data.set_block(bhh.clone(), Some(block_id));

    // Snapshot-context propagation for committed non-squash blocks is deferred to
    // `snapshot_height_for_block()` / backptr resolution. Walking the parent chain here on every committed open would
    // add up to `MAX_PARENT_CHAIN_DEPTH` SQL/blob-header lookups per open — catastrophic
    // for canonical chains extended many blocks past the last squash, which are the vast
    // majority of opens. The lazy resolver caches per user_block_id in
    // `data.resolved_snapshot_context`, so the walk fires at most once per user-level open
    // and only when a squashed leaf or inherited squash-level backptr is actually reached.

    bench.open_block_finish(false);
    Ok(())
}

/// Walk a block's parent chain — reading the exact parent block hash from each per-block
/// trie blob's header, NOT inferring it from root-node backptrs (which can point to older
/// ancestors past COW chains and would mis-classify the snapshot height).
///
/// Each iteration:
/// 1. Check whether the current block is in the squash. If yes, return its squash height —
///    `value_at_height(height)` against this height returns the parent's view of the keys,
///    which is exactly what a non-canonical descendant should consult.
/// 2. Otherwise, read 32 bytes at the start of this block's trie blob — that's the parent
///    block hash captured at commit time (see `TrieRAM::dump` and `TrieRAM::load`).
/// 3. If the parent is the chain sentinel, the chain has no squashed ancestor — return
///    `None` (caller falls through to the "no height context" branch).
/// 4. Otherwise look up the parent's `block_id` and continue with the parent.
///
/// Returns only the snapshot height. The caller must not propagate the squash level index
/// or `reads_redirected` flag — those are properties of an in-squash block's own blob (the
/// merged squash blob with omitted leaf hashes), not of a fork descendant whose own blob is
/// a regular per-block blob with hashes.
///
/// **Bounded by `MAX_PARENT_CHAIN_DEPTH`** (a generous cap relative to realistic Bitcoin
/// reorg depths — Bitcoin's deepest historical reorg was 6 blocks). On exhaustion we
/// return `None` and emit a `debug!` trace; correctness is preserved because `None` falls
/// through to the tip-read branch — *correct* for canonical descendants extended far past
/// the last squash (the common reason for exhaustion), and the best we can do for
/// pathological deep forks. Hence `debug!`, not `warn!`: warning here would be operator
/// noise on long-canonical-chain reads.
///
/// **Pruned-ancestor caveat:** if a non-canonical ancestor was already reclaimed by a
/// previous squash (its `external_offset`/`external_length` zeroed by
/// `prune_orphaned_external_refs`), we cannot read its blob header and the walk halts at
/// `None`. This is the pre-existing limitation of the reclaim path and the durable fix is
/// `marf_data.parent_block_hash` going forward; this helper degrades gracefully rather
/// than panicking.
const MAX_PARENT_CHAIN_DEPTH: u32 = 64;

fn compute_snapshot_context_via_parent_chain<T: MarfTrieId>(
    data: &TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    start_block_hash: &T,
    start_block_id: u32,
) -> Option<(usize, u32)> {
    // Fast path: no squash exists, so there's no squashed ancestor to find.
    // Without this guard, every committed `open_block` would walk up to
    // `MAX_PARENT_CHAIN_DEPTH` blob headers + SQL lookups before bailing — a hot-path
    // disaster for the (overwhelmingly common) no-squash case.
    if data.squash_meta.block_index.is_empty() {
        return None;
    }

    let blobs = blobs?;
    let sentinel = T::sentinel();
    let mut current_hash: T = start_block_hash.clone();
    let mut current_id: u32 = start_block_id;

    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        // 1. In-squash check.
        let key: [u8; 32] = current_hash
            .as_bytes()
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 32]);
        if let Some(&(level_idx, height, _, _reads_redirected, _)) =
            data.squash_meta.block_index.get(&key)
        {
            return Some((level_idx, height));
        }

        // 2. Read parent hash from the trie blob's header.
        // `debug!` (not `warn!`) on failure: a missing offset usually means a pruned
        // non-canonical ancestor (benign; caller falls back to tip-read which is already
        // the correct answer for canonical descendants), so spamming warnings would be noise.
        // v1.5: route via storage location so hot-row offsets resolve
        // against the right hot file rather than the cold blob fd.
        let location = match trie_sql::get_trie_storage_location(db, current_id) {
            Ok(loc) => loc,
            Err(e) => {
                debug!(
                    "compute_snapshot_height: cannot read storage location for \
                     block_id={current_id} ({current_hash}) — likely a pruned non-canonical \
                     ancestor. Falling back to tip-read. Error: {e}"
                );
                return None;
            }
        };
        let trie_offset = location.offset;
        let parent_hash_bytes =
            match blobs.read_parent_hash_at(location.kind, location.seq, trie_offset) {
                Ok(b) => b,
                Err(e) => {
                    debug!(
                        "compute_snapshot_height: blob header read failed at \
                         block_id={current_id} offset={trie_offset} (kind={:?}, seq={}): {e}",
                        location.kind, location.seq
                    );
                    return None;
                }
            };
        let parent_hash: T = T::from_bytes(parent_hash_bytes);

        // 3. Sentinel parent ⇒ end of chain, no squashed ancestor.
        if parent_hash == sentinel {
            return None;
        }

        // 4. Resolve parent's block_id for the next iteration.
        let parent_id = match trie_sql::get_block_identifier(db, &parent_hash) {
            Ok(id) => id,
            Err(e) => {
                debug!(
                    "compute_snapshot_height: parent {parent_hash} not in marf_data \
                     (looked up from block_id={current_id}'s blob header): {e}"
                );
                return None;
            }
        };
        current_hash = parent_hash;
        current_id = parent_id;
    }

    // `debug!` (not `warn!`): cap exhaustion is expected and correct for canonical chains
    // extended far past the last squash (tip-read is the right answer for those). It's only
    // incorrect for pathological deep forks, which are rare enough that a debug trace is
    // sufficient — a `warn!` here would spam operator logs on every read of a long-canonical
    // block whose key hits a `LeafSquashed`.
    debug!(
        "compute_snapshot_height: exceeded MAX_PARENT_CHAIN_DEPTH ({MAX_PARENT_CHAIN_DEPTH}) \
         walking from block_id={start_block_id} ({start_block_hash}); falling back to tip-read"
    );
    None
}

fn snapshot_context_for_block<T: MarfTrieId>(
    data: &TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    block_hash: &T,
    block_id: u32,
) -> Option<(usize, u32)> {
    if data.squash_meta.block_index.is_empty() {
        return None;
    }
    if let Some((cached_id, cached_result)) = data.resolved_snapshot_context.get() {
        if cached_id == block_id {
            return cached_result;
        }
    }
    let resolved = compute_snapshot_context_via_parent_chain(data, db, blobs, block_hash, block_id);
    data.resolved_snapshot_context
        .set(Some((block_id, resolved)));
    resolved
}

fn patch_source_context_for_open_block<T: MarfTrieId>(
    data: &TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    block_hash: &T,
    block_id: u32,
) -> Option<(usize, u32)> {
    data.squash_opened_level_idx
        .zip(data.squash_opened_height)
        .or_else(|| {
            if data.squash_meta.ambiguous_block_ids.is_empty() {
                return None;
            }
            snapshot_context_for_block(data, db, blobs, block_hash, block_id)
        })
}

fn patch_source_context_for_block_hash<T: MarfTrieId>(
    data: &TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    block_hash: &T,
) -> Option<(usize, u32)> {
    let block_key: [u8; 32] = block_hash
        .as_bytes()
        .get(..32)
        .and_then(|s| s.try_into().ok())?;
    if let Some(&(level_idx, height, _, _, _)) = data.squash_meta.block_index.get(&block_key) {
        return Some((level_idx, height));
    }

    let block_id = trie_sql::get_block_identifier(db, block_hash).ok()?;
    snapshot_context_for_block(data, db, blobs, block_hash, block_id)
}

/// Shared implementation for `TrieReadStorage::open_block_known_id`, used by both
/// `TrieStorageConnection` and `ReopenedTrieStorageConnection`.
///
/// Panics if `bhh` matches the currently-being-built uncommitted block (programming error).
///
/// Restores squash context (opened height, level index, trie offset) when the block
/// lives in a squash level, mirroring the squash-aware path in `open_block_impl`.
fn open_block_known_id_impl<T: MarfTrieId>(
    data: &mut TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    bhh: &T,
    id: u32,
) -> Result<(), Error> {
    if *bhh == data.cur_block && data.cur_block_id.is_some() {
        return Ok(());
    }

    if let Some((ref uncommitted_bhh, _)) = data.uncommitted_writes {
        if uncommitted_bhh == bhh {
            panic!("BUG: passed id of a currently building block");
        }
    }

    // Capture the prior squash-level context BEFORE `set_block` resets it.
    // The retired-context-aware branch below needs to know which level the
    // *caller* is reading from; without this snapshot the level idx would
    // already be `None` by the time we test it.
    //
    // The parent-chain fallback walk is gated on `ambiguous_block_ids` because
    // it only changes the answer when the target id has dual+ membership across
    // squash levels (shared ancestors carried in both an active and a retired
    // level). For ids in zero or exactly one level the global `block_index`
    // resolution at the end of this function is already unambiguous, and
    // walking would just be wasted I/O. This collapses walk frequency from
    // "~1 per user-level read" to "only on retired-fork descendants reaching
    // a shared ancestor" — the actual case the fix exists for.
    let source_block = data.cur_block.clone();
    let source_block_id = data.cur_block_id;
    let prior_level_idx = data.squash_opened_level_idx.or_else(|| {
        if !data.squash_meta.ambiguous_block_ids.contains(&id) {
            return None;
        }
        source_block_id.and_then(|source_id| {
            snapshot_context_for_block(data, db, blobs, &source_block, source_id)
                .map(|(level_idx, _height)| level_idx)
        })
    });

    data.set_block(bhh.clone(), Some(id));

    // **Retired-context-aware backptr resolution.** When the read pipeline
    // is currently inside squash level `L` and follows a backptr whose
    // target `id` is also recorded in `L`'s trailer, stay in `L`. Each
    // squash level's merged-blob layout is independent — backptr offsets
    // baked into `L`'s nodes are self-relative to `L`'s blob, and routing
    // the target through the global `block_index` would land us in some
    // *other* level (typically the active level, which won the Replace-
    // time overwrite for shared ancestors) and apply `L`'s offset to the
    // wrong blob's bytes. The failure mode is silent corruption / wrong
    // leaf — it surfaced as a bounded-fork-test divergence where reads
    // from a retired blob returned `None` for keys whose leaf was
    // reachable through a backptr to a shared ancestor. Only when the
    // target `id` is **not** in `L`'s trailer (a real cross-level
    // backptr) do we fall through to the global `block_index`.
    if let Some(cur_level_idx) = prior_level_idx {
        if let Some(&target_height) = data
            .squash_meta
            .level_block_id_to_height
            .get(cur_level_idx)
            .and_then(|m| m.get(&id))
        {
            // Strict per-level lookups: the parallel vectors
            // (`level_blob_offsets`, `level_reads_redirected`) are sized
            // identically to `levels` by `build_squash_meta_from_sql`.
            // A missing entry here would mean `SquashMeta` is internally
            // inconsistent — surface that as a corruption error rather
            // than silently substituting offset 0 / `false`, which would
            // route a redirected read to the start of the file or apply
            // the wrong leaf-hash policy.
            let cur_level_blob_offset = *data
                .squash_meta
                .level_blob_offsets
                .get(cur_level_idx)
                .ok_or_else(|| {
                    Error::corruption(&format!(
                        "SquashMeta.level_blob_offsets missing entry for level_idx={cur_level_idx}"
                    ))
                })?;
            let cur_level_reads_redirected = *data
                .squash_meta
                .level_reads_redirected
                .get(cur_level_idx)
                .ok_or_else(|| {
                    Error::corruption(&format!(
                        "SquashMeta.level_reads_redirected missing entry for level_idx={cur_level_idx}"
                    ))
                })?;
            data.squash_opened_height = Some(target_height);
            data.squash_opened_level_idx = Some(cur_level_idx);
            data.leaf_hashes_omitted = cur_level_reads_redirected;
            if cur_level_reads_redirected {
                data.cur_block_trie_offset = Some(cur_level_blob_offset);
            }
            return Ok(());
        }
    }

    // Restore squash context so that root-hash lookups and trie reads use the
    // squash blob/trailer instead of the (possibly reclaimed) per-block blobs.
    let bhh_key: [u8; 32] = bhh
        .as_bytes()
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 32]);
    if let Some(&(level_idx, height, squash_blob_offset, reads_redirected, _block_id)) =
        data.squash_meta.block_index.get(&bhh_key)
    {
        data.squash_opened_height = Some(height);
        data.squash_opened_level_idx = Some(level_idx);
        data.leaf_hashes_omitted = reads_redirected;
        if reads_redirected {
            data.cur_block_trie_offset = Some(squash_blob_offset);
        }
    }
    // Committed non-squash blocks: parent-chain walk is deferred to
    // `squash_opened_height()` on the connection (lazy; see `open_block_impl`).

    Ok(())
}

/// Inner implementation of `BlockMap::get_block_id_caching` shared across storage types.
/// Extracted here so that `open_block_impl` can replicate caching behavior without
/// borrowing the full storage struct.
fn get_block_id_caching_impl<T: MarfTrieId>(
    unconfirmed: bool,
    cache: &mut BlockCache<T>,
    db: &Connection,
    block_hash: &T,
) -> Result<u32, Error> {
    if unconfirmed {
        trie_sql::get_block_identifier(db, block_hash)
    } else if let Some(id) = cache.load_block_id(block_hash) {
        Ok(id)
    } else {
        let id = trie_sql::get_block_identifier(db, block_hash)?;
        cache.store_block_hash(id, block_hash.clone());
        Ok(id)
    }
}

/// Resolve a level's orphan sidecar, validate it, and open a fresh
/// [`crate::chainstate::stacks::index::sidecar::OrphanSidecarHandle`]. Used by both:
/// - [`TrieStorageConnection::try_read_orphan_bytes`] (the connection-scoped path, where it
///   feeds the cached handle slot keyed on `split_offset`).
/// - [`read_patched_persisted_node`] (the patch-chase path, which opens fresh per orphan
///   step because chains can visit blocks across multiple levels in one call).
///
/// Returns `Err(Error::SnapshotTrimmed)` if the level's sidecar has been trimmed
/// (operator-recovery condition); returns generic `CorruptionError` for missing or malformed
/// sidecars. The handle's `split_offset` is set to the level's `orphan_split_offset` so the
/// caller can compute relative-offset reads via [`read_orphan_node_bytes_into`].
fn open_orphan_sidecar_for_level(
    db_path: &str,
    squash_meta: &SquashMeta,
    level_idx: usize,
    snapshot_retention_blocks: u32,
) -> Result<crate::chainstate::stacks::index::sidecar::OrphanSidecarHandle, Error> {
    use crate::chainstate::stacks::index::sidecar::{
        squash_root_sidecar_path, OrphanSidecarHandle, RecordKind, SidecarExpectation,
    };
    let level = squash_meta.levels.get(level_idx).ok_or_else(|| {
        Error::CorruptionError(format!(
            "open_orphan_sidecar_for_level: level_idx {level_idx} out of range \
             ({} levels)",
            squash_meta.levels.len(),
        ))
    })?;
    if squash_meta
        .root_sidecar_trimmed
        .get(level_idx)
        .copied()
        .unwrap_or(false)
    {
        return Err(Error::SnapshotTrimmed {
            level_id: level.info.level_id,
            retention_blocks: snapshot_retention_blocks,
        });
    }
    let split = squash_meta
        .orphan_split_offset
        .get(level_idx)
        .copied()
        .unwrap_or(0);
    if split == 0 {
        return Err(Error::CorruptionError(format!(
            "open_orphan_sidecar_for_level: level_idx {level_idx} has split_offset=0 \
             (no orphan section)"
        )));
    }
    let level_blob_offset = *squash_meta
        .level_blob_offsets
        .get(level_idx)
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "open_orphan_sidecar_for_level: level_idx {level_idx} missing blob_offset \
                     (level_blob_offsets has {})",
                squash_meta.level_blob_offsets.len(),
            ))
        })?;
    let path = squash_root_sidecar_path(
        std::path::Path::new(db_path),
        level.info.level_id,
        level.info.min_height,
        level.info.max_height,
        level_blob_offset,
    );
    let expectation = SidecarExpectation {
        level_id: Some(level.info.level_id),
        min_height: Some(level.info.min_height),
        max_height: Some(level.info.max_height),
        require_section: Some(RecordKind::OrphanNode),
    };
    OrphanSidecarHandle::open(&path, expectation, split)
}

/// Read trie-item bytes from an orphan sidecar via a pre-opened handle, with the same
/// two-phase size resolution [`TrieFile::read_item_at_offset`]'s slow path uses on the
/// merged blob:
/// 1. pread `hinted_max` bytes (from the parent `ptr`'s type hint).
/// 2. peek at the first byte for the actual stored node ID; if its max body is wider, pread
///    again at the wider size into the resized buffer.
///
/// `buf` is filled in-place; on success the bytes are at `&buf[..]` (length matches the
/// stored item). The caller's allocation is reused across both pread attempts (resize-up
/// only), so a pooled scratch buffer can be threaded through without reallocating per call.
///
/// Concurrency: the handle's `pread` is lock-free, but callers reading against an actively-
/// publishing MARF must hold a `BlobReadGuard` for the duration of the decode that follows.
/// This helper does NOT acquire a guard; it expects the caller's broader read path to.
fn read_orphan_node_bytes_into(
    handle: &crate::chainstate::stacks::index::sidecar::OrphanSidecarHandle,
    ptr: &TriePtr,
    leaf_hashes_omitted: bool,
    buf: &mut Vec<u8>,
) -> Result<(), Error> {
    let is_leaf_hint = leaf_hashes_omitted && is_leaf_type(ptr.id());
    let hinted_max = if is_leaf_hint {
        bits::get_node_body_max_byte_len(ptr.id())?
    } else {
        bits::get_node_max_byte_len(ptr.id())?
    };
    let relative = (ptr.ptr() - handle.split_offset) as u64;

    buf.clear();
    buf.resize(hinted_max, 0);
    let n = handle.pread_at(buf, relative)?;
    if n == 0 {
        return Err(Error::CorruptionError(format!(
            "read_orphan_node_bytes_into: pread at relative_offset={relative} returned 0 \
             bytes (split_offset={}, ptr.ptr()={}, section_length={})",
            handle.split_offset,
            ptr.ptr(),
            handle.section_length(),
        )));
    }
    buf.truncate(n);

    let stored_max = if is_leaf_hint {
        let stored_node_id = bits::stored_node_id_from_bytes(buf)?;
        bits::get_node_body_max_byte_len(stored_node_id as u8)?
    } else {
        let (_hash, after_hash) = bits::parse_hash_from_bytes(buf)?;
        let stored_node_id = bits::stored_node_id_from_bytes(after_hash)?;
        bits::get_node_max_byte_len(stored_node_id as u8)?
    };
    if stored_max > buf.len() {
        buf.resize(stored_max, 0);
        let n = handle.pread_at(buf, relative)?;
        buf.truncate(n);
    }
    Ok(())
}

/// Resolve the level index that owns `block_id` for a patch-chase step, using the same
/// disambiguation rules `read_patched_persisted_node`'s merged-blob path uses for trie offset
/// + leaf-hash policy:
///
/// 1. **Source-level preference**: if `patch_source_context` is `Some((src_idx, _))` and
///    level `src_idx`'s trailer contains `block_id`, return `src_idx`. This handles the
///    common case where the patch chain stays inside the level the read started in, and
///    matches `open_block_known_id_impl`'s retired-context-aware backptr resolution
///    contract: "when the read pipeline is currently inside squash level `L` and follows a
///    backptr whose target id is also recorded in `L`'s trailer, stay in `L`."
/// 2. **Global scan, gated on unambiguous block IDs**: if step 1 didn't match AND
///    `block_id` is NOT in `squash_meta.ambiguous_block_ids`, scan
///    `level_block_id_to_height` for the first level containing `block_id`. For unambiguous
///    block IDs the scan returns the unique answer, so this is safe.
/// 3. **Fall through (`None`)**: ambiguous block ID without a matching source-level —
///    cannot pick a level safely; caller skips orphan routing and falls back to the
///    merged-blob read path. (Covering this case correctly would require parent-chain
///    disambiguation per orphan step, which the existing merged-blob path also doesn't do.)
///
/// Returning `None` means "don't orphan-route this step." The caller's existing merged-blob
/// fallback applies — same behavior as the pre-fix code path for ambiguous blocks.
fn resolve_orphan_routing_level(
    squash_meta: &SquashMeta,
    block_id: u32,
    patch_source_context: Option<(usize, u32)>,
) -> Option<usize> {
    // Step 1: source-level preference.
    if let Some((src_idx, _)) = patch_source_context {
        if squash_meta
            .level_block_id_to_height
            .get(src_idx)
            .is_some_and(|m| m.contains_key(&block_id))
        {
            return Some(src_idx);
        }
    }
    // Step 2: gated global scan. Skip for ambiguous block IDs since the first match could be
    // the wrong level for a retired-fork reader.
    if squash_meta.ambiguous_block_ids.contains(&block_id) {
        return None;
    }
    squash_meta
        .level_block_id_to_height
        .iter()
        .position(|m| m.contains_key(&block_id))
}

/// Patch-aware per-node read shared by [`TrieStorageConnection`] and
/// [`ReopenedTrieStorageConnection`].
///
/// Inlines the dispatch from `inner_read_persisted_trie_item` (blobs vs. SQL, unconfirmed
/// guard) and runs the full patch-chasing loop. Both storage types call this from their
/// `TrieReadStorage::read_node_with_state` impls.
///
/// **Orphan-section routing**: each step in the patch chain checks whether `(block_id, ptr)`
/// addresses bytes in a published level's orphan section (`ptr.ptr() >= orphan_split_offset`
/// for the level that owns `block_id`). If so, the read is routed through that level's
/// orphan sidecar via [`open_orphan_sidecar_for_level`] +
/// [`read_orphan_node_bytes_into`] — the same primitives the connection's
/// [`TrieStorageConnection::try_read_orphan_bytes`] uses for the normal-read path. Without
/// this routing, descendant patch base ptrs that the publish phase rewrote into orphan-
/// section logical offsets (correct rewrites — the node really does live there) would chase
/// into reclaimed merged-blob bytes and decode garbage. Mainnet level-18 / clarity height
/// 33190 hit this on the perf/marf-squash-cyle branch.
///
/// `db_path` is the MARF's sqlite db_path, threaded through so the orphan-routing helpers
/// can resolve the level's sidecar file path.
fn read_patched_persisted_node<'b>(
    db: &Connection,
    db_path: &str,
    blobs: Option<&TrieFile>,
    unconfirmed_block_id: Option<u32>,
    mut block_id: u32,
    mut ptr: TriePtr,
    cur_block_trie_offset: Option<u64>,
    leaf_hashes_omitted: bool,
    patch_source_context: Option<(usize, u32)>,
    squash_meta: &SquashMeta,
    snapshot_retention_blocks: u32,
    scratch: &'b mut impl NodePatching,
) -> Result<ReadTrieNode<'b>, Error> {
    let target_block_id = block_id;
    let mut node_hash_opt = None;
    let mut patches = scratch.take_patch_chain_buf();
    let mut trie_offset_hint = cur_block_trie_offset;
    let mut cur_leaf_hashes_omitted = leaf_hashes_omitted;

    // Per-call cache: open each level's orphan sidecar at most once even if the patch chain
    // visits the same level multiple times. Patch chains are bounded by `MAX_PATCH_DEPTH`,
    // so the cache size is bounded by the number of distinct levels visited (≤ 9 in
    // practice). Without the cache, deep chains paid an `OpenOptions::new().open(...)` +
    // SidecarReader validation per orphan step. The cache stays local to this call —
    // unlike the connection-side `data.orphan_sidecar` slot, which is keyed on
    // `squash_opened_level_idx` and would conflict if a patch chain visits a level
    // different from the currently-opened block's level.
    let mut orphan_sidecar_cache: std::collections::HashMap<
        usize,
        crate::chainstate::stacks::index::sidecar::OrphanSidecarHandle,
    > = std::collections::HashMap::new();
    // Reusable scratch buffer for orphan-routed reads. Allocated lazily on first orphan
    // step (chains that never hit an orphan offset pay nothing); resize-up only across
    // subsequent steps so capacity carries.
    let mut orphan_buf: Vec<u8> = Vec::new();

    for _ in 0..=MAX_PATCH_DEPTH {
        // ── Orphan-section routing ─────────────────────────────────
        //
        // If the current `(block_id, ptr)` lands in a level's orphan section, route through
        // the sidecar. Level resolution mirrors the merged-blob path's
        // `patch_source_context`-first discipline (see `resolve_orphan_routing_level`):
        // unambiguous block IDs use a global scan if the source level doesn't match;
        // ambiguous block IDs without a matching source level skip orphan routing entirely
        // (falling through to the merged-blob path — same behavior the pre-fix code took
        // for those blocks).
        //
        // Skips for:
        // - unconfirmed block reads (handled below by SQL — orphan routing only applies to
        //   blocks that have been squashed into a published level).
        // - blocks not in any squashed level (still hot, or older than the lowest-active
        //   level — read from the merged blob's main section / SQL as normal).
        // - reads where `ptr.ptr() < orphan_split_offset` (in the level's main section).
        //
        // `bypass_blob_guard` and the publish/quiesce guard are NOT acquired here; the
        // caller's outer read path (e.g. `read_node_with_state`'s slow path) holds the
        // guard for the duration of the decode that follows.
        let orphan_routed = if unconfirmed_block_id != Some(block_id) {
            if let Some(level_idx) =
                resolve_orphan_routing_level(squash_meta, block_id, patch_source_context)
            {
                let split = squash_meta
                    .orphan_split_offset
                    .get(level_idx)
                    .copied()
                    .unwrap_or(0);
                if split != 0 && ptr.ptr() >= split {
                    // Lazy-open + cache the handle for this level. `entry().or_insert_with`
                    // would require fallible construction; we use the explicit pattern.
                    if !orphan_sidecar_cache.contains_key(&level_idx) {
                        let handle = open_orphan_sidecar_for_level(
                            db_path,
                            squash_meta,
                            level_idx,
                            snapshot_retention_blocks,
                        )?;
                        orphan_sidecar_cache.insert(level_idx, handle);
                    }
                    let handle = orphan_sidecar_cache
                        .get(&level_idx)
                        .expect("inserted just above");
                    read_orphan_node_bytes_into(
                        handle,
                        &ptr,
                        cur_leaf_hashes_omitted,
                        &mut orphan_buf,
                    )?;
                    let item = if cur_leaf_hashes_omitted {
                        bits::read_trie_item_from_slice_leaf_hash_free(
                            &orphan_buf,
                            ptr.id(),
                            scratch,
                        )?
                    } else {
                        bits::read_trie_item_from_slice(&orphan_buf, ptr.id(), scratch)?
                    };
                    // Orphan records must encode complete node bytes — a Patch return here
                    // would mean the orphan section contains a patch, which the writer
                    // protocol forbids. Match the connection-side `try_read_orphan_bytes`
                    // path's rejection.
                    if matches!(item.kind, ReadTrieItemKind::Patch(_)) {
                        scratch.restore_patch_chain_buf(patches);
                        return Err(Error::CorruptionError(format!(
                            "Orphan-section read at block_id={block_id} ptr={ptr:?} \
                             returned Patch; orphan records must encode complete node bytes"
                        )));
                    }
                    Some(item)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let read = if let Some(item) = orphan_routed {
            item
        } else if unconfirmed_block_id == Some(block_id) {
            trace!("Read persisted node from unconfirmed block id {block_id}");
            trie_sql::read_trie_item(db, block_id, &ptr, scratch)?
        } else {
            match blobs {
                Some(blobs) => blobs.read_trie_item(
                    db,
                    block_id,
                    &ptr,
                    trie_offset_hint,
                    cur_leaf_hashes_omitted,
                    scratch,
                )?,
                None => trie_sql::read_trie_item(db, block_id, &ptr, scratch)?,
            }
        };
        let ReadTrieItem { hash, kind, .. } = read;

        match kind {
            ReadTrieItemKind::Node(_) => {
                let node_hash = node_hash_opt.or(hash);
                // Hash-free leaves legitimately have None; non-leaf nodes must
                // always carry a hash — flag corruption if one is missing.
                if node_hash.is_none() && !is_leaf_type(ptr.id()) {
                    scratch.restore_patch_chain_buf(patches);
                    return Err(Error::CorruptionError(
                        "Missing node hash in trie read".to_string(),
                    ));
                }
                if !patches.is_empty() {
                    patches.reverse();
                    scratch.apply_patches_in_place(&patches, target_block_id)?;
                }

                let patch_depth = patches.len();
                scratch.restore_patch_chain_buf(patches);
                return Ok(
                    ReadTrieNode::from_state_borrowed(scratch.get_ref(), node_hash)
                        .with_patch_depth(patch_depth),
                );
            }
            ReadTrieItemKind::Patch(_) => {
                let node_patch = scratch.take_patch();
                trace!("read_patched_persisted_node({block_id}): at {ptr:?} read patch {node_patch:?} (original hash is {hash:?})");
                let new_ptr = node_patch.ptr.from_backptr();
                let new_block_id = node_patch.ptr.back_block();

                patches.push((block_id, ptr, node_patch));

                ptr = new_ptr;
                block_id = new_block_id;
                if let Some((source_level_idx, _)) = patch_source_context {
                    if squash_meta
                        .level_block_id_to_height
                        .get(source_level_idx)
                        .is_some_and(|m| m.contains_key(&block_id))
                    {
                        trie_offset_hint = Some(*squash_meta.level_blob_offsets.get(source_level_idx).ok_or_else(|| {
                            Error::corruption(&format!(
                                "SquashMeta.level_blob_offsets missing entry for source_level_idx={source_level_idx}"
                            ))
                        })?);
                        cur_leaf_hashes_omitted = *squash_meta
                            .level_reads_redirected
                            .get(source_level_idx)
                            .ok_or_else(|| {
                                Error::corruption(&format!(
                                    "SquashMeta.level_reads_redirected missing entry for \
                                     source_level_idx={source_level_idx}"
                                ))
                            })?;
                    } else {
                        trie_offset_hint = None;
                        cur_leaf_hashes_omitted =
                            squash_meta.leaf_hash_omitted_blocks.contains(&block_id);
                    }
                } else {
                    trie_offset_hint = None;
                    cur_leaf_hashes_omitted =
                        squash_meta.leaf_hash_omitted_blocks.contains(&block_id);
                }
                if node_hash_opt.is_none() {
                    node_hash_opt = hash;
                }
            }
        }
    }
    scratch.restore_patch_chain_buf(patches);
    Err(Error::NodeTooDeep)
}

/// PR2 helper: extract the hash of a single orphan-section record from
/// its raw bytes. Mirrors the merged-blob fast path's hash extraction:
/// non-leaves carry a 32-byte hash prefix (`bits::parse_hash_from_bytes`),
/// hash-omitted leaves are recomputed from the body
/// (`recompute_orphan_leaf_hash_from_bytes`).
fn read_orphan_node_hash_from_bytes(
    bytes: &[u8],
    ptr_id: u8,
    leaf_hashes_omitted: bool,
) -> Result<TrieHash, Error> {
    if leaf_hashes_omitted && is_leaf_type(ptr_id) {
        recompute_orphan_leaf_hash_from_bytes(bytes)
    } else {
        let (hash, _remaining) = bits::parse_hash_from_bytes(bytes)?;
        Ok(hash)
    }
}

/// PR2 helper: recompute a leaf's hash from its body bytes. Mirrors
/// [`TrieFile::recompute_leaf_hash_at`] but operates on a pre-read byte
/// slice rather than re-reading from a file. Used for orphan-section
/// reads against `leaf_hashes_omitted=true` (reclaim) blobs, where
/// leaves are stored without a 32-byte hash prefix and must be hashed
/// on demand.
fn recompute_orphan_leaf_hash_from_bytes(bytes: &[u8]) -> Result<TrieHash, Error> {
    let stored_id_byte = *bytes.first().ok_or_else(|| {
        Error::CorruptionError("recompute_orphan_leaf_hash_from_bytes: empty leaf body".into())
    })?;
    let stored_id = crate::chainstate::stacks::index::node::clear_ctrl_bits(stored_id_byte);
    let (node, _consumed) = bits::decode_nodetype_from_slice_at_head(bytes, stored_id)?;
    use sha2::Digest;
    let mut hasher = TrieHasher::new();
    match &node {
        TrieNodeType::Leaf(leaf) => {
            leaf.write_bytes(&mut hasher)
                .expect("IO failure pushing leaf bytes to hasher");
        }
        TrieNodeType::LeafSquashed(sq) => {
            // Match `recompute_leaf_hash_at` semantics: for squashed
            // leaves the hash is computed against the tip-value flat
            // leaf representation. Per-height hashing happens via
            // explicit get_node_hash paths, not via this fast path.
            let leaf = TrieLeaf {
                path: sq.path,
                data: sq.tip_value()?.clone(),
            };
            leaf.write_bytes(&mut hasher)
                .expect("IO failure pushing leaf bytes to hasher");
        }
        _ => {
            return Err(Error::CorruptionError(
                "recompute_orphan_leaf_hash_from_bytes: not a leaf node".into(),
            ));
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_slice());
    Ok(TrieHash(out))
}

/// Investigation-only: dump leaf-level details when a `read_node_with_state` call lands on a
/// `Leaf` or `LeafSquashed` while a squash trace window is active. Used to compare what the
/// `AtBlock` (merged-tip) and `ForkExtend` (sidecar) routes actually find at the same path:
/// physical `TriePtr`, `leaf_path`, and the full transition vector for `LeafSquashed`. Emit
/// this from each return point inside `read_node_with_state` so we can correlate by
/// `walk_intent` + `route`. Strip after the squash construction bug is identified.
fn trace_leaf_at_squash_read<T: MarfTrieId>(
    walk_intent: WalkIntent,
    route: &str,
    cur_block: &T,
    cur_block_id: Option<u32>,
    squash_opened_height: Option<u32>,
    squash_opened_level_idx: Option<usize>,
    ptr: &TriePtr,
    node: &ReadTrieNode<'_>,
) {
    if !marf_squash_trace_enabled_for_height(squash_opened_height) {
        return;
    }
    let Some(node_type) = node.node_type() else {
        return;
    };
    match node_type {
        TrieNodeID::Leaf => {
            let Ok(Some(leaf_ref)) = node.as_leaf() else {
                return;
            };
            info!(
                "MARF_SQUASH_TRACE leaf_node_at_squash_read";
                "kind" => "leaf",
                "route" => route,
                "walk_intent" => ?walk_intent,
                "block" => %cur_block,
                "block_id" => ?cur_block_id,
                "height" => ?squash_opened_height,
                "level_idx" => ?squash_opened_level_idx,
                "ptr" => ?ptr,
                "leaf_path" => %to_hex(leaf_ref.path),
                "leaf_value" => %leaf_ref.data.to_hex()
            );
        }
        TrieNodeID::LeafSquashed => {
            let Ok(Some(sq)) = node.as_leaf_squashed_ref() else {
                return;
            };
            // The new multipurpose carrier holds only a chunk-blob
            // reference; historical entries live in the per-level history
            // blob and are not loaded for this trace line. We log the
            // leaf header (type + flags + tip + chunk pointer) instead of
            // the entries themselves.
            info!(
                "MARF_SQUASH_TRACE leaf_node_at_squash_read";
                "kind" => "leaf_squashed",
                "route" => route,
                "walk_intent" => ?walk_intent,
                "block" => %cur_block,
                "block_id" => ?cur_block_id,
                "height" => ?squash_opened_height,
                "level_idx" => ?squash_opened_level_idx,
                "ptr" => ?ptr,
                "leaf_path" => %to_hex(sq.path),
                "leaf_type" => ?sq.leaf_type,
                "flags" => format!("0x{:02x}", sq.flags.bits()),
                "tip_value" => %sq.tip_value.to_hex(),
                "history_offset" => sq.history_offset,
                "history_byte_len" => sq.history_byte_len,
                "history_entry_count" => sq.history_entry_count
            );
        }
        _ => {}
    }
}

impl<T: MarfTrieId, Db: Deref<Target = Connection>> TrieReadStorage<T>
    for TrieStorageConnection<'_, T, Db>
{
    fn read_node_with_state<'a, S: TrieNodeReadState>(
        &'a mut self,
        ptr: &TriePtr,
        state: &'a mut S,
    ) -> Result<ReadTrieNode<'a>, Error> {
        trace!("read_node({:?}): {:?}", &self.data.cur_block, ptr);

        self.data.read_count += 1;
        if is_backptr(ptr.id()) {
            self.data.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.data.read_leaf_count += 1;
        } else {
            self.data.read_node_count += 1;
        }

        let clear_ptr = ptr.from_backptr();

        if self.has_open_uncommitted_trie() {
            let (_, uncommitted_trie) = self
                .data
                .uncommitted_writes
                .as_mut()
                .expect("BUG: uncommitted state disappeared while it was open");
            return uncommitted_trie.read_node(&clear_ptr);
        }

        let Some(id) = self.data.cur_block_id else {
            debug!("Not found (no file is open)");
            return Err(Error::NotFoundError);
        };

        // ROOT_PTR_DISK sidecar route (`WalkIntent::ForkExtend` only): rebuild the
        // per-height root shape from the sidecar so `MARF::root_copy` can extend a fork
        // off a non-tip squashed parent. For [`WalkIntent::AtBlock`] (the default —
        // ordinary `MARF::get(historical_block, key)` walks), this sidecar route is
        // skipped and the read falls through to the merged blob's offset-36 root, which
        // is the merged tip's root body. The walk traverses tip-reachable nodes only;
        // historical values are resolved at the leaf via `LeafSquashed::value_at_height`.
        // Trimming the sidecar therefore cannot break at-block reads — only fork-extension
        // surfaces `Error::SnapshotTrimmed`, as documented by the retention policy.
        if clear_ptr.ptr() == ROOT_PTR_DISK
            && marf_squash_trace_enabled_for_height(self.data.squash_opened_height)
        {
            info!(
                "MARF_SQUASH_TRACE read_node_with_state root_route";
                "block" => %self.data.cur_block,
                "block_id" => ?self.data.cur_block_id,
                "height" => ?self.data.squash_opened_height,
                "level_idx" => ?self.data.squash_opened_level_idx,
                "walk_intent" => ?self.data.walk_intent,
                "route" => if self.data.walk_intent == WalkIntent::ForkExtend {
                    "sidecar_if_available"
                } else {
                    "merged_tip_root"
                }
            );
        }
        if self.data.walk_intent == WalkIntent::ForkExtend {
            if let Some((stored_id, body, hash)) =
                self.resolve_squash_root_via_sidecar(&clear_ptr)?
            {
                if marf_squash_trace_enabled_for_height(self.data.squash_opened_height) {
                    info!(
                        "MARF_SQUASH_TRACE read_node_with_state root_sidecar_hit";
                        "block" => %self.data.cur_block,
                        "block_id" => ?self.data.cur_block_id,
                        "height" => ?self.data.squash_opened_height,
                        "level_idx" => ?self.data.squash_opened_level_idx,
                        "stored_id" => ?stored_id,
                        "hash" => %hash,
                        "body_len" => body.len()
                    );
                }
                state.decode_node_from_slice(stored_id, &body)?;
                return Ok(ReadTrieNode::from_state_borrowed(
                    state.get_ref(),
                    Some(hash),
                ));
            }
        }

        // PR2 orphan-sidecar route: orphan-section nodes are routed through the sidecar
        // unconditionally — both fork-extension reconstruction and at-block walks can
        // legitimately reach orphan offsets.
        //
        // `WalkIntent` does NOT gate this route, on purpose. The writer invariant
        // ([`squash::verify_orphan_split_invariant`]) keeps tip-rooted historical
        // *value-lookup* walks (the mainnet `at-block` GET shape that drove this fix)
        // out of the orphan section, but it doesn't cover newly-extended fork blocks
        // whose root was copied from a per-height historical root by `MARF::root_copy`:
        // those copies preserve intra-level backptrs that may target orphan offsets, and
        // `seal()` must follow them under the default `AtBlock` intent.
        //
        // Trim contract therefore stays as documented: at-block GETs against in-range
        // squashed blocks survive trim (the per-height *root* route is what we gate, see
        // `resolve_squash_root_via_sidecar` above); fork-extension off a non-tip squashed
        // parent stops working once that level's sidecar has aged out, by design.
        if let Some(bytes) = self.try_read_orphan_bytes(&clear_ptr)? {
            if marf_squash_trace_enabled_for_height(self.data.squash_opened_height) {
                info!(
                    "MARF_SQUASH_TRACE read_node_with_state orphan_route";
                    "block" => %self.data.cur_block,
                    "block_id" => ?self.data.cur_block_id,
                    "height" => ?self.data.squash_opened_height,
                    "level_idx" => ?self.data.squash_opened_level_idx,
                    "walk_intent" => ?self.data.walk_intent,
                    "ptr" => ?clear_ptr,
                    "bytes_len" => bytes.len()
                );
            }
            let leaf_hashes_omitted = self.data.leaf_hashes_omitted;
            let item_result = if leaf_hashes_omitted {
                bits::read_trie_item_from_slice_leaf_hash_free(&bytes, clear_ptr.id(), state)
            } else {
                bits::read_trie_item_from_slice(&bytes, clear_ptr.id(), state)
            };
            self.orphan_scratch_restore(bytes);
            let item = item_result?;
            return match item.kind {
                ReadTrieItemKind::Node(node) => {
                    trace_leaf_at_squash_read(
                        self.data.walk_intent,
                        "orphan_route",
                        &self.data.cur_block,
                        self.data.cur_block_id,
                        self.data.squash_opened_height,
                        self.data.squash_opened_level_idx,
                        &clear_ptr,
                        &node,
                    );
                    Ok(node)
                }
                ReadTrieItemKind::Patch(_) => Err(Error::CorruptionError(format!(
                    "Orphan-section read at ptr {clear_ptr:?} returned Patch; orphan \
                     records must encode complete node bytes"
                ))),
            };
        }

        // Zero-copy mmap fast path: return borrowed bytes directly from the mmap region
        // without decoding into scratch. Only for committed, non-patch nodes.
        //
        // We acquire a fresh [`BlobReadGuard`] per read and hand it to the returned
        // `ReadTrieNode`, which keeps `active_reads` incremented until the node is dropped.
        // If `try_acquire_blob_read` returns `None`, a writer on another handle has entered
        // its truncate window — bubble `Error::RetryAfterSquash` so the public-entry retry
        // wrapper resets per-traversal state (releasing any guards from parked nodes) and
        // restarts against the freshly published metadata. Also verify the generation hasn't
        // drifted since `open_block` sync'd: if it has, the mmap layout we cached at
        // block-open time is stale and the traversal must restart.
        //
        // `bypass_blob_guard` (squash-internal use only) skips the fast path entirely so we
        // never return mmap-borrowed bytes — the caller must own its bytes via scratch
        // decode below. This avoids the per-read atomic on `active_reads` and the cache-
        // line ping-pong that contention causes across worker cores. Safe only when the
        // caller knows no concurrent publish can fire on this MARF (see field doc).
        if self.data.unconfirmed_block_id != Some(id) && !self.data.bypass_blob_guard {
            if let Some(ref blobs) = self.blobs {
                let guard = self
                    .data
                    .shared_squash
                    .try_acquire_blob_read()
                    .ok_or(Error::RetryAfterSquash)?;
                if !self
                    .data
                    .shared_squash
                    .squash_state_fresh(self.data.seen_squash_generation)
                {
                    return Err(Error::RetryAfterSquash);
                }
                if let Some(ReadTrieItem {
                    kind: ReadTrieItemKind::Node(node),
                    ..
                }) = blobs.read_trie_item_borrowed(
                    &self.db,
                    id,
                    &clear_ptr,
                    self.data.cur_block_trie_offset,
                    self.data.leaf_hashes_omitted,
                    guard,
                )? {
                    trace_leaf_at_squash_read(
                        self.data.walk_intent,
                        "mmap_fast_path",
                        &self.data.cur_block,
                        self.data.cur_block_id,
                        self.data.squash_opened_height,
                        self.data.squash_opened_level_idx,
                        &clear_ptr,
                        &node,
                    );
                    return Ok(node);
                }
            }
        }

        // Resolve the trie offset for the current block (cached or fresh).
        let trie_offset = self.data.cur_block_trie_offset.or_else(|| {
            let offset = self.blobs.as_ref()?.get_trie_offset(&self.db, id).ok();
            self.data.cur_block_trie_offset = offset;
            offset
        });

        // Slow path (SQL / mmap-read-into-scratch). `read_patched_persisted_node` decodes into
        // caller-owned scratch, so no borrowed bytes escape — a local guard dropped at the end
        // of this function suffices. Skip acquisition when the blob file is absent (pure-SQL
        // backend has no mmap to protect). Generation check guards against stale `trie_offset`
        // / `leaf_hashes_omitted` cached on `self.data` after a mid-walk publish.
        //
        // `bypass_blob_guard` skips both: no atomic acquire, no staleness check. Safe only
        // when the caller knows no concurrent publish can fire on this MARF.
        let _slow_path_guard = if self.blobs.is_some() && !self.data.bypass_blob_guard {
            let guard = self
                .data
                .shared_squash
                .try_acquire_blob_read()
                .ok_or(Error::RetryAfterSquash)?;
            if !self
                .data
                .shared_squash
                .squash_state_fresh(self.data.seen_squash_generation)
            {
                return Err(Error::RetryAfterSquash);
            }
            Some(guard)
        } else {
            None
        };
        self.bench.read_nodetype_start();
        let patch_source_context = patch_source_context_for_open_block(
            self.data,
            &self.db,
            self.blobs.as_deref(),
            &self.data.cur_block,
            id,
        );
        let result = read_patched_persisted_node(
            &self.db,
            self.db_path,
            self.blobs.as_deref(),
            self.data.unconfirmed_block_id,
            id,
            clear_ptr,
            trie_offset,
            self.data.leaf_hashes_omitted,
            patch_source_context,
            &self.data.squash_meta,
            self.data.squash_root_snapshot_retention_blocks,
            state,
        );
        self.bench.read_nodetype_finish(false);
        match result {
            Ok(node) => {
                trace_leaf_at_squash_read(
                    self.data.walk_intent,
                    "slow_path",
                    &self.data.cur_block,
                    self.data.cur_block_id,
                    self.data.squash_opened_height,
                    self.data.squash_opened_level_idx,
                    &clear_ptr,
                    &node,
                );
                Ok(node)
            }
            Err(e) => {
                error!(
                    "read_node_with_state failed: block={}, block_id={id}, ptr={clear_ptr:?}, \
                     leaf_hashes_omitted={}, squash_levels={}, squash_block_index_len={}, \
                     trie_offset={trie_offset:?}, err={e:?}",
                    &self.data.cur_block,
                    self.data.leaf_hashes_omitted,
                    self.data.squash_meta.levels.len(),
                    self.data.squash_meta.block_index.len(),
                );
                Err(e)
            }
        }
    }

    fn open_block(&mut self, bhh: &T) -> Result<(), Error> {
        trace!(
            "open_block({}) (unconfirmed={:?},{}) in {}",
            bhh,
            &self.data.unconfirmed_block_id,
            self.unconfirmed(),
            self.db_path
        );
        self.sync_shared_squash_state()?;
        open_block_impl(self.data, &self.db, self.cache, self.bench, bhh)
    }

    fn open_block_known_id(&mut self, bhh: &T, id: u32) -> Result<(), Error> {
        trace!(
            "open_block_known_id({},{}) (unconfirmed={:?},{}) from {},{:?} in {}",
            bhh,
            id,
            &self.data.unconfirmed_block_id,
            self.unconfirmed(),
            &self.data.cur_block,
            &self.data.cur_block_id,
            self.db_path,
        );
        // No auto-refresh here: `open_block_known_id` is called during backptr resolution with a
        // pre-resolved block_id. The parent `open_block` has already run the staleness check for
        // this walk.
        open_block_known_id_impl(self.data, &self.db, self.blobs.as_deref(), bhh, id)
    }

    fn get_cur_block_and_id(&self) -> (T, Option<u32>) {
        (self.data.cur_block.clone(), self.data.cur_block_id)
    }

    fn root_trieptr(&self) -> TriePtr {
        TriePtr::new(TrieNodeID::Node256 as u8, 0, self.root_ptr())
    }

    fn read_node_hash(&mut self, ptr: &TriePtr) -> Result<TrieHash, Error> {
        if self.has_open_uncommitted_trie() {
            let (_, uncommitted_trie) = self
                .data
                .uncommitted_writes
                .as_mut()
                .expect("BUG: uncommitted state disappeared while it was open");
            return uncommitted_trie.read_node_hash(ptr);
        }

        // Per-height root-hash override: when reading `ROOT_PTR_DISK` for a block inside a
        // squash level, return the per-height (consensus) root hash from the trailer instead
        // of the merged blob's offset-36 hash prefix. The merged blob's hash prefix is the
        // *post-remap* hash recomputed by the squash writer (a storage detail; child ptrs
        // there were rewritten to merged-blob offsets), and does not match the original
        // consensus hash that backpointer-chain hash computation depends on. The trailer is
        // in-memory metadata, not a sidecar dependency, so this override is correct for both
        // [`WalkIntent::AtBlock`] (e.g., back-chain hash lookups during `seal`) and
        // [`WalkIntent::ForkExtend`] (historical seal-hash reconstruction). It must run
        // unconditionally — gating it caused tip-extension seal-hash divergence from the
        // unsquashed reference (see `test_tier2_fork_at_boundary_full_history_differential`).
        if ptr.ptr() == ROOT_PTR_DISK {
            if let (Some(h), Some(level_idx)) = (
                self.data.squash_opened_height,
                self.data.squash_opened_level_idx,
            ) {
                if let Some(level) = self.data.squash_meta.levels.get(level_idx) {
                    if let Some(root_hash) = level.root_hash_at(h) {
                        return Ok(*root_hash);
                    }
                }
            }
        }

        // PR2 orphan-sidecar route: see [`Self::read_node_with_state`] for the full
        // contract — orphan reads are routed unconditionally because fork-extension
        // copies of per-height historical roots can carry intra-level backptrs that
        // legitimately target orphan offsets, and `seal()` must follow them under the
        // default `AtBlock` intent.
        if let Some(bytes) = self.try_read_orphan_bytes(ptr)? {
            let leaf_hashes_omitted = self.data.leaf_hashes_omitted;
            let result = read_orphan_node_hash_from_bytes(&bytes, ptr.id(), leaf_hashes_omitted);
            self.orphan_scratch_restore(bytes);
            return result;
        }

        match self.data.cur_block_id {
            Some(block_id) => {
                // Per-read guard: `inner_read_persisted_node_hash` calls `blobs.get_node_hash`
                // which touches the mmap. The returned `TrieHash` is an owned 32-byte copy, so
                // the guard can be local. Skip when blobs aren't enabled (pure-SQL backend) or
                // when `bypass_blob_guard` is set (squash-internal handles only).
                let _guard = if self.blobs.is_some() && !self.data.bypass_blob_guard {
                    let guard = self
                        .data
                        .shared_squash
                        .try_acquire_blob_read()
                        .ok_or(Error::RetryAfterSquash)?;
                    if !self
                        .data
                        .shared_squash
                        .squash_state_fresh(self.data.seen_squash_generation)
                    {
                        return Err(Error::RetryAfterSquash);
                    }
                    Some(guard)
                } else {
                    None
                };
                self.bench.read_node_hash_start();
                let node_hash = self.inner_read_persisted_node_hash(block_id, ptr)?;
                self.bench.read_node_hash_finish(false);
                Ok(node_hash)
            }
            None => {
                error!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }

    fn read_node_type_id(&mut self, ptr: &TriePtr) -> Result<(TrieNodeID, TrieHash), Error> {
        let clear_ptr = ptr.from_backptr();

        if self.has_open_uncommitted_trie() {
            let (_, uncommitted_trie) = self
                .data
                .uncommitted_writes
                .as_mut()
                .expect("BUG: uncommitted state disappeared while it was open");
            let read_node = uncommitted_trie.read_node(&clear_ptr)?;
            let node_id = read_node
                .node_type()
                .filter(|node_id| *node_id != TrieNodeID::Patch)
                .ok_or_else(|| {
                    Error::CorruptionError("Unknown trie node type in uncommitted trie".to_string())
                })?;
            let hash = read_node.hash.ok_or_else(|| {
                Error::CorruptionError("Missing node hash in uncommitted trie read".to_string())
            })?;
            return Ok((node_id, hash));
        }

        // ROOT_PTR_DISK sidecar route (`WalkIntent::ForkExtend` only): mirrors
        // [`Self::read_node_with_state`]'s gating. At-block reads walk from the merged
        // tip's root, so its (type, hash) pair must come from the merged blob, not the
        // per-height sidecar. Fork-extension routes through the sidecar to recover the
        // historical root shape.
        if self.data.walk_intent == WalkIntent::ForkExtend {
            if let Some((stored_id, _body, hash)) =
                self.resolve_squash_root_via_sidecar(&clear_ptr)?
            {
                return Ok((stored_id, hash));
            }
        }

        // Orphan-sidecar route: see [`Self::read_node_with_state`] for the unconditional
        // contract — fork-extension copies of per-height historical roots may carry
        // backptrs into the orphan section that `seal()` follows under the default
        // `AtBlock` intent.
        if let Some(bytes) = self.try_read_orphan_bytes(&clear_ptr)? {
            let leaf_hashes_omitted = self.data.leaf_hashes_omitted;
            // IIFE: borrow `bytes` for the duration of the decode, then
            // release the borrow so the surrounding scope can move
            // `bytes` into `orphan_scratch_restore` regardless of
            // success/failure.
            let result: Result<(TrieNodeID, TrieHash), Error> = (|| {
                if leaf_hashes_omitted && is_leaf_type(clear_ptr.id()) {
                    let stored_id = bits::stored_node_id_from_bytes(&bytes)?;
                    let hash = recompute_orphan_leaf_hash_from_bytes(&bytes)?;
                    Ok((stored_id, hash))
                } else {
                    bits::read_stored_node_type_from_slice(&bytes)
                }
            })();
            self.orphan_scratch_restore(bytes);
            return result;
        }

        let Some(id) = self.data.cur_block_id else {
            return Err(Error::NotFoundError);
        };
        if self.blobs.is_some() {
            // Per-read guard for the mmap-backed path. Hash/type decode yields owned values
            // (Copy types), so the guard is local to this call and drops at scope end.
            // Skipped when `bypass_blob_guard` is set (squash-internal handles only).
            let _guard = if !self.data.bypass_blob_guard {
                let guard = self
                    .data
                    .shared_squash
                    .try_acquire_blob_read()
                    .ok_or(Error::RetryAfterSquash)?;
                if !self
                    .data
                    .shared_squash
                    .squash_state_fresh(self.data.seen_squash_generation)
                {
                    return Err(Error::RetryAfterSquash);
                }
                Some(guard)
            } else {
                None
            };
            let blobs = self
                .blobs
                .as_mut()
                .expect("blobs.is_some() above proves this is Some");
            blobs.read_node_type_id(&self.db, id, &clear_ptr, self.data.leaf_hashes_omitted)
        } else {
            trie_sql::probe_node_type(&self.db, id, &clear_ptr)
        }
    }

    fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &T, bytes: Vec<TrieHash>) {
        self.data.set_ancestor_hashes_bytes(bhh, bytes);
    }

    fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &T) -> Option<Vec<TrieHash>> {
        self.data.get_ancestor_hashes_bytes(bhh)
    }

    #[cfg(test)]
    fn test_genesis_block(&self) -> Option<T> {
        self.test_genesis_block.clone()
    }

    fn squash_opened_height(&self) -> Option<u32> {
        // Eager getter only — returns the height set by `open_block_impl` when the
        // currently-open block is in a squash level (or its uncommitted-parent-of-squash).
        // For committed non-squash blocks (fork descendants, canonical past last squash),
        // this is `None`; the lazy parent-chain walk lives in `snapshot_height_for_block`,
        // which the marf walk only invokes if it actually hits a `LeafSquashed`.
        self.data.squash_opened_height
    }

    fn squash_opened_level_idx(&self) -> Option<usize> {
        self.data.squash_opened_level_idx
    }

    fn squashed_leaf_value_at_height(
        &self,
        history_offset: u64,
        history_byte_len: u32,
        history_entry_count: u32,
        height: u32,
    ) -> Result<Option<MARFValue>, Error> {
        // Concurrency / generation gate (mirrors the cold-blob read pattern
        // in `read_trie_item_borrowed`'s mmap fast path):
        //
        // 1. Acquire a `BlobReadGuard` to bump `active_reads` for the
        //    duration of this read. Phase 4 trim respects the same
        //    counter — it can't unlink the history blob while reads are
        //    in flight. On POSIX an unlinked mmap region survives until
        //    the last reference drops, but Windows doesn't allow unlink-
        //    while-open without special flags, so the guard is necessary
        //    for cross-platform correctness.
        // 2. Re-check `squash_state_fresh`: a publish or trim between
        //    this handle's last sync and now would install a new
        //    `SquashMeta` whose `level_history_blob_state[level_idx]`
        //    may differ from our cached snapshot. Without this check,
        //    we could read from a stale `Arc<HistoryBlobReader>` that
        //    happens to still be alive (POSIX) and serve data that
        //    `'trimmed'` semantics promise to surface as
        //    `HistoryTrimmed`. Bubble `RetryAfterSquash` so the
        //    top-level wrapper resyncs and the retry returns the
        //    correct error.
        let _guard = self
            .data
            .shared_squash
            .try_acquire_blob_read()
            .ok_or(Error::RetryAfterSquash)?;
        if !self
            .data
            .shared_squash
            .squash_state_fresh(self.data.seen_squash_generation)
        {
            return Err(Error::RetryAfterSquash);
        }

        let level_idx = self.data.squash_opened_level_idx.ok_or_else(|| {
            Error::CorruptionError(
                "squashed_leaf_value_at_height: hit LeafSquashed without an opened squash level"
                    .into(),
            )
        })?;
        // marf_dir = parent of the sqlite path.
        let marf_dir = std::path::Path::new(&self.db_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let reader_opt = self
            .data
            .squash_meta
            .history_blob_reader(&marf_dir, level_idx)?;
        let reader = reader_opt.ok_or_else(|| {
            Error::CorruptionError(format!(
                "squashed_leaf_value_at_height: level_idx={level_idx} has history_blob_state \
                 = NeverWritten but a TrieLeafSquashed with has_history was decoded here \
                 (corruption between SQL row and on-disk leaf)"
            ))
        })?;
        let chunk = reader.read_chunk(history_offset, history_byte_len, history_entry_count)?;
        Ok(chunk.value_at_height(height))
    }

    #[cfg(test)]
    fn bump_squashed_tip_fallback_count(&self) {
        let c = &self.data.squashed_tip_fallback_count;
        c.set(c.get() + 1);
    }

    #[cfg(test)]
    fn bump_squashed_entries_reread_count(&self) {
        let c = &self.data.squashed_entries_reread_count;
        c.set(c.get() + 1);
    }

    fn snapshot_height_for_block(&self, block_hash: &T, block_id: u32) -> Option<u32> {
        // Eager fast path: the requested block is the currently-open block AND was
        // detected as in-squash by `open_block_impl`. No walk needed.
        if self.data.cur_block_id == Some(block_id) {
            if let Some(h) = self.data.squash_opened_height {
                return Some(h);
            }
        }
        // No squash exists ⇒ no squashed ancestor to find. Cheap predicate that drops
        // canonical-only chains (the common case) before any walk machinery.
        if self.data.squash_meta.block_index.is_empty() {
            return None;
        }
        // Memoized walk, keyed by user_block_id. Survives backptr resolution — which
        // mutates `cur_block_id` mid-walk — because the cache key is the user's identity,
        // passed in explicitly. Single-entry cache: a different user query overwrites it,
        // which is fine since reads target one user block at a time.
        let resolved = snapshot_context_for_block(
            self.data,
            &self.db,
            self.blobs.as_deref(),
            block_hash,
            block_id,
        );
        resolved.map(|(_level_idx, height)| height)
    }

    fn write_children_hashes_by_ptrs<W: Write + ?Sized>(
        &mut self,
        ptrs: &[TriePtr],
        w: &mut W,
    ) -> Result<(), Error> {
        trace!("write_children_hashes for {:?}", ptrs);

        let mut map = TrieSqlHashMapCursor {
            db: &self.db,
            cache: self.cache,
            unconfirmed: self.data.unconfirmed,
        };

        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                let start_time = self.bench.write_children_hashes_start();
                let res = Self::inner_write_children_hashes(
                    uncommitted_trie.trie_ram_mut(),
                    &mut map,
                    ptrs,
                    w,
                    self.bench,
                );
                self.bench.write_children_hashes_finish(start_time, true);
                return res;
            }
        }

        let cur_block_id = self.data.cur_block_id.ok_or_else(|| {
            error!("Failed to get cur block as hash reader");
            Error::NotFoundError
        })?;
        // Unconfirmed-trie rows live in the inline `data` blob (no external file backing),
        // so route them through the SQL cursor even when blob storage is attached. Without
        // this bypass the blob path resolves to `(StorageKind::Cold, offset=0)` from the
        // unconfirmed row and fails on a positional read against an empty cold blob.
        let unconfirmed_in_use = self.data.unconfirmed_block_id == Some(cur_block_id);

        if self.blobs.is_some() && !unconfirmed_in_use {
            // Per-read guard covers the entire `inner_write_children_hashes` walk — the hash
            // reader does multiple mmap accesses across sibling pointers, all of which must
            // stay protected against a concurrent ftruncate until this call returns.
            // Skipped when `bypass_blob_guard` is set (squash-internal handles only).
            let _guard = if !self.data.bypass_blob_guard {
                let guard = self
                    .data
                    .shared_squash
                    .try_acquire_blob_read()
                    .ok_or(Error::RetryAfterSquash)?;
                if !self
                    .data
                    .shared_squash
                    .squash_state_fresh(self.data.seen_squash_generation)
                {
                    return Err(Error::RetryAfterSquash);
                }
                Some(guard)
            } else {
                None
            };
            let start_time = self.bench.write_children_hashes_start();
            let blobs = self
                .blobs
                .as_mut()
                .expect("blobs.is_some() above proves this is Some");
            let mut cursor = TrieFileNodeHashReader::new(
                &self.db,
                blobs,
                cur_block_id,
                self.data.leaf_hashes_omitted,
            );
            let res = Self::inner_write_children_hashes(&mut cursor, &mut map, ptrs, w, self.bench);
            self.bench.write_children_hashes_finish(start_time, false);
            res
        } else {
            let start_time = self.bench.write_children_hashes_start();
            let mut cursor = TrieSqlCursor {
                db: &self.db,
                block_id: cur_block_id,
            };
            let res = Self::inner_write_children_hashes(&mut cursor, &mut map, ptrs, w, self.bench);
            self.bench.write_children_hashes_finish(start_time, false);
            res
        }
    }

    fn bench_mut(&mut self) -> &mut TrieBenchmark {
        self.bench
    }

    fn refresh_after_concurrent_squash(&mut self) -> Result<(), Error> {
        // Wait for any in-flight publisher to exit its mutation window before syncing —
        // otherwise `sync_shared_squash_state` sees the not-yet-bumped generation, no-ops,
        // and the next retry attempt hits the same `truncate_pending` flag. Reader holds
        // no guards here (the retry reset dropped everything), so the writer's drain is
        // unblocked and this wait is bounded by the publisher's mutation window length.
        self.data.shared_squash.wait_for_publish_complete();
        // Pick up fresh squash metadata, remap the mmap, clear the block cache, reset
        // `cur_block` so the next `open_block()` re-resolves against the new layout.
        self.sync_shared_squash_state()
    }
}

impl<T: MarfTrieId> TrieFileStorage<T> {
    /// Split-borrow the SQL connection + the attached `HotFileSet` for Phase C's hot-reclaim
    /// sweep. The sweep mutates the `HotFileSet` (`drop_seq` after `apply_unlinkable`) AND the
    /// `marf_data` table (DELETE rows for the dropped seq) in the same call, so it needs both
    /// borrows simultaneously — going through [`Self::connection`] would re-borrow `&mut self.data`
    /// + everything else needlessly.
    ///
    /// Returns `None` if the storage handle is RAM-backed (no `TrieFile::Disk`, hence no hot
    /// tier attached). Phase C has nothing to sweep on RAM-backed handles.
    pub(crate) fn sweep_borrows(
        &mut self,
    ) -> Option<(
        &Connection,
        &mut crate::chainstate::stacks::index::hot_file::HotFileSet,
    )> {
        let blobs = self.blobs.as_mut()?;
        let hot_files = blobs.hot_files_mut()?;
        Some((&self.db, hot_files))
    }

    /// Borrow-split helper for the squash-promote publish phase. Returns `(&mut Connection,
    /// &mut HotFileSet)` so [`crate::chainstate::stacks::index::squash_promote::apply_prepared_plan`]
    /// can call the shared `publish_prepared_inner` core (which also runs in the recovery path
    /// against raw `&mut Connection + &mut HotFileSet`). Direct field access from
    /// `squash_promote.rs` would conflict because `db` is private; this method is the
    /// load-bearing accessor.
    ///
    /// Returns `None` if the storage handle is RAM-backed or has no hot tier — the publish path
    /// requires hot-tier-attached storage.
    pub(crate) fn publish_borrows(
        &mut self,
    ) -> Option<(
        &mut Connection,
        &mut crate::chainstate::stacks::index::hot_file::HotFileSet,
    )> {
        let blobs = self.blobs.as_mut()?;
        let hot_files = blobs.hot_files_mut()?;
        Some((&mut self.db, hot_files))
    }

    pub fn connection(&mut self) -> TrieStorageConnection<'_, T> {
        // Per-read guard model: no connection-level acquisition. See the equivalent comment
        // on `ReopenedTrieStorageConnection::connection` for the full rationale.
        TrieStorageConnection {
            db: &self.db,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            compress: self.compress,
            mmap: self.mmap,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        }
    }

    /// Build a read-only storage connection which can be used for reads without modifying the
    ///  calling TrieFileStorage struct (i.e., the tip pointer is only changed in the connection)
    ///  but reusing the TrieFileStorage's existing SQLite Connection (avoiding the overhead of
    ///   `reopen_readonly`).
    pub fn reopen_connection(&self) -> Result<ReopenedTrieStorageConnection<'_, T>, Error> {
        let data = TrieStorageTransientData {
            uncommitted_writes: self.data.uncommitted_writes.clone(),
            // Share the source-of-truth squash state with the parent — writers' `publish` will be
            // visible to this handle via the generation counter.
            squash_meta: Arc::clone(&self.data.squash_meta),
            shared_squash: Arc::clone(&self.data.shared_squash),
            seen_squash_generation: self.data.seen_squash_generation,
            ..TrieStorageTransientData::new(
                self.data.cur_block.clone(),
                self.data.cur_block_id,
                true,
                self.unconfirmed(),
            )
        };
        // perf note: should we attempt to clone the cache
        let cache = BlockCache::default();
        let mut blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true, self.mmap)?)
        } else {
            None
        };
        // Phase D (2026-05-04): hot tier is non-optional, so the reopened readonly handle must
        // attach a `HotFileSet` whenever the new blob handle is disk-backed. Without this, reads
        // of `storage_kind = Hot` rows fail with `read_hot_bytes_at: storage_kind = Hot but no
        // hot files attached`. Mirrors the attachment in `build_readonly_storage`.
        if let Some(blobs_handle) = blobs.as_mut() {
            if matches!(blobs_handle, TrieFile::Disk(_)) {
                let hot_files = crate::chainstate::stacks::index::hot_file::HotFileSet::open(
                    &self.db_path,
                    &self.db,
                    self.mmap,
                    crate::chainstate::stacks::index::hot_file::DEFAULT_HOT_FILE_ROTATION_THRESHOLD_BYTES,
                    /* readonly = */ true,
                )?;
                blobs_handle.attach_hot_files(hot_files)?;
            }
        }
        let bench = TrieBenchmark::new();
        let hash_calculation_mode = self.hash_calculation_mode;
        Ok(ReopenedTrieStorageConnection {
            db_path: &self.db_path,
            db: &self.db,
            blobs,
            data,
            cache,
            bench,
            hash_calculation_mode,
            compress: self.compress,
            mmap: self.mmap,
            #[cfg(test)]
            test_genesis_block: self.test_genesis_block.clone(),
        })
    }

    pub fn transaction(&mut self) -> Result<TrieStorageTransaction<'_, T>, Error> {
        if self.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let tx = tx_begin_immediate(&mut self.db)?;

        // Writer transactions don't race with their own squash (squash is serial on the writer
        // thread), so acquiring a guard at transaction start would be harmless but redundant.
        // Per-read acquisition inside the storage layer covers concurrent read-path safety on
        // other handles.
        Ok(TrieStorageConnection {
            db: tx,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            compress: self.compress,
            mmap: self.mmap,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        })
    }

    pub fn sqlite_conn(&self) -> &Connection {
        &self.db
    }

    pub fn sqlite_tx(&mut self) -> Result<Transaction<'_>, db_error> {
        tx_begin_immediate(&mut self.db)
    }

    pub fn into_sqlite_conn(self) -> Connection {
        self.db
    }

    /// Write a chunk of blob data at the given file offset without syncing.
    ///
    /// Part of the streaming blob write API. Call [`finish_blob_write`] after
    /// all chunks are written.
    pub(crate) fn pwrite_blob_chunk(&mut self, data: &[u8], offset: u64) -> Result<(), Error> {
        let blobs = self.blobs.as_mut().ok_or_else(|| {
            Error::NotSupportedError("Cannot pwrite blob chunk: external_blobs not enabled".into())
        })?;
        blobs.pwrite_blob_chunk(data, offset)
    }

    /// Finalize a streaming blob write: sync, optionally truncate, remap.
    ///
    /// See [`TrieFile::finish_blob_write`] for details.
    pub(crate) fn finish_blob_write(&mut self, truncate_to: Option<u64>) -> Result<(), Error> {
        let blobs = self.blobs.as_mut().ok_or_else(|| {
            Error::NotSupportedError("Cannot finish blob write: external_blobs not enabled".into())
        })?;
        blobs.finish_blob_write(truncate_to)
    }

    /// Return the current length of the external blobs file (next append offset).
    pub(crate) fn get_blob_append_offset(&self) -> Result<u64, Error> {
        trie_sql::get_external_blobs_length(&self.db)
    }

    /// Actual on-disk length of the external blobs file, queried via filesystem
    /// metadata (NOT the SQL-tracked `external_blobs_length` row, which may lag
    /// or precede the file during in-flight pwrites/truncates).
    ///
    /// Used by squash bookkeeping to compute reclaimed bytes around the
    /// `finish_blob_write` truncate boundary.
    pub(crate) fn get_blob_file_len(&self) -> Result<u64, Error> {
        let blobs = self.blobs.as_ref().ok_or_else(|| {
            Error::NotSupportedError(
                "Cannot query blob file length: external_blobs not enabled".into(),
            )
        })?;
        blobs.current_file_len()
    }

    /// Lightweight local sync for the writer that just published a squash on
    /// this same handle. The publishing path (`publish_squashed_blob` →
    /// `SharedStorageState::publish_squash`) has already installed the new
    /// `SquashMeta`, bumped the shared generation, and remapped this handle's
    /// mmap from inside the rebuild closure. All that's left for the writer
    /// is to refresh its handle-local view of the shared state (snapshot
    /// pointer, `seen_squash_generation`, block cache, current-block context)
    /// — done via the existing peer-sync helper, which does NOT re-enter
    /// `publish_squash`. Avoids the redundant second global quiesce +
    /// generation bump that calling [`Self::refresh_after_squash`] would do.
    pub fn sync_after_published_squash(&mut self) -> Result<(), Error> {
        sync_from_shared_squash_state(
            &mut self.data,
            self.blobs.as_mut(),
            &mut self.cache,
            &self.db,
        )
    }

    /// Run an arbitrary SQL mutation INSIDE the shared squash-publish quiesce
    /// window, then republish [`SquashMeta`] atomically so that the new SQL
    /// state and the new in-memory snapshot become visible to all handles at
    /// the same generation bump.
    ///
    /// This is the correct path for any post-squash SQL flip that affects the
    /// read path's behavior (e.g. `marf_squash_levels.history_blob_state`
    /// going from `'present'` to `'trimmed'`): the alternative — SQL UPDATE
    /// outside the quiesce window, then a separate
    /// [`Self::refresh_after_squash`] — leaves a window where existing handles
    /// can still pass the generation-freshness check, observe SQL as
    /// `Trimmed` via a fresh read, but read the cached `Present`
    /// [`SquashMeta`] and serve bytes from a file that's about to be
    /// unlinked.
    ///
    /// Ordering inside `publish_squash`:
    ///
    /// 1. `truncate_pending = true` — new readers back off.
    /// 2. Drain in-flight readers (`active_reads == 0`).
    /// 3. **Run `mutation(&Connection)`** — pre-arm; failures here are safely
    ///    surfaced to the caller without risk to other handles.
    /// 4. `guard.arm()` — SQL change is durable from here on.
    /// 5. `remap_and_invalidate` (when external blobs are present).
    /// 6. `build_squash_meta_from_sql` — reflects the post-mutation SQL state.
    /// 7. Install new `Arc<SquashMeta>`, bump generation, clear
    ///    `truncate_pending`.
    ///
    /// A failure at step 5 or 6 aborts the process — once the mutation
    /// committed, recovering would mean serving the old `SquashMeta` against
    /// the new SQL state (the inverse of the bug we're guarding against).
    pub fn refresh_after_squash_with_sql_mutation<F>(&mut self, mutation: F) -> Result<(), Error>
    where
        F: FnOnce(&Connection) -> Result<(), Error>,
    {
        let TrieFileStorage { db, blobs, .. } = self;
        let db: &Connection = db;
        let blobs: &mut Option<TrieFile> = blobs;

        let rebuild = |guard: &PublishMutationGuard| -> Result<SquashMeta, Error> {
            mutation(db)?;
            guard.arm();
            if let Some(b) = blobs.as_mut() {
                b.remap_and_invalidate()?;
            }
            build_squash_meta_from_sql(db, blobs.as_ref())
        };

        self.data.shared_squash.publish_squash(rebuild)?;

        self.data.squash_meta = self.data.shared_squash.snapshot();
        self.data.seen_squash_generation = self.data.shared_squash.generation();
        self.data.external_bytes_since_last_squash =
            trie_sql::current_external_bytes_since_last_squash(&self.db)?;

        self.cache = BlockCache::new("noop");
        self.data.set_block(T::sentinel(), None);
        self.data.trie_ancestor_hash_bytes_cache = None;
        self.data.resolved_snapshot_context.set(None);

        Ok(())
    }

    /// Reload squash level metadata and remap the blob file after an external
    /// squash operation has modified both the SQLite DB and the `.blobs` file
    /// through a separate handle.
    ///
    /// Runs the remap + metadata rebuild inside the shared quiesce window so
    /// that concurrent readers on other handles cannot be holding mmap bytes
    /// when the file is mutated. See [`SharedStorageState::publish_squash`]
    /// for the exact ordering guarantees.
    ///
    /// **For writers that just published a squash on this same handle, prefer
    /// [`Self::sync_after_published_squash`]** — that path skips the second
    /// `publish_squash` entry entirely.
    pub fn refresh_after_squash(&mut self) -> Result<(), Error> {
        // Split borrows so the closure captures the blobs+db directly rather than through
        // `&mut self` — lets us still access `self.data` and friends after.
        let TrieFileStorage { db, blobs, .. } = self;
        let db: &Connection = db;
        let blobs: &mut Option<TrieFile> = blobs;

        // `publish_squash` runs our rebuild under the quiesce. Inside the closure all other
        // readers on this db path have drained, so remap_and_invalidate + trailer reads see a
        // stable file. The generation bump and writer-flag release happen after we return.
        //
        // We never arm the mutation guard here: `refresh_after_squash` is the
        // *consumer* path — a separate publisher has already truncated the file, and
        // this rebuild only remaps THIS handle's mmap and re-reads the SQL trailer.
        // No irreversible file mutation occurs, so any `Err` is safely surfaced to the
        // caller without risk to other readers.
        let rebuild = |_guard: &PublishMutationGuard| -> Result<SquashMeta, Error> {
            if let Some(b) = blobs.as_mut() {
                b.remap_and_invalidate()?;
            }
            build_squash_meta_from_sql(db, blobs.as_ref())
        };

        self.data.shared_squash.publish_squash(rebuild)?;

        // Sync this handle's local snapshot + watermark to the fresh published state.
        self.data.squash_meta = self.data.shared_squash.snapshot();
        self.data.seen_squash_generation = self.data.shared_squash.generation();
        // Reconstruct the per-MARF squash-work counter from SQL: the
        // separate publishing handle has just advanced
        // `published_max_block_id`, so any rows this handle had counted as
        // "post-watermark" may now be inside the new level. Cheap query
        // (O(post-watermark rows), index-driven).
        self.data.external_bytes_since_last_squash =
            trie_sql::current_external_bytes_since_last_squash(&self.db)?;

        // Clear the block cache and current-block context — stale after the squash redirected
        // blocks to new blob offsets.
        self.cache = BlockCache::new("noop");
        self.data.set_block(T::sentinel(), None);
        self.data.trie_ancestor_hash_bytes_cache = None;
        // Cached level_idx values reference the *prior* squash_meta; replacing meta
        // can change which level a block_id resolves into.
        self.data.resolved_snapshot_context.set(None);

        Ok(())
    }

    fn open_opts(
        db_path: &str,
        readonly: bool,
        unconfirmed: bool,
        marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<T>, Error> {
        // `auto_recovery = false` (set via [`MARFOpenOpts::with_auto_recovery`]) skips
        // canonical-sensitive recovery (publish/discard of pending squash plans) at open time.
        // Byte-level recovery (torn hot-tail truncation, stale tmp-file sweep) still runs. Caller
        // is then responsible for invoking [`crate::chainstate::stacks::index::marf::MARF::drain_pending_plans`]
        // before exposing the handle to readers.
        let defer_canonical_recovery = !marf_opts.auto_recovery;
        let mut create_flag = false;
        let open_flags = if db_path != ":memory:" {
            match fs::metadata(db_path) {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        // need to create
                        if !readonly {
                            create_flag = true;
                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                        } else {
                            return Err(Error::NotFoundError);
                        }
                    } else {
                        return Err(Error::IOError(e));
                    }
                }
                Ok(_md) => {
                    // can just open
                    if !readonly {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
            }
        } else {
            create_flag = true;
            if !readonly {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_CREATE
            }
        };

        let mut db = marf_sqlite_open(db_path, open_flags, false)?;
        let db_path = db_path.to_string();

        if create_flag {
            trie_sql::create_tables_if_needed(&mut db)?;
        }

        // Resolve the per-path recovery state up front. The state is moved into the resulting
        // `TrieFileStorage` so the live count stays accurate while this handle is open; the
        // inner `rw_recovery_done` flag (taken under a mutex) gates the in-process truncate-on-
        // startup + Phase B promotion-recovery block below. See [`recovery_state_for`] for the
        // multi-handle race this guards against.
        let recovery_state = recovery_state_for(&db_path);

        let mut blobs = if marf_opts.external_blobs {
            Some(TrieFile::from_db_path(&db_path, readonly, marf_opts.mmap)?)
        } else {
            None
        };

        let prev_schema_version = trie_sql::migrate_tables_if_needed::<T>(&mut db)?;
        // Blob export is only needed when upgrading from schema 1 (inline sqlite blobs) to schema
        // 2+ (external .blobs file).  Later schema bumps (e.g. 2→3 for squash metadata) don't touch
        // the blob layout and must not trigger a full re-export.
        if prev_schema_version < 2 || marf_opts.force_db_migrate {
            if let Some(blobs) = blobs.as_mut() {
                if TrieFile::exists(&db_path)? {
                    // migrate blobs out of the old DB
                    blobs.export_trie_blobs::<T>(&db, &db_path)?;
                }
            }
        }
        if trie_sql::detect_partial_migration(&db)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        // v1.5 (Phase D 2026-05-03): hot tier is non-optional. Every disk-backed open attaches a
        // `HotFileSet`; new block writes land in `<db>.hot.NNNN`, and the cold blob
        // (`<db>.blobs`) is reserved for promoted (squashed) blocks. The Phase A `enable_hot_tier`
        // opt-in flag was removed once Phase B + C shipped — leaving it in place was the only way
        // production could still hit the legacy tip-only squash path (the level-34 panic class).
        {
            if let Some(blobs_handle) = blobs.as_mut() {
                if matches!(blobs_handle, TrieFile::Disk(_)) {
                    let mut hot_files = crate::chainstate::stacks::index::hot_file::HotFileSet::open(
                        &db_path,
                        &db,
                        marf_opts.mmap,
                        crate::chainstate::stacks::index::hot_file::DEFAULT_HOT_FILE_ROTATION_THRESHOLD_BYTES,
                        readonly,
                    )?;

                    // Recovery dispatch:
                    //
                    //  * RW handles serialize on `recovery_state.rw_recovery_done` so the first
                    //    RW opener for this path runs truncate-on-startup + Phase B reconciliation
                    //    and any concurrent RW opener (e.g. p2p attaching while the chains-
                    //    coordinator is mid-flight) sees `done = true` and skips. Crucially, a
                    //    readonly-first ordering does NOT flip this flag: a readonly handle
                    //    doesn't truncate (it would mutate disk on a readonly open) and doesn't
                    //    reconcile (its Phase B contract is fail-hard, not commit/abandon), so a
                    //    later RW opener still finds `done = false` and runs the cleanup.
                    //
                    //  * Readonly handles ALWAYS run [`recover_pending_promotions`] because that
                    //    call's readonly mode is a state check, not a state mutation — it fails
                    //    fast if any pending plan exists, regardless of what other handles have
                    //    done. Skipping it under any condition would let a mid-swap state appear
                    //    as wrong-but-readable bytes.
                    if readonly {
                        // Canonical-sensitive recovery is gated by `defer_canonical_recovery`. When
                        // deferred, the caller is expected to invoke `MARF::drain_pending_plans`
                        // before exposing the handle to readers; the readonly fail-fast on pending
                        // plans then happens inside drain instead of here.
                        if !defer_canonical_recovery {
                            let recovery_stats = crate::chainstate::stacks::index::squash_recover::recover_pending_promotions::<T>(
                                &mut db,
                                &db_path,
                                &mut hot_files,
                                readonly,
                                None,
                            )?;
                            if recovery_stats.any_plan_processed()
                                || recovery_stats.cold_tail_truncated_bytes > 0
                            {
                                info!(
                                    "Phase B promotion recovery: {} plan(s) discovered \
                                     ({} committed, {} abandoned, {} discarded stale, \
                                     {} rewrites applied, {} skipped, \
                                     cold tail truncated by {} bytes)",
                                    recovery_stats.plans_discovered(),
                                    recovery_stats.plans_committed(),
                                    recovery_stats.plans_abandoned(),
                                    recovery_stats.plans_discarded_stale(),
                                    recovery_stats.rewrites_applied,
                                    recovery_stats.rewrites_skipped,
                                    recovery_stats.cold_tail_truncated_bytes,
                                );
                                blobs_handle.remap_and_invalidate()?;
                            }
                        }
                    } else {
                        let mut rw_done = recovery_state.rw_recovery_done.lock();
                        if !*rw_done {
                            // SQL-as-authoritative truncation for the active hot file
                            // (Slice A6 / `.docs/squashing-v1.5.md` §5.3 (a)). The hot-file
                            // write path fsyncs the file *before* committing the SQL row, so
                            // any bytes past the last committed `external_offset +
                            // external_length` belong to a torn append from a prior process
                            // exit and are uncommitted. Truncate them so the next append lands
                            // at the correct offset and the mmap doesn't expose unparsable
                            // trailing bytes to the read path.
                            let active_seq = hot_files.active_seq();
                            let committed_len =
                                trie_sql::get_hot_file_committed_length(&db, active_seq)?;
                            let on_disk_len = hot_files.active_len()?;
                            if on_disk_len > committed_len {
                                info!(
                                    "Hot-file recovery: truncating <db>.hot.{active_seq:08} from \
                                     {on_disk_len} -> {committed_len} bytes (clipping torn append)"
                                );
                                hot_files.truncate_active(committed_len)?;
                            }

                            // v1.5 Phase B promotion recovery. Drives any pending
                            // `<db>.squash_pending.*.plan` left over from a crashed promotion
                            // to a consistent terminal state (committed or abandoned), then
                            // truncates the cold blob's uncommitted tail. Must run BEFORE
                            // attaching `hot_files` to `blobs_handle` because recovery needs
                            // `&mut HotFileSet` (attach moves it into the TrieFile) and may
                            // truncate `<db>.blobs` (the `remap_and_invalidate` call refreshes
                            // the TrieFile's mmap to cover the post-truncation extent).
                            //
                            // Gated by `defer_canonical_recovery`: when deferred, the caller is
                            // expected to invoke `MARF::drain_pending_plans` after open returns,
                            // so the canonical-sensitive recovery runs against an explicit
                            // policy (TrustPlan or Canonical(view)) instead of inline here.
                            // Byte-level recovery above (torn hot-tail truncation) and the tmp
                            // sweep below are NOT gated — they run regardless because they need
                            // no canonical context and must happen before any reader sees the
                            // file.
                            if !defer_canonical_recovery {
                                let recovery_stats = crate::chainstate::stacks::index::squash_recover::recover_pending_promotions::<T>(
                                    &mut db,
                                    &db_path,
                                    &mut hot_files,
                                    readonly,
                                    None,
                                )?;
                                if recovery_stats.any_plan_processed()
                                    || recovery_stats.cold_tail_truncated_bytes > 0
                                {
                                    info!(
                                        "Phase B promotion recovery: {} plan(s) discovered \
                                         ({} committed, {} abandoned, {} discarded stale, \
                                         {} rewrites applied, {} skipped, \
                                         cold tail truncated by {} bytes)",
                                        recovery_stats.plans_discovered(),
                                        recovery_stats.plans_committed(),
                                        recovery_stats.plans_abandoned(),
                                        recovery_stats.plans_discarded_stale(),
                                        recovery_stats.rewrites_applied,
                                        recovery_stats.rewrites_skipped,
                                        recovery_stats.cold_tail_truncated_bytes,
                                    );
                                    blobs_handle.remap_and_invalidate()?;
                                }
                            }

                            // Sweep stale `squash-nodes-{pid}-{ts}-{seq}.tmp` files left in the
                            // MARF directory by a prior process that crashed mid-squash (before
                            // [`crate::chainstate::stacks::index::squash::NodeStore`] grew its
                            // `Drop` impl, the multi-handle recovery race was reliably leaking
                            // these on every aborted run — multi-GB each, accumulating into
                            // hundreds of GB on a long-running genesis sync). Gated on
                            // `rw_recovery_done` so concurrent openers don't race each other and
                            // can't trip the wrong-PID-still-live edge case (the lock-protected
                            // first-RW-opener path is the only place this runs, and it runs
                            // before any in-process `NodeStore::new` could have been called).
                            if let Some(parent) = std::path::Path::new(&db_path).parent() {
                                match crate::chainstate::stacks::index::squash::cleanup_stale_node_store_tmp_files(parent) {
                                    Ok((removed, bytes)) if removed > 0 => {
                                        info!(
                                            "Squash NodeStore tmp sweep: removed {removed} \
                                             stale file(s) reclaiming {bytes} bytes from {}",
                                            parent.display()
                                        );
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!(
                                            "Squash NodeStore tmp sweep: failed scanning {}: {e}",
                                            parent.display()
                                        );
                                    }
                                }
                            }

                            *rw_done = true;
                        }
                    }

                    blobs_handle.attach_hot_files(hot_files)?;
                }
            }
        }

        debug!(
            "Opened TrieFileStorage {}; external blobs: {}",
            db_path,
            blobs.is_some()
        );

        let cache = BlockCache::new(&marf_opts.cache_strategy);

        let mut data = TrieStorageTransientData::new(T::sentinel(), None, readonly, unconfirmed);
        // Plumb the configured retention from MARFOpenOpts so per-handle
        // reads (`Error::SnapshotTrimmed`) report the deployment's
        // resolved block-count window. Resolved here so callers that match
        // on `Error::SnapshotTrimmed { retention_blocks, .. }` get a value
        // consistent with whichever `MARFOpenOpts` field was actually
        // populated (legacy levels vs new blocks).
        data.squash_root_snapshot_retention_blocks =
            crate::chainstate::stacks::index::squash::resolve_retention_blocks(
                Some(marf_opts.squash_root_snapshot_retention_levels),
                marf_opts.squash_root_snapshot_retention_blocks,
            );

        // Join (or create) the process-wide `SharedSquashState` entry for this db path. Any other
        // independent `MARF::from_path` opens against the same file (e.g. the Stacks 2.x P2P
        // thread's chainstate and the runloop's chainstate both targeting the same headers MARF)
        // will share the Arc with us, so a `refresh_after_squash()` publish on either handle is
        // observable by the other via the generation counter.
        //
        // Sidecar reconcile runs INSIDE the build closure so it fires exactly
        // once per process per db path — bound to the lifetime of the shared
        // state entry. This is load-bearing for correctness: a squash on
        // handle A is a two-step (write file → commit SQL row) operation,
        // and a concurrent open on handle B that runs reconcile mid-window
        // would see "file present, no SQL row" and delete the in-flight
        // sidecar as an orphan. Confining reconcile to the first open per
        // process eliminates the race because no further reconciles can
        // execute concurrently with a squash.
        //
        // Crash-recovery semantics are preserved: when the last handle for a
        // db path is dropped, the registry's `Weak` dies, and the next open
        // re-runs the build closure (and thus reconcile) — picking up any
        // crash-leaked orphan files.
        let shared = {
            let db_for_build = &db;
            let blobs_for_build = blobs.as_ref();
            let db_path_for_reconcile = std::path::PathBuf::from(&db_path);
            shared_squash_state_for(&db_path, || {
                let meta = build_squash_meta_from_sql(db_for_build, blobs_for_build)?;

                // Reconcile the squash root-node sidecar dir against SQL state:
                //   - ignore `.tmp` files because they may belong to an in-flight
                //     sidecar writer on another handle;
                //   - delete any `.dat` files whose level_id has no SQL row, has
                //     `root_sidecar_present=0`, or is `root_sidecar_trimmed=1`
                //     (trimmed sidecar cleanup);
                //   - if any level marked `root_sidecar_present=1 && trimmed=0`
                //     has no on-disk sidecar, raise a corruption error here
                //     rather than letting fork-extension silently fail later.
                // For pure-SQL setups (no external blobs) this is a no-op:
                // sidecars only exist alongside reclaim levels that themselves
                // require external blobs. Readonly opens still run reconcile here
                // because this is the first-open path: the per-process registry
                // serializes us against any concurrent squash, and a readonly
                // first-open is just as valid a startup-cleanup trigger as a
                // read-write one.
                use crate::chainstate::stacks::index::sidecar::{
                    reconcile_squash_sidecars, ExpectedSidecar,
                };
                // Strict per-level lookups: the parallel vectors are
                // sized identically to `meta.levels` by
                // `build_squash_meta_from_sql`. A missing entry would
                // mean `SquashMeta` is internally inconsistent. Surface
                // that as corruption — silently substituting `0` for
                // `blob_offset` would let reconcile misidentify the
                // canonical sidecar (whose path is keyed by blob_offset)
                // as an orphan and unlink it.
                let expected: Vec<ExpectedSidecar> = meta
                    .levels
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        let blob_offset = *meta.level_blob_offsets.get(i).ok_or_else(|| {
                            Error::corruption(&format!(
                                "SquashMeta.level_blob_offsets missing entry for level_idx={i}"
                            ))
                        })?;
                        let present = *meta.root_sidecar_present.get(i).ok_or_else(|| {
                            Error::corruption(&format!(
                                "SquashMeta.root_sidecar_present missing entry for level_idx={i}"
                            ))
                        })?;
                        let trimmed = *meta.root_sidecar_trimmed.get(i).ok_or_else(|| {
                            Error::corruption(&format!(
                                "SquashMeta.root_sidecar_trimmed missing entry for level_idx={i}"
                            ))
                        })?;
                        Ok::<ExpectedSidecar, Error>(ExpectedSidecar {
                            level_id: t.info.level_id,
                            min_height: t.info.min_height,
                            max_height: t.info.max_height,
                            blob_offset,
                            present,
                            trimmed,
                        })
                    })
                    .collect::<Result<_, Error>>()?;
                // When `defer_canonical_recovery` is set, the caller will run
                // `drain_pending_plans` AFTER open returns. The drain may publish a level row
                // whose sidecar currently appears as orphan to this reconcile pass — running
                // reconcile here would unlink that sidecar before drain can validate/use it.
                // So skip reconcile in the deferred path; drain re-runs it after publish.
                if !defer_canonical_recovery {
                    let report = reconcile_squash_sidecars(&db_path_for_reconcile, &expected)?;
                    if report.tmp_orphans_deleted > 0 || report.dat_orphans_deleted > 0 {
                        info!(
                            "MARF squash sidecar reconcile: tmp_orphans_deleted={}, \
                             dat_orphans_deleted={}, dat_kept={}",
                            report.tmp_orphans_deleted, report.dat_orphans_deleted, report.dat_kept,
                        );
                    }

                    // Reconcile the per-level history blob files against SQL
                    // `marf_squash_levels.history_blob_state` per
                    // `.docs/full-history-history-blob-design.md` §9.4 step 4.
                    // Pattern mirrors the root sidecar reconcile above:
                    //   - `'never_written'` row: defensive unlink of any
                    //      canonical history blob file
                    //   - `'present'` row: file MUST exist + pass footer
                    //      validation, else CorruptionError
                    //   - `'trimmed'` row: file MUST be absent; leftover
                    //      gets unlinked (handles §10.2 crash window
                    //      between SQL commit and unlink)
                    //   - tmp `.history-tmp-*.dat` files: unlinked as
                    //      crashed-writer orphans
                    use crate::chainstate::stacks::index::history_blob::{
                        reconcile_history_blobs, ExpectedHistoryBlob,
                    };
                    let marf_dir = db_path_for_reconcile
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    let expected_hb: Vec<ExpectedHistoryBlob> = meta
                        .levels
                        .iter()
                        .enumerate()
                        .map(|(i, t)| {
                            let blob_offset = *meta.level_blob_offsets.get(i).ok_or_else(|| {
                                Error::corruption(&format!(
                                    "SquashMeta.level_blob_offsets missing entry for \
                                         level_idx={i}"
                                ))
                            })?;
                            let state = *meta.level_history_blob_state.get(i).ok_or_else(|| {
                                Error::corruption(&format!(
                                    "SquashMeta.level_history_blob_state missing entry \
                                         for level_idx={i}"
                                ))
                            })?;
                            use crate::chainstate::stacks::index::squash::HistoryBlobState;
                            Ok::<ExpectedHistoryBlob, Error>(ExpectedHistoryBlob {
                                level_id: t.info.level_id,
                                min_height: t.info.min_height,
                                max_height: t.info.max_height,
                                blob_offset,
                                present: matches!(state, HistoryBlobState::Present),
                                trimmed: matches!(state, HistoryBlobState::Trimmed),
                            })
                        })
                        .collect::<Result<_, Error>>()?;
                    let hb_report = reconcile_history_blobs(&marf_dir, &expected_hb)?;
                    if hb_report.tmp_orphans_deleted > 0 || hb_report.dat_orphans_deleted > 0 {
                        info!(
                            "MARF history blob reconcile: tmp_orphans_deleted={}, \
                             dat_orphans_deleted={}, dat_kept={}",
                            hb_report.tmp_orphans_deleted,
                            hb_report.dat_orphans_deleted,
                            hb_report.dat_kept,
                        );
                    }
                }

                Ok(meta)
            })?
        };
        data.squash_meta = shared.snapshot();
        data.shared_squash = shared;
        data.seen_squash_generation = data.shared_squash.generation();
        // Reconstruct the per-MARF squash-work counter from SQL. Cost is
        // O(post-watermark rows) — sub-millisecond in steady state. On a
        // freshly-migrated v3 -> v4 DB where every level's
        // `published_max_block_id = 0`, this sums over the entire
        // `marf_data` table once; the next squash overwrites the watermark
        // and resets the counter to 0.
        data.external_bytes_since_last_squash =
            trie_sql::current_external_bytes_since_last_squash(&db)?;

        let ret = TrieFileStorage {
            db_path,
            db,
            cache,
            blobs,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: marf_opts.hash_calculation_mode,
            compress: marf_opts.compress,
            mmap: marf_opts.mmap,
            _recovery_state: recovery_state,

            data,

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: None,
        };

        Ok(ret)
    }

    #[cfg(test)]
    pub fn new_memory(marf_opts: MARFOpenOpts) -> Result<TrieFileStorage<T>, Error> {
        TrieFileStorage::open(":memory:", marf_opts)
    }

    pub fn open(db_path: &str, marf_opts: MARFOpenOpts) -> Result<TrieFileStorage<T>, Error> {
        TrieFileStorage::open_opts(db_path, false, false, marf_opts)
    }

    pub fn open_readonly(
        db_path: &str,
        marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<T>, Error> {
        TrieFileStorage::open_opts(db_path, true, false, marf_opts)
    }

    pub fn open_unconfirmed(
        db_path: &str,
        mut marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<T>, Error> {
        // no caching allowed for unconfirmed tries, since they can disappear
        marf_opts.cache_strategy = "noop".to_string();
        TrieFileStorage::open_opts(db_path, false, true, marf_opts)
    }

    /// Drain any pending squash promotion plans to a consistent terminal state. Counterpart to
    /// opens that pass [`MARFOpenOpts::with_auto_recovery(false)`]; see
    /// [`crate::chainstate::stacks::index::marf::MARF::drain_pending_plans`] for the user-facing
    /// contract. Lives on `TrieFileStorage` (not on `MARF`) so the implementation has direct
    /// access to the private `db` field; the `MARF::drain_pending_plans` method is a thin
    /// delegation.
    pub fn drain_pending_plans(
        &mut self,
        policy: crate::chainstate::stacks::index::squash_recover::DrainPolicy<'_>,
    ) -> Result<crate::chainstate::stacks::index::squash_recover::DrainStats, Error> {
        use crate::chainstate::stacks::index::squash_recover::{
            CanonicalView, DrainPolicy, DrainStats,
        };

        let canonical_view: Option<&dyn CanonicalView> = match &policy {
            DrainPolicy::TrustPlan => None,
            DrainPolicy::Canonical(view) => Some(*view),
        };

        let Some(blobs_handle) = self.blobs.as_mut() else {
            // RAM-backed storage has no on-disk plans to recover.
            return Ok(DrainStats::default());
        };
        let Some(hot_files) = blobs_handle.hot_files_mut() else {
            // Non-disk TrieFile: same situation as above.
            return Ok(DrainStats::default());
        };

        let drain_stats =
            crate::chainstate::stacks::index::squash_recover::recover_pending_promotions::<T>(
                &mut self.db,
                &self.db_path,
                hot_files,
                self.data.readonly,
                canonical_view,
            )?;

        if drain_stats.any_plan_processed() || drain_stats.cold_tail_truncated_bytes > 0 {
            info!(
                "Phase B promotion drain: {} plan(s) discovered \
                 ({} committed, {} abandoned, {} discarded stale, {} rewrites applied, \
                 {} skipped, cold tail truncated by {} bytes)",
                drain_stats.plans_discovered(),
                drain_stats.plans_committed(),
                drain_stats.plans_abandoned(),
                drain_stats.plans_discarded_stale(),
                drain_stats.rewrites_applied,
                drain_stats.rewrites_skipped,
                drain_stats.cold_tail_truncated_bytes,
            );
            blobs_handle.remap_and_invalidate()?;
        }

        // Reconcile the squash sidecar directory now that drain has finished publishing or
        // abandoning plans. The `open_opts` path with `auto_recovery=false` skipped this step to
        // avoid unlinking the sidecar of a yet-to-be-published level; with that decision now
        // resolved, run the reconcile against the up-to-date `marf_squash_levels` state. Mirrors
        // the post-build reconcile call inside `open_opts`'s auto-recovery path.
        if drain_stats.any_plan_processed() {
            // Recovery published or abandoned plans → SquashMeta is stale. Rebuild before
            // reconcile so the expected-sidecar list reflects post-recovery SQL state.
            self.refresh_after_squash()?;
        }

        {
            use crate::chainstate::stacks::index::sidecar::{
                reconcile_squash_sidecars, ExpectedSidecar,
            };
            let meta = &self.data.squash_meta;
            let expected: Vec<ExpectedSidecar> = meta
                .levels
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let blob_offset = *meta.level_blob_offsets.get(i).ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.level_blob_offsets missing entry for level_idx={i}"
                        ))
                    })?;
                    let present = *meta.root_sidecar_present.get(i).ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.root_sidecar_present missing entry for level_idx={i}"
                        ))
                    })?;
                    let trimmed = *meta.root_sidecar_trimmed.get(i).ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.root_sidecar_trimmed missing entry for level_idx={i}"
                        ))
                    })?;
                    Ok::<ExpectedSidecar, Error>(ExpectedSidecar {
                        level_id: t.info.level_id,
                        min_height: t.info.min_height,
                        max_height: t.info.max_height,
                        blob_offset,
                        present,
                        trimmed,
                    })
                })
                .collect::<Result<_, Error>>()?;
            let db_path_for_reconcile = std::path::PathBuf::from(&self.db_path);
            let report = reconcile_squash_sidecars(&db_path_for_reconcile, &expected)?;
            if report.tmp_orphans_deleted > 0 || report.dat_orphans_deleted > 0 {
                info!(
                    "MARF squash sidecar reconcile (post-drain): tmp_orphans_deleted={}, \
                     dat_orphans_deleted={}, dat_kept={}",
                    report.tmp_orphans_deleted, report.dat_orphans_deleted, report.dat_kept,
                );
            }

            // Mirror the post-drain history-blob reconcile that the
            // normal open path runs alongside the sidecar reconcile.
            // Without this, deferred recovery would leave `present`
            // history blobs unvalidated and `trimmed`/orphan files
            // unswept until the next ordinary open. Same dispatch
            // (per design doc §9.4 step 4): present → footer-validate,
            // trimmed → unlink leftover, never_written → defensive unlink.
            use crate::chainstate::stacks::index::history_blob::{
                reconcile_history_blobs, ExpectedHistoryBlob,
            };
            use crate::chainstate::stacks::index::squash::HistoryBlobState;
            let marf_dir = db_path_for_reconcile
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let expected_hb: Vec<ExpectedHistoryBlob> = meta
                .levels
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let blob_offset = *meta.level_blob_offsets.get(i).ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.level_blob_offsets missing entry for level_idx={i}"
                        ))
                    })?;
                    let state = *meta.level_history_blob_state.get(i).ok_or_else(|| {
                        Error::corruption(&format!(
                            "SquashMeta.level_history_blob_state missing entry for level_idx={i}"
                        ))
                    })?;
                    Ok::<ExpectedHistoryBlob, Error>(ExpectedHistoryBlob {
                        level_id: t.info.level_id,
                        min_height: t.info.min_height,
                        max_height: t.info.max_height,
                        blob_offset,
                        present: matches!(state, HistoryBlobState::Present),
                        trimmed: matches!(state, HistoryBlobState::Trimmed),
                    })
                })
                .collect::<Result<_, Error>>()?;
            let hb_report = reconcile_history_blobs(&marf_dir, &expected_hb)?;
            if hb_report.tmp_orphans_deleted > 0 || hb_report.dat_orphans_deleted > 0 {
                info!(
                    "MARF history blob reconcile (post-drain): tmp_orphans_deleted={}, \
                     dat_orphans_deleted={}, dat_kept={}",
                    hb_report.tmp_orphans_deleted,
                    hb_report.dat_orphans_deleted,
                    hb_report.dat_kept,
                );
            }
        }

        Ok(drain_stats)
    }

    pub fn readonly(&self) -> bool {
        self.data.readonly
    }

    /// Return true if this storage connection was opened with the intention of operating on an
    /// unconfirmed trie -- i.e. this is a storage connection for reading and writing a persisted
    /// scratch space trie, such as one for storing unconfirmed microblock transactions in the
    /// chain state.
    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    /// Returns true if there are uncommitted writes in the storage.
    pub fn has_uncommitted_writes(&self) -> bool {
        self.data.uncommitted_writes.is_some()
    }

    /// Returns a new TrieFileStorage in read-only mode.
    ///
    /// Returns Err if the underlying SQLite database connection cannot be created.
    pub fn reopen_readonly(&self) -> Result<TrieFileStorage<T>, Error> {
        trace!("Make read-only view of TrieFileStorage: {}", &self.db_path);

        // TODO: borrow self.uncommitted_writes; don't copy them
        let data = TrieStorageTransientData {
            uncommitted_writes: self.data.uncommitted_writes.clone(),
            // Share the source-of-truth squash state with the parent so
            // future `publish` calls are observable by this handle.
            squash_meta: Arc::clone(&self.data.squash_meta),
            shared_squash: Arc::clone(&self.data.shared_squash),
            seen_squash_generation: self.data.seen_squash_generation,
            ..TrieStorageTransientData::new(
                self.data.cur_block.clone(),
                self.data.cur_block_id,
                true,
                self.unconfirmed(),
            )
        };

        build_readonly_storage(
            &self.db_path,
            self.blobs.is_some(),
            self.hash_calculation_mode,
            self.compress,
            self.mmap,
            data,
            #[cfg(test)]
            self.test_genesis_block.clone(),
        )
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }
}

/// Build a fresh read-only `TrieFileStorage` from the given path and pre-constructed
/// transient data. Both `reopen_readonly` implementations delegate here so the
/// open-DB / open-blobs / construct-struct pattern lives in one place.
///
/// Disk-backed blobs always get a [`HotFileSet`] attached in readonly mode (no creation,
/// no truncation) so reads of `storage_kind = Hot` rows resolve correctly. RAM-backed
/// blobs and pure-SQL backends skip the attachment.
fn build_readonly_storage<T: MarfTrieId>(
    db_path: &str,
    blobs_active: bool,
    hash_calculation_mode: TrieHashCalculationMode,
    compress: bool,
    mmap: bool,
    data: TrieStorageTransientData<T>,
    #[cfg(test)] test_genesis_block: Option<T>,
) -> Result<TrieFileStorage<T>, Error> {
    // Hold a recovery state ref for this readonly handle's lifetime so the live count in
    // [`recovery_registry`] reflects this opener too. Readonly opens never touch
    // `rw_recovery_done` (they don't run the truncate-on-startup that owns that flag), so a
    // readonly-first ordering still leaves a later RW opener observing `rw_recovery_done = false`
    // and running the cleanup. See [`recovery_state_for`].
    let recovery_state = recovery_state_for(db_path);
    let db = marf_sqlite_open(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
    let mut blobs = if blobs_active {
        Some(TrieFile::from_db_path(db_path, true, mmap)?)
    } else {
        None
    };
    if let Some(blobs_handle) = blobs.as_mut() {
        if matches!(blobs_handle, TrieFile::Disk(_)) {
            let hot_files = crate::chainstate::stacks::index::hot_file::HotFileSet::open(
                db_path,
                &db,
                mmap,
                crate::chainstate::stacks::index::hot_file::DEFAULT_HOT_FILE_ROTATION_THRESHOLD_BYTES,
                /* readonly = */ true,
            )?;
            blobs_handle.attach_hot_files(hot_files)?;
        }
    }
    let cache = BlockCache::default();
    Ok(TrieFileStorage {
        db_path: db_path.to_string(),
        db,
        blobs,
        cache,
        bench: TrieBenchmark::new(),
        hash_calculation_mode,
        compress,
        mmap,
        _recovery_state: recovery_state,
        data,
        #[cfg(test)]
        test_genesis_block,
    })
}

impl<'a, T: MarfTrieId> TrieStorageConnection<'a, T, Transaction<'a>> {
    /// reopen this transaction as a read-only marf.
    ///  _does not_ preserve the cur_block/open tip
    pub fn reopen_readonly(&self) -> Result<TrieFileStorage<T>, Error> {
        trace!(
            "Make read-only view of TrieStorageTransaction: {}",
            &self.db_path
        );

        let data = TrieStorageTransientData {
            squash_meta: Arc::clone(&self.data.squash_meta),
            shared_squash: Arc::clone(&self.data.shared_squash),
            seen_squash_generation: self.data.seen_squash_generation,
            ..TrieStorageTransientData::new(T::sentinel(), None, true, self.unconfirmed())
        };
        build_readonly_storage(
            self.db_path,
            self.blobs.is_some(),
            self.hash_calculation_mode,
            self.compress,
            self.mmap,
            data,
            #[cfg(test)]
            self.test_genesis_block.clone(),
        )
    }

    /// Run `cls` with a mutable reference to the inner trie blobs opt.
    fn with_trie_blobs<F, R>(&mut self, cls: F) -> R
    where
        F: FnOnce(&Connection, &mut Option<&mut TrieFile>) -> R,
    {
        let mut blobs = self.blobs.take();
        let res = cls(&self.db, &mut blobs);
        self.blobs = blobs;
        res
    }

    /// Inner method for flushing the UncommittedState's TrieRAM to disk.
    fn inner_flush(&mut self, flush_options: FlushOptions<'_, T>) -> Result<(), Error> {
        // save the currently-buffered Trie to disk, and atomically put it into place (possibly to
        // a different block than the one opened, as indicated by final_bhh).
        // Runs once -- subsequent calls are no-ops.
        // Panics on a failure to rename the Trie file into place (i.e. if the actual commitment
        // fails).
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.readonly {
            return Err(Error::ReadOnlyError);
        }
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            trace!("Buffering block flush started.");

            // Enable MARF compression only when:
            // - Compression is explicitly requested, and
            // - The flush option is *not* `FlushOptions::UnconfirmedTable`, which is used when
            //   writing an unconfirmed trie for Stacks 2.x.
            //
            //   Compression is intentionally disabled for unconfirmed tries to avoid regressions
            //   in `TrieRAM::load`, which is responsible for loading these unconfirmed structures.
            let marf_compression_enabled =
                self.compress && !matches!(flush_options, FlushOptions::UnconfirmedTable);

            let mut cursor = Cursor::new(Vec::new());
            if marf_compression_enabled {
                trie_ram.dump_compressed(self, &mut cursor, &bhh)?;
            } else {
                trie_ram.dump(self, &mut cursor, &bhh)?;
            }
            let buffer = cursor.into_inner();

            trace!("Buffering block flush finished.");
            debug!("Flush: {} to {}", &bhh, flush_options);

            // Per-MARF squash-work counter increment is gated on the
            // FlushOptions variant: only `CurrentHeader` / `NewHeader` produce
            // confirmed `marf_data` rows that the next squash will absorb.
            // `MinedTable` writes go to `mined_blocks`; `UnconfirmedTable`
            // writes go to the unconfirmed-trie path. Neither belongs in
            // the squash work measurement. Additionally, inline-blob
            // backends (`blobs.is_none()`) record `external_length = 0`,
            // so they contribute nothing to squash blob bytes — skip the
            // increment to match the SQL reconstruction path.
            let increments_squash_counter = matches!(
                flush_options,
                FlushOptions::CurrentHeader | FlushOptions::NewHeader(_),
            ) && self.blobs.is_some();
            let buffer_len = buffer.len() as u64;
            let block_id = match flush_options {
                FlushOptions::CurrentHeader => {
                    if self.unconfirmed() {
                        return Err(Error::UnconfirmedError);
                    }
                    self.with_trie_blobs(|db, blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(db, &bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {bhh} to db");
                            trie_sql::write_trie_blob(db, &bhh, &buffer)
                        }
                    })?
                }
                FlushOptions::NewHeader(real_bhh) => {
                    // If we opened a block with a given hash, but want to store it as a block with a *different*
                    // hash, then call this method to update the internal storage state to make it so.  This is
                    // necessary for validating blocks in the blockchain, since the miner will always build a
                    // block whose hash is all 0's (since it can't know the final block hash).  As such, a peer
                    // will process a block as if it's hash is all 0's (in order to validate the state root), and
                    // then use this method to switch over the block hash to the "real" block hash.
                    if self.data.unconfirmed {
                        return Err(Error::UnconfirmedError);
                    }

                    let new_block_id = self.with_trie_blobs(|db, blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(db, real_bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {} to db", real_bhh);
                            trie_sql::write_trie_blob(db, real_bhh, &buffer)
                        }
                    })?;
                    self.data.set_block(real_bhh.clone(), Some(new_block_id));
                    new_block_id
                }
                FlushOptions::MinedTable(real_bhh) => {
                    if self.unconfirmed() {
                        return Err(Error::UnconfirmedError);
                    }
                    trie_sql::write_trie_blob_to_mined(&self.db, real_bhh, &buffer)?
                }
                FlushOptions::UnconfirmedTable => {
                    if !self.unconfirmed() {
                        return Err(Error::UnconfirmedError);
                    }
                    trie_sql::write_trie_blob_to_unconfirmed(&self.db, &bhh, &buffer)?
                }
            };
            if increments_squash_counter {
                self.data.external_bytes_since_last_squash = self
                    .data
                    .external_bytes_since_last_squash
                    .saturating_add(buffer_len);
            }

            trie_sql::drop_lock(&self.db, &bhh)?;

            debug!("Flush: identifier of {} is {}", flush_options, block_id);
        }

        Ok(())
    }

    /// Flush uncommitted state to disk.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.data.unconfirmed {
            self.inner_flush(FlushOptions::UnconfirmedTable)
        } else {
            self.inner_flush(FlushOptions::CurrentHeader)
        }
    }

    /// Flush uncommitted state to disk, but under the given block hash.
    pub fn flush_to(&mut self, bhh: &T) -> Result<(), Error> {
        self.inner_flush(FlushOptions::NewHeader(bhh))
    }

    /// Flush uncommitted state to disk for a mined block (i.e. not part of the chainstate, and not
    /// an ancestor of any block), and do so under a given block hash.
    pub fn flush_mined(&mut self, bhh: &T) -> Result<(), Error> {
        self.inner_flush(FlushOptions::MinedTable(bhh))
    }

    /// Drop the uncommitted state and any associated cached state.
    pub fn drop_extending_trie(&mut self) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.readonly {
            if let Some((ref bhh, _)) = self.data.uncommitted_writes.take() {
                trie_sql::drop_lock(&self.db, bhh)
                    .expect("Corruption: Failed to drop the extended trie lock");
            }
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Drop the unconfirmed state and uncommitted state.
    pub fn drop_unconfirmed_trie(&mut self, bhh: &T) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.readonly && self.data.unconfirmed {
            trie_sql::drop_unconfirmed_trie(&self.db, bhh)
                .expect("Corruption: Failed to drop unconfirmed trie");
            trie_sql::drop_lock(&self.db, bhh)
                .expect("Corruption: Failed to drop the extended trie lock");
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Seal the inner uncommitted TrieRAM and return the MARF root hash.
    /// Only works if there's an uncommitted TrieRAM extension; panics if not.
    pub fn seal(&mut self) -> Result<TrieHash, Error> {
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            let sealed_trie_ram = trie_ram.seal(self)?;
            let root_hash = match &sealed_trie_ram {
                UncommittedState::Sealed(_, root_hash) => *root_hash,
                _ => {
                    unreachable!("FATAL: .seal() did not make a sealed trieram");
                }
            };
            self.data.uncommitted_writes = Some((bhh, sealed_trie_ram));
            Ok(root_hash)
        } else {
            panic!("FATAL: tried to a .seal() a trie that was not extended");
        }
    }

    /// Extend the forest of Tries to include a new confirmed block.
    /// Fails if the block already exists, or if the storage is read-only, or open
    /// only for unconfirmed state.
    pub fn extend_to_block(&mut self, bhh: &T) -> Result<(), Error> {
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.readonly {
            return Err(Error::ReadOnlyError);
        }
        if self.data.unconfirmed {
            return Err(Error::UnconfirmedError);
        }

        if self.get_block_id_caching(bhh).is_ok() {
            warn!("Block already exists: {}", &bhh);
            return Err(Error::ExistsError);
        }

        self.flush()?;

        let size_hint = match self.data.uncommitted_writes {
            Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
            None => 1024, // don't try to guess _byte_ allocation here.
        };

        let trie_buf = TrieRAM::new(bhh, size_hint, &self.data.cur_block);

        // place a lock on this block, so we can't extend to it again
        if !trie_sql::lock_bhh_for_extension(self.sqlite_tx(), bhh, false)? {
            warn!("Block already extended: {}", &bhh);
            return Err(Error::ExistsError);
        }

        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(())
    }

    /// Extend the forest of Tries to include a new unconfirmed block.
    /// If the unconfirmed block (bhh) already exists, then load up its trie as the uncommitted_writes
    /// trie.
    pub fn extend_to_unconfirmed_block(&mut self, bhh: &T) -> Result<bool, Error> {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.unconfirmed {
            return Err(Error::UnconfirmedError);
        }

        self.flush()?;

        // try to load up the trie
        let (trie_buf, created, unconfirmed_block_id) =
            if let Some(block_id) = trie_sql::get_unconfirmed_block_identifier(&self.db, bhh)? {
                debug!("Reload unconfirmed trie {} ({})", bhh, block_id);

                // restore trie
                let mut fd = trie_sql::open_trie_blob(&self.db, block_id)?;

                test_debug!("Unconfirmed trie block ID for {} is {}", bhh, block_id);
                (TrieRAM::load(&mut fd, bhh)?, false, Some(block_id))
            } else {
                debug!("Instantiate unconfirmed trie {}", bhh);

                // new trie
                let size_hint = match self.data.uncommitted_writes {
                    Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
                    None => 1024, // don't try to guess _byte_ allocation here.
                };

                (
                    TrieRAM::new(bhh, size_hint, &self.data.cur_block),
                    true,
                    None,
                )
            };

        // place a lock on this block, so we can't extend to it again
        if !trie_sql::tx_lock_bhh_for_extension(&self.db, bhh, true)? {
            warn!("Block already extended: {}", &bhh);
            return Err(Error::ExistsError);
        }

        self.data.unconfirmed_block_id = unconfirmed_block_id;
        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(created)
    }

    /// Clear out the underlying storage.
    pub fn format(&mut self) -> Result<(), Error> {
        if self.data.readonly {
            return Err(Error::ReadOnlyError);
        }

        debug!("Format TrieFileStorage");

        // blow away db
        trie_sql::clear_tables(self.sqlite_tx())?;

        if let Some((_, ref mut trie_storage)) = self.data.uncommitted_writes {
            trie_storage.format()?
        };

        self.data.set_block(T::sentinel(), None);

        self.data.uncommitted_writes = None;
        self.clear_cached_ancestor_hashes_bytes();

        Ok(())
    }

    pub fn sqlite_tx(&self) -> &Transaction<'a> {
        &self.db
    }

    pub fn sqlite_tx_mut(&mut self) -> &mut Transaction<'a> {
        &mut self.db
    }

    pub fn commit_tx(self) {
        self.db.commit().expect("CORRUPTION: Failed to commit MARF");
    }

    pub fn rollback(self) {
        self.db
            .rollback()
            .expect("CORRUPTION: Failed to rollback MARF");
    }
}

impl<'a, T: MarfTrieId, Db: Deref<Target = Connection>> TrieStorageConnection<'a, T, Db> {
    pub fn readonly(&self) -> bool {
        self.data.readonly
    }

    /// Run `f` with the read path's [`WalkIntent`] set to [`WalkIntent::ForkExtend`], then
    /// restore the previous intent. Used by
    /// [`crate::chainstate::stacks::index::marf::MARF::root_copy`] (the only legitimate
    /// caller) so reads inside its body resolve `ROOT_PTR_DISK` against the per-height
    /// root sidecar — required to reconstruct the historical root shape for fork-extension.
    ///
    /// **Panic safety.** Uses an RAII `Drop` guard so the previous intent is restored even
    /// if `f` unwinds. The guard owns a `&mut TrieStorageConnection`; we hand `f` a fresh
    /// re-borrow through the guard, so the guard's `Drop` impl reliably runs after `f`
    /// returns (or unwinds), restoring `walk_intent`. No `catch_unwind` overhead on this
    /// hot path: `MARF::root_copy` runs on every fork-extending block construction.
    pub fn with_fork_extend_intent<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        struct IntentGuard<'a, 'b, T: MarfTrieId, Db: Deref<Target = Connection>> {
            storage: &'a mut TrieStorageConnection<'b, T, Db>,
            prev: WalkIntent,
        }
        impl<T: MarfTrieId, Db: Deref<Target = Connection>> Drop for IntentGuard<'_, '_, T, Db> {
            fn drop(&mut self) {
                self.storage.data.walk_intent = self.prev;
            }
        }
        let prev = self.data.walk_intent;
        self.data.walk_intent = WalkIntent::ForkExtend;
        let guard = IntentGuard {
            storage: self,
            prev,
        };
        // Reborrow mutably through the guard's owned `&mut`: `guard.storage` already has
        // type `&mut TrieStorageConnection`, so `&mut *guard.storage` is a fresh reborrow
        // that's released by the time the statement ends, leaving the guard's `Drop` impl
        // free to run after `f` returns or unwinds.
        f(&mut *guard.storage)
    }

    /// **Test-only** mutable accessor for the attached hot-file set, used by integration tests
    /// to override the default 1 GiB rotation threshold so a test can rotate cheaply. Returns
    /// `None` when the handle is RAM-backed (RAM handles never carry a [`HotFileSet`]).
    #[cfg(test)]
    pub fn hot_files_mut(
        &mut self,
    ) -> Option<&mut crate::chainstate::stacks::index::hot_file::HotFileSet> {
        self.blobs.as_deref_mut().and_then(|b| b.hot_files_mut())
    }

    /// Detect whether a writer has published a new [`SquashMeta`] since this
    /// handle last synced, and if so re-snapshot the shared metadata and
    /// invalidate the handle-local blob mmap + block cache + current-block
    /// context.
    ///
    /// Fast-path: a single atomic load with no lock, no SQL, no trailer
    /// parsing. Only the slow path (generation mismatch) acquires the
    /// RwLock read guard to snapshot the fresh metadata, and reconstructs
    /// this handle's per-MARF squash-work counter from SQL — so [`MARF::stats`]
    /// stays authoritative on peer / reopened read-only handles after
    /// another handle publishes a squash.
    fn sync_shared_squash_state(&mut self) -> Result<(), Error> {
        sync_from_shared_squash_state(self.data, self.blobs.as_deref_mut(), self.cache, &*self.db)
    }

    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    /// If the currently-open block sits inside a redirected squash level,
    /// read its per-height root node body from the level's sidecar file
    /// and return it (post-remap, no hash prefix). Decode via
    /// [`crate::chainstate::stacks::index::bits::decode_nodetype_from_slice_at_head`].
    ///
    /// Returns `Ok(None)` when the currently-open block is not in any
    /// squash level, or when it's in a no-reclaim/append-only squash
    /// level whose original blob still serves the per-block root via
    /// `ROOT_PTR_DISK`.
    ///
    /// **Lifecycle.** The sidecar file is opened, its header validated,
    /// its index parsed, and the requested body read — all on each call.
    /// PR 1 deliberately avoids caching open file handles or parsed
    /// indexes; the fork-extension code path is rare (one call per
    /// fork-from-squashed-parent, not per read), so the open-read-close
    /// per call is fine. Iteration 2 may add a small bounded LRU index
    /// cache if profiling shows it matters.
    ///
    /// **Fails closed.** A redirected level whose SQL row carries
    /// `root_sidecar_present = 1` MUST have its sidecar file on disk and
    /// readable; if it doesn't, we surface a corruption error rather
    /// than silently fall back to `Trie::read_root` (which on a
    /// redirected blob returns the merged-tip's root, reintroducing the
    /// bug this fix addresses). PR 2 will introduce a distinct
    /// "trimmed-by-policy" error path; in PR 1 a missing-or-trimmed
    /// sidecar always reports as corruption.
    ///
    /// Used by `MARF::root_copy` so that fork-extending a non-tip squashed
    /// block reconstructs the parent's actual root shape rather than
    /// reading the merged tip's root.
    pub fn squash_opened_root_node_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        use crate::chainstate::stacks::index::sidecar::{
            squash_root_sidecar_path, RecordKind, SidecarExpectation, SidecarReader,
        };

        let Some(height) = self.data.squash_opened_height else {
            return Ok(None);
        };
        let Some(level_idx) = self.data.squash_opened_level_idx else {
            return Ok(None);
        };
        if !self.data.leaf_hashes_omitted {
            // No-reclaim / append-only level: the original per-block blob
            // still serves the correct per-block root via `ROOT_PTR_DISK`.
            // No saved snapshot is required (or written).
            return Ok(None);
        }
        let level = self.data.squash_meta.levels.get(level_idx).ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash_opened_level_idx={level_idx} but SquashMeta has no matching level"
            ))
        })?;
        let trimmed = self
            .data
            .squash_meta
            .root_sidecar_trimmed
            .get(level_idx)
            .copied()
            .unwrap_or(false);
        let present = self
            .data
            .squash_meta
            .root_sidecar_present
            .get(level_idx)
            .copied()
            .unwrap_or(false);
        if trimmed {
            // Expected outcome: this level was trimmed by the retention
            // policy. Surface the dedicated `SnapshotTrimmed` variant so
            // higher layers can convert it into a chainstate-level
            // rejection (don't treat as corruption).
            return Err(Error::SnapshotTrimmed {
                level_id: level.info.level_id,
                retention_blocks: self.data.squash_root_snapshot_retention_blocks,
            });
        }
        if !present {
            // Level predates the sidecar feature: its merged blob doesn't
            // contain the per-block root snapshots and there's no path
            // forward without a re-squash.
            return Err(Error::UnsupportedLegacyLevel {
                level_id: level.info.level_id,
            });
        }

        // Compute the sidecar path from the level's `(level_id,
        // min_height, max_height, blob_offset)` tuple. Including
        // `blob_offset` in the path makes each Replace publish land at
        // a unique path: the new active sidecar at the new
        // `blob_offset`'s path, the retired predecessor untouched at
        // its old `blob_offset`'s path. Both rows resolve their
        // sidecars unambiguously without retired-specific dispatch.
        let level_blob_offset = self
            .data
            .squash_meta
            .level_blob_offsets
            .get(level_idx)
            .copied()
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "squash_opened_root_node_bytes: level_idx {level_idx} \
                     out of range for level_blob_offsets ({})",
                    self.data.squash_meta.level_blob_offsets.len()
                ))
            })?;
        let sidecar_path = squash_root_sidecar_path(
            std::path::Path::new(self.db_path),
            level.info.level_id,
            level.info.min_height,
            level.info.max_height,
            level_blob_offset,
        );

        info!(
            "squash_opened_root_node_bytes: db_path={} level_id={} heights=[{}..={}] height={height} reading {}",
            self.db_path,
            level.info.level_id,
            level.info.min_height,
            level.info.max_height,
            sidecar_path.display(),
        );

        // If the file is missing, dump the parent dir contents and the raw
        // SQL view of `marf_squash_levels` so we can see whether the
        // disagreement is "writer never wrote", "trim/reconcile deleted",
        // or "stale SQL pointing at wrong identity tuple".
        if !sidecar_path.exists() {
            error!(
                "squash_opened_root_node_bytes: sidecar MISSING at {} \
                 (level_id={}, heights=[{}..={}], present={}, trimmed={})",
                sidecar_path.display(),
                level.info.level_id,
                level.info.min_height,
                level.info.max_height,
                present,
                trimmed,
            );
            if let Some(parent) = sidecar_path.parent() {
                match std::fs::read_dir(parent) {
                    Ok(entries) => {
                        let names: Vec<String> = entries
                            .filter_map(|e| e.ok())
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect();
                        error!(
                            "squash_opened_root_node_bytes: parent dir {} contains: [{}]",
                            parent.display(),
                            names.join(", "),
                        );
                    }
                    Err(e) => {
                        error!(
                            "squash_opened_root_node_bytes: cannot read parent dir {}: {e}",
                            parent.display(),
                        );
                    }
                }
            }
        }

        // Open + validate file header + section table. Pass the level's
        // identity tuple and require the SquashRootNode section so a
        // stale or corrupt sidecar with the right `level_id` but wrong
        // height range can't serve the wrong slot's body. The sidecar's
        // file lifetime is independent of the squash blob's truncate
        // window, so no blob-read-guard interaction is needed here.
        let mut reader = SidecarReader::open(
            &sidecar_path,
            SidecarExpectation {
                level_id: Some(level.info.level_id),
                min_height: Some(level.info.min_height),
                max_height: Some(level.info.max_height),
                require_section: Some(RecordKind::SquashRootNode),
            },
        )?;
        let body = reader.read_body_at_height(height)?.ok_or_else(|| {
            Error::CorruptionError(format!(
                "Sidecar for level_id={} (heights [{}..={}]) does not contain a record \
                 for height={height}",
                level.info.level_id, level.info.min_height, level.info.max_height,
            ))
        })?;
        Ok(Some(body))
    }

    /// Resolve a `ROOT_PTR_DISK` read against the per-height root saved in the
    /// `SquashRootNode` sidecar section. Returns:
    ///
    /// * `Ok(None)` — `ptr.ptr() != ROOT_PTR_DISK`, or the currently-opened block isn't in a
    ///   reclaim-squash level (`squash_opened_root_node_bytes` returned `None`). Callers should
    ///   fall through to the normal read path.
    /// * `Ok(Some((stored_id, body, hash)))` — the saved root is present and its trailer hash
    ///   resolved cleanly. `stored_id` is decoded from the body's leading byte; `body` is the
    ///   full saved bytes (caller decodes into its own scratch); `hash` is the per-height root
    ///   hash from the squash trailer.
    /// * `Err(CorruptionError)` — metadata drift: sidecar body present but `squash_opened_*`
    ///   state, the `SquashMeta` level entry, or the trailer's per-height hash is missing.
    ///   Surfaced (rather than fabricated as a zero hash or hashless node) so wrong-but-plausible
    ///   reads can't propagate through the read pipeline.
    ///
    /// **Why this exists.** `read_node_with_state`, `read_node_type_id`, and `MARF::root_copy`
    /// (and historically `read_node_hash`'s ROOT_PTR_DISK fast-path) all need to short-circuit a
    /// `ROOT_PTR_DISK` read against an in-range squashed block's per-height root rather than
    /// indexing into the merged blob at offset 36 (which would return the merged TIP's root).
    /// Centralizing the resolution here keeps the four call sites consistent and lets the
    /// fail-closed contract live in one place.
    pub(crate) fn resolve_squash_root_via_sidecar(
        &self,
        ptr: &TriePtr,
    ) -> Result<Option<(TrieNodeID, Vec<u8>, TrieHash)>, Error> {
        if ptr.ptr() != ROOT_PTR_DISK {
            return Ok(None);
        }
        let Some(body) = self.squash_opened_root_node_bytes()? else {
            return Ok(None);
        };
        let head = *body.first().ok_or_else(|| {
            Error::CorruptionError("squash sidecar per-height root body is empty".into())
        })?;
        let stored_id = TrieNodeID::from_u8(clear_ctrl_bits(head)).ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash sidecar per-height root: unknown stored node id {}",
                clear_ctrl_bits(head)
            ))
        })?;
        let height = self.data.squash_opened_height.ok_or_else(|| {
            Error::CorruptionError(
                "ROOT_PTR_DISK fast-path: `squash_opened_root_node_bytes` returned bytes but \
                 `squash_opened_height` is unset"
                    .into(),
            )
        })?;
        let level_idx = self.data.squash_opened_level_idx.ok_or_else(|| {
            Error::CorruptionError(
                "ROOT_PTR_DISK fast-path: `squash_opened_root_node_bytes` returned bytes but \
                 `squash_opened_level_idx` is unset"
                    .into(),
            )
        })?;
        let level = self.data.squash_meta.levels.get(level_idx).ok_or_else(|| {
            Error::CorruptionError(format!(
                "ROOT_PTR_DISK fast-path: SquashMeta has no level at idx {level_idx}"
            ))
        })?;
        let hash = level.root_hash_at(height).copied().ok_or_else(|| {
            Error::CorruptionError(format!(
                "ROOT_PTR_DISK fast-path: trailer for level_idx={level_idx} has no root hash \
                 for height={height} (metadata drift — sidecar body present but trailer entry \
                 missing)"
            ))
        })?;
        Ok(Some((stored_id, body, hash)))
    }

    /// PR2 read-path overlay: if the currently-opened block is in a
    /// squashed level whose orphan-section sidecar exists, and `ptr.ptr()`
    /// addresses an orphan byte (`>= orphan_split_offset`), read up to
    /// `max_node_byte_len(ptr.id())` bytes from the orphan section and
    /// return them. Returns `Ok(None)` if `ptr` is tip-reachable (or the
    /// block is not in a squashed level) so the caller falls through to
    /// its existing merged-blob read path.
    ///
    /// Lazy-opens the sidecar handle on first use per opened block;
    /// `set_block` clears the cache so a subsequent `open_block` to a
    /// different level forces a re-open.
    ///
    /// **Publish/generation protocol.** Orphan reads acquire the same
    /// `BlobReadGuard` and freshness check that merged-blob reads use,
    /// so a publish (including trim's metadata-republish step) cannot
    /// race an in-flight read: publishers wait for `active_reads` to
    /// drain before mutating SQL state, and a stale generation here
    /// surfaces as `RetryAfterSquash`, which the MARF-level retry
    /// wrapper turns into a re-sync followed by a re-walk against the
    /// fresh metadata. Without this guard a stale connection could
    /// keep an `OrphanSidecarHandle` open and serve bytes after the
    /// level was trimmed by a peer handle's publish. `bypass_blob_guard`
    /// (squash-internal use only) skips both the acquire and the
    /// freshness check, mirroring the merged-blob primitives.
    ///
    /// Returns `Error::SnapshotTrimmed` if the level's sidecar has been
    /// trimmed and the caller is trying to follow an orphan ptr — by
    /// invariant, tip reads against the merged tip never trigger this
    /// branch, so reaching it on a trimmed level means the caller is
    /// fork-extending or otherwise descending from a per-height root,
    /// which is the documented post-trim contract.
    fn try_read_orphan_bytes(&mut self, ptr: &TriePtr) -> Result<Option<Vec<u8>>, Error> {
        let Some(level_idx) = self.data.squash_opened_level_idx else {
            return Ok(None);
        };
        let split = self
            .data
            .squash_meta
            .orphan_split_offset
            .get(level_idx)
            .copied()
            .unwrap_or(0);
        if split == 0 || ptr.ptr() < split {
            return Ok(None);
        }

        // Acquire the publish/quiesce guard before any cache use or
        // pread, and verify the generation hasn't drifted since
        // `open_block` synced. Held for the rest of this function so
        // no concurrent publish can mutate metadata or trim the sidecar
        // mid-read. Stale generation → `RetryAfterSquash`; the
        // MARF-level retry wrapper handles the re-sync (which clears
        // `orphan_sidecar` via `set_block`) and re-walks against the
        // fresh metadata.
        let _orphan_guard = if !self.data.bypass_blob_guard {
            let guard = self
                .data
                .shared_squash
                .try_acquire_blob_read()
                .ok_or(Error::RetryAfterSquash)?;
            if !self
                .data
                .shared_squash
                .squash_state_fresh(self.data.seen_squash_generation)
            {
                // Drop the now-stale cache so the post-resync retry
                // doesn't reuse a handle into a level whose split
                // offset (or trim status) may have shifted.
                self.data.orphan_sidecar = None;
                return Err(Error::RetryAfterSquash);
            }
            Some(guard)
        } else {
            None
        };

        // Lazy-open or reuse the cached handle. The handle is per-level; `set_block`
        // invalidates the cache, so `split_offset` from the cached handle either matches
        // the current level's split or the cache is `None` after a level change. The open
        // helper itself handles the trim check + sidecar path resolution.
        let needs_open = match self.data.orphan_sidecar.as_ref() {
            Some(h) if h.split_offset == split => false,
            _ => true,
        };
        if needs_open {
            self.data.orphan_sidecar = Some(open_orphan_sidecar_for_level(
                self.db_path,
                &self.data.squash_meta,
                level_idx,
                self.data.squash_root_snapshot_retention_blocks,
            )?);
        }

        let handle = self
            .data
            .orphan_sidecar
            .as_ref()
            .expect("orphan_sidecar set just above; absent here is a logic error");
        // Reuse the connection-scoped scratch buffer (cleared, capacity preserved between
        // calls). The buffer is returned to `self.data.orphan_read_scratch` by
        // [`Self::orphan_scratch_restore`] once the caller has finished decoding from it.
        let mut buf = std::mem::take(&mut self.data.orphan_read_scratch);
        let leaf_hashes_omitted = self.data.leaf_hashes_omitted;
        match read_orphan_node_bytes_into(handle, ptr, leaf_hashes_omitted, &mut buf) {
            Ok(()) => Ok(Some(buf)),
            Err(e) => {
                // Restore the scratch on error so we don't leak its capacity.
                self.data.orphan_read_scratch = buf;
                Err(e)
            }
        }
    }

    /// Return an orphan-section read buffer to the connection-scoped
    /// scratch slot. Pairs with [`Self::try_read_orphan_bytes`]: callers
    /// invoke this once they've finished decoding the buffer's bytes,
    /// regardless of whether the decode itself succeeded — keeping the
    /// `Vec<u8>`'s capacity reused across reads.
    fn orphan_scratch_restore(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        self.data.orphan_read_scratch = buf;
    }

    pub fn clear_cached_ancestor_hashes_bytes(&mut self) {
        self.data.clear_ancestor_hashes_bytes();
    }

    pub fn get_root_hash_at(&mut self, tip: &T) -> Result<TrieHash, Error> {
        let cur_block_hash = self.get_cur_block();

        self.open_block(tip)?;
        let root_hash_res = bits::read_root_hash(self);

        // restore
        self.open_block(&cur_block_hash)?;
        root_hash_res
    }

    /// Recover from partially-written state -- i.e. blow it away.
    /// Doesn't get called automatically.
    pub fn recover(db_path: &String) -> Result<(), Error> {
        let conn = marf_sqlite_open(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE, false)?;
        trie_sql::clear_lock_data(&conn)
    }

    /// internal procedure for locking a trie hash for work
    fn switch_trie(&mut self, bhh: &T, trie_buf: UncommittedState<T>) {
        trace!("Extended from {} to {}", &self.data.cur_block, bhh);

        // update internal structures
        self.data.set_block(bhh.clone(), None);
        self.clear_cached_ancestor_hashes_bytes();

        self.data.uncommitted_writes = Some((bhh.clone(), trie_buf));
    }

    /// Is the given block in the marf_data DB table, and is it part of the block history (i.e. it's not mined and
    /// its not unconfirmed)?
    pub fn has_confirmed_block(&self, bhh: &T) -> Result<bool, Error> {
        match trie_sql::get_confirmed_block_identifier(&self.db, bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Is the given block in the marf_data DB table, and is it unconfirmed?
    pub fn has_unconfirmed_block(&self, bhh: &T) -> Result<bool, Error> {
        match trie_sql::get_unconfirmed_block_identifier(&self.db, bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Is the given block represented in either the confirmed or unconfirmed block tables?
    /// The mined table is ignored.
    pub fn has_block(&self, bhh: &T) -> Result<bool, Error> {
        Ok(self.has_confirmed_block(bhh)? || self.has_unconfirmed_block(bhh)?)
    }

    /// Return the block_identifier / row_id for a given bhh. If that bhh
    ///  is currently being extended, return None, since the row_id won't
    ///  be known until the extended trie is flushed.
    pub fn get_block_identifier(&mut self, bhh: &T) -> Option<u32> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if bhh == uncommitted_bhh {
                return None;
            }
        }

        self.get_block_id_caching(bhh).ok()
    }

    /// Get the currently-open block identifier (its row ID)
    pub fn get_cur_block_identifier(&mut self) -> Result<u32, Error> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return Err(Error::RequestedIdentifierForExtensionTrie);
            }
        }

        self.data.cur_block_id.ok_or_else(|| Error::NotOpenedError)
    }

    /// Gets the currently open block context which can later be used together with
    /// [`restore_block_context()`](Self::restore_block_context) to restore the connection to the
    /// that block context.
    pub fn get_block_context(&self) -> BlockCtx<T> {
        BlockCtx {
            block_hash: self.data.cur_block.clone(),
            block_id: self.data.cur_block_id,
        }
    }

    /// Restore a block context that was previously obtained via
    /// [`get_block_context()`](Self::get_block_context).
    pub fn restore_block_context(&mut self, ctx: BlockCtx<T>) -> Result<(), Error> {
        let BlockCtx {
            block_hash,
            block_id,
        } = ctx;

        self.open_block_maybe_id(&block_hash, block_id)
            .inspect_err(|e| {
                warn!("Failed to restore original block context {block_hash} {block_id:?}: {e:?}");
            })
    }

    /// Get the TriePtr::ptr() value for the root node in the currently-open block.
    pub fn root_ptr(&self) -> u32 {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return 0;
            }
        }

        ROOT_PTR_DISK
    }

    /// Read a node's children's hashes into the provided <Write> implementation.
    /// This only works for intermediate nodes and leafs (the latter of which have no children).
    ///
    /// This method is designed to only access hashes that are either (1) in this Trie, or (2) in
    /// RAM already (i.e. as part of the block map)
    ///
    /// This means that the hash of a node that is in a previous Trie will _not_ be its
    /// hash (as that would require a disk access), but would instead be the root hash of the Trie
    /// that contains it.  While this makes the Merkle proof construction a bit more complicated,
    /// it _significantly_ improves the performance of this method (which is crucial since this is on
    /// the write path, which must be as short as possible).
    ///
    /// Rules:
    /// If a node is empty, pass in an empty hash.
    /// If a node is in this Trie, pass its hash.
    /// If a node is in a previous Trie, pass the root hash of its Trie.
    ///
    /// On err, S may point to a prior block.  The caller should call s.open(...) if an error
    /// occurs.
    ///
    /// NOTE: this method should only be called if `hash_calculation_mode` is set to
    /// `TrieHashCalculationMode::All` or `TrieHashCalculationMode::Immediate`.  There is no need
    /// to call if the hash mode is `::Deferred`.  The only way this gets called while not in
    /// `::Deferred` mode is when generating a Merkle proof.
    pub fn write_children_hashes<W: Write>(
        &mut self,
        node: &TrieNodeType,
        w: &mut W,
    ) -> Result<(), Error> {
        self.write_children_hashes_by_ptrs(node.ptrs(), w)
    }

    /// Inner method for calculating a node's hash, by hashing its children.
    fn inner_write_children_hashes<W: Write + ?Sized, H: NodeHashReader, M: BlockMap>(
        hash_reader: &mut H,
        map: &mut M,
        ptrs: &[TriePtr],
        w: &mut W,
        bench: &mut TrieBenchmark,
    ) -> Result<(), Error> {
        trace!("inner_write_children_hashes begin for ptrs {:?}:", &ptrs);
        for ptr in ptrs.iter() {
            if ptr.id() == TrieNodeID::Empty as u8 {
                // hash of empty string
                let start_time = bench.write_children_hashes_empty_start();

                trace!(
                    "inner_write_children_hashes for ptrs {:?}: {:?} empty",
                    &ptrs,
                    &ptr
                );
                w.write_all(TrieHash::EMPTY.as_bytes())?;

                bench.write_children_hashes_empty_finish(start_time);
            } else if !is_backptr(ptr.id()) {
                // hash is in the same block as this node
                let start_time = bench.write_children_hashes_same_block_start();

                let mut buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
                hash_reader.read_node_hash(ptr, &mut buf)?;
                trace!(
                    "inner_write_children_hashes for ptrs {:?}: {:?} same block {}",
                    &ptrs,
                    &ptr,
                    &to_hex(&buf)
                );
                w.write_all(&buf[..])?;

                bench.write_children_hashes_same_block_finish(start_time);
            } else {
                // hash is in a different block altogether, so we just use the ancestor block hash.  The
                // ptr.ptr() value points to the actual node in the ancestor block.
                let start_time = bench.write_children_hashes_ancestor_block_start();

                let block_hash = map.get_block_hash_caching(ptr.back_block())?;
                trace!(
                    "inner_write_children_hashes for ptrs {:?}: {:?} back block {:?}",
                    &ptrs,
                    &ptr,
                    &block_hash
                );
                w.write_all(block_hash.as_bytes())?;

                bench.write_children_hashes_ancestor_block_finish(start_time);
            }
        }
        trace!("inner_write_children_hashes end for ptrs {:?}:", &ptrs);

        Ok(())
    }

    /// read a persisted node's hash
    fn inner_read_persisted_node_hash(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error> {
        if self.data.unconfirmed_block_id == Some(block_id) {
            // read from unconfirmed trie
            test_debug!(
                "Read persisted node hash from unconfirmed block id {}",
                block_id
            );
            return trie_sql::get_node_hash_bytes(&self.db, block_id, ptr);
        }
        let node_hash = match self.blobs.as_mut() {
            Some(blobs) => {
                blobs.get_node_hash(&self.db, block_id, ptr, None, self.data.leaf_hashes_omitted)
            }
            None => trie_sql::get_node_hash_bytes(&self.db, block_id, ptr),
        }?;
        Ok(node_hash)
    }

    #[inline]
    fn has_open_uncommitted_trie(&self) -> bool {
        matches!(
            self.data.uncommitted_writes.as_ref(),
            Some((uncommitted_bhh, _)) if &self.data.cur_block == uncommitted_bhh
        )
    }

    /// Store a node and its hash to the uncommitted state.
    /// If the uncommitted state is not instantiated, then this panics.
    pub fn write_nodetype(
        &mut self,
        disk_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        if self.data.readonly {
            return Err(Error::ReadOnlyError);
        }

        trace!(
            "write_nodetype({:?}): at {}: {:?} {:?}",
            &self.data.cur_block,
            disk_ptr,
            &hash,
            node
        );

        self.data.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.data.write_leaf_count += 1;
            }
            _ => {
                self.data.write_node_count += 1;
            }
        }

        // Only allow writes when the cur_block is the current in-RAM extending block.
        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.write_nodetype(disk_ptr, node, hash);
            }
        }

        panic!("Tried to write to another Trie besides the currently-buffered one.  This should never happen -- only flush() can write to disk!");
    }

    /// Take a node+hash out of the uncommitted TrieRAM via O(1) swap, leaving a placeholder.
    ///
    /// This is a performance optimization for the hash-recalculation hot path: it avoids
    /// the heap allocation that `into_owned_node()` → `to_owned_node()` would require.
    ///
    /// The caller MUST call [`restore_ram_node`] before this slot is read again. Any error
    /// between take and restore is unrecoverable (hash computation failure = block abandoned),
    /// so the placeholder cannot be observed by other readers.
    pub fn take_ram_node(&mut self, ptr: u32) -> Result<(TrieNodeType, TrieHash), Error> {
        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.take_node(ptr);
            }
        }
        panic!("take_ram_node: no uncommitted trie is open");
    }

    /// Restore a node+hash into the uncommitted TrieRAM at the given slot.
    pub fn restore_ram_node(
        &mut self,
        ptr: u32,
        node: TrieNodeType,
        hash: TrieHash,
    ) -> Result<(), Error> {
        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.restore_node(ptr, node, hash);
            }
        }
        panic!("restore_ram_node: no uncommitted trie is open");
    }

    /// Store a node and its hash to uncommitted state.
    pub fn write_node<N: TrieNode + std::fmt::Debug>(
        &mut self,
        ptr: u32,
        node: &N,
        hash: TrieHash,
    ) -> Result<(), Error> {
        if self.data.readonly {
            return Err(Error::ReadOnlyError);
        }

        let node_type = node.as_trie_node_type();
        self.write_nodetype(ptr, &node_type, hash)
    }

    /// Get the last slot into which a node will be inserted in the uncommitted state.
    /// Panics if there is no uncommmitted state instantiated.
    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        if let Some((_, ref mut uncommitted_trie)) = self.data.uncommitted_writes {
            uncommitted_trie.last_ptr()
        } else {
            panic!("Cannot allocate new ptrs in a Trie that is not in RAM");
        }
    }

    /// Count up the number of trie blocks this storage represents
    pub fn num_blocks(&self) -> usize {
        let result = if self.data.uncommitted_writes.is_some() {
            1
        } else {
            0
        };
        result
            + (trie_sql::count_blocks(&self.db)
                .expect("Corruption: SQL Error on a non-fallible query.") as usize)
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub trait MarfTestStorage<T: MarfTrieId> {
        fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, T>, Error>;
    }

    impl<T: MarfTrieId, Db: Deref<Target = Connection>> MarfTestStorage<T>
        for TrieStorageConnection<'_, T, Db>
    {
        fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, T>, Error> {
            Self::read_root_to_block_table(self)
        }
    }

    impl<T: MarfTrieId> MarfTestStorage<T> for ReopenedTrieStorageConnection<'_, T> {
        fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, T>, Error> {
            self.connection().read_root_to_block_table()
        }
    }

    fn read_persisted_root_to_blocks<T: MarfTrieId>(
        db: &Connection,
        blobs: Option<&mut TrieFile>,
    ) -> Result<HashMap<TrieHash, T>, Error> {
        let ret = match blobs {
            Some(blobs) => HashMap::from_iter(blobs.read_all_block_hashes_and_roots(db)?),
            None => HashMap::from_iter(trie_sql::read_all_block_hashes_and_roots(db)?),
        };
        Ok(ret)
    }

    fn read_root_to_block_table_from_parts<T: MarfTrieId>(
        db: &Connection,
        blobs: Option<&mut TrieFile>,
        uncommitted_writes: &mut Option<(T, UncommittedState<T>)>,
    ) -> Result<HashMap<TrieHash, T>, Error> {
        let mut ret = read_persisted_root_to_blocks(db, blobs)?;
        let pending_writes = match uncommitted_writes.take() {
            Some((bhh, trie_ram)) => {
                let ptr = TriePtr::new(set_backptr(TrieNodeID::Node256 as u8), 0, 0);
                let root_hash = trie_ram.read_node_hash(&ptr)?;

                ret.insert(root_hash, bhh.clone());
                Some((bhh, trie_ram))
            }
            None => None,
        };

        *uncommitted_writes = pending_writes;
        Ok(ret)
    }

    impl<'a, T: MarfTrieId, Db: Deref<Target = Connection>> TrieStorageConnection<'a, T, Db> {
        pub fn stats(&mut self) -> (u64, u64) {
            let r = self.data.read_count;
            let w = self.data.write_count;
            self.data.read_count = 0;
            self.data.write_count = 0;
            (r, w)
        }

        pub fn node_stats(&mut self) -> (u64, u64, u64) {
            let nr = self.data.read_node_count;
            let br = self.data.read_backptr_count;
            let nw = self.data.write_node_count;

            self.data.read_node_count = 0;
            self.data.read_backptr_count = 0;
            self.data.write_node_count = 0;

            (nr, br, nw)
        }

        pub fn leaf_stats(&mut self) -> (u64, u64) {
            let lr = self.data.read_leaf_count;
            let lw = self.data.write_leaf_count;

            self.data.read_leaf_count = 0;
            self.data.write_leaf_count = 0;

            (lr, lw)
        }

        /// Read the Trie root node's hash from the block table.
        pub fn read_block_root_hash(&mut self, bhh: &T) -> Result<TrieHash, Error> {
            let root_hash_ptr = TriePtr::new(TrieNodeID::Node256 as u8, 0, ROOT_PTR_DISK);
            if let Some(blobs) = self.blobs.as_mut() {
                // stored in a blobs file
                blobs.get_node_hash_by_bhh(&self.db, bhh, &root_hash_ptr)
            } else {
                // stored to DB
                trie_sql::get_node_hash_bytes_by_bhh(&self.db, bhh, &root_hash_ptr)
            }
        }

        /// Generate a mapping between Trie root hashes and the blocks that contain them
        pub fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, T>, Error> {
            read_root_to_block_table_from_parts(
                &self.db,
                self.blobs.as_deref_mut(),
                &mut self.data.uncommitted_writes,
            )
        }

        pub fn transient_data(&self) -> &TrieStorageTransientData<T> {
            self.data
        }

        pub fn transient_data_mut(&mut self) -> &mut TrieStorageTransientData<T> {
            self.data
        }
    }
}
