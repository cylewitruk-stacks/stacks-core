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
    is_backptr, is_leaf_type, set_backptr, TrieCowPtr, TrieNode, TrieNodeID, TrieNodePatch,
    TrieNodeRef, TrieNodeTransientMeta, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::profile::TrieBenchmark;
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::squash::SquashTrailer;
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    bits, trie_sql, BlockMap, ClarityMarfTrieId, Error, MARFValue, MarfTrieId, NodePatching,
    NodePath, ReadTrieItem, ReadTrieItemKind, ReadTrieNode, TrieHasher, TrieLeaf,
    TrieNodeReadState, TrieReadStorage, MAX_PATCH_DEPTH,
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
        decode_scratch: &mut impl TrieNodeReadState,
    ) -> Result<Option<TrieNodePatch>, Error> {
        // Save block state. We use `set_block` to restore instead of `open_block` because the
        // current block may be the uncommitted trie (which has been `.take()`'d from storage during
        // `dump_compressed_consume`), making it unreachable via `open_block`.
        let (cur_block, cur_block_id) = storage_tx.get_cur_block_and_id();
        storage_tx.open_block(&base_ptr.block_id())?;
        match storage_tx.read_node_with_state(base_ptr.ptr(), decode_scratch) {
            Ok(read) => {
                if read.patch_depth >= MAX_PATCH_DEPTH as usize {
                    storage_tx.data.set_block(cur_block, cur_block_id);
                    return Ok(None);
                }
                if read.path_bytes()? != node.path_bytes() {
                    storage_tx.data.set_block(cur_block, cur_block_id);
                    return Ok(None);
                }

                let (old_node, _) = read.as_node_ref()?;

                trace!(
                    "Make patch from old node from block {:?} to new node {:?}",
                    &old_node,
                    node
                );
                let result = TrieNodePatch::try_from_noderef(*base_ptr.ptr(), old_node, &node);
                storage_tx.data.set_block(cur_block, cur_block_id);
                return Ok(result);
            }
            Err(Error::Patch(_, _old_patch)) => {
                storage_tx.data.set_block(cur_block, cur_block_id);

                // building atop an existing patch.
                // Make sure that the base node's path isn't different from this node
                let scratch = &mut MarfReadState::new();
                let read = read_patched_persisted_node(
                    &storage_tx.db,
                    storage_tx.blobs.as_deref(),
                    storage_tx.data.unconfirmed_block_id,
                    base_ptr.ptr().back_block(),
                    *base_ptr.ptr(),
                    None,
                    storage_tx.data.leaf_hashes_omitted,
                    &storage_tx.data.squash_meta.leaf_hash_omitted_blocks,
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
                storage_tx.data.set_block(cur_block, cur_block_id);
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

        while let Some(pointer) = frontier.pop_front() {
            let (node, node_hash) = self.get_nodetype(pointer)?;

            // IMPROVEMENT: if we can, store a patch node instead of the whole node.
            // Only applies to non-leaf nodes, and only if doing so results in a stack of patches
            // that's less than MAX_PATCH_DEPTH. Also, only patch a node if the path is the same.
            let mut patch_node_opt = if !node.is_leaf()
                && node.patch_depth() < MAX_PATCH_DEPTH as usize
            {
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
                    let patch_node_opt =
                        Self::make_node_patch(storage_tx, base_ptr, &node, &mut decode_scratch)?;
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
                    let patch_node_opt =
                        Self::make_node_patch(storage_tx, *cowptr, &node, &mut decode_scratch)?;
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
pub struct SquashMeta {
    /// Loaded squash level trailers (sorted by min_height). Empty for non-squashed MARFs.
    pub levels: Vec<SquashTrailer>,
    /// O(1) block-hash → (level_index, height, blob_offset, reads_redirected, block_id) index built
    /// from all trailers.
    pub block_index: HashMap<[u8; 32], (usize, u32, u64, bool, u32)>,
    /// Set of block_ids whose blobs have leaf hashes omitted (reclaimed squash levels).
    pub leaf_hash_omitted_blocks: HashSet<u32>,
}

impl SquashMeta {
    pub fn empty() -> Self {
        Self {
            levels: Vec::new(),
            block_index: HashMap::new(),
            leaf_hash_omitted_blocks: HashSet::new(),
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

/// Build a [`SquashMeta`] by reading `marf_squash_levels` from SQLite and parsing each level's
/// trailer from the blob file.
///
/// Returns an empty `SquashMeta` if no squash levels have been recorded or if all present levels
/// are stubs (blob_length == 0) with no trailers.
pub(crate) fn build_squash_meta_from_sql(
    db: &Connection,
    blobs: Option<&TrieFile>,
) -> Result<SquashMeta, Error> {
    let squash_level_rows = trie_sql::read_squash_levels(db)?;
    if squash_level_rows.is_empty() {
        return Ok(SquashMeta::empty());
    }

    let mut levels = Vec::with_capacity(squash_level_rows.len());
    let mut block_index = HashMap::new();
    let mut leaf_hash_omitted = HashSet::new();

    for row in &squash_level_rows {
        if row.blob_length == 0 {
            levels.push(SquashTrailer::empty());
            continue;
        }
        let Some(blobs_ref) = blobs else {
            // External-blobs disabled but a level is present: defensive fallback — register an
            // empty stub so reads fall through to the legacy SQL path.
            levels.push(SquashTrailer::empty());
            continue;
        };

        let footer_offset = row.blob_offset + row.blob_length
            - crate::chainstate::stacks::index::squash::SQUASH_FOOTER_SIZE as u64;
        let footer_bytes = blobs_ref.read_blob_range(footer_offset, 12)?;
        let trailer_rel_offset = SquashTrailer::read_footer(&footer_bytes).ok_or_else(|| {
            Error::CorruptionError("Squash level blob has no valid trailer footer".into())
        })?;

        let trailer_abs_offset = row.blob_offset + trailer_rel_offset;
        let trailer_length = row.blob_offset + row.blob_length - trailer_abs_offset;
        let trailer_bytes = blobs_ref.read_blob_range(trailer_abs_offset, trailer_length)?;
        let trailer = SquashTrailer::read_from(&trailer_bytes)?;

        let level_idx = levels.len();
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
            if row.reads_redirected {
                leaf_hash_omitted.insert(block_id);
            }
        }
        levels.push(trailer);
    }

    Ok(SquashMeta {
        levels,
        block_index,
        leaf_hash_omitted_blocks: leaf_hash_omitted,
    })
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

    /// Memoized result of `compute_snapshot_height_via_parent_chain`, keyed by the
    /// **user's** original opened block_id. The parent-chain walk is lazy — it only
    /// runs when `snapshot_height_for_block()` is called from a `LeafSquashed` resolution
    /// in the marf walk, and only for blocks whose eager paths (in-squash block, or
    /// uncommitted-parent-of-squash) haven't already populated `squash_opened_height`.
    ///
    /// Stored as `(user_block_id, walk_result)` so the cache survives backptr resolution
    /// (which mutates `cur_block_id` mid-walk). On a different user block, the entry is
    /// overwritten — single-entry cache is enough because typical reads target one block
    /// at a time.
    ///
    /// Inner walk result: `Some(h)` = squashed ancestor at height `h`; `None` =
    /// sentinel/cap-exhaustion/pruned-ancestor (caller falls back to tip-read, which is
    /// correct for canonical descendants and the best we can do for pathological deep forks).
    pub resolved_snapshot_height: Cell<Option<(u32, Option<u32>)>>,

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
            resolved_snapshot_height: Cell::new(None),
            #[cfg(test)]
            squashed_tip_fallback_count: Cell::new(0),
            #[cfg(test)]
            squashed_entries_reread_count: Cell::new(0),
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
    fn set_block(&mut self, bhh: T, id: Option<u32>) {
        trace!("set_block({},{:?})", &bhh, &id);
        self.cur_block_id = id;
        self.cur_block = bhh;
        self.cur_block_trie_offset = None;
        self.squash_opened_height = None;
        self.squash_opened_level_idx = None;
        self.leaf_hashes_omitted = false;
        self.resolved_snapshot_height.set(None);
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
        read_patched_persisted_node(
            self.db,
            self.blobs.as_ref(),
            self.data.unconfirmed_block_id,
            block_id,
            ptr.from_backptr(),
            self.data.cur_block_trie_offset,
            self.data.leaf_hashes_omitted,
            &self.data.squash_meta.leaf_hash_omitted_blocks,
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
fn sync_from_shared_squash_state<T: MarfTrieId>(
    data: &mut TrieStorageTransientData<T>,
    mut blobs: Option<&mut TrieFile>,
    cache: &mut BlockCache<T>,
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
            // Limitation: this only handles uncommitted blocks whose IMMEDIATE parent is in the
            // squash. Committed-non-canonical blocks (deeper forks) are not yet covered — they
            // would require a parent-chain walk via either a `marf_data.parent_block_hash` schema
            // addition or a chainstate-level snapshot-height passthrough on `open_block`.
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

    // Snapshot-height propagation for committed non-squash blocks is deferred to
    // `snapshot_height_for_block()` on the connection, called from the marf walk's
    // `LeafSquashed` branch. Walking the parent chain here on every committed open would
    // add up to `MAX_PARENT_CHAIN_DEPTH` SQL/blob-header lookups per open — catastrophic
    // for canonical chains extended many blocks past the last squash, which are the vast
    // majority of opens. The lazy resolver caches per user_block_id in
    // `data.resolved_snapshot_height`, so the walk fires at most once per user-level open
    // and only when a squashed leaf is actually reached.

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

fn compute_snapshot_height_via_parent_chain<T: MarfTrieId>(
    data: &TrieStorageTransientData<T>,
    db: &Connection,
    blobs: Option<&TrieFile>,
    start_block_hash: &T,
    start_block_id: u32,
) -> Option<u32> {
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
        if let Some(&(_level_idx, height, _, _reads_redirected, _)) =
            data.squash_meta.block_index.get(&key)
        {
            return Some(height);
        }

        // 2. Read parent hash from the trie blob's header.
        // `debug!` (not `warn!`) on failure: a missing offset usually means a pruned
        // non-canonical ancestor (benign; caller falls back to tip-read which is already
        // the correct answer for canonical descendants), so spamming warnings would be noise.
        let trie_offset = match blobs.get_trie_offset(db, current_id) {
            Ok(o) => o,
            Err(e) => {
                debug!(
                    "compute_snapshot_height: cannot read trie offset for block_id={current_id} \
                     ({current_hash}) — likely a pruned non-canonical ancestor. \
                     Falling back to tip-read. Error: {e}"
                );
                return None;
            }
        };
        let parent_hash_bytes = match blobs.read_parent_hash_at(trie_offset) {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    "compute_snapshot_height: blob header read failed at block_id={current_id} \
                     offset={trie_offset}: {e}"
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

/// Shared implementation for `TrieReadStorage::open_block_known_id`, used by both
/// `TrieStorageConnection` and `ReopenedTrieStorageConnection`.
///
/// Panics if `bhh` matches the currently-being-built uncommitted block (programming error).
///
/// Restores squash context (opened height, level index, trie offset) when the block
/// lives in a squash level, mirroring the squash-aware path in `open_block_impl`.
fn open_block_known_id_impl<T: MarfTrieId>(
    data: &mut TrieStorageTransientData<T>,
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

    data.set_block(bhh.clone(), Some(id));

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

/// Patch-aware per-node read shared by [`TrieStorageConnection`] and
/// [`ReopenedTrieStorageConnection`].
///
/// Inlines the dispatch from `inner_read_persisted_trie_item` (blobs vs. SQL, unconfirmed
/// guard) and runs the full patch-chasing loop. Both storage types call this from their
/// `TrieReadStorage::read_node_with_state` impls.
fn read_patched_persisted_node<'b>(
    db: &Connection,
    blobs: Option<&TrieFile>,
    unconfirmed_block_id: Option<u32>,
    mut block_id: u32,
    mut ptr: TriePtr,
    cur_block_trie_offset: Option<u64>,
    leaf_hashes_omitted: bool,
    leaf_hash_omitted_blocks: &HashSet<u32>,
    scratch: &'b mut impl NodePatching,
) -> Result<ReadTrieNode<'b>, Error> {
    let target_block_id = block_id;
    let mut node_hash_opt = None;
    let mut patches = scratch.take_patch_chain_buf();
    let mut trie_offset_hint = cur_block_trie_offset;
    let mut cur_leaf_hashes_omitted = leaf_hashes_omitted;

    for _ in 0..=MAX_PATCH_DEPTH {
        let read = if unconfirmed_block_id == Some(block_id) {
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
        // Clear the hint after the first iteration — subsequent reads chase into
        // different blocks via backptrs and need fresh offset lookups.
        trie_offset_hint = None;
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
                cur_leaf_hashes_omitted = leaf_hash_omitted_blocks.contains(&block_id);
                if node_hash_opt.is_none() {
                    node_hash_opt = hash;
                }
            }
        }
    }
    scratch.restore_patch_chain_buf(patches);
    Err(Error::NodeTooDeep)
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
        if self.data.unconfirmed_block_id != Some(id) {
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
        let _slow_path_guard = if self.blobs.is_some() {
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
        let result = read_patched_persisted_node(
            &self.db,
            self.blobs.as_deref(),
            self.data.unconfirmed_block_id,
            id,
            clear_ptr,
            trie_offset,
            self.data.leaf_hashes_omitted,
            &self.data.squash_meta.leaf_hash_omitted_blocks,
            state,
        );
        self.bench.read_nodetype_finish(false);
        if let Err(ref e) = result {
            error!(
                "read_node_with_state failed: block={}, block_id={id}, ptr={clear_ptr:?}, \
                 leaf_hashes_omitted={}, squash_levels={}, squash_block_index_len={}, \
                 trie_offset={trie_offset:?}, err={e:?}",
                &self.data.cur_block,
                self.data.leaf_hashes_omitted,
                self.data.squash_meta.levels.len(),
                self.data.squash_meta.block_index.len(),
            );
        }
        result
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
        open_block_known_id_impl(self.data, bhh, id)
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

        // Squash fast-path: when reading the root node hash of a block inside a squash level,
        // return the per-height root hash stored in the squash trailer instead of reading from the
        // blob. The squash blob contains a single merged trie whose root node hash is the *tip's*
        // hash, not the per-block hash, so the normal read path would return the wrong value for
        // ancestor blocks.
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

        match self.data.cur_block_id {
            Some(block_id) => {
                // Per-read guard: `inner_read_persisted_node_hash` calls `blobs.get_node_hash`
                // which touches the mmap. The returned `TrieHash` is an owned 32-byte copy, so
                // the guard can be local. Skip when blobs aren't enabled (pure-SQL backend).
                let _guard = if self.blobs.is_some() {
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

        let Some(id) = self.data.cur_block_id else {
            return Err(Error::NotFoundError);
        };
        if self.blobs.is_some() {
            // Per-read guard for the mmap-backed path. Hash/type decode yields owned values
            // (Copy types), so the guard is local to this call and drops at scope end.
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
        if let Some((cached_id, cached_result)) = self.data.resolved_snapshot_height.get() {
            if cached_id == block_id {
                return cached_result;
            }
        }
        let resolved = compute_snapshot_height_via_parent_chain(
            self.data,
            &self.db,
            self.blobs.as_deref(),
            block_hash,
            block_id,
        );
        self.data
            .resolved_snapshot_height
            .set(Some((block_id, resolved)));
        resolved
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

        if self.blobs.is_some() {
            // Per-read guard covers the entire `inner_write_children_hashes` walk — the hash
            // reader does multiple mmap accesses across sibling pointers, all of which must
            // stay protected against a concurrent ftruncate until this call returns.
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
            let start_time = self.bench.write_children_hashes_start();
            let block_id = self.data.cur_block_id.ok_or_else(|| {
                error!("Failed to get cur block as hash reader");
                Error::NotFoundError
            })?;
            let blobs = self
                .blobs
                .as_mut()
                .expect("blobs.is_some() above proves this is Some");
            let mut cursor = TrieFileNodeHashReader::new(
                &self.db,
                blobs,
                block_id,
                self.data.leaf_hashes_omitted,
            );
            let res = Self::inner_write_children_hashes(&mut cursor, &mut map, ptrs, w, self.bench);
            self.bench.write_children_hashes_finish(start_time, false);
            res
        } else {
            let start_time = self.bench.write_children_hashes_start();
            let mut cursor = TrieSqlCursor {
                db: &self.db,
                block_id: self.data.cur_block_id.ok_or_else(|| {
                    error!("Failed to get cur block as hash reader");
                    Error::NotFoundError
                })?,
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
        let blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true, self.mmap)?)
        } else {
            None
        };
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

    /// Reload squash level metadata and remap the blob file after an external squash operation
    /// has modified both the SQLite DB and the `.blobs` file through a separate handle.
    ///
    /// Runs the remap + metadata rebuild inside the shared quiesce window so that concurrent
    /// readers on other handles cannot be holding mmap bytes when the file is mutated. See
    /// [`SharedStorageState::publish_squash`] for the exact ordering guarantees.
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

        // Clear the block cache and current-block context — stale after the squash redirected
        // blocks to new blob offsets.
        self.cache = BlockCache::new("noop");
        self.data.set_block(T::sentinel(), None);
        self.data.trie_ancestor_hash_bytes_cache = None;

        Ok(())
    }

    fn open_opts(
        db_path: &str,
        readonly: bool,
        unconfirmed: bool,
        marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<T>, Error> {
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

        debug!(
            "Opened TrieFileStorage {}; external blobs: {}",
            db_path,
            blobs.is_some()
        );

        let cache = BlockCache::new(&marf_opts.cache_strategy);

        let mut data = TrieStorageTransientData::new(T::sentinel(), None, readonly, unconfirmed);

        // Join (or create) the process-wide `SharedSquashState` entry for this db path. Any other
        // independent `MARF::from_path` opens against the same file (e.g. the Stacks 2.x P2P
        // thread's chainstate and the runloop's chainstate both targeting the same headers MARF)
        // will share the Arc with us, so a `refresh_after_squash()` publish on either handle is
        // observable by the other via the generation counter.
        let shared = {
            let db_for_build = &db;
            let blobs_for_build = blobs.as_ref();
            shared_squash_state_for(&db_path, || {
                build_squash_meta_from_sql(db_for_build, blobs_for_build)
            })?
        };
        data.squash_meta = shared.snapshot();
        data.shared_squash = shared;
        data.seen_squash_generation = data.shared_squash.generation();

        let ret = TrieFileStorage {
            db_path,
            db,
            cache,
            blobs,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: marf_opts.hash_calculation_mode,
            compress: marf_opts.compress,
            mmap: marf_opts.mmap,

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
fn build_readonly_storage<T: MarfTrieId>(
    db_path: &str,
    blobs_active: bool,
    hash_calculation_mode: TrieHashCalculationMode,
    compress: bool,
    mmap: bool,
    data: TrieStorageTransientData<T>,
    #[cfg(test)] test_genesis_block: Option<T>,
) -> Result<TrieFileStorage<T>, Error> {
    let db = marf_sqlite_open(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
    let blobs = if blobs_active {
        Some(TrieFile::from_db_path(db_path, true, mmap)?)
    } else {
        None
    };
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

    /// Detect whether a writer has published a new [`SquashMeta`] since this
    /// handle last synced, and if so re-snapshot the shared metadata and
    /// invalidate the handle-local blob mmap + block cache + current-block
    /// context.
    ///
    /// Fast-path: a single atomic load with no lock, no SQL, no trailer
    /// parsing. Only the slow path (generation mismatch) acquires the
    /// RwLock read guard to snapshot the fresh metadata.
    fn sync_shared_squash_state(&mut self) -> Result<(), Error> {
        sync_from_shared_squash_state(self.data, self.blobs.as_deref_mut(), self.cache)
    }

    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
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
