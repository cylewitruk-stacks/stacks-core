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

#[cfg(test)]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::Path;
use std::{fmt, fs, io};

use rusqlite::{Connection, OpenFlags, Transaction};
use sha2::Digest;

use crate::chainstate::stacks::index::cache::*;
use crate::chainstate::stacks::index::file::{TrieFile, TrieFileNodeHashReader};
use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::node::{
    is_backptr, set_backptr, TrieCowPtr, TrieNode, TrieNodeID, TrieNodePatch, TrieNodeRef,
    TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::profile::TrieBenchmark;
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    bits, trie_sql, BlockMap, ClarityMarfTrieId, Error, MarfTrieId, NodeDecodeScratch,
    NodePatching, ReadTrieItem, ReadTrieItemKind, ReadTrieNode, TrieHasher, TrieNodeReadState,
    TrieReadStorage, MAX_PATCH_DEPTH,
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
    #[allow(dead_code)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
            bits::write_node_bytes(f, &node.0, node.1)?;

            // next node
            let next_offset = *offsets.get(ix).ok_or_else(|| {
                Error::CorruptionError("node_data_order.len() != offsets.len()".into())
            })?;
            f.seek(SeekFrom::Start(next_offset.into()))?;
        }

        Ok(())
    }

    /// write the trie data to f, using node_data_order to
    ///   iterate over node_data
    /// Compression improvements:
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

        // write parent block ptr
        f.rewind()?;
        f.write_all(parent_hash.as_bytes())
            .map_err(Error::IOError)?;

        // write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        //    identifier from the trie data blob)
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
                    "write {:?} {} at {}-{}",
                    &patch,
                    &to_hex(hash_bytes),
                    f_pos_before,
                    f_pos_after
                );
            } else {
                // dump the node to storage
                let node = node_data.get(indirect.ptr() as usize).ok_or_else(|| {
                    Error::CorruptionError("node_data_order pointer invalid".into())
                })?;

                bits::write_node_bytes_compressed(f, &node.0, node.1)?;
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

    /// Calculate and store the MARF root hash, as well as any necessary intermediate nodes.  Do
    /// this only for deferred hashing mode.
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

    /// Recursively calculate all node hashes in this `TrieRAM`.  The top-most call to this method
    /// should pass `0` for `node_ptr`, since this is the pointer to the root node.  Returns the
    /// node hash for the `TrieNode` at `node_ptr`.
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

    /// Walk through the buffered TrieNodes and dump them to f.
    /// This consumes this TrieRAM instance.
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
        let cur_block = storage_tx.get_cur_block();
        storage_tx.open_block(&base_ptr.block_id())?;
        match storage_tx.read_node_with_state(base_ptr.ptr(), decode_scratch) {
            Ok(read) => {
                if read.patch_depth >= MAX_PATCH_DEPTH as usize {
                    return Ok(None);
                }
                if read.path_bytes()? != node.path_bytes() {
                    return Ok(None);
                }

                let (old_node, _) = read.as_node_ref()?;

                trace!(
                    "Make patch from old node from block {:?} to new node {:?}",
                    &old_node,
                    node
                );
                return Ok(TrieNodePatch::try_from_noderef(
                    *base_ptr.ptr(),
                    old_node,
                    &node,
                ));
            }
            Err(Error::Patch(_, _old_patch)) => {
                storage_tx.open_block(&cur_block)?;

                // building atop an existing patch.
                // Make sure that the base node's path isn't different from this node
                let scratch = &mut MarfReadState::new();
                match storage_tx.inner_read_patched_persisted_node(
                    base_ptr.ptr().back_block(),
                    *base_ptr.ptr(),
                    scratch,
                ) {
                    Ok(read) => {
                        if read.patch_depth >= MAX_PATCH_DEPTH as usize {
                            return Ok(None);
                        }
                        if read.path_bytes()? != node.path_bytes() {
                            return Ok(None);
                        }
                        let (base_node, _) = read.as_node_ref()?;
                        trace!(
                            "Make patch from reconstructed node {:?} to new node {:?}",
                            &base_node,
                            node
                        );
                        return Ok(TrieNodePatch::try_from_noderef(
                            *base_ptr.ptr(),
                            base_node,
                            &node,
                        ));
                    }
                    Err(e) => {
                        storage_tx.open_block(&cur_block)?;
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                storage_tx.open_block(&cur_block)?;
                return Err(e);
            }
        }
    }

    /// Walk through the buffered TrieNodes and dump them to f, compressing the trie.
    /// This consumes this TrieRAM instance.
    /// The trie will already have been sealed.
    ///
    /// Space improvements:
    /// * Do not store backptr 0's if the node isn't a backptr
    /// * Store a compact representation for sparse child pointer lists
    /// * If a node was copied from another, then only store the difference in ptrs (TrieNodePatch)
    ///
    /// Returns Ok(len) to report number of bytes written
    /// Returns Err(..) if we fail to write
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
                && node.get_patches().len() < MAX_PATCH_DEPTH as usize
            {
                if let Some((last_patch_block_id, last_patch_ptr, _)) = node.get_patches().last() {
                    // this node is a patch to a node in a previous trie.  Try to amend a patch
                    // atop it.
                    let block_hash = storage_tx.get_block_hash_caching(*last_patch_block_id)?;

                    // construct a COW pointer to this patch node
                    let mut patch_ptr = TriePtr::new(
                        set_backptr(TrieNodeID::Patch as u8),
                        last_patch_ptr.chr(),
                        last_patch_ptr.ptr(),
                    );
                    patch_ptr.back_block = *last_patch_block_id;

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

    /// load the trie from F.
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
                "TrieRAM get_nodetype({:?}): Failed to read node: {} >= {}",
                &self.block_header,
                ptr,
                self.data.len()
            );
            Error::NotFoundError
        })
    }

    /// Get an owned instance of a node and its hash from the TrieRAM.  ptr.ptr() is an array
    /// index.
    /// Note that this will never return a patch node, since we only ever store patch nodes to
    /// persistent media.
    #[cfg(test)]
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        trace!(
            "TrieRAM: read_nodetype({:?}): at {:?}",
            &self.block_header,
            ptr
        );

        self.read_count += 1;
        if is_backptr(ptr.id()) {
            self.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.read_leaf_count += 1;
        } else {
            self.read_node_count += 1;
        }

        if let Some(node) = self.data.get(ptr.ptr() as usize) {
            Ok(node.clone())
        } else {
            error!(
                "TrieRAM read_nodetype({:?}): Failed to read node {:?}: {} >= {}",
                &self.block_header,
                ptr,
                ptr.ptr(),
                self.data.len()
            );
            Err(Error::NotFoundError)
        }
    }

    pub fn read_node(&mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'_>, Error> {
        trace!("TrieRAM: read_node({:?}): at {:?}", &self.block_header, ptr);

        self.read_count += 1;
        if is_backptr(ptr.id()) {
            self.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.read_leaf_count += 1;
        } else {
            self.read_node_count += 1;
        }

        if let Some((node, hash)) = self.data.get(ptr.ptr() as usize) {
            Ok(ReadTrieNode::from_borrowed(
                TrieNodeRef::from(node),
                Some(*hash),
            ))
        } else {
            error!(
                "TrieRAM read_node({:?}): Failed to read node {:?}: {} >= {}",
                &self.block_header,
                ptr,
                ptr.ptr(),
                self.data.len()
            );
            Err(Error::NotFoundError)
        }
    }

    /// Store a node and its hash to the TrieRAM at the given slot.
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

        trace!(
            "TrieRAM: write_nodetype({:?}): at {}: {:?} {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
            node
        );

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

    /// Store a node hash into the TrieRAM at a given node slot.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        trace!(
            "TrieRAM: write_node_hash({:?}): at {}: {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
        );

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

/// TrieStorageTransientData holds all the data that _isn't_ committed to the underlying SQL
/// storage. Used internally to simplify the TrieStorageConnection/TrieFileStorage interactions
pub struct TrieStorageTransientData<T: MarfTrieId> {
    /// This is all the nodes written but not yet committed to disk.
    pub uncommitted_writes: Option<(T, UncommittedState<T>)>,

    /// Currently-open block (may be `uncommitted_writes.unwrap().0`)
    cur_block: T,
    /// Tracking the row_id for the cur_block. If cur_block == uncommitted_writes,
    ///   this value should always be None
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

    /// List of ancestral trie root hashes that must be hashed with the `uncommitted_writes` root node
    /// hash to produce the MarfTrieId for the trie when it gets written to disk.  This is
    /// maintained by the MARF whenever it needs to update the trie root hash after a leaf insert,
    /// so that a batch of leaf inserts into `uncommitted_writes` don't require an ancestor trie hash
    /// query more than once.
    trie_ancestor_hash_bytes_cache: Option<(T, Vec<TrieHash>)>,

    /// Is the trie opened read-only?
    readonly: bool,

    /// Does this trie represent unconfirmed state?
    unconfirmed: bool,

    /// row ID of a trie that represents unconfirmed state (i.e. trie state that will never become
    /// part of the MARF, but nevertheless represents a persistent scratch space).  If this field
    /// is Some(..), then the storage was used to (re-)open an unconfirmed trie
    /// (via `open_unconfirmed()` or `open_block()` when `self.unconfirmed` is `true`), or used
    /// to create an unconfirmed trie (via `extend_to_unconfirmed_block()`).
    unconfirmed_block_id: Option<u32>,
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage<T: MarfTrieId> {
    pub db_path: String,

    db: Connection,
    blobs: Option<TrieFile>,
    data: TrieStorageTransientData<T>,
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

    /// Target the transient data to a particular block, and optionally its block ID
    fn set_block(&mut self, bhh: T, id: Option<u32>) {
        trace!("set_block({},{:?})", &bhh, &id);
        self.cur_block_id = id;
        self.cur_block = bhh;
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
            scratch,
        )
    }
}

/// Shared implementation for `TrieReadStorage::open_block`, used by both
/// `TrieStorageConnection` and `ReopenedTrieStorageConnection`.
///
/// `cache` is required because `get_block_id_caching` accesses `TrieCache<T>`, which lives
/// on the storage struct alongside (not inside) `TrieStorageTransientData`.
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

    if let Some((ref uncommitted_bhh, _)) = data.uncommitted_writes {
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
            data.set_block(bhh.clone(), None);
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

    let block_id = get_block_id_caching_impl(data.unconfirmed, cache, db, bhh).map_err(|e| {
        test_debug!("Failed to open {:?}: {:?}", bhh, e);
        e
    })?;

    data.set_block(bhh.clone(), Some(block_id));
    bench.open_block_finish(false);
    Ok(())
}

/// Shared implementation for `TrieReadStorage::open_block_known_id`, used by both
/// `TrieStorageConnection` and `ReopenedTrieStorageConnection`.
///
/// Panics if `bhh` matches the currently-being-built uncommitted block (programming error).
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
    scratch: &'b mut impl NodePatching,
) -> Result<ReadTrieNode<'b>, Error> {
    let target_block_id = block_id;
    let mut node_hash_opt = None;
    let mut patches: Vec<(u32, TriePtr, TrieNodePatch)> = vec![];

    for _ in 0..=MAX_PATCH_DEPTH {
        let read = if unconfirmed_block_id == Some(block_id) {
            trace!("Read persisted node from unconfirmed block id {block_id}");
            trie_sql::read_trie_item(db, block_id, &ptr, scratch)?
        } else {
            match blobs {
                Some(blobs) => blobs.read_trie_item(db, block_id, &ptr, scratch)?,
                None => trie_sql::read_trie_item(db, block_id, &ptr, scratch)?,
            }
        };
        let ReadTrieItem { hash, kind, .. } = read;

        match kind {
            ReadTrieItemKind::Node(_) => {
                let node_hash = node_hash_opt.or(hash).ok_or_else(|| {
                    Error::CorruptionError("Missing node hash in trie read".to_string())
                })?;
                if !patches.is_empty() {
                    patches.reverse();
                    scratch.apply_patches_in_place(&patches, target_block_id)?;
                }

                return Ok(
                    ReadTrieNode::from_state_borrowed(scratch.get_ref(), Some(node_hash))
                        .with_patch_depth(patches.len()),
                );
            }
            ReadTrieItemKind::Patch(patch) => {
                let node_patch = patch.clone();
                trace!("read_patched_persisted_node({block_id}): at {ptr:?} read patch {node_patch:?} (original hash is {hash:?})");
                let new_ptr = node_patch.ptr.from_backptr();
                let new_block_id = node_patch.ptr.back_block();

                patches.push((block_id, ptr, node_patch));

                ptr = new_ptr;
                block_id = new_block_id;
                if node_hash_opt.is_none() {
                    node_hash_opt = hash;
                }
            }
        }
    }
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

        match self.data.cur_block_id {
            Some(id) => {
                // Zero-copy mmap fast path: try to return borrowed bytes directly
                // from the mmap region without decoding into scratch. All read
                // methods on TrieFile take &self (positional I/O), so this immutable
                // borrow of self.blobs doesn't conflict with later mutable borrows.
                if self.data.unconfirmed_block_id != Some(id) {
                    if let Some(ref blobs) = self.blobs {
                        if let Some(read) =
                            blobs.read_trie_item_borrowed(&self.db, id, &clear_ptr)?
                        {
                            if let ReadTrieItemKind::Node(node) = read.kind {
                                return Ok(node);
                            }
                        }
                    }
                }

                self.bench.read_nodetype_start();
                let result = read_patched_persisted_node(
                    &self.db,
                    self.blobs.as_deref(),
                    self.data.unconfirmed_block_id,
                    id,
                    clear_ptr,
                    state,
                );
                self.bench.read_nodetype_finish(false);
                result
            }
            None => {
                debug!("Not found (no file is open)");
                Err(Error::NotFoundError)
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

        match self.data.cur_block_id {
            Some(block_id) => {
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

        match self.data.cur_block_id {
            Some(id) => match self.blobs.as_mut() {
                Some(blobs) => blobs.read_node_type_id(&self.db, id, &clear_ptr),
                None => trie_sql::probe_node_type(&self.db, id, &clear_ptr),
            },
            None => Err(Error::NotFoundError),
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

        if let Some(blobs) = self.blobs.as_mut() {
            let start_time = self.bench.write_children_hashes_start();
            let block_id = self.data.cur_block_id.ok_or_else(|| {
                error!("Failed to get cur block as hash reader");
                Error::NotFoundError
            })?;
            let mut cursor = TrieFileNodeHashReader::new(&self.db, blobs, block_id);
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
}

impl<T: MarfTrieId> TrieFileStorage<T> {
    pub fn connection(&mut self) -> TrieStorageConnection<'_, T> {
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
        if prev_schema_version != trie_sql::SQL_MARF_SCHEMA_VERSION || marf_opts.force_db_migrate {
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

        let ret = TrieFileStorage {
            db_path,
            db,
            cache,
            blobs,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: marf_opts.hash_calculation_mode,
            compress: marf_opts.compress,
            mmap: marf_opts.mmap,

            data: TrieStorageTransientData::new(T::sentinel(), None, readonly, unconfirmed),

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

    /// Returns a new TrieFileStorage in read-only mode.
    ///
    /// Returns Err if the underlying SQLite database connection cannot be created.
    pub fn reopen_readonly(&self) -> Result<TrieFileStorage<T>, Error> {
        trace!("Make read-only view of TrieFileStorage: {}", &self.db_path);

        // TODO: borrow self.uncommitted_writes; don't copy them
        let data = TrieStorageTransientData {
            uncommitted_writes: self.data.uncommitted_writes.clone(),
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

        build_readonly_storage(
            self.db_path,
            self.blobs.is_some(),
            self.hash_calculation_mode,
            self.compress,
            self.mmap,
            TrieStorageTransientData::new(T::sentinel(), None, true, self.unconfirmed()),
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
            Some(blobs) => blobs.get_node_hash(&self.db, block_id, ptr),
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

    fn inner_read_persisted_trie_item<'b>(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
        scratch: &'b mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieItem<'b>, Error> {
        trace!(
            "inner_read_persisted_node({block_id}): {ptr:?} (unconfirmed={:?},{})",
            &self.data.unconfirmed_block_id,
            self.unconfirmed()
        );

        if self.data.unconfirmed_block_id == Some(block_id) {
            trace!("Read persisted node from unconfirmed block id {block_id}");
            return trie_sql::read_trie_item(&self.db, block_id, ptr, scratch);
        }

        match self.blobs.as_mut() {
            Some(blobs) => blobs.read_trie_item(&self.db, block_id, ptr, scratch),
            None => trie_sql::read_trie_item(&self.db, block_id, ptr, scratch),
        }
    }

    fn inner_read_persisted_node<'b>(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
        scratch: &'b mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieNode<'b>, Error> {
        self.inner_read_persisted_trie_item(block_id, ptr, scratch)?
            .into_node()
    }

    fn inner_read_patched_persisted_node<'b>(
        &mut self,
        block_id: u32,
        ptr: TriePtr,
        scratch: &'b mut impl NodePatching,
    ) -> Result<ReadTrieNode<'b>, Error> {
        trace!(
            "inner_read_patched_persisted_node({block_id}): {ptr:?} (unconfirmed={:?},{})",
            &self.data.unconfirmed_block_id,
            self.unconfirmed()
        );
        read_patched_persisted_node(
            &self.db,
            self.blobs.as_deref(),
            self.data.unconfirmed_block_id,
            block_id,
            ptr,
            scratch,
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
