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

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::{env, fs, io};

/// Positional read: reads bytes from a file at a given offset without modifying the
/// file cursor. Maps to `pread(2)` on Unix and `seek_read` on Windows.
fn pread(fd: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        fd.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        fd.seek_read(buf, offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        compile_error!("pread: unsupported platform");
    }
}

/// Positional write: writes bytes to a file at a given offset without modifying the
/// file cursor. Maps to `pwrite(2)` on Unix and `seek_write` on Windows.
fn pwrite(fd: &fs::File, buf: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        fd.write_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        fd.seek_write(buf, offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        compile_error!("pwrite: unsupported platform");
    }
}

/// Positional write_all: writes the entire buffer at the given offset.
/// Loops until all bytes are written (handles short writes).
fn pwrite_all(fd: &fs::File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let n = pwrite(fd, buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        buf = buf.get(n..).unwrap_or(&[]);
        offset += n as u64;
    }
    Ok(())
}

use memmap2::Mmap;
#[cfg(test)]
use rusqlite::params;
use rusqlite::Connection;

use crate::chainstate::stacks::index::node::{TrieNodeID, TriePtr};
#[cfg(test)]
use crate::chainstate::stacks::index::storage;
use crate::chainstate::stacks::index::storage::NodeHashReader;
use crate::chainstate::stacks::index::{
    bits, trie_sql, BorrowedNodeBytes, Error, MarfTrieId, NodeDecodeScratch, ReadTrieItem,
    ReadTrieNode,
};
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use crate::util_lib::db::sql_vacuum;

/// Mapping between block IDs and trie offsets
pub type TrieIdOffsets = HashMap<u32, u64>;

/// Handle to a flat file containing Trie blobs, optionally mmap-accelerated for reads.
/// When `mmap` is `Some`, hot read methods (`get_node_hash`, `read_trie_item`,
/// `read_node_type_id`) slice directly into the mapped region instead of using
/// positional I/O. All `Write`/`Seek`/`Read` trait impls always go through the fd.
pub struct TrieFileDisk {
    fd: fs::File,
    path: String,
    /// If true, mmap is desired but not yet active (file was empty at open time).
    /// `append_trie_blob` will create the mmap after the first write.
    mmap_enabled: bool,
    /// Memory-mapped view of the blobs file. `None` if mmap is not enabled or the
    /// file was empty at open time (will be populated after first write).
    mmap: Option<Mmap>,
    /// Cached mapping from block_id → trie file offset. Interior-mutable so that
    /// read methods can populate the cache while taking `&self`.
    trie_offsets: RefCell<TrieIdOffsets>,
}

/// Handle to a flat in-memory buffer containing Trie blobs (used for testing)
pub struct TrieFileRAM {
    fd: Cursor<Vec<u8>>,
    readonly: bool,
    trie_offsets: RefCell<TrieIdOffsets>,
}

/// This is flat-file storage for a MARF's tries.  All tries are stored as contiguous byte arrays
/// within a larger byte array.  The variants differ in how those bytes are backed.  The `RAM`
/// variant stores data in RAM in a byte buffer, and the `Disk` variant stores data in a flat file
/// on disk — optionally with a memory-mapped read overlay for zero-syscall reads.
pub enum TrieFile {
    RAM(TrieFileRAM),
    Disk(TrieFileDisk),
}

impl TrieFile {
    /// Make a new disk-backed TrieFile (no mmap).
    fn new_disk(path: &str, readonly: bool) -> Result<TrieFile, Error> {
        let fd = OpenOptions::new()
            .read(true)
            .write(!readonly)
            .create(!readonly)
            .open(path)?;
        Ok(TrieFile::Disk(TrieFileDisk {
            fd,
            path: path.to_string(),
            mmap_enabled: false,
            mmap: None,
            trie_offsets: RefCell::new(TrieIdOffsets::new()),
        }))
    }

    /// Make a new RAM-backed TrieFile
    fn new_ram(readonly: bool) -> TrieFile {
        TrieFile::RAM(TrieFileRAM {
            fd: Cursor::new(vec![]),
            readonly,
            trie_offsets: RefCell::new(TrieIdOffsets::new()),
        })
    }

    /// Make a new disk-backed TrieFile with mmap-accelerated reads.
    /// If the file is empty (no committed tries yet), the mmap is deferred —
    /// `append_trie_blob` will create it after the first write.
    fn new_mmap(path: &str, readonly: bool) -> Result<TrieFile, Error> {
        let fd = OpenOptions::new()
            .read(true)
            .write(!readonly)
            .create(!readonly)
            .open(path)?;
        let file_len = fd.metadata()?.len();
        let mmap = if file_len > 0 {
            // SAFETY: The .blobs file is append-only and single-writer. Existing data
            // at existing offsets never changes. The mmap is read-only.
            Some(unsafe { Mmap::map(&fd)? })
        } else {
            // Can't mmap an empty file. Will be created on first append.
            None
        };
        Ok(TrieFile::Disk(TrieFileDisk {
            fd,
            path: path.to_string(),
            mmap_enabled: true,
            mmap,
            trie_offsets: RefCell::new(TrieIdOffsets::new()),
        }))
    }

    /// Does the TrieFile exist at the expected path?
    pub fn exists(path: &str) -> Result<bool, Error> {
        if path == ":memory:" {
            Ok(false)
        } else {
            let blob_path = format!("{}.blobs", path);
            match fs::metadata(&blob_path) {
                Ok(_) => Ok(true),
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(false)
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    /// Get a copy of the path to this TrieFile.
    /// If in RAM, then the path will be ":memory:"
    pub fn get_path(&self) -> String {
        match self {
            TrieFile::RAM(_) => ":memory:".to_string(),
            TrieFile::Disk(ref disk) => disk.path.clone(),
        }
    }

    /// Instantiate a TrieFile, given the associated DB path.
    /// If path is ':memory:', then it'll be an in-RAM TrieFile.
    /// If `use_mmap` is true, the file will be memory-mapped for reads.
    /// Otherwise, it'll use seek+read I/O on `$db_path.blobs`.
    pub fn from_db_path(path: &str, readonly: bool, use_mmap: bool) -> Result<TrieFile, Error> {
        if path == ":memory:" {
            Ok(TrieFile::new_ram(readonly))
        } else {
            let blob_path = format!("{}.blobs", path);
            if use_mmap {
                TrieFile::new_mmap(&blob_path, readonly)
            } else {
                TrieFile::new_disk(&blob_path, readonly)
            }
        }
    }

    /// Append a new trie blob to external storage, and add the offset and length to the trie DB.
    /// Return the trie ID
    pub fn store_trie_blob<T: MarfTrieId>(
        &mut self,
        db: &Connection,
        bhh: &T,
        buffer: &[u8],
    ) -> Result<u32, Error> {
        let offset = self.append_trie_blob(db, buffer)?;
        test_debug!("Stored trie blob {} to offset {}", bhh, offset);
        trie_sql::write_external_trie_blob(db, bhh, offset, buffer.len() as u64)
    }

    /// Read a trie blob in its entirety from the DB
    fn read_trie_blob_from_db(db: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
        let trie_blob = {
            let mut fd = trie_sql::open_trie_blob_readonly(db, block_id)?;
            let mut trie_blob = vec![];
            fd.read_to_end(&mut trie_blob)
                .inspect_err(|e| error!("Failed to read trie blob {block_id} from DB: {e:}"))?;
            trie_blob
        };
        Ok(trie_blob)
    }

    /// Read a trie blob in its entirety from the blobs file.
    /// Takes `&self` — uses positional reads.
    pub fn read_trie_blob_bytes(&self, db: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
        let (offset, length) = trie_sql::get_external_trie_offset_length(db, block_id)?;
        let mut buf = vec![0u8; length as usize];
        let n = self
            .read_bytes_at(&mut buf, offset)
            .inspect_err(|e| error!("Failed to read trie blob {block_id}: {e:}"))?;
        buf.truncate(n);
        Ok(buf)
    }

    #[cfg(test)]
    pub fn read_trie_blob(&self, db: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
        self.read_trie_blob_bytes(db, block_id)
    }

    /// Vacuum the database and report the size before and after.
    ///
    /// Returns database errors.  Filesystem errors from reporting the file size change are masked.
    fn inner_post_migrate_vacuum(db: &Connection, db_path: &str) -> Result<(), Error> {
        // for fun, report the shrinkage
        let size_before_opt = fs::metadata(db_path)
            .map(|stat| Some(stat.len()))
            .unwrap_or(None);

        info!("Preemptively vacuuming the database file to free up space after copying trie blobs to a separate file");
        sql_vacuum(db)?;

        let size_after_opt = fs::metadata(db_path)
            .map(|stat| Some(stat.len()))
            .unwrap_or(None);

        if let (Some(sz_before), Some(sz_after)) = (size_before_opt, size_after_opt) {
            debug!("Shrank DB from {} to {} bytes", sz_before, sz_after);
        }

        Ok(())
    }

    /// Vacuum the database, and set up and tear down the necessary environment variables to
    /// use same parent directory for scratch space.
    ///
    /// Infallible -- any vacuum errors are masked.
    fn post_migrate_vacuum(db: &Connection, db_path: &str) {
        // set SQLITE_TMPDIR if it isn't set already
        let mut set_sqlite_tmpdir = false;
        let mut old_tmpdir_opt = None;
        if let Some(parent_path) = Path::new(db_path).parent() {
            if env::var("SQLITE_TMPDIR").is_err() {
                debug!(
                    "Sqlite will store temporary migration state in '{}'",
                    parent_path.display()
                );
                env::set_var("SQLITE_TMPDIR", parent_path);
                set_sqlite_tmpdir = true;
            }

            // also set TMPDIR
            old_tmpdir_opt = env::var("TMPDIR").ok();
            env::set_var("TMPDIR", parent_path);
        }

        // don't materialize the error; just warn
        let res = TrieFile::inner_post_migrate_vacuum(db, db_path);
        if let Err(e) = res {
            warn!("Failed to VACUUM the MARF DB post-migration: {:?}", &e);
        }

        if set_sqlite_tmpdir {
            debug!("Unset SQLITE_TMPDIR");
            env::remove_var("SQLITE_TMPDIR");
        }
        if let Some(old_tmpdir) = old_tmpdir_opt {
            debug!("Restore TMPDIR to '{}'", &old_tmpdir);
            env::set_var("TMPDIR", old_tmpdir);
        } else {
            debug!("Unset TMPDIR");
            env::remove_var("TMPDIR");
        }
    }

    /// Copy the trie blobs out of a sqlite3 DB into their own file.
    /// NOTE: this is *not* thread-safe.  Do not call while the DB is being used by another thread.
    pub fn export_trie_blobs<T: MarfTrieId>(
        &mut self,
        db: &Connection,
        db_path: &str,
    ) -> Result<(), Error> {
        if trie_sql::detect_partial_migration(db)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        let max_block = trie_sql::count_blocks(db)?;
        info!(
            "Migrate {} blocks to external blob storage at {}",
            max_block,
            &self.get_path()
        );

        for block_id in 0..(max_block + 1) {
            match trie_sql::is_unconfirmed_block(db, block_id) {
                Ok(true) => {
                    test_debug!("Skip block_id {} since it's unconfirmed", block_id);
                    continue;
                }
                Err(Error::NotFoundError) => {
                    test_debug!("Skip block_id {} since it's not a block", block_id);
                    continue;
                }
                Ok(false) => {
                    // get the blob
                    let trie_blob = TrieFile::read_trie_blob_from_db(db, block_id)?;

                    // get the block ID
                    let bhh: T = trie_sql::get_block_hash(db, block_id)?;

                    // append the blob, replacing the current trie blob
                    if block_id % 1000 == 0 {
                        info!(
                            "Migrate block {} ({} of {}) to external blob storage",
                            &bhh, block_id, max_block
                        );
                    }

                    // append directly to file, so we can get the true offset
                    let offset = match self {
                        TrieFile::Disk(ref disk) => disk.fd.metadata()?.len(),
                        TrieFile::RAM(ref ram) => ram.fd.get_ref().len() as u64,
                    };
                    match self {
                        TrieFile::Disk(ref disk) => {
                            pwrite_all(&disk.fd, &trie_blob, offset)?;
                        }
                        TrieFile::RAM(ref mut ram) => {
                            let data = ram.fd.get_mut();
                            let start = offset as usize;
                            let end = start + trie_blob.len();
                            if data.len() < end {
                                data.resize(end, 0);
                            }
                            data.get_mut(start..end)
                                .expect("BUG: just resized to cover range")
                                .copy_from_slice(&trie_blob);
                        }
                    }

                    test_debug!("Stored trie blob {} to offset {}", bhh, offset);
                    trie_sql::update_external_trie_blob(
                        db,
                        &bhh,
                        offset,
                        trie_blob.len() as u64,
                        block_id,
                    )?;
                }
                Err(e) => {
                    test_debug!(
                        "Failed to determine if {} is unconfirmed: {:?}",
                        block_id,
                        &e
                    );
                    return Err(e);
                }
            }
        }

        TrieFile::post_migrate_vacuum(db, db_path);

        debug!("Mark MARF trie migration of '{}' as finished", db_path);
        trie_sql::set_migrated(db).expect("FATAL: failed to mark DB as migrated");
        Ok(())
    }
}

/// NodeHashReader for TrieFile
pub struct TrieFileNodeHashReader<'a> {
    db: &'a Connection,
    file: &'a TrieFile,
    block_id: u32,
}

impl<'a> TrieFileNodeHashReader<'a> {
    pub fn new(
        db: &'a Connection,
        file: &'a TrieFile,
        block_id: u32,
    ) -> TrieFileNodeHashReader<'a> {
        TrieFileNodeHashReader { db, file, block_id }
    }
}

impl NodeHashReader for TrieFileNodeHashReader<'_> {
    fn read_node_hash<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        let hash = self.file.get_node_hash(self.db, self.block_id, ptr, None)?;
        w.write_all(hash.as_ref()).map_err(|e| e.into())
    }
}

impl TrieFile {
    /// Determine the file offset in the TrieFile where a serialized trie starts.
    /// The offsets are stored in the given DB, and are cached indefinitely once loaded.
    /// Takes `&self` — the offset cache uses interior mutability (`RefCell`).
    pub fn get_trie_offset(&self, db: &Connection, block_id: u32) -> Result<u64, Error> {
        let cache = match self {
            TrieFile::RAM(ref ram) => &ram.trie_offsets,
            TrieFile::Disk(ref disk) => &disk.trie_offsets,
        };
        if let Some(offset) = cache.borrow().get(&block_id).copied() {
            return Ok(offset);
        }
        let (offset, _length) = trie_sql::get_external_trie_offset_length(db, block_id)?;
        cache.borrow_mut().insert(block_id, offset);
        Ok(offset)
    }

    /// Read bytes at a given file offset into `buf` without modifying any cursor state.
    /// Uses `pread` for Disk, direct slice for RAM, mmap slice for mmap-enabled Disk.
    /// Returns the number of bytes read.
    fn read_bytes_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        match self {
            TrieFile::Disk(ref disk) => {
                if let Some(ref mmap) = disk.mmap {
                    let start = offset as usize;
                    let bytes = mmap.get(start..).ok_or(Error::NotFoundError)?;
                    let len = buf.len().min(bytes.len());
                    let dst = buf.get_mut(..len).ok_or(Error::NotFoundError)?;
                    let src = bytes.get(..len).ok_or(Error::NotFoundError)?;
                    dst.copy_from_slice(src);
                    Ok(len)
                } else {
                    pread(&disk.fd, buf, offset).map_err(Error::IOError)
                }
            }
            TrieFile::RAM(ref ram) => {
                let data = ram.fd.get_ref();
                let start = offset as usize;
                let bytes = data.get(start..).ok_or(Error::NotFoundError)?;
                let len = buf.len().min(bytes.len());
                let dst = buf.get_mut(..len).ok_or(Error::NotFoundError)?;
                let src = bytes.get(..len).ok_or(Error::NotFoundError)?;
                dst.copy_from_slice(src);
                Ok(len)
            }
        }
    }

    /// Get a slice from the mmap region at the given offset, if mmap is active.
    /// Returns `None` if not mmap-enabled or if offset is out of range.
    fn mmap_slice_at(&self, offset: u64) -> Option<&[u8]> {
        if let TrieFile::Disk(ref disk) = self {
            disk.mmap.as_ref()?.get(offset as usize..)
        } else {
            None
        }
    }

    /// Read bytes at a known file position into scratch, then decode.
    /// For mmap: slices directly into the mapped region (zero-copy decode).
    /// For disk: uses `pread` into scratch's node_bytes buffer.
    /// For RAM: slices the in-memory buffer.
    fn read_item_at_offset<'a>(
        &self,
        file_offset: u64,
        ptr: &TriePtr,
        scratch: &'a mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieItem<'a>, Error> {
        // Fast path: mmap slice available — decode directly from it.
        if let Some(bytes) = self.mmap_slice_at(file_offset) {
            return bits::read_trie_item_from_slice(bytes, ptr.id(), scratch);
        }
        // Slow path: positional read into scratch's reusable buffer, then decode.
        // Pattern: take buffer → pread → decode (extracts hash + node ID from bytes,
        // copies decoded node into scratch slots) → restore buffer for reuse.
        let max_len = bits::get_node_max_byte_len(ptr.id())?;
        let mut buf = scratch.take_node_bytes();
        buf.resize(max_len, 0);
        let n = self.read_bytes_at(&mut buf, file_offset)?;
        buf.truncate(n);
        let (hash, remaining) = bits::parse_hash_from_bytes(&buf)?;
        let stored_node_id = bits::stored_node_id_from_bytes(remaining)?;
        let _consumed = if stored_node_id == TrieNodeID::Patch {
            scratch.decode_patch_from_slice(remaining)?
        } else {
            scratch.decode_node_from_slice(
                TrieNodeID::from_u8(ptr.id()).ok_or_else(|| {
                    Error::CorruptionError(format!("Invalid node ID {}", ptr.id()))
                })?,
                remaining,
            )?
        };
        scratch.restore_node_bytes(buf);
        if stored_node_id == TrieNodeID::Patch {
            Ok(ReadTrieItem::from_patch(scratch.patch(), Some(hash)))
        } else {
            Ok(ReadTrieItem::from_node(ReadTrieNode::from_state_borrowed(
                scratch.get_ref(),
                Some(hash),
            )))
        }
    }

    /// Read hash bytes at a known file position.
    fn read_hash_at(&self, file_offset: u64) -> Result<TrieHash, Error> {
        if let Some(bytes) = self.mmap_slice_at(file_offset) {
            let (hash, _) = bits::parse_hash_from_bytes(bytes)?;
            return Ok(hash);
        }
        let mut buf = [0u8; TRIEHASH_ENCODED_SIZE];
        let n = self.read_bytes_at(&mut buf, file_offset)?;
        if n < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(
                "Failed to read hash in full via pread".to_string(),
            ));
        }
        Ok(TrieHash(buf))
    }

    /// Read node type ID and hash at a known file position.
    fn read_node_type_at(&self, file_offset: u64) -> Result<(TrieNodeID, TrieHash), Error> {
        if let Some(bytes) = self.mmap_slice_at(file_offset) {
            return bits::read_stored_node_type_from_slice(bytes);
        }
        // hash (32 bytes) + node id (1 byte)
        let mut buf = [0u8; TRIEHASH_ENCODED_SIZE + 1];
        let n = self.read_bytes_at(&mut buf, file_offset)?;
        if n < TRIEHASH_ENCODED_SIZE + 1 {
            return Err(Error::CorruptionError(
                "Failed to read node type via pread".to_string(),
            ));
        }
        bits::read_stored_node_type_from_slice(&buf)
    }

    /// Obtain a [`TrieHash`] for a node, given its block ID and pointer.
    ///
    /// If `trie_offset` is `Some`, uses the pre-resolved offset (bypassing the offset
    /// cache). Otherwise resolves the offset from the cache or SQL.
    pub fn get_node_hash(
        &self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
        trie_offset: Option<u64>,
    ) -> Result<TrieHash, Error> {
        let offset = trie_offset.map_or_else(|| self.get_trie_offset(db, block_id), Ok)?;
        self.read_hash_at(offset + ptr.ptr() as u64)
    }

    // TODO: Unused -- do we need this?
    // /// Obtain a trie node view and its associated TrieHash for a node, given its block ID and
    // /// pointer.
    // pub fn read_node<'a>(
    //     &self,
    //     db: &Connection,
    //     block_id: u32,
    //     ptr: &TriePtr,
    //     scratch: &'a mut impl NodeDecodeScratch,
    // ) -> Result<ReadTrieNode<'a>, Error> {
    //     self.read_trie_item(db, block_id, ptr, None, scratch)?.into_node()
    // }

    /// Read a trie item (node or patch) at the given block and pointer.
    ///
    /// If `trie_offset` is `Some`, uses the pre-resolved offset (bypassing the offset
    /// cache). Otherwise resolves the offset from the cache or SQL.
    pub fn read_trie_item<'a>(
        &self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
        trie_offset: Option<u64>,
        scratch: &'a mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieItem<'a>, Error> {
        let offset = trie_offset.map_or_else(|| self.get_trie_offset(db, block_id), Ok)?;
        self.read_item_at_offset(offset + ptr.ptr() as u64, ptr, scratch)
    }

    /// Read a trie item as borrowed bytes from the mmap region (zero-copy).
    /// Returns `None` if mmap is not active or the node is a patch.
    /// Takes `&self` — no cursor state needed.
    pub fn read_trie_item_borrowed<'a>(
        &'a self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<Option<ReadTrieItem<'a>>, Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        let Some(bytes) = self.mmap_slice_at(offset + ptr.ptr() as u64) else {
            return Ok(None);
        };
        let (hash, remaining) = bits::parse_hash_from_bytes(bytes)?;
        let stored_node_id = bits::stored_node_id_from_bytes(remaining)?;
        if stored_node_id == TrieNodeID::Patch {
            return Ok(None);
        }
        let node_bytes = BorrowedNodeBytes::new(stored_node_id, remaining);
        Ok(Some(ReadTrieItem::from_node(
            ReadTrieNode::from_stable_bytes(node_bytes, Some(hash)),
        )))
    }

    /// Read the node type ID and hash at the given block and pointer.
    /// Takes `&self` — uses positional reads, no cursor state.
    pub fn read_node_type_id(
        &self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeID, TrieHash), Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.read_node_type_at(offset + ptr.ptr() as u64)
    }

    /// Append a serialized trie to the TrieFile.
    /// Returns the offset at which it was appended.
    pub fn append_trie_blob(&mut self, db: &Connection, buf: &[u8]) -> Result<u64, Error> {
        let offset = trie_sql::get_external_blobs_length(db)?;
        test_debug!("Write trie of {} bytes at {}", buf.len(), offset);

        match self {
            TrieFile::Disk(ref mut disk) => {
                pwrite_all(&disk.fd, buf, offset)?;
                disk.fd.sync_data()?;
                if disk.mmap_enabled {
                    // (Re)map to cover the written data.
                    // SAFETY: append-only, single-writer, file just fsynced.
                    disk.mmap = Some(unsafe { Mmap::map(&disk.fd)? });
                }
            }
            TrieFile::RAM(ref mut ram) => {
                let data = ram.fd.get_mut();
                let start = offset as usize;
                let end = start + buf.len();
                if data.len() < end {
                    data.resize(end, 0);
                }
                data.get_mut(start..end)
                    .expect("BUG: just resized to cover range")
                    .copy_from_slice(buf);
            }
        }
        Ok(offset)
    }
}

#[cfg(test)]
impl TrieFile {
    /// Obtain a TrieHash for a node, given the node's block's hash (used only in testing)
    #[cfg(test)]
    pub fn get_node_hash_by_bhh<T: MarfTrieId>(
        &self,
        db: &Connection,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error> {
        let (offset, _length) = trie_sql::get_external_trie_offset_length_by_bhh(db, bhh)?;
        self.read_hash_at(offset + ptr.ptr() as u64)
    }

    /// Get all (root hash, trie hash) pairs for this TrieFile
    #[cfg(test)]
    pub fn read_all_block_hashes_and_roots<T: MarfTrieId>(
        &self,
        db: &Connection,
    ) -> Result<Vec<(TrieHash, T)>, Error> {
        let mut s =
            db.prepare("SELECT block_hash, external_offset FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash")?;
        let rows = s.query_and_then(params![], |row| {
            let block_hash: T = row.get_unwrap("block_hash");
            let offset_i64: i64 = row.get_unwrap("external_offset");
            let offset = offset_i64 as u64;
            let start = storage::ROOT_PTR_DISK as u64;

            let root_hash = self.read_hash_at(offset + start)?;

            trace!(
                "Root hash for block {} at offset {} is {}",
                &block_hash,
                offset + start,
                &root_hash
            );
            Ok((root_hash, block_hash))
        })?;
        rows.collect()
    }
}
