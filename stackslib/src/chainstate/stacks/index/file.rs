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
use rusqlite::Connection;

use crate::chainstate::stacks::index::node::{self, TrieNodeID, TriePtr};
use crate::chainstate::stacks::index::storage::{BlobReadGuard, NodeHashReader};
use crate::chainstate::stacks::index::{
    bits, trie_sql, BorrowedNodeBytes, Error, MarfTrieId, NodeDecodeScratch, ReadTrieItem,
    ReadTrieNode,
};
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use crate::util_lib::db::sql_vacuum;

/// Maximum number of block_id → offset entries kept in memory per-handle before
/// wholesale eviction. Sized to cover the active working set of a long genesis
/// sync (~hours of hot block lookups) without letting the cache grow unbounded
/// across millions of historical blocks. Wholesale eviction on overflow is
/// acceptable because a miss just falls back to a single SQLite row lookup.
const TRIE_OFFSETS_CACHE_MAX: usize = 65_536;

/// Bounded block_id → trie-file-offset cache. Populated lazily from
/// `marf_data.external_offset` on first lookup of each block_id, and cleared
/// wholesale when it grows past [`TRIE_OFFSETS_CACHE_MAX`] or when a squash
/// publish invalidates per-handle derived state.
///
/// This replaces the previous unbounded `HashMap<u32, u64>` (which would grow
/// indefinitely on long-running nodes with millions of historical block_ids).
#[derive(Default)]
pub struct TrieIdOffsets {
    inner: HashMap<u32, u64>,
}

impl TrieIdOffsets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, block_id: &u32) -> Option<u64> {
        self.inner.get(block_id).copied()
    }

    pub fn insert(&mut self, block_id: u32, offset: u64) {
        if self.inner.len() >= TRIE_OFFSETS_CACHE_MAX {
            // Simple bounded-memory policy: nuke the whole map when it hits
            // the cap. A miss after eviction is just one extra SQL lookup.
            // A more precise LRU would reduce misses but is overkill given
            // how often the cache is invalidated by squash publishes.
            self.inner.clear();
        }
        self.inner.insert(block_id, offset);
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

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
    fn new_ram() -> TrieFile {
        TrieFile::RAM(TrieFileRAM {
            fd: Cursor::new(vec![]),
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
            Ok(TrieFile::new_ram())
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
    /// Read a raw byte range from the blob file at the given offset and length.
    /// Used for reading squash level blobs (which include trie nodes + trailer).
    pub fn read_blob_range(&self, offset: u64, length: u64) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; length as usize];
        let n = self.read_bytes_at(&mut buf, offset)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_trie_blob_bytes(&self, db: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
        let (offset, length) = trie_sql::get_external_trie_offset_length(db, block_id)?;
        let mut buf = vec![0u8; length as usize];
        let n = self
            .read_bytes_at(&mut buf, offset)
            .inspect_err(|e| error!("Failed to read trie blob {block_id}: {e:}"))?;
        buf.truncate(n);
        Ok(buf)
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
    leaf_hashes_omitted: bool,
}

impl<'a> TrieFileNodeHashReader<'a> {
    pub fn new(
        db: &'a Connection,
        file: &'a TrieFile,
        block_id: u32,
        leaf_hashes_omitted: bool,
    ) -> TrieFileNodeHashReader<'a> {
        TrieFileNodeHashReader {
            db,
            file,
            block_id,
            leaf_hashes_omitted,
        }
    }
}

impl NodeHashReader for TrieFileNodeHashReader<'_> {
    fn read_node_hash<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        let hash =
            self.file
                .get_node_hash(self.db, self.block_id, ptr, None, self.leaf_hashes_omitted)?;
        w.write_all(hash.as_ref()).map_err(|e| e.into())
    }
}

impl TrieFile {
    /// Determine the file offset in the TrieFile where a serialized trie starts.
    /// The offsets are stored in the given DB and cached in the bounded
    /// [`TrieIdOffsets`] map. Takes `&self` — the cache uses interior mutability.
    pub fn get_trie_offset(&self, db: &Connection, block_id: u32) -> Result<u64, Error> {
        let cache = match self {
            TrieFile::RAM(ref ram) => &ram.trie_offsets,
            TrieFile::Disk(ref disk) => &disk.trie_offsets,
        };
        if let Some(offset) = cache.borrow().get(&block_id) {
            return Ok(offset);
        }
        let (offset, _length) = trie_sql::get_external_trie_offset_length(db, block_id)?;
        cache.borrow_mut().insert(block_id, offset);
        Ok(offset)
    }

    /// Read bytes at a given file offset into `buf` without modifying any cursor state.
    /// Uses mmap when available and the offset is in range; otherwise falls back to `pread`.
    ///
    /// The mmap may be stale when another connection (e.g., the chains coordinator) has
    /// appended data that this connection's mmap doesn't cover yet. In that case we
    /// gracefully fall back to `pread`, which always sees the latest file contents.
    fn read_bytes_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        match self {
            TrieFile::Disk(ref disk) => {
                if let Some(ref mmap) = disk.mmap {
                    let start = offset as usize;
                    if let Some(bytes) = mmap.get(start..) {
                        let len = buf.len().min(bytes.len());
                        let dst = buf.get_mut(..len).ok_or(Error::NotFoundError)?;
                        let src = bytes.get(..len).ok_or(Error::NotFoundError)?;
                        dst.copy_from_slice(src);
                        return Ok(len);
                    }

                    // Mmap doesn't cover this offset; fall through to pread.
                    //
                    // TODO: This is a not the ideal long-term solution for handling concurrent
                    // reads. Today, several threads get their own StacksChainState instances with
                    // their own mmap handles, so they won't see each other's appends until they
                    // reopen their StacksChainState and remap (which the read-only consumers
                    // typically never do). Ideally we'd only have a single StacksChainState
                    // instance per-MARF, shared by all threads, so that the mmap is always mapping
                    // the latest file contents, but also so that we're not wasting system resources
                    // on multiple mmap handles for the same file, multiple block/offset caches,
                    // etc.
                }
                pread(&disk.fd, buf, offset).map_err(Error::IOError)
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
        leaf_hashes_omitted: bool,
        scratch: &'a mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieItem<'a>, Error> {
        // Fast path: mmap slice available — decode directly from it.
        if let Some(bytes) = self.mmap_slice_at(file_offset) {
            if leaf_hashes_omitted && node::is_leaf_type(ptr.id()) {
                return bits::read_trie_item_from_slice_leaf_hash_free(bytes, ptr.id(), scratch);
            }
            return bits::read_trie_item_from_slice(bytes, ptr.id(), scratch);
        }

        // Slow path: positional read into scratch's reusable buffer, then decode.
        //
        // We size the read buffer from the ptr hint first (correct in the vast
        // majority of cases). After reading, we check the actual stored node ID.
        // If it requires a larger buffer (e.g. ptr says Leaf but on-disk is
        // LeafSquashed in a FullHistory squash blob), we re-read with the
        // correct size. This avoids a double-read in the common case while
        // remaining correct when the ptr hint is stale.
        let is_leaf_hint = leaf_hashes_omitted && node::is_leaf_type(ptr.id());
        let hinted_max = if is_leaf_hint {
            bits::get_node_body_max_byte_len(ptr.id())?
        } else {
            bits::get_node_max_byte_len(ptr.id())?
        };
        let mut buf = scratch.take_node_bytes();
        buf.resize(hinted_max, 0);
        let n = self.read_bytes_at(&mut buf, file_offset)?;
        buf.truncate(n);

        if is_leaf_hint {
            // Hash-free leaf: body starts at byte 0.
            let stored_node_id = bits::stored_node_id_from_bytes(&buf)?;
            let stored_max = bits::get_node_body_max_byte_len(stored_node_id as u8)?;
            if stored_max > hinted_max {
                buf.resize(stored_max, 0);
                let n = self.read_bytes_at(&mut buf, file_offset)?;
                buf.truncate(n);
            }
            let _consumed = scratch.decode_node_from_slice(stored_node_id, &buf)?;
            scratch.restore_node_bytes(buf);
            return Ok(ReadTrieItem::from_node(ReadTrieNode::from_state_borrowed(
                scratch.get_ref(),
                None,
            )));
        }

        let (hash, remaining) = bits::parse_hash_from_bytes(&buf)?;
        let stored_node_id = bits::stored_node_id_from_bytes(remaining)?;

        // If the stored type needs a larger buffer than what we allocated,
        // re-read with the correct size. This only triggers when the ptr
        // hint and stored type diverge (e.g. Leaf → LeafSquashed).
        let stored_max = bits::get_node_max_byte_len(stored_node_id as u8)?;
        if stored_max > hinted_max {
            buf.resize(stored_max, 0);
            let n = self.read_bytes_at(&mut buf, file_offset)?;
            buf.truncate(n);
            // Re-parse after the larger read.
            let (rehash, remaining) = bits::parse_hash_from_bytes(&buf)?;
            let _consumed = if stored_node_id == TrieNodeID::Patch {
                scratch.decode_patch_from_slice(remaining)?
            } else {
                scratch.decode_node_from_slice(stored_node_id, remaining)?
            };
            scratch.restore_node_bytes(buf);
            return if stored_node_id == TrieNodeID::Patch {
                Ok(ReadTrieItem::from_patch(scratch.patch(), Some(rehash)))
            } else {
                Ok(ReadTrieItem::from_node(ReadTrieNode::from_state_borrowed(
                    scratch.get_ref(),
                    Some(rehash),
                )))
            };
        }

        let _consumed = if stored_node_id == TrieNodeID::Patch {
            scratch.decode_patch_from_slice(remaining)?
        } else {
            scratch.decode_node_from_slice(stored_node_id, remaining)?
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

    /// Read a hash-free leaf's body at `file_offset`, decode it, and compute
    /// its hash (SHA-512/256 of the canonical `write_bytes()` representation).
    /// For `TrieLeafSquashed`, the hash covers the tip value only (same as
    /// `get_nodetype_hash_bytes`).
    fn recompute_leaf_hash_at(&self, file_offset: u64, ptr_id: u8) -> Result<TrieHash, Error> {
        // Decode the leaf node from either the mmap slice (zero-copy) or a
        // positional read into a temporary buffer.
        let decode_from_slice = |slice: &[u8]| -> Result<TrieNodeType, Error> {
            let stored_id_byte = *slice.first().ok_or_else(|| {
                Error::CorruptionError("Empty leaf body in recompute_leaf_hash_at".into())
            })?;
            let stored_id = node::clear_ctrl_bits(stored_id_byte);
            let (node, _) = bits::decode_nodetype_from_slice_at_head(slice, stored_id)?;
            Ok(node)
        };

        let node = if let Some(bytes) = self.mmap_slice_at(file_offset) {
            // Zero-copy: decode directly from the mmap region.
            decode_from_slice(bytes)?
        } else {
            // Slow path: positional read into a temporary buffer.
            let hinted_max = bits::get_node_body_max_byte_len(ptr_id)?;
            let mut buf = vec![0u8; hinted_max];
            let n = self.read_bytes_at(&mut buf, file_offset)?;
            buf.truncate(n);

            // If the stored type is larger than the hinted type, re-read.
            let stored_id = node::clear_ctrl_bits(*buf.first().ok_or_else(|| {
                Error::CorruptionError("Empty leaf body in recompute_leaf_hash_at".into())
            })?);
            let stored_max = bits::get_node_body_max_byte_len(stored_id)?;
            if stored_max > hinted_max {
                buf.resize(stored_max, 0);
                let n = self.read_bytes_at(&mut buf, file_offset)?;
                buf.truncate(n);
            }

            decode_from_slice(&buf)?
        };

        // Leaf hash: SHA-512/256(write_bytes()). For LeafSquashed, uses tip
        // value only (consistent with get_nodetype_hash_bytes).
        use sha2::{Digest, Sha512_256 as TrieHasher};

        use crate::chainstate::stacks::index::node::{TrieNode, TrieNodeType};
        let mut hasher = TrieHasher::new();
        match &node {
            TrieNodeType::Leaf(leaf) => {
                leaf.write_bytes(&mut hasher)
                    .expect("IO failure pushing to hasher");
            }
            TrieNodeType::LeafSquashed(sq) => {
                let leaf = crate::chainstate::stacks::index::TrieLeaf {
                    path: sq.path,
                    data: sq.tip_value()?.clone(),
                };
                leaf.write_bytes(&mut hasher)
                    .expect("IO failure pushing to hasher");
            }
            _ => {
                return Err(Error::CorruptionError(
                    "recompute_leaf_hash_at: not a leaf node".into(),
                ));
            }
        }
        let res: [u8; 32] = hasher.finalize().into();
        Ok(TrieHash(res))
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
    ///
    /// When `leaf_hashes_omitted` is true, leaf nodes lack a hash prefix in
    /// the blob and the hash is recomputed from the node body.
    pub fn get_node_hash(
        &self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
        trie_offset: Option<u64>,
        leaf_hashes_omitted: bool,
    ) -> Result<TrieHash, Error> {
        let offset = trie_offset.map_or_else(|| self.get_trie_offset(db, block_id), Ok)?;
        let file_offset = offset + ptr.ptr() as u64;
        if leaf_hashes_omitted && node::is_leaf_type(ptr.id()) {
            self.recompute_leaf_hash_at(file_offset, ptr.id())
        } else {
            self.read_hash_at(file_offset)
        }
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
        leaf_hashes_omitted: bool,
        scratch: &'a mut impl NodeDecodeScratch,
    ) -> Result<ReadTrieItem<'a>, Error> {
        let offset = trie_offset.map_or_else(|| self.get_trie_offset(db, block_id), Ok)?;
        self.read_item_at_offset(offset + ptr.ptr() as u64, ptr, leaf_hashes_omitted, scratch)
    }

    /// Read a trie item as borrowed bytes from the mmap region (zero-copy). Returns `None`
    /// if mmap is not active or the node is a patch.
    ///
    /// The returned `ReadTrieItem<'a>` carries the supplied `BlobReadGuard`, which keeps
    /// the blob-mutation quiesce counter incremented for as long as the borrowed mmap bytes
    /// are in use. The caller acquires the guard (via
    /// [`SharedStorageState::acquire_blob_read`]) before calling this function and passes
    /// ownership in; the guard is dropped when the returned `ReadTrieItem` is dropped,
    /// releasing the writer-drain waiter.
    pub fn read_trie_item_borrowed<'a>(
        &'a self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
        trie_offset_hint: Option<u64>,
        leaf_hashes_omitted: bool,
        guard: BlobReadGuard,
    ) -> Result<Option<ReadTrieItem<'a>>, Error> {
        let offset = trie_offset_hint.map_or_else(|| self.get_trie_offset(db, block_id), Ok)?;
        let Some(bytes) = self.mmap_slice_at(offset + ptr.ptr() as u64) else {
            return Ok(None);
        };
        if leaf_hashes_omitted && node::is_leaf_type(ptr.id()) {
            // Hash-free leaf: body starts at byte 0, hash deferred to explicit
            // hash paths (get_node_hash / write_children_hashes).
            let stored_node_id = bits::stored_node_id_from_bytes(bytes).map_err(|e| {
                error!(
                    "read_trie_item_borrowed: hash-free leaf decode failed: \
                     block_id={block_id}, ptr={ptr:?}, file_offset={}, err={e:?}",
                    offset + ptr.ptr() as u64,
                );
                e
            })?;
            if stored_node_id == TrieNodeID::Patch {
                return Ok(None);
            }
            let node_bytes = BorrowedNodeBytes::new(stored_node_id, bytes);
            return Ok(Some(ReadTrieItem::from_node(
                ReadTrieNode::from_stable_bytes(node_bytes, None).with_blob_guard(guard),
            )));
        }
        let (hash, remaining) = bits::parse_hash_from_bytes(bytes)?;
        let stored_node_id = bits::stored_node_id_from_bytes(remaining).map_err(|e| {
            error!(
                "read_trie_item_borrowed: node ID after hash failed: \
                 block_id={block_id}, ptr={ptr:?}, leaf_hashes_omitted={leaf_hashes_omitted}, \
                 file_offset={}, is_leaf_hint={}",
                offset + ptr.ptr() as u64,
                node::is_leaf_type(ptr.id()),
            );
            e
        })?;
        if stored_node_id == TrieNodeID::Patch {
            return Ok(None);
        }
        let node_bytes = BorrowedNodeBytes::new(stored_node_id, remaining);
        Ok(Some(ReadTrieItem::from_node(
            ReadTrieNode::from_stable_bytes(node_bytes, Some(hash)).with_blob_guard(guard),
        )))
    }

    /// Read the node type ID and hash at the given block and pointer.
    ///
    /// When `leaf_hashes_omitted` is true, leaf nodes are stored without a
    /// hash prefix; the hash is recomputed from the body.
    pub fn read_node_type_id(
        &self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
        leaf_hashes_omitted: bool,
    ) -> Result<(TrieNodeID, TrieHash), Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        let file_offset = offset + ptr.ptr() as u64;
        if leaf_hashes_omitted && node::is_leaf_type(ptr.id()) {
            // Hash-free leaf: ID at byte 0, recompute hash from body.
            if let Some(bytes) = self.mmap_slice_at(file_offset) {
                let stored_id = bits::stored_node_id_from_bytes(bytes)?;
                let hash = self.recompute_leaf_hash_at(file_offset, ptr.id())?;
                return Ok((stored_id, hash));
            }
            let mut id_buf = [0u8; 1];
            let n = self.read_bytes_at(&mut id_buf, file_offset)?;
            if n < 1 {
                return Err(Error::CorruptionError(
                    "Failed to read node ID for hash-free leaf".into(),
                ));
            }
            let stored_id = bits::stored_node_id_from_bytes(&id_buf)?;
            let hash = self.recompute_leaf_hash_at(file_offset, ptr.id())?;
            Ok((stored_id, hash))
        } else {
            self.read_node_type_at(file_offset)
        }
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

    /// Write a blob at a specific offset in the blob file, then truncate the file
    /// to exactly `offset + buf.len()` and remap the mmap.
    ///
    /// # Safety contract
    ///
    /// The caller MUST coordinate exclusive access against any concurrent reader
    /// — typically via the [`SharedStorageState::publish_squash`] quiesce protocol — and
    /// MUST have validated that no live `marf_data` or `marf_squash_levels` row references
    /// any byte at or beyond `offset` that is not being superseded by this write.
    ///
    /// This is an **experimental** reclamation primitive. Until crash recovery is
    /// implemented (pending-file + recovery gate), a crash between the pwrite and
    /// the subsequent metadata commit leaves the blob file in a state that requires
    /// manual intervention.
    pub fn write_blob_at_and_truncate(&mut self, buf: &[u8], offset: u64) -> Result<(), Error> {
        let new_len = offset + buf.len() as u64;

        match self {
            TrieFile::Disk(ref mut disk) => {
                pwrite_all(&disk.fd, buf, offset)?;
                disk.fd.set_len(new_len)?;
                disk.fd.sync_data()?;
                if disk.mmap_enabled {
                    // Remap to cover exactly the new file extent.
                    // SAFETY: exclusive access, file just fsynced, no concurrent readers.
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
                data.truncate(end);
            }
        }

        // Invalidate the trie offset cache — offsets for blocks that were in the
        // truncated region are now stale.
        match self {
            TrieFile::Disk(ref disk) => disk.trie_offsets.borrow_mut().clear(),
            TrieFile::RAM(ref ram) => ram.trie_offsets.borrow_mut().clear(),
        }

        Ok(())
    }

    /// Write a chunk of blob data at the given file offset without syncing or
    /// remapping.
    ///
    /// Used by the streaming squash blob writer to avoid building the entire blob
    /// in memory. Call [`finish_blob_write`] after all chunks are written.
    pub fn pwrite_blob_chunk(&mut self, data: &[u8], offset: u64) -> Result<(), Error> {
        match self {
            TrieFile::Disk(ref disk) => {
                pwrite_all(&disk.fd, data, offset)?;
            }
            TrieFile::RAM(ref mut ram) => {
                let buf = ram.fd.get_mut();
                let start = offset as usize;
                let end = start + data.len();
                if buf.len() < end {
                    buf.resize(end, 0);
                }
                buf.get_mut(start..end)
                    .expect("BUG: just resized to cover range")
                    .copy_from_slice(data);
            }
        }
        Ok(())
    }

    /// Finalize a streaming blob write: optionally truncate the file, sync to disk,
    /// remap the mmap, and clear the trie offset cache.
    ///
    /// If `truncate_to` is `Some(len)`, the file is truncated to exactly `len` bytes
    /// (used by reclaim mode). If `None`, the file is left at its current size
    /// (used by append mode).
    pub fn finish_blob_write(&mut self, truncate_to: Option<u64>) -> Result<(), Error> {
        match self {
            TrieFile::Disk(ref mut disk) => {
                if let Some(len) = truncate_to {
                    disk.fd.set_len(len)?;
                }
                disk.fd.sync_data()?;
                if disk.mmap_enabled {
                    disk.mmap = Some(unsafe { Mmap::map(&disk.fd)? });
                }
                disk.trie_offsets.borrow_mut().clear();
            }
            TrieFile::RAM(ref mut ram) => {
                if let Some(len) = truncate_to {
                    ram.fd.get_mut().truncate(len as usize);
                }
                ram.trie_offsets.borrow_mut().clear();
            }
        }
        Ok(())
    }

    /// Remap the mmap (if any) to cover the current file extent and clear
    /// the trie offset cache. Call after an external writer (e.g. squash)
    /// has modified the blob file through a separate handle.
    pub fn remap_and_invalidate(&mut self) -> Result<(), Error> {
        match self {
            TrieFile::Disk(ref mut disk) => {
                if disk.mmap_enabled {
                    let file_len = disk.fd.metadata()?.len();
                    if file_len > 0 {
                        disk.mmap = Some(unsafe { Mmap::map(&disk.fd)? });
                    } else {
                        disk.mmap = None;
                    }
                }
                disk.trie_offsets.borrow_mut().clear();
            }
            TrieFile::RAM(ref ram) => {
                ram.trie_offsets.borrow_mut().clear();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod testing {
    use rusqlite::params;

    use super::*;
    use crate::chainstate::stacks::index::storage;
    use crate::types::chainstate::TrieHash;

    impl TrieFile {
        pub fn read_trie_blob(&self, db: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
            self.read_trie_blob_bytes(db, block_id)
        }

        /// Obtain a TrieHash for a node, given the node's block's hash (used only in testing)
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
}
