// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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

//! Per-level history-blob files for FullHistory squash mode.
//!
//! Each FullHistory squash level emits one of these alongside its cold-blob
//! extent and root sidecar (see [`.docs/full-history-history-blob-design.md`](../../../../../.docs/full-history-history-blob-design.md)).
//! A history blob holds **per-distinct-key** value-transition chunks: each
//! chunk is the full `(height, MARFValue)` history for one key in the
//! squash range, sorted descending by height. Multiple physical leaves
//! sharing the same `TrieHash` reference the **same chunk** via dedup.
//!
//! On-disk layout (v1):
//!
//! ```text
//! +-------------------+ offset 0
//! | HistoryBlobHeader |  10 bytes — magic(4) + version(1) + flags(1) + level_id(4)
//! +-------------------+ offset 10
//! | Chunk 0           |  HistoryChunkHeader(6) + entries(entry_count × 44)
//! +-------------------+
//! | Chunk 1           |
//! +-------------------+
//! | ...               |
//! +-------------------+ offset = 10 + body_len
//! | HistoryBlobFooter |  24 bytes — chunk_count(4) + total_entry_count(8) +
//! |                   |             body_len(8) + magic(4)
//! +-------------------+ EOF
//! ```
//!
//! Counts (`chunk_count`, `total_entry_count`) live in the footer because
//! they're only known after every chunk has been appended — putting them in
//! the header would require a seek-back-to-update on close. The trailing
//! `magic` distinguishes "fully written" from "torn" in a single read at
//! the end of the file.
//!
//! See §5.2, §6.1, §6.1.1, §6.2 of the design doc for the full contract.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::chainstate::stacks::index::{Error, MARFValue};

// ---------------------------------------------------------------------------
// File-format constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of the file header and end of the file footer.
pub const HISTORY_BLOB_MAGIC: [u8; 4] = *b"MHIS";

/// File-format version. Bump only on incompatible changes; the chunk format
/// has its own per-chunk version (see [`HistoryChunkHeader`]) for future
/// variable-length-value support without a file-level migration.
pub const HISTORY_BLOB_VERSION: u8 = 1;

/// Header bit 0: chunk entries use the fixed-`MARFValue` encoding (v1).
/// When this bit is clear in a future v2, chunks use variable-length values.
pub const HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING: u8 = 0x01;

/// Fixed file-header size in bytes: magic(4) + version(1) + flags(1) + level_id(4).
pub const HISTORY_BLOB_HEADER_SIZE: usize = 10;

/// Fixed file-footer size in bytes:
/// chunk_count(4) + total_entry_count(8) + body_len(8) + magic(4).
pub const HISTORY_BLOB_FOOTER_SIZE: usize = 24;

/// Fixed chunk-header size in bytes: version(1) + flags(1) + entry_count(4).
pub const HISTORY_CHUNK_HEADER_SIZE: usize = 6;

/// Per-entry payload in v1 fixed-encoding chunks: height(4) + MARFValue(40).
pub const HISTORY_CHUNK_ENTRY_SIZE_V1: usize = 4 + 40;

/// Chunk-format version. Always equals [`HISTORY_BLOB_VERSION`] in v1.
pub const HISTORY_CHUNK_VERSION: u8 = 1;

/// Chunk flag bit 0: entries use the fixed-`MARFValue` encoding (v1).
pub const HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING: u8 = 0x01;

// ---------------------------------------------------------------------------
// File-header / file-footer / chunk-header types
// ---------------------------------------------------------------------------

/// Identifying header at the start of a history blob file. Written once at
/// file creation; never rewritten. Counts that are only known at finalize
/// time live in [`HistoryBlobFooter`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryBlobHeader {
    pub version: u8,
    pub flags: u8,
    pub level_id: u32,
}

impl HistoryBlobHeader {
    /// Encode the header as `HISTORY_BLOB_HEADER_SIZE` bytes (big-endian).
    pub fn encode(&self) -> [u8; HISTORY_BLOB_HEADER_SIZE] {
        let mut buf = [0u8; HISTORY_BLOB_HEADER_SIZE];
        buf[0..4].copy_from_slice(&HISTORY_BLOB_MAGIC);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..10].copy_from_slice(&self.level_id.to_be_bytes());
        buf
    }

    /// Decode and validate. Surfaces `Error::CorruptionError` on bad magic,
    /// unsupported version, or invalid flag bits. v1 requires
    /// [`HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING`] to be set and rejects any
    /// reserved bits — without these checks, a wrong-format file whose
    /// footer shape happens to match could pass validation. We surface
    /// non-v1 as corruption rather than silently downgrading; there's no
    /// v0 in the wild, so any non-v1 is either truncation or wrong format.
    #[allow(clippy::indexing_slicing)] // length-checked above against HISTORY_BLOB_HEADER_SIZE
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HISTORY_BLOB_HEADER_SIZE {
            return Err(Error::CorruptionError(format!(
                "history blob: header truncated ({} < {})",
                bytes.len(),
                HISTORY_BLOB_HEADER_SIZE
            )));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != HISTORY_BLOB_MAGIC {
            return Err(Error::CorruptionError(format!(
                "history blob: bad header magic {:?}, expected {:?}",
                magic, HISTORY_BLOB_MAGIC
            )));
        }
        let version = bytes[4];
        if version != HISTORY_BLOB_VERSION {
            return Err(Error::CorruptionError(format!(
                "history blob: unsupported version {} (expected {})",
                version, HISTORY_BLOB_VERSION
            )));
        }
        let flags = bytes[5];
        if flags & HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING == 0 {
            return Err(Error::CorruptionError(format!(
                "history blob: v1 requires fixed-value-encoding flag bit set in 0x{flags:02x}",
            )));
        }
        let reserved_mask = !HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING;
        if flags & reserved_mask != 0 {
            return Err(Error::CorruptionError(format!(
                "history blob: reserved header flag bits set (flags=0x{flags:02x}, valid mask 0x{:02x})",
                HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING
            )));
        }
        let level_id = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        Ok(Self {
            version,
            flags,
            level_id,
        })
    }
}

/// Trailing footer at the end of a history blob file. Written once at
/// finalize. The trailing `magic` distinguishes "fully written" from "torn"
/// in a single read at file end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryBlobFooter {
    /// Number of distinct-key chunks in this file (= `needed_keys.len()`
    /// per the design doc §7.3, NOT physical-leaf count — the same key
    /// contributes one chunk regardless of how many leaves reference it).
    pub chunk_count: u32,
    /// Sum of `entry_count` across DISTINCT chunks (NOT summed across
    /// physical leaves; many leaves share one chunk via dedup).
    pub total_entry_count: u64,
    /// Bytes from end-of-header to start-of-footer
    /// (= total file size − header size − footer size).
    pub body_len: u64,
}

impl HistoryBlobFooter {
    pub fn encode(&self) -> [u8; HISTORY_BLOB_FOOTER_SIZE] {
        let mut buf = [0u8; HISTORY_BLOB_FOOTER_SIZE];
        buf[0..4].copy_from_slice(&self.chunk_count.to_be_bytes());
        buf[4..12].copy_from_slice(&self.total_entry_count.to_be_bytes());
        buf[12..20].copy_from_slice(&self.body_len.to_be_bytes());
        buf[20..24].copy_from_slice(&HISTORY_BLOB_MAGIC);
        buf
    }

    /// Decode + validate the trailing magic. The caller is responsible for
    /// cross-checking `body_len` against `file_length - header - footer`
    /// (see [`HistoryBlobReader::open`], which performs that check at file
    /// open time per `.docs/full-history-history-blob-design.md` §9.4).
    #[allow(clippy::indexing_slicing)] // length-checked above against HISTORY_BLOB_FOOTER_SIZE
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HISTORY_BLOB_FOOTER_SIZE {
            return Err(Error::CorruptionError(format!(
                "history blob: footer truncated ({} < {})",
                bytes.len(),
                HISTORY_BLOB_FOOTER_SIZE
            )));
        }
        let chunk_count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut total_arr = [0u8; 8];
        total_arr.copy_from_slice(&bytes[4..12]);
        let total_entry_count = u64::from_be_bytes(total_arr);
        let mut body_arr = [0u8; 8];
        body_arr.copy_from_slice(&bytes[12..20]);
        let body_len = u64::from_be_bytes(body_arr);
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[20..24]);
        if magic != HISTORY_BLOB_MAGIC {
            return Err(Error::CorruptionError(format!(
                "history blob: bad footer magic {:?}, expected {:?} (truncated or wrong format)",
                magic, HISTORY_BLOB_MAGIC
            )));
        }
        Ok(Self {
            chunk_count,
            total_entry_count,
            body_len,
        })
    }
}

/// Per-chunk header. Allows chunks within a single file to use different
/// encodings (the v1/v2 split in §6.3 — v1 = fixed 40B values, v2 = variable
/// per-entry length). v1 only ever emits chunks with `version = 1` and
/// `flags = HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryChunkHeader {
    pub version: u8,
    pub flags: u8,
    pub entry_count: u32,
}

impl HistoryChunkHeader {
    pub fn encode(&self) -> [u8; HISTORY_CHUNK_HEADER_SIZE] {
        let mut buf = [0u8; HISTORY_CHUNK_HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.flags;
        buf[2..6].copy_from_slice(&self.entry_count.to_be_bytes());
        buf
    }

    #[allow(clippy::indexing_slicing)] // length-checked above against HISTORY_CHUNK_HEADER_SIZE
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HISTORY_CHUNK_HEADER_SIZE {
            return Err(Error::CorruptionError(format!(
                "history chunk: header truncated ({} < {})",
                bytes.len(),
                HISTORY_CHUNK_HEADER_SIZE
            )));
        }
        let version = bytes[0];
        if version != HISTORY_CHUNK_VERSION {
            return Err(Error::CorruptionError(format!(
                "history chunk: unsupported chunk version {} (expected {})",
                version, HISTORY_CHUNK_VERSION
            )));
        }
        let flags = bytes[1];
        // v1: must have fixed-value-encoding bit set; no other flag bits valid yet.
        if flags & HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING == 0 {
            return Err(Error::CorruptionError(
                "history chunk: v1 requires fixed-value-encoding flag bit set".into(),
            ));
        }
        let reserved_mask = !HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING;
        if flags & reserved_mask != 0 {
            return Err(Error::CorruptionError(format!(
                "history chunk: reserved flag bits set (flags=0x{:02x})",
                flags
            )));
        }
        let entry_count = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        if entry_count == 0 {
            return Err(Error::CorruptionError(
                "history chunk: entry_count == 0 is invalid (per §6.4 invariant)".into(),
            ));
        }
        Ok(Self {
            version,
            flags,
            entry_count,
        })
    }

    /// Total byte length of this chunk on disk
    /// (header + entries × per-entry size).
    pub fn chunk_byte_len(&self) -> usize {
        HISTORY_CHUNK_HEADER_SIZE + (self.entry_count as usize) * HISTORY_CHUNK_ENTRY_SIZE_V1
    }
}

// ---------------------------------------------------------------------------
// ChunkRef — pointer carried in the leaf
// ---------------------------------------------------------------------------

/// Pointer from a `TrieLeafSquashed` (subtype 2) into a chunk in the
/// history blob, plus the per-key tip value. Captured at chunk-emission
/// time (Phase A.6 in the design doc) so Phase B can drop the in-memory
/// `history` map before leaf rewrite — see §7.3 / §7.4.
///
/// Not `Copy` because `MARFValue` is `[u8; 40]` and not `Copy` itself.
/// `Clone` is cheap (40B inline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    /// Byte offset from the start of the history blob file to the start
    /// of this chunk's `HistoryChunkHeader`.
    pub history_offset: u64,
    /// Bytes occupied by this chunk on disk
    /// (= `HistoryChunkHeader` + entries).
    pub history_byte_len: u32,
    /// Number of `(height, value)` entries in this chunk.
    pub history_entry_count: u32,
    /// The tip-era value for this key (= `chunk[0].value`, since entries
    /// are descending by height). Cached here so tip reads can answer
    /// from the leaf body alone, no history-blob I/O.
    pub tip_value: MARFValue,
}

// ---------------------------------------------------------------------------
// Chunk decode / value lookup
// ---------------------------------------------------------------------------

/// A decoded history chunk (v1 fixed-encoding). Borrows from the chunk
/// bytes — typically an `mmap` region — to avoid copying the entries
/// vector for every read.
///
/// Lifetime is tied to whatever buffer the caller passed to
/// [`HistoryChunk::decode`].
#[derive(Debug, Clone)]
pub struct HistoryChunk<'a> {
    pub entry_count: u32,
    /// Raw entries bytes, length = `entry_count × HISTORY_CHUNK_ENTRY_SIZE_V1`.
    /// Sorted descending by height.
    entries_bytes: &'a [u8],
}

impl<'a> HistoryChunk<'a> {
    /// Decode a chunk from a byte slice. The slice must start with the
    /// chunk header and contain the full chunk (header + entries).
    /// Returns the decoded chunk or `Error::CorruptionError`.
    #[allow(clippy::indexing_slicing)] // length-checked above against chunk_total
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = HistoryChunkHeader::decode(bytes)?;
        let chunk_total = header.chunk_byte_len();
        if bytes.len() < chunk_total {
            return Err(Error::CorruptionError(format!(
                "history chunk: body truncated ({} < {})",
                bytes.len(),
                chunk_total
            )));
        }
        let entries_bytes = &bytes[HISTORY_CHUNK_HEADER_SIZE..chunk_total];
        Ok(Self {
            entry_count: header.entry_count,
            entries_bytes,
        })
    }

    /// Number of `(height, value)` entries in this chunk.
    pub fn len(&self) -> usize {
        self.entry_count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Read the `(height, MARFValue)` entry at index `idx` (0-based,
    /// in the chunk's natural descending-by-height order).
    ///
    /// `entries_bytes.len() == entry_count × HISTORY_CHUNK_ENTRY_SIZE_V1`
    /// by construction in [`Self::decode`]; this method is private and
    /// callers must pass `idx < entry_count`.
    #[allow(clippy::indexing_slicing)] // see invariant in doc comment
    fn entry_at(&self, idx: usize) -> (u32, MARFValue) {
        let off = idx * HISTORY_CHUNK_ENTRY_SIZE_V1;
        let height = u32::from_be_bytes([
            self.entries_bytes[off],
            self.entries_bytes[off + 1],
            self.entries_bytes[off + 2],
            self.entries_bytes[off + 3],
        ]);
        let mut value = MARFValue([0u8; 40]);
        value
            .0
            .copy_from_slice(&self.entries_bytes[off + 4..off + HISTORY_CHUNK_ENTRY_SIZE_V1]);
        (height, value)
    }

    /// Point-in-time lookup. Returns the value from the most recent
    /// transition at or before `query_height`, or `None` if the key
    /// did not exist at that height (i.e., the query is below the
    /// chunk's earliest entry — which encodes either the first in-range
    /// write or the synthetic `(min_height - 1, baseline)` entry from
    /// inheritance, depending on whether the key was inherited).
    ///
    /// Matches the existing `TrieLeafSquashed::value_at_height` semantics
    /// per §8.2 of the design doc.
    pub fn value_at_height(&self, query_height: u32) -> Option<MARFValue> {
        // entries are descending by height; partition_point returns the
        // first index whose height is NOT `> query_height` (i.e., the
        // first entry whose height is `<= query_height`).
        let n = self.len();
        // Manual binary-search since we read entries lazily from the byte
        // slice — Vec::partition_point would force a full decode.
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (h, _) = self.entry_at(mid);
            if h > query_height {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo >= n {
            None
        } else {
            Some(self.entry_at(lo).1)
        }
    }

    /// Decode every entry into an owned `Vec`. Used by tests; the read
    /// path uses [`Self::value_at_height`] (which avoids the allocation).
    pub fn entries_owned(&self) -> Vec<(u32, MARFValue)> {
        (0..self.len()).map(|i| self.entry_at(i)).collect()
    }
}

// ---------------------------------------------------------------------------
// HistoryBlobWriter
// ---------------------------------------------------------------------------

/// Append-only writer for a history blob file. The writer takes a
/// **tmp path** at construction; finalize + rename to the canonical path
/// is the caller's responsibility (typically deferred until `blob_offset`
/// is known at publish time per §9.2 step 1).
///
/// Lifecycle:
///
/// 1. [`Self::create_at`] — opens at `tmp_path`, writes the file header.
/// 2. [`Self::append_chunk`] — once per distinct key during Phase A.6.
/// 3. [`Self::finalize`] — writes the footer, flushes, fsyncs, closes
///    the fd. The file remains at `tmp_path`. The caller renames it to
///    the canonical history-blob path (see [`history_blob_path`]) once
///    `blob_offset` is known.
/// 4. Dropping without `finalize` (or calling [`Self::cancel`]) unlinks
///    the tmp file. Recovery (§9.4) also sweeps stale tmp files.
pub struct HistoryBlobWriter {
    /// Buffered writer over the tmp file. `None` after `finalize` or
    /// `cancel`; methods that need it panic if called after consumption.
    writer: Option<BufWriter<File>>,
    /// Tmp path the file is being written to. Caller chose this; the
    /// writer keeps it for `Drop`/`cancel` cleanup.
    tmp_path: PathBuf,
    /// Header bytes already on disk (count from `next_offset = 0`
    /// at creation time).
    next_offset: u64,
    /// Running counters used to populate the footer at `finalize`.
    chunk_count: u32,
    total_entry_count: u64,
    /// Set by `finalize` / `cancel` to suppress the `Drop` cleanup.
    finished: bool,
}

impl HistoryBlobWriter {
    /// Open a new history blob file at `tmp_path` and write the header.
    /// If the path already exists (stale from a prior crashed run), it
    /// is overwritten.
    ///
    /// The caller chooses `tmp_path` (typically via [`history_blob_tmp_path`]).
    /// After [`Self::finalize`] returns, the caller is responsible for
    /// renaming `tmp_path` to the canonical [`history_blob_path`] keyed
    /// on the published `blob_offset`.
    pub fn create_at(tmp_path: PathBuf, level_id: u32) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .map_err(Error::IOError)?;
        let mut writer = BufWriter::new(file);
        let header = HistoryBlobHeader {
            version: HISTORY_BLOB_VERSION,
            flags: HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING,
            level_id,
        };
        writer.write_all(&header.encode()).map_err(Error::IOError)?;
        Ok(Self {
            writer: Some(writer),
            tmp_path,
            next_offset: HISTORY_BLOB_HEADER_SIZE as u64,
            chunk_count: 0,
            total_entry_count: 0,
            finished: false,
        })
    }

    /// Path the writer is writing to. Useful for the caller's later
    /// rename-to-canonical step.
    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    /// Append one chunk of entries (one distinct key's history). `entries`
    /// must be sorted **descending by height** (matches `value_at_height`'s
    /// partition-point semantics) and non-empty (the §5.2 / §6.4 invariant
    /// — `has_history` always implies `entry_count >= 1`).
    ///
    /// Returns the chunk's offset and byte-length, suitable for stashing
    /// into a [`ChunkRef`] alongside the per-key `tip_value`.
    #[allow(clippy::indexing_slicing)] // windows(2) guarantees each w has length 2
    pub fn append_chunk(&mut self, entries: &[(u32, MARFValue)]) -> Result<(u64, u32), Error> {
        if entries.is_empty() {
            return Err(Error::CorruptionError(
                "history blob: refusing to append empty chunk (history_entry_count >= 1 invariant)"
                    .into(),
            ));
        }
        let entry_count = u32::try_from(entries.len()).map_err(|_| {
            Error::CorruptionError("history blob: chunk entry_count exceeds u32".into())
        })?;
        // Defensive: verify descending-by-height ordering. Failing this check at write
        // time turns a Phase A.6 ordering bug into a CorruptionError instead of corrupt
        // on-disk bytes that only fail on read.
        if !entries.windows(2).all(|w| w[0].0 >= w[1].0) {
            return Err(Error::CorruptionError(
                "history blob: chunk entries must be sorted descending by height".into(),
            ));
        }
        let chunk_offset = self.next_offset;
        let header = HistoryChunkHeader {
            version: HISTORY_CHUNK_VERSION,
            flags: HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING,
            entry_count,
        };
        let writer = self.writer_mut();
        writer.write_all(&header.encode()).map_err(Error::IOError)?;
        for (height, value) in entries {
            writer
                .write_all(&height.to_be_bytes())
                .map_err(Error::IOError)?;
            writer.write_all(&value.0).map_err(Error::IOError)?;
        }
        let chunk_byte_len_usize = header.chunk_byte_len();
        let chunk_byte_len =
            u32::try_from(chunk_byte_len_usize).map_err(|_| Error::OverflowError)?;
        self.next_offset = self
            .next_offset
            .checked_add(chunk_byte_len_usize as u64)
            .ok_or(Error::OverflowError)?;
        self.chunk_count = self
            .chunk_count
            .checked_add(1)
            .ok_or(Error::OverflowError)?;
        self.total_entry_count = self
            .total_entry_count
            .checked_add(entries.len() as u64)
            .ok_or(Error::OverflowError)?;
        Ok((chunk_offset, chunk_byte_len))
    }

    /// Write the footer, flush, and fsync the file. The file remains at
    /// `tmp_path`; the caller is responsible for renaming to the
    /// canonical path keyed on `blob_offset` at publish time.
    ///
    /// On success, the bytes at `tmp_path` are a complete, footer-validated
    /// history blob (recovery would accept them after rename).
    pub fn finalize(mut self) -> Result<(), Error> {
        let body_len = self
            .next_offset
            .checked_sub(HISTORY_BLOB_HEADER_SIZE as u64)
            .ok_or_else(|| {
                Error::CorruptionError("history blob: next_offset < header size".into())
            })?;
        let footer = HistoryBlobFooter {
            chunk_count: self.chunk_count,
            total_entry_count: self.total_entry_count,
            body_len,
        };
        let mut writer = self
            .writer
            .take()
            .expect("BUG: HistoryBlobWriter::finalize called after writer was taken");
        writer.write_all(&footer.encode()).map_err(Error::IOError)?;
        writer.flush().map_err(Error::IOError)?;
        let file = writer
            .into_inner()
            .map_err(|e| Error::IOError(e.into_error()))?;
        file.sync_all().map_err(Error::IOError)?;
        drop(file);
        self.finished = true;
        Ok(())
    }

    /// Abandon the in-progress write: close the tmp file and unlink it.
    /// Useful for error paths that have already opened the writer but
    /// can't proceed.
    pub fn cancel(mut self) -> Result<(), Error> {
        let _ = self.writer.take(); // drop the fd
        let unlink_result = std::fs::remove_file(&self.tmp_path);
        self.finished = true;
        match unlink_result {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::IOError(e)),
        }
    }

    fn writer_mut(&mut self) -> &mut BufWriter<File> {
        self.writer
            .as_mut()
            .expect("BUG: HistoryBlobWriter::writer_mut called after writer was taken")
    }
}

impl Drop for HistoryBlobWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Torn write: close the fd first, then unlink. Tolerate NotFound for the
        // double-cleanup case (cancel + drop, etc.).
        let _ = self.writer.take();
        match std::fs::remove_file(&self.tmp_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                "Failed to remove orphan history blob tmp file {}: {e}",
                self.tmp_path.display()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// StagedHistoryBlob — RAII guard for finalized-but-not-yet-renamed tmp files
// ---------------------------------------------------------------------------

/// RAII guard around a finalized history-blob tmp path that has been
/// fsync'd to disk but not yet renamed to its canonical
/// `marf-history-level-{...}-blob-{blob_offset:016x}.dat` path. The rename
/// happens later in the publish flow once `blob_offset` is known.
///
/// On drop, the tmp file is unlinked — guarding the window between
/// `HistoryBlobWriter::finalize` and the canonical rename. If anything in
/// the squash prep / publish pipeline returns an `Err` after Phase A.6
/// completes (e.g. a remap or rehash failure, an unrelated SQL error, a
/// sidecar publish failure), the finalized tmp file would otherwise
/// linger until startup recovery cleans it up. That's crash-safe but
/// noisy under normal retries.
///
/// The successful rename site MUST call [`Self::forget`] to consume the
/// guard without unlinking; only then does the file remain at its
/// canonical path.
pub struct StagedHistoryBlob {
    tmp_path: PathBuf,
    /// Set to `true` by [`Self::forget`]. The Drop impl checks this flag
    /// and skips the unlink when set.
    consumed: bool,
}

impl StagedHistoryBlob {
    /// Wrap a tmp path that's been fsync'd to disk but not yet renamed.
    /// The guard owns the path and the Drop responsibility.
    pub fn new(tmp_path: PathBuf) -> Self {
        Self {
            tmp_path,
            consumed: false,
        }
    }

    /// Path of the staged file. Used by the rename site to compute the
    /// canonical destination and perform the `std::fs::rename` call.
    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    /// Consume the guard without unlinking. Call this after a successful
    /// rename to the canonical path. After this, dropping the returned
    /// `()` is a no-op — the file remains where the rename put it.
    ///
    /// The naming follows `std::mem::forget` semantics: the guard
    /// promises not to run the destructor.
    pub fn forget(mut self) {
        self.consumed = true;
        // explicit drop here is a no-op since consumed = true, but
        // makes the intent clear at call sites.
        drop(self);
    }
}

impl std::fmt::Debug for StagedHistoryBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedHistoryBlob")
            .field("tmp_path", &self.tmp_path)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl Drop for StagedHistoryBlob {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        match std::fs::remove_file(&self.tmp_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                "Failed to remove orphan staged history blob {} on drop: {e}",
                self.tmp_path.display()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// HistoryBlobReader (mmap-backed)
// ---------------------------------------------------------------------------

/// Read-only view of a history blob file. v1 commits to mmap (per §8.3 of
/// the design doc); pread is the fallback path for systems where mmap is
/// unavailable, but v1's storage backend doesn't currently take that
/// fallback. The reader is constructed via [`Self::open`], which performs
/// footer validation up front (§9.4) — the file is rejected with
/// `CorruptionError` if the footer magic, length, or `body_len` are wrong.
///
/// The reader is intended to be opened **once per level at MARF
/// level-load time** and held for the level's lifetime (per §8.3 reader
/// lifecycle). Per-`read_chunk` calls slice into the mmap region; no
/// `File::open`/`pread` syscall on the hot path.
pub struct HistoryBlobReader {
    mmap: Mmap,
    header: HistoryBlobHeader,
    footer: HistoryBlobFooter,
    /// Byte offset from start of file to start of body
    /// (= [`HISTORY_BLOB_HEADER_SIZE`]; cached for clarity at call sites).
    body_start: u64,
}

// `Mmap` does not implement `Debug`; provide a manual impl that prints the
// validated header/footer (the useful diagnostic info) and the mapping length.
impl std::fmt::Debug for HistoryBlobReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryBlobReader")
            .field("header", &self.header)
            .field("footer", &self.footer)
            .field("body_start", &self.body_start)
            .field("mmap_len", &self.mmap.len())
            .finish()
    }
}

impl HistoryBlobReader {
    /// Open and validate a history blob file. Returns `CorruptionError`
    /// if the file fails any of:
    ///
    /// - exists and is at least `header + footer` bytes long
    /// - header magic + version are valid
    /// - footer magic is valid
    /// - `header_size + body_len + footer_size == file_length`
    /// - level_id matches the caller's expectation (when supplied)
    #[allow(clippy::indexing_slicing)] // mmap len is verified >= min_size above; footer_start is derived from file_len
    pub fn open(path: &Path, expected_level_id: Option<u32>) -> Result<Self, Error> {
        let file = File::open(path).map_err(Error::IOError)?;
        let metadata = file.metadata().map_err(Error::IOError)?;
        let file_len = metadata.len();
        let min_size = (HISTORY_BLOB_HEADER_SIZE + HISTORY_BLOB_FOOTER_SIZE) as u64;
        if file_len < min_size {
            return Err(Error::CorruptionError(format!(
                "history blob {}: file too short ({} < {})",
                path.display(),
                file_len,
                min_size
            )));
        }
        // SAFETY: `Mmap::map` is unsafe because external mutation (writer + reader on
        // the same file path, or a process truncating the file) would invalidate the
        // mapping. Per the design (§8.3) the writer renames the tmp file once on
        // `finalize` — the file at `path` is then immutable for the level's lifetime
        // until trim unlinks it (which closes this reader first per §8.3 lifecycle).
        // No concurrent writer can mutate the bytes under us.
        let mmap = unsafe { Mmap::map(&file) }.map_err(Error::IOError)?;

        let header = HistoryBlobHeader::decode(&mmap[..HISTORY_BLOB_HEADER_SIZE])?;
        if let Some(expected) = expected_level_id {
            if header.level_id != expected {
                return Err(Error::CorruptionError(format!(
                    "history blob {}: header level_id {} does not match expected {}",
                    path.display(),
                    header.level_id,
                    expected
                )));
            }
        }

        let footer_start = file_len
            .checked_sub(HISTORY_BLOB_FOOTER_SIZE as u64)
            .ok_or_else(|| {
                Error::CorruptionError(format!("history blob {}: footer underflow", path.display()))
            })?;
        let footer = HistoryBlobFooter::decode(
            &mmap[footer_start as usize..(footer_start as usize + HISTORY_BLOB_FOOTER_SIZE)],
        )?;

        // Cross-check body_len against actual file length (per §9.4 step 4 'present').
        let expected_file_len = (HISTORY_BLOB_HEADER_SIZE as u64)
            .checked_add(footer.body_len)
            .and_then(|v| v.checked_add(HISTORY_BLOB_FOOTER_SIZE as u64))
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "history blob {}: footer body_len overflow",
                    path.display()
                ))
            })?;
        if expected_file_len != file_len {
            return Err(Error::CorruptionError(format!(
                "history blob {}: footer body_len {} inconsistent with file length \
                 {} (expected {} = header {} + body {} + footer {})",
                path.display(),
                footer.body_len,
                file_len,
                expected_file_len,
                HISTORY_BLOB_HEADER_SIZE,
                footer.body_len,
                HISTORY_BLOB_FOOTER_SIZE
            )));
        }

        Ok(Self {
            mmap,
            header,
            footer,
            body_start: HISTORY_BLOB_HEADER_SIZE as u64,
        })
    }

    /// File header (validated at open).
    pub fn header(&self) -> &HistoryBlobHeader {
        &self.header
    }

    /// File footer (validated at open).
    pub fn footer(&self) -> &HistoryBlobFooter {
        &self.footer
    }

    /// Byte offset where chunks start (immediately after the header).
    pub fn body_start(&self) -> u64 {
        self.body_start
    }

    /// Read the chunk at `(offset, byte_len)`. The caller is expected to
    /// supply the same `(offset, byte_len, entry_count)` triple that was
    /// stored in the leaf's `ChunkRef`. The returned `HistoryChunk`
    /// borrows directly from the mmap region — no copy.
    ///
    /// Validation (all surface `CorruptionError`):
    ///
    /// 1. `[offset, offset + byte_len)` lies entirely within the body region.
    /// 2. `byte_len` exactly equals the v1 chunk size implied by
    ///    `expected_entry_count` (`HISTORY_CHUNK_HEADER_SIZE +
    ///    expected_entry_count × HISTORY_CHUNK_ENTRY_SIZE_V1`). Without
    ///    this exact check, a corrupted leaf with an oversized `byte_len`
    ///    could overlap the next chunk and still parse the header — the
    ///    `bytes.len() >= chunk_total` check inside `HistoryChunk::decode`
    ///    only detects truncation, not over-read.
    /// 3. The decoded chunk header's `entry_count` matches the caller's
    ///    expectation (i.e., the leaf and the chunk header agree).
    #[allow(clippy::indexing_slicing)] // [offset, chunk_end) is bounds-checked against body region above
    pub fn read_chunk(
        &self,
        offset: u64,
        byte_len: u32,
        expected_entry_count: u32,
    ) -> Result<HistoryChunk<'_>, Error> {
        // (2) Exact-size check first — cheaper than the bounds check and
        // catches the "leaf says oversized chunk, body still has room"
        // case that would otherwise overlap the next chunk silently.
        let expected_byte_len = (HISTORY_CHUNK_HEADER_SIZE as u64)
            .checked_add((expected_entry_count as u64) * (HISTORY_CHUNK_ENTRY_SIZE_V1 as u64))
            .ok_or_else(|| {
                Error::CorruptionError("history chunk: expected_byte_len overflow".into())
            })?;
        if expected_byte_len > u32::MAX as u64 || byte_len as u64 != expected_byte_len {
            return Err(Error::CorruptionError(format!(
                "history chunk @ offset {offset}: byte_len {byte_len} does not match \
                 expected {expected_byte_len} for entry_count {expected_entry_count} \
                 (header {HISTORY_CHUNK_HEADER_SIZE}B + {expected_entry_count} × \
                 {HISTORY_CHUNK_ENTRY_SIZE_V1}B v1 entries)"
            )));
        }

        // (1) Bounds-check: the chunk must lie entirely in the body region.
        let chunk_end = offset
            .checked_add(byte_len as u64)
            .ok_or_else(|| Error::CorruptionError("history chunk: offset+len overflow".into()))?;
        let body_end = self.body_start + self.footer.body_len;
        if offset < self.body_start || chunk_end > body_end {
            return Err(Error::CorruptionError(format!(
                "history chunk: range [{}..{}] out of body [{}..{}]",
                offset, chunk_end, self.body_start, body_end
            )));
        }
        let bytes = &self.mmap[offset as usize..chunk_end as usize];
        let chunk = HistoryChunk::decode(bytes)?;

        // (3) Header entry_count must match the caller's expectation.
        if chunk.entry_count != expected_entry_count {
            return Err(Error::CorruptionError(format!(
                "history chunk @ offset {}: header entry_count {} does not match \
                 expected {} from leaf ChunkRef",
                offset, chunk.entry_count, expected_entry_count
            )));
        }
        Ok(chunk)
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Canonical filename for a history blob file. Mirrors the root sidecar
/// naming pattern from `sidecar.rs` so that recovery can sweep both
/// artifact families with one directory walk:
/// `marf-history-level-{level_id:06}-h{min:08}-{max:08}-blob-{blob_offset:016x}.dat`.
pub fn history_blob_filename(
    level_id: u32,
    min_height: u32,
    max_height: u32,
    blob_offset: u64,
) -> String {
    format!(
        "marf-history-level-{:06}-h{:08}-{:08}-blob-{:016x}.dat",
        level_id, min_height, max_height, blob_offset
    )
}

/// Canonical full path for a history blob file. `marf_dir` is the
/// directory holding the MARF index sqlite (typically the parent of the
/// `<db>.blobs` file).
pub fn history_blob_path(
    marf_dir: &Path,
    level_id: u32,
    min_height: u32,
    max_height: u32,
    blob_offset: u64,
) -> PathBuf {
    marf_dir.join(history_blob_filename(
        level_id,
        min_height,
        max_height,
        blob_offset,
    ))
}

/// Canonical tmp path used during chunk emission, before the publish
/// flow knows `blob_offset`. The filename includes a process-unique
/// suffix so concurrent squash workers (different MARFs in the same dir)
/// don't collide. Recovery sweeps any file matching `.history-tmp-*`.
pub fn history_blob_tmp_path(marf_dir: &Path, level_id: u32) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    marf_dir.join(format!(
        ".history-tmp-level-{:06}-{:x}-{}-{}.dat",
        level_id, nanos, pid, seq
    ))
}

/// Parse a history blob filename into its `(level_id, min_height,
/// max_height, blob_offset)` components, or `None` if the filename
/// doesn't match the canonical pattern. Used by recovery sweeps.
pub fn parse_history_blob_filename(name: &str) -> Option<(u32, u32, u32, u64)> {
    // Expected form: `marf-history-level-{level_id:06}-h{min:08}-{max:08}-blob-{blob_offset:016x}.dat`
    let stem = name.strip_suffix(".dat")?;
    let after_prefix = stem.strip_prefix("marf-history-level-")?;
    let mut parts = after_prefix.split('-');
    let level_str = parts.next()?;
    let min_str = parts.next()?.strip_prefix('h')?;
    let max_str = parts.next()?;
    let blob_label = parts.next()?;
    if blob_label != "blob" {
        return None;
    }
    let offset_str = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let level_id = u32::from_str_radix(level_str, 10).ok()?;
    let min_height = u32::from_str_radix(min_str, 10).ok()?;
    let max_height = u32::from_str_radix(max_str, 10).ok()?;
    let blob_offset = u64::from_str_radix(offset_str, 16).ok()?;
    Some((level_id, min_height, max_height, blob_offset))
}

// ---------------------------------------------------------------------------
// Recovery sweep helpers
// ---------------------------------------------------------------------------

/// Enumerate history blob files in `marf_dir`, returning the parsed
/// `(level_id, min_height, max_height, blob_offset, path)` for each file
/// matching the canonical naming pattern. Files that don't match are
/// silently skipped (they belong to other artifact families). Tmp files
/// (`.tmp` suffix) are skipped as well — recovery handles them via a
/// separate sweep.
pub fn enumerate_history_blobs(
    marf_dir: &Path,
) -> Result<Vec<(u32, u32, u32, u64, PathBuf)>, Error> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir(marf_dir) {
        Ok(d) => d,
        // Missing dir is not an error: a fresh chainstate has nothing to
        // sweep. The caller should still create the dir before writing.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::IOError(e)),
    };
    for entry in dir {
        let entry = entry.map_err(Error::IOError)?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Some((level_id, min_h, max_h, blob_offset)) = parse_history_blob_filename(name_str) {
            out.push((level_id, min_h, max_h, blob_offset, entry.path()));
        }
    }
    Ok(out)
}

/// Per-level expected state for [`reconcile_history_blobs`]. Mirrors the
/// shape of the existing `ExpectedSidecar` in `sidecar.rs` but for the
/// history blob's lifecycle states (`'never_written'` / `'present'` /
/// `'trimmed'`).
#[derive(Debug, Clone, Copy)]
pub struct ExpectedHistoryBlob {
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub blob_offset: u64,
    /// True when SQL says `history_blob_state = 'present'`. The file MUST
    /// be present + pass footer validation.
    pub present: bool,
    /// True when SQL says `history_blob_state = 'trimmed'`. The file MUST
    /// be absent; leftover files at the canonical path are unlinked.
    pub trimmed: bool,
}

/// Outcome of [`reconcile_history_blobs`]. Mirrors `ReconcileReport` in
/// `sidecar.rs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HistoryBlobReconcileReport {
    /// Number of stale `.history-tmp-*.dat` files unlinked.
    pub tmp_orphans_deleted: usize,
    /// Number of orphan canonical history-blob files unlinked
    /// (`(level_id, blob_offset)` not matching any SQL row + the row's
    /// expected presence; or a leftover file for a `'trimmed'` row).
    pub dat_orphans_deleted: usize,
    /// Number of canonical history-blob files kept (matched an active
    /// `'present'` row + passed footer validation).
    pub dat_kept: usize,
}

/// Reconcile the on-disk history-blob files in `marf_dir` against the
/// `marf_squash_levels` rows passed in `expected_by_level`. Mirrors the
/// shape + ordering of `sidecar::reconcile_squash_sidecars` per design
/// doc §9.4 step 4:
///
/// 1. Enumerate `.history-tmp-*.dat` files in `marf_dir` and unlink them
///    (crashed writer cleanup — completed writers rename to the canonical
///    path, so any tmp file at startup is an orphan).
/// 2. Enumerate canonical `marf-history-level-*-blob-*.dat` files and
///    dispatch on each file's `(level_id, blob_offset)`:
///    - matches an SQL row with `present=true && trimmed=false`: keep
///      the file; validate the footer via a brief
///      [`HistoryBlobReader::open`] (closes immediately, releasing the
///      mmap — the lazy cache opens for real on first read);
///    - matches a row with `present=false || trimmed=true`: unlink
///      (defensive cleanup for the `'never_written'` orphan case + the
///      `'trimmed'` leftover-after-crash case);
///    - matches no row at all: unlink (orphan from a torn commit).
/// 3. After the directory scan, for every expected SQL row with
///    `present=true && trimmed=false` whose canonical path does NOT
///    appear in the kept set: return `Error::CorruptionError`. Catches
///    the SQL-says-present-but-file-missing inconsistency before any
///    at-block read silently fails.
pub fn reconcile_history_blobs(
    marf_dir: &Path,
    expected_by_level: &[ExpectedHistoryBlob],
) -> Result<HistoryBlobReconcileReport, Error> {
    // Key by FULL identity `(level_id, min_height, max_height, blob_offset)`
    // — the exact tuple encoded in the canonical filename. Keying only on
    // `(level_id, blob_offset)` would let a file with the right level + offset
    // but wrong height range mask a missing canonical file: the wrong-named
    // file would be matched/kept here, the expected canonical path wouldn't
    // appear missing, and the lazy reader would later fail at open against
    // the true canonical path. Full-identity matching catches this.
    let mut expected_by_full: std::collections::HashMap<(u32, u32, u32, u64), ExpectedHistoryBlob> =
        std::collections::HashMap::with_capacity(expected_by_level.len());
    for &exp in expected_by_level {
        expected_by_full.insert(
            (
                exp.level_id,
                exp.min_height,
                exp.max_height,
                exp.blob_offset,
            ),
            exp,
        );
    }

    let mut report = HistoryBlobReconcileReport::default();

    // (1) Stale tmp files.
    for tmp in enumerate_history_blob_tmp_files(marf_dir)? {
        match std::fs::remove_file(&tmp) {
            Ok(()) => {
                report.tmp_orphans_deleted += 1;
                info!(
                    "reconcile_history_blobs: deleted orphan tmp file {}",
                    tmp.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    "reconcile_history_blobs: failed to delete tmp file {}: {e}",
                    tmp.display()
                );
            }
        }
    }

    // (2) Canonical files.
    let mut kept: std::collections::HashSet<(u32, u32, u32, u64)> =
        std::collections::HashSet::with_capacity(expected_by_full.len());
    for (level_id, min_h, max_h, blob_offset, path) in enumerate_history_blobs(marf_dir)? {
        match expected_by_full.get(&(level_id, min_h, max_h, blob_offset)) {
            Some(exp) if exp.present && !exp.trimmed => {
                // Footer-validate by opening + immediately dropping. If
                // open succeeds, the file is well-formed; the lazy reader
                // cache will re-open it on first read.
                HistoryBlobReader::open(&path, Some(level_id))?;
                kept.insert((level_id, min_h, max_h, blob_offset));
                report.dat_kept += 1;
            }
            _ => {
                // No SQL row matching the full identity tuple, or row says
                // `never_written`/`trimmed` → orphan. Unlink.
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        report.dat_orphans_deleted += 1;
                        info!(
                            "reconcile_history_blobs: deleted orphan history blob {}",
                            path.display()
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        warn!(
                            "reconcile_history_blobs: failed to delete orphan history blob {}: {e}",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    // (3) Presence check — every `present && !trimmed` row must have its
    // canonical file in `kept`. A wrongly-named-but-otherwise-plausible
    // file would have been unlinked above (it didn't match a full
    // identity tuple), so this check correctly fires when the canonical
    // path is missing — even if a near-miss file happened to exist.
    for exp in expected_by_level {
        let full_key = (
            exp.level_id,
            exp.min_height,
            exp.max_height,
            exp.blob_offset,
        );
        if exp.present && !exp.trimmed && !kept.contains(&full_key) {
            let expected_path = history_blob_path(
                marf_dir,
                exp.level_id,
                exp.min_height,
                exp.max_height,
                exp.blob_offset,
            );
            return Err(Error::CorruptionError(format!(
                "reconcile_history_blobs: SQL row says level_id={} history_blob_state='present' \
                 but canonical history blob is missing at {}",
                exp.level_id,
                expected_path.display()
            )));
        }
    }

    Ok(report)
}

/// Enumerate stale tmp history blob files in `marf_dir` (filenames
/// matching `.history-tmp-*`). Used by the recovery sweep to clean up
/// files left behind by crashed [`HistoryBlobWriter`] instances.
pub fn enumerate_history_blob_tmp_files(marf_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir(marf_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::IOError(e)),
    };
    for entry in dir {
        let entry = entry.map_err(Error::IOError)?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with(".history-tmp-") && name_str.ends_with(".dat") {
            out.push(entry.path());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("history_blob_test-{pid}-{seq}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Build a recognizable `MARFValue` from a small integer label. The
    /// label's bytes are written into the value's leading bytes (BE u32);
    /// makes value comparisons in tests human-debuggable.
    fn mv(label: u32) -> MARFValue {
        let mut b = [0u8; 40];
        b[0..4].copy_from_slice(&label.to_be_bytes());
        MARFValue(b)
    }

    fn entries_desc(heights: &[u32]) -> Vec<(u32, MARFValue)> {
        heights.iter().map(|&h| (h, mv(h))).collect()
    }

    /// Open a writer at a fresh tmp path under `dir`.
    fn mk_writer(dir: &Path, level_id: u32) -> HistoryBlobWriter {
        let tmp = history_blob_tmp_path(dir, level_id);
        HistoryBlobWriter::create_at(tmp, level_id).unwrap()
    }

    /// Finalize the writer and rename its tmp file to `final_path`
    /// (the rename step the publish flow does once `blob_offset` is known).
    fn finalize_to(w: HistoryBlobWriter, final_path: &Path) {
        let tmp = w.tmp_path().to_path_buf();
        w.finalize().unwrap();
        std::fs::rename(&tmp, final_path).unwrap();
    }

    // ---- header / footer encode/decode round-trips ----

    #[test]
    fn header_round_trip() {
        let h = HistoryBlobHeader {
            version: 1,
            flags: HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING,
            level_id: 0xdead_beef,
        };
        let bytes = h.encode();
        let decoded = HistoryBlobHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_decode_rejects_bad_magic() {
        let mut bytes = HistoryBlobHeader {
            version: 1,
            flags: 1,
            level_id: 0,
        }
        .encode();
        bytes[0] = b'X';
        let err = HistoryBlobHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_decode_rejects_unsupported_version() {
        let mut bytes = HistoryBlobHeader {
            version: 1,
            flags: 1,
            level_id: 0,
        }
        .encode();
        bytes[4] = 99;
        let err = HistoryBlobHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn footer_round_trip() {
        let f = HistoryBlobFooter {
            chunk_count: 1234,
            total_entry_count: 56_789_012,
            body_len: 9_876_543_210,
        };
        let bytes = f.encode();
        let decoded = HistoryBlobFooter::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn footer_decode_rejects_bad_magic() {
        let mut bytes = HistoryBlobFooter {
            chunk_count: 0,
            total_entry_count: 0,
            body_len: 0,
        }
        .encode();
        bytes[20] = b'X';
        let err = HistoryBlobFooter::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    // ---- chunk-header decode ----

    #[test]
    fn chunk_header_rejects_zero_entry_count() {
        let h = HistoryChunkHeader {
            version: 1,
            flags: HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING,
            entry_count: 0,
        };
        let err = HistoryChunkHeader::decode(&h.encode()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn chunk_header_rejects_reserved_flag_bits() {
        let h = HistoryChunkHeader {
            version: 1,
            flags: HISTORY_CHUNK_FLAG_FIXED_VALUE_ENCODING | 0x02,
            entry_count: 1,
        };
        let err = HistoryChunkHeader::decode(&h.encode()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn chunk_header_rejects_missing_fixed_encoding_bit() {
        let h = HistoryChunkHeader {
            version: 1,
            flags: 0,
            entry_count: 1,
        };
        let err = HistoryChunkHeader::decode(&h.encode()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    // ---- writer / reader round-trip ----

    #[test]
    fn writer_reader_round_trip_single_chunk() {
        let dir = tempdir();
        let final_path = history_blob_path(&dir, 7, 100, 199, 0xa5a5_a5a5_a5a5_a5a5);

        let entries = entries_desc(&[150, 130, 110]);
        let mut w = mk_writer(&dir, 7);
        let (offset, byte_len) = w.append_chunk(&entries).unwrap();
        finalize_to(w, &final_path);

        let r = HistoryBlobReader::open(&final_path, Some(7)).unwrap();
        assert_eq!(r.header().level_id, 7);
        assert_eq!(r.footer().chunk_count, 1);
        assert_eq!(r.footer().total_entry_count, 3);

        let chunk = r.read_chunk(offset, byte_len, 3).unwrap();
        assert_eq!(chunk.entries_owned(), entries);
    }

    #[test]
    fn writer_reader_round_trip_many_chunks() {
        let dir = tempdir();
        let final_path = history_blob_path(&dir, 1, 0, 999, 0);
        let mut w = mk_writer(&dir, 1);
        let key_a = entries_desc(&[990, 880, 770, 660, 550]);
        let key_b = entries_desc(&[800, 100]);
        let key_c = entries_desc(&[42]);
        let (oa, la) = w.append_chunk(&key_a).unwrap();
        let (ob, lb) = w.append_chunk(&key_b).unwrap();
        let (oc, lc) = w.append_chunk(&key_c).unwrap();
        finalize_to(w, &final_path);

        let r = HistoryBlobReader::open(&final_path, None).unwrap();
        assert_eq!(r.footer().chunk_count, 3);
        assert_eq!(r.footer().total_entry_count, 5 + 2 + 1);
        assert_eq!(r.read_chunk(oa, la, 5).unwrap().entries_owned(), key_a);
        assert_eq!(r.read_chunk(ob, lb, 2).unwrap().entries_owned(), key_b);
        assert_eq!(r.read_chunk(oc, lc, 1).unwrap().entries_owned(), key_c);
    }

    // ---- value_at_height ----

    #[test]
    fn value_at_height_resolves_within_range() {
        let dir = tempdir();
        let final_path = history_blob_path(&dir, 2, 0, 1000, 0);
        let entries = entries_desc(&[800, 500, 200]); // descending
        let mut w = mk_writer(&dir, 2);
        let (off, len) = w.append_chunk(&entries).unwrap();
        finalize_to(w, &final_path);

        let r = HistoryBlobReader::open(&final_path, None).unwrap();
        let chunk = r.read_chunk(off, len, 3).unwrap();
        // h >= 800 → tip
        assert_eq!(chunk.value_at_height(900), Some(mv(800)));
        assert_eq!(chunk.value_at_height(800), Some(mv(800)));
        // 500 <= h < 800
        assert_eq!(chunk.value_at_height(799), Some(mv(500)));
        assert_eq!(chunk.value_at_height(500), Some(mv(500)));
        // 200 <= h < 500
        assert_eq!(chunk.value_at_height(499), Some(mv(200)));
        assert_eq!(chunk.value_at_height(200), Some(mv(200)));
        // h < 200 → None (key didn't exist / wasn't yet inherited)
        assert_eq!(chunk.value_at_height(199), None);
        assert_eq!(chunk.value_at_height(0), None);
    }

    #[test]
    fn value_at_height_single_entry() {
        let dir = tempdir();
        let final_path = history_blob_path(&dir, 3, 0, 0, 0);
        let entries = entries_desc(&[42]);
        let mut w = mk_writer(&dir, 3);
        let (off, len) = w.append_chunk(&entries).unwrap();
        finalize_to(w, &final_path);

        let r = HistoryBlobReader::open(&final_path, None).unwrap();
        let chunk = r.read_chunk(off, len, 1).unwrap();
        assert_eq!(chunk.value_at_height(100), Some(mv(42)));
        assert_eq!(chunk.value_at_height(42), Some(mv(42)));
        assert_eq!(chunk.value_at_height(41), None);
    }

    // ---- writer rejects empty / mis-ordered chunks ----

    #[test]
    fn writer_rejects_empty_chunk() {
        let dir = tempdir();
        let mut w = mk_writer(&dir, 4);
        let err = w.append_chunk(&[]).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn writer_rejects_ascending_entries() {
        let dir = tempdir();
        let mut w = mk_writer(&dir, 5);
        let err = w.append_chunk(&[(10, mv(1)), (20, mv(2))]).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    // ---- reader rejects torn / wrong-length / wrong-magic / wrong-level files ----

    #[test]
    fn reader_rejects_truncated_file() {
        let dir = tempdir();
        let p = history_blob_path(&dir, 6, 0, 0, 0);
        let mut w = mk_writer(&dir, 6);
        w.append_chunk(&entries_desc(&[100])).unwrap();
        finalize_to(w, &p);
        // Truncate to header-only.
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(HISTORY_BLOB_HEADER_SIZE as u64).unwrap();
        let err = HistoryBlobReader::open(&p, Some(6)).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_wrong_level_id() {
        let dir = tempdir();
        let p = history_blob_path(&dir, 8, 0, 0, 0);
        let mut w = mk_writer(&dir, 8);
        w.append_chunk(&entries_desc(&[1])).unwrap();
        finalize_to(w, &p);
        let err = HistoryBlobReader::open(&p, Some(99)).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_torn_footer_magic() {
        let dir = tempdir();
        let p = history_blob_path(&dir, 9, 0, 0, 0);
        let mut w = mk_writer(&dir, 9);
        w.append_chunk(&entries_desc(&[1])).unwrap();
        finalize_to(w, &p);
        // Corrupt the trailing magic.
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        let len = f.metadata().unwrap().len();
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(len - 4)).unwrap();
        f.write_all(b"XXXX").unwrap();
        f.sync_all().unwrap();
        drop(f);
        let err = HistoryBlobReader::open(&p, None).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_chunk_entry_count_mismatch() {
        let dir = tempdir();
        let p = history_blob_path(&dir, 10, 0, 0, 0);
        let entries = entries_desc(&[5, 4, 3]);
        let mut w = mk_writer(&dir, 10);
        let (off, len) = w.append_chunk(&entries).unwrap();
        finalize_to(w, &p);
        let r = HistoryBlobReader::open(&p, None).unwrap();
        // ask for the wrong entry count (chunk has 3, ask for 2).
        let err = r.read_chunk(off, len, 2).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_oversized_byte_len_overlapping_next_chunk() {
        // Two adjacent chunks — `key_a` (3 entries) followed by `key_b`
        // (1 entry). A corrupted leaf for `key_a` claiming `byte_len`
        // matching `key_a + key_b` together must be rejected, even though
        // the bytes are still inside the body and the (over-extended)
        // chunk header would still parse successfully. Catches the
        // "ChunkRef byte_len not exact-checked" footgun Codex flagged.
        let dir = tempdir();
        let p = history_blob_path(&dir, 14, 0, 0, 0);
        let mut w = mk_writer(&dir, 14);
        let (off_a, len_a) = w.append_chunk(&entries_desc(&[5, 4, 3])).unwrap();
        let (_off_b, len_b) = w.append_chunk(&entries_desc(&[10])).unwrap();
        finalize_to(w, &p);

        let r = HistoryBlobReader::open(&p, None).unwrap();
        // Sanity: correct byte_len decodes fine.
        let chunk = r.read_chunk(off_a, len_a, 3).unwrap();
        assert_eq!(chunk.entry_count, 3);

        // Oversized: claim byte_len that overlaps the next chunk while still
        // matching expected_entry_count = 3 → rejected.
        let oversized = len_a + len_b;
        let err = r.read_chunk(off_a, oversized, 3).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));

        // Also: claim a different expected_entry_count whose implied byte_len
        // doesn't match the actual byte_len → rejected on the exact-size check.
        let err2 = r.read_chunk(off_a, len_a, 4).unwrap_err();
        assert!(matches!(err2, Error::CorruptionError(_)));
    }

    #[test]
    fn header_decode_rejects_missing_fixed_value_encoding_flag() {
        // v1 requires HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING set; a header
        // with flags=0 must fail open-time validation. Catches the
        // "header flag bits not validated" footgun Codex flagged.
        let mut bytes = HistoryBlobHeader {
            version: 1,
            flags: HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING,
            level_id: 0,
        }
        .encode();
        bytes[5] = 0; // clear flags
        let err = HistoryBlobHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_decode_rejects_reserved_flag_bits() {
        let h = HistoryBlobHeader {
            version: 1,
            flags: HISTORY_BLOB_FLAG_FIXED_VALUE_ENCODING,
            level_id: 0,
        };
        let mut bytes = h.encode();
        bytes[5] |= 0b1000_0000; // set a reserved bit
        let err = HistoryBlobHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_chunk_offset_out_of_body() {
        let dir = tempdir();
        let p = history_blob_path(&dir, 11, 0, 0, 0);
        let mut w = mk_writer(&dir, 11);
        w.append_chunk(&entries_desc(&[1])).unwrap();
        finalize_to(w, &p);
        let r = HistoryBlobReader::open(&p, None).unwrap();
        // Offset way past EOF.
        let err = r.read_chunk(99_999, 100, 1).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    // ---- writer Drop unlinks the tmp file on torn write ----

    #[test]
    fn writer_drop_without_finalize_unlinks_tmp() {
        let dir = tempdir();
        let tmp;
        {
            let mut w = mk_writer(&dir, 12);
            tmp = w.tmp_path().to_path_buf();
            w.append_chunk(&entries_desc(&[1])).unwrap();
            // drop without finalize
        }
        assert!(!tmp.exists(), "tmp file should be unlinked on drop");
    }

    #[test]
    fn writer_cancel_unlinks_tmp() {
        let dir = tempdir();
        let mut w = mk_writer(&dir, 13);
        let tmp = w.tmp_path().to_path_buf();
        w.append_chunk(&entries_desc(&[1])).unwrap();
        w.cancel().unwrap();
        assert!(!tmp.exists());
    }

    // ---- StagedHistoryBlob RAII guard ----

    #[test]
    fn staged_drop_without_forget_unlinks_file() {
        // Simulates the "ordinary error after Phase A.6" case: writer was
        // finalized, file lives at tmp path, then later prep/publish fails
        // before the rename — we expect the guard's Drop to clean up.
        let dir = tempdir();
        let final_path = history_blob_path(&dir, 14, 0, 0, 0);
        let mut w = mk_writer(&dir, 14);
        let tmp = w.tmp_path().to_path_buf();
        w.append_chunk(&entries_desc(&[1])).unwrap();
        finalize_to(w, &final_path);
        // Re-create the staged guard pointing at the canonical path
        // (simulating the "we never got past prep" state — but for the
        // pure-test purpose, just create one pointing at any extant file).
        // Easier: stage a fresh tmp path.
        let staged_tmp = history_blob_tmp_path(&dir, 14);
        std::fs::write(&staged_tmp, b"finalized-but-not-renamed").unwrap();
        {
            let _guard = StagedHistoryBlob::new(staged_tmp.clone());
            assert!(staged_tmp.exists(), "guard holds the file alive");
        }
        assert!(
            !staged_tmp.exists(),
            "drop without forget() unlinked the staged file"
        );
        // The earlier finalized-then-renamed file is unrelated; verify it
        // wasn't disturbed by the guard.
        let _ = (tmp, final_path);
    }

    #[test]
    fn staged_forget_does_not_unlink() {
        // Simulates the "rename succeeded" case: caller called forget()
        // after rename. The guard's Drop is a no-op, the file remains
        // wherever the rename put it.
        let dir = tempdir();
        let staged_tmp = history_blob_tmp_path(&dir, 15);
        std::fs::write(&staged_tmp, b"about-to-be-renamed").unwrap();

        let guard = StagedHistoryBlob::new(staged_tmp.clone());
        // Pretend we successfully renamed the file out from under the guard.
        let canonical = history_blob_path(&dir, 15, 0, 0, 0);
        std::fs::rename(&staged_tmp, &canonical).unwrap();
        // forget() must not panic, and must not error on the now-missing
        // tmp path (the guard's Drop tolerates NotFound either way, but
        // forget() guarantees Drop never even tries the unlink).
        guard.forget();
        // The renamed-to file should still be there.
        assert!(canonical.exists(), "forget() preserved the renamed file");
    }

    #[test]
    fn staged_drop_on_already_missing_file_does_not_panic() {
        // Crash-recovery edge case: the file was unlinked between staging
        // and Drop (e.g., a separate cleanup ran). The guard's Drop must
        // tolerate NotFound silently — no panic, no error log spam.
        let dir = tempdir();
        let p = history_blob_tmp_path(&dir, 16);
        // Don't create the file at all.
        let _guard = StagedHistoryBlob::new(p);
        // Drop runs at end of scope; should be a no-op.
    }

    // ---- path naming helpers ----

    #[test]
    fn filename_format_matches_spec() {
        // Min-width fields: level_id(6), min_h(8), max_h(8), blob_offset(16 hex).
        // Values smaller than the min-width get zero-padded; larger values render
        // at their natural width.
        let name = history_blob_filename(7, 100, 999, 0x1000);
        assert_eq!(
            name,
            "marf-history-level-000007-h00000100-00000999-blob-0000000000001000.dat"
        );
    }

    #[test]
    fn parse_filename_round_trips() {
        let name = history_blob_filename(42, 100, 199, 0xdead_beef);
        let (lvl, mn, mx, off) = parse_history_blob_filename(&name).unwrap();
        assert_eq!(lvl, 42);
        assert_eq!(mn, 100);
        assert_eq!(mx, 199);
        assert_eq!(off, 0xdead_beef);
    }

    #[test]
    fn parse_filename_rejects_unrelated_files() {
        assert!(parse_history_blob_filename("README.md").is_none());
        assert!(parse_history_blob_filename(
            "marf-roots-level-000001-h00000000-00000099-blob-0000000000000000.dat"
        )
        .is_none());
        assert!(parse_history_blob_filename("marf-history-level-001-h0-99-blob-0.txt").is_none());
    }

    // ---- enumerate_history_blobs ----

    #[test]
    fn enumerate_history_blobs_returns_only_history_files() {
        let dir = tempdir();
        // Create one history blob via the writer.
        let p1 = history_blob_path(&dir, 1, 0, 99, 0x1000);
        let mut w = mk_writer(&dir, 1);
        w.append_chunk(&entries_desc(&[10])).unwrap();
        finalize_to(w, &p1);
        // Create one root sidecar-shaped file (should be skipped).
        std::fs::write(
            dir.join("marf-roots-level-000002-h00000100-00000199-blob-0000000000002000.dat"),
            b"unrelated",
        )
        .unwrap();
        // Create one totally unrelated file (should be skipped).
        std::fs::write(dir.join("README.md"), b"hi").unwrap();

        let mut found = enumerate_history_blobs(&dir).unwrap();
        found.sort_by_key(|t| t.0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 1);
        assert_eq!(found[0].3, 0x1000);
        assert_eq!(found[0].4, p1);
    }

    #[test]
    fn enumerate_history_blob_tmp_files_finds_orphan_tmp() {
        let dir = tempdir();
        // Simulate a crashed writer: tmp file (matching the
        // `.history-tmp-*.dat` pattern) exists, no finalize.
        let tmp = history_blob_tmp_path(&dir, 5);
        std::fs::write(&tmp, b"partial").unwrap();
        let found = enumerate_history_blob_tmp_files(&dir).unwrap();
        assert_eq!(found, vec![tmp]);
    }

    #[test]
    fn enumerate_returns_empty_when_dir_missing() {
        let p = std::env::temp_dir().join(format!(
            "history_blob_missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let found = enumerate_history_blobs(&p).unwrap();
        assert!(found.is_empty());
        let found_tmp = enumerate_history_blob_tmp_files(&p).unwrap();
        assert!(found_tmp.is_empty());
    }
}
