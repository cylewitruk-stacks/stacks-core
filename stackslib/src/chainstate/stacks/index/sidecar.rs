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

//! Per-level sidecar files for MARF squash auxiliary records.
//!
//! Each squash level that requires a per-height structural snapshot (currently
//! only redirected/reclaim levels, for fork-extension correctness in
//! [`crate::chainstate::stacks::index::marf::MARF::root_copy`]) gets one
//! self-describing sidecar file. The file format is fixed-header + dense
//! head-located index + concatenated bodies; reads are a single positional
//! index entry lookup followed by a single positional body read. Trim
//! decommissions a level's records by `unlink`-ing its sidecar — no file
//! collapse, no offset rewrites, no SQL bookkeeping per record.
//!
//! The format reserves a `record_kind` field so future MARF auxiliary record
//! types (per-height ancestor-hash precomputations, etc.) can share the same
//! container without a format-version bump. v1 only emits
//! [`RecordKind::SquashRootNode`].
//!
//! # On-disk layout (v1)
//!
//! ```text
//! +---------------------------------+ offset 0
//! | Header (40 bytes, fixed)        |
//! +---------------------------------+ offset SIDECAR_HEADER_SIZE
//! | Index (count × ENTRY_SIZE bytes)|  (offset u64, length u32, reserved u32)
//! +---------------------------------+ offset SIDECAR_HEADER_SIZE + count*ENTRY_SIZE
//! | Body 0  (raw bytes)             |
//! +---------------------------------+
//! | Body 1                          |
//! +---------------------------------+
//! | ...                             |
//! +---------------------------------+
//! | Body N-1                        |
//! +---------------------------------+ EOF
//! ```
//!
//! # Atomicity
//!
//! The writer always emits `<path>.tmp`, `fsync`s, then `rename`s to the
//! final path. Callers are expected to `fsync` the parent directory after
//! the rename for full crash durability — this module exposes the
//! [`SidecarWriter::finalize`] step but defers parent-dir fsync to the
//! caller, which already knows the marf directory.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chainstate::stacks::index::Error;

/// Magic bytes identifying a MARF sidecar file. Appears at the start of the
/// header (and is verified at open time).
pub const SIDECAR_MAGIC: [u8; 8] = *b"MARFSCAR";

/// Format version byte. Bump only on incompatible changes.
pub const SIDECAR_FORMAT_VERSION: u16 = 1;

/// Fixed header size in bytes.
///
/// magic(8) + format_version(2) + schema_flags(2) + record_kind(2) +
/// reserved(2) + level_id(4) + min_height(4) + max_height(4) + count(4) +
/// created_at(8) = 40 bytes.
pub const SIDECAR_HEADER_SIZE: usize = 40;

/// Size of a single index entry: body_offset(8) + body_length(4) +
/// reserved/crc32(4) = 16 bytes.
pub const SIDECAR_INDEX_ENTRY_SIZE: usize = 16;

/// Sidecar record-kind tags. The `u16` encoding leaves 65k future kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    /// Per-height post-remap squash-level root node body (Node256/Node48/...).
    /// One body per height in `[min_height ..= max_height]`.
    SquashRootNode = 0x0001,
}

impl RecordKind {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::SquashRootNode),
            _ => None,
        }
    }
}

/// Parsed sidecar header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarHeader {
    pub format_version: u16,
    pub schema_flags: u16,
    pub record_kind: RecordKind,
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub count: u32,
    /// Unix epoch seconds. Diagnostic only.
    pub created_at: u64,
}

impl SidecarHeader {
    /// Number of entries that the index must contain to fully cover this
    /// header's height range.
    pub fn expected_count(&self) -> u32 {
        // count == max - min + 1, validated at parse time. Returned here so
        // callers don't recompute.
        self.count
    }

    /// Convert an absolute height into a 0-based index slot, or `None` if
    /// the height is out of range for this header.
    pub fn slot_for_height(&self, height: u32) -> Option<u32> {
        if height < self.min_height || height > self.max_height {
            return None;
        }
        Some(height - self.min_height)
    }

    fn write<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&SIDECAR_MAGIC)?;
        w.write_all(&self.format_version.to_be_bytes())?;
        w.write_all(&self.schema_flags.to_be_bytes())?;
        w.write_all(&(self.record_kind as u16).to_be_bytes())?;
        w.write_all(&[0u8, 0u8])?; // reserved
        w.write_all(&self.level_id.to_be_bytes())?;
        w.write_all(&self.min_height.to_be_bytes())?;
        w.write_all(&self.max_height.to_be_bytes())?;
        w.write_all(&self.count.to_be_bytes())?;
        w.write_all(&self.created_at.to_be_bytes())?;
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < SIDECAR_HEADER_SIZE {
            return Err(Error::CorruptionError(format!(
                "Sidecar header too short: {} < {}",
                bytes.len(),
                SIDECAR_HEADER_SIZE
            )));
        }
        if &bytes[0..8] != &SIDECAR_MAGIC {
            return Err(Error::CorruptionError(format!(
                "Sidecar bad magic: {:?}",
                &bytes[0..8]
            )));
        }
        let format_version = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        if format_version != SIDECAR_FORMAT_VERSION {
            return Err(Error::CorruptionError(format!(
                "Unsupported sidecar format version: {format_version}"
            )));
        }
        let schema_flags = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        let record_kind_raw = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
        let record_kind = RecordKind::from_u16(record_kind_raw).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Unknown sidecar record_kind: 0x{record_kind_raw:04x}"
            ))
        })?;
        // bytes[14..16] reserved, ignored.
        let level_id = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let min_height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let max_height = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let count = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        let created_at = u64::from_be_bytes(bytes[32..40].try_into().unwrap());

        if max_height < min_height {
            return Err(Error::CorruptionError(format!(
                "Sidecar header: max_height {max_height} < min_height {min_height}"
            )));
        }
        let expected = max_height - min_height + 1;
        if count != expected {
            return Err(Error::CorruptionError(format!(
                "Sidecar header: count {count} does not match height range \
                 [{min_height}, {max_height}] (expected {expected})"
            )));
        }
        Ok(Self {
            format_version,
            schema_flags,
            record_kind,
            level_id,
            min_height,
            max_height,
            count,
            created_at,
        })
    }
}

/// One entry in the head-located index. `body_offset` is relative to the
/// start of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarIndexEntry {
    pub body_offset: u64,
    pub body_length: u32,
    /// Reserved space for an opt-in CRC32 of the body. v1 always writes 0;
    /// readers MUST ignore unless `schema_flags` advertises checksum support.
    pub reserved: u32,
}

impl SidecarIndexEntry {
    fn write<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&self.body_offset.to_be_bytes())?;
        w.write_all(&self.body_length.to_be_bytes())?;
        w.write_all(&self.reserved.to_be_bytes())?;
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < SIDECAR_INDEX_ENTRY_SIZE {
            return Err(Error::CorruptionError(format!(
                "Sidecar index entry too short: {} < {}",
                bytes.len(),
                SIDECAR_INDEX_ENTRY_SIZE
            )));
        }
        Ok(Self {
            body_offset: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            body_length: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            reserved: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
        })
    }
}

/// Build a sidecar file in-RAM and atomically publish it to disk via
/// `<path>.tmp` → `fsync` → `rename`. Caller is responsible for fsync of the
/// parent directory after [`Self::finalize`] returns.
///
/// Bodies are passed by reference and copied into the staging buffer; the
/// caller's `Vec<Vec<u8>>` can be dropped after [`Self::finalize`].
pub struct SidecarWriter {
    final_path: PathBuf,
    tmp_path: PathBuf,
    header: SidecarHeader,
    bodies: Vec<Vec<u8>>,
}

impl SidecarWriter {
    /// `bodies.len()` must equal `header.count`. The writer enforces this at
    /// [`Self::finalize`] time.
    pub fn new(final_path: PathBuf, header: SidecarHeader, bodies: Vec<Vec<u8>>) -> Self {
        let mut tmp_path = final_path.clone();
        let mut tmp_name = tmp_path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        Self {
            final_path,
            tmp_path,
            header,
            bodies,
        }
    }

    /// Build the sidecar bytes in-RAM, write to `<path>.tmp`, fsync, and
    /// rename to the final path. After this returns, the caller should
    /// fsync the parent directory (best-effort; not required for content
    /// correctness, only for rename-durability across power loss).
    pub fn finalize(self) -> Result<(), Error> {
        let SidecarWriter {
            final_path,
            tmp_path,
            header,
            bodies,
        } = self;

        if bodies.len() as u32 != header.count {
            return Err(Error::CorruptionError(format!(
                "Sidecar writer: bodies.len()={} does not match header.count={}",
                bodies.len(),
                header.count,
            )));
        }

        // Build the file in one buffer: header + index + bodies.
        let header_size = SIDECAR_HEADER_SIZE;
        let index_size = (header.count as usize)
            .checked_mul(SIDECAR_INDEX_ENTRY_SIZE)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar index size overflow during write".into())
            })?;
        let bodies_total: usize = bodies.iter().map(|b| b.len()).sum();
        let total_size = header_size
            .checked_add(index_size)
            .and_then(|n| n.checked_add(bodies_total))
            .ok_or_else(|| Error::CorruptionError("Sidecar total size overflow".into()))?;

        let mut buf: Vec<u8> = Vec::with_capacity(total_size);

        // Header.
        header.write(&mut buf)?;
        debug_assert_eq!(buf.len(), header_size);

        // Compute index entries first, then write index then bodies. Index
        // entries' body_offset values are absolute file offsets, anchored at
        // the position immediately after the index region.
        let mut index_entries: Vec<SidecarIndexEntry> = Vec::with_capacity(bodies.len());
        let bodies_region_start = (header_size + index_size) as u64;
        let mut next_body_offset = bodies_region_start;
        for body in &bodies {
            let body_length = u32::try_from(body.len()).map_err(|_| {
                Error::CorruptionError(format!(
                    "Sidecar body too large for u32 length: {} bytes",
                    body.len()
                ))
            })?;
            index_entries.push(SidecarIndexEntry {
                body_offset: next_body_offset,
                body_length,
                reserved: 0,
            });
            next_body_offset = next_body_offset
                .checked_add(body_length as u64)
                .ok_or_else(|| {
                    Error::CorruptionError("Sidecar body offset overflow during write".into())
                })?;
        }

        // Index.
        for entry in &index_entries {
            entry.write(&mut buf)?;
        }
        debug_assert_eq!(buf.len(), header_size + index_size);

        // Bodies.
        for body in &bodies {
            buf.extend_from_slice(body);
        }
        debug_assert_eq!(buf.len(), total_size);

        // Ensure the parent directory exists. This is the
        // `<db>.squash_sidecars/` dir; making the writer responsible for
        // it keeps callers from having to track sidecar layout details.
        if let Some(parent) = tmp_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: cannot create parent dir {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Atomic publish: write .tmp, fsync, rename. If the .tmp already
        // exists from a prior crashed attempt, truncate-overwrite it.
        {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| {
                    Error::CorruptionError(format!(
                        "Sidecar writer: cannot create {}: {e}",
                        tmp_path.display()
                    ))
                })?;
            tmp_file.write_all(&buf).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: write_all to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            tmp_file.sync_all().map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: fsync of {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
        } // close the file handle before rename for cross-platform sanity

        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar writer: rename {} -> {} failed: {e}",
                tmp_path.display(),
                final_path.display()
            ))
        })?;

        info!(
            "Sidecar writer: renamed {} -> {} ({} bytes)",
            tmp_path.display(),
            final_path.display(),
            buf.len(),
        );

        // Post-rename existence check: catches the "rename returned Ok but
        // file isn't on disk" failure mode without waiting for a downstream
        // reader to surface it as a corruption panic.
        match std::fs::metadata(&final_path) {
            Ok(md) => {
                info!(
                    "Sidecar writer: post-rename verify ok, {} bytes on disk at {}",
                    md.len(),
                    final_path.display(),
                );
            }
            Err(e) => {
                return Err(Error::CorruptionError(format!(
                    "Sidecar writer: rename returned Ok but {} is not present \
                     post-rename: {e}",
                    final_path.display()
                )));
            }
        }

        Ok(())
    }
}

/// Opens a published sidecar file, validates its header, and reads the
/// index. The caller can then [`Self::read_body_at_height`] to fetch
/// individual bodies via positional reads. The file handle is closed when
/// the reader is dropped.
#[derive(Debug)]
pub struct SidecarReader {
    file: File,
    pub header: SidecarHeader,
    pub index: Vec<SidecarIndexEntry>,
}

/// Caller's expectation about a sidecar's identity, validated by
/// [`SidecarReader::open`]. Any field set to `Some` is enforced; `None`
/// means "trust the file." Production callers pass the full set so a
/// stale file with a partially-matching header (e.g. right `level_id`
/// but wrong `min_height`/`max_height`) is rejected rather than serving
/// the wrong slot's body.
#[derive(Debug, Clone, Copy, Default)]
pub struct SidecarExpectation {
    pub level_id: Option<u32>,
    pub record_kind: Option<RecordKind>,
    pub min_height: Option<u32>,
    pub max_height: Option<u32>,
    pub count: Option<u32>,
}

impl SidecarReader {
    /// Open a sidecar at `path`, validating header and parsing the full
    /// index. Every field of `expect` set to `Some` is verified against
    /// the parsed header — production callers should populate all five
    /// (`level_id`, `record_kind`, `min_height`, `max_height`, `count`)
    /// so a stale or corrupt sidecar with the right `level_id` but a
    /// shifted height range can't return the wrong slot's body.
    pub fn open(path: &Path, expect: SidecarExpectation) -> Result<Self, Error> {
        let mut file = OpenOptions::new().read(true).open(path).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: cannot open {}: {e}",
                path.display()
            ))
        })?;

        // Header.
        let mut header_buf = [0u8; SIDECAR_HEADER_SIZE];
        file.read_exact(&mut header_buf).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: short read of header from {}: {e}",
                path.display()
            ))
        })?;
        let header = SidecarHeader::parse(&header_buf)?;

        if let Some(want) = expect.level_id {
            if header.level_id != want {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: level_id mismatch in {} (file says {}, caller expected {})",
                    path.display(),
                    header.level_id,
                    want,
                )));
            }
        }
        if let Some(want) = expect.record_kind {
            if header.record_kind != want {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: record_kind mismatch in {} (file says {:?}, caller expected {:?})",
                    path.display(),
                    header.record_kind,
                    want,
                )));
            }
        }
        if let Some(want) = expect.min_height {
            if header.min_height != want {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: min_height mismatch in {} (file says {}, caller expected {})",
                    path.display(),
                    header.min_height,
                    want,
                )));
            }
        }
        if let Some(want) = expect.max_height {
            if header.max_height != want {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: max_height mismatch in {} (file says {}, caller expected {})",
                    path.display(),
                    header.max_height,
                    want,
                )));
            }
        }
        if let Some(want) = expect.count {
            if header.count != want {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: count mismatch in {} (file says {}, caller expected {})",
                    path.display(),
                    header.count,
                    want,
                )));
            }
        }

        // Index.
        let index_size = (header.count as usize)
            .checked_mul(SIDECAR_INDEX_ENTRY_SIZE)
            .ok_or_else(|| Error::CorruptionError("Sidecar reader: index size overflow".into()))?;
        let mut index_buf = vec![0u8; index_size];
        file.read_exact(&mut index_buf).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: short read of index from {}: {e}",
                path.display()
            ))
        })?;
        let mut index = Vec::with_capacity(header.count as usize);
        for i in 0..(header.count as usize) {
            let start = i * SIDECAR_INDEX_ENTRY_SIZE;
            let end = start + SIDECAR_INDEX_ENTRY_SIZE;
            index.push(SidecarIndexEntry::parse(&index_buf[start..end])?);
        }

        // Validate every index entry's `(body_offset, body_length)` against
        // the file's bounds before returning the reader. A corrupt index
        // entry that points into the header/index region, overflows
        // `u64`, or extends past EOF must fail closed at open time —
        // otherwise the body read could silently return nonsense bytes
        // (or bytes from the index/header) and `MARF::root_copy` would
        // then decode garbage as a `TrieNodeType`.
        let file_len = file
            .metadata()
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar reader: cannot stat {}: {e}",
                    path.display()
                ))
            })?
            .len();
        let bodies_region_start = (SIDECAR_HEADER_SIZE as u64)
            .checked_add(index_size as u64)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar reader: bodies region offset overflow".into())
            })?;
        for (slot, entry) in index.iter().enumerate() {
            if entry.body_offset < bodies_region_start {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: index entry {slot} body_offset {} encroaches \
                     into the header/index region (must be >= {bodies_region_start}) in {}",
                    entry.body_offset,
                    path.display(),
                )));
            }
            let end = entry.body_offset.checked_add(entry.body_length as u64).ok_or_else(|| {
                Error::CorruptionError(format!(
                    "Sidecar reader: index entry {slot} body_offset {} + length {} overflows u64 in {}",
                    entry.body_offset,
                    entry.body_length,
                    path.display(),
                ))
            })?;
            if end > file_len {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: index entry {slot} body extends past EOF \
                     ({}+{}={end} > file_len {file_len}) in {}",
                    entry.body_offset,
                    entry.body_length,
                    path.display(),
                )));
            }
        }

        Ok(Self {
            file,
            header,
            index,
        })
    }

    /// Fetch the body bytes for `height`. Returns `None` if `height` is out
    /// of the file's `[min_height, max_height]` range.
    pub fn read_body_at_height(&mut self, height: u32) -> Result<Option<Vec<u8>>, Error> {
        let Some(slot) = self.header.slot_for_height(height) else {
            return Ok(None);
        };
        let entry = self.index.get(slot as usize).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Sidecar reader: slot {slot} out of bounds for index len {}",
                self.index.len()
            ))
        })?;
        self.file
            .seek(SeekFrom::Start(entry.body_offset))
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar reader: seek to body_offset {} failed: {e}",
                    entry.body_offset
                ))
            })?;
        let mut body = vec![0u8; entry.body_length as usize];
        self.file.read_exact(&mut body).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: short read of body (offset={}, len={}): {e}",
                entry.body_offset, entry.body_length
            ))
        })?;
        Ok(Some(body))
    }
}

/// Construct the canonical sidecar directory path for a given MARF DB file.
///
/// Naming follows the same pattern as the `<db>.blobs` blob file: each MARF
/// DB gets its own `<db>.squash_sidecars/` directory next to it. This is
/// load-bearing for correctness when multiple MARF DBs (e.g., the squashed
/// chainstate and an unsquashed reference) live in the same parent
/// directory — without per-DB scoping, one MARF's startup orphan-scan
/// would happily delete another MARF's sidecars because the SQL state of
/// either DB doesn't reference the other's level_ids.
pub fn squash_sidecar_dir_for_db(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".squash_sidecars");
    p.set_file_name(name);
    p
}

/// Construct the canonical path for a per-level squash root-node sidecar.
/// Sidecars live in `<db>.squash_sidecars/`; filenames embed level_id and
/// the height range for human readability when listing the directory.
pub fn squash_root_sidecar_path(
    db_path: &Path,
    level_id: u32,
    min_height: u32,
    max_height: u32,
) -> PathBuf {
    let mut p = squash_sidecar_dir_for_db(db_path);
    p.push(format!(
        "marf-roots-level-{:06}-h{:08}-{:08}.dat",
        level_id, min_height, max_height,
    ));
    p
}

/// Parse a sidecar filename of the form
/// `marf-roots-level-{level_id:06}-h{min_height:08}-{max_height:08}.dat` and
/// return its `(level_id, min_height, max_height)`. Returns `None` for
/// filenames that don't match the canonical pattern (which the orphan-scan
/// then ignores rather than touches).
fn parse_squash_root_sidecar_filename(name: &str) -> Option<(u32, u32, u32)> {
    let stem = name.strip_suffix(".dat")?;
    let after_prefix = stem.strip_prefix("marf-roots-level-")?;
    // expected: "{level_id}-h{min}-{max}"
    let mut parts = after_prefix.splitn(2, "-h");
    let level_str = parts.next()?;
    let h_str = parts.next()?;
    let level_id: u32 = level_str.parse().ok()?;
    let mut h_parts = h_str.splitn(2, '-');
    let min_str = h_parts.next()?;
    let max_str = h_parts.next()?;
    let min_h: u32 = min_str.parse().ok()?;
    let max_h: u32 = max_str.parse().ok()?;
    Some((level_id, min_h, max_h))
}

/// One level's expected sidecar state, as derived from
/// `marf_squash_levels`. Used by [`reconcile_squash_sidecars`] to decide
/// which on-disk files to keep, delete, or treat as missing.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedSidecar {
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub present: bool,
    pub trimmed: bool,
}

/// Outcome of a startup reconcile pass. Returned for diagnostics; callers
/// log the counts to make orphan-cleanup actions visible in normal operation.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    /// `.tmp` files actually unlinked. Currently always 0: reconcile leaves
    /// tmp files alone because another MARF handle may be publishing a
    /// sidecar concurrently. Writers truncate-overwrite stale tmp files on
    /// their next attempt.
    pub tmp_orphans_deleted: u64,
    /// `.dat` files actually unlinked because no SQL row matches the
    /// expected `(level_id, min_height, max_height)` tuple with
    /// `present=true && trimmed=false` (rename succeeded but SQL commit
    /// didn't, or the level is `trimmed=true`, or the filename's height
    /// range doesn't match the expected one).
    pub dat_orphans_deleted: u64,
    /// `.dat` files left in place because SQL agrees they should be
    /// present at the exact `(level_id, min_height, max_height)`.
    pub dat_kept: u64,
    /// Count of files we tried to delete but `remove_file` returned an
    /// error for. These files remain on disk; reconciliation does NOT
    /// claim success on them.
    pub delete_failures: u64,
}

/// Reconcile the on-disk sidecar directory against the SQL-side expectation.
///
/// Behavior:
///
/// 1. For every `*.tmp` file in the sidecar dir: leave it alone. A tmp
///    file can belong to an in-flight sidecar writer on another handle,
///    and deleting it races the writer's final rename. Stale tmp files are
///    harmless because [`SidecarWriter`] truncates-overwrites them.
/// 2. For every `*.dat` file matching the canonical filename pattern: parse
///    `(level_id, min_height, max_height)` from the name. Keep only if SQL's
///    `expected[level_id]` says `present=true && trimmed=false` AND the
///    expected `min_height`/`max_height` exactly match the filename's. Any
///    mismatch (no SQL row, `present=false`, `trimmed=true`, or stale
///    height range) → orphan, attempt deletion.
/// 3. Files whose names don't match the canonical pattern are LEFT ALONE
///    (defensive — could be operator artifacts or future record kinds).
/// 4. After the directory scan, for every expected sidecar with
///    `present=true && trimmed=false` whose canonical path does NOT exist
///    on disk: return a corruption error naming the level. This catches
///    SQL-says-present-but-file-missing inconsistency at startup, before
///    any fork-extension can silently fall back.
pub fn reconcile_squash_sidecars(
    db_path: &Path,
    expected_by_level: &[ExpectedSidecar],
) -> Result<ReconcileReport, Error> {
    let sidecar_dir = squash_sidecar_dir_for_db(db_path);

    // Index expected by level_id for O(1) lookup during the scan.
    let mut expected_by_id: std::collections::HashMap<u32, ExpectedSidecar> =
        std::collections::HashMap::with_capacity(expected_by_level.len());
    for &exp in expected_by_level {
        expected_by_id.insert(exp.level_id, exp);
    }

    let mut report = ReconcileReport::default();

    // If the directory doesn't exist yet, there's nothing to scan; the
    // presence check below catches the case where SQL claims sidecars
    // should be present but the dir is absent.
    if sidecar_dir.exists() {
        let entries = std::fs::read_dir(&sidecar_dir).map_err(|e| {
            Error::CorruptionError(format!(
                "reconcile_squash_sidecars: cannot read {}: {e}",
                sidecar_dir.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::CorruptionError(format!(
                    "reconcile_squash_sidecars: dir-read iter error: {e}"
                ))
            })?;
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if name.ends_with(".tmp") {
                continue;
            }
            if let Some((file_level_id, file_min, file_max)) =
                parse_squash_root_sidecar_filename(&name)
            {
                // Match the FULL canonical tuple, not just `level_id`. A
                // stale sidecar with the same `level_id` but a different
                // height range (e.g. left over from a prior squash that
                // covered a different range) is an orphan and must be
                // deleted, not kept.
                let keep = expected_by_id
                    .get(&file_level_id)
                    .map(|e| {
                        e.present
                            && !e.trimmed
                            && e.min_height == file_min
                            && e.max_height == file_max
                    })
                    .unwrap_or(false);
                if !keep {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {
                            info!(
                                "reconcile_squash_sidecars: deleted orphan sidecar {} \
                                 (level_id={file_level_id}, heights=[{file_min}..={file_max}])",
                                path.display(),
                            );
                            report.dat_orphans_deleted += 1;
                        }
                        Err(e) => {
                            warn!(
                                "reconcile_squash_sidecars: failed to delete .dat orphan {}: {e}",
                                path.display()
                            );
                            report.delete_failures += 1;
                        }
                    }
                } else {
                    report.dat_kept += 1;
                }
            }
            // Non-matching filenames are intentionally left alone.
        }
    }

    // Presence check: every expected sidecar with present=true && trimmed=false
    // must exist on disk after the orphan-cleanup pass.
    for exp in expected_by_level {
        if !(exp.present && !exp.trimmed) {
            continue;
        }
        let path = squash_root_sidecar_path(db_path, exp.level_id, exp.min_height, exp.max_height);
        if !path.exists() {
            return Err(Error::CorruptionError(format!(
                "reconcile_squash_sidecars: SQL marks level_id={} (heights [{}..={}]) \
                 as root_sidecar_present=1 but the canonical sidecar file is missing: \
                 {}",
                exp.level_id,
                exp.min_height,
                exp.max_height,
                path.display(),
            )));
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("marf-sidecar-test-{name}"));
        if p.exists() {
            fs::remove_dir_all(&p).unwrap();
        }
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_header(level_id: u32, min_h: u32, max_h: u32) -> SidecarHeader {
        SidecarHeader {
            format_version: SIDECAR_FORMAT_VERSION,
            schema_flags: 0,
            record_kind: RecordKind::SquashRootNode,
            level_id,
            min_height: min_h,
            max_height: max_h,
            count: max_h - min_h + 1,
            created_at: 1_700_000_000,
        }
    }

    fn make_bodies(count: u32) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                // Per-body content is "[height_index_byte; some_length]". Vary
                // the length so we exercise non-uniform body sizes in the
                // index/body layout.
                let length = 7 + (i as usize % 13);
                vec![i as u8; length]
            })
            .collect()
    }

    #[test]
    fn header_round_trip() {
        let h = make_header(7, 100, 105);
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        assert_eq!(buf.len(), SIDECAR_HEADER_SIZE);
        let parsed = SidecarHeader::parse(&buf).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut buf = vec![0u8; SIDECAR_HEADER_SIZE];
        buf[0..8].copy_from_slice(b"NOTMARF!");
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_rejects_unknown_version() {
        let h = make_header(0, 0, 0);
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        // Bump the version field (bytes 8..10) to something unsupported.
        buf[8..10].copy_from_slice(&999u16.to_be_bytes());
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_rejects_unknown_record_kind() {
        let h = make_header(0, 0, 0);
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        // Patch record_kind (bytes 12..14) to something undefined.
        buf[12..14].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_rejects_bad_height_range() {
        let mut h = make_header(0, 100, 105);
        h.max_height = 99; // less than min
        h.count = 0;
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn header_rejects_count_height_mismatch() {
        let h = SidecarHeader {
            format_version: SIDECAR_FORMAT_VERSION,
            schema_flags: 0,
            record_kind: RecordKind::SquashRootNode,
            level_id: 0,
            min_height: 0,
            max_height: 9,
            count: 3, // should be 10
            created_at: 0,
        };
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn writer_reader_round_trip() {
        let dir = temp_dir("writer_reader_round_trip");
        // Sidecar paths are anchored at a synthetic db file under `dir`;
        // the helper computes `<db>.squash_sidecars/` next to it. We
        // create the parent dir; the writer creates the sidecar subdir.

        let level_id = 42;
        let min_h = 100;
        let max_h = 199;
        let count = max_h - min_h + 1;
        let header = make_header(level_id, min_h, max_h);
        let bodies = make_bodies(count);

        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), level_id, min_h, max_h);
        SidecarWriter::new(path.clone(), header.clone(), bodies.clone())
            .finalize()
            .unwrap();

        // The .tmp file must NOT remain after rename.
        let mut tmp_path = path.clone();
        let mut tmp_name = tmp_path.file_name().unwrap().to_os_string();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        assert!(!tmp_path.exists(), "tmp file should be renamed away");

        // Open and verify.
        let mut reader = SidecarReader::open(
            &path,
            SidecarExpectation {
                level_id: Some(level_id),
                record_kind: Some(RecordKind::SquashRootNode),
                min_height: Some(min_h),
                max_height: Some(max_h),
                count: Some(count),
            },
        )
        .unwrap();
        assert_eq!(reader.header, header);
        assert_eq!(reader.index.len(), count as usize);

        // Read every body and check it round-trips.
        for h in min_h..=max_h {
            let got = reader.read_body_at_height(h).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(bodies[(h - min_h) as usize].as_slice())
            );
        }

        // Out-of-range heights return Ok(None).
        assert!(reader.read_body_at_height(min_h - 1).unwrap().is_none());
        assert!(reader.read_body_at_height(max_h + 1).unwrap().is_none());
    }

    #[test]
    fn writer_rejects_count_mismatch() {
        let dir = temp_dir("writer_rejects_count_mismatch");
        // Sidecar paths are anchored at a synthetic db file under `dir`;
        // the helper computes `<db>.squash_sidecars/` next to it. We
        // create the parent dir; the writer creates the sidecar subdir.
        let header = make_header(1, 0, 9); // count = 10
        let bodies = make_bodies(5); // wrong length
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 1, 0, 9);
        let err = SidecarWriter::new(path, header, bodies)
            .finalize()
            .unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_level_id_mismatch() {
        let dir = temp_dir("reader_rejects_level_id_mismatch");
        // Sidecar paths are anchored at a synthetic db file under `dir`;
        // the helper computes `<db>.squash_sidecars/` next to it. We
        // create the parent dir; the writer creates the sidecar subdir.
        let header = make_header(7, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 7, 0, 4);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();
        let err = SidecarReader::open(
            &path,
            SidecarExpectation {
                level_id: Some(8),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_record_kind_mismatch() {
        let dir = temp_dir("reader_rejects_record_kind_mismatch");
        // Sidecar paths are anchored at a synthetic db file under `dir`;
        // the helper computes `<db>.squash_sidecars/` next to it. We
        // create the parent dir; the writer creates the sidecar subdir.
        let header = make_header(0, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();
        // The only kind v1 emits is SquashRootNode; ask for a hypothetical
        // future kind via a hand-constructed enum patch. The cleanest way
        // to assert this from outside the enum is to reach in via the raw
        // byte (offset 12..14 in the header).
        let mut bytes = fs::read(&path).unwrap();
        bytes[12..14].copy_from_slice(&0xFFFFu16.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        let err = SidecarReader::open(
            &path,
            SidecarExpectation {
                record_kind: Some(RecordKind::SquashRootNode),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_truncated_file() {
        let dir = temp_dir("reader_rejects_truncated_file");
        let header = make_header(0, 0, 9);
        let bodies = make_bodies(10);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 9);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();

        // Truncate to mid-body.
        let len = fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 5).unwrap();
        drop(f);

        // The bounds check during `open` catches the last index entry
        // pointing past EOF — fail closed at open time, not at read time.
        let err = SidecarReader::open(&path, SidecarExpectation::default()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    /// Patch a single index entry in an already-published sidecar file.
    /// Used by the bounds-check tests to plant deliberately corrupt
    /// `(body_offset, body_length)` values without going through the
    /// writer (which validates and would refuse to write them).
    fn patch_index_entry(path: &Path, slot: usize, body_offset: u64, body_length: u32) {
        let mut bytes = fs::read(path).unwrap();
        let entry_start = SIDECAR_HEADER_SIZE + slot * SIDECAR_INDEX_ENTRY_SIZE;
        bytes[entry_start..entry_start + 8].copy_from_slice(&body_offset.to_be_bytes());
        bytes[entry_start + 8..entry_start + 12].copy_from_slice(&body_length.to_be_bytes());
        // Leave reserved bytes (entry_start+12..+16) as-is.
        fs::write(path, &bytes).unwrap();
    }

    #[test]
    fn reader_rejects_index_entry_pointing_into_header_or_index() {
        let dir = temp_dir("reader_rejects_index_into_header");
        let header = make_header(0, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();

        // Patch slot 0 to point at offset 16 (deep inside the header) with
        // a small length. open() must reject this before the body is read.
        patch_index_entry(&path, 0, 16, 4);

        let err = SidecarReader::open(&path, SidecarExpectation::default()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_index_entry_overflowing_u64() {
        let dir = temp_dir("reader_rejects_index_overflow");
        let header = make_header(0, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();

        // body_offset = u64::MAX, body_length = 1 → checked_add overflows.
        patch_index_entry(&path, 0, u64::MAX, 1);

        let err = SidecarReader::open(&path, SidecarExpectation::default()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_index_entry_extending_past_eof() {
        let dir = temp_dir("reader_rejects_index_past_eof");
        let header = make_header(0, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4);
        SidecarWriter::new(path.clone(), header, bodies)
            .finalize()
            .unwrap();

        // Set slot 0's body_offset to a valid bodies-region offset but
        // length large enough to extend past file end. This is the
        // partial-write / corrupt-during-rename case.
        let file_len = fs::metadata(&path).unwrap().len();
        let bodies_region_start = SIDECAR_HEADER_SIZE as u64 + 5 * SIDECAR_INDEX_ENTRY_SIZE as u64;
        let runaway_length = (file_len - bodies_region_start + 64) as u32;
        patch_index_entry(&path, 0, bodies_region_start, runaway_length);

        let err = SidecarReader::open(&path, SidecarExpectation::default()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn writer_overwrites_existing_tmp() {
        // Crash recovery scenario: a prior crashed write left a .tmp file.
        // The writer should truncate-overwrite it, not fail.
        let dir = temp_dir("writer_overwrites_existing_tmp");

        let header = make_header(3, 0, 4);
        let bodies = make_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 3, 0, 4);

        // Plant a stale .tmp with junk bytes. Create the sidecar parent
        // dir manually because the writer hasn't run yet to create it.
        let mut tmp_path = path.clone();
        let mut tmp_name = tmp_path.file_name().unwrap().to_os_string();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        if let Some(parent) = tmp_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&tmp_path, b"garbage from a prior crash").unwrap();
        assert!(tmp_path.exists());

        SidecarWriter::new(path.clone(), header, bodies.clone())
            .finalize()
            .unwrap();

        // .tmp is gone; .dat readable and matches.
        assert!(!tmp_path.exists());
        let mut reader = SidecarReader::open(
            &path,
            SidecarExpectation {
                level_id: Some(3),
                ..Default::default()
            },
        )
        .unwrap();
        for h in 0..=4 {
            let got = reader.read_body_at_height(h).unwrap();
            assert_eq!(got.as_deref(), Some(bodies[h as usize].as_slice()));
        }
    }

    #[test]
    fn path_format_is_stable() {
        // Filename encodes level_id and height range with fixed-width
        // padding so directory listings sort in level order. The sidecar
        // dir is `<db>.squash_sidecars/` so peer DBs in the same parent
        // directory (e.g. squashed.sqlite + reference.sqlite in tests)
        // don't share a sidecar dir.
        let p =
            squash_root_sidecar_path(std::path::Path::new("/marf/squashed.sqlite"), 5, 4001, 5000);
        assert_eq!(
            p,
            PathBuf::from(
                "/marf/squashed.sqlite.squash_sidecars/\
                 marf-roots-level-000005-h00004001-00005000.dat"
            )
        );
    }
}
