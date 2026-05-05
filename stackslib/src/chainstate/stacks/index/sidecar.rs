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
//! Each squash level that requires per-block structural snapshots gets one
//! self-describing **multi-section** sidecar file. v1 emits up to two
//! sections per file:
//!
//! - [`RecordKind::SquashRootNode`]: per-height post-remap root node bodies,
//!   one body per height in `[min_height ..= max_height]`. Index-addressable
//!   by height slot. Required for [`crate::chainstate::stacks::index::marf::MARF::root_copy`]
//!   when fork-extending off a non-tip squashed parent.
//! - [`RecordKind::OrphanNode`]: contiguous trie-node records for
//!   structural nodes reachable from per-height roots but NOT from the
//!   merged-tip root. Each record uses the **same encoding as the
//!   merged blob**: non-leaves are `[hash(32) | body]`, hash-omitted
//!   leaves are `[body]` (set by the level's `leaf_hashes_omitted` flag,
//!   which is always true for reclaim levels). Byte-offset-addressable:
//!   a node at logical `TriePtr.ptr() = orphan_split_offset + d` lives
//!   at section-relative offset `d`. v1 (PR1) writes this section but
//!   the read path doesn't yet route into it; PR2 introduces the
//!   routing in [`crate::chainstate::stacks::index::storage`].
//!
//! Both sections share a single file's lifetime: published atomically
//! together, reconciled together, trimmed together. Trim removes the
//! file as a unit when the level ages past the retention window.
//!
//! # On-disk layout (v1, multi-section)
//!
//! ```text
//! +----------------------------------------+ offset 0
//! | FileHeader (40 bytes, fixed)           |
//! +----------------------------------------+ offset SIDECAR_HEADER_SIZE
//! | SectionTable (section_count × 32 bytes)|  one descriptor per section
//! +----------------------------------------+
//! | Section 0 body (per kind's layout)     |
//! +----------------------------------------+
//! | Section 1 body                         |
//! +----------------------------------------+
//! | ...                                    |
//! +----------------------------------------+ EOF
//! ```
//!
//! Per-section internal layouts:
//!
//! - `SquashRootNode`: `[Index: count × 16 bytes (body_offset, body_length, reserved)]`
//!   followed by `[Bodies (concatenated)]`. `body_offset` is an absolute
//!   file offset.
//! - `OrphanNode`: a verbatim copy of the merged blob's
//!   `[orphan_split_offset .. end_of_nodes)` byte range, concatenated
//!   record-by-record. Each record encodes a single trie node using the
//!   **same convention as the merged blob**: non-leaf nodes are
//!   `[hash(32) | body]`, hash-omitted leaves are `[body]` (controlled by
//!   the level's `leaf_hashes_omitted` flag, which is always set for
//!   reclaim levels). No internal index; the consumer derives the
//!   in-section offset from `TriePtr.ptr() - orphan_split_offset` and
//!   uses the standard node-decode path to determine record length.
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
/// file header (and is verified at open time).
pub const SIDECAR_MAGIC: [u8; 8] = *b"MARFSCAR";

/// Format version. Bump only on incompatible changes.
pub const SIDECAR_FORMAT_VERSION: u16 = 1;

/// Fixed file-header size in bytes.
///
/// magic(8) + format_version(2) + schema_flags(2) + reserved(4) +
/// level_id(4) + min_height(4) + max_height(4) + section_count(4) +
/// created_at(8) = 40 bytes.
pub const SIDECAR_HEADER_SIZE: usize = 40;

/// Fixed per-section descriptor size in bytes.
///
/// record_kind(2) + schema_flags(2) + reserved(4) + offset_in_file(8) +
/// length(8) + count(4) + reserved(4) = 32 bytes.
pub const SIDECAR_SECTION_DESCRIPTOR_SIZE: usize = 32;

/// Size of a single root-snapshot index entry: body_offset(8) +
/// body_length(4) + reserved/crc32(4) = 16 bytes.
pub const SIDECAR_INDEX_ENTRY_SIZE: usize = 16;

/// Read a big-endian `u16` at a fixed offset within a byte slice.
///
/// Used by the sidecar header / descriptor / index-entry parsers, all of
/// which know their field offsets at compile time. Each parser does an
/// up-front length check before calling these helpers, but using `.get()`
/// here keeps the slicing bounds-checked at the helper boundary too —
/// silences `clippy::indexing_slicing` and gives a useful corruption error
/// instead of a panic if the upstream length check is ever weakened.
#[inline]
fn read_be_u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let arr: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "sidecar: read_be_u16_at(offset={offset}) out of bounds (slice len {})",
                bytes.len()
            ))
        })?
        .try_into()
        .expect("get(offset..offset+2) yields exactly 2 bytes when Some");
    Ok(u16::from_be_bytes(arr))
}

#[inline]
fn read_be_u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let arr: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "sidecar: read_be_u32_at(offset={offset}) out of bounds (slice len {})",
                bytes.len()
            ))
        })?
        .try_into()
        .expect("get(offset..offset+4) yields exactly 4 bytes when Some");
    Ok(u32::from_be_bytes(arr))
}

#[inline]
fn read_be_u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let arr: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "sidecar: read_be_u64_at(offset={offset}) out of bounds (slice len {})",
                bytes.len()
            ))
        })?
        .try_into()
        .expect("get(offset..offset+8) yields exactly 8 bytes when Some");
    Ok(u64::from_be_bytes(arr))
}

/// Sidecar section kinds. The `u16` encoding leaves 65k future kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    /// Per-height post-remap squash-level root node body. Index-addressable
    /// by height slot.
    SquashRootNode = 0x0001,
    /// Orphan structural nodes reachable from per-height roots but not
    /// from the merged tip. Byte-offset-addressable; each record uses
    /// the merged blob's encoding (non-leaves: `[hash(32) | body]`,
    /// hash-omitted leaves: `[body]`), concatenated in writer-determined
    /// order.
    OrphanNode = 0x0002,
}

impl RecordKind {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::SquashRootNode),
            0x0002 => Some(Self::OrphanNode),
            _ => None,
        }
    }
}

/// File-level header. Identifies the level + height range; per-section
/// metadata lives in the [`SectionDescriptor`] table that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarHeader {
    pub format_version: u16,
    pub schema_flags: u16,
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub section_count: u32,
    /// Unix epoch seconds. Diagnostic only.
    pub created_at: u64,
}

impl SidecarHeader {
    /// Number of heights covered by this file (inclusive).
    pub fn height_count(&self) -> u32 {
        // max < min is rejected at parse time; safe to compute.
        self.max_height - self.min_height + 1
    }

    /// Convert an absolute height into a 0-based index slot, or `None` if
    /// the height is out of range.
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
        w.write_all(&[0u8; 4])?; // reserved
        w.write_all(&self.level_id.to_be_bytes())?;
        w.write_all(&self.min_height.to_be_bytes())?;
        w.write_all(&self.max_height.to_be_bytes())?;
        w.write_all(&self.section_count.to_be_bytes())?;
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
        let magic = bytes
            .get(0..8)
            .ok_or_else(|| Error::CorruptionError("Sidecar header: magic slice missing".into()))?;
        if magic != SIDECAR_MAGIC {
            return Err(Error::CorruptionError(format!(
                "Sidecar bad magic: {magic:?}"
            )));
        }
        let format_version = read_be_u16_at(bytes, 8)?;
        if format_version != SIDECAR_FORMAT_VERSION {
            return Err(Error::CorruptionError(format!(
                "Unsupported sidecar format version: {format_version}"
            )));
        }
        let schema_flags = read_be_u16_at(bytes, 10)?;
        // bytes[12..16] reserved, ignored.
        let level_id = read_be_u32_at(bytes, 16)?;
        let min_height = read_be_u32_at(bytes, 20)?;
        let max_height = read_be_u32_at(bytes, 24)?;
        let section_count = read_be_u32_at(bytes, 28)?;
        let created_at = read_be_u64_at(bytes, 32)?;

        if max_height < min_height {
            return Err(Error::CorruptionError(format!(
                "Sidecar header: max_height {max_height} < min_height {min_height}"
            )));
        }
        Ok(Self {
            format_version,
            schema_flags,
            level_id,
            min_height,
            max_height,
            section_count,
            created_at,
        })
    }
}

/// Per-section descriptor in the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionDescriptor {
    pub record_kind: RecordKind,
    pub schema_flags: u16,
    /// Absolute file offset where this section's body starts.
    pub offset_in_file: u64,
    /// Section body length in bytes.
    pub length: u64,
    /// Number of records in this section. Section-kind-specific:
    /// for `SquashRootNode` this equals the height range count; for
    /// `OrphanNode` this is the number of trie-node records the writer
    /// concatenated. Note that for `OrphanNode`, addressing is
    /// byte-offset-based (driven by `length`), not record-index-based —
    /// `count` is informational only.
    pub count: u32,
}

impl SectionDescriptor {
    fn write<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&(self.record_kind as u16).to_be_bytes())?;
        w.write_all(&self.schema_flags.to_be_bytes())?;
        w.write_all(&[0u8; 4])?; // reserved
        w.write_all(&self.offset_in_file.to_be_bytes())?;
        w.write_all(&self.length.to_be_bytes())?;
        w.write_all(&self.count.to_be_bytes())?;
        w.write_all(&[0u8; 4])?; // reserved
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < SIDECAR_SECTION_DESCRIPTOR_SIZE {
            return Err(Error::CorruptionError(format!(
                "Sidecar section descriptor too short: {} < {}",
                bytes.len(),
                SIDECAR_SECTION_DESCRIPTOR_SIZE
            )));
        }
        let record_kind_raw = read_be_u16_at(bytes, 0)?;
        let record_kind = RecordKind::from_u16(record_kind_raw).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Unknown sidecar record_kind: 0x{record_kind_raw:04x}"
            ))
        })?;
        let schema_flags = read_be_u16_at(bytes, 2)?;
        // bytes[4..8] reserved
        let offset_in_file = read_be_u64_at(bytes, 8)?;
        let length = read_be_u64_at(bytes, 16)?;
        let count = read_be_u32_at(bytes, 24)?;
        // bytes[28..32] reserved
        Ok(Self {
            record_kind,
            schema_flags,
            offset_in_file,
            length,
            count,
        })
    }
}

/// One entry in the head-located index for a `SquashRootNode` section.
/// `body_offset` is an absolute file offset.
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
            body_offset: read_be_u64_at(bytes, 0)?,
            body_length: read_be_u32_at(bytes, 8)?,
            reserved: read_be_u32_at(bytes, 12)?,
        })
    }
}

/// Section payload provided to a [`SidecarWriter`]. Each variant defines
/// its own internal layout; the writer streams them in declared order
/// into the tmp file at writer-computed offsets.
pub enum SidecarSection {
    /// Per-height root node bodies. Length must equal the file header's
    /// height range count, validated at finalize time.
    RootSnapshot {
        /// One body per height in `[min_height ..= max_height]`, ordered
        /// by ascending height.
        bodies: Vec<Vec<u8>>,
    },
    /// Orphan structural nodes, byte-for-byte copy of the merged blob's
    /// `[orphan_split_offset .. end_of_nodes)` byte range. Each record
    /// uses the same encoding as the merged blob: non-leaves are
    /// `[hash(32) | body]`, hash-omitted leaves are `[body]`. The order
    /// is load-bearing: a consumer computes a record's section-relative
    /// offset from `TriePtr.ptr() - orphan_split_offset`. `record_count`
    /// is the number of nodes the writer concatenated; the section's
    /// length comes from `bytes.len()`.
    OrphanNode {
        /// Pre-concatenated record bytes. Passing this as a single buffer
        /// (rather than `Vec<Vec<u8>>`) drops one transient copy on the
        /// 100 MB+ orphan sections seen in mainnet squashes.
        bytes: Vec<u8>,
        /// Diagnostic: number of trie nodes packed into `bytes`. Stored
        /// in the section descriptor's `count` for diagnostics; not
        /// load-bearing for read-side correctness (offset addressing
        /// uses `bytes.len()`, not `record_count`).
        record_count: u32,
    },
}

impl SidecarSection {
    pub fn record_kind(&self) -> RecordKind {
        match self {
            SidecarSection::RootSnapshot { .. } => RecordKind::SquashRootNode,
            SidecarSection::OrphanNode { .. } => RecordKind::OrphanNode,
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            SidecarSection::RootSnapshot { bodies } => bodies.len(),
            SidecarSection::OrphanNode { record_count, .. } => *record_count as usize,
        }
    }

    /// Byte length of this section's body once written, used by the
    /// writer to compute section descriptors before any bytes hit the
    /// tmp file.
    fn body_length(&self) -> Result<u64, Error> {
        match self {
            SidecarSection::RootSnapshot { bodies } => {
                let index_size = bodies
                    .len()
                    .checked_mul(SIDECAR_INDEX_ENTRY_SIZE)
                    .ok_or_else(|| {
                        Error::CorruptionError("Sidecar root section: index size overflow".into())
                    })?;
                let bodies_total: usize = bodies.iter().map(|b| b.len()).sum();
                let total = index_size.checked_add(bodies_total).ok_or_else(|| {
                    Error::CorruptionError("Sidecar root section: total size overflow".into())
                })?;
                Ok(total as u64)
            }
            SidecarSection::OrphanNode { bytes, .. } => Ok(bytes.len() as u64),
        }
    }
}

/// Stream-write a sidecar file to `<path>.tmp` → `fsync` → `rename` for
/// atomic publish. Section input buffers are dropped as they're written,
/// so peak transient memory is bounded by the largest single section's
/// input rather than the full file image (see [`Self::finalize`] for the
/// memory profile in detail). Caller is responsible for fsync of the
/// parent directory after [`Self::finalize`] returns.
///
/// Sections are passed by value; [`Self::finalize`] consumes them and
/// streams each section's bytes through a `BufWriter` directly into the
/// tmp file, dropping each section's input buffers as soon as they're
/// written.
pub struct SidecarWriter {
    final_path: PathBuf,
    tmp_path: PathBuf,
    header: SidecarHeader,
    sections: Vec<SidecarSection>,
}

impl SidecarWriter {
    /// Construct a new writer. `header.section_count` is overwritten at
    /// `finalize` time from `sections.len()`, so callers can leave it 0.
    pub fn new(final_path: PathBuf, header: SidecarHeader, sections: Vec<SidecarSection>) -> Self {
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
            sections,
        }
    }

    /// Stream-write the sidecar to `<path>.tmp`, fsync, and rename to the
    /// final path. After this returns, the caller should fsync the parent
    /// directory (best-effort; not required for content correctness, only
    /// for rename-durability across power loss).
    ///
    /// **Memory profile:** this writer never holds the full file image in
    /// RAM. The peak transient allocation is dominated by the largest
    /// single section's input buffers — for orphan sections, the
    /// pre-concatenated `bytes: Vec<u8>` the caller passes in (which is
    /// then moved through to the file via `BufWriter`). On mainnet
    /// FullHistory squashes (~150 MB orphan sections), the peak ~doubles
    /// from this writer's perspective dropped from "input + section
    /// payload + file image" (~3×) in the prior implementation to roughly
    /// "input only" (~1×) here.
    pub fn finalize(self) -> Result<(), Error> {
        let SidecarWriter {
            final_path,
            tmp_path,
            mut header,
            sections,
        } = self;

        // Populate section_count from the actual sections vector. Callers
        // construct the header before knowing the section list, so we own
        // this field at finalize time.
        header.section_count = u32::try_from(sections.len()).map_err(|_| {
            Error::CorruptionError(format!(
                "Sidecar writer: section_count {} exceeds u32::MAX",
                sections.len()
            ))
        })?;

        // Per-section validation.
        let height_count_usize = (header.max_height as usize)
            .checked_sub(header.min_height as usize)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "Sidecar writer: bad height range [{}, {}]",
                    header.min_height, header.max_height
                ))
            })?;
        for section in &sections {
            if let SidecarSection::RootSnapshot { bodies } = section {
                if bodies.len() != height_count_usize {
                    return Err(Error::CorruptionError(format!(
                        "Sidecar writer: RootSnapshot bodies.len()={} does not match \
                         height range [{}, {}] (expected {height_count_usize})",
                        bodies.len(),
                        header.min_height,
                        header.max_height,
                    )));
                }
            }
        }

        // ── Pass 1: compute layout (descriptors + offsets) without
        // materializing any payloads. The writer needs each section's
        // `offset_in_file` and `length` populated in the section table
        // before any section bytes hit the tmp file.
        let table_size = sections
            .len()
            .checked_mul(SIDECAR_SECTION_DESCRIPTOR_SIZE)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar writer: section table size overflow".into())
            })?;
        let mut next_offset: u64 = (SIDECAR_HEADER_SIZE as u64)
            .checked_add(table_size as u64)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar writer: post-table offset overflow".into())
            })?;

        let mut descriptors: Vec<SectionDescriptor> = Vec::with_capacity(sections.len());
        for section in &sections {
            let length = section.body_length()?;
            let count = u32::try_from(section.record_count()).map_err(|_| {
                Error::CorruptionError(format!(
                    "Sidecar writer: section record_count {} exceeds u32::MAX",
                    section.record_count()
                ))
            })?;
            descriptors.push(SectionDescriptor {
                record_kind: section.record_kind(),
                schema_flags: 0,
                offset_in_file: next_offset,
                length,
                count,
            });
            next_offset = next_offset.checked_add(length).ok_or_else(|| {
                Error::CorruptionError("Sidecar writer: section offset overflow".into())
            })?;
        }
        let total_size = next_offset;

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

        // ── Pass 2: stream the file. Header + section table + each
        // section body, in declared order. Each section's input buffer is
        // dropped as soon as its bytes are written, keeping peak memory
        // bounded by the largest single section's input.
        let bytes_written = {
            let tmp_file = OpenOptions::new()
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
            // 1 MiB write buffer: amortizes syscall overhead while staying
            // small relative to the largest sections we expect (~150 MB).
            let mut bw = std::io::BufWriter::with_capacity(1 << 20, tmp_file);

            // File header.
            let mut header_buf = Vec::with_capacity(SIDECAR_HEADER_SIZE);
            header.write(&mut header_buf)?;
            debug_assert_eq!(header_buf.len(), SIDECAR_HEADER_SIZE);
            bw.write_all(&header_buf).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: write file header to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;

            // Section table.
            let mut table_buf = Vec::with_capacity(table_size);
            for descriptor in &descriptors {
                descriptor.write(&mut table_buf)?;
            }
            debug_assert_eq!(table_buf.len(), table_size);
            bw.write_all(&table_buf).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: write section table to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;

            // Section bodies. `sections.into_iter()` consumes the Vec so
            // each section's input buffers are dropped after streaming.
            for (section, descriptor) in sections.into_iter().zip(descriptors.iter()) {
                stream_section_body(&mut bw, section, descriptor.offset_in_file, &tmp_path)?;
            }

            // Flush BufWriter, then sync_all on the underlying File.
            let mut tmp_file = bw.into_inner().map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: BufWriter flush to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            tmp_file.flush().map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: final flush to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            tmp_file.sync_all().map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: fsync of {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            total_size
        }; // file handle closed here for cross-platform rename sanity

        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar writer: rename {} -> {} failed: {e}",
                tmp_path.display(),
                final_path.display()
            ))
        })?;

        info!(
            "Sidecar writer: renamed {} -> {} ({} bytes, {} sections)",
            tmp_path.display(),
            final_path.display(),
            bytes_written,
            descriptors.len(),
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

/// Stream a single section's body into `w`. Consumes the section, so its
/// input buffers are dropped as soon as their bytes are written. Anchored
/// at `section_file_offset` (used to compute absolute body offsets in the
/// `SquashRootNode` index, which `read_body_at_height` later seeks to).
fn stream_section_body<W: Write>(
    w: &mut W,
    section: SidecarSection,
    section_file_offset: u64,
    tmp_path: &Path,
) -> Result<(), Error> {
    match section {
        SidecarSection::RootSnapshot { bodies } => {
            let count = bodies.len();
            let index_size = count.checked_mul(SIDECAR_INDEX_ENTRY_SIZE).ok_or_else(|| {
                Error::CorruptionError("Sidecar root section: index size overflow".into())
            })?;
            let bodies_region_start = section_file_offset
                .checked_add(index_size as u64)
                .ok_or_else(|| {
                    Error::CorruptionError(
                        "Sidecar root section: bodies-region offset overflow".into(),
                    )
                })?;
            // Build the index buffer in RAM (small: 16 B × count). Bodies
            // are streamed one-by-one to keep peak memory bounded by the
            // largest single body.
            let mut index_buf: Vec<u8> = Vec::with_capacity(index_size);
            let mut next_body_offset = bodies_region_start;
            for body in &bodies {
                let body_length = u32::try_from(body.len()).map_err(|_| {
                    Error::CorruptionError(format!(
                        "Sidecar root section: body too large for u32 length: {} bytes",
                        body.len()
                    ))
                })?;
                let entry = SidecarIndexEntry {
                    body_offset: next_body_offset,
                    body_length,
                    reserved: 0,
                };
                entry.write(&mut index_buf)?;
                next_body_offset = next_body_offset
                    .checked_add(body_length as u64)
                    .ok_or_else(|| {
                        Error::CorruptionError("Sidecar root section: body offset overflow".into())
                    })?;
            }
            debug_assert_eq!(index_buf.len(), index_size);
            w.write_all(&index_buf).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: write root-section index to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            for body in bodies {
                w.write_all(&body).map_err(|e| {
                    Error::CorruptionError(format!(
                        "Sidecar writer: write root-section body to {} failed: {e}",
                        tmp_path.display()
                    ))
                })?;
            }
            Ok(())
        }
        SidecarSection::OrphanNode { bytes, .. } => {
            // Single contiguous write. The caller pre-concatenated the
            // record bytes (matching the merged blob's encoding), so the
            // payload is exactly the byte image the section descriptor
            // declared. After this returns, `bytes` is dropped and its
            // ~100 MB+ allocation is freed.
            w.write_all(&bytes).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar writer: write orphan-section body to {} failed: {e}",
                    tmp_path.display()
                ))
            })?;
            Ok(())
        }
    }
}

/// Opens a published sidecar file, validates its file header + section
/// table, and exposes per-section accessors. The file handle is closed
/// when the reader is dropped.
#[derive(Debug)]
pub struct SidecarReader {
    file: File,
    pub header: SidecarHeader,
    pub sections: Vec<SectionDescriptor>,
    /// Cached `SquashRootNode` section index, if the section is present.
    /// Loaded eagerly at `open` time so [`Self::read_body_at_height`] is a
    /// single positional read.
    root_index: Option<Vec<SidecarIndexEntry>>,
}

/// Caller's expectation about a sidecar's identity, validated by
/// [`SidecarReader::open`]. Any field set to `Some` is enforced; `None`
/// means "trust the file." Production callers populate the full identity
/// tuple (`level_id`, `min_height`, `max_height`) so a stale file with a
/// partially-matching header (e.g. right `level_id` but wrong height
/// range) is rejected rather than serving the wrong slot's body.
#[derive(Debug, Clone, Copy, Default)]
pub struct SidecarExpectation {
    pub level_id: Option<u32>,
    pub min_height: Option<u32>,
    pub max_height: Option<u32>,
    /// If `Some(kind)`, the file must contain a section with that kind;
    /// otherwise [`SidecarReader::open`] returns `CorruptionError`.
    pub require_section: Option<RecordKind>,
}

impl SidecarReader {
    /// Open a sidecar at `path`, validating the file header, section
    /// table, and (if present) the `SquashRootNode` section's index. The
    /// `expect` fields are checked against the file header / sections.
    pub fn open(path: &Path, expect: SidecarExpectation) -> Result<Self, Error> {
        let mut file = OpenOptions::new().read(true).open(path).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: cannot open {}: {e}",
                path.display()
            ))
        })?;

        // ── File header ─────────────────────────────────────────────────
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

        // ── Section table ───────────────────────────────────────────────
        let table_size = (header.section_count as usize)
            .checked_mul(SIDECAR_SECTION_DESCRIPTOR_SIZE)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar reader: section table size overflow".into())
            })?;
        let mut table_buf = vec![0u8; table_size];
        file.read_exact(&mut table_buf).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: short read of section table from {}: {e}",
                path.display()
            ))
        })?;
        let mut sections: Vec<SectionDescriptor> =
            Vec::with_capacity(header.section_count as usize);
        // `chunks_exact` is bounds-safe by construction: it yields exactly
        // `len / SIDECAR_SECTION_DESCRIPTOR_SIZE` chunks of the requested
        // size, dropping any partial trailing remainder. We've already
        // validated `table_buf.len() >= header.section_count *
        // SIDECAR_SECTION_DESCRIPTOR_SIZE` above, so the chunk count
        // matches and there is no remainder to consider.
        for chunk in table_buf
            .chunks_exact(SIDECAR_SECTION_DESCRIPTOR_SIZE)
            .take(header.section_count as usize)
        {
            sections.push(SectionDescriptor::parse(chunk)?);
        }

        // ── Section-table bounds checks ─────────────────────────────────
        let file_len = file
            .metadata()
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar reader: cannot stat {}: {e}",
                    path.display()
                ))
            })?
            .len();
        let post_table_offset = (SIDECAR_HEADER_SIZE as u64)
            .checked_add(table_size as u64)
            .ok_or_else(|| {
                Error::CorruptionError("Sidecar reader: post-table offset overflow".into())
            })?;
        for (idx, descriptor) in sections.iter().enumerate() {
            if descriptor.offset_in_file < post_table_offset {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: section {idx} ({:?}) offset_in_file {} encroaches \
                     into the file header / section table (must be >= {post_table_offset}) in {}",
                    descriptor.record_kind,
                    descriptor.offset_in_file,
                    path.display(),
                )));
            }
            let end = descriptor
                .offset_in_file
                .checked_add(descriptor.length)
                .ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "Sidecar reader: section {idx} ({:?}) offset+length overflows u64 in {}",
                        descriptor.record_kind,
                        path.display(),
                    ))
                })?;
            if end > file_len {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: section {idx} ({:?}) extends past EOF \
                     ({}+{}={end} > file_len {file_len}) in {}",
                    descriptor.record_kind,
                    descriptor.offset_in_file,
                    descriptor.length,
                    path.display(),
                )));
            }
        }

        // ── Required-section enforcement ────────────────────────────────
        if let Some(want) = expect.require_section {
            if !sections.iter().any(|s| s.record_kind == want) {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: required section {want:?} not present in {}",
                    path.display()
                )));
            }
        }

        // ── Eagerly load the SquashRootNode section's index (if present) ─
        let root_index = if let Some(descriptor) = sections
            .iter()
            .find(|s| s.record_kind == RecordKind::SquashRootNode)
            .copied()
        {
            // Validate count against the file's height range — root snapshot
            // count must equal max - min + 1.
            let expected_count = header.height_count();
            if descriptor.count != expected_count {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: SquashRootNode section count {} does not match \
                     header height range count {expected_count} in {}",
                    descriptor.count,
                    path.display()
                )));
            }
            let count = descriptor.count as usize;
            let index_size = count.checked_mul(SIDECAR_INDEX_ENTRY_SIZE).ok_or_else(|| {
                Error::CorruptionError("Sidecar reader: root index size overflow".into())
            })?;
            if (index_size as u64) > descriptor.length {
                return Err(Error::CorruptionError(format!(
                    "Sidecar reader: SquashRootNode index region ({index_size} bytes) \
                     exceeds section length {} in {}",
                    descriptor.length,
                    path.display(),
                )));
            }
            let mut index_buf = vec![0u8; index_size];
            file.seek(SeekFrom::Start(descriptor.offset_in_file))
                .map_err(|e| {
                    Error::CorruptionError(format!(
                        "Sidecar reader: seek to root section start failed: {e}"
                    ))
                })?;
            file.read_exact(&mut index_buf).map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar reader: short read of root index from {}: {e}",
                    path.display()
                ))
            })?;
            let mut index = Vec::with_capacity(count);
            // `chunks_exact` is bounds-safe by construction (see the
            // section-table parser above for the matching pattern). The
            // upstream length check ensures `index_buf.len() >= count *
            // SIDECAR_INDEX_ENTRY_SIZE`, so `take(count)` yields exactly
            // the entries we need with no partial trailing chunk.
            for chunk in index_buf.chunks_exact(SIDECAR_INDEX_ENTRY_SIZE).take(count) {
                index.push(SidecarIndexEntry::parse(chunk)?);
            }
            // Per-entry bounds check: entries must lie within the bodies
            // sub-region of the section (i.e., past the index, before the
            // section ends). Same defensive posture as the prior format.
            let bodies_region_start = descriptor
                .offset_in_file
                .checked_add(index_size as u64)
                .ok_or_else(|| {
                    Error::CorruptionError("Sidecar reader: bodies region offset overflow".into())
                })?;
            let section_end = descriptor
                .offset_in_file
                .checked_add(descriptor.length)
                .ok_or_else(|| {
                    Error::CorruptionError("Sidecar reader: section end overflow".into())
                })?;
            for (slot, entry) in index.iter().enumerate() {
                if entry.body_offset < bodies_region_start {
                    return Err(Error::CorruptionError(format!(
                        "Sidecar reader: root index entry {slot} body_offset {} encroaches \
                         into the section's index region (must be >= {bodies_region_start}) in {}",
                        entry.body_offset,
                        path.display(),
                    )));
                }
                let entry_end = entry
                    .body_offset
                    .checked_add(entry.body_length as u64)
                    .ok_or_else(|| {
                        Error::CorruptionError(format!(
                            "Sidecar reader: root index entry {slot} body_offset {} + length {} \
                             overflows u64 in {}",
                            entry.body_offset,
                            entry.body_length,
                            path.display(),
                        ))
                    })?;
                if entry_end > section_end {
                    return Err(Error::CorruptionError(format!(
                        "Sidecar reader: root index entry {slot} body extends past section end \
                         ({}+{}={entry_end} > section_end {section_end}) in {}",
                        entry.body_offset,
                        entry.body_length,
                        path.display(),
                    )));
                }
            }
            Some(index)
        } else {
            None
        };

        Ok(Self {
            file,
            header,
            sections,
            root_index,
        })
    }

    /// Locate the descriptor for a section of the given kind, if present.
    pub fn find_section(&self, kind: RecordKind) -> Option<&SectionDescriptor> {
        self.sections.iter().find(|s| s.record_kind == kind)
    }

    /// Convenience accessor: descriptor for the `SquashRootNode` section.
    pub fn root_section(&self) -> Option<&SectionDescriptor> {
        self.find_section(RecordKind::SquashRootNode)
    }

    /// Convenience accessor: descriptor for the `OrphanNode` section.
    pub fn orphan_section(&self) -> Option<&SectionDescriptor> {
        self.find_section(RecordKind::OrphanNode)
    }

    /// Fetch the root body bytes for `height` from the `SquashRootNode`
    /// section. Returns `None` if `height` is out of the file's range.
    /// Returns `CorruptionError` if the file does not contain a
    /// `SquashRootNode` section.
    pub fn read_body_at_height(&mut self, height: u32) -> Result<Option<Vec<u8>>, Error> {
        let Some(slot) = self.header.slot_for_height(height) else {
            return Ok(None);
        };
        let index = self.root_index.as_ref().ok_or_else(|| {
            Error::CorruptionError(
                "Sidecar reader: read_body_at_height called but file has no SquashRootNode section"
                    .into(),
            )
        })?;
        let entry = index.get(slot as usize).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Sidecar reader: slot {slot} out of bounds for root index len {}",
                index.len()
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

    /// Read the entire `OrphanNode` section into a single byte vector.
    /// Used by tests for differential validation against the merged blob;
    /// PR2's read-path migration will introduce a positional accessor that
    /// fetches a single node by section-relative offset.
    pub fn read_orphan_section_bytes(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some(descriptor) = self.orphan_section().copied() else {
            return Ok(None);
        };
        self.file
            .seek(SeekFrom::Start(descriptor.offset_in_file))
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "Sidecar reader: seek to orphan section failed: {e}"
                ))
            })?;
        let mut buf = vec![0u8; descriptor.length as usize];
        self.file.read_exact(&mut buf).map_err(|e| {
            Error::CorruptionError(format!(
                "Sidecar reader: short read of orphan section (len={}): {e}",
                descriptor.length
            ))
        })?;
        Ok(Some(buf))
    }
}

/// Long-lived, positional-read handle to a sidecar's `OrphanNode`
/// section. Opens its own `File` handle so consumers can issue concurrent
/// `pread`s without contending on a shared cursor.
///
/// PR2 read-path routing uses this: a `TrieStorageConnection` caches one
/// of these whenever the currently-opened block is in a squashed level
/// that has orphans, so subsequent reads of `TriePtr.ptr() >=
/// split_offset` can fetch bytes from the sidecar's orphan section
/// instead of from the merged blob (which no longer contains them).
#[derive(Debug)]
pub struct OrphanSidecarHandle {
    file: File,
    /// Absolute file offset where the `OrphanNode` section's body begins.
    /// Cached at open time from the section descriptor; stable for the
    /// lifetime of the handle.
    section_offset_in_file: u64,
    /// Section body length in bytes. Used to bounds-check positional
    /// reads so callers can never `pread` past the section into another
    /// section's bytes.
    section_length: u64,
    /// The level's `orphan_split_offset`. A read at logical
    /// `TriePtr.ptr() = P` (where `P >= split_offset`) maps to
    /// section-relative offset `P - split_offset`.
    pub split_offset: u32,
}

impl OrphanSidecarHandle {
    /// Open a sidecar at `path`, validate it against `expect`, locate its
    /// `OrphanNode` section, and return a handle with its own `File` so
    /// positional reads can run concurrently with other handles on the
    /// same file.
    ///
    /// Returns `Err(CorruptionError)` if the file is missing, fails
    /// validation, or has no `OrphanNode` section. Caller is responsible
    /// for handling the trim case (`root_sidecar_trimmed = true` in SQL)
    /// before reaching this constructor — by then the file may already
    /// be unlinked.
    pub fn open(path: &Path, expect: SidecarExpectation, split_offset: u32) -> Result<Self, Error> {
        // Open through SidecarReader to get header/section validation,
        // then drop it and reopen our own File for positional reads —
        // we don't share the reader's seek cursor.
        let reader = SidecarReader::open(path, expect)?;
        let descriptor = reader.orphan_section().copied().ok_or_else(|| {
            Error::CorruptionError(format!(
                "OrphanSidecarHandle::open: no OrphanNode section in {}",
                path.display()
            ))
        })?;
        drop(reader);
        let file = OpenOptions::new().read(true).open(path).map_err(|e| {
            Error::CorruptionError(format!(
                "OrphanSidecarHandle::open: cannot reopen {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self {
            file,
            section_offset_in_file: descriptor.offset_in_file,
            section_length: descriptor.length,
            split_offset,
        })
    }

    /// Section body length in bytes. Caller can use this to size buffers
    /// or bounds-check. PR2's writer-time invariant ensures
    /// `section_length == end_of_nodes - orphan_split_offset` for the
    /// level, but readers should not assume that.
    pub fn section_length(&self) -> u64 {
        self.section_length
    }

    /// Read up to `buf.len()` bytes from the orphan section starting at
    /// the section-relative `relative_offset`. Returns the number of
    /// bytes read. Returns `0` (Ok) if `relative_offset` is at or past
    /// the section's end, matching the convention for short reads at
    /// EOF. Per-call buffer size is bounded by the caller; the reader
    /// caps the read at the section's remaining bytes so it can never
    /// stray into another section's data.
    pub fn pread_at(&self, buf: &mut [u8], relative_offset: u64) -> Result<usize, Error> {
        if relative_offset >= self.section_length {
            return Ok(0);
        }
        let available = self.section_length - relative_offset;
        let read_len = buf.len().min(available as usize);
        if read_len == 0 {
            return Ok(0);
        }
        let absolute_offset = self.section_offset_in_file.checked_add(relative_offset).ok_or_else(|| {
            Error::CorruptionError(format!(
                "OrphanSidecarHandle::pread_at: section_offset_in_file {} + relative_offset {} overflows",
                self.section_offset_in_file, relative_offset,
            ))
        })?;
        // `read_len = buf.len().min(...)` ⇒ `read_len ≤ buf.len()` by
        // construction, so `get_mut(..read_len)` is always `Some`. We use
        // `get_mut` rather than indexing to keep the bounds check explicit
        // for `clippy::indexing_slicing`.
        let dst = buf
            .get_mut(..read_len)
            .expect("read_len ≤ buf.len() by construction (see min above)");
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file
                .read_at(dst, absolute_offset)
                .map_err(Error::IOError)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file
                .seek_read(dst, absolute_offset)
                .map_err(Error::IOError)
        }
        #[cfg(not(any(unix, windows)))]
        {
            compile_error!("OrphanSidecarHandle::pread_at: unsupported platform");
        }
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

/// Construct the canonical path for a per-level squash sidecar.
///
/// The path includes the level's `blob_offset` so each publish lands at
/// a unique path. Without this, a `Replace` would have to overwrite the
/// previous active sidecar at the same path, opening a crash window
/// where SQL still describes the old level but the canonical path holds
/// new sidecar contents (split-brain). With the `blob_offset` suffix,
/// the new sidecar lands at a fresh path; the old sidecar at the prior
/// `blob_offset` path stays in place and is referenced by the retired
/// SQL row. Both rows resolve their sidecars unambiguously.
///
/// Same path scheme used for retired levels: a retired row carries the
/// pre-Replace `blob_offset`, which uniquely identifies its sidecar.
///
/// File pattern:
/// `marf-roots-level-{level_id:06}-h{min:08}-{max:08}-blob-{blob_offset:016x}.dat`.
///
/// Sidecars live in `<db>.squash_sidecars/`. See
/// [`migrate_legacy_sidecar_paths`] for the one-shot rename that brings
/// pre-versioned (`...-h{min}-{max}.dat`) sidecars onto this scheme.
pub fn squash_root_sidecar_path(
    db_path: &Path,
    level_id: u32,
    min_height: u32,
    max_height: u32,
    blob_offset: u64,
) -> PathBuf {
    let mut p = squash_sidecar_dir_for_db(db_path);
    p.push(format!(
        "marf-roots-level-{:06}-h{:08}-{:08}-blob-{:016x}.dat",
        level_id, min_height, max_height, blob_offset,
    ));
    p
}

/// Pre-versioning sidecar path (no `blob_offset` suffix). Used only by
/// [`migrate_legacy_sidecar_paths`] to find existing on-disk files
/// produced by older publishes and rename them onto the versioned
/// scheme. New code MUST use [`squash_root_sidecar_path`].
pub fn squash_root_sidecar_path_legacy(
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

/// Parsed identity tuple for a sidecar filename.
///
/// `blob_offset` is `Some(...)` for the versioned form
/// (`...-blob-{blob_offset:016x}.dat`) and `None` for the legacy
/// pre-versioning form (`...-h{min}-{max}.dat`). Reconcile uses the
/// presence/absence to decide which on-disk files belong to which SQL
/// row and to drive the legacy → versioned migration.
struct ParsedSidecarName {
    level_id: u32,
    min_height: u32,
    max_height: u32,
    blob_offset: Option<u64>,
}

/// Parse a sidecar filename of either the versioned form
/// (`marf-roots-level-{lid:06}-h{min:08}-{max:08}-blob-{offset:016x}.dat`)
/// or the legacy unversioned form
/// (`marf-roots-level-{lid:06}-h{min:08}-{max:08}.dat`).
///
/// Returns `None` for filenames that don't match either pattern (the
/// orphan-scan then ignores rather than touches them — operator
/// artifacts, future record kinds, etc. live under different names).
fn parse_squash_root_sidecar_filename(name: &str) -> Option<ParsedSidecarName> {
    let stem = name.strip_suffix(".dat")?;
    let after_prefix = stem.strip_prefix("marf-roots-level-")?;
    // Expected: "{level_id}-h{min}-{max}" optionally followed by
    // "-blob-{blob_offset:016x}".
    let mut parts = after_prefix.splitn(2, "-h");
    let level_str = parts.next()?;
    let h_str = parts.next()?;
    let level_id: u32 = level_str.parse().ok()?;

    let mut h_parts = h_str.splitn(2, '-');
    let min_str = h_parts.next()?;
    let rest = h_parts.next()?;
    let min_h: u32 = min_str.parse().ok()?;

    // `rest` is either `{max:08}` (legacy) or `{max:08}-blob-{offset:016x}`
    // (versioned). Split on `-blob-` to disambiguate.
    let (max_str, blob_offset) = match rest.split_once("-blob-") {
        Some((max_str, offset_hex)) => {
            let off = u64::from_str_radix(offset_hex, 16).ok()?;
            (max_str, Some(off))
        }
        None => (rest, None),
    };
    let max_h: u32 = max_str.parse().ok()?;
    Some(ParsedSidecarName {
        level_id,
        min_height: min_h,
        max_height: max_h,
        blob_offset,
    })
}

/// One level's expected sidecar state, as derived from `marf_squash_levels`. Used by
/// [`reconcile_squash_sidecars`] to decide which on-disk files to keep, delete, or treat as
/// missing.
///
/// `blob_offset` is included so reconcile can match on the versioned canonical pattern
/// (`...-blob-{blob_offset:016x}.dat`). (Pre-B6.3 it also distinguished current sidecars from
/// stale pre-`Replace` ones; with retired-row emission gone there is at most one sidecar per
/// `level_id`, but the offset-keyed match remains correct.)
#[derive(Debug, Clone, Copy)]
pub struct ExpectedSidecar {
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub blob_offset: u64,
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

    // Index expected sidecars by `(level_id, blob_offset)` for exact matching. The legacy index
    // keys only on `(level_id, min, max)` — used to migrate pre-versioning sidecars that don't
    // carry blob_offset in their filename. (Pre-B6.3 the active+retired split could yield
    // multiple entries per `level_id`; with retired-row emission gone, at most one entry exists
    // per level, but the keying scheme is unchanged.)
    let mut expected_by_full: std::collections::HashMap<(u32, u64), ExpectedSidecar> =
        std::collections::HashMap::with_capacity(expected_by_level.len());
    let mut expected_by_legacy: std::collections::HashMap<(u32, u32, u32), ExpectedSidecar> =
        std::collections::HashMap::with_capacity(expected_by_level.len());
    for &exp in expected_by_level {
        expected_by_full.insert((exp.level_id, exp.blob_offset), exp);
        // Legacy migration: a legacy filename (no `blob` suffix) maps onto the active row for
        // this `(level_id, min, max)`. (Pre-B6.3 we explicitly skipped retired entries here
        // because retired rows were introduced alongside the versioned
        // path scheme. This map's value gets overwritten if multiple
        // entries share `(level_id, min, max)`; that's fine, the legacy
        // file at most matches one of them, and we prefer to migrate it
        // toward whichever is present-and-not-trimmed.
        if exp.present && !exp.trimmed {
            expected_by_legacy.insert((exp.level_id, exp.min_height, exp.max_height), exp);
        }
    }

    let mut report = ReconcileReport::default();
    let mut needs_dir_fsync = false;

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
            let Some(parsed) = parse_squash_root_sidecar_filename(&name) else {
                // Non-matching filename — operator artifact, future
                // record kind, or pending-retire scratch file. Leave it
                // alone.
                continue;
            };

            match parsed.blob_offset {
                Some(blob_offset) => {
                    // Versioned form. Match on full identity. Any file
                    // whose `(level_id, blob_offset)` doesn't appear in
                    // SQL is an orphan: either it's a partially-published
                    // sidecar from a Replace whose SQL commit was lost,
                    // or a level row that was deleted post-publish.
                    let exp = expected_by_full
                        .get(&(parsed.level_id, blob_offset))
                        .copied();
                    let keep = exp
                        .map(|e| {
                            e.present
                                && !e.trimmed
                                && e.min_height == parsed.min_height
                                && e.max_height == parsed.max_height
                        })
                        .unwrap_or(false);
                    if !keep {
                        match std::fs::remove_file(&path) {
                            Ok(()) => {
                                info!(
                                    "reconcile_squash_sidecars: deleted orphan versioned \
                                     sidecar {} (level_id={}, heights=[{}..={}], \
                                     blob_offset={:#x})",
                                    path.display(),
                                    parsed.level_id,
                                    parsed.min_height,
                                    parsed.max_height,
                                    blob_offset,
                                );
                                report.dat_orphans_deleted += 1;
                                needs_dir_fsync = true;
                            }
                            Err(e) => {
                                warn!(
                                    "reconcile_squash_sidecars: failed to delete \
                                     versioned orphan {}: {e}",
                                    path.display()
                                );
                                report.delete_failures += 1;
                            }
                        }
                    } else {
                        report.dat_kept += 1;
                    }
                }
                None => {
                    // Legacy form (pre-versioning). If a SQL row
                    // matches `(level_id, min, max)` AND is
                    // `present && !trimmed`, migrate by renaming to
                    // the versioned path. Otherwise it's an orphan.
                    let key = (parsed.level_id, parsed.min_height, parsed.max_height);
                    let exp = expected_by_legacy.get(&key).copied();
                    if let Some(e) = exp {
                        let target = squash_root_sidecar_path(
                            db_path,
                            e.level_id,
                            e.min_height,
                            e.max_height,
                            e.blob_offset,
                        );
                        if target.exists() {
                            // Versioned target already in place — the
                            // legacy file is a stale duplicate. Delete it.
                            match std::fs::remove_file(&path) {
                                Ok(()) => {
                                    info!(
                                        "reconcile_squash_sidecars: deleted stale legacy \
                                         sidecar {} (versioned target already at {})",
                                        path.display(),
                                        target.display()
                                    );
                                    report.dat_orphans_deleted += 1;
                                    needs_dir_fsync = true;
                                }
                                Err(err) => {
                                    warn!(
                                        "reconcile_squash_sidecars: failed to delete \
                                         legacy duplicate {}: {err}",
                                        path.display()
                                    );
                                    report.delete_failures += 1;
                                }
                            }
                        } else {
                            // Migrate.
                            match std::fs::rename(&path, &target) {
                                Ok(()) => {
                                    info!(
                                        "reconcile_squash_sidecars: migrated legacy {} -> {}",
                                        path.display(),
                                        target.display()
                                    );
                                    report.dat_kept += 1;
                                    needs_dir_fsync = true;
                                }
                                Err(err) => {
                                    return Err(Error::CorruptionError(format!(
                                        "reconcile_squash_sidecars: legacy migration \
                                         {} -> {} failed: {err}",
                                        path.display(),
                                        target.display()
                                    )));
                                }
                            }
                        }
                    } else {
                        // No SQL row claims this legacy file. Orphan.
                        match std::fs::remove_file(&path) {
                            Ok(()) => {
                                info!(
                                    "reconcile_squash_sidecars: deleted orphan legacy \
                                     sidecar {} (no SQL row at level_id={}, \
                                     heights=[{}..={}])",
                                    path.display(),
                                    parsed.level_id,
                                    parsed.min_height,
                                    parsed.max_height,
                                );
                                report.dat_orphans_deleted += 1;
                                needs_dir_fsync = true;
                            }
                            Err(err) => {
                                warn!(
                                    "reconcile_squash_sidecars: failed to delete legacy \
                                     orphan {}: {err}",
                                    path.display()
                                );
                                report.delete_failures += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // fsync the dir so any rename/delete from the migration is durable
    // before the caller proceeds (and writes new sidecars or starts
    // serving reads). Best-effort — same precedent as the canonical
    // sidecar publish path.
    if needs_dir_fsync && sidecar_dir.exists() {
        if let Ok(handle) = std::fs::File::open(&sidecar_dir) {
            let _ = handle.sync_all();
        }
    }

    // Presence check: every expected sidecar with present=true && trimmed=false
    // must exist on disk after the migration / orphan-cleanup pass.
    for exp in expected_by_level {
        if !exp.present || exp.trimmed {
            continue;
        }
        let path = squash_root_sidecar_path(
            db_path,
            exp.level_id,
            exp.min_height,
            exp.max_height,
            exp.blob_offset,
        );
        if !path.exists() {
            return Err(Error::CorruptionError(format!(
                "reconcile_squash_sidecars: SQL marks level_id={} (heights [{}..={}], \
                 blob_offset={:#x}) as root_sidecar_present=1 but the versioned \
                 sidecar file is missing: {}",
                exp.level_id,
                exp.min_height,
                exp.max_height,
                exp.blob_offset,
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
            level_id,
            min_height: min_h,
            max_height: max_h,
            // section_count is overwritten by the writer at finalize time.
            section_count: 0,
            created_at: 1_700_000_000,
        }
    }

    fn make_root_bodies(count: u32) -> Vec<Vec<u8>> {
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

    fn make_orphan_records(count: u32) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut record = Vec::with_capacity(32 + 5);
                // hash bytes: encode the index in the first 4 hash bytes
                let mut hash = [0u8; 32];
                hash[0..4].copy_from_slice(&i.to_be_bytes());
                record.extend_from_slice(&hash);
                // body: variable length, stamped with the index for round-trip checks
                let body_len = 5 + (i as usize % 9);
                let body = vec![0xa0 | (i as u8 & 0x0f); body_len];
                record.extend_from_slice(&body);
                record
            })
            .collect()
    }

    #[test]
    fn header_round_trip() {
        let mut h = make_header(7, 100, 105);
        h.section_count = 2;
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
    fn header_rejects_bad_height_range() {
        let mut h = make_header(0, 100, 105);
        h.max_height = 99; // less than min
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        let err = SidecarHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn section_descriptor_round_trip() {
        let d = SectionDescriptor {
            record_kind: RecordKind::OrphanNode,
            schema_flags: 0xABCD,
            offset_in_file: 0x1234_5678_9ABC_DEF0,
            length: 0x0000_FFFF_FFFF_0000,
            count: 12345,
        };
        let mut buf = Vec::new();
        d.write(&mut buf).unwrap();
        assert_eq!(buf.len(), SIDECAR_SECTION_DESCRIPTOR_SIZE);
        let parsed = SectionDescriptor::parse(&buf).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn section_descriptor_rejects_unknown_kind() {
        let mut buf = vec![0u8; SIDECAR_SECTION_DESCRIPTOR_SIZE];
        buf[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let err = SectionDescriptor::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn writer_reader_round_trip_root_only() {
        let dir = temp_dir("writer_reader_round_trip_root_only");
        let level_id = 42;
        let min_h = 100;
        let max_h = 199;
        let count = max_h - min_h + 1;
        let header = make_header(level_id, min_h, max_h);
        let bodies = make_root_bodies(count);

        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), level_id, min_h, max_h, 0);
        SidecarWriter::new(
            path.clone(),
            header.clone(),
            vec![SidecarSection::RootSnapshot {
                bodies: bodies.clone(),
            }],
        )
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
                min_height: Some(min_h),
                max_height: Some(max_h),
                require_section: Some(RecordKind::SquashRootNode),
            },
        )
        .unwrap();
        assert_eq!(reader.header.level_id, level_id);
        assert_eq!(reader.header.min_height, min_h);
        assert_eq!(reader.header.max_height, max_h);
        assert_eq!(reader.header.section_count, 1);
        assert_eq!(reader.sections.len(), 1);
        assert_eq!(reader.sections[0].record_kind, RecordKind::SquashRootNode);
        assert_eq!(reader.sections[0].count, count);
        assert!(reader.orphan_section().is_none());

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
    fn writer_reader_round_trip_root_plus_orphan() {
        let dir = temp_dir("writer_reader_round_trip_root_plus_orphan");
        let level_id = 7;
        let min_h = 0;
        let max_h = 9;
        let count = max_h - min_h + 1;
        let header = make_header(level_id, min_h, max_h);
        let bodies = make_root_bodies(count);
        let orphans_per_record = make_orphan_records(13);
        // The writer takes a single pre-concatenated buffer + record count.
        // Mirrors what `squash.rs` does with `node_store.read_node_bytes`
        // accumulated into one Vec before publish.
        let orphan_record_count = orphans_per_record.len() as u32;
        let orphan_bytes: Vec<u8> = orphans_per_record
            .iter()
            .flat_map(|r| r.iter().copied())
            .collect();

        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), level_id, min_h, max_h, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![
                SidecarSection::RootSnapshot {
                    bodies: bodies.clone(),
                },
                SidecarSection::OrphanNode {
                    bytes: orphan_bytes.clone(),
                    record_count: orphan_record_count,
                },
            ],
        )
        .finalize()
        .unwrap();

        let mut reader = SidecarReader::open(
            &path,
            SidecarExpectation {
                level_id: Some(level_id),
                min_height: Some(min_h),
                max_height: Some(max_h),
                require_section: Some(RecordKind::OrphanNode),
            },
        )
        .unwrap();
        assert_eq!(reader.header.section_count, 2);
        assert_eq!(reader.sections.len(), 2);
        assert!(reader.root_section().is_some());
        let orphan_desc = reader.orphan_section().copied().expect("orphan section");
        assert_eq!(orphan_desc.record_kind, RecordKind::OrphanNode);
        assert_eq!(orphan_desc.count, orphan_record_count);

        // Roots are still readable.
        for h in min_h..=max_h {
            let got = reader.read_body_at_height(h).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(bodies[(h - min_h) as usize].as_slice())
            );
        }

        // Orphan section bytes are the verbatim pre-concatenated input.
        let got = reader.read_orphan_section_bytes().unwrap().unwrap();
        assert_eq!(got, orphan_bytes);
    }

    #[test]
    fn writer_rejects_root_count_mismatch() {
        let dir = temp_dir("writer_rejects_root_count_mismatch");
        let header = make_header(1, 0, 9); // height range = 10
        let bodies = make_root_bodies(5); // wrong length
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 1, 0, 9, 0);
        let err = SidecarWriter::new(path, header, vec![SidecarSection::RootSnapshot { bodies }])
            .finalize()
            .unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn reader_rejects_level_id_mismatch() {
        let dir = temp_dir("reader_rejects_level_id_mismatch");
        let header = make_header(7, 0, 4);
        let bodies = make_root_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 7, 0, 4, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![SidecarSection::RootSnapshot { bodies }],
        )
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
    fn reader_rejects_missing_required_section() {
        let dir = temp_dir("reader_rejects_missing_required_section");
        let header = make_header(0, 0, 4);
        let bodies = make_root_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![SidecarSection::RootSnapshot { bodies }],
        )
        .finalize()
        .unwrap();
        // File only has SquashRootNode; require OrphanNode → err.
        let err = SidecarReader::open(
            &path,
            SidecarExpectation {
                require_section: Some(RecordKind::OrphanNode),
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
        let bodies = make_root_bodies(10);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 9, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![SidecarSection::RootSnapshot { bodies }],
        )
        .finalize()
        .unwrap();

        // Truncate to mid-body.
        let len = fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 5).unwrap();
        drop(f);

        let err = SidecarReader::open(&path, SidecarExpectation::default()).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }

    #[test]
    fn writer_overwrites_existing_tmp() {
        // Crash recovery scenario: a prior crashed write left a .tmp file.
        // The writer should truncate-overwrite it, not fail.
        let dir = temp_dir("writer_overwrites_existing_tmp");

        let header = make_header(3, 0, 4);
        let bodies = make_root_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 3, 0, 4, 0);

        let mut tmp_path = path.clone();
        let mut tmp_name = tmp_path.file_name().unwrap().to_os_string();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        if let Some(parent) = tmp_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&tmp_path, b"garbage from a prior crash").unwrap();
        assert!(tmp_path.exists());

        SidecarWriter::new(
            path.clone(),
            header,
            vec![SidecarSection::RootSnapshot {
                bodies: bodies.clone(),
            }],
        )
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
        // Filename encodes level_id, height range, and merged-blob offset
        // with fixed-width padding so directory listings sort in level
        // order. The blob_offset suffix versions the sidecar so each
        // publish lands at a unique path (avoids overwriting the
        // canonical sidecar before the SQL state transition commits).
        // The sidecar dir is `<db>.squash_sidecars/` so peer DBs in the
        // same parent directory don't share a sidecar dir.
        let p = squash_root_sidecar_path(
            std::path::Path::new("/marf/squashed.sqlite"),
            5,
            4001,
            5000,
            0xdead_beef_u64,
        );
        assert_eq!(
            p,
            PathBuf::from(
                "/marf/squashed.sqlite.squash_sidecars/\
                 marf-roots-level-000005-h00004001-00005000-blob-00000000deadbeef.dat"
            )
        );
    }

    #[test]
    fn orphan_sidecar_handle_pread_at_round_trip() {
        // PR2 read-path entry: open the orphan section via
        // OrphanSidecarHandle, pread arbitrary slices, and verify the
        // returned bytes match the writer's input.
        let dir = temp_dir("orphan_sidecar_handle_pread_at_round_trip");
        let level_id = 11;
        let min_h = 0;
        let max_h = 4;
        let split_offset = 0x1234_5678u32; // arbitrary; not validated by handle
        let header = make_header(level_id, min_h, max_h);
        let bodies = make_root_bodies(max_h - min_h + 1);
        let orphans = make_orphan_records(7);
        let orphan_record_count = orphans.len() as u32;
        let orphan_bytes: Vec<u8> = orphans.iter().flat_map(|r| r.iter().copied()).collect();

        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), level_id, min_h, max_h, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![
                SidecarSection::RootSnapshot { bodies },
                SidecarSection::OrphanNode {
                    bytes: orphan_bytes.clone(),
                    record_count: orphan_record_count,
                },
            ],
        )
        .finalize()
        .unwrap();

        let handle = OrphanSidecarHandle::open(
            &path,
            SidecarExpectation {
                level_id: Some(level_id),
                min_height: Some(min_h),
                max_height: Some(max_h),
                require_section: Some(RecordKind::OrphanNode),
            },
            split_offset,
        )
        .unwrap();

        assert_eq!(handle.split_offset, split_offset);
        assert_eq!(handle.section_length(), orphan_bytes.len() as u64);

        // Read the entire section in one shot.
        let mut buf = vec![0u8; orphan_bytes.len()];
        let n = handle.pread_at(&mut buf, 0).unwrap();
        assert_eq!(n, orphan_bytes.len());
        assert_eq!(buf, orphan_bytes);

        // Read random sub-ranges and verify against the input.
        for &(off, len) in &[(0, 4), (3, 17), (10, 11), (orphan_bytes.len() / 2, 8)] {
            let mut buf = vec![0u8; len];
            let n = handle.pread_at(&mut buf, off as u64).unwrap();
            assert!(n <= len);
            let expected_end = (off + len).min(orphan_bytes.len());
            assert_eq!(n, expected_end - off);
            assert_eq!(&buf[..n], &orphan_bytes[off..expected_end]);
        }

        // Read past EOS returns Ok(0).
        let mut buf = vec![0u8; 8];
        let n = handle
            .pread_at(&mut buf, orphan_bytes.len() as u64)
            .unwrap();
        assert_eq!(n, 0);
        let n = handle
            .pread_at(&mut buf, orphan_bytes.len() as u64 + 100)
            .unwrap();
        assert_eq!(n, 0);

        // Tail-spanning read is capped at the section's remaining bytes.
        let off = orphan_bytes.len() - 3;
        let mut buf = vec![0u8; 16];
        let n = handle.pread_at(&mut buf, off as u64).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &orphan_bytes[off..]);
    }

    #[test]
    fn orphan_sidecar_handle_rejects_file_without_orphan_section() {
        // If a sidecar has only a RootSnapshot section,
        // OrphanSidecarHandle::open must surface CorruptionError instead
        // of silently constructing a handle to nonexistent bytes.
        let dir = temp_dir("orphan_sidecar_handle_rejects_no_orphan");
        let header = make_header(0, 0, 4);
        let bodies = make_root_bodies(5);
        let path = squash_root_sidecar_path(&dir.join("test.sqlite"), 0, 0, 4, 0);
        SidecarWriter::new(
            path.clone(),
            header,
            vec![SidecarSection::RootSnapshot { bodies }],
        )
        .finalize()
        .unwrap();

        let err = OrphanSidecarHandle::open(&path, SidecarExpectation::default(), 42).unwrap_err();
        assert!(matches!(err, Error::CorruptionError(_)));
    }
}
