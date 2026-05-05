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

//! On-disk plan format for Phase B horizon-gated squash promotion.
//!
//! A `SquashPlan` is the durable hand-off between a promotion's background
//! phase (which appends the merged blob to `<db>.blobs` and computes the
//! descendant rewrite plan) and its swap phase (which applies the rewrites
//! and commits the SQL transaction). The plan is written to
//! `<db>.squash_pending.{level_id:08}.plan` and fsynced before the swap
//! starts; if a crash interrupts the swap, the plan file is the recovery
//! anchor that lets a subsequent open replay everything idempotently.
//!
//! See `.docs/squashing-v1.5-phase-b.md` §4.2 (on-disk format) and §7
//! (recovery state machine) for the design.
//!
//! # Format
//!
//! The format is versioned (`format_version = 1`). Every multi-byte
//! integer is big-endian. The body is followed by a 32-byte
//! Sha512_256 hash that covers everything before it; readers must
//! recompute and compare. Mismatches are treated as a corrupt plan
//! file (recovery abandons it).
//!
//! Strong hashes (Sha512_256) are used in three roles:
//! - `cold_blob_hash`: validates the merged-blob byte range the plan
//!   reserved in `<db>.blobs` is intact (catches partial cold-blob
//!   appends on crash).
//! - `sidecar_hash`: validates the published per-height-root sidecar
//!   file matches what the merger emitted.
//! - `body_hash`: validates the plan file itself wasn't truncated
//!   mid-write.
//!
//! # File-name convention
//!
//! The active plan files for a MARF are
//! `<db>.squash_pending.{level_id:08}.plan` (8-digit zero-padded
//! `level_id` for sort-stable on-disk ordering). Discovery scans the
//! parent directory for files matching this pattern.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha512_256};
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

use crate::chainstate::stacks::index::Error;

/// Magic bytes identifying a squash promotion plan file. Cheap structural
/// sanity check before validating the body hash.
pub const PLAN_MAGIC: &[u8; 4] = b"SQPL";

/// Current on-disk format version. Bump on any breaking change to the
/// layout; readers refuse versions they don't know.
pub const PLAN_FORMAT_VERSION: u32 = 1;

/// File-name suffix template. The discoverer matches files of the form
/// `<db>.squash_pending.{level_id:08}.plan`.
pub const PLAN_FILE_PREFIX: &str = ".squash_pending.";
pub const PLAN_FILE_SUFFIX: &str = ".plan";

/// Build the on-disk path for a plan file with the given DB-path stem
/// and level id. Mirrors [`crate::chainstate::stacks::index::hot_file::hot_file_path`]'s
/// format conventions.
pub fn plan_file_path(db_path: &str, level_id: u32) -> String {
    format!("{db_path}{PLAN_FILE_PREFIX}{level_id:08}{PLAN_FILE_SUFFIX}")
}

/// In-memory representation of a parsed plan file.
///
/// The four sections (header, in-range blocks, translation map, rewrite
/// plan) reflect the on-disk layout from
/// `.docs/squashing-v1.5-phase-b.md` §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashPlan {
    /// Plan-wide metadata: level id, height range, cold-blob extent,
    /// sidecar reference, and integrity hashes.
    pub header: PlanHeader,
    /// The canonical in-range block list, in ascending height order.
    /// Used by the swap-phase SQL transaction to drive `UPDATE marf_data
    /// ... WHERE block_hash = ?` for each row.
    pub in_range_blocks: Vec<InRangeBlock>,
    /// Per-source-block translation map. Catch-up scan looks up
    /// `(back_block, captured_offset)` here to derive the post-promotion
    /// rewrite value.
    pub translation_map: TranslationMap,
    /// Pre-computed rewrite plan from the background phase. Catch-up
    /// extends this with newly-written descendant blocks; recovery
    /// replays it idempotently using the `pre_bytes` / `post_bytes`
    /// witnesses.
    pub rewrite_plan: Vec<RewriteEntry>,
}

/// Plan-wide metadata at the head of every plan file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanHeader {
    /// Squash level id this plan publishes. Identifies the plan file
    /// (`<db>.squash_pending.{level_id:08}.plan`) and becomes the new
    /// row's level id in `marf_squash_levels`.
    pub level_id: u32,
    /// Inclusive low end of the squash range (Stacks block height).
    pub min_height: u32,
    /// Inclusive high end of the squash range.
    pub max_height: u32,
    /// `MAX(block_id) FROM marf_data` snapshotted at the end of the
    /// background phase's descendant enumeration. The catch-up scan
    /// (B5d-fu.1) re-enumerates hot-tier rows with `block_id >
    /// tip_at_scan_start` to find descendants written between
    /// plan-build and swap.
    ///
    /// Field name is historical (originally documented as a chain-tip
    /// height); the semantics now are "block_id watermark for catch-up
    /// detection". Renaming is deferred to a wider format change.
    pub tip_at_scan_start: u32,
    /// Reserved cold-blob extent (offset + length) where the merger
    /// appended the merged blob.
    pub cold_blob_offset: u64,
    pub cold_blob_length: u64,
    /// Sha512_256 hash of the cold-blob region's bytes. Recovery
    /// recomputes this and abandons the plan on mismatch — that's the
    /// "missing/short cold blob" branch of §7.1 step 2a.
    pub cold_blob_hash: TrieHash,
    /// On-disk path to the published sidecar (per-height root sidecar).
    /// Stored relative to the DB path's parent directory; recovery
    /// resolves it back to an absolute path.
    pub sidecar_path: String,
    /// Sha512_256 hash of the sidecar file's bytes. Recovery validates;
    /// mismatch abandons the plan.
    pub sidecar_hash: TrieHash,

    // ── Additional fields needed to reconstruct a `marf_squash_levels`
    // row at recovery time without re-running the merger. The five
    // fields below mirror the corresponding `SquashLevelRow` columns
    // (`squash.rs:475`); recovery passes them straight through to
    // `trie_sql::write_squash_level`.
    /// `marf_data` rows for in-range blocks point at the merged blob
    /// (true for any horizon-gated promotion). Stored as part of the
    /// plan so recovery doesn't have to re-derive the publish mode.
    pub reads_redirected: bool,
    /// Whether a per-height root-node sidecar was published for this
    /// level (always true for v1.5 promotions; included for forward
    /// compatibility with future no-sidecar variants).
    pub root_sidecar_present: bool,
    /// Trim policy state. Always false at publish time; later trim
    /// passes flip it to true.
    pub root_sidecar_trimmed: bool,
    /// Logical offset where orphan structural nodes begin in the
    /// merged blob's address space. See `SquashLevelRow.orphan_split_offset`
    /// for the routing semantics.
    pub orphan_split_offset: u32,
    /// `MAX(block_id) FROM marf_data WHERE unconfirmed = 0` snapshotted
    /// at publish time. Backs the per-MARF squash-work counter.
    pub published_max_block_id: u32,
}

/// One entry in the in-range canonical block list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InRangeBlock {
    pub block_hash: [u8; 32],
    pub block_id: u32,
}

/// Per-source-block translation map. Indexed first by the source
/// block's `block_id`, then by the **node-start offset** within that
/// block's hot-layout encoding. Returns the corresponding offset in
/// the merged blob.
///
/// The `BTreeMap` inner type gives deterministic iteration order, which
/// matters for the body hash (see [`SquashPlan::compute_body_hash`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TranslationMap {
    pub by_block: HashMap<u32, BTreeMap<u32, u32>>,
}

impl TranslationMap {
    /// Look up the post-promotion offset for `(block_id, old_offset)`.
    pub fn lookup(&self, block_id: u32, old_offset: u32) -> Option<u32> {
        self.by_block.get(&block_id)?.get(&old_offset).copied()
    }

    /// Add a single entry, creating the per-block map if needed.
    pub fn insert(&mut self, block_id: u32, old_offset: u32, new_offset: u32) {
        self.by_block
            .entry(block_id)
            .or_default()
            .insert(old_offset, new_offset);
    }

    /// Total number of (block, offset) pairs.
    pub fn entry_count(&self) -> usize {
        self.by_block.values().map(|m| m.len()).sum()
    }
}

/// One rewrite-plan entry. Points at a 4-byte `ptr` field somewhere in
/// the hot tier whose value needs to be updated as part of the swap.
///
/// The pre/post witness bytes make replay idempotent (§7.1 step 2c):
/// recovery can tell whether an entry has been applied already by
/// comparing the on-disk bytes to `pre_bytes` and `post_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteEntry {
    /// Hot file sequence number (`marf_data.storage_seq`) holding the
    /// ptr field.
    pub hot_file_seq: u32,
    /// Absolute byte offset of the 4-byte `ptr` field within the hot
    /// file. Suitable as a `pwrite` target.
    pub file_offset: u64,
    /// On-disk bytes of the ptr field as the background phase observed
    /// them. Recovery's idempotent replay (§7.1 step 2c) uses this as
    /// the "not yet applied" witness.
    pub pre_bytes: [u8; 4],
    /// New ptr field bytes the swap will write. Recovery's idempotent
    /// replay uses this as the "already applied" witness.
    pub post_bytes: [u8; 4],
}

// ---------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------

impl SquashPlan {
    /// Encode the plan to `w`. Computes the trailing body hash and
    /// writes it after the body — readers must recompute and compare.
    pub fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        // Buffer the body so we can hash + flush atomically. Plan files
        // are bounded by squash range size and well within the 100s-of-MB
        // range; one in-RAM buffer is fine.
        let mut body = Vec::with_capacity(4096);
        self.write_body(&mut body)?;
        let body_hash = sha512_256_of(&body);

        w.write_all(&body).map_err(Error::IOError)?;
        w.write_all(body_hash.as_bytes()).map_err(Error::IOError)?;
        Ok(())
    }

    /// Decode a plan from `r`. Validates the magic, format version, and
    /// trailing body hash; returns an error (with a descriptive message)
    /// on any mismatch so the recovery state machine can decide whether
    /// to abandon the plan or fail the open.
    pub fn decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        let mut all = Vec::new();
        r.read_to_end(&mut all).map_err(Error::IOError)?;

        if all.len() < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(format!(
                "squash_plan: file too short for trailer hash (have {})",
                all.len(),
            )));
        }
        let split = all
            .len()
            .checked_sub(TRIEHASH_ENCODED_SIZE)
            .ok_or(Error::OverflowError)?;
        let body = all
            .get(..split)
            .ok_or_else(|| Error::CorruptionError("squash_plan: body slice".into()))?;
        let stored_hash_bytes: [u8; 32] = all
            .get(split..)
            .ok_or_else(|| Error::CorruptionError("squash_plan: trailer slice".into()))?
            .try_into()
            .map_err(|_| Error::CorruptionError("squash_plan: trailer hash slice".into()))?;
        let computed = sha512_256_of(body);
        if computed.as_bytes() != &stored_hash_bytes {
            return Err(Error::CorruptionError(
                "squash_plan: body hash mismatch (file is corrupt or torn)".to_string(),
            ));
        }

        let mut cursor = std::io::Cursor::new(body);
        Self::read_body(&mut cursor)
    }

    /// Write everything except the trailing body hash.
    fn write_body<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        // Magic + version
        w.write_all(PLAN_MAGIC).map_err(Error::IOError)?;
        write_u32(w, PLAN_FORMAT_VERSION)?;

        // Header
        write_u32(w, self.header.level_id)?;
        write_u32(w, self.header.min_height)?;
        write_u32(w, self.header.max_height)?;
        write_u32(w, self.header.tip_at_scan_start)?;
        write_u64(w, self.header.cold_blob_offset)?;
        write_u64(w, self.header.cold_blob_length)?;
        w.write_all(self.header.cold_blob_hash.as_bytes())
            .map_err(Error::IOError)?;
        write_varbytes(w, self.header.sidecar_path.as_bytes())?;
        w.write_all(self.header.sidecar_hash.as_bytes())
            .map_err(Error::IOError)?;
        // Level-row extras. Booleans are written as single u8s (0/1).
        write_u8(w, self.header.reads_redirected as u8)?;
        write_u8(w, self.header.root_sidecar_present as u8)?;
        write_u8(w, self.header.root_sidecar_trimmed as u8)?;
        write_u32(w, self.header.orphan_split_offset)?;
        write_u32(w, self.header.published_max_block_id)?;

        // In-range blocks
        write_u32(
            w,
            u32_try_from(self.in_range_blocks.len(), "in_range_blocks")?,
        )?;
        for b in &self.in_range_blocks {
            w.write_all(&b.block_hash).map_err(Error::IOError)?;
            write_u32(w, b.block_id)?;
        }

        // Translation map. Iterate the per-block maps in sorted block_id
        // order so the body bytes are deterministic regardless of HashMap
        // insertion order — that keeps the body hash stable across runs
        // for the same logical plan.
        let mut block_ids: Vec<u32> = self.translation_map.by_block.keys().copied().collect();
        block_ids.sort_unstable();
        write_u32(
            w,
            u32_try_from(block_ids.len(), "translation_map.by_block")?,
        )?;
        for block_id in block_ids {
            // by_block contains exactly the keys we just collected; the
            // entry MUST be present.
            let map = self
                .translation_map
                .by_block
                .get(&block_id)
                .ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "squash_plan: translation_map missing block_id {block_id} during encode \
                     (BUG: keys vec out of sync with map)"
                    ))
                })?;
            write_u32(w, block_id)?;
            write_u32(w, u32_try_from(map.len(), "translation_map entry vec")?)?;
            for (old_offset, new_offset) in map.iter() {
                write_u32(w, *old_offset)?;
                write_u32(w, *new_offset)?;
            }
        }

        // Rewrite plan
        write_u32(w, u32_try_from(self.rewrite_plan.len(), "rewrite_plan")?)?;
        for entry in &self.rewrite_plan {
            write_u32(w, entry.hot_file_seq)?;
            write_u64(w, entry.file_offset)?;
            w.write_all(&entry.pre_bytes).map_err(Error::IOError)?;
            w.write_all(&entry.post_bytes).map_err(Error::IOError)?;
        }
        Ok(())
    }

    /// Read everything except the trailing body hash.
    fn read_body<R: Read>(r: &mut R) -> Result<Self, Error> {
        // Magic + version
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).map_err(Error::IOError)?;
        if &magic != PLAN_MAGIC {
            return Err(Error::CorruptionError(format!(
                "squash_plan: bad magic {magic:?} (expected {PLAN_MAGIC:?})",
            )));
        }
        let version = read_u32(r)?;
        if version != PLAN_FORMAT_VERSION {
            return Err(Error::CorruptionError(format!(
                "squash_plan: unsupported format_version {version} (this binary supports {PLAN_FORMAT_VERSION})",
            )));
        }

        // Header
        let level_id = read_u32(r)?;
        let min_height = read_u32(r)?;
        let max_height = read_u32(r)?;
        let tip_at_scan_start = read_u32(r)?;
        let cold_blob_offset = read_u64(r)?;
        let cold_blob_length = read_u64(r)?;
        let cold_blob_hash = read_trie_hash(r)?;
        let sidecar_path_bytes = read_varbytes(r)?;
        let sidecar_path = String::from_utf8(sidecar_path_bytes).map_err(|e| {
            Error::CorruptionError(format!("squash_plan: sidecar_path is not valid UTF-8: {e}"))
        })?;
        let sidecar_hash = read_trie_hash(r)?;
        let reads_redirected = read_bool(r)?;
        let root_sidecar_present = read_bool(r)?;
        let root_sidecar_trimmed = read_bool(r)?;
        let orphan_split_offset = read_u32(r)?;
        let published_max_block_id = read_u32(r)?;
        let header = PlanHeader {
            level_id,
            min_height,
            max_height,
            tip_at_scan_start,
            cold_blob_offset,
            cold_blob_length,
            cold_blob_hash,
            sidecar_path,
            sidecar_hash,
            reads_redirected,
            root_sidecar_present,
            root_sidecar_trimmed,
            orphan_split_offset,
            published_max_block_id,
        };

        // In-range blocks
        let n = read_u32(r)? as usize;
        let mut in_range_blocks = Vec::with_capacity(n);
        for _ in 0..n {
            let mut block_hash = [0u8; 32];
            r.read_exact(&mut block_hash).map_err(Error::IOError)?;
            let block_id = read_u32(r)?;
            in_range_blocks.push(InRangeBlock {
                block_hash,
                block_id,
            });
        }

        // Translation map
        let block_count = read_u32(r)? as usize;
        let mut translation_map = TranslationMap::default();
        for _ in 0..block_count {
            let block_id = read_u32(r)?;
            let entry_count = read_u32(r)? as usize;
            let mut map = BTreeMap::new();
            for _ in 0..entry_count {
                let old_offset = read_u32(r)?;
                let new_offset = read_u32(r)?;
                map.insert(old_offset, new_offset);
            }
            // Reject duplicate block_ids — the encoder writes each at
            // most once, so a duplicate signals corruption.
            if translation_map.by_block.contains_key(&block_id) {
                return Err(Error::CorruptionError(format!(
                    "squash_plan: duplicate block_id {block_id} in translation_map",
                )));
            }
            translation_map.by_block.insert(block_id, map);
        }

        // Rewrite plan
        let rcount = read_u32(r)? as usize;
        let mut rewrite_plan = Vec::with_capacity(rcount);
        for _ in 0..rcount {
            let hot_file_seq = read_u32(r)?;
            let file_offset = read_u64(r)?;
            let mut pre_bytes = [0u8; 4];
            let mut post_bytes = [0u8; 4];
            r.read_exact(&mut pre_bytes).map_err(Error::IOError)?;
            r.read_exact(&mut post_bytes).map_err(Error::IOError)?;
            rewrite_plan.push(RewriteEntry {
                hot_file_seq,
                file_offset,
                pre_bytes,
                post_bytes,
            });
        }

        Ok(Self {
            header,
            in_range_blocks,
            translation_map,
            rewrite_plan,
        })
    }

    /// Compute the trailing body hash that `encode` would produce. Used
    /// in tests and during partial encode validation.
    #[cfg(test)]
    pub fn compute_body_hash(&self) -> Result<TrieHash, Error> {
        let mut body = Vec::new();
        self.write_body(&mut body)?;
        Ok(sha512_256_of(&body))
    }
}

// ---------------------------------------------------------------------------
// File-level helpers
// ---------------------------------------------------------------------------

/// Write `plan` to `path` atomically: serialize to a tempfile in the same
/// directory, fsync the file, rename into place, then fsync the parent
/// directory. After this returns successfully, the plan file's directory
/// entry is durable across a crash — that's what makes the plan file a
/// safe recovery anchor for Phase B's promotion swap.
///
/// The rename is atomic on POSIX filesystems and guarantees that a crash
/// either leaves the old file (or nothing) — never a partial new file
/// under the final name. The directory fsync is required to make the
/// post-rename directory entry survive a crash; without it, ext4 (and
/// other ordered-data filesystems) can leave file content durable while
/// the parent directory still references the pre-rename state.
pub fn write_plan_file_atomic(path: &Path, plan: &SquashPlan) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| {
        Error::CorruptionError(format!(
            "squash_plan: write target {path:?} has no parent directory"
        ))
    })?;

    // Tempfile name: <basename>.tmp. Same directory ensures the rename
    // is atomic (cross-filesystem renames degrade to copy+remove).
    let basename = path.file_name().ok_or_else(|| {
        Error::CorruptionError(format!(
            "squash_plan: write target {path:?} has no file name component"
        ))
    })?;
    let mut tmp_name = basename.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(&tmp_name);

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(Error::IOError)?;
        plan.encode(&mut tmp_file)?;
        tmp_file.sync_all().map_err(Error::IOError)?;
    }

    fs::rename(&tmp_path, path).map_err(Error::IOError)?;

    // Fsync the parent directory so the rename's directory entry is
    // durable. POSIX permits opening a directory read-only specifically
    // for fsync; on macOS/Linux this is the standard pattern.
    //
    // **Soft-fail policy**: only "this filesystem doesn't support
    // directory fsync" errors (`Unsupported` / `EINVAL` / `ENOTSUP` /
    // `EOPNOTSUPP`) are downgraded to a warning. Other failures (EIO,
    // EBADF, ENOENT, etc.) fail the publish hard — they signal real
    // filesystem corruption or a races we don't want to silently
    // ignore, and propagating the error lets the caller treat the plan
    // as not-yet-durable instead of falsely committed.
    fsync_directory(parent)?;
    Ok(())
}

/// Fsync `parent` so a preceding `rename` into it is durable. Soft-
/// fails (warn + return Ok) on filesystems that don't support directory
/// fsync (`Unsupported` / `EINVAL` / `ENOTSUP` / `EOPNOTSUPP`); fails
/// hard on every other error.
fn fsync_directory(parent: &Path) -> Result<(), Error> {
    let dir = match File::open(parent) {
        Ok(d) => d,
        Err(e) if is_dir_fsync_unsupported(&e) => {
            warn!(
                "squash_plan: parent directory {parent:?} cannot be opened for fsync; \
                 filesystem appears not to support directory durability ({e}). The plan \
                 file content is durable; the directory entry may not survive an \
                 immediate crash on this filesystem."
            );
            return Ok(());
        }
        Err(e) => return Err(Error::IOError(e)),
    };
    match dir.sync_all() {
        Ok(()) => Ok(()),
        Err(e) if is_dir_fsync_unsupported(&e) => {
            warn!(
                "squash_plan: parent directory {parent:?} fsync unsupported ({e}). \
                 The plan file content is durable; the directory entry may not survive \
                 an immediate crash on this filesystem."
            );
            Ok(())
        }
        Err(e) => Err(Error::IOError(e)),
    }
}

/// Whether the given I/O error is a "directory fsync isn't supported by
/// this filesystem" signal that's safe to downgrade to a warning. Any
/// other error (EIO, EBADF, ENOENT, etc.) should fail the publish.
///
/// Covers:
/// - `ErrorKind::Unsupported` — Rust's modern signal (1.53+); set by
///   some platforms when the operation is structurally not supported.
/// - `EINVAL` (22) — what Linux returns for `fsync` on a directory
///   opened with the wrong flags on some filesystems (e.g. tmpfs,
///   FAT-derived).
/// - `ENOTSUP` (95 on Linux, 45 on macOS) and `EOPNOTSUPP` (95 on
///   Linux, 102 on macOS) — what NFS / FUSE / other network/userspace
///   filesystems return when directory fsync isn't implemented.
fn is_dir_fsync_unsupported(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    let Some(errno) = e.raw_os_error() else {
        return false;
    };
    // EINVAL on every Unix we care about.
    if errno == 22 {
        return true;
    }
    // ENOTSUP / EOPNOTSUPP — platform-specific values, all hardcoded
    // to avoid pulling in `libc`.
    #[cfg(target_os = "linux")]
    {
        // Linux: ENOTSUP == EOPNOTSUPP == 95.
        errno == 95
    }
    #[cfg(target_os = "macos")]
    {
        // macOS: ENOTSUP = 45, EOPNOTSUPP = 102.
        errno == 45 || errno == 102
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Read and validate a plan file. Combines I/O with body-hash validation
/// so the recovery state machine doesn't have to re-implement either.
pub fn read_plan_file(path: &Path) -> Result<SquashPlan, Error> {
    let mut f = File::open(path).map_err(Error::IOError)?;
    let len = f.seek(SeekFrom::End(0)).map_err(Error::IOError)?;
    f.seek(SeekFrom::Start(0)).map_err(Error::IOError)?;
    if len > MAX_PLAN_FILE_SIZE {
        return Err(Error::CorruptionError(format!(
            "squash_plan: plan file at {path:?} is {len} bytes, refusing to load \
             (limit is {MAX_PLAN_FILE_SIZE})",
        )));
    }
    SquashPlan::decode(&mut f)
}

/// Hard upper bound on a plan file's size (1 GiB). Plans should fit in
/// tens of MB even for large squash ranges; this guard exists to catch a
/// corrupt length field at the front of the file before we allocate
/// gigabytes of memory.
const MAX_PLAN_FILE_SIZE: u64 = 1u64 << 30;

/// Discover plan files for the MARF at `db_path`. Returns the sorted
/// list of `(level_id, path)` pairs found in the parent directory.
///
/// Files matching the `<db_basename>.squash_pending.{seq}.plan` pattern
/// are returned; non-matching siblings are ignored. Tempfiles
/// (`.plan.tmp`) are also ignored — they belong to in-flight writes
/// that didn't complete (the atomic-rename writer hadn't issued the
/// rename yet, or the writer crashed before fsync). A tempfile is not
/// a recovery anchor; drop it on the floor.
pub fn discover_pending_plans(db_path: &str) -> Result<Vec<(u32, PathBuf)>, Error> {
    let db_path = Path::new(db_path);
    let parent = db_path.parent().map(PathBuf::from).unwrap_or_else(|| {
        // Bare basename → assume current directory.
        PathBuf::from(".")
    });
    let stem = db_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash_plan: cannot derive basename from db_path {db_path:?}",
            ))
        })?;
    let prefix = format!("{stem}{PLAN_FILE_PREFIX}");
    let suffix = PLAN_FILE_SUFFIX;

    let mut found = Vec::new();
    if !parent.exists() {
        return Ok(found);
    }
    for entry in fs::read_dir(&parent).map_err(Error::IOError)? {
        let entry = entry.map_err(Error::IOError)?;
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(level_str) = rest.strip_suffix(suffix) else {
            continue;
        };
        let Ok(level_id) = level_str.parse::<u32>() else {
            continue;
        };
        found.push((level_id, entry.path()));
    }
    found.sort_by_key(|(id, _)| *id);
    Ok(found)
}

// ---------------------------------------------------------------------------
// Hashing helper
// ---------------------------------------------------------------------------

/// Hash `bytes` with the codebase's standard MARF hasher (Sha512_256).
/// Public so the recovery state machine can hash cold-blob regions and
/// sidecar files with the same primitive.
pub fn sha512_256_of(bytes: &[u8]) -> TrieHash {
    let mut hasher = Sha512_256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    TrieHash(arr)
}

// ---------------------------------------------------------------------------
// Small typed I/O helpers (big-endian for portability)
// ---------------------------------------------------------------------------

fn write_u8<W: Write>(w: &mut W, v: u8) -> Result<(), Error> {
    w.write_all(&[v]).map_err(Error::IOError)
}

fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), Error> {
    w.write_all(&v.to_be_bytes()).map_err(Error::IOError)
}

fn write_u64<W: Write>(w: &mut W, v: u64) -> Result<(), Error> {
    w.write_all(&v.to_be_bytes()).map_err(Error::IOError)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, Error> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).map_err(Error::IOError)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_bool<R: Read>(r: &mut R) -> Result<bool, Error> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).map_err(Error::IOError)?;
    match buf[0] {
        0 => Ok(false),
        1 => Ok(true),
        b => Err(Error::CorruptionError(format!(
            "squash_plan: bool byte must be 0 or 1, got {b}",
        ))),
    }
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, Error> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf).map_err(Error::IOError)?;
    Ok(u64::from_be_bytes(buf))
}

fn read_trie_hash<R: Read>(r: &mut R) -> Result<TrieHash, Error> {
    let mut buf = [0u8; TRIEHASH_ENCODED_SIZE];
    r.read_exact(&mut buf).map_err(Error::IOError)?;
    Ok(TrieHash(buf))
}

fn write_varbytes<W: Write>(w: &mut W, bytes: &[u8]) -> Result<(), Error> {
    let len = u32_try_from(bytes.len(), "varbytes")?;
    write_u32(w, len)?;
    w.write_all(bytes).map_err(Error::IOError)
}

fn read_varbytes<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
    let len = read_u32(r)? as usize;
    // Cap any single varbytes field at 64 KiB. Sidecar paths and the
    // like are far smaller; a multi-MB length here is a corruption
    // signal that should fail before we allocate the buffer.
    const MAX_VAR_BYTES: usize = 64 * 1024;
    if len > MAX_VAR_BYTES {
        return Err(Error::CorruptionError(format!(
            "squash_plan: varbytes length {len} exceeds cap {MAX_VAR_BYTES}",
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(Error::IOError)?;
    Ok(buf)
}

fn u32_try_from(n: usize, what: &str) -> Result<u32, Error> {
    u32::try_from(n)
        .map_err(|_| Error::CorruptionError(format!("squash_plan: {what} count {n} exceeds u32")))
}

#[cfg(test)]
mod tests {
    //! Plan-format unit tests. These cover the on-disk encoding in
    //! isolation; the recovery state machine is tested separately in
    //! `test/squash_recover.rs`.

    use super::*;

    fn make_hash(seed: u8) -> TrieHash {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        TrieHash(b)
    }

    fn make_plan() -> SquashPlan {
        let mut tmap = TranslationMap::default();
        tmap.insert(7, 100, 1_000);
        tmap.insert(7, 200, 2_000);
        tmap.insert(8, 50, 5_500);

        SquashPlan {
            header: PlanHeader {
                level_id: 42,
                min_height: 10,
                max_height: 1010,
                tip_at_scan_start: 1500,
                cold_blob_offset: 0xfeed_face_u64,
                cold_blob_length: 4096,
                cold_blob_hash: make_hash(0x10),
                sidecar_path: "marf.sqlite-blob-0000000000feedface.dat".into(),
                sidecar_hash: make_hash(0x20),
                reads_redirected: true,
                root_sidecar_present: true,
                root_sidecar_trimmed: false,
                orphan_split_offset: 0xc0de,
                published_max_block_id: 1010,
            },
            in_range_blocks: vec![
                InRangeBlock {
                    block_hash: [0xaa; 32],
                    block_id: 7,
                },
                InRangeBlock {
                    block_hash: [0xbb; 32],
                    block_id: 8,
                },
            ],
            translation_map: tmap,
            rewrite_plan: vec![
                RewriteEntry {
                    hot_file_seq: 1,
                    file_offset: 0x1234,
                    pre_bytes: [0x00, 0x00, 0x10, 0x00],
                    post_bytes: [0x00, 0x00, 0xfa, 0x00],
                },
                RewriteEntry {
                    hot_file_seq: 2,
                    file_offset: 0x5678,
                    pre_bytes: [0xff, 0xff, 0xff, 0x00],
                    post_bytes: [0xab, 0xcd, 0xef, 0x01],
                },
            ],
        }
    }

    #[test]
    fn round_trip_via_encode_decode_yields_equal_plan() {
        let plan = make_plan();
        let mut buf = Vec::new();
        plan.encode(&mut buf).unwrap();
        let decoded = SquashPlan::decode(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(plan, decoded);
    }

    #[test]
    fn round_trip_via_write_plan_file_atomic_yields_equal_plan() {
        let dir = std::env::temp_dir().join("squash_plan_round_trip_via_write");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("marf.sqlite.squash_pending.00000007.plan");
        let plan = make_plan();
        write_plan_file_atomic(&path, &plan).unwrap();
        let decoded = read_plan_file(&path).unwrap();
        assert_eq!(plan, decoded);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let plan = make_plan();
        let mut buf = Vec::new();
        plan.encode(&mut buf).unwrap();
        // Flip a magic byte.
        buf[0] = b'X';
        let err =
            SquashPlan::decode(&mut std::io::Cursor::new(&buf)).expect_err("must reject bad magic");
        // Will fail body-hash check (since flipping the magic invalidates
        // the body hash too); the relevant signal is "won't decode."
        let msg = format!("{err:?}");
        assert!(
            msg.contains("body hash mismatch") || msg.contains("bad magic"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn decode_rejects_unknown_format_version() {
        let plan = make_plan();
        let mut buf = Vec::new();
        plan.encode(&mut buf).unwrap();
        // Format version sits at bytes 4..=7. Bump to a future value.
        let body_len = buf.len() - 32;
        let body = &mut buf[..body_len];
        body[4..8].copy_from_slice(&999u32.to_be_bytes());
        // Recompute trailing hash so the body-hash check passes and we
        // hit the version check specifically.
        let new_hash = sha512_256_of(&buf[..body_len]);
        buf[body_len..].copy_from_slice(new_hash.as_bytes());

        let err = SquashPlan::decode(&mut std::io::Cursor::new(&buf))
            .expect_err("must reject unknown version");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("format_version 999"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn decode_rejects_torn_body() {
        let plan = make_plan();
        let mut buf = Vec::new();
        plan.encode(&mut buf).unwrap();
        // Flip a byte deep in the body (somewhere past the magic + version).
        let mid = buf.len() / 2;
        buf[mid] ^= 0xff;
        let err =
            SquashPlan::decode(&mut std::io::Cursor::new(&buf)).expect_err("must reject torn body");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("body hash mismatch"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn decode_rejects_truncated_file() {
        let plan = make_plan();
        let mut buf = Vec::new();
        plan.encode(&mut buf).unwrap();
        // Lose the last 16 bytes (clips into the trailer hash).
        buf.truncate(buf.len() - 16);
        let err = SquashPlan::decode(&mut std::io::Cursor::new(&buf))
            .expect_err("must reject truncated file");
        let msg = format!("{err:?}");
        // Either body-hash mismatch or short-read are acceptable; both
        // signal "don't trust this file."
        assert!(
            msg.contains("body hash mismatch") || msg.contains("squash_plan"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn discover_pending_plans_returns_sorted_level_ids() {
        let dir = std::env::temp_dir().join("squash_plan_discover_sorted");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stem = dir.join("marf.sqlite");
        let stem_str = stem.to_str().unwrap();

        // Create three plan files (out of order) plus one unrelated file
        // that must NOT be picked up.
        for level in [9u32, 1u32, 5u32] {
            let p = plan_file_path(stem_str, level);
            std::fs::write(&p, b"placeholder").unwrap();
        }
        std::fs::write(
            dir.join("marf.sqlite.squash_pending.99999999.plan.tmp"),
            b"x",
        )
        .unwrap();
        std::fs::write(dir.join("marf.sqlite.unrelated"), b"x").unwrap();

        let found = discover_pending_plans(stem_str).unwrap();
        let levels: Vec<u32> = found.iter().map(|(l, _)| *l).collect();
        assert_eq!(levels, vec![1, 5, 9]);
    }

    #[test]
    fn translation_map_lookup_round_trips() {
        let mut m = TranslationMap::default();
        m.insert(1, 100, 200);
        m.insert(1, 300, 400);
        m.insert(2, 50, 75);
        assert_eq!(m.lookup(1, 100), Some(200));
        assert_eq!(m.lookup(1, 300), Some(400));
        assert_eq!(m.lookup(2, 50), Some(75));
        assert_eq!(m.lookup(2, 100), None);
        assert_eq!(m.lookup(99, 0), None);
        assert_eq!(m.entry_count(), 3);
    }

    #[test]
    fn body_hash_is_stable_across_encodes() {
        // Determinism: encoding the same plan twice produces identical
        // bytes (and thus identical trailing hash). Specifically tests
        // that the HashMap-backed translation map's iteration is
        // sorted-stable.
        let plan = make_plan();
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        plan.encode(&mut buf1).unwrap();
        plan.encode(&mut buf2).unwrap();
        assert_eq!(buf1, buf2);
    }
}
