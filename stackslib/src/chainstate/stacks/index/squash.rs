// Squash pipeline code uses bounded-index loops (`0..node_count`) over
// parallel arrays that are always the same length. The indices are
// correct by construction; `.get()` would add noise without safety.
#![allow(clippy::indexing_slicing)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, TrieLeafSquashed, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::storage::{
    build_squash_meta_from_sql, SquashMeta, TrieHashCalculationMode,
};
use crate::chainstate::stacks::index::{
    bits, trie_sql, BlockMap, Error, MARFValue, MarfTrieId, TrieReadStorage,
};
use crate::types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE};

/// Magic bytes identifying a squash trailer at the end of a blob.
pub const SQUASH_MAGIC: [u8; 4] = *b"SQSH";

/// Current squash trailer format version.
pub const SQUASH_VERSION: u8 = 1;

/// Size of the trailer footer (trailer_offset: u64 + magic: [u8; 4]).
pub const SQUASH_FOOTER_SIZE: usize = 12;

/// Size of the SquashInfo fixed header.
/// magic(4) + version(1) + mode(1) + level_id(4) + min_height(4) + max_height(4) +
/// archival_root(32) + squash_root(32) = 82 bytes.
pub const SQUASH_INFO_SIZE: usize = 82;

/// Maximum size of the node-addressable region (header + nodes) within a
/// single squash level's blob. `TriePtr.ptr` offsets must fit in `u32`, so
/// this region must stay below `u32::MAX`. The trailer is appended after
/// this region and is not subject to this cap.
pub const MAX_SQUASH_NODE_REGION_SIZE: u64 = 3_500_000_000;

/// Maximum number of blocks for the first L0 squash range before a stub
/// level is created instead. This is a conservative heuristic — the hard
/// overflow guard (`checked_offset_add`) catches ranges that actually
/// exceed the node-region cap regardless of block count.
pub const STUB_THRESHOLD: u64 = 50_000;

/// Default per-height root snapshot retention, in levels.
///
/// After each new squash, sidecar files for levels older than
/// `current_squash_tip_level - MARF_ROOT_SNAPSHOT_RETENTION_LEVELS` are
/// `unlink`ed and their `marf_squash_levels.root_sidecar_trimmed` flag is
/// set to 1. Fork-extension off a parent in a trimmed level then surfaces
/// [`Error::SnapshotTrimmed`] — an *expected* policy outcome that higher
/// layers should convert into a chainstate-level rejection (don't treat
/// it as data corruption).
///
/// 100 levels at a 1000-block cadence covers ~100k blocks of
/// fork-extension capability — generous safety margin past the maximum
/// realistic BTC reorg depth. Storage cost: ~100 × ~2.5 MB per sidecar
/// ≈ ~250 MB of disk for the live snapshot window. Set via the
/// `root_snapshot_retention_levels` knob on [`MARFOpenOpts`] (TBD) or
/// edit this constant for now.
pub const MARF_ROOT_SNAPSHOT_RETENTION_LEVELS: u32 = 100;

/// Checked offset accumulation for squash blob node regions. Returns the
/// new offset after adding `size`, or an error if the result exceeds
/// `MAX_SQUASH_NODE_REGION_SIZE` or overflows `u32`.
pub fn checked_offset_add(current: u32, size: u32) -> Result<u32, Error> {
    let next = current.checked_add(size).ok_or_else(|| {
        Error::CorruptionError(format!(
            "Squash blob offset overflow: {current} + {size} exceeds u32::MAX"
        ))
    })?;
    if (next as u64) > MAX_SQUASH_NODE_REGION_SIZE {
        return Err(Error::CorruptionError(format!(
            "Squash node region {next} exceeds MAX_SQUASH_NODE_REGION_SIZE \
             {MAX_SQUASH_NODE_REGION_SIZE}"
        )));
    }
    Ok(next)
}

/// Squash mode controls whether squash levels preserve per-key value
/// history for historical reads, or store only tip-era values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SquashMode {
    /// Leaves are plain `TrieLeaf` nodes with the current value.
    /// Historical RPC reads within the squash range return tip-era
    /// values. Default. No new node types in the blob.
    TipOnly = 0,
    /// Leaves with multiple value transitions are `TrieLeafSquashed`
    /// nodes carrying the complete value-transition history scoped to
    /// the level's block range. Historical RPC reads return correct
    /// point-in-time values (with `proof=0` only).
    FullHistory = 1,
}

impl SquashMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::TipOnly),
            1 => Some(Self::FullHistory),
            _ => None,
        }
    }
}

/// Fixed-size metadata at the start of the squash trailer.
#[derive(Debug, Clone)]
pub struct SquashInfo {
    pub mode: SquashMode,
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub archival_root: TrieHash,
    pub squash_root: TrieHash,
}

impl SquashInfo {
    /// Number of heights in this level's range (inclusive).
    pub fn height_count(&self) -> usize {
        (self.max_height - self.min_height + 1) as usize
    }
}

/// Per-level squash trailer appended after trie nodes in a squash blob.
///
/// Provides O(1) height-indexed lookups for root hashes and block hashes,
/// and O(log N) block-hash-to-height lookups via binary search.
#[derive(Debug, Clone)]
pub struct SquashTrailer {
    pub info: SquashInfo,
    /// Root hashes indexed by `height - min_height`.
    pub root_hashes: Vec<TrieHash>,
    /// Block hashes indexed by `height - min_height`.
    pub block_hashes: Vec<[u8; 32]>,
    /// (block_hash, height, block_id) tuples sorted by block_hash for binary search.
    /// The `block_id` is the `marf_data` primary key at squash time, enabling
    /// trailer-based block_id resolution without SQL lookups at read time.
    pub sorted_block_entries: Vec<([u8; 32], u32, u32)>,
}

impl SquashTrailer {
    /// Construct an empty trailer for stub levels (no blob, no block entries).
    pub fn empty() -> Self {
        Self {
            info: SquashInfo {
                mode: SquashMode::TipOnly,
                level_id: 0,
                min_height: 0,
                max_height: 0,
                archival_root: TrieHash::EMPTY,
                squash_root: TrieHash::EMPTY,
            },
            root_hashes: Vec::new(),
            block_hashes: Vec::new(),
            sorted_block_entries: Vec::new(),
        }
    }

    /// Returns true if this trailer's range contains the given height.
    pub fn contains_height(&self, h: u32) -> bool {
        h >= self.info.min_height && h <= self.info.max_height
    }

    /// O(1) root hash lookup by absolute height.
    pub fn root_hash_at(&self, h: u32) -> Option<&TrieHash> {
        if !self.contains_height(h) {
            return None;
        }
        let idx = (h - self.info.min_height) as usize;
        self.root_hashes.get(idx)
    }

    /// O(1) block hash lookup by absolute height.
    pub fn block_hash_at(&self, h: u32) -> Option<&[u8; 32]> {
        if !self.contains_height(h) {
            return None;
        }
        let idx = (h - self.info.min_height) as usize;
        self.block_hashes.get(idx)
    }

    /// O(log N) height lookup by block hash.
    pub fn height_of_block(&self, bhh: &[u8; 32]) -> Option<u32> {
        self.sorted_block_entries
            .binary_search_by_key(bhh, |(hash, _, _)| *hash)
            .ok()
            .map(|idx| self.sorted_block_entries[idx].1)
    }

    /// Serialize the trailer to a writer. Returns the number of bytes written.
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<u64, Error> {
        let mut written: u64 = 0;

        // --- SquashInfo ---
        w.write_all(&SQUASH_MAGIC)?;
        w.write_all(&[SQUASH_VERSION])?;
        w.write_all(&[self.info.mode as u8])?;
        w.write_all(&self.info.level_id.to_be_bytes())?;
        w.write_all(&self.info.min_height.to_be_bytes())?;
        w.write_all(&self.info.max_height.to_be_bytes())?;
        w.write_all(&self.info.archival_root.0)?;
        w.write_all(&self.info.squash_root.0)?;
        written += SQUASH_INFO_SIZE as u64;

        // --- Height→RootHash (dense) ---
        let count = self.root_hashes.len() as u32;
        w.write_all(&count.to_be_bytes())?;
        written += 4;
        for hash in &self.root_hashes {
            w.write_all(&hash.0)?;
            written += 32;
        }

        // --- Height→BlockHash (dense) ---
        let count = self.block_hashes.len() as u32;
        w.write_all(&count.to_be_bytes())?;
        written += 4;
        for bhh in &self.block_hashes {
            w.write_all(bhh)?;
            written += 32;
        }

        // --- BlockHash→Height+BlockId (sorted) ---
        let count = self.sorted_block_entries.len() as u32;
        w.write_all(&count.to_be_bytes())?;
        written += 4;
        for (bhh, height, block_id) in &self.sorted_block_entries {
            w.write_all(bhh)?;
            w.write_all(&height.to_be_bytes())?;
            w.write_all(&block_id.to_be_bytes())?;
            written += 40;
        }

        // Per-height root node bodies are NOT in the trailer anymore — they
        // live in a per-level sidecar file under `squash_sidecars/`. See
        // [`crate::chainstate::stacks::index::sidecar`].

        // --- Footer ---
        // trailer_offset is filled in by the caller (who knows the absolute
        // offset within the blob file). We write a placeholder here and
        // return the total size so the caller can compute it.
        // Actually, the caller should write the footer separately after
        // knowing the trailer start offset. Let's just return bytes written
        // for the trailer body (excluding footer).

        Ok(written)
    }

    /// Write the 12-byte footer at the current position.
    ///
    /// `trailer_offset` is the byte offset of the trailer start relative to the blob start.
    pub fn write_footer<W: Write>(w: &mut W, trailer_offset: u64) -> Result<(), Error> {
        w.write_all(&trailer_offset.to_be_bytes())?;
        w.write_all(&SQUASH_MAGIC)?;
        Ok(())
    }

    /// Read the 12-byte footer from the last 12 bytes of a blob.
    ///
    /// Returns `Some(trailer_offset)` if the magic matches, `None` otherwise.
    pub fn read_footer(blob_bytes: &[u8]) -> Option<u64> {
        if blob_bytes.len() < SQUASH_FOOTER_SIZE {
            return None;
        }
        let footer = &blob_bytes[blob_bytes.len() - SQUASH_FOOTER_SIZE..];
        if footer[8..12] != SQUASH_MAGIC {
            return None;
        }
        let offset = u64::from_be_bytes(footer[0..8].try_into().ok()?);
        Some(offset)
    }

    /// Deserialize a trailer from a byte slice. The slice should start at
    /// the trailer (after all trie nodes).
    ///
    /// `trailer_file_offset` is the absolute file offset where `bytes`
    /// begins in the blob file. It anchors [`Self::root_node_locations`]:
    /// the per-height root node bodies are NOT copied into memory by this
    /// function — only their `(absolute_file_offset, length)` is recorded,
    /// so consumers can fetch each body lazily via
    /// [`TrieFile::read_blob_range`]. For unit-test scenarios that operate
    /// on an isolated buffer, pass `0`; the recorded offsets will then be
    /// relative to `bytes`.
    pub fn read_from(bytes: &[u8], trailer_file_offset: u64) -> Result<Self, Error> {
        if bytes.len() < SQUASH_INFO_SIZE {
            return Err(Error::CorruptionError(
                "Squash trailer too short for SquashInfo".into(),
            ));
        }

        // --- SquashInfo ---
        let magic = &bytes[0..4];
        if magic != SQUASH_MAGIC {
            return Err(Error::CorruptionError(format!(
                "Bad squash trailer magic: {:?}",
                magic
            )));
        }
        let version = bytes[4];
        if version != SQUASH_VERSION {
            return Err(Error::CorruptionError(format!(
                "Unsupported squash trailer version: {version}"
            )));
        }
        let mode = SquashMode::from_u8(bytes[5])
            .ok_or_else(|| Error::CorruptionError(format!("Bad squash mode: {}", bytes[5])))?;
        let level_id =
            u32::from_be_bytes(bytes[6..10].try_into().map_err(|_| {
                Error::CorruptionError("Squash trailer: bad level_id slice".into())
            })?);
        let min_height =
            u32::from_be_bytes(bytes[10..14].try_into().map_err(|_| {
                Error::CorruptionError("Squash trailer: bad min_height slice".into())
            })?);
        let max_height =
            u32::from_be_bytes(bytes[14..18].try_into().map_err(|_| {
                Error::CorruptionError("Squash trailer: bad max_height slice".into())
            })?);

        let mut archival_root = TrieHash([0u8; 32]);
        archival_root.0.copy_from_slice(&bytes[18..50]);
        let mut squash_root = TrieHash([0u8; 32]);
        squash_root.0.copy_from_slice(&bytes[50..82]);

        let info = SquashInfo {
            mode,
            level_id,
            min_height,
            max_height,
            archival_root,
            squash_root,
        };

        let mut pos = SQUASH_INFO_SIZE;

        // --- Height→RootHash ---
        let root_count = read_u32_be(bytes, &mut pos)?;
        let mut root_hashes = Vec::with_capacity(root_count as usize);
        for _ in 0..root_count {
            let mut hash = TrieHash([0u8; 32]);
            let end = pos + 32;
            hash.0.copy_from_slice(
                bytes
                    .get(pos..end)
                    .ok_or_else(|| Error::CorruptionError("Truncated root hash table".into()))?,
            );
            root_hashes.push(hash);
            pos = end;
        }

        // --- Height→BlockHash ---
        let block_count = read_u32_be(bytes, &mut pos)?;
        let mut block_hashes = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            let end = pos + 32;
            let mut bhh = [0u8; 32];
            bhh.copy_from_slice(
                bytes
                    .get(pos..end)
                    .ok_or_else(|| Error::CorruptionError("Truncated block hash table".into()))?,
            );
            block_hashes.push(bhh);
            pos = end;
        }

        // --- BlockHash→Height+BlockId (sorted) ---
        let sorted_count = read_u32_be(bytes, &mut pos)?;
        let mut sorted_block_entries = Vec::with_capacity(sorted_count as usize);
        for _ in 0..sorted_count {
            let end = pos + 40;
            let entry = bytes
                .get(pos..end)
                .ok_or_else(|| Error::CorruptionError("Truncated sorted block table".into()))?;
            let mut bhh = [0u8; 32];
            bhh.copy_from_slice(&entry[0..32]);
            let height = u32::from_be_bytes(entry[32..36].try_into().map_err(|_| {
                Error::CorruptionError(
                    "Squash trailer: bad height slice in sorted block entry".into(),
                )
            })?);
            let block_id = u32::from_be_bytes(entry[36..40].try_into().map_err(|_| {
                Error::CorruptionError(
                    "Squash trailer: bad block_id slice in sorted block entry".into(),
                )
            })?);
            sorted_block_entries.push((bhh, height, block_id));
            pos = end;
        }

        // Per-height root node bodies are NOT in the trailer anymore — they
        // live in a per-level sidecar file under `squash_sidecars/`. See
        // [`crate::chainstate::stacks::index::sidecar`].
        let _ = trailer_file_offset; // anchor argument retained for future kinds

        Ok(Self {
            info,
            root_hashes,
            block_hashes,
            sorted_block_entries,
        })
    }
}

/// Read a big-endian u32 from `bytes` at `*pos`, advancing `*pos` by 4.
fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, Error> {
    let end = *pos + 4;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| Error::CorruptionError("Truncated u32 in squash trailer".into()))?;
    *pos = end;
    Ok(u32::from_be_bytes(slice.try_into().map_err(|_| {
        Error::CorruptionError("Squash trailer: u32 slice is not 4 bytes".into())
    })?))
}

/// Row data for the `marf_squash_levels` SQL table.
#[derive(Debug, Clone)]
pub struct SquashLevelRow {
    pub level_id: u32,
    pub min_height: u32,
    pub max_height: u32,
    pub blob_offset: u64,
    pub blob_length: u64,
    /// When true, `marf_data` rows for blocks in this level point to the squash blob (originals
    /// were destroyed by reclaim or never existed). When false, reads go through the original
    /// per-block blobs.
    pub reads_redirected: bool,
    /// Set to true once a per-height root node sidecar file has been
    /// atomically published for this level. Used by
    /// [`MARF::root_copy`](crate::chainstate::stacks::index::marf::MARF::root_copy)
    /// to know whether the canonical sidecar path is expected to exist.
    pub root_sidecar_present: bool,
    /// Reserved for the trim policy that lands in iteration 2. v1 always
    /// `false`; iteration 2 will set `true` after `unlink`-ing the sidecar
    /// for a level that has aged past the retention threshold.
    pub root_sidecar_trimmed: bool,
}

// ---------------------------------------------------------------------------
// NodeStore — disk-backed temporary storage for squash DFS
// ---------------------------------------------------------------------------

/// Disk-backed temporary storage for nodes collected during the squash DFS.
///
/// Full `TrieNodeType` objects are serialized to a temp file; only ~80 bytes per node (offset,
/// length, hash, block_id) stays in RAM.
pub struct NodeStore {
    /// Temp file writer for serialized nodes.
    writer: BufWriter<File>,
    /// Path to the temp file (for reopening as reader).
    path: PathBuf,
    /// Per-node: (offset_in_tempfile, byte_length).
    file_offsets: Vec<(u64, u32)>,
    /// Per-node hash.
    hashes: Vec<TrieHash>,
    /// Per-node source block_id.
    block_ids: Vec<u32>,
    /// Next write offset.
    next_offset: u64,
}

impl NodeStore {
    /// Create a new `NodeStore` backed by a temp file in `tmp_dir`.
    pub fn new(tmp_dir: &Path) -> Result<Self, Error> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::SystemTime;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let filename = format!("squash-nodes-{pid}-{ts}-{seq}.tmp");
        let path = tmp_dir.join(filename);

        let file_handle = File::create(&path)?;

        Ok(Self {
            writer: BufWriter::new(file_handle),
            path,
            file_offsets: Vec::new(),
            hashes: Vec::new(),
            block_ids: Vec::new(),
            next_offset: 0,
        })
    }

    /// Append a serialized node to the temp file.
    ///
    /// * Records the byte offset, length, hash, and block_id.
    /// * Returns the index of the newly stored node.
    pub fn push(
        &mut self,
        node_bytes: &[u8],
        hash: TrieHash,
        block_id: u32,
    ) -> Result<usize, Error> {
        let offset = self.next_offset;
        let len = node_bytes.len() as u32;
        self.writer.write_all(node_bytes)?;
        self.file_offsets.push((offset, len));
        self.hashes.push(hash);
        self.block_ids.push(block_id);
        self.next_offset += len as u64;
        Ok(self.file_offsets.len() - 1)
    }

    /// Number of nodes stored.
    pub fn len(&self) -> usize {
        self.file_offsets.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.file_offsets.is_empty()
    }

    /// Byte length of the serialized node at `idx`.
    pub fn node_byte_len(&self, idx: usize) -> u32 {
        self.file_offsets[idx].1
    }

    /// Borrow the hash for node at `idx`.
    pub fn hash(&self, idx: usize) -> &TrieHash {
        &self.hashes[idx]
    }

    /// Overwrite the hash for node at `idx`.
    pub fn set_hash(&mut self, idx: usize, hash: TrieHash) {
        self.hashes[idx] = hash;
    }

    /// Block id for the node at `idx`.
    pub fn block_id(&self, idx: usize) -> u32 {
        self.block_ids[idx]
    }

    /// Read back the serialized bytes for node at `idx`.
    ///
    /// Opens a fresh reader from the file path each time so that the writer can remain active.
    pub fn read_node_bytes(&self, idx: usize) -> Result<Vec<u8>, Error> {
        let (offset, len) = self.file_offsets[idx];
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Flush any buffered writes to disk. Must be called before reading data that was written via
    /// `push` or `update`.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush()?;
        Ok(())
    }

    /// Overwrite a node's serialized bytes. The new bytes are appended at the end of the file and
    /// the index entry is updated to point to the new location. The old bytes become dead space
    /// (acceptable for a temp file).
    pub fn update(&mut self, idx: usize, new_bytes: &[u8]) -> Result<(), Error> {
        let offset = self.next_offset;
        let len = new_bytes.len() as u32;
        self.writer.write_all(new_bytes)?;
        self.file_offsets[idx] = (offset, len);
        self.next_offset += len as u64;
        Ok(())
    }

    /// Flush any buffered writes and delete the temp file.
    pub fn finish(self) -> Result<(), Error> {
        // Drop the writer (flushes on drop), then remove the file.
        drop(self.writer);
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SquashStats
// ---------------------------------------------------------------------------

/// Counters collected during a squash pass.
#[derive(Debug, Default)]
pub struct SquashStats {
    pub nodes_collected: u64,
    pub leaves_collected: u64,
    pub leaves_squashed: u64,
    pub blob_bytes: u64,
    pub trailer_bytes: u64,
}

// ---------------------------------------------------------------------------
// FullHistory: history collection
// ---------------------------------------------------------------------------

/// Precomputed `TrieHash` of `OWN_BLOCK_HEIGHT_KEY`. This is a single pathological key written
/// every block with a different value; storing its full history would produce a leaf of unbounded
/// size. Filtered during history collection (see design doc §4.5).
static OWN_BLOCK_HEIGHT_KEY_HASH: std::sync::LazyLock<TrieHash> =
    std::sync::LazyLock::new(|| TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY));

/// Returns `true` if `key_hash` belongs to a MARF-internal key that must be excluded from
/// FullHistory history collection. Currently filters only `OWN_BLOCK_HEIGHT_KEY`.
fn is_marf_internal_key(key_hash: &TrieHash) -> bool {
    *key_hash == *OWN_BLOCK_HEIGHT_KEY_HASH
}

/// Decode an existing serialized leaf, build a `TrieLeafSquashed` carrying the
/// given transitions (sorted descending by height for `value_at_height` binary
/// search), and re-serialize the new node body.
///
/// Hash-free: leaf bodies in the squash blob are stored without the 32-byte
/// hash prefix (squash blobs use `leaf_hashes_omitted`).
///
/// Extracted as a helper so it can be called from both the serial fallback and
/// the parallel `thread::scope` workers in `squash_level_incremental` Step 2.5.
fn build_squashed_leaf_bytes(
    raw: &[u8],
    transitions: &[(u32, MARFValue)],
) -> Result<Vec<u8>, Error> {
    let node_id_byte = *raw.first().ok_or_else(|| {
        Error::CorruptionError("Empty node body during FullHistory leaf replace".into())
    })?;
    let node_id = clear_backptr(node_id_byte) & 0x3f;
    let (existing_node, _) = bits::decode_nodetype_from_slice_at_head(raw, node_id)?;
    let path_slice = existing_node.path_bytes();

    // `transitions` from `collect_history` is ascending by height; `TrieLeafSquashed`
    // wants descending so `value_at_height`'s `partition_point(|h| *h > query)` works.
    let mut entries: Vec<(u32, MARFValue)> = transitions.to_vec();
    entries.reverse();

    let squashed = TrieLeafSquashed::new(path_slice, entries)?;
    let squashed_node = TrieNodeType::LeafSquashed(squashed);
    let mut new_buf = Vec::with_capacity(squashed_node.byte_len() + 1);
    squashed_node.write_bytes(&mut new_buf)?;
    Ok(new_buf)
}

/// Human-readable byte size formatter for squash log lines. Picks GB / MB / KB
/// based on magnitude, with two decimals of precision; falls back to raw bytes
/// for sub-KB values.
fn fmt_bytes(bytes: u64) -> String {
    const KB: u64 = 1 << 10;
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Walk the locally-written subtree of the currently-opened block, invoking `callback` for every
/// leaf written at this block height.
///
/// "Locally-written" means we descend only into non-backpointer children — backpointer children
/// belong to earlier blocks and are skipped. This visits exactly the connected subtree of nodes
/// COW'd into the current block.
///
/// The callback receives the reconstructed full `TrieHash` key path (32 bytes accumulated from the
/// root's path segment + branch bytes
/// + each descendant's path segment) and a clone of the leaf's `MARFValue`.
fn walk_local_leaves<T: MarfTrieId, F>(
    conn: &mut impl TrieReadStorage<T>,
    callback: &mut F,
) -> Result<(), Error>
where
    F: FnMut(&TrieHash, MARFValue),
{
    let root_ptr = conn.root_trieptr();
    let mut scratch = MarfReadState::new();

    // Single mutable path buffer with push/pop. Each stack entry records (ptr, parent_depth): the
    // path_buf length to restore before adding this child's chr byte. The root is special-cased (no
    // chr byte; parent_depth = 0).
    let mut path_buf: Vec<u8> = Vec::with_capacity(32);

    // Stack entries: (TriePtr, parent_depth, is_root)
    let mut stack: Vec<(TriePtr, usize, bool)> = vec![(root_ptr, 0, true)];

    while let Some((ptr, parent_depth, is_root)) = stack.pop() {
        path_buf.truncate(parent_depth);
        if !is_root {
            path_buf.push(ptr.chr());
        }

        let read = conn.read_node_with_state(&ptr, &mut scratch)?;
        let (node, _hash) = read.into_owned_node()?;
        path_buf.extend_from_slice(node.path_bytes());

        if node.is_leaf() {
            if path_buf.len() != 32 {
                return Err(Error::CorruptionError(format!(
                    "walk_local_leaves: accumulated path is {} bytes, expected 32",
                    path_buf.len()
                )));
            }
            let full_key_hash = TrieHash(path_buf[..32].try_into().map_err(|_| {
                Error::CorruptionError(
                    "walk_local_leaves: path_buf to array conversion failed".into(),
                )
            })?);
            let leaf_value = match node {
                TrieNodeType::Leaf(ref leaf) => leaf.data.clone(),
                TrieNodeType::LeafSquashed(ref sq) => sq.tip_value()?.clone(),
                _ => unreachable!("is_leaf() returned true for non-leaf"),
            };
            callback(&full_key_hash, leaf_value);
        } else {
            let depth_after_node = path_buf.len();
            // Push children in reverse for correct DFS order.
            for child_ptr in node.ptrs().iter().rev() {
                if child_ptr.id() == TrieNodeID::Empty as u8 {
                    continue;
                }
                // CRITICAL: skip backpointer children — they belong to earlier blocks.
                if is_backptr(child_ptr.id()) {
                    continue;
                }
                stack.push((*child_ptr, depth_after_node, false));
            }
        }
    }

    Ok(())
}

/// Build the per-key value-transition history map for FullHistory mode.
///
/// For each block height in `min_height..=max_height`, opens the block and walks only its
/// locally-written subtree to find leaves. Builds a map from full `TrieHash` key → `Vec<(height,
/// MARFValue)>` sorted ascending by height.
///
/// Structural-rewrite duplicates (from `promote_leaf_to_node4`) are filtered by comparing each new
/// value against the last entry for that key — if the value is byte-identical, the entry is
/// skipped.
///
/// The `OWN_BLOCK_HEIGHT_KEY` is excluded (see `is_marf_internal_key`).
///
/// `block_hashes` must be a slice of length `max_height - min_height + 1` where `block_hashes[i]`
/// is the block hash at height `min_height + i`.
pub fn collect_history<T: MarfTrieId>(
    marf: &mut MARF<T>,
    block_hashes: &[T],
    min_height: u32,
    max_height: u32,
) -> Result<HashMap<TrieHash, Vec<(u32, MARFValue)>>, Error> {
    let expected_len = (max_height - min_height + 1) as usize;
    if block_hashes.len() != expected_len {
        return Err(Error::CorruptionError(format!(
            "collect_history: block_hashes length {} does not match height range [{min_height}, {max_height}] (expected {expected_len})",
            block_hashes.len()
        )));
    }

    let mut history: HashMap<TrieHash, Vec<(u32, MARFValue)>> = HashMap::new();

    let storage = marf.storage_backend_mut();
    let mut conn = storage.connection();

    collect_history_into(
        &mut conn,
        block_hashes,
        min_height,
        max_height,
        &mut history,
    )?;

    Ok(history)
}

/// Walk a contiguous height range and append discovered (height, value) entries
/// per key into `history`. Within-range dedup of consecutive same values is
/// applied here; cross-range boundary dedup is the caller's responsibility (the
/// parallel `collect_history_parallel` merges per-worker `history` maps and
/// re-applies dedup at the chunk seams).
fn collect_history_into<T: MarfTrieId, R: TrieReadStorage<T>>(
    conn: &mut R,
    block_hashes: &[T],
    min_height: u32,
    max_height: u32,
    history: &mut HashMap<TrieHash, Vec<(u32, MARFValue)>>,
) -> Result<(), Error> {
    for h in min_height..=max_height {
        let block_hash = &block_hashes[(h - min_height) as usize];
        conn.open_block(block_hash)?;

        walk_local_leaves(conn, &mut |full_key_hash, leaf_value| {
            // Skip the pathological internal key.
            if is_marf_internal_key(full_key_hash) {
                return;
            }
            let entries = history.entry(*full_key_hash).or_default();
            // Filter structural rewrites: skip if value unchanged from last entry.
            if entries.last().is_some_and(|(_, v)| *v == leaf_value) {
                return;
            }
            entries.push((h, leaf_value));
        })?;
    }
    Ok(())
}

/// Parallel variant of [`collect_history`]. For ranges large enough to amortize
/// the per-worker setup cost (opening N read-only MARF handles), divides
/// `min_height..=max_height` into N contiguous height chunks, walks each chunk
/// on its own worker thread with its own read-only MARF handle (own SQL
/// connection + mmap), and merges the per-worker partial histories at the end.
///
/// The merge concatenates per-key entries in worker order — workers process
/// disjoint ascending height ranges, so the concatenated entries remain
/// ascending. A boundary dedup pass at chunk seams handles the case where
/// worker N's last value for a key equals worker N+1's first value.
///
/// Falls back to the serial [`collect_history`] when (a) the range is small
/// enough that thread/handle setup would dominate, (b) only one core is
/// available, or (c) `available_parallelism()` returns an error.
fn collect_history_parallel<T: MarfTrieId + Send + Sync>(
    marf: &mut MARF<T>,
    block_hashes: &[T],
    min_height: u32,
    max_height: u32,
) -> Result<HashMap<TrieHash, Vec<(u32, MARFValue)>>, Error> {
    let expected_len = (max_height - min_height + 1) as usize;
    if block_hashes.len() != expected_len {
        return Err(Error::CorruptionError(format!(
            "collect_history_parallel: block_hashes length {} does not match height range [{min_height}, {max_height}] (expected {expected_len})",
            block_hashes.len()
        )));
    }

    const HISTORY_MAX_WORKERS: usize = 8;
    const HISTORY_MIN_HEIGHTS_FOR_PARALLEL: usize = 64;
    let num_heights = expected_len;
    let n_workers = if num_heights < HISTORY_MIN_HEIGHTS_FOR_PARALLEL {
        0
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get().min(HISTORY_MAX_WORKERS))
            .unwrap_or(1)
            .max(1)
            .min(num_heights)
    };

    if n_workers <= 1 {
        return collect_history(marf, block_hashes, min_height, max_height);
    }

    // Pre-open N read-only MARF handles so any open error propagates as a
    // normal Err (vs being a thread-panic inside the scope).
    //
    // Set `bypass_blob_guard` on each handle: workers do many small reads
    // (every node decode in `walk_local_leaves` would otherwise hit the
    // `shared_squash.active_reads` atomic), and the cache-line ping-pong
    // across cores can dominate. Safe here because the caller is inside
    // `squash_level_incremental` for this MARF — no concurrent publish can
    // truncate the blob during the read phases.
    let mut ro_marfs: Vec<MARF<T>> = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let mut ro = marf.reopen_readonly()?;
        ro.storage_backend_mut().data.bypass_blob_guard = true;
        ro_marfs.push(ro);
    }

    // Divide heights into contiguous chunks. The last worker takes the
    // remainder if `num_heights` doesn't divide evenly.
    let heights_per_worker = num_heights.div_ceil(n_workers).max(1);
    let block_hashes_ref: &[T] = block_hashes;

    let partial_histories: Vec<HashMap<TrieHash, Vec<(u32, MARFValue)>>> =
        std::thread::scope(|s| -> Result<Vec<_>, Error> {
            let handles: Vec<_> = ro_marfs
                .iter_mut()
                .enumerate()
                .map(|(idx, ro_marf)| {
                    let chunk_start_h = min_height + (idx * heights_per_worker) as u32;
                    let chunk_end_h_excl =
                        min_height.saturating_add(((idx + 1) * heights_per_worker) as u32);
                    let chunk_end_h = chunk_end_h_excl.min(max_height + 1);
                    // Slice `block_hashes` to just this chunk's height range so
                    // `collect_history_into`'s `(h - chunk_start_h)` indexing is
                    // valid. Without this slice, every worker after the first would
                    // index past offset 0 of the FULL block_hashes slice — which is
                    // wrong (block_hashes[0] is at the OUTER min_height, not the
                    // chunk's start).
                    let chunk_offset_lo = (chunk_start_h.saturating_sub(min_height)) as usize;
                    let chunk_offset_hi = (chunk_end_h.saturating_sub(min_height)) as usize;
                    let chunk_block_hashes = &block_hashes_ref[chunk_offset_lo..chunk_offset_hi];
                    s.spawn(
                        move || -> Result<HashMap<TrieHash, Vec<(u32, MARFValue)>>, Error> {
                            let mut partial: HashMap<TrieHash, Vec<(u32, MARFValue)>> =
                                HashMap::new();
                            if chunk_start_h >= chunk_end_h {
                                return Ok(partial);
                            }
                            let storage = ro_marf.storage_backend_mut();
                            let mut conn = storage.connection();
                            collect_history_into(
                                &mut conn,
                                chunk_block_hashes,
                                chunk_start_h,
                                chunk_end_h - 1,
                                &mut partial,
                            )?;
                            Ok(partial)
                        },
                    )
                })
                .collect();

            // Drain ALL handles before returning (see baseline-lookup loop for
            // the rationale — leaving workers unjoined on early-return risks
            // scope-drop panics that bypass our wrapped error).
            let mut partials = Vec::with_capacity(n_workers);
            let mut first_err: Option<Error> = None;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(partial)) => partials.push(partial),
                    Ok(Err(e)) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                    Err(_panic_payload) => {
                        if first_err.is_none() {
                            first_err = Some(Error::CorruptionError(
                                "collect_history worker thread panicked".into(),
                            ));
                        }
                    }
                }
            }
            if let Some(e) = first_err {
                return Err(e);
            }
            Ok(partials)
        })?;

    // Merge: concatenate per-key entries in worker order. Workers process
    // disjoint ascending height ranges, so the concatenation is globally
    // ascending. Re-apply dedup at chunk seams (worker N's last value for a
    // key may equal worker N+1's first value — e.g. a key whose value is
    // unchanged across the seam).
    let mut history: HashMap<TrieHash, Vec<(u32, MARFValue)>> = HashMap::new();
    for partial in partial_histories {
        for (key, entries) in partial {
            let merged = history.entry(key).or_default();
            for (h, v) in entries {
                if merged.last().is_some_and(|(_, lv)| *lv == v) {
                    continue;
                }
                merged.push((h, v));
            }
        }
    }
    Ok(history)
}

// ---------------------------------------------------------------------------
// Pipeline entry points (scaffolding)
// ---------------------------------------------------------------------------

/// Size of the blob header: block_header_hash (32 bytes) + block_id (4 bytes).
const BLOB_HEADER_SIZE: u64 = (BLOCK_HEADER_HASH_ENCODED_SIZE as u64) + 4;

/// A collected node with its metadata, used during the DFS collection phase.
struct CollectedNode {
    /// Source block ID where this node lives.
    block_id: u32,
    /// Whether this is a leaf node.
    is_leaf: bool,
}

/// Squash a range of blocks into a single level.
///
/// For level 0 (`min_height=0`): collects ALL reachable nodes from the tip and resolves all
/// backpointers to inline.
///
/// For incremental levels (`min_height>0`): collects only nodes modified in the range, storing
/// unmodified subtrees as cross-level backpointers and modified internal nodes as `TrieNodePatch`
/// diffs.
pub fn squash_level<T: MarfTrieId>(
    src_path: &str,
    dst_path: &str,
    mode: SquashMode,
    min_height: u32,
    max_height: u32,
) -> Result<SquashStats, Error> {
    if min_height > 0 {
        return Err(Error::NotSupportedError(
            "Use squash_level_incremental() for incremental squash (min_height > 0)".into(),
        ));
    }

    let mut stats = SquashStats::default();

    // ---------------------------------------------------------------
    // Step 1: Open the source MARF and find the tip block
    // ---------------------------------------------------------------
    let open_opts = MARFOpenOpts {
        hash_calculation_mode: TrieHashCalculationMode::Immediate,
        cache_strategy: "noop".to_string(),
        external_blobs: true,
        force_db_migrate: false,
        compress: false,
        mmap: false,
        squash_mode: SquashMode::TipOnly,
    };

    let mut src_marf = MARF::<T>::from_path(src_path, open_opts.clone())?;

    // Find the tip block hash at max_height. We need to know some block that exists so we can look
    // up other blocks relative to it.
    //
    // First, find the most recent known block by trying to open each height from max_height down.
    let tip_block = find_tip_block(&mut src_marf, max_height)?;

    // ---------------------------------------------------------------
    // Step 2: Collect per-height metadata (block hashes, root hashes, block ids)
    // ---------------------------------------------------------------
    let mut root_hashes: Vec<TrieHash> = Vec::with_capacity((max_height + 1) as usize);
    let mut block_hashes_raw: Vec<[u8; 32]> = Vec::with_capacity((max_height + 1) as usize);
    let mut block_ids_per_height: Vec<u32> = Vec::with_capacity((max_height + 1) as usize);

    for h in 0..=max_height {
        let block_hash_at_h = src_marf
            .get_block_at_height(h, &tip_block)?
            .ok_or_else(|| Error::CorruptionError(format!("No block hash found at height {h}")))?;

        let root_hash = src_marf.get_root_hash_at(&block_hash_at_h)?;
        let block_id = trie_sql::get_block_identifier(src_marf.sqlite_conn(), &block_hash_at_h)?;

        let mut bhh_bytes = [0u8; 32];
        bhh_bytes.copy_from_slice(block_hash_at_h.as_bytes());
        block_hashes_raw.push(bhh_bytes);
        root_hashes.push(root_hash);
        block_ids_per_height.push(block_id);
    }

    // ---------------------------------------------------------------
    // Step 3: DFS collect all reachable nodes from the tip trie
    // ---------------------------------------------------------------
    let tmp_dir = Path::new(dst_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut node_store = NodeStore::new(tmp_dir)?;

    // Map from (source_block_id, source_ptr_offset) -> index in node_store
    let mut ptr_to_idx: HashMap<(u32, u32), usize> = HashMap::new();
    // Collected node metadata
    let mut collected: Vec<CollectedNode> = Vec::new();

    // FullHistory: per-node key hash for each leaf (None for internal nodes).
    // Populated during the DFS, consumed by step 3.5.
    let full_history = mode == SquashMode::FullHistory;
    let mut leaf_key_hashes: Vec<Option<TrieHash>> = Vec::new();

    {
        let storage = src_marf.storage_backend_mut();
        let mut conn = storage.connection();
        let tip_block_ref = tip_block.clone();
        conn.open_block(&tip_block_ref)?;

        let mut scratch = MarfReadState::new();

        // Read root node
        let root_ptr = conn.root_trieptr();
        let root_read = conn.read_node_with_state(&root_ptr, &mut scratch)?;
        let (root_node, root_hash) = root_read.into_owned_node()?;
        let root_hash = root_hash.unwrap_or(TrieHash([0u8; 32]));

        let (_, root_block_id) = conn.get_cur_block_and_id();
        let root_block_id = root_block_id.ok_or(Error::NotOpenedError)?;

        // Serialize root
        let root_bytes = serialize_node(&root_node, &root_hash)?;
        let root_idx = node_store.push(&root_bytes, root_hash, root_block_id)?;
        ptr_to_idx.insert((root_block_id, root_ptr.ptr()), root_idx);

        collected.push(CollectedNode {
            block_id: root_block_id,
            is_leaf: root_node.is_leaf(),
        });
        stats.nodes_collected += 1;

        // FullHistory path tracking: accumulate trie path bytes during DFS so we can reconstruct
        // the full 32-byte TrieHash key for each leaf.
        let mut path_buf: Vec<u8> = Vec::with_capacity(if full_history { 32 } else { 0 });

        if full_history {
            path_buf.extend_from_slice(root_node.path_bytes());
            if root_node.is_leaf() && path_buf.len() == 32 {
                leaf_key_hashes.push(Some(TrieHash(
                    path_buf[..32].try_into().expect("path_buf is 32 bytes"),
                )));
            } else {
                leaf_key_hashes.push(None);
            }
        }

        // DFS stack: (ptr, return_block_hash, return_block_id, parent_depth) parent_depth is only
        // meaningful when full_history == true.
        let mut dfs_stack: Vec<(TriePtr, T, Option<u32>, usize)> = Vec::new();

        // Push children of root onto stack
        if !root_node.is_leaf() {
            let root_path_depth = path_buf.len();
            let (cur_block, cur_block_id) = conn.get_cur_block_and_id();
            for child_ptr in root_node.ptrs().iter() {
                if child_ptr.id() != TrieNodeID::Empty as u8 {
                    dfs_stack.push((*child_ptr, cur_block.clone(), cur_block_id, root_path_depth));
                }
            }
        } else {
            stats.leaves_collected += 1;
        }

        // DFS traversal
        while let Some((ptr, return_block, return_block_id, parent_depth)) = dfs_stack.pop() {
            // FullHistory path tracking: restore path to parent state, add branch byte
            if full_history {
                path_buf.truncate(parent_depth);
                path_buf.push(ptr.chr());
            }

            // Resolve backpointers: if this is a backptr, open the referenced block
            let (resolved_ptr, node_block_id) = if is_backptr(ptr.id()) {
                let back_block_id = ptr.back_block();
                let back_block_hash = conn.get_block_from_local_id(back_block_id)?;
                conn.open_block_known_id(&back_block_hash, back_block_id)?;
                let resolved = ptr.from_backptr();
                let (_, bid) = conn.get_cur_block_and_id();
                (resolved, bid.unwrap_or(back_block_id))
            } else {
                // Make sure we're in the right block
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                let (_, bid) = conn.get_cur_block_and_id();
                (ptr, bid.ok_or(Error::NotOpenedError)?)
            };

            // Check if already collected (shared subtree from multiple backptrs)
            let key = (node_block_id, resolved_ptr.ptr());
            if let Some(&_existing_idx) = ptr_to_idx.get(&key) {
                // Restore the block we came from
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                continue;
            }

            // Read the node
            let read = conn.read_node_with_state(&resolved_ptr, &mut scratch)?;
            let (node, hash) = read.into_owned_node()?;
            let hash = hash.unwrap_or(TrieHash([0u8; 32]));

            // FullHistory: extend path with this node's path segment
            if full_history {
                path_buf.extend_from_slice(node.path_bytes());
            }

            let is_leaf = node.is_leaf();
            let child_ptrs: Vec<TriePtr> = if !is_leaf {
                node.ptrs()
                    .iter()
                    .filter(|p| p.id() != TrieNodeID::Empty as u8)
                    .copied()
                    .collect()
            } else {
                Vec::new()
            };

            // Serialize and store
            let node_bytes = serialize_node(&node, &hash)?;
            let idx = node_store.push(&node_bytes, hash, node_block_id)?;
            ptr_to_idx.insert(key, idx);

            collected.push(CollectedNode {
                block_id: node_block_id,
                is_leaf,
            });

            // FullHistory: record the full key hash for leaves
            if full_history {
                if is_leaf && path_buf.len() == 32 {
                    leaf_key_hashes.push(Some(TrieHash(
                        path_buf[..32].try_into().expect("path_buf is 32 bytes"),
                    )));
                } else {
                    leaf_key_hashes.push(None);
                }
            }

            stats.nodes_collected += 1;
            if is_leaf {
                stats.leaves_collected += 1;
            }

            // Get current block context before pushing children
            let (cur_block_for_children, cur_block_id_for_children) = conn.get_cur_block_and_id();

            // Push children for DFS
            let depth_after_node = path_buf.len();
            for child_ptr in child_ptrs.iter() {
                dfs_stack.push((
                    *child_ptr,
                    cur_block_for_children.clone(),
                    cur_block_id_for_children,
                    depth_after_node,
                ));
            }

            // Restore block context for next iteration
            let (cur_block, _) = conn.get_cur_block_and_id();
            if cur_block != return_block {
                conn.open_block_maybe_id(&return_block, return_block_id)?;
            }
        }
    }

    // Flush the node store writer
    node_store.flush()?;

    // Step 3b: Extend the structural closure to cover every canonical root,
    // so the per-height root snapshots written by
    // [`capture_per_height_root_nodes`] resolve at every populated chr. See
    // [`extend_squash_dfs_with_canonical_roots`] for details.
    //
    // Base level (squash_level) has no prior squash levels, so cross-level
    // backptrs cannot occur — pass `None` for the cross-level block-hash
    // sink.
    let orphan_nodes_added = extend_squash_dfs_with_canonical_roots(
        &mut src_marf,
        &block_hashes_raw,
        &block_ids_per_height,
        &mut ptr_to_idx,
        &mut collected,
        &mut leaf_key_hashes,
        &mut node_store,
        full_history,
        None,
    )?;
    if orphan_nodes_added > 0 {
        node_store.flush()?;
        stats.nodes_collected = collected.len() as u64;
        stats.leaves_collected = collected.iter().filter(|c| c.is_leaf).count() as u64;
    }

    info!(
        "Squash DFS: collected {} nodes ({} leaves) \
         (orphan structural extension added {} nodes)",
        stats.nodes_collected, stats.leaves_collected, orphan_nodes_added,
    );

    // ---------------------------------------------------------------
    // Step 3.5: FullHistory leaf replacement
    //
    // For FullHistory mode, collect the per-key value history and
    // replace multi-transition leaves with TrieLeafSquashed nodes in
    // the node store. This runs BEFORE remap (step 4) so that the
    // updated node sizes are naturally picked up by offset computation.
    // Leaf hashes are unchanged: TrieLeafSquashed hashes the same way
    // as TrieLeaf (only the tip value is covered by the hash).
    // ---------------------------------------------------------------
    if mode == SquashMode::FullHistory {
        let block_hashes_typed: Vec<T> = block_hashes_raw
            .iter()
            .map(|bhh| T::from_bytes(*bhh))
            .collect();

        let history = collect_history(&mut src_marf, &block_hashes_typed, min_height, max_height)?;

        let node_count_before = node_store.len();
        for i in 0..node_count_before {
            if !collected[i].is_leaf {
                continue;
            }
            let key_hash = match &leaf_key_hashes[i] {
                Some(kh) => kh,
                None => continue,
            };
            // Base-level squash: no inheritance from prior levels, so every in-range write needs a
            // height-tagged entry so that reads at heights below the first write return None via
            // `value_at_height`. Keys not in `history` are internal MARF keys and stay plain.
            let transitions = match history.get(key_hash) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };

            // Read the existing serialized leaf to get its path bytes.
            // Leaf bytes in node_store are hash-free: [body] only.
            let raw = node_store.read_node_bytes(i)?;

            // Decode the leaf to get its path (NodePath)
            let node_id_byte = *raw.first().ok_or_else(|| {
                Error::CorruptionError("Empty node body during FullHistory leaf replace".into())
            })?;
            let node_id = clear_backptr(node_id_byte) & 0x3f;
            let (existing_node, _) = bits::decode_nodetype_from_slice_at_head(&raw, node_id)?;
            let path_slice = existing_node.path_bytes();

            // Build the TrieLeafSquashed: entries must be sorted descending by height
            let mut entries: Vec<(u32, MARFValue)> = transitions.clone();
            entries.reverse(); // history map is ascending; TrieLeafSquashed wants descending

            let squashed = TrieLeafSquashed::new(path_slice, entries)?;

            // Re-serialize without hash prefix (leaf hashes are omitted in squash blobs)
            let squashed_node = TrieNodeType::LeafSquashed(squashed);
            let mut new_buf = Vec::with_capacity(squashed_node.byte_len() + 1);
            squashed_node.write_bytes(&mut new_buf)?;

            node_store.update(i, &new_buf)?;
            stats.leaves_squashed += 1;
        }

        node_store.flush()?;

        info!(
            "FullHistory: replaced {} leaves with TrieLeafSquashed",
            stats.leaves_squashed
        );
    }

    // ---------------------------------------------------------------
    // Step 4: Compute sequential byte offsets and remap pointers
    // ---------------------------------------------------------------
    let node_count = node_store.len();

    // First pass: compute the byte size of each serialized node and its offset
    let mut node_sizes: Vec<u32> = Vec::with_capacity(node_count);
    for i in 0..node_count {
        node_sizes.push(node_store.node_byte_len(i));
    }

    // Compute sequential offsets: each node's offset in the final blob.
    //
    // The blob starts with a BLOB_HEADER_SIZE header, then nodes are laid out sequentially
    let mut seq_offsets: Vec<u32> = Vec::with_capacity(node_count);
    let mut current_offset = BLOB_HEADER_SIZE as u32;
    for &size in &node_sizes {
        seq_offsets.push(current_offset);
        current_offset = checked_offset_add(current_offset, size)?;
    }

    // Flush before remap pass (reads need to see the DFS writes)
    node_store.flush()?;

    // Second pass: for each non-leaf node, decode, remap child pointers, re-encode
    for i in 0..node_count {
        if collected[i].is_leaf {
            continue;
        }

        let raw = node_store.read_node_bytes(i)?;
        // raw = hash (32 bytes) + node_body
        if raw.len() < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(
                "Serialized node too short for hash prefix".into(),
            ));
        }
        let hash_bytes = &raw[..TRIEHASH_ENCODED_SIZE];
        let node_body = &raw[TRIEHASH_ENCODED_SIZE..];

        // Decode the node from its body bytes
        let node_id_byte = *node_body
            .first()
            .ok_or_else(|| Error::CorruptionError("Empty node body during remap".into()))?;
        let node_id = clear_backptr(node_id_byte) & 0x3f; // clear both ctrl bits
        let (mut node, _consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;

        // Remap child pointers
        remap_child_ptrs(&mut node, &collected[i], &ptr_to_idx, &seq_offsets)?;

        // Re-encode
        let mut new_buf = Vec::with_capacity(raw.len());
        new_buf.extend_from_slice(hash_bytes);
        node.write_bytes(&mut new_buf)?;

        // Update in node store - we need to write back (may change size due to backptr removal)
        node_store.update(i, &new_buf)?;
        node_sizes[i] = new_buf.len() as u32;
    }

    // Flush after remap pass so subsequent reads see the updated data
    node_store.flush()?;

    // Recompute sequential offsets after remapping (sizes may have changed)
    current_offset = BLOB_HEADER_SIZE as u32;
    for i in 0..node_count {
        seq_offsets[i] = current_offset;
        current_offset = checked_offset_add(current_offset, node_sizes[i])?;
    }

    // ---------------------------------------------------------------
    // Step 5: Recompute hashes bottom-up
    // ---------------------------------------------------------------

    // Process nodes in reverse order (leaves first, root last)
    for i in (0..node_count).rev() {
        if collected[i].is_leaf {
            // Leaf hashes stay the same
            continue;
        }

        let raw = node_store.read_node_bytes(i)?;
        if raw.len() < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(
                "Serialized node too short for hash prefix in rehash pass".into(),
            ));
        }
        let node_body = &raw[TRIEHASH_ENCODED_SIZE..];
        let node_id_byte = *node_body
            .first()
            .ok_or_else(|| Error::CorruptionError("Empty node body during rehash".into()))?;
        let node_id = clear_backptr(node_id_byte) & 0x3f;
        let (node, _consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;

        // Collect child hashes from node_store via binary search on seq_offsets
        let child_hashes: Vec<TrieHash> = node
            .ptrs()
            .iter()
            .map(|child_ptr| {
                if child_ptr.id() == TrieNodeID::Empty as u8 {
                    return Ok(TrieHash::EMPTY);
                }
                let child_offset = child_ptr.ptr();
                if let Ok(child_idx) = seq_offsets.binary_search(&child_offset) {
                    Ok(*node_store.hash(child_idx))
                } else {
                    warn!(
                        "Could not find child node at offset {} during rehash",
                        child_offset
                    );
                    Ok(TrieHash::EMPTY)
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Compute new hash for this node
        let new_hash =
            compute_node_hash::<T, _>(&node, &child_hashes, &mut SquashBlockMap::<T>::new())?;
        node_store.set_hash(i, new_hash);

        // Rewrite the node bytes with the new hash
        let mut new_buf = Vec::with_capacity(raw.len());
        new_buf.extend_from_slice(new_hash.as_bytes());
        new_buf.extend_from_slice(node_body);
        node_store.update(i, &new_buf)?;
        node_sizes[i] = new_buf.len() as u32;
    }

    // Flush after rehash pass
    node_store.flush()?;

    // Final offset recompute
    current_offset = BLOB_HEADER_SIZE as u32;
    for i in 0..node_count {
        seq_offsets[i] = current_offset;
        current_offset = checked_offset_add(current_offset, node_sizes[i])?;
    }

    let squash_root_hash = *node_store.hash(0);
    let archival_root_hash = root_hashes.last().copied().unwrap_or(TrieHash::EMPTY);

    // Capture per-height root nodes (post-remap) so that
    // `MARF::root_copy` can rebuild the correct fork-extension root for any
    // non-tip squashed parent. Must run before the source blobs are touched.
    let per_height_root_node_bodies = capture_per_height_root_nodes(
        &mut src_marf,
        &block_hashes_raw,
        &block_ids_per_height,
        &ptr_to_idx,
        &seq_offsets,
    )?;

    // ---------------------------------------------------------------
    // Step 6: Stream blob to destination file
    // ---------------------------------------------------------------
    let dst_open_opts = MARFOpenOpts {
        hash_calculation_mode: TrieHashCalculationMode::Immediate,
        cache_strategy: "noop".to_string(),
        external_blobs: true,
        force_db_migrate: false,
        compress: false,
        mmap: false,
        squash_mode: SquashMode::TipOnly,
    };

    let mut dst_marf = MARF::<T>::from_path(dst_path, dst_open_opts)?;

    // Publish the per-height root sidecar AFTER opening dst_marf so the
    // dst's startup reconcile (running on an empty SQL state) doesn't
    // see the just-written sidecar as an orphan and delete it. The dir
    // is keyed off dst_path so each MARF's sidecars are isolated from
    // peer MARFs sharing the same parent directory. Sidecar publish
    // happens BEFORE the SQL row write below; the row carries
    // root_sidecar_present=true, gated on the rename having succeeded.
    write_squash_root_sidecar(
        Path::new(dst_path),
        0, // base squash always emits level_id = 0
        min_height,
        max_height,
        per_height_root_node_bodies,
    )?;

    // Stream the blob to the destination file in chunks to avoid holding the entire 2+ GB node
    // payload in memory at once.

    // Store the blob via the destination MARF's storage
    {
        let storage = dst_marf.storage_backend_mut();

        // Ensure the squash levels table exists
        trie_sql::create_squash_levels_table(storage.sqlite_conn())?;

        let blob_offset = storage.get_blob_append_offset()?;
        let mut write_pos = blob_offset;

        // Write blob header: block hash (32 bytes) + block_id placeholder (4 bytes)
        let mut header = [0u8; BLOB_HEADER_SIZE as usize];
        header[..32].copy_from_slice(tip_block.as_bytes());
        // bytes 32..36 remain zero (block_id placeholder)
        storage.pwrite_blob_chunk(&header, write_pos)?;
        write_pos += BLOB_HEADER_SIZE;

        // Stream nodes through a fixed-size write buffer (1 MB)
        const WRITE_BUF_CAP: usize = 1 << 20;
        let mut write_buf: Vec<u8> = Vec::with_capacity(WRITE_BUF_CAP);

        for i in 0..node_count {
            let node_bytes = node_store.read_node_bytes(i)?;
            if write_buf.len() + node_bytes.len() > WRITE_BUF_CAP && !write_buf.is_empty() {
                storage.pwrite_blob_chunk(&write_buf, write_pos)?;
                write_pos += write_buf.len() as u64;
                write_buf.clear();
            }
            write_buf.extend_from_slice(&node_bytes);
        }
        if !write_buf.is_empty() {
            storage.pwrite_blob_chunk(&write_buf, write_pos)?;
            write_pos += write_buf.len() as u64;
            write_buf.clear();
        }

        stats.blob_bytes = write_pos - blob_offset;

        // Build the trailer into a separate buffer (small relative to node data)
        let trailer_offset = write_pos - blob_offset;

        let mut sorted_block_entries: Vec<([u8; 32], u32, u32)> = block_hashes_raw
            .iter()
            .zip(block_ids_per_height.iter())
            .enumerate()
            .map(|(i, (bhh, &bid))| (*bhh, i as u32, bid))
            .collect();
        sorted_block_entries.sort_by_key(|(bhh, _, _)| *bhh);

        let trailer = SquashTrailer {
            info: SquashInfo {
                mode,
                level_id: 0,
                min_height,
                max_height,
                archival_root: archival_root_hash,
                squash_root: squash_root_hash,
            },
            root_hashes,
            block_hashes: block_hashes_raw,
            sorted_block_entries,
        };

        let mut trailer_buf = Vec::new();
        let trailer_bytes_written = trailer.write_to(&mut trailer_buf)?;
        stats.trailer_bytes = trailer_bytes_written + SQUASH_FOOTER_SIZE as u64;
        SquashTrailer::write_footer(&mut trailer_buf, trailer_offset)?;

        storage.pwrite_blob_chunk(&trailer_buf, write_pos)?;
        write_pos += trailer_buf.len() as u64;

        // Finalize: sync to disk and remap
        storage.finish_blob_write(None)?;

        let blob_len = write_pos - blob_offset;

        // Register the squash level in the DB. The per-height root sidecar
        // was already atomically published before this block; its
        // visibility is gated on this row commit.
        let row = SquashLevelRow {
            level_id: 0,
            min_height,
            max_height,
            blob_offset,
            blob_length: blob_len,
            reads_redirected: true,
            root_sidecar_present: true,
            root_sidecar_trimmed: false,
        };
        trie_sql::write_squash_level(storage.sqlite_conn(), &row)?;

        // Register placeholder marf_data rows for all blocks in the range. Each block maps to the
        // squash blob's offset so that open_block can find it. All blocks share the same blob.
        //
        // NOTE: squash_to_path creates a fresh DB, so these are INSERT rows, not UPDATE. The
        // incremental squash path (squash_level_incremental) intentionally does NOT update existing
        // per-block offsets.
        for bhh_bytes in &trailer.block_hashes {
            let bhh = T::from_bytes(*bhh_bytes);
            trie_sql::write_external_trie_blob(storage.sqlite_conn(), &bhh, blob_offset, blob_len)?;
        }
    }

    // Cleanup
    node_store.finish()?;

    info!(
        "Squash level 0 complete: {} nodes, {} blob bytes, {} trailer bytes",
        stats.nodes_collected, stats.blob_bytes, stats.trailer_bytes
    );

    Ok(stats)
}

/// Find the tip block hash for the given max_height by querying the MARF.
///
/// This looks up the last known block using the MARF's own height-to-hash mapping. We need to find
/// an existing block to use as a reference tip for `get_block_at_height` calls.
fn find_tip_block<T: MarfTrieId>(marf: &mut MARF<T>, max_height: u32) -> Result<T, Error> {
    // The MARF stores height mappings internally. We need to find a block at max_height. Since
    // get_block_at_height requires a tip, and we need the tip itself, we use get_block_at_height
    // with the tip as itself.
    //
    // The trick: look at the MARF's internal block map. The last block in the chain is at
    // max_height.

    // Try to find the tip by looking at what blocks exist. We need to use the low-level storage to
    // find a known block hash.
    let tip_block_hash: T = {
        let conn = marf.sqlite_conn();

        // Query the marf_data table for any block, then use it to bootstrap.
        trie_sql::get_block_hash(conn, 1)
            .or_else(|_| {
                // Try block_id 0
                trie_sql::get_block_hash(conn, 0)
            })
            .map_err(|_| {
                Error::CorruptionError(
                    "Cannot find any blocks in the MARF to use as bootstrap tip".into(),
                )
            })?
    };

    // Try using the bootstrap block to find the actual tip at max_height
    //
    // First find the height of our bootstrap block
    let bootstrap_height = marf
        .get_block_height_of(&tip_block_hash, &tip_block_hash)?
        .ok_or_else(|| Error::CorruptionError("Bootstrap block has no height mapping".into()))?;

    if bootstrap_height == max_height {
        return Ok(tip_block_hash);
    }

    // Use get_block_at_height to find the block at max_height We need a tip that's >= max_height
    if bootstrap_height >= max_height {
        let block_at_height = marf
            .get_block_at_height(max_height, &tip_block_hash)?
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "No block found at height {max_height} relative to bootstrap block"
                ))
            })?;
        return Ok(block_at_height);
    }

    // bootstrap_height < max_height, so we need a higher block; scan the block map for a block at a
    // higher height
    find_tip_block_by_scanning(marf, max_height)
}

/// Fallback: scan block IDs to find a block at the desired height.
fn find_tip_block_by_scanning<T: MarfTrieId>(
    marf: &mut MARF<T>,
    max_height: u32,
) -> Result<T, Error> {
    // Get the max block_id in marf_data
    let max_block_id: u32 = {
        let conn = marf.sqlite_conn();
        conn.query_row(
            "SELECT MAX(block_id) FROM marf_data",
            rusqlite::params![],
            |row| row.get(0),
        )
        .map_err(|e| Error::CorruptionError(format!("Failed to query max block_id: {e}")))?
    };

    // Try blocks from highest ID downward to find one at or above max_height
    for block_id in (1..=max_block_id).rev() {
        let block_hash: T = {
            let conn = marf.sqlite_conn();
            match trie_sql::get_block_hash(conn, block_id) {
                Ok(bh) => bh,
                Err(_) => continue,
            }
        };

        // Check this block's height
        if let Ok(Some(height)) = marf.get_block_height_of(&block_hash, &block_hash) {
            if height >= max_height {
                // Found a block high enough — now get the actual block at max_height
                if height == max_height {
                    return Ok(block_hash);
                }
                if let Ok(Some(target)) = marf.get_block_at_height(max_height, &block_hash) {
                    return Ok(target);
                }
            }
        }
    }

    Err(Error::CorruptionError(format!(
        "Could not find any block at height {max_height} by scanning"
    )))
}

/// Serialize a node for storage in a squash blob.
///
/// * Non-leaf nodes are stored as `[hash(32)][body]`.
/// * Leaf nodes are stored as `[body]` only — the hash is omitted from the blob (it lives in the
///   `NodeStore` side-table during construction and can be recomputed on read via `get_leaf_hash` /
///   `get_nodetype_hash_bytes`).
fn serialize_node(node: &TrieNodeType, hash: &TrieHash) -> Result<Vec<u8>, Error> {
    let omit_hash = node.is_leaf();
    let hash_size = if omit_hash { 0 } else { TRIEHASH_ENCODED_SIZE };
    let mut buf = Vec::with_capacity(hash_size + node.byte_len() + 1);
    if !omit_hash {
        buf.extend_from_slice(hash.as_bytes());
    }
    node.write_bytes(&mut buf)?;
    Ok(buf)
}

/// Remap child pointers in a node from (old_block_id, old_offset) to new sequential offsets.
///
/// * For base-level squash: all children are remapped (no backpointers survive).
/// * For incremental squash: only intra-level children are in `ptr_to_idx`; cross-level
///   backpointers are not found and are left as-is, which is correct — they already carry valid
///   destination-native offsets into prior levels.
fn remap_child_ptrs(
    node: &mut TrieNodeType,
    collected: &CollectedNode,
    ptr_to_idx: &HashMap<(u32, u32), usize>,
    seq_offsets: &[u32],
) -> Result<(), Error> {
    // Iterate the actual ptrs and remap each one using ptr_to_idx + seq_offsets
    for ptr in node.ptrs_mut().iter_mut() {
        if ptr.id() == TrieNodeID::Empty as u8 {
            continue;
        }

        // Find this child's original location
        let (lookup_block_id, lookup_ptr) = if is_backptr(ptr.id()) {
            (ptr.back_block(), ptr.ptr())
        } else {
            (collected.block_id, ptr.ptr())
        };

        if let Some(&child_idx) = ptr_to_idx.get(&(lookup_block_id, lookup_ptr)) {
            let new_offset = seq_offsets[child_idx];
            if is_backptr(ptr.id()) {
                // * Intra-level backpointer: preserve backptr bit and original back_block.
                // * Only update the ptr offset to the new blob-local position.
                // * This maintains correct canonical hashing (consensus bytes use
                //   block_hash(back_block)) and prevents COW from re-targeting the pointer.
                ptr.ptr = new_offset;
            } else {
                // Direct child (same block as parent): stays direct with new offset.
                ptr.ptr = new_offset;
                ptr.back_block = 0;
            }
        }
        // If not found in mapping, leave as-is (cross-level backpointer)
    }

    Ok(())
}

/// Extend the squash collection's structural closure to cover every canonical
/// block's root, not just the tip's reachable set.
///
/// The tip-DFS visits only nodes reachable from the merged-tip's root. Any
/// non-tip canonical block H may have direct children whose target nodes were
/// COW-replaced by a later block — those orphan subtrees are absent from the
/// merged blob. To support consensus-correct fork-extension via
/// `MARF::root_copy` against a non-tip squashed parent (whose captured root
/// must point at real merged-blob targets at every populated child slot),
/// the merged blob must contain every node referenced by any canonical
/// root's child ptrs (and their descendants).
///
/// This pass runs after the tip-DFS, walking each canonical block's root and
/// adding orphan subtree nodes to `node_store` / `ptr_to_idx` / `collected` /
/// `leaf_key_hashes`. The canonical root itself is NOT emitted — it is
/// captured separately into [`SquashTrailer::root_nodes`].
///
/// Cross-level handling: backptrs whose `back_block` is outside the current
/// squash level (i.e. not in `block_ids_per_height`) are skipped — those
/// already carry valid offsets into prior levels and the existing read
/// pipeline resolves them via prior-level metadata. The back_block hash IS
/// recorded in `block_id_to_hash` (when provided) so the downstream rehash
/// pass can resolve `block_hash(back_block)` for backptr child-hash
/// computation, mirroring the tip-DFS's handling of cross-level targets.
///
/// Must run BEFORE leaf-replace, remap, and rehash so the orphan nodes go
/// through the same downstream passes as tip-DFS-collected nodes.
fn extend_squash_dfs_with_canonical_roots<T: MarfTrieId>(
    marf: &mut MARF<T>,
    block_hashes_raw: &[[u8; 32]],
    block_ids_per_height: &[u32],
    ptr_to_idx: &mut HashMap<(u32, u32), usize>,
    collected: &mut Vec<CollectedNode>,
    leaf_key_hashes: &mut Vec<Option<TrieHash>>,
    node_store: &mut NodeStore,
    full_history: bool,
    block_id_to_hash: Option<&mut HashMap<u32, T>>,
) -> Result<u64, Error> {
    debug_assert_eq!(block_hashes_raw.len(), block_ids_per_height.len());
    let intra_level_block_ids: HashSet<u32> = block_ids_per_height.iter().copied().collect();
    let storage = marf.storage_backend_mut();
    let mut conn = storage.connection();
    let mut scratch = MarfReadState::new();
    let mut nodes_added: u64 = 0;
    let mut block_id_to_hash = block_id_to_hash;

    for (idx, bhh_bytes) in block_hashes_raw.iter().enumerate() {
        let bhh = T::from_bytes(*bhh_bytes);
        conn.open_block(&bhh)?;
        let root_ptr = conn.root_trieptr();
        let root_read = conn.read_node_with_state(&root_ptr, &mut scratch)?;
        let (root_node, _root_hash) = root_read.into_owned_node()?;
        let block_id = block_ids_per_height[idx];

        if root_node.is_leaf() {
            // A leaf at the root level carries one key for the whole block.
            // Tip-DFS already saw it (tip's root must reach this key's
            // current leaf via some path), so nothing to add here.
            continue;
        }

        let mut path_buf: Vec<u8> = Vec::with_capacity(if full_history { 32 } else { 0 });
        if full_history {
            path_buf.extend_from_slice(root_node.path_bytes());
        }
        let root_path_depth = path_buf.len();

        let mut dfs_stack: Vec<(TriePtr, T, Option<u32>, usize)> = Vec::new();
        for child_ptr in root_node.ptrs().iter() {
            if child_ptr.id() == TrieNodeID::Empty as u8 {
                continue;
            }
            dfs_stack.push((*child_ptr, bhh.clone(), Some(block_id), root_path_depth));
        }

        while let Some((ptr, return_block, return_block_id, parent_depth)) = dfs_stack.pop() {
            if full_history {
                path_buf.truncate(parent_depth);
                path_buf.push(ptr.chr());
            }

            let (resolved_ptr, node_block_id) = if is_backptr(ptr.id()) {
                let back_block_id = ptr.back_block();
                if !intra_level_block_ids.contains(&back_block_id) {
                    // Cross-level: don't inline the target subtree, but
                    // record the back_block's hash so the downstream rehash
                    // pass can resolve `block_hash(back_block)` for the
                    // backptr child-hash. The tip-DFS does the same for
                    // cross-level backptrs it encounters; if the orphan
                    // walk discovered this back_block first (e.g. because
                    // the tip never traverses this particular cross-level
                    // edge), the rehash would otherwise fail with
                    // "Missing block hash for backptr target block_id ...".
                    if let Some(map) = block_id_to_hash.as_deref_mut() {
                        if !map.contains_key(&back_block_id) {
                            let back_block_hash = conn.get_block_from_local_id(back_block_id)?;
                            map.insert(back_block_id, back_block_hash);
                        }
                    }
                    continue;
                }
                let back_block_hash = conn.get_block_from_local_id(back_block_id)?;
                conn.open_block_known_id(&back_block_hash, back_block_id)?;
                let resolved = ptr.from_backptr();
                (resolved, back_block_id)
            } else {
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                let (_, bid) = conn.get_cur_block_and_id();
                (ptr, bid.ok_or(Error::NotOpenedError)?)
            };

            let key = (node_block_id, resolved_ptr.ptr());
            if ptr_to_idx.contains_key(&key) {
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                continue;
            }

            let read = conn.read_node_with_state(&resolved_ptr, &mut scratch)?;
            let (node, hash) = read.into_owned_node()?;
            let hash = hash.unwrap_or(TrieHash([0u8; 32]));

            if full_history {
                path_buf.extend_from_slice(node.path_bytes());
            }

            let is_leaf = node.is_leaf();
            let child_ptrs: Vec<TriePtr> = if !is_leaf {
                node.ptrs()
                    .iter()
                    .filter(|p| p.id() != TrieNodeID::Empty as u8)
                    .copied()
                    .collect()
            } else {
                Vec::new()
            };

            let node_bytes = serialize_node(&node, &hash)?;
            let new_idx = node_store.push(&node_bytes, hash, node_block_id)?;
            ptr_to_idx.insert(key, new_idx);
            collected.push(CollectedNode {
                block_id: node_block_id,
                is_leaf,
            });
            if full_history {
                if is_leaf && path_buf.len() == 32 {
                    leaf_key_hashes.push(Some(TrieHash(
                        path_buf[..32].try_into().expect("path_buf is 32 bytes"),
                    )));
                } else {
                    leaf_key_hashes.push(None);
                }
            }
            nodes_added += 1;

            let (cur_block_for_children, cur_block_id_for_children) = conn.get_cur_block_and_id();
            let depth_after_node = path_buf.len();
            for child_ptr in child_ptrs.iter() {
                dfs_stack.push((
                    *child_ptr,
                    cur_block_for_children.clone(),
                    cur_block_id_for_children,
                    depth_after_node,
                ));
            }

            let (cur_block, _) = conn.get_cur_block_and_id();
            if cur_block != return_block {
                conn.open_block_maybe_id(&return_block, return_block_id)?;
            }
        }
    }
    Ok(nodes_added)
}

/// Capture each per-height block's root node, with child ptrs remapped to the
/// merged-blob layout, ready for inclusion in the [`SquashTrailer::root_nodes`]
/// table.
///
/// The squash blob contains exactly one materialized root (the merged tip's),
/// so any read of `ROOT_PTR_DISK` against a non-tip squashed block returns the
/// merged shape rather than the per-block shape. `MARF::root_copy` for a fork
/// extending such a parent therefore produces a structurally-wrong root and a
/// diverging seal hash. This helper captures each block's actual root before
/// the source blobs are reclaimed/truncated, runs `remap_child_ptrs` to point
/// each child at its merged-blob offset, and serializes the body.
///
/// Precondition: every reachable `(block_id, ptr)` referenced by a canonical
/// root in the level must appear in `ptr_to_idx`. The tip-DFS alone does not
/// guarantee this — orphan subtrees that were COW-replaced by later blocks
/// are not on the tip's reachable set. [`extend_squash_dfs_with_canonical_roots`]
/// must run before this helper to extend the merged-blob's structural closure
/// to cover every canonical root.
///
/// Must be called BEFORE the source blobs are truncated. `seq_offsets` must be
/// in its final post-rehash state so that the captured ptrs match what the
/// merged blob will contain on disk.
fn capture_per_height_root_nodes<T: MarfTrieId>(
    marf: &mut MARF<T>,
    block_hashes_raw: &[[u8; 32]],
    block_ids_per_height: &[u32],
    ptr_to_idx: &HashMap<(u32, u32), usize>,
    seq_offsets: &[u32],
) -> Result<Vec<Vec<u8>>, Error> {
    debug_assert_eq!(block_hashes_raw.len(), block_ids_per_height.len());

    let storage = marf.storage_backend_mut();
    let mut conn = storage.connection();
    let mut scratch = MarfReadState::new();
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(block_hashes_raw.len());

    for (idx, bhh_bytes) in block_hashes_raw.iter().enumerate() {
        let bhh = T::from_bytes(*bhh_bytes);
        conn.open_block(&bhh)?;
        let root_ptr = conn.root_trieptr();
        let root_read = conn.read_node_with_state(&root_ptr, &mut scratch)?;
        let (mut root_node, _hash) = root_read.into_owned_node()?;

        let collected_node = CollectedNode {
            block_id: block_ids_per_height[idx],
            is_leaf: root_node.is_leaf(),
        };
        remap_child_ptrs(&mut root_node, &collected_node, ptr_to_idx, seq_offsets)?;

        let mut buf = Vec::with_capacity(root_node.byte_len());
        root_node.write_bytes(&mut buf)?;
        out.push(buf);
    }
    Ok(out)
}

/// Atomically publish the per-height root node sidecar for `level_id`.
///
/// Writes a `<sidecar_path>.tmp`, fsyncs it, renames into place, then does a
/// best-effort fsync of the sidecar parent directory for rename durability.
///
/// Must be called BEFORE `publish_squash`'s `guard.arm()` for the level —
/// failures here are cleanly recoverable (return `Err`, no chainstate
/// mutation has occurred yet). The corresponding
/// `marf_squash_levels.root_sidecar_present` flag is set inside the
/// `publish_squash` SQL transaction once we know the rename succeeded.
fn write_squash_root_sidecar(
    db_path: &Path,
    level_id: u32,
    min_height: u32,
    max_height: u32,
    bodies: Vec<Vec<u8>>,
) -> Result<(), Error> {
    use crate::chainstate::stacks::index::sidecar::{
        squash_root_sidecar_path, squash_sidecar_dir_for_db, RecordKind, SidecarHeader,
        SidecarWriter, SIDECAR_FORMAT_VERSION,
    };

    info!(
        "write_squash_root_sidecar: ENTER db_path={} level_id={} heights=[{min_height}..={max_height}] bodies={}",
        db_path.display(),
        level_id,
        bodies.len(),
    );

    let count_usize = (max_height as usize)
        .checked_sub(min_height as usize)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            Error::CorruptionError(format!(
                "write_squash_root_sidecar: bad height range [{min_height}, {max_height}]"
            ))
        })?;
    if bodies.len() != count_usize {
        return Err(Error::CorruptionError(format!(
            "write_squash_root_sidecar: {} bodies for {count_usize} heights \
             (level_id={level_id}, range=[{min_height}, {max_height}])",
            bodies.len()
        )));
    }
    let count = u32::try_from(count_usize).map_err(|_| {
        Error::CorruptionError(format!(
            "write_squash_root_sidecar: count {count_usize} exceeds u32::MAX"
        ))
    })?;

    let sidecar_dir = squash_sidecar_dir_for_db(db_path);
    std::fs::create_dir_all(&sidecar_dir).map_err(|e| {
        Error::CorruptionError(format!(
            "write_squash_root_sidecar: cannot create {}: {e}",
            sidecar_dir.display()
        ))
    })?;

    let header = SidecarHeader {
        format_version: SIDECAR_FORMAT_VERSION,
        schema_flags: 0,
        record_kind: RecordKind::SquashRootNode,
        level_id,
        min_height,
        max_height,
        count,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let path = squash_root_sidecar_path(db_path, level_id, min_height, max_height);
    SidecarWriter::new(path.clone(), header, bodies).finalize()?;

    // Best-effort parent-dir fsync for rename durability. Not load-bearing
    // for content correctness; only matters across power-loss between rename
    // and SQL commit. On platforms where directory fsync is unsupported or
    // a no-op, the failure is silently ignored.
    if let Ok(dir_handle) = std::fs::File::open(&sidecar_dir) {
        let _ = dir_handle.sync_all();
    }

    // Post-finalize existence check at the squash-call boundary. The writer
    // already verifies post-rename, but this catches the case where something
    // between the rename and dir-fsync (or the dir-fsync itself) renders the
    // file inaccessible from the squash thread's view.
    match std::fs::metadata(&path) {
        Ok(md) => {
            info!(
                "write_squash_root_sidecar: EXIT ok, {} bytes at {} (level_id={level_id})",
                md.len(),
                path.display(),
            );
        }
        Err(e) => {
            return Err(Error::CorruptionError(format!(
                "write_squash_root_sidecar: rename succeeded but {} is not \
                 visible post-finalize (level_id={level_id}): {e}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Outcome of a single trim pass; used for diagnostics and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrimReport {
    /// Number of levels whose `root_sidecar_trimmed` SQL flag was
    /// successfully flipped to `true`. From this count's perspective a
    /// level is trimmed the moment SQL records the policy decision; the
    /// subsequent file `unlink` is best-effort disk hygiene tracked in
    /// `unlink_failures`.
    pub levels_trimmed: u64,
    /// Number of levels whose SQL `UPDATE` for `root_sidecar_trimmed`
    /// failed. The trim does not advance for these levels — file is
    /// untouched, level stays trim-eligible, retried next pass.
    pub trim_failures: u64,
    /// Number of levels whose SQL flag was successfully set but whose
    /// sidecar file `unlink` returned an error. Disk leakage only:
    /// `MARF::root_copy` correctly returns `SnapshotTrimmed` for these
    /// levels (the SQL flag drives the read path), and
    /// [`reconcile_squash_sidecars`] cleans up the orphan file on next
    /// startup.
    pub unlink_failures: u64,
    /// Number of levels skipped because the sidecar was already
    /// `root_sidecar_trimmed = 1` from a prior pass (idempotent).
    pub already_trimmed: u64,
}

/// Trim per-height root snapshot sidecars for any squash level whose age
/// from the current `latest_level_id` exceeds `retention_levels`.
///
/// The trim policy decommissions the level's per-height root snapshot
/// by flipping `marf_squash_levels.root_sidecar_trimmed = 1` (the SQL
/// flag is the load-bearing source of truth) and `unlink`-ing the
/// sidecar file. After trim, [`MARF::root_copy`] against a parent in
/// that level surfaces [`Error::SnapshotTrimmed`] — the dedicated
/// policy-error variant — instead of attempting a now-impossible
/// reconstruction. Trimmed levels otherwise remain fully readable for
/// value reads; only the fork-extension capability is decommissioned.
///
/// # Ordering and crash safety
///
/// The implementation runs in two phases with a metadata republish
/// between them, deliberately ordered so no crash window can leave a
/// handle observing the (file-missing, trimmed=false) corruption case:
///
/// 1. **Phase 1** flips `root_sidecar_trimmed=1` in SQL for each
///    candidate level. **Files are not touched.** SQL failures here
///    leave the level untrimmed and increment `trim_failures` in the
///    report — retried on the next pass.
/// 2. **Phase 1.5** (only if Phase 1 advanced any level) calls
///    `marf.refresh_after_squash()`, which rebuilds `SquashMeta` from
///    SQL and bumps the shared generation. From this point on every
///    handle — the one that issued the trim and any peer that re-syncs
///    on its next read — routes fork-extension off these levels via
///    [`Error::SnapshotTrimmed`] and never opens the sidecar file.
/// 3. **Phase 2** best-effort `unlink`s the now-trimmed sidecar files.
///    Failures here are pure disk leakage: SQL still says
///    `trimmed=true` (so the read path is correct via
///    [`Error::SnapshotTrimmed`]) and
///    [`crate::chainstate::stacks::index::sidecar::reconcile_squash_sidecars`]
///    deletes the orphan files on the next startup. The
///    `unlink_failures` counter tracks these for diagnostics. `ENOENT`
///    is treated as success (a prior crash mid-trim has already
///    handled the unlink for us).
///
/// Idempotent: levels with `root_sidecar_trimmed=1` are skipped and
/// counted under `already_trimmed`.
///
/// Exposed at `pub(crate)` so tests can drive it directly with a
/// non-default `retention_levels`. Production calls go through the
/// `squash_level_incremental` post-publish hook with
/// [`MARF_ROOT_SNAPSHOT_RETENTION_LEVELS`].
pub(crate) fn trim_aged_root_sidecars<T: MarfTrieId>(
    marf: &mut MARF<T>,
    db_path: &Path,
    latest_level_id: u32,
    retention_levels: u32,
) -> Result<TrimReport, Error> {
    use crate::chainstate::stacks::index::sidecar::squash_root_sidecar_path;

    let mut report = TrimReport::default();

    // Read the level registry. `read_squash_levels` already returns rows
    // ordered by `min_height`, which monotonically tracks `level_id` for
    // the squash sequence we produce, so iterating the natural order
    // suffices.
    let storage = marf.storage_backend_mut();
    let levels = trie_sql::read_squash_levels(storage.sqlite_conn())?;

    // Phase 1: identify trim candidates and flip
    // `root_sidecar_trimmed=1` in SQL. Files are NOT touched yet —
    // peers may still be mid-read off them via cached `SquashMeta`
    // snapshots that haven't synced to the new generation. By flipping
    // SQL first and refreshing in phase 1.5 BEFORE any unlink, we
    // guarantee that no handle ever observes the (file-missing,
    // trimmed=false) corruption window.
    let mut trim_candidates: Vec<(u32, std::path::PathBuf)> = Vec::new();
    for row in levels {
        // Only redirected (reclaim) levels carry sidecars; no-op others.
        if !row.reads_redirected {
            continue;
        }
        if row.root_sidecar_trimmed {
            report.already_trimmed += 1;
            continue;
        }
        // Compute "age in levels" via saturating subtraction so a
        // mis-ordered row (level_id > latest) doesn't underflow.
        let age = latest_level_id.saturating_sub(row.level_id);
        if age <= retention_levels {
            // Within retention window — keep the sidecar.
            continue;
        }

        if let Err(e) =
            trie_sql::set_root_sidecar_trimmed(storage.sqlite_conn(), row.level_id, true)
        {
            warn!(
                "trim_aged_root_sidecars: SQL flag update failed for \
                 level_id={}: {e:?}. File left in place; will retry on \
                 next trim pass.",
                row.level_id,
            );
            report.trim_failures += 1;
            continue;
        }
        report.levels_trimmed += 1;

        let path = squash_root_sidecar_path(db_path, row.level_id, row.min_height, row.max_height);
        trim_candidates.push((row.level_id, path));
    }

    // Phase 1.5: republish `SquashMeta` so every live handle sees the
    // new `root_sidecar_trimmed=true` flags BEFORE any file is removed.
    // From this point on, fork-extension off any of these levels routes
    // via `Error::SnapshotTrimmed` and never tries to open the sidecar
    // file. A failure here aborts the trim before unlink, leaving the
    // SQL flags set and the files intact — startup reconcile will
    // delete the (now orphan-by-SQL) files on the next open.
    if report.levels_trimmed > 0 {
        marf.refresh_after_squash()?;
    }

    // Phase 2: best-effort unlink of the now-trimmed sidecars.
    //
    // No live handle can be reading these files anymore — we set
    // `root_sidecar_trimmed=true` AND republished `SquashMeta` above,
    // so the read path skips file open and returns
    // `Error::SnapshotTrimmed` first. Any failure here just leaves
    // disk leakage: SQL still says `trimmed=true`, but the file
    // remains. The next startup's `reconcile_squash_sidecars` will
    // catch the inconsistency (file present + trimmed=true) and delete
    // the orphan. ENOENT is harmless (already gone from a prior crash
    // mid-trim).
    for (level_id, path) in trim_candidates {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(
                    "trim_aged_root_sidecars: deleted sidecar {} (level_id={level_id})",
                    path.display(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    "trim_aged_root_sidecars: sidecar {} already gone \
                     (level_id={level_id}); skipping",
                    path.display(),
                );
            }
            Err(e) => {
                warn!(
                    "trim_aged_root_sidecars: file unlink failed for {} \
                     (level_id={level_id}): {e}. SQL flag is set, so the \
                     read path is correct; startup reconcile will clean \
                     up the orphan file on next open.",
                    path.display(),
                );
                report.unlink_failures += 1;
            }
        }
    }

    Ok(report)
}

/// A dummy `BlockMap` for squash blob hash computation.
///
/// All backpointers are resolved before hash recomputation, so no block hash lookups should occur.
/// If one does (programming error), it returns a sentinel.
struct SquashBlockMap<T: MarfTrieId> {
    _phantom: std::marker::PhantomData<T>,
    sentinel: T,
}

impl<T: MarfTrieId> SquashBlockMap<T> {
    fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            sentinel: T::sentinel(),
        }
    }
}

impl<T: MarfTrieId> BlockMap for SquashBlockMap<T> {
    type TrieId = T;
    fn get_block_hash(&self, _id: u32) -> Result<T, Error> {
        Ok(self.sentinel.clone())
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&T, Error> {
        Ok(&self.sentinel)
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        true
    }
    fn get_block_id(&self, _bhh: &T) -> Result<u32, Error> {
        Ok(0)
    }
    fn get_block_id_caching(&mut self, _bhh: &T) -> Result<u32, Error> {
        Ok(0)
    }
}

/// A `BlockMap` backed by a real `block_id → block_hash` mapping for incremental squash.
///
/// * Used during rehash of incremental squash blobs where backpointers are preserved.
/// * Consensus bytes need the actual block hash for each backpointer target.
struct IncrementalSquashBlockMap<T: MarfTrieId> {
    block_id_to_hash: HashMap<u32, T>,
}

impl<T: MarfTrieId> BlockMap for IncrementalSquashBlockMap<T> {
    type TrieId = T;
    fn get_block_hash(&self, id: u32) -> Result<T, Error> {
        self.block_id_to_hash.get(&id).cloned().ok_or_else(|| {
            Error::CorruptionError(format!(
                "No block hash for block_id {id} in incremental squash block map"
            ))
        })
    }
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, Error> {
        self.block_id_to_hash.get(&id).ok_or_else(|| {
            Error::CorruptionError(format!(
                "No block hash for block_id {id} in incremental squash block map"
            ))
        })
    }
    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.block_id_to_hash.contains_key(&id)
    }
    fn get_block_id(&self, bhh: &T) -> Result<u32, Error> {
        for (&id, hash) in &self.block_id_to_hash {
            if hash == bhh {
                return Ok(id);
            }
        }
        Err(Error::NotFoundError)
    }
    fn get_block_id_caching(&mut self, bhh: &T) -> Result<u32, Error> {
        self.get_block_id(bhh)
    }
}

/// Compute the hash for a node using canonical MARF consensus bytes.
///
/// Uses `write_consensus_bytes` (not `write_bytes`) to match the hash computation in
/// `bits::get_node_hash`. The provided `BlockMap` resolves backpointer block IDs to block hashes
/// for the consensus bytes contribution.
fn compute_node_hash<T: MarfTrieId, M: BlockMap<TrieId = T>>(
    node: &TrieNodeType,
    child_hashes: &[TrieHash],
    block_map: &mut M,
) -> Result<TrieHash, Error> {
    bits::get_nodetype_hash_bytes::<T, _>(node, child_hashes, block_map)
}

/// Convenience wrapper: squash everything from height 0 to `height` as a single base level.
pub fn squash_to_path<T: MarfTrieId>(
    src_path: &str,
    dst_path: &str,
    mode: SquashMode,
    height: u32,
) -> Result<SquashStats, Error> {
    squash_level::<T>(src_path, dst_path, mode, 0, height)
}

// ---------------------------------------------------------------------------
// Incremental squash
// ---------------------------------------------------------------------------

/// Extract a `[u8; 32]` key from a `MarfTrieId` for squash block index lookups.
fn bhh_to_key<T: MarfTrieId>(bhh: &T) -> [u8; 32] {
    bhh.as_bytes()
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 32])
}

/// Verify that no blocks exist above `max_height` in the MARF.
///
/// This enforces the lifecycle constraint: incremental squash may only target the current
/// unsquashed tip suffix. If blocks above `max_height` exist, their backpointers into the squash
/// range would be invalidated by the `marf_data` row updates.
///
/// Cheap check: find the highest non-squashed block_id (which is the most recently committed
/// per-block blob, since block_ids auto-increment), resolve its height, and verify it equals
/// `max_height`.
fn verify_no_descendants<T: MarfTrieId>(marf: &mut MARF<T>, max_height: u32) -> Result<(), Error> {
    let squash_meta = Arc::clone(&marf.storage.data.squash_meta);
    let squash_index = &squash_meta.block_index;

    // Find the highest confirmed block_id in marf_data. Filter out unconfirmed rows — they are
    // in-progress writes that should not block squashing of the confirmed tip suffix.
    let max_block_id: u32 = {
        let conn = marf.sqlite_conn();
        conn.query_row(
            "SELECT COALESCE(MAX(block_id), 0) FROM marf_data WHERE unconfirmed = 0",
            rusqlite::params![],
            |row| row.get(0),
        )
        .map_err(|e| Error::CorruptionError(format!("Query max confirmed block_id: {e}")))?
    };

    // Scan from the highest confirmed block_id downward to find the first non-squashed,
    // non-sentinel block. Since block_ids auto- increment, this is the most recently committed
    // per-block blob.
    for block_id in (1..=max_block_id).rev() {
        let block_hash: T = match trie_sql::get_block_hash(marf.sqlite_conn(), block_id) {
            Ok(bh) => bh,
            Err(_) => continue,
        };
        if block_hash == T::sentinel() {
            continue;
        }
        if squash_index.contains_key(&bhh_to_key(&block_hash)) {
            continue;
        }
        // Found the highest per-block blob. Its height must be <= max_height.
        match marf.get_block_height_of(&block_hash, &block_hash) {
            Ok(Some(h)) if h > max_height => {
                return Err(Error::NotSupportedError(format!(
                    "Cannot squash: block at height {h} exists above max_height {max_height}. \
                     Incremental squash requires max_height to be the chain tip."
                )));
            }
            _ => return Ok(()),
        }
    }
    // No non-squashed blocks at all — everything is already squashed.
    Ok(())
}

/// Incremental squash: collapse blocks `min_height..=max_height` into a new squash level, operating
/// in-place on the given MARF.
///
/// Prior squash levels must cover all blocks below `min_height`. The MARF must have per-block blobs
/// for blocks in the range. `max_height` must be the chain tip (no descendants above it).
///
/// Cross-level backpointers into prior levels are preserved as-is. Only intra-range nodes are
/// collected and remapped to sequential offsets in the new squash blob.
pub fn squash_level_incremental<T: MarfTrieId + Send + Sync>(
    marf_path: &str,
    mode: SquashMode,
    min_height: u32,
    max_height: u32,
    reclaim: bool,
) -> Result<SquashStats, Error> {
    // Phase-timing instrumentation. Each phase's duration is captured into a `phase_*_ms` binding
    // and reported in the final summary log so we can see where the wall-clock time actually goes
    // (DFS vs collect_history vs leaf replacement vs publish_squash vs prune+truncate vs SQL
    // updates).
    //
    // Style note: phases assigned in the *outer* function body that are unconditionally set (DFS,
    // remap, publish_overhead) use `let … = …` at the assignment site to avoid an
    // `unused_assignments` warning on the initial `0`. Phases assigned inside `if full_history` AND
    // phases assigned inside the `publish_squash` closure must be declared up front here because
    // (a) they may not be reached on the false branch, or (b) the closure captures them by `&mut`
    // and the outer summary log needs visibility.
    let t_start = Instant::now();
    let mut phase_collect_history_ms: u128 = 0;
    let mut phase_baseline_ms: u128 = 0;
    let mut phase_baseline_keys: usize = 0;
    let mut phase_leaf_replace_ms: u128 = 0;
    let mut phase_leaf_replace_flush_ms: u128 = 0;
    let mut phase_prune_ms: u128 = 0;
    let mut phase_blob_write_ms: u128 = 0;
    let mut phase_finish_blob_ms: u128 = 0;
    let mut phase_sql_updates_ms: u128 = 0;
    let mut phase_build_meta_ms: u128 = 0;

    let mut stats = SquashStats::default();
    let full_history = mode == SquashMode::FullHistory;

    let open_opts = MARFOpenOpts {
        hash_calculation_mode: TrieHashCalculationMode::Immediate,
        cache_strategy: "noop".to_string(),
        external_blobs: true,
        force_db_migrate: false,
        compress: false,
        mmap: false,
        squash_mode: SquashMode::TipOnly,
    };

    let mut marf = MARF::<T>::from_path(marf_path, open_opts)?;

    // Precondition: max_height must be the chain tip
    verify_no_descendants(&mut marf, max_height)?;

    // Snapshot the squash metadata for cross-level detection during DFS. Arc::clone is a
    // cheap reference-count bump — no deep copy of the block index.
    let squash_meta = Arc::clone(&marf.storage.data.squash_meta);
    let squash_index = &squash_meta.block_index;

    // Determine the next level_id from existing levels and verify that prior levels contiguously
    // cover heights 0..min_height-1.
    let existing_levels = trie_sql::read_squash_levels(marf.sqlite_conn())?;
    if existing_levels.is_empty() && min_height > 0 {
        return Err(Error::CorruptionError(format!(
            "Incremental squash requires prior levels, but none exist (min_height={min_height})"
        )));
    }
    // Check that prior levels cover 0..=min_height-1 without gaps. When min_height=0 (L0
    // bootstrap), no prior levels are needed.
    if min_height > 0 {
        let mut covered_up_to: Option<u32> = None;
        for level in &existing_levels {
            let expected_start = covered_up_to.map_or(0, |h| h + 1);
            if level.min_height != expected_start {
                return Err(Error::CorruptionError(format!(
                    "Squash level gap: expected level starting at height {expected_start}, \
                     found level {} starting at {}",
                    level.level_id, level.min_height
                )));
            }
            covered_up_to = Some(level.max_height);
        }
        let prior_max = covered_up_to.unwrap_or(0);
        if prior_max + 1 != min_height {
            return Err(Error::CorruptionError(format!(
                "Prior squash levels cover up to height {prior_max}, but \
                 incremental squash starts at min_height={min_height}. \
                 All heights below min_height must be covered."
            )));
        }
    }
    let next_level_id = existing_levels
        .iter()
        .map(|r| r.level_id)
        .max()
        .map_or(0, |m| m + 1);

    // Detect stub level: any prior level with blob_length == 0 has no
    // block entries in squash_block_index, so backpointers into its range
    // must be classified via height lookup rather than index lookup.
    let has_stub_level = existing_levels.iter().any(|r| r.blob_length == 0);

    // ---------------------------------------------------------------
    // Step 1: Find tip block, collect per-height metadata
    // ---------------------------------------------------------------
    let tip_block = find_tip_block(&mut marf, max_height)?;

    let height_count = (max_height - min_height + 1) as usize;
    let mut root_hashes: Vec<TrieHash> = Vec::with_capacity(height_count);
    let mut block_hashes_raw: Vec<[u8; 32]> = Vec::with_capacity(height_count);
    let mut block_ids_per_height: Vec<u32> = Vec::with_capacity(height_count);
    let mut block_id_to_hash: HashMap<u32, T> = HashMap::with_capacity(height_count);

    for h in min_height..=max_height {
        let block_hash_at_h = marf
            .get_block_at_height(h, &tip_block)?
            .ok_or_else(|| Error::CorruptionError(format!("No block hash found at height {h}")))?;

        let root_hash = marf.get_root_hash_at(&block_hash_at_h)?;

        let mut bhh_bytes = [0u8; 32];
        bhh_bytes.copy_from_slice(block_hash_at_h.as_bytes());
        block_hashes_raw.push(bhh_bytes);
        root_hashes.push(root_hash);

        let block_id = trie_sql::get_block_identifier(marf.sqlite_conn(), &block_hash_at_h)?;
        block_ids_per_height.push(block_id);
        block_id_to_hash.insert(block_id, block_hash_at_h);
    }

    // ---------------------------------------------------------------
    // Step 2: DFS collect intra-range nodes, detect cross-level boundaries
    // ---------------------------------------------------------------
    // Use the MARF's parent directory for the temp file so it's in the
    // same filesystem (avoids cross-device issues).
    let tmp_dir = Path::new(marf_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut node_store = NodeStore::new(tmp_dir)?;

    let mut ptr_to_idx: HashMap<(u32, u32), usize> = HashMap::new();
    let mut collected: Vec<CollectedNode> = Vec::new();
    let mut leaf_key_hashes: Vec<Option<TrieHash>> = Vec::new();

    {
        let storage = marf.storage_backend_mut();
        let mut conn = storage.connection();
        let tip_block_ref = tip_block.clone();
        conn.open_block(&tip_block_ref)?;

        let mut scratch = MarfReadState::new();

        // Read root node (always in the tip block, always collected)
        let root_ptr = conn.root_trieptr();
        let root_read = conn.read_node_with_state(&root_ptr, &mut scratch)?;
        let (root_node, root_hash) = root_read.into_owned_node()?;
        let root_hash = root_hash.unwrap_or(TrieHash([0u8; 32]));

        let (_, root_block_id) = conn.get_cur_block_and_id();
        let root_block_id = root_block_id.ok_or(Error::NotOpenedError)?;

        let root_bytes = serialize_node(&root_node, &root_hash)?;
        let root_idx = node_store.push(&root_bytes, root_hash, root_block_id)?;
        ptr_to_idx.insert((root_block_id, root_ptr.ptr()), root_idx);

        collected.push(CollectedNode {
            block_id: root_block_id,
            is_leaf: root_node.is_leaf(),
        });
        stats.nodes_collected += 1;

        // FullHistory path tracking: accumulate trie path bytes during DFS
        // so we can reconstruct the full 32-byte TrieHash key for each leaf.
        let mut path_buf: Vec<u8> = Vec::with_capacity(if full_history { 32 } else { 0 });

        if full_history {
            path_buf.extend_from_slice(root_node.path_bytes());
            if root_node.is_leaf() && path_buf.len() == 32 {
                leaf_key_hashes.push(Some(TrieHash(
                    path_buf[..32].try_into().expect("path_buf is 32 bytes"),
                )));
            } else {
                leaf_key_hashes.push(None);
            }
        }

        // DFS stack: (ptr, return_block_hash, return_block_id, parent_depth)
        // parent_depth is only meaningful when full_history == true.
        let mut dfs_stack: Vec<(TriePtr, T, Option<u32>, usize)> = Vec::new();

        if !root_node.is_leaf() {
            let root_path_depth = path_buf.len();
            let (cur_block, cur_block_id) = conn.get_cur_block_and_id();
            for child_ptr in root_node.ptrs().iter() {
                if child_ptr.id() != TrieNodeID::Empty as u8 {
                    dfs_stack.push((*child_ptr, cur_block.clone(), cur_block_id, root_path_depth));
                }
            }
        } else {
            stats.leaves_collected += 1;
        }

        // DFS traversal with cross-level boundary detection
        while let Some((ptr, return_block, return_block_id, parent_depth)) = dfs_stack.pop() {
            // FullHistory path tracking: restore path to parent state, add branch byte
            if full_history {
                path_buf.truncate(parent_depth);
                path_buf.push(ptr.chr());
            }

            // --- Cross-level check for backpointers ---
            //
            // If this is a backpointer into a prior squash level, don't collect the target node.
            // Instead, pre-collect its hash for rehash and leave the backpointer as-is (it already
            // carries correct offsets).
            let (resolved_ptr, node_block_id) = if is_backptr(ptr.id()) {
                let back_block_id = ptr.back_block();
                let back_block_hash = conn.get_block_from_local_id(back_block_id)?;
                let bhh_key = bhh_to_key(&back_block_hash);

                match squash_index.get(&bhh_key) {
                    Some(&(_, h, _, _, _)) if h < min_height => {
                        // Cross-level backpointer: record block_id → block_hash for
                        // consensus hash computation. No need to read the target node;
                        // the child hash contribution is the ancestor block hash.
                        block_id_to_hash
                            .entry(back_block_id)
                            .or_insert_with(|| back_block_hash.clone());
                        continue;
                    }
                    Some(&(_, h, _, _, _)) => {
                        // Target is in a squash level at height >= min_height. This shouldn't
                        // happen — blocks in the current range should be per-block blobs, not
                        // already squashed.
                        return Err(Error::CorruptionError(format!(
                            "Backpointer target at height {h} is in a squash level \
                             but within the range being squashed (min_height={min_height})"
                        )));
                    }
                    None => {
                        // Target is a per-block blob (not in any squash level's
                        // block index). When a stub level exists, the target may
                        // be in the stub range (height < min_height) despite not
                        // being indexed. Open the block and verify.
                    }
                }

                // Open the back block for both the intra-range and
                // stub-range-check paths.
                conn.open_block_known_id(&back_block_hash, back_block_id)?;

                // Stub-level cross-level check: read the block's own height
                // and classify as cross-level if it falls below min_height.
                if has_stub_level {
                    use crate::chainstate::stacks::index::marf::{
                        MarfReadCtx, OWN_BLOCK_HEIGHT_KEY,
                    };
                    use crate::chainstate::stacks::index::MARFValue;

                    // Get cur_block before borrowing conn into MarfReadCtx.
                    let cur_block_for_height = conn.get_cur_block();
                    let is_stub_range = {
                        let mut height_cursor = None;
                        let mut height_scratch = MarfReadState::new();
                        let mut ctx =
                            MarfReadCtx::new(&mut conn, &mut height_cursor, &mut height_scratch);
                        let height_val: Option<MARFValue> =
                            ctx.get_by_key(&cur_block_for_height, OWN_BLOCK_HEIGHT_KEY)?;
                        match height_val {
                            Some(v) => u32::from(v) < min_height,
                            None => {
                                return Err(Error::CorruptionError(format!(
                                    "OWN_BLOCK_HEIGHT_KEY not found for block \
                                         {back_block_hash:?} (id={back_block_id})"
                                )));
                            }
                        }
                    };
                    if is_stub_range {
                        // Cross-level: in the stub range. Restore block context.
                        conn.open_block_maybe_id(&return_block, return_block_id)?;
                        block_id_to_hash
                            .entry(back_block_id)
                            .or_insert_with(|| back_block_hash.clone());
                        continue;
                    }
                }
                let resolved = ptr.from_backptr();
                let (_, bid) = conn.get_cur_block_and_id();
                (resolved, bid.unwrap_or(back_block_id))
            } else {
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                let (_, bid) = conn.get_cur_block_and_id();
                (ptr, bid.ok_or(Error::NotOpenedError)?)
            };

            // Check if already collected (shared subtree)
            let key = (node_block_id, resolved_ptr.ptr());
            if let Some(&_existing_idx) = ptr_to_idx.get(&key) {
                let (cur_block, _) = conn.get_cur_block_and_id();
                if cur_block != return_block {
                    conn.open_block_maybe_id(&return_block, return_block_id)?;
                }
                continue;
            }

            // Read and collect the node
            let read = conn.read_node_with_state(&resolved_ptr, &mut scratch)?;
            let (node, hash) = read.into_owned_node()?;
            let hash = hash.unwrap_or(TrieHash([0u8; 32]));

            let is_leaf = node.is_leaf();
            let child_ptrs: Vec<TriePtr> = if !is_leaf {
                node.ptrs()
                    .iter()
                    .filter(|p| p.id() != TrieNodeID::Empty as u8)
                    .copied()
                    .collect()
            } else {
                Vec::new()
            };

            // FullHistory: extend path with this node's path segment
            if full_history {
                path_buf.extend_from_slice(node.path_bytes());
            }

            let node_bytes = serialize_node(&node, &hash)?;
            let idx = node_store.push(&node_bytes, hash, node_block_id)?;
            ptr_to_idx.insert(key, idx);

            collected.push(CollectedNode {
                block_id: node_block_id,
                is_leaf,
            });

            // FullHistory: record the full key hash for leaves
            if full_history {
                if is_leaf && path_buf.len() == 32 {
                    leaf_key_hashes.push(Some(TrieHash(
                        path_buf[..32].try_into().expect("path_buf is 32 bytes"),
                    )));
                } else {
                    leaf_key_hashes.push(None);
                }
            }

            stats.nodes_collected += 1;
            if is_leaf {
                stats.leaves_collected += 1;
            }

            let (cur_block_for_children, cur_block_id_for_children) = conn.get_cur_block_and_id();
            let depth_after_node = path_buf.len();
            for child_ptr in child_ptrs.iter() {
                dfs_stack.push((
                    *child_ptr,
                    cur_block_for_children.clone(),
                    cur_block_id_for_children,
                    depth_after_node,
                ));
            }

            let (cur_block, _) = conn.get_cur_block_and_id();
            if cur_block != return_block {
                conn.open_block_maybe_id(&return_block, return_block_id)?;
            }
        }
    }

    node_store.flush()?;

    // Step 2b: Extend the structural closure to cover every canonical root —
    // RECLAIM-ONLY. For no-reclaim levels, marf_data still points each
    // squashed block at its original blob, so `Trie::read_root` returns the
    // correct per-block root via the original blob's `ROOT_PTR_DISK`; no
    // saved-root machinery is needed and the merged blob does not need to
    // contain the orphan subtrees.
    //
    // For reclaim levels, every squashed block is redirected to the merged
    // blob, so the merged blob must structurally cover any node referenced
    // by a per-height root. The tip-DFS alone leaves orphan subtrees out;
    // this pass adds them so the saved roots from
    // [`capture_per_height_root_nodes`] resolve at every populated chr.
    let orphan_nodes_added = if reclaim {
        let added = extend_squash_dfs_with_canonical_roots(
            &mut marf,
            &block_hashes_raw,
            &block_ids_per_height,
            &mut ptr_to_idx,
            &mut collected,
            &mut leaf_key_hashes,
            &mut node_store,
            full_history,
            Some(&mut block_id_to_hash),
        )?;
        if added > 0 {
            node_store.flush()?;
            stats.nodes_collected = collected.len() as u64;
            stats.leaves_collected = collected.iter().filter(|c| c.is_leaf).count() as u64;
        }
        added
    } else {
        0
    };

    // Time from function entry through DFS completion. Pre-DFS setup
    // (`MARF::from_path`, `verify_no_descendants`, `read_squash_levels`, the
    // contiguity check) lands inside this number — it's typically a few ms
    // for L0 and grows slowly with the number of prior squash levels.
    let phase_dfs_ms = t_start.elapsed().as_millis();

    info!(
        "Incremental squash DFS: collected {} nodes ({} leaves), {} block_id→hash entries \
         (orphan structural extension added {} nodes)",
        stats.nodes_collected,
        stats.leaves_collected,
        block_id_to_hash.len(),
        orphan_nodes_added,
    );

    // ---------------------------------------------------------------
    // Step 2.5: FullHistory leaf replacement
    //
    // Same pattern as base-level Step 3.5, but with an additional
    // baseline lookup pass: for keys whose first transition is after
    // min_height, walk the prior level's tip trie (at min_height - 1)
    // to get the inherited value and append a synthetic entry.
    // ---------------------------------------------------------------
    if full_history {
        let block_hashes_typed: Vec<T> = block_hashes_raw
            .iter()
            .map(|bhh| T::from_bytes(*bhh))
            .collect();

        let t_collect_history = Instant::now();
        let mut history =
            collect_history_parallel(&mut marf, &block_hashes_typed, min_height, max_height)?;
        phase_collect_history_ms = t_collect_history.elapsed().as_millis();

        // Keys whose single in-range write is dominated by the inherited value. Populated in the
        // `min_height > 0` branch below; used when deciding which leaves to promote to
        // `TrieLeafSquashed`.
        let mut dominated_single_keys: HashSet<TrieHash> = HashSet::new();

        // Baseline lookup: for keys whose earliest entry has height > min_height, the key was
        // inherited from a prior level. Walk the prior level's tip trie to get the inherited value
        // and inject a synthetic (min_height - 1, value) entry.
        let t_baseline = Instant::now();
        if min_height > 0 {
            let prior_tip_block =
                MarfConnection::get_block_at_height(&mut marf, min_height - 1, &tip_block)?
                    .ok_or_else(|| {
                        Error::CorruptionError(format!(
                            "No block hash found at baseline height {}",
                            min_height - 1
                        ))
                    })?;

            let keys_needing_baseline: Vec<TrieHash> = history
                .iter()
                .filter_map(|(key_hash, entries)| {
                    // entries from collect_history are ascending by height; first() is the earliest
                    // write.
                    if entries.first().map_or(false, |&(h, _)| h > min_height) {
                        Some(*key_hash)
                    } else {
                        None
                    }
                })
                .collect();
            phase_baseline_keys = keys_needing_baseline.len();

            // Parallelize the baseline `get_from_hash` lookups across worker threads.
            // Each lookup is an independent read against the same `prior_tip_block`,
            // and the prior tip lives in a previously-published squash level — so all
            // lookups are read-only against settled state with no cross-iteration
            // dependencies.
            //
            // For Stacks 2.x clarity workloads this phase dominates squash wall-time
            // at scale (~100µs per key × 100k+ keys per range). Each worker holds its
            // own read-only MARF handle (own SQL connection + mmap), so workers don't
            // contend on a shared connection. Phase B (mutating `history` and
            // `dominated_single_keys`) stays serial because the maps aren't
            // thread-safe and the mutations are O(1) per result anyway.
            //
            // Sizing: capped at `MAX_BASELINE_WORKERS` to bound mmap/SQL handle count
            // and avoid oversaturating I/O on smaller ranges. The serial fallback
            // kicks in below `MIN_KEYS_FOR_PARALLEL` because spawning + opening N
            // read-only MARF handles costs ~tens of ms — for small key counts that
            // setup overhead dwarfs the actual lookup work.
            const MAX_BASELINE_WORKERS: usize = 8;
            const MIN_KEYS_FOR_PARALLEL: usize = 1024;
            let n_workers = if keys_needing_baseline.len() < MIN_KEYS_FOR_PARALLEL {
                0
            } else {
                std::thread::available_parallelism()
                    .map(|n| n.get().min(MAX_BASELINE_WORKERS))
                    .unwrap_or(1)
                    .max(1)
                    .min(keys_needing_baseline.len())
            };

            let lookups: Vec<(TrieHash, Option<MARFValue>)> = if n_workers <= 1 {
                // Serial fallback: identical to the pre-parallelization path. Used
                // when (a) the baseline set is small enough that thread/handle
                // setup would dominate, (b) only one core is available, or
                // (c) `available_parallelism()` returns an error.
                let mut results = Vec::with_capacity(keys_needing_baseline.len());
                for key_hash in &keys_needing_baseline {
                    let val = MarfConnection::get_from_hash(&mut marf, &prior_tip_block, key_hash)?;
                    results.push((*key_hash, val));
                }
                results
            } else {
                // Pre-open N read-only MARF handles. `reopen_readonly` opens its own
                // SQL connection per handle so workers don't contend on the writer's
                // connection. Build before scope so any open error propagates as a
                // normal Err return (vs being a thread-panic inside the scope).
                //
                // Set `bypass_blob_guard` on each handle: workers do many small reads,
                // and the per-read atomic on `shared_squash.active_reads` causes cache-
                // line ping-pong across cores. Safe here because we're inside
                // `squash_level_incremental` for this MARF — no concurrent publish can
                // truncate the blob during the read phases (publish happens after).
                let mut ro_marfs: Vec<MARF<T>> = Vec::with_capacity(n_workers);
                for _ in 0..n_workers {
                    let mut ro = marf.reopen_readonly()?;
                    ro.storage_backend_mut().data.bypass_blob_guard = true;
                    ro_marfs.push(ro);
                }

                let chunk_size = keys_needing_baseline.len().div_ceil(n_workers).max(1);
                let prior_tip_block_ref = &prior_tip_block;
                let keys_ref: &[TrieHash] = &keys_needing_baseline;

                std::thread::scope(|s| -> Result<Vec<(TrieHash, Option<MARFValue>)>, Error> {
                    let handles: Vec<_> = ro_marfs
                        .iter_mut()
                        .enumerate()
                        .map(|(idx, ro_marf)| {
                            let chunk_start = (idx * chunk_size).min(keys_ref.len());
                            let chunk_end = ((idx + 1) * chunk_size).min(keys_ref.len());
                            let chunk = &keys_ref[chunk_start..chunk_end];
                            s.spawn(
                                move || -> Result<Vec<(TrieHash, Option<MARFValue>)>, Error> {
                                    let mut results = Vec::with_capacity(chunk.len());
                                    for key_hash in chunk {
                                        let val = MarfConnection::get_from_hash(
                                            ro_marf,
                                            prior_tip_block_ref,
                                            key_hash,
                                        )?;
                                        results.push((*key_hash, val));
                                    }
                                    Ok(results)
                                },
                            )
                        })
                        .collect();

                    // Drain ALL handles before returning. Using `??` to short-circuit
                    // on the first error would leave later workers unjoined; if any
                    // of those subsequently panicked, `thread::scope`'s drop would
                    // re-panic, bypassing our wrapped `Error::CorruptionError`. By
                    // joining every handle and recording only the first failure, we
                    // guarantee the wrapper fires for any worker outcome.
                    let mut all = Vec::with_capacity(keys_ref.len());
                    let mut first_err: Option<Error> = None;
                    for handle in handles {
                        match handle.join() {
                            Ok(Ok(chunk_results)) => all.extend(chunk_results),
                            Ok(Err(e)) => {
                                if first_err.is_none() {
                                    first_err = Some(e);
                                }
                            }
                            Err(_panic_payload) => {
                                if first_err.is_none() {
                                    first_err = Some(Error::CorruptionError(
                                        "Baseline-lookup worker thread panicked".into(),
                                    ));
                                }
                            }
                        }
                    }
                    if let Some(e) = first_err {
                        return Err(e);
                    }
                    Ok(all)
                })?
            };

            // Phase B (serial): apply the lookups to `history` and `dominated_single_keys`.
            // Keys whose single in-range write is byte-identical to the inherited value from the
            // prior level are recorded in `dominated_single_keys`; they can safely stay as plain
            // `TrieLeaf` because reading the same value at every height in range is correct (the
            // merged trie is only reachable from blocks within the range, where the inherited
            // value already applied before the structural re-insert).
            for (key_hash, inherited_value) in lookups {
                if let Some(value) = inherited_value {
                    if let Some(entries) = history.get_mut(&key_hash) {
                        let dominated_single = entries.len() == 1
                            && entries.first().map_or(false, |&(_, ref v)| *v == value);
                        if dominated_single {
                            dominated_single_keys.insert(key_hash);
                        } else {
                            entries.insert(0, (min_height - 1, value));
                        }
                    }
                }
                // If the key has no prior-level value, it is a new key whose first write is at h >
                // min_height. We leave `entries` single-element; the promotion filter below will
                // still convert it to `TrieLeafSquashed` so that reads in [min_height, first_write)
                // return `None`.
            }
        }
        phase_baseline_ms = t_baseline.elapsed().as_millis();

        let t_leaf_replace = Instant::now();
        let node_count_before = node_store.len();

        // Promote any leaf with an in-range write to `TrieLeafSquashed` so that historical
        // reads below the first in-range write return `None` (for new keys) or the inherited
        // baseline (for keys with an injected baseline entry above). Dominated-single keys stay
        // plain — their single in-range write matches the inherited value, so plain-leaf reads
        // are correct at every range height.
        //
        // Two-phase parallelization. Phase A (parallel) decodes each squashable
        // leaf, constructs `TrieLeafSquashed`, and serializes the new bytes —
        // all CPU-bound and per-leaf independent. `NodeStore::read_node_bytes`
        // takes `&self` and opens a fresh file handle per call, so concurrent
        // reads are safe (effectively `Sync`). Phase B (serial) applies the
        // new bytes via `node_store.update(&mut self)`.
        //
        // Pre-filter the index list serially so workers get evenly-sized
        // chunks regardless of where squashable leaves cluster in `node_store`.
        // This pre-pass is fast (slice indexing + HashMap reads only).
        let squashable: Vec<(usize, TrieHash)> = (0..node_count_before)
            .filter_map(|i| {
                if !collected[i].is_leaf {
                    return None;
                }
                let key_hash = leaf_key_hashes[i].as_ref()?;
                let transitions = history.get(key_hash)?;
                if transitions.is_empty() || dominated_single_keys.contains(key_hash) {
                    return None;
                }
                Some((i, *key_hash))
            })
            .collect();

        const LEAF_MAX_WORKERS: usize = 8;
        const LEAF_MIN_FOR_PARALLEL: usize = 1024;
        let leaf_n_workers = if squashable.len() < LEAF_MIN_FOR_PARALLEL {
            0
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get().min(LEAF_MAX_WORKERS))
                .unwrap_or(1)
                .max(1)
                .min(squashable.len())
        };

        let updates: Vec<(usize, Vec<u8>)> = if leaf_n_workers <= 1 {
            // Serial fallback: identical to the pre-parallelization path. Used
            // when (a) the squashable count is small enough that thread setup
            // would dominate, or (b) only one core is available.
            let mut results = Vec::with_capacity(squashable.len());
            for (i, key_hash) in &squashable {
                let transitions = history.get(key_hash).ok_or_else(|| {
                    Error::CorruptionError(
                        "key_hash disappeared from history between pre-filter and apply".into(),
                    )
                })?;
                let raw = node_store.read_node_bytes(*i)?;
                let new_buf = build_squashed_leaf_bytes(&raw, transitions)?;
                results.push((*i, new_buf));
            }
            results
        } else {
            let chunk_size = squashable.len().div_ceil(leaf_n_workers).max(1);
            let history_ref = &history;
            let node_store_ref = &node_store;
            let squashable_ref: &[(usize, TrieHash)] = &squashable;

            std::thread::scope(|s| -> Result<Vec<(usize, Vec<u8>)>, Error> {
                let handles: Vec<_> = (0..leaf_n_workers)
                    .map(|idx| {
                        let chunk_start = (idx * chunk_size).min(squashable_ref.len());
                        let chunk_end = ((idx + 1) * chunk_size).min(squashable_ref.len());
                        let chunk = &squashable_ref[chunk_start..chunk_end];
                        s.spawn(move || -> Result<Vec<(usize, Vec<u8>)>, Error> {
                            let mut chunk_updates = Vec::with_capacity(chunk.len());
                            for (i, key_hash) in chunk {
                                let transitions = history_ref.get(key_hash).ok_or_else(|| {
                                    Error::CorruptionError(
                                        "key_hash disappeared from history \
                                         between pre-filter and apply"
                                            .into(),
                                    )
                                })?;
                                let raw = node_store_ref.read_node_bytes(*i)?;
                                let new_buf = build_squashed_leaf_bytes(&raw, transitions)?;
                                chunk_updates.push((*i, new_buf));
                            }
                            Ok(chunk_updates)
                        })
                    })
                    .collect();

                // Drain all handles before returning (see baseline-lookup loop
                // for the rationale — leaving workers unjoined risks scope-drop
                // panics that bypass our wrapped error).
                let mut all = Vec::with_capacity(squashable_ref.len());
                let mut first_err: Option<Error> = None;
                for handle in handles {
                    match handle.join() {
                        Ok(Ok(chunk_updates)) => all.extend(chunk_updates),
                        Ok(Err(e)) => {
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                        Err(_panic_payload) => {
                            if first_err.is_none() {
                                first_err = Some(Error::CorruptionError(
                                    "Leaf-replace worker thread panicked".into(),
                                ));
                            }
                        }
                    }
                }
                if let Some(e) = first_err {
                    return Err(e);
                }
                Ok(all)
            })?
        };

        // Phase B (serial): apply updates to node_store. `update` takes `&mut self`
        // so this stays single-threaded.
        for (i, new_buf) in updates {
            node_store.update(i, &new_buf)?;
            stats.leaves_squashed += 1;
        }
        phase_leaf_replace_ms = t_leaf_replace.elapsed().as_millis();

        let t_replace_flush = Instant::now();
        node_store.flush()?;
        phase_leaf_replace_flush_ms = t_replace_flush.elapsed().as_millis();

        info!(
            "Incremental FullHistory: replaced {} leaves with TrieLeafSquashed",
            stats.leaves_squashed
        );
    }

    // Mark the boundary between FullHistory leaf replacement and Step 3+4
    // (pointer remap + offset compute) so we can attribute time to the
    // structural prep that runs before publish_squash.
    let t_remap = Instant::now();

    // ---------------------------------------------------------------
    // Step 3: Compute sequential byte offsets and remap pointers
    // ---------------------------------------------------------------

    // Identical to base level. Cross-level backpointers are not in ptr_to_idx and are left as-is
    // by remap_child_ptrs.
    let node_count = node_store.len();

    let mut node_sizes: Vec<u32> = Vec::with_capacity(node_count);
    for i in 0..node_count {
        node_sizes.push(node_store.node_byte_len(i));
    }

    let mut seq_offsets: Vec<u32> = Vec::with_capacity(node_count);
    let mut current_offset = BLOB_HEADER_SIZE as u32;
    for &size in &node_sizes {
        seq_offsets.push(current_offset);
        current_offset = checked_offset_add(current_offset, size)?;
    }

    node_store.flush()?;

    for i in 0..node_count {
        if collected[i].is_leaf {
            continue;
        }

        let raw = node_store.read_node_bytes(i)?;
        if raw.len() < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(
                "Serialized node too short for hash prefix".into(),
            ));
        }
        let hash_bytes = &raw[..TRIEHASH_ENCODED_SIZE];
        let node_body = &raw[TRIEHASH_ENCODED_SIZE..];

        let node_id_byte = *node_body
            .first()
            .ok_or_else(|| Error::CorruptionError("Empty node body during remap".into()))?;
        let node_id = clear_backptr(node_id_byte) & 0x3f;
        let (mut node, _consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;

        remap_child_ptrs(&mut node, &collected[i], &ptr_to_idx, &seq_offsets)?;

        let mut new_buf = Vec::with_capacity(raw.len());
        new_buf.extend_from_slice(hash_bytes);
        node.write_bytes(&mut new_buf)?;

        node_store.update(i, &new_buf)?;
        node_sizes[i] = new_buf.len() as u32;
    }

    node_store.flush()?;

    current_offset = BLOB_HEADER_SIZE as u32;
    for i in 0..node_count {
        seq_offsets[i] = current_offset;
        current_offset = checked_offset_add(current_offset, node_sizes[i])?;
    }

    // ---------------------------------------------------------------
    // Step 4: Recompute hashes bottom-up (backpointer-aware)
    // ---------------------------------------------------------------

    // Build block map for consensus byte hash computation. Covers all block_ids that appear as
    // backpointer targets (intra-level from height metadata, cross-level from DFS detection).
    let mut block_map = IncrementalSquashBlockMap { block_id_to_hash };

    for i in (0..node_count).rev() {
        if collected[i].is_leaf {
            continue;
        }

        let raw = node_store.read_node_bytes(i)?;
        if raw.len() < TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(
                "Serialized node too short for hash prefix in rehash pass".into(),
            ));
        }
        let node_body = &raw[TRIEHASH_ENCODED_SIZE..];
        let node_id_byte = *node_body
            .first()
            .ok_or_else(|| Error::CorruptionError("Empty node body during rehash".into()))?;
        let node_id = clear_backptr(node_id_byte) & 0x3f;
        let (node, _consumed) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;

        let child_hashes: Vec<TrieHash> = node
            .ptrs()
            .iter()
            .map(|child_ptr| {
                if child_ptr.id() == TrieNodeID::Empty as u8 {
                    return Ok(TrieHash::EMPTY);
                }
                // All backpointers (intra-level preserved + cross-level) use the
                // ancestor block hash as child hash, matching canonical MARF behavior
                // in inner_write_children_hashes.
                if is_backptr(child_ptr.id()) {
                    let bhh = block_map
                        .block_id_to_hash
                        .get(&child_ptr.back_block())
                        .ok_or_else(|| {
                            Error::CorruptionError(format!(
                                "Missing block hash for backptr target block_id {} during rehash",
                                child_ptr.back_block()
                            ))
                        })?;
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(bhh.as_bytes());
                    return Ok(TrieHash(hash_bytes));
                }
                // Direct children: look up computed hash via binary search on seq_offsets
                let child_offset = child_ptr.ptr();
                if let Ok(child_idx) = seq_offsets.binary_search(&child_offset) {
                    Ok(*node_store.hash(child_idx))
                } else {
                    warn!(
                        "Could not find child node at offset {} during rehash",
                        child_offset
                    );
                    Ok(TrieHash::EMPTY)
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let new_hash = compute_node_hash::<T, _>(&node, &child_hashes, &mut block_map)?;
        node_store.set_hash(i, new_hash);

        let mut new_buf = Vec::with_capacity(raw.len());
        new_buf.extend_from_slice(new_hash.as_bytes());
        new_buf.extend_from_slice(node_body);
        node_store.update(i, &new_buf)?;
        node_sizes[i] = new_buf.len() as u32;
    }

    node_store.flush()?;

    current_offset = BLOB_HEADER_SIZE as u32;
    for i in 0..node_count {
        seq_offsets[i] = current_offset;
        current_offset = checked_offset_add(current_offset, node_sizes[i])?;
    }

    let squash_root_hash = *node_store.hash(0);
    let archival_root_hash = root_hashes.last().copied().unwrap_or(TrieHash::EMPTY);

    // Capture per-height root nodes (post-remap) so that
    // `MARF::root_copy` can rebuild the correct fork-extension root for any
    // non-tip squashed parent. RECLAIM-ONLY: for no-reclaim levels, original
    // blobs are preserved and `Trie::read_root` returns the right per-block
    // root via the original blob, so the saved roots aren't consulted. Must
    // run before the source blobs are touched by the publish_squash closure
    // (pwrite + ftruncate).
    let per_height_root_node_bodies = if reclaim {
        capture_per_height_root_nodes(
            &mut marf,
            &block_hashes_raw,
            &block_ids_per_height,
            &ptr_to_idx,
            &seq_offsets,
        )?
    } else {
        Vec::new()
    };

    // Publish the per-height root sidecar BEFORE entering `publish_squash`'s
    // arm region. A failure here returns an error from this function with no
    // chainstate mutation having occurred. After arm, the
    // `marf_squash_levels.root_sidecar_present` flag is set to `true` inside
    // the same SQL transaction that registers the level, so SQL is the
    // source of truth and any orphan sidecar from a crash between rename
    // and SQL commit is reaped by startup orphan-scan.
    let sidecar_published = if reclaim {
        write_squash_root_sidecar(
            Path::new(marf_path),
            next_level_id,
            min_height,
            max_height,
            per_height_root_node_bodies,
        )?;
        true
    } else {
        false
    };

    // ---------------------------------------------------------------
    // Step 5: Stream blob and finalize (in-place on same MARF)
    // ---------------------------------------------------------------
    // Build the trailer into a separate buffer (small relative to node data).
    let mut sorted_block_entries: Vec<([u8; 32], u32, u32)> = block_hashes_raw
        .iter()
        .zip(block_ids_per_height.iter())
        .enumerate()
        .map(|(i, (bhh, &bid))| (*bhh, min_height + i as u32, bid))
        .collect();
    sorted_block_entries.sort_by_key(|(bhh, _, _)| *bhh);

    let trailer = SquashTrailer {
        info: SquashInfo {
            mode,
            level_id: next_level_id,
            min_height,
            max_height,
            archival_root: archival_root_hash,
            squash_root: squash_root_hash,
        },
        root_hashes,
        block_hashes: block_hashes_raw,
        sorted_block_entries,
    };

    // Write blob and update DB (in-place on the same MARF), under the shared-blob
    // quiesce so concurrent readers on other handles can't see torn mmap views or
    // SIGBUS on the `ftruncate`.
    //
    // `publish_squash` handles the strict ordering:
    //   1. set `truncate_pending`
    //   2. wait for `active_reads` to drain (readers holding `BlobReadGuard`s finish)
    //   3. run this closure — the actual mutation + metadata rebuild
    //   4. install the returned `SquashMeta` atomically
    //   5. bump the shared generation (triggers per-handle refresh on next read)
    //   6. clear `truncate_pending`
    //
    // Because we publish BEFORE clearing `truncate_pending`, any reader that wakes
    // up is guaranteed to see the new generation and re-sync its local state.
    let phase_remap_ms = t_remap.elapsed().as_millis();

    let t_publish_call = Instant::now();
    // Capture `closure_start` inside the closure to separate publish_squash's
    // own overhead (lock acquisition + quiesce wait) from the closure's work.
    let mut closure_start_ms: Option<u128> = None;
    let shared = Arc::clone(&marf.storage.data.shared_squash);
    shared.publish_squash(|guard| -> Result<SquashMeta, Error> {
        closure_start_ms = Some(t_publish_call.elapsed().as_millis());
        let storage = marf.storage_backend_mut();

        // ── Preflight (safe-to-retry): everything that can return Err WITHOUT leaving
        // partially-mutated SQL rows or a partially-written blob behind.
        // `create_squash_levels_table` is `CREATE TABLE IF NOT EXISTS` DDL — it does
        // mutate schema state, but the mutation is idempotent (retrying succeeds), so
        // an Err on a fresh DB just leaves the table absent and the next attempt
        // recreates it cleanly. Anything beyond this block is part of the irreversible
        // mutation phase covered by `guard.arm()`.
        trie_sql::create_squash_levels_table(storage.sqlite_conn())?;

        let (blob_offset, superseded_for_prune) = if reclaim {
            let write_offset = if let Some(top_prior) = existing_levels.last() {
                top_prior.blob_offset + top_prior.blob_length
            } else {
                0
            };
            let superseded: Vec<T> = trailer
                .block_hashes
                .iter()
                .map(|bhh| T::from_bytes(*bhh))
                .collect();
            (write_offset, Some(superseded))
        } else {
            (storage.get_blob_append_offset()?, None)
        };

        // ── Mutation phase begins. From here on, every operation is irreversible:
        //    * `prune_orphaned_external_refs` zeroes `external_offset`/`length` on
        //      non-canonical rows in `marf_data` — partial success leaves the SQL
        //      state with pruned refs that no published squash level claims.
        //    * `validate_truncation_zone` is read-only but runs AFTER pruning, so
        //      any Err it surfaces is post-mutation.
        //    * `pwrite`, `ftruncate`, and `remap_and_invalidate` are all
        //      irreversible blob mutations.
        //    * The post-write SQL updates (`write_squash_level`,
        //      `update_external_trie_blob_by_hash`) depend on the new blob layout.
        //
        // Any Err past `arm()` is upgraded to `process::abort` by `publish_squash`.
        guard.arm();

        let t_prune = Instant::now();
        if let Some(superseded) = superseded_for_prune {
            let pruned = trie_sql::prune_orphaned_external_refs(
                storage.sqlite_conn(),
                blob_offset,
                &superseded,
            )?;
            if pruned > 0 {
                warn!(
                    "Pruned {pruned} non-canonical external trie ref(s) in reclaim \
                     truncation zone (offset >= {blob_offset})"
                );
            }

            trie_sql::validate_truncation_zone(storage.sqlite_conn(), blob_offset, &superseded)?;
        }
        phase_prune_ms = t_prune.elapsed().as_millis();

        let t_blob_write = Instant::now();
        // Stream header
        let mut write_pos = blob_offset;
        let mut header = [0u8; BLOB_HEADER_SIZE as usize];
        header[..32].copy_from_slice(tip_block.as_bytes());
        storage.pwrite_blob_chunk(&header, write_pos)?;
        write_pos += BLOB_HEADER_SIZE;

        // Stream nodes through a fixed-size write buffer (1 MB)
        const WRITE_BUF_CAP: usize = 1 << 20;
        let mut write_buf: Vec<u8> = Vec::with_capacity(WRITE_BUF_CAP);

        for i in 0..node_count {
            let node_bytes = node_store.read_node_bytes(i)?;
            if write_buf.len() + node_bytes.len() > WRITE_BUF_CAP && !write_buf.is_empty() {
                storage.pwrite_blob_chunk(&write_buf, write_pos)?;
                write_pos += write_buf.len() as u64;
                write_buf.clear();
            }
            write_buf.extend_from_slice(&node_bytes);
        }
        if !write_buf.is_empty() {
            storage.pwrite_blob_chunk(&write_buf, write_pos)?;
            write_pos += write_buf.len() as u64;
            write_buf.clear();
        }

        stats.blob_bytes = write_pos - blob_offset;

        // Write trailer
        let trailer_offset_in_blob = write_pos - blob_offset;
        let mut trailer_buf = Vec::new();
        let trailer_bytes_written = trailer.write_to(&mut trailer_buf)?;
        stats.trailer_bytes = trailer_bytes_written + SQUASH_FOOTER_SIZE as u64;
        SquashTrailer::write_footer(&mut trailer_buf, trailer_offset_in_blob)?;

        storage.pwrite_blob_chunk(&trailer_buf, write_pos)?;
        write_pos += trailer_buf.len() as u64;

        let blob_len = write_pos - blob_offset;
        phase_blob_write_ms = t_blob_write.elapsed().as_millis();

        // Finalize: sync, optionally truncate, remap.
        //
        // For reclaim, capture the on-disk file length BEFORE `finish_blob_write`
        // so we can report bytes actually freed by the truncate. The pwrite
        // calls above may have *grown* the file (if `write_pos` extends past
        // the prior end) — we want the size right before the ftruncate, which
        // is exactly the file's length now.
        let t_finish_blob = Instant::now();
        if reclaim {
            let pre_truncate_len = storage.get_blob_file_len()?;
            storage.finish_blob_write(Some(write_pos))?;
            let freed = pre_truncate_len.saturating_sub(write_pos);
            info!(
                "Reclaimed dead blob space: wrote {} ({}) at offset {}, \
                 truncated file from {} to {} (freed {})",
                blob_len,
                fmt_bytes(blob_len),
                blob_offset,
                fmt_bytes(pre_truncate_len),
                fmt_bytes(write_pos),
                fmt_bytes(freed),
            );
        } else {
            storage.finish_blob_write(None)?;
        }
        phase_finish_blob_ms = t_finish_blob.elapsed().as_millis();

        let t_sql_updates = Instant::now();
        let row = SquashLevelRow {
            level_id: next_level_id,
            min_height,
            max_height,
            blob_offset,
            blob_length: blob_len,
            reads_redirected: reclaim,
            // Set inside the same SQL transaction that registers the level,
            // so SQL is the durable source of truth: row visible ⇒ sidecar
            // is on disk. Any rename-but-no-SQL crash leaves an orphan that
            // startup reconciliation deletes.
            root_sidecar_present: sidecar_published,
            root_sidecar_trimmed: false,
        };
        trie_sql::write_squash_level(storage.sqlite_conn(), &row)?;

        if reclaim {
            for bhh_bytes in &trailer.block_hashes {
                let bhh = T::from_bytes(*bhh_bytes);
                trie_sql::update_external_trie_blob_by_hash(
                    storage.sqlite_conn(),
                    &bhh,
                    blob_offset,
                    blob_len,
                )?;
            }
        }
        phase_sql_updates_ms = t_sql_updates.elapsed().as_millis();

        // Build the fresh SquashMeta snapshot from the just-updated SQL + blob file.
        // `publish_squash` will install it atomically with the generation bump.
        let t_build_meta = Instant::now();
        let result = build_squash_meta_from_sql(storage.sqlite_conn(), storage.blobs.as_ref());
        phase_build_meta_ms = t_build_meta.elapsed().as_millis();
        result
    })?;
    // `publish_squash` pre-closure overhead = lock acquisition + quiesce wait
    // for in-flight `BlobReadGuard`s to drain. Captured by the time delta from
    // `t_publish_call` until the closure body started running.
    let phase_publish_overhead_ms = closure_start_ms.unwrap_or(0);

    node_store.finish()?;

    // Trim per-height root snapshot sidecars that have aged past the
    // configured retention window. Runs AFTER `publish_squash` has
    // committed the new level so it operates on the latest level set.
    //
    // **Swallow errors deliberately**: the squash itself has already
    // succeeded and been published at this point, and trim is
    // best-effort disk hygiene — any error here (e.g. a transient
    // SQLite read failure inside `read_squash_levels`) is logged and
    // retried on the next squash. Returning `Err` from
    // `squash_level_incremental` after a successful publish would
    // imply the squash failed, which is misleading. Sidecar trim is
    // only meaningful for reclaim levels (no-reclaim never wrote one).
    if reclaim {
        match trim_aged_root_sidecars(
            &mut marf,
            Path::new(marf_path),
            next_level_id,
            MARF_ROOT_SNAPSHOT_RETENTION_LEVELS,
        ) {
            Ok(trim_report) => {
                if trim_report.levels_trimmed > 0
                    || trim_report.trim_failures > 0
                    || trim_report.unlink_failures > 0
                {
                    info!(
                        "MARF squash root-sidecar trim after level {next_level_id}: \
                         levels_trimmed={}, already_trimmed={}, trim_failures={}, \
                         unlink_failures={} \
                         (retention_levels={MARF_ROOT_SNAPSHOT_RETENTION_LEVELS})",
                        trim_report.levels_trimmed,
                        trim_report.already_trimmed,
                        trim_report.trim_failures,
                        trim_report.unlink_failures,
                    );
                }
            }
            Err(e) => {
                warn!(
                    "MARF squash root-sidecar trim after level {next_level_id} failed: \
                     {e:?}. The squash itself is fully committed; trim will be \
                     retried after the next squash."
                );
            }
        }
    }

    let total_ms = t_start.elapsed().as_millis();

    info!(
        "Incremental squash level {} complete: {} nodes, {} blob bytes, {} trailer bytes",
        next_level_id, stats.nodes_collected, stats.blob_bytes, stats.trailer_bytes
    );

    // Phase-timing summary. Sums may not equal total exactly: setup time before
    // DFS, small inter-phase gaps (e.g. log calls, struct construction), and
    // sub-millisecond rounding all land in the unattributed remainder. The
    // intent is order-of-magnitude attribution to identify the dominant phase
    // for parallelization, not a perfect breakdown.
    info!(
        "Squash level {} phase timing (ms): \
         dfs={}, collect_history={}, baseline={}({} keys), \
         leaf_replace={}, leaf_replace_flush={}, \
         remap={}, publish_overhead={}, prune={}, \
         blob_write={}, finish_blob={}, sql_updates={}, build_meta={}, total={}",
        next_level_id,
        phase_dfs_ms,
        phase_collect_history_ms,
        phase_baseline_ms,
        phase_baseline_keys,
        phase_leaf_replace_ms,
        phase_leaf_replace_flush_ms,
        phase_remap_ms,
        phase_publish_overhead_ms,
        phase_prune_ms,
        phase_blob_write_ms,
        phase_finish_blob_ms,
        phase_sql_updates_ms,
        phase_build_meta_ms,
        total_ms,
    );

    Ok(stats)
}

/// Create a stub squash level covering `min_height..=max_height` with no actual squash blob. Used
/// by the late-enablement guard when the first L0 range exceeds [`STUB_THRESHOLD`].
///
/// The stub satisfies the contiguity precondition for subsequent real levels. Reads for blocks in
/// the stub range continue to use original per-block blobs. `blob_offset` is set to the current end
/// of the blob file so that future reclaim operations do not truncate per-block data.
pub fn create_stub_level<T: MarfTrieId>(
    marf_path: &str,
    min_height: u32,
    max_height: u32,
) -> Result<(), Error> {
    let open_opts = MARFOpenOpts {
        hash_calculation_mode: TrieHashCalculationMode::Immediate,
        cache_strategy: "noop".to_string(),
        external_blobs: true,
        force_db_migrate: false,
        compress: false,
        mmap: false,
        squash_mode: SquashMode::TipOnly,
    };

    let mut marf = MARF::<T>::from_path(marf_path, open_opts)?;

    // Guard: stub levels are only valid as the first level (L0). If levels already exist, this is a
    // programming error — the caller should have checked squash_min_height_for_marf() and skipped
    // the stub path.
    let existing = trie_sql::read_squash_levels(marf.sqlite_conn())?;
    if !existing.is_empty() {
        return Err(Error::NotSupportedError(
            "Cannot create stub level: squash levels already exist".into(),
        ));
    }

    let blob_offset = {
        let storage = marf.storage_backend_mut();
        trie_sql::create_squash_levels_table(storage.sqlite_conn())?;
        let offset = storage.get_blob_append_offset()?;

        let row = SquashLevelRow {
            level_id: 0,
            min_height,
            max_height,
            blob_offset: offset,
            blob_length: 0,
            reads_redirected: false,
            root_sidecar_present: false,
            root_sidecar_trimmed: false,
        };
        trie_sql::write_squash_level(storage.sqlite_conn(), &row)?;
        offset
    };

    info!(
        "Created stub squash level 0 covering heights {min_height}..={max_height} \
         (blob_offset={blob_offset}, no blob data)"
    );

    Ok(())
}
