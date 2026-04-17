// Squash pipeline code uses bounded-index loops (`0..node_count`) over
// parallel arrays that are always the same length. The indices are
// correct by construction; `.get()` would add noise without safety.
#![allow(clippy::indexing_slicing)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, TrieLeafSquashed, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
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
    /// (block_hash, height) pairs sorted by block_hash for binary search.
    pub sorted_block_entries: Vec<([u8; 32], u32)>,
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
            .binary_search_by_key(bhh, |(hash, _)| *hash)
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

        // --- BlockHash→Height (sorted) ---
        let count = self.sorted_block_entries.len() as u32;
        w.write_all(&count.to_be_bytes())?;
        written += 4;
        for (bhh, height) in &self.sorted_block_entries {
            w.write_all(bhh)?;
            w.write_all(&height.to_be_bytes())?;
            written += 36;
        }

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
    /// `trailer_offset` is the byte offset of the trailer start relative
    /// to the blob start.
    pub fn write_footer<W: Write>(w: &mut W, trailer_offset: u64) -> Result<(), Error> {
        w.write_all(&trailer_offset.to_be_bytes())?;
        w.write_all(&SQUASH_MAGIC)?;
        Ok(())
    }

    /// Read the 12-byte footer from the last 12 bytes of a blob.
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

    /// Deserialize a trailer from a byte slice starting at `offset` within
    /// the blob. The slice should start at the trailer (after all trie nodes).
    pub fn read_from(bytes: &[u8]) -> Result<Self, Error> {
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

        // --- BlockHash→Height (sorted) ---
        let sorted_count = read_u32_be(bytes, &mut pos)?;
        let mut sorted_block_entries = Vec::with_capacity(sorted_count as usize);
        for _ in 0..sorted_count {
            let end = pos + 36;
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
            sorted_block_entries.push((bhh, height));
            pos = end;
        }

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
    /// Records the byte offset, length, hash, and block_id.
    /// Returns the index of the newly stored node.
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

/// Precomputed `TrieHash` of `OWN_BLOCK_HEIGHT_KEY`. This is a
/// single pathological key written every block with a different value;
/// storing its full history would produce a leaf of unbounded size.
/// Filtered during history collection (see design doc §4.5).
static OWN_BLOCK_HEIGHT_KEY_HASH: std::sync::LazyLock<TrieHash> =
    std::sync::LazyLock::new(|| TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY));

/// Returns `true` if `key_hash` belongs to a MARF-internal key that
/// must be excluded from FullHistory history collection. Currently
/// filters only `OWN_BLOCK_HEIGHT_KEY`.
fn is_marf_internal_key(key_hash: &TrieHash) -> bool {
    *key_hash == *OWN_BLOCK_HEIGHT_KEY_HASH
}

/// Walk the locally-written subtree of the currently-opened block,
/// invoking `callback` for every leaf written at this block height.
///
/// "Locally-written" means we descend only into non-backpointer
/// children — backpointer children belong to earlier blocks and are
/// skipped. This visits exactly the connected subtree of nodes COW'd
/// into the current block.
///
/// The callback receives the reconstructed full `TrieHash` key path
/// (32 bytes accumulated from the root's path segment + branch bytes
/// + each descendant's path segment) and a clone of the leaf's
/// `MARFValue`.
fn walk_local_leaves<T: MarfTrieId, F>(
    conn: &mut impl TrieReadStorage<T>,
    callback: &mut F,
) -> Result<(), Error>
where
    F: FnMut(&TrieHash, MARFValue),
{
    let root_ptr = conn.root_trieptr();
    let mut scratch = MarfReadState::new();

    // Single mutable path buffer with push/pop. Each stack entry
    // records (ptr, parent_depth): the path_buf length to restore
    // before adding this child's chr byte. The root is special-cased
    // (no chr byte; parent_depth = 0).
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
/// For each block height in `min_height..=max_height`, opens the block
/// and walks only its locally-written subtree to find leaves. Builds
/// a map from full `TrieHash` key → `Vec<(height, MARFValue)>` sorted
/// ascending by height.
///
/// Structural-rewrite duplicates (from `promote_leaf_to_node4`) are
/// filtered by comparing each new value against the last entry for
/// that key — if the value is byte-identical, the entry is skipped.
///
/// The `OWN_BLOCK_HEIGHT_KEY` is excluded (see `is_marf_internal_key`).
///
/// `block_hashes` must be a slice of length `max_height - min_height + 1`
/// where `block_hashes[i]` is the block hash at height `min_height + i`.
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

    for h in min_height..=max_height {
        let block_hash = &block_hashes[(h - min_height) as usize];
        conn.open_block(block_hash)?;

        walk_local_leaves(&mut conn, &mut |full_key_hash, leaf_value| {
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
    // Step 2: Collect per-height metadata (block hashes, root hashes)
    // ---------------------------------------------------------------
    let mut root_hashes: Vec<TrieHash> = Vec::with_capacity((max_height + 1) as usize);
    let mut block_hashes_raw: Vec<[u8; 32]> = Vec::with_capacity((max_height + 1) as usize);

    for h in 0..=max_height {
        let block_hash_at_h = src_marf
            .get_block_at_height(h, &tip_block)?
            .ok_or_else(|| Error::CorruptionError(format!("No block hash found at height {h}")))?;

        let root_hash = src_marf.get_root_hash_at(&block_hash_at_h)?;

        let mut bhh_bytes = [0u8; 32];
        bhh_bytes.copy_from_slice(block_hash_at_h.as_bytes());
        block_hashes_raw.push(bhh_bytes);
        root_hashes.push(root_hash);
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

    info!(
        "Squash DFS: collected {} nodes ({} leaves)",
        stats.nodes_collected, stats.leaves_collected
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
            let transitions = match history.get(key_hash) {
                Some(t) if t.len() > 1 => t,
                _ => continue, // single-write or internal key: keep as plain TrieLeaf
            };

            // Read the existing serialized leaf to get its hash and path bytes
            let raw = node_store.read_node_bytes(i)?;
            if raw.len() < TRIEHASH_ENCODED_SIZE {
                return Err(Error::CorruptionError(
                    "Serialized leaf too short for hash prefix".into(),
                ));
            }
            let hash_bytes = &raw[..TRIEHASH_ENCODED_SIZE];

            // Decode the leaf to get its path (NodePath)
            let node_body = &raw[TRIEHASH_ENCODED_SIZE..];
            let node_id_byte = *node_body.first().ok_or_else(|| {
                Error::CorruptionError("Empty node body during FullHistory leaf replace".into())
            })?;
            let node_id = clear_backptr(node_id_byte) & 0x3f;
            let (existing_node, _) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;
            let path_slice = existing_node.path_bytes();

            // Build the TrieLeafSquashed: entries must be sorted descending by height
            let mut entries: Vec<(u32, MARFValue)> = transitions.clone();
            entries.reverse(); // history map is ascending; TrieLeafSquashed wants descending

            let squashed = TrieLeafSquashed::new(path_slice, entries)?;

            // Re-serialize with the same hash (hash covers tip value only)
            let squashed_node = TrieNodeType::LeafSquashed(squashed);
            let mut new_buf =
                Vec::with_capacity(TRIEHASH_ENCODED_SIZE + squashed_node.byte_len() + 1);
            new_buf.extend_from_slice(hash_bytes);
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

    // Stream the blob to the destination file in chunks to avoid holding the
    // entire 2+ GB node payload in memory at once.

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

        let mut sorted_block_entries: Vec<([u8; 32], u32)> = block_hashes_raw
            .iter()
            .enumerate()
            .map(|(i, bhh)| (*bhh, i as u32))
            .collect();
        sorted_block_entries.sort_by_key(|(bhh, _)| *bhh);

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

        // Register the squash level in the DB
        let row = SquashLevelRow {
            level_id: 0,
            min_height,
            max_height,
            blob_offset,
            blob_length: blob_len,
            reads_redirected: true,
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

/// Serialize a node as: hash_bytes (32) + node_body.
fn serialize_node(node: &TrieNodeType, hash: &TrieHash) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE + node.byte_len() + 1);
    buf.extend_from_slice(hash.as_bytes());
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
                // Intra-level backpointer: preserve backptr bit and original back_block.
                // Only update the ptr offset to the new blob-local position.
                // This maintains correct canonical hashing (consensus bytes use
                // block_hash(back_block)) and prevents COW from re-targeting the pointer.
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
/// Used during rehash of incremental squash blobs where backpointers are preserved.
/// Consensus bytes need the actual block hash for each backpointer target.
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
/// `bits::get_node_hash`. The provided `BlockMap` resolves backpointer block IDs to
/// block hashes for the consensus bytes contribution.
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
    let squash_index = marf.storage.data.squash_block_index.clone();

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
pub fn squash_level_incremental<T: MarfTrieId>(
    marf_path: &str,
    mode: SquashMode,
    min_height: u32,
    max_height: u32,
    reclaim: bool,
) -> Result<SquashStats, Error> {
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

    // Snapshot the squash block index for cross-level detection during DFS. This must be cloned
    // before the mutable storage borrow in the DFS block.
    let squash_index = marf.storage.data.squash_block_index.clone();

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
                    Some(&(_, h, _, _)) if h < min_height => {
                        // Cross-level backpointer: record block_id → block_hash for
                        // consensus hash computation. No need to read the target node;
                        // the child hash contribution is the ancestor block hash.
                        block_id_to_hash
                            .entry(back_block_id)
                            .or_insert_with(|| back_block_hash.clone());
                        continue;
                    }
                    Some(&(_, h, _, _)) => {
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

    info!(
        "Incremental squash DFS: collected {} nodes ({} leaves), {} block_id→hash entries",
        stats.nodes_collected,
        stats.leaves_collected,
        block_id_to_hash.len()
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

        let mut history = collect_history(&mut marf, &block_hashes_typed, min_height, max_height)?;

        // Baseline lookup: for keys whose earliest entry has height > min_height,
        // the key was inherited from a prior level. Walk the prior level's tip trie
        // to get the inherited value and inject a synthetic (min_height - 1, value) entry.
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
                    // entries from collect_history are ascending by height;
                    // first() is the earliest write.
                    if entries.first().map_or(false, |&(h, _)| h > min_height) {
                        Some(*key_hash)
                    } else {
                        None
                    }
                })
                .collect();

            for key_hash in &keys_needing_baseline {
                if let Some(inherited_value) =
                    MarfConnection::get_from_hash(&mut marf, &prior_tip_block, key_hash)?
                {
                    if let Some(entries) = history.get_mut(key_hash) {
                        // Only skip the baseline when the key has a single entry with the
                        // same value — it will stay as a plain TrieLeaf and doesn't need
                        // a synthetic entry. For multi-entry keys (which become
                        // TrieLeafSquashed), always add the baseline so that
                        // value_at_height covers heights before the first in-range write.
                        let dominated_single = entries.len() == 1
                            && entries
                                .first()
                                .map_or(false, |&(_, ref v)| *v == inherited_value);
                        if !dominated_single {
                            entries.insert(0, (min_height - 1, inherited_value));
                        }
                    }
                }
            }
        }

        let node_count_before = node_store.len();
        for i in 0..node_count_before {
            if !collected[i].is_leaf {
                continue;
            }
            let key_hash = match &leaf_key_hashes[i] {
                Some(kh) => kh,
                None => continue,
            };
            let transitions = match history.get(key_hash) {
                Some(t) if t.len() > 1 => t,
                _ => continue, // single-write or internal key: keep as plain TrieLeaf
            };

            // Read the existing serialized leaf to get its hash and path bytes
            let raw = node_store.read_node_bytes(i)?;
            if raw.len() < TRIEHASH_ENCODED_SIZE {
                return Err(Error::CorruptionError(
                    "Serialized leaf too short for hash prefix".into(),
                ));
            }
            let hash_bytes = &raw[..TRIEHASH_ENCODED_SIZE];

            // Decode the leaf to get its path (NodePath)
            let node_body = &raw[TRIEHASH_ENCODED_SIZE..];
            let node_id_byte = *node_body.first().ok_or_else(|| {
                Error::CorruptionError("Empty node body during FullHistory leaf replace".into())
            })?;
            let node_id = clear_backptr(node_id_byte) & 0x3f;
            let (existing_node, _) = bits::decode_nodetype_from_slice_at_head(node_body, node_id)?;
            let path_slice = existing_node.path_bytes();

            // Build the TrieLeafSquashed: entries must be sorted descending by height
            let mut entries: Vec<(u32, MARFValue)> = transitions.clone();
            entries.reverse(); // history map is ascending; TrieLeafSquashed wants descending

            let squashed = TrieLeafSquashed::new(path_slice, entries)?;

            // Re-serialize with the same hash (hash covers tip value only)
            let squashed_node = TrieNodeType::LeafSquashed(squashed);
            let mut new_buf =
                Vec::with_capacity(TRIEHASH_ENCODED_SIZE + squashed_node.byte_len() + 1);
            new_buf.extend_from_slice(hash_bytes);
            squashed_node.write_bytes(&mut new_buf)?;

            node_store.update(i, &new_buf)?;
            stats.leaves_squashed += 1;
        }

        node_store.flush()?;

        info!(
            "Incremental FullHistory: replaced {} leaves with TrieLeafSquashed",
            stats.leaves_squashed
        );
    }

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

    // Build block map for consensus byte hash computation. Covers all block_ids
    // that appear as backpointer targets (intra-level from height metadata,
    // cross-level from DFS detection).
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

    // ---------------------------------------------------------------
    // Step 5: Stream blob and finalize (in-place on same MARF)
    // ---------------------------------------------------------------
    // Build the trailer into a separate buffer (small relative to node data).
    let mut sorted_block_entries: Vec<([u8; 32], u32)> = block_hashes_raw
        .iter()
        .enumerate()
        .map(|(i, bhh)| (*bhh, min_height + i as u32))
        .collect();
    sorted_block_entries.sort_by_key(|(bhh, _)| *bhh);

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

    // Write blob and update DB (in-place on the same MARF)
    {
        let storage = marf.storage_backend_mut();

        trie_sql::create_squash_levels_table(storage.sqlite_conn())?;

        let blob_offset = if reclaim {
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

            let pruned = trie_sql::prune_orphaned_external_refs(
                storage.sqlite_conn(),
                write_offset,
                &superseded,
            )?;
            if pruned > 0 {
                warn!(
                    "Pruned {pruned} non-canonical external trie ref(s) in reclaim \
                     truncation zone (offset >= {write_offset})"
                );
            }

            trie_sql::validate_truncation_zone(storage.sqlite_conn(), write_offset, &superseded)?;

            write_offset
        } else {
            storage.get_blob_append_offset()?
        };

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

        // Finalize: sync, optionally truncate, remap
        if reclaim {
            storage.finish_blob_write(Some(write_pos))?;
            info!(
                "Reclaimed dead blob space: wrote {} bytes at offset {}, truncated file",
                blob_len, blob_offset
            );
        } else {
            storage.finish_blob_write(None)?;
        }

        let row = SquashLevelRow {
            level_id: next_level_id,
            min_height,
            max_height,
            blob_offset,
            blob_length: blob_len,
            reads_redirected: reclaim,
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
    }

    node_store.finish()?;

    info!(
        "Incremental squash level {} complete: {} nodes, {} blob bytes, {} trailer bytes",
        next_level_id, stats.nodes_collected, stats.blob_bytes, stats.trailer_bytes
    );

    Ok(stats)
}

/// Create a stub squash level covering `min_height..=max_height` with no
/// actual squash blob. Used by the late-enablement guard when the first L0
/// range exceeds [`STUB_THRESHOLD`].
///
/// The stub satisfies the contiguity precondition for subsequent real
/// levels. Reads for blocks in the stub range continue to use original
/// per-block blobs. `blob_offset` is set to the current end of the blob
/// file so that future reclaim operations do not truncate per-block data.
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

    // Guard: stub levels are only valid as the first level (L0). If levels
    // already exist, this is a programming error — the caller should have
    // checked squash_min_height_for_marf() and skipped the stub path.
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
