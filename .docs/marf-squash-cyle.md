# MARF Squash Engine — Implementation Plan

> **Author**: Cyle Witruk
> **Date**: 2026-04-08 (rev. 3)
> **Branch**: `perf/marf-squash-cyle` (based on `perf/marf-read-refactor`)
> **Companion doc**: [`.docs/marf-squash-analysis.md`](.docs/marf-squash-analysis.md)

---

## Implementation Status

**What is implemented** (branch `perf/marf-squash-cyle`):

- `TrieLeafSquashed` type with full wire format, `TrieNode` trait impl,
  consensus hashing, and integration across all decode/scratch/read paths
- `SquashTrailer` per-level blob trailer with O(1)/O(log N) lookups
- `marf_squash_levels` SQL registry + optimised trailer loading
- Base-level (level 0) squash pipeline with `TipOnly` mode: DFS
  collection, pointer remapping, canonical hash recomputation, blob
  streaming with trailer
- Incremental `TipOnly` squash (`squash_level_incremental`): in-place
  on same MARF, cross-level boundary detection via `squash_block_index`,
  hash-only prefetch for cross-level children, contiguous prior-level
  coverage validation, confirmed-only descendant check
- Runtime integration: trailer loading on MARF open, squash-aware
  `open_block_impl` with `cur_block_trie_offset` caching, proof errors
  for squash-range blocks (both trait and inherent methods)
- Post-squash COW: `walk_cow`, `node_copy_update`, `add_value`,
  `promote_leaf_to_node4`, and proof walks accept `LeafSquashed`
- Decode fixes: slow path uses stored node ID (not ptr hint) for both
  buffer sizing and dispatch; `to_owned_node()` preserves `LeafSquashed`
  type (COW flattening is explicit at `node_child_copy`)
- 13 tests (unit + integration), 241 existing MARF tests pass

**What is NOT yet implemented** (follow-up work):

- `FullHistory` mode: pipeline step 3 (history collection), read-path
  `value_at_height()` integration, inherited baseline for incremental
  levels
- Cross-level `TrieNodePatch` diffs in squash output (see incremental
  design doc section 5 for analysis of requirements)
- Level compaction (architecture designed, implementation deferred — see
  incremental design doc section 5.1)
- Online/inline squashing (background squash during normal operation)
- Trailer-backed navigational fast paths (`get_bhh_at_height`,
  `get_root_hash_at`, ancestor hashes) — data structures exist but
  runtime methods don't yet consult them

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Architecture: Squash Levels as Super-Blocks](#2-architecture-squash-levels-as-super-blocks)
3. [SquashMode: TipOnly vs FullHistory](#3-squashmode-tiponly-vs-fullhistory)
4. [New Types and Wire Formats](#4-new-types-and-wire-formats)
5. [Per-Level Blob Trailer](#5-per-level-blob-trailer)
6. [Squash Pipeline](#6-squash-pipeline)
7. [Runtime Integration](#7-runtime-integration)
8. [Proof Semantics](#8-proof-semantics)
9. [Post-Squash COW](#9-post-squash-cow)
10. [Compaction](#10-compaction)
11. [Deferred Work](#11-deferred-work)
12. [Implementation Phases](#12-implementation-phases)
13. [File Change Summary](#13-file-change-summary)
14. [Test Plan](#14-test-plan)

---

## 1. Motivation

The archival MARF stores one trie blob per block in an append-only
`.blobs` file. Reading a single key may chase backpointers across dozens
of blobs — each requiring a blob offset lookup plus a random seek. With
`TrieNodePatch` compression enabled, each backpointer hop may also
require resolving a patch chain (up to `MAX_PATCH_DEPTH = 4` levels),
with each patch in a different per-block blob. At mainnet scale (~7M
blocks, ~50M unique keys), this dominates read latency.

The squash engine collapses contiguous block ranges into **squash
levels** — "super-blocks" that represent ~1000 blocks of cumulative
state changes in a single blob. Within a level, all per-block
backpointers and patch chains are resolved. Across levels, the same
backpointer and `TrieNodePatch` mechanisms used by per-block blobs apply
— but at ~1000x coarser granularity, meaning dramatically fewer hops per
read.

As of Epoch 3.4 (SIP-042), Clarity's `at-block` is disabled, removing
the primary in-VM consumer of historical state reads. The remaining
consumers are RPC endpoints (`/v2/data_var`, `/v2/map_entry`, etc.),
which are a node-operator concern. This motivates the configurable
`SquashMode` (section 3): operators choose between minimal storage
(`TipOnly`) and historical value support (`FullHistory`).

See the [companion analysis doc](.docs/marf-squash-analysis.md) for the
full evaluation of Francesco's `squash.rs`, the SQL side-store critique,
and the `TrieLeafSquashed` + blob trailer design rationale.

---

## 2. Architecture: Squash Levels as Super-Blocks

### Core insight

A squash level is structurally identical to a per-block trie blob. It
has a root node, internal nodes, and leaves. Some nodes are full copies,
some are `TrieNodePatch` diffs against a prior level, and some subtrees
are referenced via backpointers to earlier levels. The existing read
infrastructure — `MARF::walk()`, `Trie::resolve_backptr()`,
`read_patched_persisted_node()` — handles all of this without
modification.

The only difference from a per-block blob is **what gets resolved vs.
what stays as a backpointer/patch**:

| Per-block blob (current) | Squash level (proposed) |
| ---- | ---- |
| COW'd nodes from this single block | All nodes modified in ~1000 blocks, fully resolved |
| Patches against the prior block's version | Patches against the prior level's version |
| Backpointers to prior blocks' blobs | Backpointers to the prior level's blob |
| ~5 sec of changes | ~1000 blocks of changes |

### Level structure

```text
Level 0 (blocks 0..=H0)
  Base snapshot. All reachable nodes stored inline — no prior level
  exists. No patches, no backpointers. Fully self-contained.

Level 1 (blocks H0+1..=H1)
  Modified internal nodes stored as TrieNodePatch diffs against L0.
  New/modified leaves stored as TrieLeaf or TrieLeafSquashed.
  Unchanged subtrees: backpointers to L0.

Level 2 (blocks H1+1..=H2)
  Patches against L1. Backpointers to L1 (or transitively to L0
  through L1's backpointers).

...archival blocks after latest level
  Standard per-block blobs with backpointers to the latest level.
```

### How cross-level reads work

When `MARF::walk()` encounters a backpointer, it calls
`Trie::resolve_backptr()` (`trie.rs:81`), which looks up the target
block via `get_block_from_local_id()` → `open_block_known_id()`. This
opens the target block's blob — which, for a squash level, is the
level's blob — and the walk continues from the referenced offset.

When the walk encounters a `TrieNodePatch`, the existing
`read_patched_persisted_node` (`storage.rs:1985`) resolves it by reading
the base node from the prior level, applying the pointer diffs, and
returning the reconstructed node.

**No new resolution code is needed.** The key requirement is that prior
levels' `marf_data` rows remain stable: each `block_id` must map to the
correct squash blob's `(external_offset, external_length)`.

### Why this is dramatically better than per-block

Consider reading a key that hasn't changed in 5000 blocks:

**Archival MARF**: The walk resolves ~32 nodes along the key path. Each
node may be a backpointer to a prior block's blob, and each backpointer
hop may itself be a `TrieNodePatch` chain up to `MAX_PATCH_DEPTH = 4`
deep, with each patch in a different per-block blob. In practice, the
top ~4-5 trie levels are COW'd in nearly every block, so the walk
chases backpointers through many per-block blobs with frequent patch
resolution.

**With 1000-block squash levels (4 levels)**: The walk resolves the same
~32 nodes, but the per-node cost is dramatically lower:

- **Nodes deep in the trie** (most of the path): these change
  infrequently and are typically found directly in the level where the
  key was last written — zero cross-level hops.
- **Nodes near the root** (~4-5 trie levels): these are modified in
  every squash level and are stored as `TrieNodePatch` diffs. Each
  requires one cross-level patch resolution per level — but each
  resolution reads from a squash-level blob (contiguous, mmap-friendly),
  not a per-block blob. With 4 uncompacted levels, that's up to 4
  patch hops per root-region node — the same `MAX_PATCH_DEPTH` budget
  as today, but covering ~4000 blocks instead of ~4.
- **Leaves**: never patches. Found directly in the level that last
  modified the key.

The net effect is a strong improvement for most workloads, particularly
for keys in stable subtrees (the vast majority). Hot root-region nodes
see patch chains proportional to the level count, which is bounded.

**With compaction (2-3 levels)**: Even fewer hops. Background compaction
merges older levels, reducing cross-level patch chains.

### Patch chain depth and safety

The existing `MAX_PATCH_DEPTH = 4` limit in `read_patched_persisted_node`
(`storage.rs:1999`) hard-stops patch chasing and returns `NodeTooDeep`
beyond that depth. With uncompacted squash levels, each level
contributes at most one patch hop per node resolution (because each
level's pipeline resolves all intra-level patches). So the total chain
depth for a given node equals the number of uncompacted levels.

**Hard cap**: the squash pipeline **refuses to create a new level** if
the existing uncompacted level count is already at `MAX_PATCH_DEPTH`.
This is enforced at the `squash_level()` entry point before any work
begins:

```rust
let existing_levels = read_squash_levels(&db)?.len();
if existing_levels >= MAX_PATCH_DEPTH {
    return Err(Error::NotSupportedError(
        "Cannot create squash level: patch depth limit reached. \
         Run compaction to merge existing levels first.".into(),
    ));
}
```

This makes the system safe without compaction: up to 4 levels covering
~4000 blocks. Compaction then becomes the mechanism to "make room" for
new levels by merging older ones, but it is not required for
correctness.

**Note on node-type changes**: `TrieNodePatch` can only diff nodes of
the same type (`node.rs:1692`). If a node changes type between levels
(e.g., `Node4` promoted to `Node16`), the pipeline stores the full node
instead of a patch. This is correct — it just means some nodes in a
level are full copies rather than patches, which is a storage cost, not
a correctness issue.

### Why levels stay small (no blob size budget needed)

A per-block blob stores the COW'd nodes from one block — typically a
few hundred nodes. A squash level stores the cumulative delta of ~1000
blocks — the union of all nodes modified in that range.

- **Internal nodes**: the top ~4-5 trie levels are COW'd in nearly
  every block (because every block modifies some key). These are stored
  once in the level, either as full nodes or as `TrieNodePatch` diffs.
  At ~2.5 KB per Node256, even 1000 unique internal nodes is ~2.5 MB.

- **Leaves**: each key modified in the range contributes one leaf. With
  ~1000 blocks averaging ~100 key writes each, that's ~100K leaves at
  ~80 bytes = ~8 MB. With `TrieLeafSquashed` (FullHistory), add ~44
  bytes per additional transition.

- **Cross-level patches**: the storage savings are huge. A Node256
  patch with 3 changed children is ~40 bytes vs. ~2.5 KB for the full
  node.

A typical incremental level (1000 blocks) is on the order of tens of
megabytes — nowhere near the 4 GB `u32` limit. Even level 0 (the full
base snapshot at mainnet scale) is bounded by the number of unique
reachable nodes.

**Level 0 size at mainnet scale**: at ~50M reachable nodes × ~100 bytes
average serialized size = ~5 GB. This is tight against the 4 GB `u32`
limit. The operator controls this by choosing H0 conservatively — a
height where the reachable node count is under ~40M (~4 GB). At current
mainnet growth rates, this covers the full chain history. If future
state growth pushes level 0 past 4 GB, the correct fix is `u64`
`TriePtr::ptr` widening for the level 0 blob streaming step only — a
contained change to the squash pipeline's step 8, not the 100+ callsites
in the read path (which continue to use `u32` for incremental levels
that are well under the limit).

---

## 3. SquashMode: TipOnly vs FullHistory

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SquashMode {
    /// Leaves are plain `TrieLeaf`. Historical reads return tip-era values.
    /// Default. No new node types in the blob.
    TipOnly = 0,
    /// Leaves with multiple value transitions are `TrieLeafSquashed`,
    /// carrying the complete value-transition history scoped to the
    /// level's block range. Historical reads return correct
    /// point-in-time values.
    FullHistory = 1,
}
```

**`TipOnly`** is the default. The squash blob contains only standard
`TrieLeaf` nodes. Code that doesn't know about `TrieLeafSquashed` can
read a `TipOnly` blob unchanged. This matches Francesco's current squash
behaviour.

**`FullHistory`** uses `TrieLeafSquashed` (section 4) for leaves with
more than one value transition within the level's block range. Leaves
written exactly once remain plain `TrieLeaf`. This mode is opt-in for
node operators who need to serve historical state via RPC
(`proof=0` only — see section 8).

The mode is recorded in the per-level blob trailer (section 5) so
runtime code knows whether historical value queries can succeed.

---

## 4. New Types and Wire Formats

### 4.1 `TrieNodeID::LeafSquashed = 7`

Added to the `define_u8_enum!(TrieNodeID { ... })` macro in `node.rs`.
Value 7 is the next available after `Patch = 6`. The 6-bit payload
(`0b000111`) does not conflict with control bits (0x80 backptr, 0x40
compressed) or the `SPARSE_PTR_BITMAP_MARKER` (0xFF).

### 4.2 `TrieLeafSquashed`

```rust
#[derive(Debug, Clone)]
pub struct TrieLeafSquashed {
    pub path: NodePath,
    /// Value transitions sorted descending by height.
    /// entries[0] is the tip (most recent).
    ///
    /// For incremental levels (min_height > 0), entries[last] may be
    /// a synthetic baseline entry at min_height carrying the value
    /// inherited from the prior level. See "Inherited baseline" below.
    pub entries: Vec<(u32, MARFValue)>,
}
```

#### Wire format

```text
[TrieHash: 32 bytes]                   -- node hash (from tip value)
[TrieNodeID::LeafSquashed: 1 byte]     -- 0x07
[path_len: 1 byte] [path: var bytes]   -- compressed path suffix
[entry_count: 4 bytes, big-endian]     -- >= 1
[height_0: 4 BE] [value_0: 40 bytes]  -- tip (most recent)
[height_1: 4 BE] [value_1: 40 bytes]  -- second most recent
...
```

Each entry is a fixed 44 bytes (4-byte height + 40-byte `MARFValue`).

#### Consensus hashing

The stored node hash and `write_consensus_bytes` use `TrieNodeID::Leaf`
(not `LeafSquashed`) and `entries[0].value` only:

```text
hash = SHA512_256(0x01 || encoded_path || entries[0].value)
```

This preserves Merkle root equivalence: the parent internal node's hash
chain sees the same leaf hash whether the on-disk representation is
`TrieLeaf` or `TrieLeafSquashed`. Historical entries beyond `entries[0]`
are strictly non-consensus payload — the same integrity model as
`TrieNodePatch`.

#### Key methods

```rust
impl TrieLeafSquashed {
    /// The most recent value (always entries[0]).
    pub fn tip_value(&self) -> &MARFValue;

    /// Point-in-time lookup. Returns the value from the most recent
    /// transition at or before `height`, or None if the key did not
    /// exist at that height (i.e. the key was first written after
    /// `height`).
    pub fn value_at_height(&self, height: u32) -> Option<&MARFValue> {
        let idx = self.entries.partition_point(|(h, _)| *h > height);
        self.entries.get(idx).map(|(_, v)| v)
    }
}
```

#### Inherited baseline for incremental levels

For level 0 (`min_height = 0`), `entries[last]` is the key's first-ever
write, and `value_at_height(h)` returns `None` for heights before that —
correct, because the key didn't exist yet.

For incremental levels (`min_height > 0`), a key may have existed before
the level's range. If that key is modified within the level, its
`entries` must include the value it had at the start of the level.
Otherwise `value_at_height(h)` for `h` between `min_height` and the
first intra-level transition would incorrectly return `None`.

**Solution**: during history collection (pipeline step 3), when a leaf's
first transition within the level occurs at height `H > min_height`, the
pipeline reads the leaf's value from the prior level (by following the
cross-level backpointer) and prepends a synthetic baseline entry
`(min_height, prior_value)` to the entries list. This ensures:

- `value_at_height(min_height)` → returns the inherited value
- `value_at_height(H)` → returns the new value
- `value_at_height(h)` for `min_height <= h < H` → returns the
  inherited value (correct: the key hadn't changed yet within this level)

For keys that are NOT modified within the level, no `TrieLeafSquashed`
is created — the walk follows a cross-level backpointer to the prior
level and reads the leaf there. The prior level's `value_at_height()`
handles the lookup correctly.

**Example**: key has value `A` from level 0, changes to `B` at height
1100 within level 1 (range 1001..=2000):

```text
Level 1 leaf entries: [(1100, B), (1001, A)]
                        ↑ actual    ↑ synthetic baseline
```

- `value_at_height(1050)` → `A` (correct)
- `value_at_height(1100)` → `B` (correct)
- `value_at_height(1001)` → `A` (correct)

#### TrieNode trait implementation

`TrieLeafSquashed` implements the `TrieNode` trait so it can participate
in the `with_node!` macro and existing node-generic code:

- `id()` → `TrieNodeID::LeafSquashed as u8`
- `walk()` → `None` (leaf, no children)
- `ptrs()` → `&[]`
- `insert()` / `replace()` → panic (same as `TrieLeaf`)
- `write_bytes()` / `load_from_slice()` → the wire format above
- `byte_len()` → `1 + encoded_path_len + 4 + entries.len() * 44`

#### Integration into TrieNodeType

A new variant `TrieNodeType::LeafSquashed(TrieLeafSquashed)` is added.
The `with_node!` macro gains a `LeafSquashed` arm. All explicit match
blocks on `TrieNodeType` (~8 methods: `is_leaf`, `ptrs_mut`, `max_ptrs`,
`patch_depth`, `last_patch_source`, `set_patch_depth`,
`set_last_patch_source`, plus test helpers) gain `LeafSquashed` arms
that mirror `Leaf` behaviour.

A borrowed view `TrieLeafSquashedRef { path: &[u8], tip_value: &MARFValue }`
is added to `TrieNodeRef`. The `as_leaf()` method on `ReadTrieNode`
returns the tip value as a `TrieLeafRef` for `LeafSquashed` — callers
that only need the current value see no difference.

### 4.3 `Error::NotSupportedError(String)`

New variant on the `Error` enum in `mod.rs`, used for:

- `get_with_proof` / `get_with_proof_from_hash` targeting a block within
  a squash range
- Future unsupported-operation errors

---

## 5. Per-Level Blob Trailer

Each squash blob has a trailer appended after the trie nodes. The
trailer carries all global metadata that was previously in SQL
side-tables, accessible via mmap with zero SQLite interaction.

### Layout

```text
+-----------------------------------------------+
|  Trie nodes (same format as per-block blobs)  |
|  (includes patches and backpointers)          |
+==============================================+
|  SQUASH METADATA TRAILER                      |
|                                               |
|  +-- SquashInfo (fixed, 78 bytes) -----------+|
|  |  magic: [u8; 4] = b"SQSH"                ||
|  |  version: u8 = 1                          ||
|  |  squash_mode: u8                          ||
|  |  level_id: u32                            ||
|  |  min_height: u32                          ||
|  |  max_height: u32                          ||
|  |  archival_marf_root_hash: [u8; 32]        ||
|  |  squash_root_node_hash: [u8; 32]          ||
|  +-------------------------------------------+|
|                                               |
|  +-- Height→RootHash (dense) ----------------+|
|  |  entry_count: u32                         ||
|  |  [root_hash_0: [u8; 32]]  (min_height)   ||
|  |  [root_hash_1: [u8; 32]]  (min_height+1) ||
|  |  ...                                      ||
|  |  (N = max_height - min_height + 1)        ||
|  +-------------------------------------------+|
|                                               |
|  +-- Height→BlockHash (dense) ---------------+|
|  |  entry_count: u32                         ||
|  |  [block_hash_0: [u8; 32]] (min_height)   ||
|  |  ...                                      ||
|  +-------------------------------------------+|
|                                               |
|  +-- BlockHash→Height (sorted) --------------+|
|  |  entry_count: u32                         ||
|  |  [bhh_0: [u8;32], height_0: u32]         ||
|  |  [bhh_1: [u8;32], height_1: u32]         ||
|  |  ...                                      ||
|  |  (sorted by block_hash for binary search) ||
|  +-------------------------------------------+|
|                                               |
|  +-- Footer (fixed, 12 bytes) ---------------+|
|  |  trailer_offset: u64 (from blob start)    ||
|  |  magic: [u8; 4] = b"SQSH"                ||
|  +-------------------------------------------+|
+-----------------------------------------------+
```

### Key properties

- **Dense height arrays indexed relative to `min_height`**:
  `root_hash_at(h)` → `array[h - min_height]`. O(1), directly from mmap.
- **Sorted block-hash table** for `height_of_block(bhh)` → O(log N)
  binary search over contiguous memory.
- **Self-describing**: the footer's magic + offset at the very end of
  the blob allows detection by reading the last 12 bytes.
- **`squash_mode` field**: runtime code checks this to determine whether
  historical value queries can return point-in-time values.
- **`level_id` + height range**: supports multi-level incremental
  squashing. Each level's trailer describes its own range.
- **No Merkle inclusion**: the trailer is outside the node region, so it
  has no effect on content hashes.
- **mmap-compatible**: the entire blob (nodes + trailer) is one
  contiguous file region.

### Level registry (SQL, cold path only)

A small table tracks which squash levels exist:

```sql
CREATE TABLE IF NOT EXISTS marf_squash_levels (
    level_id INTEGER PRIMARY KEY,
    min_height INTEGER NOT NULL,
    max_height INTEGER NOT NULL,
    blob_offset INTEGER NOT NULL,
    blob_length INTEGER NOT NULL
);
```

One row per level. Queried only at MARF open to populate the in-memory
level list. Not on any hot read path.

### Trailer size budget

| Section | N=1K heights (incremental) | N=7M heights (level 0) |
| ---- | ---- | ---- |
| SquashInfo | 78 B | 78 B |
| Height→RootHash (32 B/entry) | ~32 KB | ~224 MB |
| Height→BlockHash (32 B/entry) | ~32 KB | ~224 MB |
| BlockHash→Height (36 B/entry) | ~36 KB | ~252 MB |
| Footer | 12 B | 12 B |
| **Total trailer** | **~100 KB** | **~700 MB** |

Incremental level trailers are tiny. The OS only pages in the 4K mmap
regions actually accessed.

---

## 6. Squash Pipeline

### 6.1 NodeStore (disk-backed temporary storage)

Full `TrieNodeType` objects are serialized to a temp file. Only ~80
bytes per node stays in RAM (hash + block_id + file offset):

```rust
struct NodeStore {
    writer: BufWriter<File>,
    path: PathBuf,
    file_offsets: Vec<(u64, u32)>,  // (offset_in_tempfile, byte_length)
    hashes: Vec<TrieHash>,
    block_ids: Vec<u32>,            // source block_id for each node
}
```

### 6.2 Two pipeline modes

The pipeline has two modes that share most steps but differ in how
nodes are collected:

**Base level (level 0, `min_height = 0`)**: collects ALL reachable nodes
from the tip trie and resolves all backpointers to inline. No patches,
no backpointers in the output. Fully self-contained.

**Incremental level (level N > 0)**: collects only nodes modified in the
level's block range. Unmodified nodes become cross-level backpointers.
Modified internal nodes are stored as `TrieNodePatch` diffs against the
prior level's version when the diff is smaller than the full node.

```rust
pub fn squash_level<T: MarfTrieId>(
    src_path: &str,
    dst_path: &str,
    mode: SquashMode,
    min_height: u32,
    max_height: u32,
) -> Result<SquashStats, Error>
```

A convenience wrapper `squash_to_path(src, dst, mode, height)` calls
`squash_level` with `min_height=0` for the common "squash everything up
to H" case.

### 6.3 Pipeline steps

#### Step 1 — Load block map

Load all `marf_data` rows into `HashMap<T, (block_id, external_offset,
external_length)>`. Sequential SQL read.

#### Step 2 — Collect per-height metadata

For heights `min..=max`, resolve `BLOCK_HEIGHT_TO_HASH_MAPPING_KEY` to
get `block_hash`, then read root hashes from blob headers. Populates the
trailer's dense arrays.

#### Step 3 — Collect value history (`FullHistory` only)

For each block `h` in `min..=max`, walk the local-only trie (descend
only into non-backpointer children from the root). For each leaf found,
record `(h, leaf.data)` keyed by the full key hash. Skip `__MARF_*`
navigational keys. Filter same-value structural rewrites
(`promote_leaf_to_node4` copies).

**Inherited baseline** (incremental levels, `min_height > 0`): after
collecting all transitions, for each key whose first intra-level
transition is at height `H > min_height`, read the leaf's value from the
prior level (by following the cross-level backpointer). Prepend a
synthetic baseline entry `(min_height, prior_value)`. See section 4.2.

Result: `HashMap<TrieHash, Vec<(u32, MARFValue)>>` — per-key value
transitions within the level's range (including synthetic baselines).

**Skipped entirely in `TipOnly` mode.**

#### Step 4 — DFS collect nodes

DFS from the tip root at `max_height`. The behaviour depends on the
level type:

**Base level (level 0)**:

Collect every reachable node. Resolve all backpointers transitively.
All nodes are stored as full copies. No patches, no backpointers in the
output.

**Incremental level (level N > 0)**:

For each node encountered during the DFS:

- **Block height < `min_height`** → the node is unchanged from a
  prior level. Record a **cross-level backpointer** in the parent's
  child list. Do NOT collect into NodeStore.

- **Block height >= `min_height`** → the node was written in this
  range. Resolve any per-block backpointers/patches within the range to
  get the final state. Then:

  - **Internal node**: compare against the prior level's version of
    this node (the node that the oldest intra-range backpointer
    pointed to). If the diff (changed child pointers) is smaller than
    the full node, emit a `TrieNodePatch` against the prior level.
    Otherwise emit the full node.

  - **Leaf**: check the history map from step 3. If multiple
    transitions (or a single transition with an inherited baseline),
    construct a `TrieLeafSquashed`. Otherwise emit a plain `TrieLeaf`.

#### Step 5 — Register placeholder blocks

Create `marf_data` rows for all blocks `min..=max` in the destination
DB, all pointing to the same blob offset (the squash blob). This
allows `open_block` to succeed for any historical block in the range and
ensures cross-level backpointers resolve correctly.

#### Step 6 — Remap intra-level pointers

Collected nodes reference `(source_block_id, source_offset)`. Convert
to sequential offsets within the squash blob. Build a mapping
`(block_id, offset) → squash_node_index`, then rewrite inline child
pointers. Cross-level backpointers and patch backpointers are left
unchanged — they reference valid `block_id`s in prior levels'
`marf_data` rows.

#### Step 7 — Recompute hashes bottom-up

Process nodes in reverse collection order (leaves first, root last).

- `TrieLeafSquashed` nodes hash as `Leaf(tip_value)` — see section 4.2.
- `TrieNodePatch` nodes: the stored hash is the hash of the fully
  resolved node (same as how per-block patches work).
- Internal nodes: standard hash computation from children's hashes.

#### Step 8 — Stream blob and finalize

Compute final byte offsets. Stream nodes from NodeStore to `.blobs` via
`BufWriter`. Append the trailer. Write the level metadata to
`marf_squash_levels`. Update `marf_data` rows with final blob offset
and length.

---

## 7. Runtime Integration

### 7.1 Trailer detection and level loading (`storage.rs`)

On MARF open, query `marf_squash_levels` and read each level's trailer
from its blob region. Build a `HashMap<[u8;32], (usize, u32)>` mapping
`block_hash → (level_index, height)` from all trailers' sorted
block-hash tables. Store in `TrieStorageTransientData`:

```rust
squash_levels: Vec<Arc<SquashTrailer>>,                // sorted by min_height
squash_block_index: HashMap<[u8;32], (usize, u32)>,   // bhh → (level_idx, height)
squash_opened_height: Option<u32>,                     // set when opening a squash-range block
```

The `squash_block_index` map gives O(1) block-hash lookups regardless
of level count, avoiding O(levels * log N) cost per `open_block` call.

### 7.2 Squash-aware block opening (`storage.rs`)

In `open_block_impl`, before the standard block-ID lookup, check
`squash_block_index` for the block hash. If found:

1. Set `cur_block` and `cur_block_id` as normal (all blocks in the
   range have valid `marf_data` rows).
2. Set `cur_block_trie_offset` to the level's blob offset (skipping
   the SQL offset lookup).
3. Record `squash_opened_height` for use by `value_at_height()`.

### 7.3 Squash-aware navigation (`marf.rs`)

When `squash_levels` is non-empty, navigational lookups check the
trailers before falling through to trie walks:

| Operation | Standard path | Squash-aware path |
| ---- | ---- | ---- |
| `get_block_height_of(bhh)` | Trie lookup of `__MARF_*` key | Trailer `BlockHash→Height` O(1) via index |
| `get_bhh_at_height(h)` | Trie lookup of `__MARF_*` key | Trailer `Height→BlockHash` O(1) |
| `get_root_hash_at(bhh)` | Trie lookup + root read | Trailer O(1) + O(1) |
| Ancestor hash (skip-list) | Trie lookup per ancestor | Trailer O(1) per ancestor |

### 7.4 Squash-aware value reads (`marf.rs`)

In `MARF::walk()`, when the walk terminates at a leaf:

- If the leaf is `TrieLeafSquashed` AND `squash_opened_height` is set,
  decode the full `TrieLeafSquashed` and call
  `value_at_height(squash_opened_height)`.
- Otherwise, return the tip value (standard `TrieLeaf` path, or
  `TrieLeafSquashed` tip for non-historical reads).

---

## 8. Proof Semantics

Merkle proofs within any squash range are **not possible** — the
internal nodes carry only tip-era hashes, and sibling hashes change
independently at different heights. This is inherent to squashing, not
mode-specific. Full proof support requires non-squashed archival
chainstate.

The current RPC layer defaults to `proof=1` (`httpcore.rs:387`).
Handlers like `getdatavar.rs`, `getmapentry.rs`, and `getaccount.rs`
all take the proof path unless `proof=0`.

**Implementation**:

- `get_with_proof` / `get_with_proof_from_hash`: if the target block is
  within any squash level's range, return
  `Error::NotSupportedError("Merkle proofs not supported for blocks within squash range")`.
- `TrieMerkleProof::from_path` leaf termination: accept
  `TrieNodeID::LeafSquashed` alongside `TrieNodeID::Leaf` (for proofs
  at the tip or post-squash blocks where the walk traverses a squash
  level's blob).
- Proofs for the tip and post-squash blocks work normally.

---

## 9. Post-Squash COW

When new blocks extend past the latest squash level, the COW walk
encounters nodes in the squash blob — both `TrieLeafSquashed` leaves
and `TrieNodePatch` internal nodes:

- **`walk_cow`** (`marf.rs`): accept `LeafSquashed` at end-of-path
  (same as `Leaf`). `TrieNodePatch` nodes are already handled by the
  existing patch resolution in `node_child_copy`.
- **`node_copy_update`** (`marf.rs`): hash a `LeafSquashed` using its
  tip value — produces the same hash as the stored node hash.
- **`Trie::add_value`** (`trie.rs`): when replacing a `LeafSquashed`
  (same key overwritten) or promoting one (`promote_leaf_to_node4` when
  a new key diverges into the squashed leaf's path), the result in the
  new block's TrieRAM is a plain `TrieLeaf`. The squash history is not
  carried forward into per-block blobs.

---

## 10. Compaction

Compaction merges adjacent squash levels to reduce the total level count
(and thus cross-level patch chain depth). It is not implemented in this
PR but the format fully supports it. Without compaction, the system is
still safe: the hard cap at `MAX_PATCH_DEPTH` (section 2) prevents
creation of levels that would exceed the patch depth limit. Compaction
is the mechanism to "make room" for new levels by merging old ones.

### How it works

Merging Level N-1 + Level N into a combined level:

1. Walk Level N's trie. For each node:
   - **Patch against Level N-1**: resolve the patch by reading the base
     from Level N-1 and applying diffs. Store the fully resolved node.
   - **Backpointer to Level N-1**: follow it and read the node. Store
     inline.
   - **Backpointer to an earlier level (< N-1)**: keep as-is — the
     combined level inherits this cross-level reference.
   - **Full node local to Level N**: keep as-is.

2. For `TrieLeafSquashed` nodes in both levels: concatenate their
   `entries` lists (Level N's entries first, then Level N-1's). The
   inherited baseline entry from Level N can be dropped since Level N-1
   now provides the actual historical entries.

3. Write the merged blob with a new trailer covering the combined height
   range.

This is analogous to LSM-tree compaction: small recent levels are cheap
to create, and background merges keep the total level count bounded.

### Compaction triggers

A simple policy: when the uncompacted level count exceeds a threshold
(e.g., 4), merge the two oldest levels. More sophisticated policies
(size-tiered, leveled) can be added later.

---

## 11. Deferred Work

| Item | Rationale |
| ---- | ---- |
| u64 `TriePtr::ptr` widening | Unnecessary for incremental levels (tens of MB). Level 0 may need u64 for the blob streaming step only if future state growth exceeds ~40M reachable nodes — a contained pipeline change, not a read-path change. |
| Compressed pointer format | Sparse bitmaps and variable-width encoding from Francesco's branch; orthogonal |
| Level compaction | Format supports it (section 10); concrete implementation is a follow-up. Without compaction the system is safe: the hard cap at `MAX_PATCH_DEPTH` prevents unsafe level creation. Compaction makes room for new levels. |
| Online/inline squashing | Background squash every ~1000 blocks during normal operation; the incremental pipeline directly supports this |
| Additional `SquashMode` variants | e.g. "recent history" keeping only last N transitions; the wire format accommodates any entry count |

---

## 12. Implementation Phases

All files in `stackslib/src/chainstate/stacks/index/` unless noted.

### Phase 1 — Foundation types

`mod.rs`, `node.rs`, `squash.rs` (new)

1. `Error::NotSupportedError(String)` variant + Display/Error impls
2. `TrieNodeID::LeafSquashed = 7` in `define_u8_enum!`
3. New `squash.rs` module with `SquashMode` enum

### Phase 2 — TrieLeafSquashed type

`node.rs`, `mod.rs`

1. `TrieLeafSquashed` struct + `TrieNode` impl
2. `tip_value()`, `value_at_height()` inherent methods
3. `TrieNodeType::LeafSquashed` variant + `with_node!` update
4. All explicit match arms on `TrieNodeType` (~8 methods)
5. Consensus hashing via `Leaf` ID
6. `TrieLeafSquashedRef` + `TrieNodeRef::LeafSquashed`

### Phase 3 — Decode + scratch integration

`bits.rs`, `scratch.rs`, `mod.rs`

1. `decode_nodetype_from_slice_at_head` LeafSquashed arm
2. `get_node_body_max_byte_len`, `get_nodetype_hash_bytes` updates
3. `MarfReadState.leaf_squashed` slot + decode/get_ref/park methods
4. `ReadTrieNode::is_leaf()` + `as_leaf()` for LeafSquashed

**Decode strategy for `TrieLeafSquashed`**: the initial implementation
uses full owned decode into the `MarfReadState.leaf_squashed` slot
(allocates the entries Vec). `as_leaf()` returns a `TrieLeafRef`
pointing at `entries[0]` — callers doing tip reads see no API
difference. For `TipOnly` mode this path is never hit (the blob
contains only `TrieLeaf`). For `FullHistory` tip reads, the entries Vec
allocation is the cost. A follow-up can add a "peek first entry from
byte slice" path in `PersistedBytes` that avoids the allocation for tip
reads, only materialising the full entries when `value_at_height()` is
needed for a historical read.

### Phase 4 — Blob trailer + level registry

`squash.rs`, `trie_sql.rs`

1. `SquashTrailer` struct with write/read/lookup methods
2. Per-level wire format (section 5)
3. `marf_squash_levels` SQL table + CRUD helpers

### Phase 5 — Squash pipeline

`squash.rs`

1. `NodeStore` disk-backed temporary storage (temp file colocated with
   MARF for parallel-test safety)
2. Base-level pipeline (level 0): DFS collect all, remap to inline
3. Incremental-level pipeline (`squash_level_incremental`): DFS
   collect intra-range nodes only, preserve cross-level backpointers
   as-is, hash-only prefetch for cross-level children, contiguous
   prior-level coverage validation, confirmed-only tip check
4. `squash_level()` + `squash_to_path()` for base level;
   `squash_level_incremental()` for incremental levels
5. Cross-level `TrieNodePatch` diffs deferred (full nodes stored for
   all collected internal nodes in initial implementation)

### Phase 6 — Runtime integration

`storage.rs`, `marf.rs`, `trie.rs`, `proofs.rs`

1. Trailer detection + level loading + block index on MARF open
2. Squash-aware `open_block_impl` with cached blob offset
3. `get_with_proof` error for squash-range blocks (both trait override
   on `MarfConnection` and inherent methods on `MARF<T>`)
4. `from_path` leaf termination for LeafSquashed
5. **Not yet wired**: navigational lookups via trailer
   (`get_bhh_at_height`, `get_root_hash_at`, ancestor hashes) — the
   trailer data structures are loaded but the runtime MARF methods
   still fall through to trie walks for these lookups
6. **Not yet wired**: `walk()` value extraction with
   `value_at_height()` for `FullHistory` mode — `squash_opened_height`
   is set on block open but not consumed for value dispatch

### Phase 7 — Post-squash COW

`marf.rs`, `trie.rs`

1. `walk_cow` accepts LeafSquashed
2. `node_copy_update` hashes LeafSquashed as Leaf
3. `Trie::add_value` / `promote_leaf_to_node4` handles LeafSquashed

### Phase 8 — Tests

`test/squash.rs` (new)

See section 14 for the full test plan.

---

## 13. File Change Summary

| File | Changes |
| ---- | ---- |
| `mod.rs` | `Error::NotSupportedError`, `ReadTrieNode` updates, `TrieNodeRef::LeafSquashed`, `TrieLeafSquashedRef` (with `entries` field for lossless round-trip) |
| `node.rs` | `TrieNodeID::LeafSquashed`, `TrieLeafSquashed` struct + `TrieNode` impl, `TrieNodeType::LeafSquashed`, `with_node!` macro, explicit match arms; `to_owned_type()` preserves `LeafSquashed` (COW flattening at explicit callsites) |
| `bits.rs` | Decode/encode `LeafSquashed`, consensus-equivalent hash computation; decode dispatch uses stored node ID (not ptr hint) |
| `scratch.rs` | `MarfReadState.leaf_squashed` slot, decode/get_ref/park/store methods |
| `file.rs` | Slow-path `read_item_at_offset` discovers stored type from header, re-reads only when needed; `read_trie_item_borrowed` accepts `trie_offset_hint` |
| `squash.rs` | **NEW**: `SquashMode`, `SquashTrailer`, `NodeStore`, base-level pipeline (`squash_level`), incremental pipeline (`squash_level_incremental`), `verify_no_descendants`, contiguous-coverage validation |
| `trie_sql.rs` | `marf_squash_levels` table + CRUD; `update_external_trie_blob_by_hash` for incremental row updates |
| `storage.rs` | `squash_levels` + `squash_block_index` + `squash_opened_height` on transient data, trailer loading, squash-aware `open_block_impl`, `append_raw_blob` |
| `marf.rs` | `is_in_squash_range`, `get_with_proof` error on both trait + inherent methods, `walk_cow` + `node_copy_update` for `LeafSquashed` (explicit flatten at `node_child_copy`), `storage_backend_mut` |
| `trie.rs` | `add_value` / `promote_leaf_to_node4` for `LeafSquashed` |
| `proofs.rs` | `from_path` leaf termination accepts `LeafSquashed` |
| `test/squash.rs` | **NEW**: 13 tests — unit tests for types/trailer + integration tests for base-level, incremental, cross-level reads, proof gating, post-squash COW |

---

## 14. Test Plan

### Implemented (current branch)

| # | Test | What it verifies |
| ---- | ---- | ---- |
| 1 | `test_leaf_squashed_serialization` | Round-trip write/read of `TrieLeafSquashed` wire format |
| 2 | `test_leaf_squashed_serialization_single_entry` | Single-entry case |
| 3 | `test_value_at_height` | Binary search correctness for various height queries |
| 4 | `test_value_at_height_single_entry` | Single-entry edge cases |
| 5 | `test_tip_value` | `tip_value()` returns `entries[0]` |
| 6 | `test_trailer_serialization` | Round-trip write/read of `SquashTrailer`, O(1) and O(log N) lookups |
| 7 | `test_trailer_serialization_full_history_mode` | `FullHistory` mode flag in trailer |
| 8 | `test_trailer_footer_not_present` | Footer detection for non-squash blobs |
| 9 | `test_squash_mode_from_u8` | `SquashMode` deserialization |
| 10 | `test_squash_base_level_tip_only` | Squash 5 blocks, verify all keys readable at tip |
| 11 | `test_squash_incremental_basic` | Level 0 + Level 1, all keys readable at tip, level registry correct |
| 12 | `test_squash_incremental_cross_level_reads_and_proofs` | Historical reads within each level's range + proof rejection for both levels |
| 13 | `test_squash_post_incremental_extension` | COW extension after two squash levels, cross-level reads at extension tip |

### Follow-up (not yet implemented)

| # | Test | What it verifies |
| ---- | ---- | ---- |
| 14 | `test_squash_base_level_full_history` | `FullHistory` squash with point-in-time reads |
| 15 | `test_squash_root_hash_equivalence` | Post-squash root hashes match archival |
| 16 | `test_squash_incremental_with_patches` | Two levels with cross-level patches |
| 17 | `test_squash_incremental_inherited_baseline` | Inherited value for incremental levels |
| 18 | `test_squash_three_levels` | Three-level reads |

### Verification commands

```text
cargo check -p stackslib                           # after each phase
cargo test -p stackslib -- index::test::squash     # squash-specific tests
cargo test -p stackslib -- index::test             # full MARF regression
```
