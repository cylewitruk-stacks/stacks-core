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

//! Hot-zone storage for pre-promotion block tries.
//!
//! See `.docs/squashing-v1.5.md` (Phase A) for the model. New block tries
//! land in rolling `<db>.hot.{NNNN}` files; once a range matures past the
//! burnchain reorg horizon, a horizon-gated squash promotes the canonical
//! blocks into the cold `<db>.blobs` zone (Phase B).
//!
//! Phase A ships the hot-file lifecycle and the per-file read-guard
//! mechanism but leaves the squash machinery untouched. The promotion path
//! and descendant rewrite land in Phase B.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use memmap2::Mmap;
use parking_lot::Mutex;
use rusqlite::Connection;

use crate::chainstate::stacks::index::{trie_sql, Error};

/// Default rotation threshold for hot files: when an active hot file crosses this size, the next
/// block append rotates to a new file. 1 GiB matches the design doc's first-cut value
/// (`squashing-v1.5.md` §4.4) and gives ~hours of writes between rotations on observed mainnet
/// workloads.
pub const DEFAULT_HOT_FILE_ROTATION_THRESHOLD_BYTES: u64 = 1 << 30;

/// File-name prefix for hot-zone files. The full name is `<prefix>{seq:08}` where `prefix` is
/// `<db>.hot.`.
pub const HOT_FILE_PREFIX: &str = ".hot.";

/// Build the path for a hot file with the given DB-path stem and sequence number. The naming is
/// zero-padded to 8 digits so on-disk listings sort in append order — convenient for diagnostics,
/// not load-bearing for correctness.
pub fn hot_file_path(db_path: &str, seq: u32) -> String {
    format!("{db_path}{HOT_FILE_PREFIX}{seq:08}")
}

/// Per-file read-guard counter + mutate-pending flag. Held inside an `Arc` so multiple
/// `HotFileReadGuard` instances and the writer can share a single source of truth.
///
/// The model mirrors `BlobReadGuard` / `SharedStorageState` from [storage.rs](super::storage), but
/// per-hot-file: each hot file has its own counter so the Phase B promotion swap can quiesce only
/// the files it's actually about to mutate (touched by the descendant-rewrite plan) without
/// stalling readers on unrelated hot files.
#[derive(Debug)]
struct ReaderFence {
    /// Number of in-flight readers of this hot file. Writer protocols (Phase B's swap) wait for
    /// this to reach zero before issuing `pwrite` on already-written byte ranges.
    active_reads: AtomicU64,
    /// Set by the writer before mutating. New readers back off until it clears. Inert in Phase A —
    /// Phase B's swap is the first writer.
    #[allow(dead_code)]
    mutate_pending: AtomicBool,
}

impl ReaderFence {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            active_reads: AtomicU64::new(0),
            mutate_pending: AtomicBool::new(false),
        })
    }
}

/// Process-wide registry mapping canonicalized hot-file paths to their live [`ReaderFence`].
/// Entries are held as `Weak` so a fence is freed when the last `HotFile` for that path is dropped.
///
/// **Why this exists.** Phase B's promotion worker calls `MARF::from_path` to reopen the chainstate
/// against a fresh `TrieFileStorage` instance. Without this registry, the worker's `HotFileSet`
/// would create independent `Arc<ReaderFence>` instances from the coordinator's. The worker's
/// `set_mutate_pending` writes would then go to its own per-handle fence, leaving the coordinator's
/// readers (using a different `HotFileSet` instance) free to observe torn ptr-field rewrites.
///
/// Sharing the fence across handles closes that gap: every `HotFile` instance opened against the
/// same on-disk path — regardless of which `MARF` opened it — sees the same `mutate_pending` flag
/// and contributes to the same `active_reads` count. The writer's quiesce wait then drains readers
/// from any handle in the process before issuing pwrites.
fn hot_fence_registry() -> &'static Mutex<HashMap<PathBuf, Weak<ReaderFence>>> {
    static REGISTRY: std::sync::OnceLock<Mutex<HashMap<PathBuf, Weak<ReaderFence>>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Canonicalize a hot-file path for use as a registry key. Falls back to the input path if
/// `canonicalize` fails (e.g. file doesn't exist yet during `open_or_create`). Mirrors
/// `storage::registry_key` so the same canonicalization rules apply across both registries.
fn fence_registry_key(path: &str) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
}

/// Obtain the [`ReaderFence`] associated with `path`, constructing a fresh one if no live entry is
/// present.
///
/// Two opens of the same hot-file path return the same `Arc<ReaderFence>`, which is what makes the
/// per-file mutate/quiesce protocol coherent across independent `MARF` handles in the same process.
fn shared_reader_fence_for(path: &str) -> Arc<ReaderFence> {
    let key = fence_registry_key(path);
    let mut registry = hot_fence_registry().lock();
    if let Some(weak) = registry.get(&key) {
        if let Some(existing) = weak.upgrade() {
            return existing;
        }
        // Weak is dead (last Arc dropped). Fall through to rebuild.
    }
    let arc = ReaderFence::new();
    registry.insert(key, Arc::downgrade(&arc));
    arc
}

/// RAII read guard for a single hot file. Holding this guard prevents Phase B's swap protocol from
/// `pwrite`-ing into the same byte range that the read scope is borrowing from this file's mmap.
///
/// Acquired via [`HotFileSet::acquire_read_guard`]; dropped automatically when the read scope ends.
/// `Clone` bumps the per-file counter so a borrowed-bytes read scope that survives across multiple
/// resolver calls can clone the guard once per resolution and the writer still sees a non-zero
/// `active_reads`.
#[derive(Debug)]
pub struct HotFileReadGuard {
    fence: Arc<ReaderFence>,
    /// The hot file this guard pins. Diagnostic only.
    seq: u32,
}

impl HotFileReadGuard {
    /// Internal — try to acquire a fence reservation. Respects `mutate_pending`: if a writer has
    /// signaled it's about to `pwrite`, returns `None` so the caller can back off. Used by the
    /// reader-side protocol: bump `active_reads`, then re-check `mutate_pending` to handle the race
    /// where the writer flips the flag concurrently with our bump.
    ///
    /// Reader-writer protocol:
    /// 1. Reader checks `mutate_pending`. If true → back off + retry.
    /// 2. Reader bumps `active_reads`.
    /// 3. Reader re-checks `mutate_pending`. If true → decrement + retry. Otherwise proceed.
    ///
    /// Writer:
    /// 1. Writer sets `mutate_pending`.
    /// 2. Writer waits for `active_reads == 0`.
    /// 3. Writer pwrites.
    /// 4. Writer clears `mutate_pending`.
    ///
    /// The double-check on the reader side handles the race where the reader passes the first
    /// check, the writer sets `mutate_pending` between read 1 and the bump, and the writer's
    /// quiesce wait would otherwise miss this reader. Since the reader's bump must be visible to
    /// the writer (memory ordering via Acquire/Release on `active_reads`), the writer's wait loop
    /// catches it on the next iteration.
    fn try_from_fence(fence: Arc<ReaderFence>, seq: u32) -> Option<Self> {
        if fence.mutate_pending.load(Ordering::Acquire) {
            return None;
        }
        fence.active_reads.fetch_add(1, Ordering::AcqRel);
        if fence.mutate_pending.load(Ordering::Acquire) {
            // Race: writer set mutate_pending after our check 1 but possibly before our bump. Back
            // off to let the writer proceed; caller will retry.
            fence.active_reads.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(Self { fence, seq })
    }

    /// Diagnostic accessor — the hot-file sequence this guard pins.
    pub fn seq(&self) -> u32 {
        self.seq
    }
}

impl Clone for HotFileReadGuard {
    fn clone(&self) -> Self {
        // Cloning an existing guard increments `active_reads` unconditionally — we already hold an
        // active fence reservation, so a writer cannot be pwriting concurrently. The mutate_pending
        // check is unnecessary here.
        self.fence.active_reads.fetch_add(1, Ordering::AcqRel);
        Self {
            fence: self.fence.clone(),
            seq: self.seq,
        }
    }
}

impl Drop for HotFileReadGuard {
    fn drop(&mut self) {
        self.fence.active_reads.fetch_sub(1, Ordering::Release);
    }
}

/// A single hot-zone file (`<db>.hot.{seq:08}`).
///
/// The file is append-only from the writer's perspective. Readers may take a [`HotFileReadGuard`]
/// over it; the Phase B swap protocol will `pwrite` into already-written byte ranges to apply
/// descendant backpointer rewrites, gated by quiescing all live read guards on this file.
pub struct HotFile {
    /// File descriptor. Opened read-write; the write side is exercised only by the writer thread.
    /// (No internal locking — single-writer per MARF, same as `<db>.blobs`.)
    fd: File,
    /// On-disk path. Diagnostic only at this layer; `HotFileSet` holds the canonical naming.
    path: String,
    /// Sequence number; matches the `<file_seq>` in the path and the `marf_data.storage_seq` column
    /// of every row backed by this file.
    seq: u32,
    /// Memory-map of the file's current extent. May lag behind appends — readers fall back to
    /// `pread` when the offset is past the map's end. The writer recreates the mmap after each
    /// successful append
    /// + fsync. `None` on freshly-created (zero-length) files; `mmap` requires non-zero file
    /// length.
    mmap: Option<Mmap>,
    /// Whether mmap-acceleration is desired. When `false`, reads always go through `pread` — used
    /// in tests and on platforms where mmap isn't available.
    mmap_enabled: bool,
    /// Per-file reader-fence. See [`ReaderFence`].
    fence: Arc<ReaderFence>,
}

impl HotFile {
    /// Open (or create) a hot file at the given path with the given sequence number. Creates the
    /// file if it doesn't exist; opens read-write so subsequent appends/pwrites can hit the same
    /// fd.
    ///
    /// Use [`Self::open_readonly`] for handles that must not create or modify the file.
    fn open_or_create(path: &str, seq: u32, mmap_enabled: bool) -> Result<Self, Error> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Self::from_fd(fd, path, seq, mmap_enabled)
    }

    /// Open an existing hot file in **read-only** mode. Used by readonly `MARF` handles: never
    /// creates, never truncates, and the resulting fd cannot be used for writes (any pwrite would
    /// fail with `EBADF`).
    ///
    /// Errors if the file doesn't exist — the caller must validate SQL-named hot files before
    /// opening, since a missing file at readonly-open time is a corruption signal.
    fn open_readonly(path: &str, seq: u32, mmap_enabled: bool) -> Result<Self, Error> {
        let fd = OpenOptions::new().read(true).open(path)?;
        Self::from_fd(fd, path, seq, mmap_enabled)
    }

    /// Internal — finalize a `HotFile` from an already-opened fd.
    fn from_fd(fd: File, path: &str, seq: u32, mmap_enabled: bool) -> Result<Self, Error> {
        let file_len = fd.metadata()?.len();
        let mmap = if mmap_enabled && file_len > 0 {
            // SAFETY: the hot file is single-writer (the chainstate coordinator's writer thread).
            // Existing data at existing offsets is append-immutable for as long as we hold this
            // mmap; Phase B's swap protocol quiesces readers (drops their `HotFileReadGuard`s)
            // before any in-place pwrite, so there are no concurrent mutations during the lifetime
            // of an mmap-backed read.
            Some(unsafe { Mmap::map(&fd)? })
        } else {
            None
        };
        Ok(Self {
            fd,
            path: path.to_string(),
            seq,
            mmap,
            mmap_enabled,
            // Share the fence across every `HotFile` opened on this path. Critical for Phase B
            // promotion: the worker thread (operating through its own `MARF::from_path`-reopened
            // `HotFileSet`) and the coordinator (still serving reads from the original handle) must
            // see the same `mutate_pending` flag and contribute to the same `active_reads` count.
            // See [`shared_reader_fence_for`].
            fence: shared_reader_fence_for(path),
        })
    }

    /// Sequence number of this hot file.
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Path on disk (for diagnostics).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Current logical length of the file (the next byte that an append would write to). Read from
    /// the kernel-tracked file metadata, not from any cached length.
    pub fn len(&self) -> Result<u64, Error> {
        Ok(self.fd.metadata()?.len())
    }

    /// Append `buf` to the file's tail. Fsyncs before returning so the caller can safely commit a
    /// SQL row that references the byte range. Returns the offset at which `buf` was written.
    ///
    /// The mmap is recreated after the fsync so readers issued after this call observe the appended
    /// bytes via the fast path.
    pub fn append(&mut self, buf: &[u8]) -> Result<u64, Error> {
        let offset = self.len()?;
        self.fd.write_all_at(buf, offset).map_err(Error::IOError)?;
        self.fd.sync_data()?;
        if self.mmap_enabled {
            // SAFETY: append-only, single-writer, just fsynced. Any pre-existing mmap is a strict
            // prefix of the new contents.
            self.mmap = Some(unsafe { Mmap::map(&self.fd)? });
        }
        Ok(offset)
    }

    /// Read `buf.len()` bytes starting at `offset`. Uses mmap when available and the offset is in
    /// range; otherwise falls back to `pread`. The mmap may lag the file's current extent — that's
    /// expected after a recent append/rotate, and the pread fallback covers it.
    ///
    /// Phase B's promotion swap protocol is the only writer that mutates already-written byte
    /// ranges. It will set `mutate_pending` and drain `active_reads` to zero before the pwrite, so
    /// a reader holding a [`HotFileReadGuard`] cannot observe a torn write.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if let Some(ref mmap) = self.mmap {
            let start = offset as usize;
            if let Some(bytes) = mmap.get(start..) {
                let len = buf.len().min(bytes.len());
                let dst = buf
                    .get_mut(..len)
                    .ok_or_else(|| Error::CorruptionError("hot mmap dst slice".into()))?;
                let src = bytes
                    .get(..len)
                    .ok_or_else(|| Error::CorruptionError("hot mmap src slice".into()))?;
                dst.copy_from_slice(src);
                return Ok(len);
            }
            // Mmap doesn't cover the offset — fall through to pread. Same rationale as
            // `TrieFile::read_bytes_at`: appends from another connection (or this one before the
            // mmap remap) can leave the mmap stale.
        }
        self.fd.read_at(buf, offset).map_err(Error::IOError)
    }

    /// Apply a 4-byte pointer rewrite at the given offset. **Phase B only** — Phase A does not call
    /// this; it is provided so the data-flow boundary between Phase A's resolver code and Phase B's
    /// promotion swap is clear.
    ///
    /// The caller is responsible for setting `mutate_pending` and quiescing `active_reads` before
    /// invoking this; see Phase B's swap protocol in `.docs/squashing-v1.5.md` §6.3.2.
    #[allow(dead_code)]
    pub(crate) fn pwrite_ptr_field(
        &mut self,
        offset: u64,
        new_value: [u8; 4],
    ) -> Result<(), Error> {
        self.fd
            .write_all_at(&new_value, offset)
            .map_err(Error::IOError)?;
        Ok(())
    }

    /// Truncate the file to `new_len` bytes and fsync. Used by startup recovery (Slice A6) to clip
    /// an in-flight torn append based on the SQL-authoritative committed extent.
    pub fn truncate_and_sync(&mut self, new_len: u64) -> Result<(), Error> {
        self.fd.set_len(new_len)?;
        self.fd.sync_data()?;
        if self.mmap_enabled {
            // Drop the old mmap (which may have been zero-length on a never-appended file) and
            // remap iff the file is non-empty afterwards.
            if new_len > 0 {
                self.mmap = Some(unsafe { Mmap::map(&self.fd)? });
            } else {
                self.mmap = None;
            }
        }
        Ok(())
    }

    /// Acquire a clone of this file's reader fence. Internal — exposed only to `HotFileSet`, which
    /// builds a [`HotFileReadGuard`] from it.
    fn fence_clone(&self) -> Arc<ReaderFence> {
        self.fence.clone()
    }
}

/// Set of hot files for a single MARF, indexed by sequence number.
///
/// Holds one *active* hot file (the writer's append target) plus zero or more *rotated* hot files
/// (still referenced by un-promoted block rows). Rotation is size-driven: when the active file's
/// length crosses the rotation threshold, the next append bumps `active_seq` and starts a fresh
/// file at offset 0.
///
/// `HotFileSet` is owned by a single writer (matching the existing `TrieFile` ownership model).
/// Read-side concurrency is mediated through [`HotFileReadGuard`].
pub struct HotFileSet {
    /// DB path stem (no `.hot.` suffix). Used to materialize file paths.
    db_path: String,
    /// All currently-known hot files, keyed by `storage_seq`. Populated at open time by scanning
    /// the disk directory.
    files: HashMap<u32, HotFile>,
    /// Sequence number of the active file. New appends land here.
    active_seq: u32,
    /// Bytes after which the writer rotates. Configurable so tests can trigger rotation cheaply.
    rotation_threshold_bytes: u64,
    /// Whether mmap-acceleration is enabled for hot files. Mirrors `TrieFile`'s mmap toggle.
    mmap_enabled: bool,
}

impl HotFileSet {
    /// Open the hot-file set for a MARF at the given DB path stem (no `.hot.` suffix; matches the
    /// convention `<db>.blobs` uses).
    ///
    /// Behavior:
    ///
    /// 1. Scan the parent directory for files matching `<stem>.hot.*`; parse their sequence numbers
    ///    and open each.
    /// 2. Read `marf_state.active_hot_seq` from the connection.
    /// 3. If the active file isn't on disk, create it (read-write open only; readonly opens
    ///    fail-fast on a missing active file).
    /// 4. **Validate every `storage_seq` referenced by `marf_data`**: each must be present in the
    ///    set with on-disk length ≥ the SQL-committed extent. Missing or short files are corruption
    ///    signals — fail at open rather than later on read.
    /// 5. Return a populated `HotFileSet`.
    pub fn open(
        db_path: &str,
        db: &Connection,
        mmap_enabled: bool,
        rotation_threshold_bytes: u64,
        readonly: bool,
    ) -> Result<Self, Error> {
        let state = trie_sql::read_marf_state(db)?;
        let active_seq = state.active_hot_seq;

        let mut files: HashMap<u32, HotFile> = HashMap::new();
        let parent = Path::new(db_path)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let stem = Path::new(db_path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "hot_file: cannot derive stem from db_path {db_path}"
                ))
            })?
            .to_string();
        let prefix = format!("{stem}{HOT_FILE_PREFIX}");

        if parent.exists() {
            for entry in fs::read_dir(&parent)? {
                let entry = entry?;
                let name = match entry.file_name().to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if let Some(suffix) = name.strip_prefix(&prefix) {
                    if let Ok(seq) = suffix.parse::<u32>() {
                        let path = hot_file_path(db_path, seq);
                        let hot = if readonly {
                            HotFile::open_readonly(&path, seq, mmap_enabled)?
                        } else {
                            HotFile::open_or_create(&path, seq, mmap_enabled)?
                        };
                        files.insert(seq, hot);
                    }
                }
            }
        }

        // Ensure the active file exists. On a fresh writable chainstate the directory scan above
        // finds nothing; create the active file so the writer has a target. A readonly open with no
        // active file on disk is a corruption signal — readonly handles must not synthesize storage
        // that the writer never produced.
        if !files.contains_key(&active_seq) {
            let path = hot_file_path(db_path, active_seq);
            if readonly {
                return Err(Error::CorruptionError(format!(
                    "hot_file: readonly open: active hot file (seq={active_seq}) is missing from \
                     disk at {path}; refusing to synthesize"
                )));
            }
            let hot = HotFile::open_or_create(&path, active_seq, mmap_enabled)?;
            files.insert(active_seq, hot);
        }

        // **Phase C C5 startup reconciliation.** Diff the on-disk file inventory against the
        // SQL-referenced seqs to detect either crash window from C3's `apply_unlinkable`
        // (post-DELETE/pre-unlink → orphan file on disk; post-unlink/pre-DELETE → orphan rows in
        // SQL). RW handles fix; readonly handles fail-closed. Runs BEFORE the validation pass below
        // so the validation operates on consistent state.
        Self::reconcile_after_sweep_crash(&mut files, active_seq, db, db_path, readonly)?;

        // Validate every hot `storage_seq` actually referenced by `marf_data` rows. A missing file
        // or a short file is a corruption signal — fail fast instead of returning `Ok` and
        // discovering it at read time.
        for (seq, committed_len) in trie_sql::referenced_hot_seqs_with_committed_len(db)? {
            let hot = files.get(&seq).ok_or_else(|| {
                Error::CorruptionError(format!(
                    "hot_file: <db>.hot.{seq:08} is referenced by marf_data but not present on disk"
                ))
            })?;
            let on_disk = hot.len()?;
            if on_disk < committed_len {
                return Err(Error::CorruptionError(format!(
                    "hot_file: <db>.hot.{seq:08} is shorter than committed extent \
                     (on_disk={on_disk}, committed={committed_len})"
                )));
            }
        }

        Ok(Self {
            db_path: db_path.to_string(),
            files,
            active_seq,
            rotation_threshold_bytes,
            mmap_enabled,
        })
    }

    /// **Phase C C5 startup reconciliation.** Reconciles the only crash/external-mismatch state
    /// distinguishable from a normal Phase C lifecycle:
    ///
    /// - **Window 2** — *referenced-but-not-on-disk*: SQL has rows referencing a seq, but no file
    ///   is on disk. C3's actual ordering (DELETE → drop_seq → unlink) doesn't produce this, but
    ///   it can occur from external causes (operator manually removed a file, fs corruption, an
    ///   old buggy sweep version, future C3 ordering change). **Fix (RW): DELETE the orphan rows.**
    ///   The data is already gone; C5 cleans up the SQL bookkeeping so the next read against any
    ///   surviving block doesn't hit a phantom-file lookup. Without this reconcile, the existing
    ///   referenced-seqs validation pass below would refuse the open.
    ///
    /// **Window 1 (post-DELETE/pre-unlink) is NOT reconciled here.** Codex 2026-05-02 caught that
    /// window-1's shape ("non-active file on disk, zero hot rows reference it") is exactly the
    /// same as a perfectly normal "all promoted, not yet swept" state — promotion flips rows from
    /// `storage_kind = 1` to `0` but leaves the file on disk for the next sweep trigger to
    /// reclaim (per [phase-c §3.1](#31-c1-hot-file-enumeration--canonical-chain-precompute)
    /// inventory-first design and [Q2](#q2-sweep-on-shutdown) shutdown-sweep deferral). C5 has no
    /// durable discriminator between the two without adding a sidecar marker (rejected: more
    /// complex than the upside warrants), so it punts entirely. Real window-1 leftovers are
    /// reclaimed on the next normal sweep tick: C2a sees `live_rows.is_empty()` → tentative
    /// `Unlinkable` → C2b closure check (no orphans → empty closure) → C3 unlinks. Cost of
    /// punting: an orphan file from a crash leftover sits on disk one extra promotion cycle.
    /// Benefit: zero risk of mis-repairing legitimate consistent-but-unswept state.
    ///
    /// **Readonly** handles fail-closed on window 2 with `CorruptionError` naming the offending
    /// seq(s) and pointing the operator at the RW open path. Mirrors `recover_pending_promotions`'s
    /// established readonly fail-hard policy: a readonly handle has neither permission for SQL
    /// writes nor authority over the on-disk file inventory, and silently proceeding over the
    /// mismatch would return wrong bytes (read resolves to a non-existent file).
    ///
    /// O(referenced_seq_count); small.
    fn reconcile_after_sweep_crash(
        files: &mut HashMap<u32, HotFile>,
        _active_seq: u32,
        db: &Connection,
        _db_path: &str,
        readonly: bool,
    ) -> Result<(), Error> {
        let referenced: HashMap<u32, u64> = trie_sql::referenced_hot_seqs_with_committed_len(db)?
            .into_iter()
            .collect();

        // Window 2 only: referenced seqs with no on-disk file.
        let orphan_seqs: Vec<u32> = referenced
            .keys()
            .filter(|&&seq| !files.contains_key(&seq))
            .copied()
            .collect();

        if orphan_seqs.is_empty() {
            return Ok(());
        }

        if readonly {
            return Err(Error::CorruptionError(format!(
                "hot_file: readonly open observed missing referenced hot file(s) \
                 (orphan_seqs={orphan_seqs:?}); reopen RW to reconcile"
            )));
        }

        for seq in orphan_seqs {
            warn!(
                "hot_file: C5 reconcile: DELETE-ing orphan marf_data rows for seq={seq} \
                 (file missing from disk)"
            );
            db.execute(
                "DELETE FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
                rusqlite::params![seq as i64],
            )
            .map_err(|e| {
                Error::CorruptionError(format!(
                    "hot_file: C5 reconcile: DELETE for seq={seq} failed: {e}"
                ))
            })?;
        }

        Ok(())
    }

    /// Sequence number of the active hot file.
    pub fn active_seq(&self) -> u32 {
        self.active_seq
    }

    /// Configured rotation threshold in bytes.
    pub fn rotation_threshold_bytes(&self) -> u64 {
        self.rotation_threshold_bytes
    }

    /// Override the rotation threshold. Used by tests to trigger rotation
    /// without writing 1 GiB.
    pub fn set_rotation_threshold_bytes(&mut self, bytes: u64) {
        self.rotation_threshold_bytes = bytes;
    }

    /// Number of hot files currently in the set (active + rotated).
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Append `buf` to the currently active hot file. Returns `(storage_seq, offset)` describing
    /// where the bytes landed — suitable for inserting into a `marf_data` row with `storage_kind =
    /// 1`.
    ///
    /// **Rotation note**: this method does NOT rotate. The caller (the writer's flush path) checks
    /// `active_len_after_append` and invokes [`Self::rotate`] when the threshold is crossed; that
    /// keeps the rotation transaction visible at the call site rather than buried inside a
    /// mid-append decision.
    pub fn append_to_active(&mut self, buf: &[u8]) -> Result<(u32, u64), Error> {
        let active_seq = self.active_seq;
        let active = self.files.get_mut(&active_seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: active hot file (seq={active_seq}) missing from set"
            ))
        })?;
        let offset = active.append(buf)?;
        Ok((active_seq, offset))
    }

    /// Length of the currently active hot file, used by the writer to decide whether to rotate.
    pub fn active_len(&self) -> Result<u64, Error> {
        let active = self.files.get(&self.active_seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: active hot file (seq={}) missing from set",
                self.active_seq
            ))
        })?;
        active.len()
    }

    /// Whether the active file is past the rotation threshold and the next append should be
    /// preceded by a rotation.
    pub fn should_rotate(&self) -> Result<bool, Error> {
        Ok(self.active_len()? >= self.rotation_threshold_bytes)
    }

    /// Rotate the active hot file: bump `marf_state.active_hot_seq`, open a new file at `seq + 1`,
    /// and switch the active pointer. The previously-active file remains in the set (and on disk)
    /// until hot-reclaim sweeps it away in Phase C.
    ///
    /// Caller-driven (rather than mid-append automatic) so the SQL transaction boundary is
    /// explicit.
    pub fn rotate(&mut self, db: &Connection) -> Result<u32, Error> {
        let new_seq = self.active_seq.checked_add(1).ok_or_else(|| {
            Error::CorruptionError("hot_file: active_hot_seq exhausted u32".into())
        })?;
        trie_sql::set_active_hot_seq(db, new_seq)?;
        let path = hot_file_path(&self.db_path, new_seq);
        let hot = HotFile::open_or_create(&path, new_seq, self.mmap_enabled)?;
        self.files.insert(new_seq, hot);
        self.active_seq = new_seq;
        Ok(new_seq)
    }

    /// Read bytes from the hot file with the given `storage_seq` at the given `offset`, holding a
    /// [`HotFileReadGuard`] for the duration of the read. Returns the number of bytes read.
    ///
    /// **Reader-fence**: blocks (with backoff) if a writer has set `mutate_pending` on this file —
    /// the swap-phase pwrite protocol (Phase B) needs an exclusive window. This ensures no read
    /// observes a torn ptr-field rewrite. See [`HotFileReadGuard::try_from_fence`] for the
    /// protocol.
    ///
    /// Returns an error if the hot file isn't in the set — that indicates a `marf_data` row points
    /// at a hot file that was already reclaimed, which Phase A treats as corruption.
    pub fn read_at(&self, seq: u32, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        let hot = self.files.get(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: read for seq={seq} but file not in set (already reclaimed?)"
            ))
        })?;
        let _guard = self.acquire_read_guard(seq)?;
        hot.read_at(buf, offset)
    }

    /// Acquire a read guard on the hot file with the given sequence number. Blocks (with backoff)
    /// if a writer has signaled `mutate_pending` on this file. The guard is dropped automatically
    /// when the read scope ends; Phase B's promotion swap protocol waits for guards on touched
    /// files to drain before issuing in-place pwrites.
    ///
    /// Backoff strategy: exponentially escalates from 100µs to ~10ms per spin. The expected wait is
    /// single-digit milliseconds (the swap window is ~50–200ms total per the design doc, and
    /// individual pwrite batches are bounded by the rewrite-plan size). A reader that's blocked for
    /// more than a few seconds indicates a stuck writer and is logged.
    pub fn acquire_read_guard(&self, seq: u32) -> Result<HotFileReadGuard, Error> {
        let hot = self.files.get(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: read-guard request for seq={seq} but file not in set"
            ))
        })?;
        let fence = hot.fence_clone();
        let mut sleep_us: u64 = 100;
        let mut total_waited = std::time::Duration::ZERO;
        let warn_threshold = std::time::Duration::from_secs(2);
        let mut warned = false;
        loop {
            if let Some(guard) = HotFileReadGuard::try_from_fence(fence.clone(), seq) {
                return Ok(guard);
            }
            let nap = std::time::Duration::from_micros(sleep_us);
            std::thread::sleep(nap);
            total_waited += nap;
            if !warned && total_waited >= warn_threshold {
                warn!(
                    "hot_file: reader has been waiting {} ms for the writer's \
                     mutate_pending fence on seq={seq} to clear; possible stuck swap",
                    total_waited.as_millis(),
                );
                warned = true;
            }
            // Cap individual nap at ~10 ms; total wait grows with the outer cadence loop but each
            // spin stays bounded so we pick up the writer's clear quickly.
            sleep_us = std::cmp::min(sleep_us.saturating_mul(2), 10_000);
        }
    }

    /// Set the per-file `mutate_pending` flag for the hot file with the given sequence number.
    /// Phase B's swap path sets this to `true` before issuing pwrites and clears it after. Readers
    /// arriving while the flag is set back off until it clears.
    ///
    /// Returns an error if the hot file isn't in the set.
    pub fn set_mutate_pending(&self, seq: u32, pending: bool) -> Result<(), Error> {
        let hot = self.files.get(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: set_mutate_pending for seq={seq} but file not in set"
            ))
        })?;
        hot.fence
            .mutate_pending
            .store(pending, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Wait for `active_reads == 0` on the hot file with the given sequence number, with `timeout`
    /// as a hard upper bound. Returns `Ok(())` once readers have drained,
    /// `Err(Error::InProgressError)` if `timeout` elapses first.
    ///
    /// Caller must have set `mutate_pending = true` first; otherwise new readers can keep arriving
    /// and `active_reads` may never drain.
    pub fn wait_for_quiesce(&self, seq: u32, timeout: std::time::Duration) -> Result<(), Error> {
        let hot = self.files.get(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: wait_for_quiesce for seq={seq} but file not in set"
            ))
        })?;
        let start = std::time::Instant::now();
        let mut sleep_us: u64 = 50;
        loop {
            if hot
                .fence
                .active_reads
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(Error::InProgressError);
            }
            std::thread::sleep(std::time::Duration::from_micros(sleep_us));
            sleep_us = std::cmp::min(sleep_us.saturating_mul(2), 5_000);
        }
    }

    /// Apply a 4-byte ptr-field rewrite at `(seq, offset)` in the hot file with the given sequence
    /// number. Phase B's promotion swap protocol and crash recovery use this to publish
    /// post-promotion offsets over previously-captured hot-layout offsets.
    ///
    /// The caller is responsible for quiescing readers (acquiring the per-file `mutate_pending`
    /// fence + waiting for `active_reads == 0`) before invoking this on a file with live
    /// mmap-backed readers; B5's swap path will own that protocol. Recovery (B2) runs before any
    /// reader exists, so it doesn't need quiescing.
    pub fn pwrite_ptr_field(
        &mut self,
        seq: u32,
        offset: u64,
        new_value: [u8; 4],
    ) -> Result<(), Error> {
        let hot = self.files.get_mut(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: pwrite for seq={seq} but file not in set"
            ))
        })?;
        hot.pwrite_ptr_field(offset, new_value)
    }

    /// `fsync` (via `sync_data`) the hot file with the given sequence number. Used by Phase B
    /// recovery to make rewrite-plan pwrites durable before committing the SQL transaction; later
    /// by the swap phase for the same purpose.
    pub fn fsync_seq(&mut self, seq: u32) -> Result<(), Error> {
        let hot = self.files.get_mut(&seq).ok_or_else(|| {
            Error::CorruptionError(format!("hot_file: fsync for seq={seq} but file not in set"))
        })?;
        hot.fd.sync_data().map_err(Error::IOError)
    }

    /// Truncate the active hot file to `new_len`. Used by startup recovery (Slice A6) to clip an
    /// in-flight torn append based on the highest committed extent in `marf_data`.
    pub fn truncate_active(&mut self, new_len: u64) -> Result<(), Error> {
        let active_seq = self.active_seq;
        let active = self.files.get_mut(&active_seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: active hot file (seq={active_seq}) missing from set"
            ))
        })?;
        active.truncate_and_sync(new_len)
    }

    /// Iterate `(seq, &HotFile)` pairs. Mostly for diagnostics / tests.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &HotFile)> {
        self.files.iter().map(|(&seq, hot)| (seq, hot))
    }

    /// Look up the on-disk path of the hot file with the given sequence number. Used by Phase C's
    /// [`apply_unlinkable`](super::hot_reclaim::apply_unlinkable) to capture the path BEFORE
    /// [`Self::drop_seq`] removes the entry, so the subsequent `unlink(2)` knows where to delete.
    ///
    /// Returns `Err(CorruptionError)` if `seq` isn't in the set — the caller is mis-ordered (the
    /// path-capture must come before any drop).
    pub fn path_for_seq(&self, seq: u32) -> Result<&str, Error> {
        let hot = self.files.get(&seq).ok_or_else(|| {
            Error::CorruptionError(format!(
                "hot_file: path_for_seq for seq={seq} but file not in set"
            ))
        })?;
        Ok(hot.path())
    }

    /// Remove the in-memory `HotFile` entry for `seq`, closing the owned file descriptor + dropping
    /// the strong `Arc<ReaderFence>` reference. The cross-handle fence registry's entry decays to
    /// `Weak::dead` once any peer-handle's strong refs also drop.
    ///
    /// Phase C only — this is the in-memory half of the unlink protocol implemented by
    /// [`apply_unlinkable`](super::hot_reclaim::apply_unlinkable). The caller is responsible for
    /// the full sequence: quiesce readers via [`Self::set_mutate_pending`] +
    /// [`Self::wait_for_quiesce`], DELETE the matching `marf_data` rows, clear `mutate_pending`,
    /// THEN call this, THEN `unlink(2)` the file. Out-of-order use (e.g. dropping while a reader
    /// holds an mmap) is safe at the POSIX level (the mmap survives until last-fd-close) but
    /// violates the sweep's invariant that no in-flight reader exists past `wait_for_quiesce`.
    ///
    /// Idempotent on absent seq (returns `Ok(())`): startup reconciliation may invoke this for a
    /// seq that's already gone if a prior crash unlinked the file before clearing the in-memory
    /// state. Erroring there would push false-positive corruption into the recovery path.
    pub fn drop_seq(&mut self, seq: u32) -> Result<(), Error> {
        self.files.remove(&seq);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rusqlite::Connection;
    use stacks_common::types::chainstate::BlockHeaderHash;

    use super::*;
    use crate::chainstate::stacks::index::trie_sql;

    /// Build a fresh on-disk MARF DB at v5 schema and return its path (with no `.hot.*` files yet).
    fn fresh_v5_db(test_name: &str) -> (PathBuf, Connection) {
        // Per-test directory under target/tmp so concurrent tests don't collide. The path stem is
        // the sqlite filename — file.rs uses the same convention for `<db>.blobs`.
        let tmp_root = std::env::temp_dir().join("hot_file_tests").join(test_name);
        let _ = fs::remove_dir_all(&tmp_root);
        fs::create_dir_all(&tmp_root).unwrap();
        let db_path = tmp_root.join("marf.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        trie_sql::create_tables_if_needed(&mut conn).unwrap();
        trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut conn).unwrap();
        (db_path, conn)
    }

    #[test]
    fn hot_file_set_open_creates_active_file_on_fresh_db() {
        let (db_path, conn) = fresh_v5_db("hot_file_set_open_creates_active_file_on_fresh_db");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        // Fresh chainstate: the active hot file (seq=1, the schema default) should have been
        // created by `open` even though the directory scan found nothing.
        assert_eq!(set.active_seq(), 1);
        assert_eq!(set.file_count(), 1);
        let path = hot_file_path(stem, 1);
        assert!(
            fs::metadata(&path).is_ok(),
            "active hot file should exist on disk"
        );
    }

    #[test]
    fn hot_file_append_then_read_round_trips_bytes() {
        let (db_path, conn) = fresh_v5_db("hot_file_append_then_read_round_trips_bytes");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let payload = b"hello hot zone";
        let (seq, offset) = set.append_to_active(payload).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(offset, 0, "first append starts at offset 0");

        let mut buf = vec![0u8; payload.len()];
        let n = set.read_at(seq, &mut buf, offset).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(buf, payload);

        // A second append lands immediately after the first.
        let payload2 = b"second";
        let (seq2, offset2) = set.append_to_active(payload2).unwrap();
        assert_eq!(seq2, 1);
        assert_eq!(offset2, payload.len() as u64);
        let mut buf2 = vec![0u8; payload2.len()];
        set.read_at(seq2, &mut buf2, offset2).unwrap();
        assert_eq!(buf2, payload2);
    }

    #[test]
    fn hot_file_rotate_bumps_seq_and_starts_fresh_offset() {
        let (db_path, conn) = fresh_v5_db("hot_file_rotate_bumps_seq_and_starts_fresh_offset");
        let stem = db_path.to_str().unwrap();
        // 32-byte rotation threshold — easy to cross.
        let mut set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
        set.append_to_active(&[0xab; 33]).unwrap();
        assert!(set.should_rotate().unwrap(), "33 bytes > 32-byte threshold");

        let new_seq = set.rotate(&conn).unwrap();
        assert_eq!(new_seq, 2);
        assert_eq!(set.active_seq(), 2);
        // Both files are tracked in the set.
        assert_eq!(set.file_count(), 2);

        // Append after rotate lands at offset 0 of seq=2.
        let payload = b"post-rotate";
        let (seq, offset) = set.append_to_active(payload).unwrap();
        assert_eq!(seq, 2);
        assert_eq!(offset, 0);

        // marf_state was updated.
        let state = trie_sql::read_marf_state(&conn).unwrap();
        assert_eq!(state.active_hot_seq, 2);
    }

    #[test]
    fn hot_file_set_open_picks_up_existing_files() {
        let (db_path, conn) = fresh_v5_db("hot_file_set_open_picks_up_existing_files");
        let stem = db_path.to_str().unwrap();
        // Round 1: append + rotate so two files exist on disk.
        {
            let mut set = HotFileSet::open(stem, &conn, false, 16, false).unwrap();
            set.append_to_active(&[0u8; 17]).unwrap();
            set.rotate(&conn).unwrap();
            set.append_to_active(b"hi").unwrap();
        }
        // Round 2: re-open — the directory scan should find both files and pick the active one from
        // marf_state.
        let set = HotFileSet::open(stem, &conn, false, 16, false).unwrap();
        assert_eq!(
            set.file_count(),
            2,
            "directory scan should find both rotated and active files"
        );
        assert_eq!(set.active_seq(), 2, "active_seq comes from marf_state");
    }

    #[test]
    fn hot_file_read_guard_increments_and_decrements() {
        let (db_path, conn) = fresh_v5_db("hot_file_read_guard_increments_and_decrements");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let active_seq = set.active_seq();

        let fence = set.files.get(&active_seq).unwrap().fence.clone();
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 0);

        let guard = set.acquire_read_guard(active_seq).unwrap();
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 1);
        let guard2 = guard.clone();
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 2);
        drop(guard);
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 1);
        drop(guard2);
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hot_file_read_guard_per_file_isolation() {
        let (db_path, conn) = fresh_v5_db("hot_file_read_guard_per_file_isolation");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 16, false).unwrap();
        set.append_to_active(&[0u8; 17]).unwrap();
        set.rotate(&conn).unwrap();
        // seq=1 (rotated) and seq=2 (active) coexist.
        let g1 = set.acquire_read_guard(1).unwrap();
        let _g2 = set.acquire_read_guard(2).unwrap();
        // Per-file counters: dropping g1 must not affect seq=2.
        let fence_seq2 = set.files.get(&2).unwrap().fence.clone();
        assert_eq!(fence_seq2.active_reads.load(Ordering::SeqCst), 1);
        drop(g1);
        assert_eq!(
            fence_seq2.active_reads.load(Ordering::SeqCst),
            1,
            "dropping a guard on seq=1 must not decrement seq=2's counter"
        );
    }

    #[test]
    fn hot_file_truncate_active_clips_to_new_len() {
        let (db_path, conn) = fresh_v5_db("hot_file_truncate_active_clips_to_new_len");
        let stem = db_path.to_str().unwrap();
        let mut set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        set.append_to_active(&[0xcd; 100]).unwrap();
        assert_eq!(set.active_len().unwrap(), 100);

        set.truncate_active(40).unwrap();
        assert_eq!(set.active_len().unwrap(), 40);
    }

    #[test]
    fn reader_fence_blocks_when_mutate_pending_is_set() {
        // Reader-fence protocol: when `mutate_pending` is set, a reader's `try_from_fence` returns
        // `None` so the caller can back off. The full `acquire_read_guard` blocks until cleared;
        // this test exercises the lower-level `try_from_fence` to keep the test fast (no
        // thread::sleep).
        let (db_path, conn) = fresh_v5_db("reader_fence_blocks_when_mutate_pending_is_set");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let active_seq = set.active_seq();

        // Default state: no mutate_pending, guard acquires immediately.
        let g = set.acquire_read_guard(active_seq).unwrap();
        drop(g);

        // Set mutate_pending → try_from_fence returns None.
        set.set_mutate_pending(active_seq, true).unwrap();
        let fence = set.files.get(&active_seq).unwrap().fence_clone();
        assert!(
            HotFileReadGuard::try_from_fence(fence.clone(), active_seq).is_none(),
            "reader must back off when mutate_pending is set"
        );
        // active_reads should be 0 (nothing acquired).
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 0);

        // Clear mutate_pending → reader acquires.
        set.set_mutate_pending(active_seq, false).unwrap();
        let g = HotFileReadGuard::try_from_fence(fence.clone(), active_seq).unwrap();
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 1);
        drop(g);
        assert_eq!(fence.active_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn writer_quiesce_drains_active_reads_before_proceeding() {
        let (db_path, conn) = fresh_v5_db("writer_quiesce_drains_active_reads_before_proceeding");
        let stem = db_path.to_str().unwrap();
        let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let active_seq = set.active_seq();

        // No active readers → quiesce returns immediately.
        set.wait_for_quiesce(active_seq, std::time::Duration::from_millis(10))
            .unwrap();

        // Acquire a guard; quiesce should time out while it's held.
        let g = set.acquire_read_guard(active_seq).unwrap();
        let result = set.wait_for_quiesce(active_seq, std::time::Duration::from_millis(50));
        assert!(
            matches!(result, Err(Error::InProgressError)),
            "quiesce must time out while a reader is active",
        );
        drop(g);
        // After dropping, quiesce returns Ok.
        set.wait_for_quiesce(active_seq, std::time::Duration::from_millis(10))
            .unwrap();
    }

    #[test]
    fn read_at_acquires_a_guard_for_the_read() {
        // `read_at` must take a `HotFileReadGuard` for the duration of the read, so a writer that's
        // set `mutate_pending` makes `read_at` BLOCK until it clears. We verify by spawning the
        // reader in a thread, observing it doesn't complete while the flag is set, then clearing
        // and observing completion.
        //
        // `HotFileSet`'s read-side methods (`read_at`, `set_mutate_pending`) all take `&self`, so
        // concurrent access via `Arc<HotFileSet>` is sound (no mutex needed — the underlying
        // `HotFile.fd` Read/Write split is via `pread`/`pwrite_at` syscalls which are
        // concurrent-safe; the fence is atomics).
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let (db_path, conn) = fresh_v5_db("read_at_acquires_a_guard_for_the_read");
        let stem = db_path.to_str().unwrap().to_string();
        let mut set = HotFileSet::open(&stem, &conn, false, 1 << 20, false).unwrap();
        let payload = b"some bytes";
        let (seq, offset) = set.append_to_active(payload).unwrap();
        set.set_mutate_pending(seq, true).unwrap();
        let set = Arc::new(set);

        let done = Arc::new(AtomicBool::new(false));
        let done_for_thread = done.clone();
        let set_for_thread = set.clone();
        let payload_len = payload.len();
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; payload_len];
            let n = set_for_thread.read_at(seq, &mut buf, offset).unwrap();
            assert_eq!(n, payload_len);
            done_for_thread.store(true, Ordering::SeqCst);
        });

        // Wait briefly; the reader should NOT complete because mutate_pending is set.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !done.load(Ordering::SeqCst),
            "reader must block while mutate_pending is set"
        );

        // Clear mutate_pending → reader proceeds.
        set.set_mutate_pending(seq, false).unwrap();
        reader.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn reader_fence_is_shared_across_independent_hot_file_set_instances() {
        // The cross-handle fence story: Phase B's promotion worker reopens the chainstate via
        // `MARF::from_path`, getting a fresh `HotFileSet`. If the worker's `HotFile` had its own
        // `Arc<ReaderFence>`, the worker's `set_mutate_pending` wouldn't block readers on the
        // coordinator's still-live handle — torn-write race.
        //
        // The process-wide registry (`shared_reader_fence_for`) closes that gap: two `HotFileSet`
        // opens against the same path see the same `Arc<ReaderFence>`, and a write from one is
        // observed by readers on the other.
        let (db_path, conn) =
            fresh_v5_db("reader_fence_is_shared_across_independent_hot_file_set_instances");
        let stem = db_path.to_str().unwrap();
        let set_a = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let set_b = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let active_seq = set_a.active_seq();
        assert_eq!(active_seq, set_b.active_seq());

        // Same Arc<ReaderFence> instance under each handle's HotFile.
        let fence_a = set_a.files.get(&active_seq).unwrap().fence_clone();
        let fence_b = set_b.files.get(&active_seq).unwrap().fence_clone();
        assert!(
            Arc::ptr_eq(&fence_a, &fence_b),
            "two HotFileSet opens on the same path must share the same ReaderFence Arc"
        );

        // Cross-handle observability: set_a flips mutate_pending, set_b's try_from_fence sees it.
        set_a.set_mutate_pending(active_seq, true).unwrap();
        assert!(
            HotFileReadGuard::try_from_fence(fence_b.clone(), active_seq).is_none(),
            "writer on handle A must block readers on handle B"
        );
        set_a.set_mutate_pending(active_seq, false).unwrap();

        // And cross-handle quiesce: a guard taken on set_b is observed by set_a's wait_for_quiesce.
        let g = set_b.acquire_read_guard(active_seq).unwrap();
        let result = set_a.wait_for_quiesce(active_seq, std::time::Duration::from_millis(50));
        assert!(
            matches!(result, Err(Error::InProgressError)),
            "set_a's quiesce must observe set_b's reader and time out"
        );
        drop(g);
        set_a
            .wait_for_quiesce(active_seq, std::time::Duration::from_millis(50))
            .unwrap();
    }

    #[test]
    fn reader_fence_registry_releases_when_last_handle_drops() {
        // Sanity: the registry uses `Weak`, so once every `Arc<ReaderFence>` is dropped, a
        // subsequent open builds a fresh fence (and the old `mutate_pending` state — set on the
        // dead Arc — does not leak into the new one).
        let (db_path, conn) = fresh_v5_db("reader_fence_registry_releases_when_last_handle_drops");
        let stem = db_path.to_str().unwrap();

        let active_seq = {
            let set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
            let active_seq = set.active_seq();
            // Stick mutate_pending so we'd notice if the same fence got reused below.
            set.set_mutate_pending(active_seq, true).unwrap();
            active_seq
            // `set` drops here; with no other handles open, the registry's Weak should be dead on
            // the next open.
        };

        let set2 = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        let fence = set2.files.get(&active_seq).unwrap().fence_clone();
        assert!(
            !fence.mutate_pending.load(Ordering::Acquire),
            "fresh open after all handles dropped must produce a clean fence"
        );
    }

    // ===========================================================================
    // C5: startup reconciliation (sweep-crash window cleanup)
    // ===========================================================================
    //
    // Both crash windows are arranged manually here (no test hook through `apply_unlinkable`)
    // because we want focused regressions for the reconcile logic itself. The integration scenario
    // (real crash mid-sweep → recovery on next open) is heavier and lives with the C6 e2e suite.

    /// Insert a synthetic hot `marf_data` row pointing at `seq`. Mirrors the helper in
    /// `hot_reclaim::tests` but local to this module (which can't share a private test helper
    /// across module boundaries).
    fn insert_synthetic_hot_row(
        conn: &Connection,
        block_byte: u8,
        seq: u32,
        offset: u64,
        length: u64,
    ) {
        let mut bytes = [0u8; 32];
        bytes[31] = block_byte;
        let bhh = BlockHeaderHash(bytes);
        conn.execute(
            "INSERT INTO marf_data \
             (block_hash, data, unconfirmed, external_offset, external_length, \
              storage_kind, storage_seq) \
             VALUES (?1, x'', 0, ?2, ?3, 1, ?4)",
            rusqlite::params![bhh, offset as i64, length as i64, seq as i64],
        )
        .unwrap();
    }

    fn count_marf_rows_for_seq(conn: &Connection, seq: u32) -> u64 {
        conn.query_row(
            "SELECT COUNT(*) FROM marf_data WHERE storage_kind = 1 AND storage_seq = ?1",
            rusqlite::params![seq as i64],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .unwrap()
    }

    /// **Regression for the Codex 2026-05-02 window-1 indistinguishability finding**: a non-active
    /// hot file with zero referencing rows is the EXPECTED post-promotion-pre-sweep state, NOT a
    /// crash. C5 must pass through it untouched on both RW and readonly opens; the next normal
    /// sweep tick (C4) reclaims it via C2a's empty-`live_rows` Unlinkable verdict. If C5 ever
    /// regrows window-1 detection without a durable discriminator, this test fails.
    #[test]
    fn c5_passes_through_post_promotion_pre_sweep_file() {
        let (db_path, conn) = fresh_v5_db("c5_passes_through_post_promotion_pre_sweep_file");
        let stem = db_path.to_str().unwrap();
        // Build seq=1 (rotated → no rows reference it) + active=2. Same shape as a real
        // "all promoted, not yet swept" file.
        {
            let mut set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
            set.append_to_active(&[0xab; 33]).unwrap();
            set.rotate(&conn).unwrap();
            assert_eq!(set.active_seq(), 2);
        }
        let path = hot_file_path(stem, 1);
        assert!(fs::metadata(&path).is_ok(), "file present pre-reopen");

        // RW reopen: file MUST stay on disk (C5 doesn't touch it).
        let set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
        assert!(
            fs::metadata(&path).is_ok(),
            "C5 must NOT unlink consistent-but-unswept file (regression: window-1 \
             indistinguishability)"
        );
        assert!(
            set.iter().any(|(s, _)| s == 1),
            "rotated seq still in HotFileSet"
        );
        drop(set);

        // Readonly reopen: must also pass through cleanly. Window-2-only fail-hard policy means
        // this state is NOT a corruption signal.
        let _set = HotFileSet::open(stem, &conn, false, 32, true).unwrap();
        assert!(
            fs::metadata(&path).is_ok(),
            "readonly open must NOT mutate disk and must NOT error on this state"
        );
    }

    /// **Window 2 (post-unlink/pre-DELETE) on RW open**: SQL has rows referencing a seq with no
    /// file on disk. RW reconcile DELETEs the orphan rows; the reopen succeeds.
    #[test]
    fn c5_rw_reconcile_deletes_orphan_marf_data_rows() {
        let (db_path, conn) = fresh_v5_db("c5_rw_reconcile_deletes_orphan_marf_data_rows");
        let stem = db_path.to_str().unwrap();
        // Build the active file (seq=1).
        {
            let _set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        }
        // Insert a marf_data row pointing at seq=99 — no such file exists. Simulates post-unlink
        // state where unlink succeeded but DELETE didn't (or any external cause of the same
        // mismatch — see reconcile rustdoc for the asymmetry rationale).
        insert_synthetic_hot_row(&conn, 1, 99, 0, 64);
        assert_eq!(count_marf_rows_for_seq(&conn, 99), 1);

        // RW reopen → reconcile DELETEs the orphan rows; open succeeds (the existing validation
        // pass would otherwise fail with "referenced by marf_data but not present on disk").
        let _set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        assert_eq!(
            count_marf_rows_for_seq(&conn, 99),
            0,
            "orphan rows must be DELETEd by C5 RW reconcile"
        );
    }

    /// **Window 2 on readonly open**: orphan rows in SQL with no on-disk file → CorruptionError;
    /// SQL rows untouched.
    #[test]
    fn c5_readonly_observes_orphan_marf_data_rows_returns_corruption_error() {
        let (db_path, conn) =
            fresh_v5_db("c5_readonly_observes_orphan_marf_data_rows_returns_corruption_error");
        let stem = db_path.to_str().unwrap();
        {
            let _set = HotFileSet::open(stem, &conn, false, 1 << 20, false).unwrap();
        }
        insert_synthetic_hot_row(&conn, 1, 99, 0, 64);

        match HotFileSet::open(stem, &conn, false, 1 << 20, true) {
            Ok(_) => panic!("readonly open over orphan rows must error"),
            Err(Error::CorruptionError(msg)) => {
                assert!(
                    msg.contains("readonly"),
                    "message must call out readonly: {msg}"
                );
                assert!(
                    msg.contains("orphan_seqs"),
                    "message must name the orphan: {msg}"
                );
            }
            Err(other) => panic!("expected CorruptionError, got {other:?}"),
        }
        assert_eq!(
            count_marf_rows_for_seq(&conn, 99),
            1,
            "readonly reconcile must NOT mutate SQL — orphan rows stay"
        );
    }

    /// **Window 2 with multiple orphan seqs in a single open**: the reconcile DELETEs every
    /// orphan seq's rows in one pass, regardless of how many there are. Coexistence with a
    /// legitimate consistent-but-unswept (zero-row, on-disk) file proves the reconcile only
    /// touches window-2 cases.
    #[test]
    fn c5_rw_reconcile_handles_multiple_orphan_seqs_and_passes_through_unswept() {
        let (db_path, conn) =
            fresh_v5_db("c5_rw_reconcile_handles_multiple_orphan_seqs_and_passes_through_unswept");
        let stem = db_path.to_str().unwrap();
        // Build seq=1 (rotated, no rows → consistent-but-unswept; C5 must NOT touch) + active=2.
        {
            let mut set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
            set.append_to_active(&[0xab; 33]).unwrap();
            set.rotate(&conn).unwrap();
        }
        // Insert window-2 orphan rows referencing TWO distinct missing seqs.
        insert_synthetic_hot_row(&conn, 1, 98, 0, 64);
        insert_synthetic_hot_row(&conn, 2, 99, 0, 64);
        insert_synthetic_hot_row(&conn, 3, 99, 64, 64);
        assert_eq!(count_marf_rows_for_seq(&conn, 98), 1);
        assert_eq!(count_marf_rows_for_seq(&conn, 99), 2);
        assert!(fs::metadata(hot_file_path(stem, 1)).is_ok());

        let _set = HotFileSet::open(stem, &conn, false, 32, false).unwrap();
        assert_eq!(
            count_marf_rows_for_seq(&conn, 98),
            0,
            "window-2 orphan rows for seq=98 must be DELETEd"
        );
        assert_eq!(
            count_marf_rows_for_seq(&conn, 99),
            0,
            "window-2 orphan rows for seq=99 must be DELETEd"
        );
        assert!(
            fs::metadata(hot_file_path(stem, 1)).is_ok(),
            "consistent-but-unswept seq=1 file must NOT be touched"
        );
    }
}
