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

#![warn(dead_code)]

use std::hash::Hash;
use std::ops::Deref;
use std::sync::{Arc, OnceLock};
use std::{error, fmt, io};

use sha2::{Digest, Sha512_256 as TrieHasher};
#[cfg(test)]
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::{
    BurnchainHeaderHash, SortitionId, StacksBlockId, TrieHash, TRIEHASH_ENCODED_SIZE,
};

use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::util_lib::db::Error as db_error;

pub mod bits;
pub mod cache;
pub mod file;
pub mod marf;
pub mod node;
pub mod profile;
pub mod proofs;
pub mod scratch;
pub mod squash;
pub mod storage;
pub mod trie;
pub mod trie_sql;

#[cfg(test)]
pub mod test;

use crate::chainstate::stacks::index::node::{
    ParkedNodeHandle, TrieLeafRef, TrieLeafSquashedRef, TrieNodeID, TrieNodePatch, TrieNodeRef,
    TrieNodeTransientMeta, TrieNodeType, TriePtr,
};

#[derive(Debug)]
pub struct TrieMerkleProof<T: MarfTrieId>(pub Vec<TrieMerkleProofType<T>>);

pub trait ClarityMarfTrieId:
    PartialEq + Clone + std::fmt::Display + std::fmt::Debug + std::convert::From<[u8; 32]>
{
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(self) -> [u8; 32];
    fn from_bytes(from: [u8; 32]) -> Self;
    fn sentinel() -> Self;
}

#[derive(Clone)]
pub enum TrieMerkleProofType<T> {
    Node4((u8, ProofTrieNode<T>, [TrieHash; 3])),
    Node16((u8, ProofTrieNode<T>, [TrieHash; 15])),
    Node48((u8, ProofTrieNode<T>, [TrieHash; 47])),
    Node256((u8, ProofTrieNode<T>, [TrieHash; 255])),
    Leaf((u8, TrieLeaf)),
    Shunt((i64, Vec<TrieHash>)),
}

/// Merkle Proof Trie Pointers have a different structure
///   than the runtime representation --- the proof includes
///   the block header hash for back pointers.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofTrieNode<T> {
    pub id: u8,
    pub path: Vec<u8>,
    pub ptrs: Vec<ProofTriePtr<T>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProofTriePtr<T> {
    pub id: u8,
    pub chr: u8,
    pub back_block: T,
}

/// A compressed trie path segment, stored inline as a fixed-size array.
///
/// Replaces `Vec<u8>` on all trie node types. Maximum length is 32 bytes
/// (the size of a `TrieHash`), enforced at construction time.
///
/// `NodePath` is `Copy`, so cloning nodes no longer heap-allocates for the path field.
#[derive(Clone, Copy, Default)]
pub struct NodePath {
    data: [u8; 32],
    len: u8,
}

impl PartialEq for NodePath {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for NodePath {}

impl NodePath {
    /// Create a `NodePath` from a byte slice. Returns `None` if `s.len() > 32`.
    #[inline]
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        let len = s.len();
        if len > 32 {
            return None;
        }
        let mut data = [0u8; 32];
        data.get_mut(..len)?.copy_from_slice(s);
        Some(Self {
            data,
            len: len as u8,
        })
    }

    /// The path bytes as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // `len` is always <= 32: only set by validated paths (try_from_slice, try_set_from_slice,
        // read_from after bits::path_from_bytes_* validates TRIEHASH_ENCODED_SIZE).
        self.data
            .get(..self.len as usize)
            .expect("BUG: NodePath len invariant violated")
    }

    /// The length of the path in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if the path is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set the path from a reader.
    ///
    /// `len` must be <= 32 (callers validate via [`TRIEHASH_ENCODED_SIZE`] before calling).
    #[inline]
    pub fn read_from<R: io::Read>(&mut self, len: u8, r: &mut R) -> Result<(), io::Error> {
        self.len = len;
        r.read_exact(
            self.data
                .get_mut(..len as usize)
                .expect("BUG: NodePath::read_from called with len > 32"),
        )
    }

    /// Set the path from a byte slice. Returns `None` if `s.len() > 32`.
    #[inline]
    pub fn set_from_slice(&mut self, s: &[u8]) -> Option<()> {
        let len = s.len();
        if len > 32 {
            return None;
        }
        self.data.get_mut(..len)?.copy_from_slice(s);
        self.len = len as u8;
        Some(())
    }
}

impl Deref for NodePath {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for NodePath {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for NodePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodePath({})",
            crate::util::hash::to_hex(self.as_slice())
        )
    }
}

/// Leaf of a Trie.
#[derive(Clone)]
pub struct TrieLeaf {
    pub path: NodePath,
    pub data: MARFValue, // the actual data
}

pub trait MarfTrieId:
    ClarityMarfTrieId
    + rusqlite::types::ToSql
    + rusqlite::types::FromSql
    + stacks_common::codec::StacksMessageCodec
    + std::convert::From<MARFValue>
    + PartialEq
    + Eq
    + Hash
{
}

pub const SENTINEL_ARRAY: [u8; 32] = [255u8; 32];

macro_rules! impl_clarity_marf_trie_id {
    ($thing:ident) => {
        impl ClarityMarfTrieId for $thing {
            fn as_bytes(&self) -> &[u8] {
                self.as_ref()
            }
            fn to_bytes(self) -> [u8; 32] {
                self.0
            }
            fn sentinel() -> Self {
                Self(SENTINEL_ARRAY.clone())
            }
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<MARFValue> for $thing {
            fn from(m: MARFValue) -> Self {
                let h = m.0;
                let mut d = [0u8; 32];
                d.copy_from_slice(&h[..32]);
                for x in &h[32..] {
                    if *x != 0 {
                        panic!(
                            "Failed to convert MARF value into BHH: data stored after 32nd byte"
                        );
                    }
                }
                Self(d)
            }
        }
    };
}

impl_clarity_marf_trie_id!(BurnchainHeaderHash);
impl_clarity_marf_trie_id!(StacksBlockId);
impl_clarity_marf_trie_id!(SortitionId);
#[cfg(test)]
impl_clarity_marf_trie_id!(BlockHeaderHash);

impl MarfTrieId for SortitionId {}
impl MarfTrieId for StacksBlockId {}
impl MarfTrieId for BurnchainHeaderHash {}
#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

/// Define the maximum node patching depth when MARF compression is enabled
pub const MAX_PATCH_DEPTH: u32 = 4;

/// Structure that holds the actual data in a MARF leaf node.
/// It only stores the hash of some value string, but we add 8 extra bytes for future extensions.
/// If not used (the rule today), then they should all be 0.
pub struct MARFValue(pub [u8; 40]);
impl_array_newtype!(MARFValue, u8, 40);
impl_array_hexstring_fmt!(MARFValue);
impl_byte_array_newtype!(MARFValue, u8, 40);
impl_byte_array_message_codec!(MARFValue, 40);
pub const MARF_VALUE_ENCODED_SIZE: u32 = 40;

impl From<String> for MARFValue {
    #[inline]
    fn from(s: String) -> Self {
        let mut hasher = TrieHasher::new();
        hasher.update(s.as_bytes());
        let tmp = hasher.finalize().into();

        MARFValue::from_value_hash_bytes(&tmp)
    }
}

impl From<u32> for MARFValue {
    fn from(value: u32) -> MARFValue {
        let h = value.to_le_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a u32 into a MARF Value.");
        }
        d.get_mut(..h.len())
            .expect("Cannot convert a u32 into a MARF Value")
            .copy_from_slice(&h);
        MARFValue(d)
    }
}

impl<T: MarfTrieId> From<T> for MARFValue {
    fn from(bhh: T) -> MARFValue {
        let h = bhh.to_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a BHH into a MARF Value.");
        }
        d.get_mut(..h.len())
            .expect("Cannot convert a BHH into a MARF Value")
            .copy_from_slice(&h);
        MARFValue(d)
    }
}

impl From<MARFValue> for u32 {
    fn from(m: MARFValue) -> u32 {
        let h = m.0;
        let mut d = [0u8; 4];

        d.copy_from_slice(&h[..4]);

        for h_i in &h[4..] {
            if *h_i != 0 {
                panic!("Failed to convert MARF value into u32: data stored after 4th byte");
            }
        }
        u32::from_le_bytes(d)
    }
}

impl MARFValue {
    /// Construct from a TRIEHASH_ENCODED_SIZE-length slice
    pub fn from_value_hash_bytes(h: &[u8; TRIEHASH_ENCODED_SIZE]) -> MARFValue {
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        d[..TRIEHASH_ENCODED_SIZE].copy_from_slice(&h[..TRIEHASH_ENCODED_SIZE]);
        MARFValue(d)
    }

    /// Construct from a TrieHash
    pub fn from_value_hash(h: &TrieHash) -> MARFValue {
        MARFValue::from_value_hash_bytes(h.as_bytes())
    }

    /// Construct from a String that encodes a value inserted into the underlying data store
    #[inline]
    pub fn from_value(s: &str) -> MARFValue {
        let mut hasher = TrieHasher::new();
        hasher.update(s.as_bytes());
        let tmp = hasher.finalize().into();

        MARFValue::from_value_hash_bytes(&tmp)
    }

    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Extract the value hash from the MARF value
    pub fn to_value_hash(&self) -> TrieHash {
        let mut h = [0u8; TRIEHASH_ENCODED_SIZE];
        h.copy_from_slice(&self.0[0..TRIEHASH_ENCODED_SIZE]);
        TrieHash(h)
    }
}

#[derive(Debug)]
pub enum Error {
    NotOpenedError,
    IOError(io::Error),
    SQLError(rusqlite::Error),
    RequestedIdentifierForExtensionTrie,
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    BlockHashMapCorruptionError(Option<Box<Error>>),
    ReadOnlyError,
    UnconfirmedError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(node::CursorError),
    RestoreMarfBlockError(Box<Error>),
    NonMatchingForks([u8; 32], [u8; 32]),
    OverflowError,
    Patch(Option<TrieHash>, TrieNodePatch),
    NodeTooDeep,
    NotSupportedError(String),
}

/// A borrowed slice of serialized trie node bytes (e.g. from an mmap'd blob).
///
/// Carries the node type so the decoder knows how to interpret the bytes.
#[derive(Debug, Clone, Copy)]
pub struct BorrowedNodeBytes<'a> {
    node_type: TrieNodeID,
    bytes: &'a [u8],
}

impl<'a> BorrowedNodeBytes<'a> {
    /// Create from a node type and a borrowed byte slice.
    pub fn new(node_type: TrieNodeID, bytes: &'a [u8]) -> Self {
        Self { node_type, bytes }
    }

    /// The type of trie node these bytes encode.
    pub fn node_type(&self) -> TrieNodeID {
        self.node_type
    }

    /// The raw serialized bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// An owned copy of serialized trie node bytes (e.g. from a seek+read I/O path).
///
/// Same role as [`BorrowedNodeBytes`] but owns its allocation.
#[derive(Debug, Clone)]
pub struct OwnedNodeBytes {
    node_type: TrieNodeID,
    bytes: Vec<u8>,
}

impl OwnedNodeBytes {
    /// Create from a node type and its serialized bytes.
    pub fn new(node_type: TrieNodeID, bytes: Vec<u8>) -> Self {
        Self { node_type, bytes }
    }

    /// The type of trie node these bytes encode.
    pub fn node_type(&self) -> TrieNodeID {
        self.node_type
    }

    /// The raw serialized bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Serialized node bytes — either borrowed from an mmap region or owned from a read buffer.
///
/// Provides uniform access to the node type and raw bytes regardless of ownership.
#[derive(Debug, Clone)]
pub enum BytesBacking<'a> {
    /// Zero-copy reference into mmap'd blob data.
    Borrowed(BorrowedNodeBytes<'a>),
    /// Owned buffer from seek+read I/O.
    Owned(OwnedNodeBytes),
}

impl<'a> BytesBacking<'a> {
    /// The type of trie node these bytes encode.
    pub fn node_type(&self) -> TrieNodeID {
        match self {
            BytesBacking::Borrowed(node) => node.node_type(),
            BytesBacking::Owned(node) => node.node_type(),
        }
    }

    /// The raw serialized bytes (borrowed or owned).
    pub fn bytes(&self) -> &[u8] {
        match self {
            BytesBacking::Borrowed(node) => node.bytes(),
            BytesBacking::Owned(node) => node.bytes(),
        }
    }
}

/// The kind of item returned when reading from persisted trie storage: either a fully-resolved node
/// or an unresolved patch that needs to be applied to its base node.
#[derive(Debug, Clone)]
pub enum ReadTrieItemKind<'a> {
    /// A resolved trie node (possibly decoded lazily from bytes).
    Node(ReadTrieNode<'a>),
    /// A patch node referencing a base node in an ancestor block.
    Patch(&'a TrieNodePatch),
}

/// A single item read from trie storage, wrapping either a resolved node or an unresolved patch
/// along with its hash and compression depth.
#[derive(Debug, Clone)]
pub struct ReadTrieItem<'a> {
    pub hash: Option<TrieHash>,
    pub patch_depth: usize,
    pub kind: ReadTrieItemKind<'a>,
}

/// How a read node's data is backed in memory.
///
/// This enum is the core of the lazy-decode / zero-copy strategy: nodes from different sources
/// carry different backing, and decoding is deferred until the caller actually needs structured
/// access (e.g. `walk()`, `ptrs()`).
#[derive(Debug, Clone)]
pub enum ReadNodeBacking<'a> {
    /// Decoded node borrowed from scratch/parking state (not persisted — e.g. the uncommitted
    /// TrieRAM).
    ///
    /// "Volatile" because the reference is invalidated when the scratch slot is reused.
    VolatileDecoded(TrieNodeRef<'a>),
    /// Decoded node borrowed from persisted storage (e.g. already-decoded cache or SQLite inline
    /// blob).
    PersistedDecoded(TrieNodeRef<'a>),
    /// Raw serialized bytes from persisted storage (mmap or read buffer). Decoded lazily on first
    /// access via [`ReadTrieNode::decoded_bytes`].
    PersistedBytes(BytesBacking<'a>),
    /// Fully owned decoded node (e.g. from patch resolution or TrieRAM clone).
    Owned(TrieNodeType),
}

/// A trie node read from storage, with lazy decoding.
///
/// Wraps a [`ReadNodeBacking`] and provides uniform access to node properties (`walk()`, `ptrs()`,
/// `path_bytes()`, `is_leaf()`, etc.) regardless of how the node is backed. When backed by raw
/// bytes ([`ReadNodeBacking::PersistedBytes`]), decoding is deferred until first structural access
/// and cached in `decoded_bytes` via [`OnceLock`].
#[derive(Debug, Clone)]
pub struct ReadTrieNode<'a> {
    /// The node's Merkle hash, if read. `None` when the caller requested a no-hash read (e.g.
    /// `read_nodetype_nohash`).
    pub hash: Option<TrieHash>,
    /// Number of patch layers resolved to produce this node (0 if uncompressed).
    pub patch_depth: usize,
    /// The node data — may be decoded, raw bytes, or owned.
    pub backing: ReadNodeBacking<'a>,
    /// Lazily-decoded node for the `PersistedBytes` case. Shared via `Arc` so that `ReadTrieNode`
    /// remains `Clone` without re-decoding.
    decoded_bytes: Arc<OnceLock<TrieNodeType>>,
    /// Transient metadata (cowptr, patch state) from the source `TrieNodeType` that
    /// `TrieNodeRef` cannot carry. Applied by `into_owned_node()` to round-trip
    /// without loss.
    transient_meta: Option<TrieNodeTransientMeta>,
}

/// Result of a single step during a trie cursor walk.
///
/// Tells the walker what to do next after visiting a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTrieNodeCursorStep {
    /// Followed a child pointer — continue walking at the returned ptr.
    Next(TriePtr),
    /// Consumed all path bytes — the walk is complete.
    EndOfPath { is_leaf: bool },
    /// Path diverged from the node's compressed path segment — key not found.
    Diverged,
    /// No child exists for the next path byte — key not found.
    ChrNotFound,
    /// Child pointer is a backpointer — caller must resolve it by opening the ancestor block and
    /// re-reading the node there.
    FollowBackptr(TriePtr),
}

/// Arena for parking decoded nodes so they remain accessible across multiple storage reads within a
/// single operation.
pub trait TrieNodeArena {
    /// Store an owned node in the arena and return a borrowed reference to it.
    fn park<'a>(&'a mut self, node: TrieNodeType) -> TrieNodeRef<'a>;
}

/// Transitional marker trait; combines parking and patching capabilities.
///
/// TODO: Not the target architecture: will be removed once all call sites declare their own
/// specific bounds.
pub trait TrieNodeReadState: NodeParking + NodePatching {}

/// Blanket impl: any type implementing both capability traits satisfies this.
impl<T: NodeParking + NodePatching> TrieNodeReadState for T {}

/// Reusable byte-buffer and typed-slot decode workspace.
///
/// Implemented by types that can deserialize trie nodes from byte slices into pre-allocated
/// internal storage, avoiding per-read allocation.
pub trait NodeDecodeScratch {
    /// Take ownership of the internal byte buffer (leaves an empty vec behind).
    fn take_node_bytes(&mut self) -> Vec<u8>;
    /// Return a previously-taken byte buffer for reuse.
    fn restore_node_bytes(&mut self, bytes: Vec<u8>);

    /// Decode a node of the given type from a byte slice into internal storage. Returns the number
    /// of bytes consumed.
    fn decode_node_from_slice(&mut self, id: TrieNodeID, bytes: &[u8]) -> Result<usize, Error>;
    /// Decode a patch node from a byte slice into internal storage.
    fn decode_patch_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error>;

    /// Get a borrowed reference to the currently-decoded node.
    fn get_ref(&self) -> TrieNodeRef<'_>;
    /// Get the decoded patch node.
    fn patch(&self) -> &TrieNodePatch;
    /// Take ownership of the decoded patch node, leaving the slot empty. Avoids cloning when the
    /// patch will be moved into a collection.
    fn take_patch(&mut self) -> TrieNodePatch;
    /// Take the reusable patch chain buffer (cleared, ready for use).
    fn take_patch_chain_buf(&mut self) -> Vec<(u32, TriePtr, TrieNodePatch)>;
    /// Return the patch chain buffer for reuse in subsequent calls.
    fn restore_patch_chain_buf(&mut self, buf: Vec<(u32, TriePtr, TrieNodePatch)>);
    /// Store an owned node as the current node and return a reference.
    fn store(&mut self, node: TrieNodeType) -> TrieNodeRef<'_>;
    /// Clear the current decoded node slot.
    fn clear_current_node(&mut self);
    /// Check whether a node is currently decoded.
    fn has_current_node(&self) -> bool;
}

/// Parking capability trait: keep decoded nodes alive across multiple storage reads.
///
/// When walking a trie, we often need to read a node, then read another node
/// (which overwrites the decode scratch), while keeping the first node
/// accessible. Parking moves a node into stable storage with a handle
/// for later retrieval.
///
/// Note: `NodeParking` is intentionally independent of `TrieNodeArena`.
/// `TrieNodeArena::park()` stores into the "current node" slot (ephemeral),
/// while `NodeParking` methods use a separate parked-node vec (persistent
/// across reads). These are distinct operations and should not be conflated.
pub trait NodeParking: NodeDecodeScratch {
    /// Move the currently-decoded node into parked storage.
    fn park_current_node(&mut self) -> Result<ParkedNodeHandle, Error>;
    /// Park an already-owned node.
    fn park_owned_node(&mut self, node: TrieNodeType) -> ParkedNodeHandle;
    /// Retrieve a reference to a previously-parked node.
    fn get_parked_ref(&self, handle: ParkedNodeHandle) -> TrieNodeRef<'_>;
    /// Clear all parked nodes (e.g., between top-level operations).
    fn clear_parked_nodes(&mut self);
}

/// Patching capability trait: apply compressed patch nodes in-place to decoded nodes.
///
/// MARF compression stores "patch" nodes that record ptr diffs relative to a base node. The
/// patching trait allows the storage layer to resolve a chain of patches by decoding the base node
/// and applying patches in-place.
pub trait NodePatching: NodeDecodeScratch {
    /// Apply a sequence of patches to the currently-decoded node.
    fn apply_patches_in_place(
        &mut self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Result<(), Error>;
}

/// Read-only access to persisted trie storage.
///
/// Provides block-level positioning (which trie to read from) and node-level I/O (reading node
/// data, hashes, and children). The MARF walk uses this trait to traverse tries across blocks:
/// [`open_block()`](Self::open_block) repositions storage to a specific block's trie, then
/// [`read_node_with_state`](Self::read_node_with_state) reads individual nodes within that trie.
///
/// Backpointer resolution works by calling [`open_block()`](Self::open_block) /
/// [`open_block_known_id()`](Self::open_block_known_id) to jump to an ancestor block, reading the
/// target node there, then continuing the walk. The storage tracks which block is currently open
/// via [`get_cur_block_and_id()`](Self::get_cur_block_and_id).
pub trait TrieReadStorage<T: MarfTrieId>: BlockMap<TrieId = T> {
    /// Read a node from the currently-open block's trie at the given pointer. The `state` parameter
    /// provides scratch space for node decoding and patch resolution (see [`TrieNodeReadState`]).
    fn read_node_with_state<'a, S: TrieNodeReadState>(
        &'a mut self,
        ptr: &TriePtr,
        state: &'a mut S,
    ) -> Result<ReadTrieNode<'a>, Error>;

    /// Reposition storage to the trie for `bhh`, resolving the block ID from the block-hash-to-ID
    /// mapping. Subsequent node reads will be relative to this block's trie.
    fn open_block(&mut self, bhh: &T) -> Result<(), Error>;

    /// Reposition storage to the trie for `bhh`, using a pre-resolved block ID if available. Falls
    /// back to [`open_block`](Self::open_block) when `id` is `None`.
    fn open_block_maybe_id(&mut self, bhh: &T, id: Option<u32>) -> Result<(), Error> {
        match id {
            Some(id) => self.open_block_known_id(bhh, id),
            None => self.open_block(bhh),
        }
    }

    /// Reposition storage to the trie for `bhh` using a known block ID, avoiding the
    /// block-hash-to-ID lookup.
    ///
    /// Used during backpointer resolution where the `back_block` ID is already available from the
    /// [`TriePtr`].
    fn open_block_known_id(&mut self, bhh: &T, id: u32) -> Result<(), Error>;

    /// Return the block hash of the currently-open trie.
    fn get_cur_block(&self) -> T {
        self.get_cur_block_and_id().0
    }

    /// Return the block hash and numeric ID of the currently-open trie.
    ///
    /// The ID is `None` if the block was opened without a known ID.
    fn get_cur_block_and_id(&self) -> (T, Option<u32>);

    /// Resolve a trie-local numeric block ID to a block hash. Uses the caching [`BlockMap`]
    /// implementation.
    fn get_block_from_local_id(&mut self, local_id: u32) -> Result<T, Error> {
        Ok(self.get_block_hash_caching(local_id)?.clone())
    }

    /// Return a [`TriePtr`] pointing to the root node of the currently-open block's trie.
    ///
    /// This is the starting point for all trie walks.
    fn root_trieptr(&self) -> TriePtr;

    /// Read only the hash of the node at `ptr`, without decoding the node body.
    fn read_node_hash(&mut self, ptr: &TriePtr) -> Result<TrieHash, Error>;

    /// Read the node type ID and hash at `ptr`, without decoding the full node.
    fn read_node_type_id(&mut self, ptr: &TriePtr) -> Result<(TrieNodeID, TrieHash), Error>;

    /// Cache the ancestor hashes for a block (used during proof generation).
    fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &T, bytes: Vec<TrieHash>);

    /// Retrieve previously-cached ancestor hashes for a block, if present.
    fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &T) -> Option<Vec<TrieHash>>;

    /// Write the hashes of the children pointed to by `ptrs` into `w`.
    ///
    /// Used during Merkle proof construction and root hash computation.
    fn write_children_hashes_by_ptrs<W: io::Write + ?Sized>(
        &mut self,
        ptrs: &[TriePtr],
        w: &mut W,
    ) -> Result<(), Error>;

    /// Mutable access to the benchmark instrumentation counters.
    fn bench_mut(&mut self) -> &mut crate::chainstate::stacks::index::profile::TrieBenchmark;

    /// Return the genesis block hash used in tests, if configured.
    #[cfg(test)]
    fn test_genesis_block(&self) -> Option<T>;

    /// Return the opened block's height within a squash level, if any.
    ///
    /// Used by `walk` to resolve `TrieLeafSquashed` entries at the correct
    /// point-in-time. Returns `None` when the currently-open block is not
    /// inside a squash range.
    fn squash_opened_height(&self) -> Option<u32> {
        None
    }
}

/// Bundles a [`TrieReadStorage`] reference with a [`TrieNodeReadState`] for convenient node
/// reading.
///
/// Callers use [`read_node()`](Self::read_node) instead of manually passing state to every
/// [`read_node_with_state()`](TrieReadStorage::read_node_with_state) call.
pub struct TrieReadSession<
    'a,
    T: MarfTrieId,
    S: TrieNodeReadState,
    R: TrieReadStorage<T> + ?Sized = TrieStorageConnection<'a, T>,
> {
    storage: &'a mut R,
    state: &'a mut S,
    _marker: std::marker::PhantomData<T>,
}

impl<'a, T: MarfTrieId, S: TrieNodeReadState, R: TrieReadStorage<T> + ?Sized>
    TrieReadSession<'a, T, S, R>
{
    pub fn new(storage: &'a mut R, state: &'a mut S) -> Self {
        Self {
            storage,
            state,
            _marker: std::marker::PhantomData,
        }
    }

    /// Access the underlying storage (e.g. for [`open_block()`](TrieReadStorage::open_block)
    /// calls).
    pub fn storage(&mut self) -> &mut R {
        self.storage
    }

    /// Read a node at `ptr` from the currently-open block, using the session's decode state for
    /// scratch space and patch resolution.
    pub fn read_node<'b>(&'b mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'b>, Error> {
        self.storage.read_node_with_state(ptr, self.state)
    }
}

impl<'a> ReadTrieItem<'a> {
    /// Wrap a resolved node as a read item.
    pub fn from_node(node: ReadTrieNode<'a>) -> Self {
        Self {
            hash: node.hash,
            patch_depth: node.patch_depth,
            kind: ReadTrieItemKind::Node(node),
        }
    }

    /// Wrap an unresolved patch as a read item.
    pub fn from_patch(patch: &'a TrieNodePatch, hash: Option<TrieHash>) -> Self {
        Self {
            hash,
            patch_depth: 0,
            kind: ReadTrieItemKind::Patch(patch),
        }
    }

    /// Returns `true` if this item is an unresolved patch.
    pub fn is_patch(&self) -> bool {
        matches!(&self.kind, ReadTrieItemKind::Patch(_))
    }

    /// Borrow the patch, if this item is one.
    pub fn as_patch(&self) -> Option<&TrieNodePatch> {
        match &self.kind {
            ReadTrieItemKind::Node(_) => None,
            ReadTrieItemKind::Patch(patch) => Some(*patch),
        }
    }

    /// Unwrap into a resolved node, or return `Error::Patch` if this is an unresolved patch (caller
    /// must resolve it first).
    pub fn into_node(self) -> Result<ReadTrieNode<'a>, Error> {
        match self.kind {
            ReadTrieItemKind::Node(node) => Ok(node),
            ReadTrieItemKind::Patch(patch) => Err(Error::Patch(self.hash, patch.clone())),
        }
    }
}

impl<'a> ReadTrieNode<'a> {
    fn new(hash: Option<TrieHash>, patch_depth: usize, backing: ReadNodeBacking<'a>) -> Self {
        Self {
            hash,
            patch_depth,
            backing,
            decoded_bytes: Arc::new(OnceLock::new()),
            transient_meta: None,
        }
    }

    /// Attach transient metadata (cowptr, patch state) captured from the source TrieNodeType.
    pub fn with_transient_meta(mut self, meta: TrieNodeTransientMeta) -> Self {
        self.transient_meta = Some(meta);
        self
    }

    fn patch_depth_from_owned(node: &TrieNodeType) -> usize {
        node.patch_depth()
    }

    /// Construct from a decoded persisted node (e.g. from SQLite inline blob or cache).
    pub fn from_borrowed(node: TrieNodeRef<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(hash, 0, ReadNodeBacking::PersistedDecoded(node))
    }

    /// Construct from a decoded node in scratch/parking state (volatile — may be overwritten on the
    /// next read).
    pub fn from_state_borrowed(node: TrieNodeRef<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(hash, 0, ReadNodeBacking::VolatileDecoded(node))
    }

    /// Construct from borrowed raw bytes (zero-copy, e.g. mmap).
    pub fn from_stable_bytes(node: BorrowedNodeBytes<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(
            hash,
            0,
            ReadNodeBacking::PersistedBytes(BytesBacking::Borrowed(node)),
        )
    }

    /// Construct from owned raw bytes (e.g. seek+read I/O buffer).
    pub fn from_owned_bytes(node: OwnedNodeBytes, hash: Option<TrieHash>) -> Self {
        Self::new(
            hash,
            0,
            ReadNodeBacking::PersistedBytes(BytesBacking::Owned(node)),
        )
    }

    /// Construct from a fully-owned decoded node (e.g. from patch resolution or TrieRAM clone).
    pub fn from_owned(node: TrieNodeType, hash: Option<TrieHash>) -> Self {
        let patch_depth = Self::patch_depth_from_owned(&node);
        Self::new(hash, patch_depth, ReadNodeBacking::Owned(node))
    }

    /// Return the node type ID, if determinable.
    pub fn node_type(&self) -> Option<TrieNodeID> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => TrieNodeID::from_u8(node.id()),
            ReadNodeBacking::PersistedDecoded(node) => TrieNodeID::from_u8(node.id()),
            ReadNodeBacking::PersistedBytes(node) => Some(node.node_type()),
            ReadNodeBacking::Owned(node) => TrieNodeID::from_u8(node.id()),
        }
    }

    /// Return the node type ID as a raw `u8` (includes control bits).
    pub fn node_type_u8(&self) -> u8 {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => node.id(),
            ReadNodeBacking::PersistedDecoded(node) => node.id(),
            ReadNodeBacking::PersistedBytes(node) => node.node_type() as u8,
            ReadNodeBacking::Owned(node) => node.id(),
        }
    }

    /// Returns `true` if this is a Node256 (the largest intermediate node type).
    pub fn is_node256(&self) -> bool {
        matches!(self.node_type(), Some(TrieNodeID::Node256))
    }

    /// Decode a [`BytesBacking`] node into an owned [`TrieNodeType`].
    ///
    /// Borrowed bytes (mmap) may be a prefix slice — uses prefix decode. Owned bytes use
    /// exact-length decode with validation.
    fn decode_bytes_to_node(&self, node: &BytesBacking<'_>) -> Result<TrieNodeType, Error> {
        match node {
            BytesBacking::Owned(_) => {
                bits::decode_stable_node_bytes(node.bytes(), node.node_type())
            }
            BytesBacking::Borrowed(_) => {
                let (decoded, _consumed) =
                    bits::decode_nodetype_from_slice_at_head(node.bytes(), node.node_type() as u8)?;
                Ok(decoded)
            }
        }
    }

    /// Return a reference to the decoded node, decoding from bytes on first call and caching the
    /// result in `decoded_bytes`.
    fn decoded_from_bytes(&self, node: &BytesBacking<'_>) -> Result<&TrieNodeType, Error> {
        if let Some(decoded) = self.decoded_bytes.get() {
            return Ok(decoded);
        }

        let decoded = self.decode_bytes_to_node(node)?;
        let _ = self.decoded_bytes.set(decoded);
        self.decoded_bytes.get().ok_or_else(|| {
            Error::CorruptionError(format!(
                "Failed to cache decoded stable byte-backed {:?} node",
                node.node_type()
            ))
        })
    }

    /// Set the patch depth (number of resolved patch layers) on this node.
    pub fn with_patch_depth(mut self, patch_depth: usize) -> Self {
        self.patch_depth = patch_depth;
        self
    }

    /// Returns `true` if this node is a leaf (end of a key path).
    pub fn is_leaf(&self) -> Result<bool, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.is_leaf()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.is_leaf()),
            ReadNodeBacking::PersistedBytes(node) => Ok(matches!(
                node.node_type(),
                TrieNodeID::Leaf | TrieNodeID::LeafSquashed
            )),
            ReadNodeBacking::Owned(node) => Ok(node.is_leaf()),
        }
    }

    /// Return the node's compressed path segment bytes.
    pub fn path_bytes(&self) -> Result<&[u8], Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.path_bytes()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.path_bytes()),
            ReadNodeBacking::PersistedBytes(node) => {
                Ok(self.decoded_from_bytes(node)?.path_bytes())
            }
            ReadNodeBacking::Owned(node) => Ok(node.path_bytes()),
        }
    }

    /// Return the node's child pointer array.
    pub fn ptrs(&self) -> Result<&[TriePtr], Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.ptrs()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.ptrs()),
            ReadNodeBacking::PersistedBytes(node) => Ok(self.decoded_from_bytes(node)?.ptrs()),
            ReadNodeBacking::Owned(node) => Ok(node.ptrs()),
        }
    }

    /// Follow a path byte to the corresponding child pointer, if present.
    pub fn walk(&self, chr: u8) -> Result<Option<TriePtr>, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.walk(chr)),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.walk(chr)),
            ReadNodeBacking::PersistedBytes(node) => Ok(self.decoded_from_bytes(node)?.walk(chr)),
            ReadNodeBacking::Owned(node) => Ok(node.walk(chr)),
        }
    }

    /// Borrow leaf data if this node is a leaf, without taking ownership.
    pub fn as_leaf(&self) -> Result<Option<TrieLeafRef<'_>>, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.as_leaf()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.as_leaf()),
            ReadNodeBacking::PersistedBytes(node) => Ok(match self.decoded_from_bytes(node)? {
                TrieNodeType::Leaf(leaf) => Some(TrieLeafRef {
                    path: leaf.path.as_slice(),
                    data: &leaf.data,
                }),
                TrieNodeType::LeafSquashed(sq) => Some(TrieLeafRef {
                    path: sq.path.as_slice(),
                    data: sq.tip_value()?,
                }),
                _ => None,
            }),
            ReadNodeBacking::Owned(node) => Ok(TrieNodeRef::from(node).as_leaf()),
        }
    }

    /// Access the borrowed squashed-leaf view if this node is a LeafSquashed.
    /// Returns `None` if this is not a LeafSquashed node.
    pub fn as_leaf_squashed_ref(&self) -> Result<Option<TrieLeafSquashedRef<'_>>, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(TrieNodeRef::LeafSquashed(sq)) => Ok(Some(*sq)),
            ReadNodeBacking::PersistedDecoded(TrieNodeRef::LeafSquashed(sq)) => Ok(Some(*sq)),
            ReadNodeBacking::PersistedBytes(node) => match self.decoded_from_bytes(node)? {
                TrieNodeType::LeafSquashed(sq) => Ok(Some(TrieLeafSquashedRef {
                    path: sq.path.as_slice(),
                    tip_value: sq.tip_value()?,
                    entries: &sq.entries,
                })),
                _ => Ok(None),
            },
            ReadNodeBacking::Owned(TrieNodeType::LeafSquashed(sq)) => {
                Ok(Some(TrieLeafSquashedRef {
                    path: sq.path.as_slice(),
                    tip_value: sq.tip_value()?,
                    entries: &sq.entries,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Borrow as a `TrieNodeRef` + hash pair (triggers decode if byte-backed).
    pub fn as_node_ref(&self) -> Result<(TrieNodeRef<'_>, Option<TrieHash>), Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok((*node, self.hash)),
            ReadNodeBacking::PersistedDecoded(node) => Ok((*node, self.hash)),
            ReadNodeBacking::PersistedBytes(node) => {
                Ok((TrieNodeRef::from(self.decoded_from_bytes(node)?), self.hash))
            }
            ReadNodeBacking::Owned(node) => Ok((TrieNodeRef::from(node), self.hash)),
        }
    }

    /// Decode (if needed) and park the node in an arena, returning a stable borrowed reference that
    /// outlives this `ReadTrieNode`.
    pub fn park_in<A: TrieNodeArena>(
        self,
        arena: &'a mut A,
    ) -> Result<(TrieNodeRef<'a>, Option<TrieHash>), Error> {
        match self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok((node, self.hash)),
            ReadNodeBacking::PersistedDecoded(node) => {
                Ok((arena.park(node.to_owned_node()), self.hash))
            }
            ReadNodeBacking::PersistedBytes(ref node) => {
                Ok((arena.park(self.decode_bytes_to_node(node)?), self.hash))
            }
            ReadNodeBacking::Owned(node) => Ok((arena.park(node), self.hash)),
        }
    }

    /// Consume this read node and return an owned [`TrieNodeType`] + hash.
    ///
    /// If transient metadata (cowptr, patch state) was captured when the `ReadTrieNode` was
    /// constructed, it is applied to the owned node so that round-tripping through [`TrieNodeRef`]
    /// doesn't lose COW/patch state.
    pub fn into_owned_node(self) -> Result<(TrieNodeType, Option<TrieHash>), Error> {
        let meta = self.transient_meta;
        let mut node = match self.backing {
            ReadNodeBacking::VolatileDecoded(node) => node.to_owned_node(),
            ReadNodeBacking::PersistedDecoded(node) => node.to_owned_node(),
            ReadNodeBacking::PersistedBytes(ref node) => self.decode_bytes_to_node(node)?,
            ReadNodeBacking::Owned(node) => node,
        };
        if let Some(meta) = meta {
            meta.apply_to(&mut node);
        }
        Ok((node, self.hash))
    }

    /// Consume this read node and return only the hash, discarding node data.
    pub fn into_hash(self) -> Result<Option<TrieHash>, Error> {
        match self.backing {
            ReadNodeBacking::VolatileDecoded(_)
            | ReadNodeBacking::PersistedDecoded(_)
            | ReadNodeBacking::PersistedBytes(_)
            | ReadNodeBacking::Owned(_) => Ok(self.hash),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::QueryReturnedNoRows = err {
            Error::NotFoundError
        } else {
            Error::SQLError(err)
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        match e {
            db_error::SqliteError(se) => Error::SQLError(se),
            db_error::NotFoundError => Error::NotFoundError,
            _ => Error::CorruptionError(format!("{}", &e)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::SQLError(ref e) => fmt::Display::fmt(e, f),
            Error::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            Error::CursorError(ref e) => fmt::Display::fmt(e, f),
            Error::BlockHashMapCorruptionError(ref opt_e) => {
                f.write_str("Corrupted MARF BlockHashMap")?;
                match opt_e {
                    Some(e) => write!(f, ": {}", e),
                    None => Ok(()),
                }
            }
            Error::NotOpenedError => write!(f, "Tried to read data from unopened storage"),
            Error::NotFoundError => write!(f, "Object not found"),
            Error::BackptrNotFoundError => write!(f, "Object not found from backptrs"),
            Error::ExistsError => write!(f, "Object exists"),
            Error::BadSeekValue => write!(f, "Bad seek value"),
            Error::ReadOnlyError => write!(f, "Storage is in read-only mode"),
            Error::UnconfirmedError => write!(f, "Storage is in unconfirmed mode"),
            Error::NotDirectoryError => write!(f, "Not a directory"),
            Error::PartialWriteError => {
                write!(f, "Data is partially written and not yet recovered")
            }
            Error::InProgressError => write!(f, "Write was in progress"),
            Error::WriteNotBegunError => write!(f, "Write has not begun"),
            Error::RestoreMarfBlockError(_) => write!(
                f,
                "Failed to restore previous open block during block header check"
            ),
            Error::NonMatchingForks(_, _) => {
                write!(f, "The supplied blocks are not in the same fork")
            }
            Error::RequestedIdentifierForExtensionTrie => {
                write!(f, "BUG: MARF requested the identifier for a RAM trie")
            }
            Error::OverflowError => write!(f, "Overflow"),
            Error::Patch(ref _h, ref p) => {
                write!(f, "Read patch node instead of expected node: {p:?}")
            }
            Error::NodeTooDeep => write!(f, "Node is too deeply buried under patches"),
            Error::NotSupportedError(ref s) => write!(f, "Operation not supported: {s}"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::IOError(ref e) => Some(e),
            Error::SQLError(ref e) => Some(e),
            Error::RestoreMarfBlockError(ref e) => Some(e),
            Error::BlockHashMapCorruptionError(Some(ref e)) => Some(e),
            _ => None,
        }
    }
}

pub trait BlockMap {
    type TrieId: MarfTrieId;
    fn get_block_hash(&self, id: u32) -> Result<Self::TrieId, Error>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Self::TrieId, Error>;
    fn is_block_hash_cached(&self, id: u32) -> bool;
    fn get_block_id(&self, bhh: &Self::TrieId) -> Result<u32, Error>;
    fn get_block_id_caching(&mut self, bhh: &Self::TrieId) -> Result<u32, Error>;
}

#[cfg(test)]
impl BlockMap for () {
    type TrieId = BlockHeaderHash;
    fn get_block_hash(&self, _id: u32) -> Result<BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &BlockHeaderHash) -> Result<u32, Error> {
        Err(Error::NotFoundError)
    }
    fn get_block_id_caching(&mut self, _bhh: &BlockHeaderHash) -> Result<u32, Error> {
        Err(Error::NotFoundError)
    }
}
