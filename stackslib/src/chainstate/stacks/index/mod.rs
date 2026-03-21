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

use std::hash::Hash;
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
pub mod storage;
pub mod trie;
pub mod trie_sql;

#[cfg(test)]
pub mod test;

use crate::chainstate::stacks::index::node::{
    ParkedNodeHandle, TrieLeafRef, TrieNodeID, TrieNodePatch, TrieNodeRef, TrieNodeType, TriePtr,
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

/// Leaf of a Trie.
#[derive(Clone)]
pub struct TrieLeaf {
    pub path: Vec<u8>,   // path to be lazily expanded
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
}

#[derive(Debug, Clone, Copy)]
pub struct BorrowedNodeBytes<'a> {
    node_type: TrieNodeID,
    bytes: &'a [u8],
}

impl<'a> BorrowedNodeBytes<'a> {
    pub fn new(node_type: TrieNodeID, bytes: &'a [u8]) -> Self {
        Self { node_type, bytes }
    }

    pub fn node_type(&self) -> TrieNodeID {
        self.node_type
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct OwnedNodeBytes {
    node_type: TrieNodeID,
    bytes: Vec<u8>,
}

impl OwnedNodeBytes {
    pub fn new(node_type: TrieNodeID, bytes: Vec<u8>) -> Self {
        Self { node_type, bytes }
    }

    pub fn node_type(&self) -> TrieNodeID {
        self.node_type
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Debug, Clone)]
pub enum BytesBacking<'a> {
    Borrowed(BorrowedNodeBytes<'a>),
    Owned(OwnedNodeBytes),
}

impl<'a> BytesBacking<'a> {
    pub fn node_type(&self) -> TrieNodeID {
        match self {
            BytesBacking::Borrowed(node) => node.node_type(),
            BytesBacking::Owned(node) => node.node_type(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            BytesBacking::Borrowed(node) => node.bytes(),
            BytesBacking::Owned(node) => node.bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReadTrieItemKind<'a> {
    Node(ReadTrieNode<'a>),
    Patch(&'a TrieNodePatch),
}

#[derive(Debug, Clone)]
pub struct ReadTrieItem<'a> {
    pub hash: Option<TrieHash>,
    pub patch_depth: usize,
    pub kind: ReadTrieItemKind<'a>,
}

#[derive(Debug, Clone)]
pub enum ReadNodeBacking<'a> {
    VolatileDecoded(TrieNodeRef<'a>),
    PersistedDecoded(TrieNodeRef<'a>),
    PersistedBytes(BytesBacking<'a>),
    Owned(TrieNodeType),
}

#[derive(Debug, Clone)]
pub struct ReadTrieNode<'a> {
    pub hash: Option<TrieHash>,
    pub patch_depth: usize,
    pub backing: ReadNodeBacking<'a>,
    decoded_bytes: Arc<OnceLock<TrieNodeType>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTrieNodeCursorStep {
    Next(TriePtr),
    EndOfPath { is_leaf: bool },
    Diverged,
    ChrNotFound,
    FollowBackptr(TriePtr),
}

pub trait TrieNodeArena {
    fn park<'a>(&'a mut self, node: TrieNodeType) -> TrieNodeRef<'a>;
}

/// Transitional marker trait — combines parking and patching capabilities.
/// Not the target architecture: will be eliminated once all call sites declare
/// their own specific bounds.
pub trait TrieNodeReadState: NodeParking + NodePatching {}

/// Blanket impl: any type implementing both capability traits satisfies this.
impl<T: NodeParking + NodePatching> TrieNodeReadState for T {}

/// Base capability trait: reusable byte-buffer and typed-slot decode workspace.
///
/// Implemented by types that can deserialize trie nodes from byte slices
/// into pre-allocated internal storage, avoiding per-read allocation.
pub trait NodeDecodeScratch {
    /// Take ownership of the internal byte buffer (leaves an empty vec behind).
    fn take_node_bytes(&mut self) -> Vec<u8>;
    /// Return a previously-taken byte buffer for reuse.
    fn restore_node_bytes(&mut self, bytes: Vec<u8>);

    /// Decode a node of the given type from a byte slice into internal storage.
    /// Returns the number of bytes consumed.
    fn decode_node_from_slice(&mut self, id: TrieNodeID, bytes: &[u8]) -> Result<usize, Error>;
    /// Decode a patch node from a byte slice into internal storage.
    fn decode_patch_from_slice(&mut self, bytes: &[u8]) -> Result<usize, Error>;

    /// Get a borrowed reference to the currently-decoded node.
    fn get_ref(&self) -> TrieNodeRef<'_>;
    /// Get the decoded patch node.
    fn patch(&self) -> &TrieNodePatch;
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
/// MARF compression stores "patch" nodes that record ptr diffs relative to
/// a base node. The patching trait allows the storage layer to resolve a chain
/// of patches by decoding the base node and applying patches in-place.
pub trait NodePatching: NodeDecodeScratch {
    /// Apply a sequence of patches to the currently-decoded node.
    fn apply_patches_in_place(
        &mut self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Result<(), Error>;
}

pub trait TrieReadStorage<T: MarfTrieId>: BlockMap<TrieId = T> {
    fn read_node_with_state<'a, S: TrieNodeReadState>(
        &'a mut self,
        ptr: &TriePtr,
        state: &'a mut S,
    ) -> Result<ReadTrieNode<'a>, Error>;

    fn open_block(&mut self, bhh: &T) -> Result<(), Error>;
    fn open_block_maybe_id(&mut self, bhh: &T, id: Option<u32>) -> Result<(), Error> {
        match id {
            Some(id) => self.open_block_known_id(bhh, id),
            None => self.open_block(bhh),
        }
    }
    fn open_block_known_id(&mut self, bhh: &T, id: u32) -> Result<(), Error>;
    fn get_cur_block(&self) -> T {
        self.get_cur_block_and_id().0
    }
    fn get_cur_block_and_id(&self) -> (T, Option<u32>);
    fn get_block_from_local_id(&mut self, local_id: u32) -> Result<T, Error> {
        Ok(self.get_block_hash_caching(local_id)?.clone())
    }
    fn root_trieptr(&self) -> TriePtr;
    fn read_node_hash(&mut self, ptr: &TriePtr) -> Result<TrieHash, Error>;
    fn read_node_type_id(&mut self, ptr: &TriePtr) -> Result<(TrieNodeID, TrieHash), Error>;
    fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &T, bytes: Vec<TrieHash>);
    fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &T) -> Option<Vec<TrieHash>>;
    #[cfg(test)]
    fn test_genesis_block(&self) -> Option<T>;
    fn write_children_hashes_by_ptrs<W: io::Write + ?Sized>(
        &mut self,
        ptrs: &[TriePtr],
        w: &mut W,
    ) -> Result<(), Error>;
    fn bench_mut(&mut self) -> &mut crate::chainstate::stacks::index::profile::TrieBenchmark;
}

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

    pub fn storage(&mut self) -> &mut R {
        self.storage
    }

    pub fn read_node<'b>(&'b mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'b>, Error> {
        self.storage.read_node_with_state(ptr, self.state)
    }
}

impl<'a> ReadTrieItem<'a> {
    pub fn from_node(node: ReadTrieNode<'a>) -> Self {
        Self {
            hash: node.hash,
            patch_depth: node.patch_depth,
            kind: ReadTrieItemKind::Node(node),
        }
    }

    pub fn from_patch(patch: &'a TrieNodePatch, hash: Option<TrieHash>) -> Self {
        Self {
            hash,
            patch_depth: 0,
            kind: ReadTrieItemKind::Patch(patch),
        }
    }

    pub fn is_patch(&self) -> bool {
        matches!(&self.kind, ReadTrieItemKind::Patch(_))
    }

    pub fn as_patch(&self) -> Option<&TrieNodePatch> {
        match &self.kind {
            ReadTrieItemKind::Node(_) => None,
            ReadTrieItemKind::Patch(patch) => Some(*patch),
        }
    }

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
        }
    }

    fn patch_depth_from_owned(node: &TrieNodeType) -> usize {
        if node.is_leaf() {
            0
        } else {
            node.get_patches().len()
        }
    }

    pub fn from_borrowed(node: TrieNodeRef<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(hash, 0, ReadNodeBacking::PersistedDecoded(node))
    }

    pub fn from_state_borrowed(node: TrieNodeRef<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(hash, 0, ReadNodeBacking::VolatileDecoded(node))
    }

    pub fn from_stable_bytes(node: BorrowedNodeBytes<'a>, hash: Option<TrieHash>) -> Self {
        Self::new(
            hash,
            0,
            ReadNodeBacking::PersistedBytes(BytesBacking::Borrowed(node)),
        )
    }

    pub fn from_owned_bytes(node: OwnedNodeBytes, hash: Option<TrieHash>) -> Self {
        Self::new(
            hash,
            0,
            ReadNodeBacking::PersistedBytes(BytesBacking::Owned(node)),
        )
    }

    pub fn from_owned(node: TrieNodeType, hash: Option<TrieHash>) -> Self {
        let patch_depth = Self::patch_depth_from_owned(&node);
        Self::new(hash, patch_depth, ReadNodeBacking::Owned(node))
    }

    pub fn node_type(&self) -> Option<TrieNodeID> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => TrieNodeID::from_u8(node.id()),
            ReadNodeBacking::PersistedDecoded(node) => TrieNodeID::from_u8(node.id()),
            ReadNodeBacking::PersistedBytes(node) => Some(node.node_type()),
            ReadNodeBacking::Owned(node) => TrieNodeID::from_u8(node.id()),
        }
    }

    pub fn node_type_u8(&self) -> u8 {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => node.id(),
            ReadNodeBacking::PersistedDecoded(node) => node.id(),
            ReadNodeBacking::PersistedBytes(node) => node.node_type() as u8,
            ReadNodeBacking::Owned(node) => node.id(),
        }
    }

    pub fn is_node256(&self) -> bool {
        matches!(self.node_type(), Some(TrieNodeID::Node256))
    }

    /// Decode a `BytesBacking` node into an owned `TrieNodeType`.
    /// Borrowed bytes (mmap) may be a prefix slice — uses prefix decode.
    /// Owned bytes use exact-length decode with validation.
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

    pub fn with_patch_depth(mut self, patch_depth: usize) -> Self {
        self.patch_depth = patch_depth;
        self
    }

    pub fn is_leaf(&self) -> Result<bool, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.is_leaf()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.is_leaf()),
            ReadNodeBacking::PersistedBytes(node) => Ok(node.node_type() == TrieNodeID::Leaf),
            ReadNodeBacking::Owned(node) => Ok(node.is_leaf()),
        }
    }

    pub fn path_bytes(&self) -> Result<&[u8], Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.path_bytes()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.path_bytes()),
            ReadNodeBacking::PersistedBytes(node) => {
                Ok(self.decoded_from_bytes(node)?.path_bytes())
            }
            ReadNodeBacking::Owned(node) => Ok(node.path_bytes().as_slice()),
        }
    }

    pub fn ptrs(&self) -> Result<&[TriePtr], Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.ptrs()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.ptrs()),
            ReadNodeBacking::PersistedBytes(node) => Ok(self.decoded_from_bytes(node)?.ptrs()),
            ReadNodeBacking::Owned(node) => Ok(node.ptrs()),
        }
    }

    pub fn walk(&self, chr: u8) -> Result<Option<TriePtr>, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.walk(chr)),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.walk(chr)),
            ReadNodeBacking::PersistedBytes(node) => Ok(self.decoded_from_bytes(node)?.walk(chr)),
            ReadNodeBacking::Owned(node) => Ok(node.walk(chr)),
        }
    }

    pub fn as_leaf(&self) -> Result<Option<TrieLeafRef<'_>>, Error> {
        match &self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok(node.as_leaf()),
            ReadNodeBacking::PersistedDecoded(node) => Ok(node.as_leaf()),
            ReadNodeBacking::PersistedBytes(node) => Ok(match self.decoded_from_bytes(node)? {
                TrieNodeType::Leaf(leaf) => Some(TrieLeafRef {
                    path: leaf.path.as_slice(),
                    data: &leaf.data,
                }),
                _ => None,
            }),
            ReadNodeBacking::Owned(node) => Ok(TrieNodeRef::from(node).as_leaf()),
        }
    }

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

    pub fn into_owned_node(self) -> Result<(TrieNodeType, Option<TrieHash>), Error> {
        match self.backing {
            ReadNodeBacking::VolatileDecoded(node) => Ok((node.to_owned_node(), self.hash)),
            ReadNodeBacking::PersistedDecoded(node) => Ok((node.to_owned_node(), self.hash)),
            ReadNodeBacking::PersistedBytes(ref node) => {
                Ok((self.decode_bytes_to_node(node)?, self.hash))
            }
            ReadNodeBacking::Owned(node) => Ok((node, self.hash)),
        }
    }

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
