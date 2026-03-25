use clarity::types::chainstate::TrieHash;
use stackslib::chainstate::stacks::index::node::{TrieNodePatch, TrieNodeType};

/// Result of decoding one entry from a trie blob.
pub enum BlobEntry {
    Node {
        hash: TrieHash,
        node: Box<TrieNodeType>,
        consumed: usize,
    },
    Patch {
        hash: TrieHash,
        patch: TrieNodePatch,
        consumed: usize,
    },
}
