use std::io::{Read as _, Seek as _, SeekFrom};

use clarity::types::chainstate::{TRIEHASH_ENCODED_SIZE, TrieHash};
use stackslib::chainstate::stacks::index::node::{TrieNodeType, is_backptr};
use stackslib::chainstate::stacks::index::{Error as MarfError, bits, trie_sql};

use crate::cli::CliCtx;
use crate::types::BlobEntry;

/// Read a block's trie blob bytes, from either external file or inline sqlite.
pub fn read_blob(ctx: &CliCtx, block_id: u32) -> Vec<u8> {
    if let Some(blobs_path) = ctx.blobs_path() {
        match trie_sql::get_external_trie_offset_length(ctx.db(), block_id) {
            Ok((offset, length)) if length > 0 => {
                let mut f = std::fs::File::open(blobs_path).unwrap_or_else(|e| {
                    eprintln!("Failed to open blobs file {:?}: {e}", blobs_path);
                    std::process::exit(1);
                });
                f.seek(SeekFrom::Start(offset)).unwrap();
                let mut buf = vec![0u8; length as usize];
                f.read_exact(&mut buf).unwrap();
                return buf;
            }
            _ => {}
        }
    }

    // Fall back to inline blob.
    trie_sql::read_trie_blob_bytes(ctx.db(), block_id).unwrap_or_else(|e| {
        eprintln!("Failed to read blob for block {block_id}: {e:?}");
        std::process::exit(1);
    })
}

pub fn node_type_name(node: &TrieNodeType) -> &'static str {
    match node {
        TrieNodeType::Node4(_) => "Node4",
        TrieNodeType::Node16(_) => "Node16",
        TrieNodeType::Node48(_) => "Node48",
        TrieNodeType::Node256(_) => "Node256",
        TrieNodeType::Leaf(_) => "Leaf",
    }
}

pub fn child_count(node: &TrieNodeType) -> usize {
    if node.is_leaf() {
        return 0;
    }
    node.ptrs().iter().filter(|p| !p.is_empty()).count()
}

pub fn backptr_count(node: &TrieNodeType) -> usize {
    if node.is_leaf() {
        return 0;
    }
    node.ptrs()
        .iter()
        .filter(|p| !p.is_empty() && is_backptr(p.id()))
        .count()
}

/// Decode a single entry (hash + node or hash + patch) from blob bytes at the given offset.
/// `ptr_id` is the expected node type ID (from the parent's pointer).
pub fn decode_entry(blob: &[u8], offset: usize, ptr_id: u8) -> Result<BlobEntry, MarfError> {
    let slice = &blob[offset..];

    // First TRIEHASH_ENCODED_SIZE bytes are the node hash.
    if slice.len() < TRIEHASH_ENCODED_SIZE {
        return Err(MarfError::CorruptionError(
            "Blob too short for hash".to_string(),
        ));
    }
    let hash =
        TrieHash::from_bytes(&slice[..TRIEHASH_ENCODED_SIZE]).expect("Failed to decode TrieHash");
    let body = &slice[TRIEHASH_ENCODED_SIZE..];

    match bits::decode_nodetype_from_slice_at_head(body, ptr_id) {
        Ok((node, body_consumed)) => Ok(BlobEntry::Node {
            hash,
            node: Box::new(node),
            consumed: TRIEHASH_ENCODED_SIZE + body_consumed,
        }),
        Err(MarfError::Patch(_, patch)) => {
            let body_consumed = patch.size();
            Ok(BlobEntry::Patch {
                hash,
                patch,
                consumed: TRIEHASH_ENCODED_SIZE + body_consumed,
            })
        }
        Err(e) => Err(e),
    }
}
