use clap::Args;
use clarity::types::chainstate::TRIEHASH_ENCODED_SIZE;
use stacks_common::util::hash::to_hex;
use stackslib::chainstate::stacks::index::node::{
    TrieNodeID, TrieNodeType, is_backptr, is_compressed,
};

use crate::cli::CliCtx;
use crate::types::BlobEntry;
use crate::util::{backptr_count, child_count, decode_entry, node_type_name, read_blob};

#[derive(Args)]
pub struct NodeArgs {
    pub block_id: u32,
    pub offset: u64,
}

pub fn exec(ctx: &CliCtx, args: NodeArgs) {
    let NodeArgs { block_id, offset } = args;

    let blob = read_blob(ctx, block_id);
    let offset = offset as usize;

    if offset >= blob.len() {
        eprintln!("Offset {offset} is past end of blob (size {})", blob.len());
        std::process::exit(1);
    }

    // Try to decode as Node256 first (root), then fall back to other types.
    let node_ids = [
        TrieNodeID::Node256 as u8,
        TrieNodeID::Node4 as u8,
        TrieNodeID::Node16 as u8,
        TrieNodeID::Node48 as u8,
        TrieNodeID::Leaf as u8,
    ];

    for &ptr_id in &node_ids {
        match decode_entry(&blob, offset, ptr_id) {
            Ok(BlobEntry::Node {
                hash,
                node,
                consumed,
            }) => {
                let ntype = node_type_name(&node);
                println!("Type:       {ntype}");
                println!("Hash:       {}", hash.to_hex());
                println!("Offset:     {offset}");
                println!("Size:       {consumed} bytes");
                println!(
                    "Path:       {} ({} bytes)",
                    to_hex(node.path_bytes()),
                    node.path_bytes().len()
                );
                let compressed =
                    is_compressed(*blob.get(offset + TRIEHASH_ENCODED_SIZE).unwrap_or(&0));
                println!("Compressed: {compressed}");

                if !node.is_leaf() {
                    println!(
                        "Children:   {} total, {} backptrs",
                        child_count(&node),
                        backptr_count(&node)
                    );
                    println!();
                    println!(
                        "  {:>4}  {:>3}  {:>8}  {:>10}  {:>10}",
                        "slot", "chr", "ptr", "back_block", "type"
                    );
                    println!("  {}", "-".repeat(50));
                    for (i, ptr) in node.ptrs().iter().enumerate() {
                        if !ptr.is_empty() {
                            let ptype = if is_backptr(ptr.id()) {
                                "backptr"
                            } else {
                                "local"
                            };
                            println!(
                                "  {i:>4}  {:>3}  {:>8}  {:>10}  {ptype:>10}",
                                ptr.chr(),
                                ptr.ptr(),
                                ptr.back_block(),
                            );
                        }
                    }
                } else if let TrieNodeType::Leaf(ref leaf) = *node {
                    println!("Leaf data:  {}", to_hex(&leaf.data.0));
                }
                return;
            }
            Ok(BlobEntry::Patch {
                hash,
                patch,
                consumed,
            }) => {
                println!("Type:       Patch");
                println!("Hash:       {}", hash.to_hex());
                println!("Offset:     {offset}");
                println!("Size:       {consumed} bytes");
                println!(
                    "Base:       block_id={}, ptr={}",
                    patch.ptr.back_block(),
                    patch.ptr.ptr()
                );
                println!("Diff count: {}", patch.ptr_diff.len());
                println!();
                println!(
                    "  {:>4}  {:>3}  {:>8}  {:>10}  {:>10}",
                    "idx", "chr", "ptr", "back_block", "type"
                );
                println!("  {}", "-".repeat(50));
                for (i, ptr) in patch.ptr_diff.iter().enumerate() {
                    let ptype = if is_backptr(ptr.id()) {
                        "backptr"
                    } else {
                        "local"
                    };
                    println!(
                        "  {i:>4}  {:>3}  {:>8}  {:>10}  {ptype:>10}",
                        ptr.chr(),
                        ptr.ptr(),
                        ptr.back_block(),
                    );
                }
                return;
            }
            Err(_) => continue,
        }
    }

    eprintln!("Failed to decode node at offset {offset} with any known type");
    eprintln!(
        "Raw bytes: {}",
        to_hex(&blob[offset..std::cmp::min(offset + 64, blob.len())])
    );
    std::process::exit(1);
}
