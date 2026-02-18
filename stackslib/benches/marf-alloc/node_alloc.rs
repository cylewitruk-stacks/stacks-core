// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Allocation-focused micro-benchmark for trie node construction/clone/decode.
//!
//! Output format is one line per case:
//! `{case}\talloc_calls=...\talloc_bytes=...\trealloc_calls=...\tdealloc_calls=...\tdealloc_bytes=...\telapsed_ms=...`
//!
//! Environment variables:
//! - `ITERS` (default `200000`): iterations per case.
//!   Runtime scales roughly linearly with this value.
//!   Allocation counters are totals over the full case, so normalize by
//!   `ITERS` when comparing per-operation allocation behavior.
//!
use std::hint::black_box;
use std::io::Cursor;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::node::{
    TrieNode16, TrieNode256, TrieNode4, TrieNodeID, TrieNodeType, TriePtr,
};
use blockstack_lib::chainstate::stacks::index::{bits, TrieLeaf};
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

use crate::allocator::{reset_stats, snapshot};

const DEFAULT_ITERS: usize = 200_000;

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("node-alloc: allocation profiling micro-benchmark for trie nodes");
        println!();
        println!("Environment variables:");
        println!("  ITERS iterations per measured case [default: {DEFAULT_ITERS}]");
        println!("        Higher values reduce timer noise but increase runtime linearly");
        println!("        Allocation counters are total counts/bytes across all iterations");
        println!();
        println!("Output:");
        println!("  One tab-separated line per case with alloc/realloc/dealloc totals");
        println!("  and elapsed_ms for the whole case.");
        return;
    }
}

fn run_case<F>(name: &str, mut f: F)
where
    F: FnMut(),
{
    reset_stats();
    let start = Instant::now();
    f();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let stats = snapshot();
    println!(
        "{name}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\telapsed_ms={:.2}",
        stats.alloc_calls,
        stats.alloc_bytes,
        stats.realloc_calls,
        stats.dealloc_calls,
        stats.dealloc_bytes,
        elapsed_ms
    );
}

fn sample_path() -> [u8; TRIEHASH_ENCODED_SIZE] {
    std::array::from_fn(|i| i as u8)
}

fn make_node4(path: &[u8]) -> TrieNode4 {
    let mut node4 = TrieNode4::new(path);
    for i in 0..4u8 {
        node4.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node4
}

fn make_node16(path: &[u8]) -> TrieNode16 {
    let mut node16 = TrieNode16::new(path);
    for i in 0..16u8 {
        node16.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node16
}

fn make_node256(path: &[u8]) -> TrieNode256 {
    let mut node256 = TrieNode256::new(path);
    for i in 0..=255u8 {
        node256.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }
    node256
}

fn serialize_nodetype(node: &TrieNodeType) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::with_capacity(bits::get_node_byte_len(node)));
    bits::write_nodetype_bytes(&mut cursor, node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE]))
        .expect("serialize nodetype");
    cursor.into_inner()
}

pub fn run(args: &[String]) {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage(args);
        return;
    }

    let iters = parse_usize_env("ITERS", DEFAULT_ITERS);
    assert!(iters > 0, "ITERS must be > 0");

    let path = sample_path();
    let leaf_data = [0x11u8; 40];

    let node4 = make_node4(&path);
    let node16 = make_node16(&path);
    let node256 = make_node256(&path);
    let leaf = TrieLeaf::new(&path, &leaf_data);

    let encoded_node4 = serialize_nodetype(&TrieNodeType::Node4(node4.clone()));
    let encoded_node256 = serialize_nodetype(&TrieNodeType::Node256(Box::new(node256.clone())));
    let encoded_leaf = serialize_nodetype(&TrieNodeType::Leaf(leaf.clone()));

    println!("iters={iters}");

    run_case("new_node4", || {
        for _ in 0..iters {
            black_box(TrieNode4::new(&path));
        }
    });

    run_case("new_node16", || {
        for _ in 0..iters {
            black_box(TrieNode16::new(&path));
        }
    });

    run_case("clone_node4", || {
        for _ in 0..iters {
            black_box(node4.clone());
        }
    });

    run_case("clone_node16", || {
        for _ in 0..iters {
            black_box(node16.clone());
        }
    });

    run_case("clone_node256", || {
        for _ in 0..iters {
            black_box(node256.clone());
        }
    });

    run_case("new_leaf", || {
        for _ in 0..iters {
            black_box(TrieLeaf::new(&path, &leaf_data));
        }
    });

    run_case("clone_leaf", || {
        for _ in 0..iters {
            black_box(leaf.clone());
        }
    });

    run_case("decode_node4_nohash", || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node4.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node4 as u8)
                    .expect("decode node4"),
            );
        }
    });

    run_case("decode_leaf_nohash", || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_leaf.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Leaf as u8)
                    .expect("decode leaf"),
            );
        }
    });

    run_case("decode_node256_nohash", || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node256.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node256 as u8)
                    .expect("decode node256"),
            );
        }
    });
}
