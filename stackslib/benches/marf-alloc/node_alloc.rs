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
//! In `MARF_ALLOC_OUTPUT=raw`, this emits detailed per-case lines.
//! In all modes, the unified `summary\tbenchmark\tname\t...` output is emitted
//! by `main.rs`.
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
use crate::utils::{has_help_flag, parse_usize_env};
use crate::{OutputMode, Summary};

const DEFAULT_ITERS: usize = 200_000;

#[derive(Clone, Copy)]
struct CaseStats {
    alloc_calls: u64,
    alloc_bytes: u64,
    elapsed_ms: f64,
}

#[rustfmt::skip]
fn print_usage(args: &[String]) {
    if has_help_flag(args) {
        println!("node-alloc: allocation profiling micro-benchmark for trie nodes");
        println!();
        println!("Environment variables:");
        println!("  ITERS iterations per measured case [default: {DEFAULT_ITERS}]");
        println!("        Higher values reduce timer noise but increase runtime linearly");
        println!("        Allocation counters are total counts/bytes across all iterations");
        println!("  MARF_ALLOC_OUTPUT output mode [default: summary]");
        println!("        'summary': unified summary lines only");
        println!("        'raw': detailed per-case lines + unified summary lines");
        println!();
        println!("Output:");
        println!("  summary\\tbenchmark\\tname\\ttotal_ms\\talloc_count\\talloc_bytes");
        return;
    }
}

fn run_case<F>(name: &str, mode: OutputMode, mut f: F) -> CaseStats
where
    F: FnMut(),
{
    reset_stats();
    let start = Instant::now();
    f();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let stats = snapshot();
    if mode.is_raw() {
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
    CaseStats {
        alloc_calls: stats.alloc_calls,
        alloc_bytes: stats.alloc_bytes,
        elapsed_ms,
    }
}

fn record_case<F>(summary: &mut Summary, name: &str, mode: OutputMode, f: F)
where
    F: FnMut(),
{
    let stats = run_case(name, mode, f);
    summary.push_line(name, stats.elapsed_ms, stats.alloc_calls, stats.alloc_bytes);
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

pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage(args);
        return None;
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

    if output_mode.is_raw() {
        println!("iters={iters}");
    }

    let mut summary = Summary::new("node-alloc", 10);

    record_case(&mut summary, "new_node4", output_mode, || {
        for _ in 0..iters {
            black_box(TrieNode4::new(&path));
        }
    });

    record_case(&mut summary, "new_node16", output_mode, || {
        for _ in 0..iters {
            black_box(TrieNode16::new(&path));
        }
    });

    record_case(&mut summary, "clone_node4", output_mode, || {
        for _ in 0..iters {
            black_box(node4.clone());
        }
    });

    record_case(&mut summary, "clone_node16", output_mode, || {
        for _ in 0..iters {
            black_box(node16.clone());
        }
    });

    record_case(&mut summary, "clone_node256", output_mode, || {
        for _ in 0..iters {
            black_box(node256.clone());
        }
    });

    record_case(&mut summary, "new_leaf", output_mode, || {
        for _ in 0..iters {
            black_box(TrieLeaf::new(&path, &leaf_data));
        }
    });

    record_case(&mut summary, "clone_leaf", output_mode, || {
        for _ in 0..iters {
            black_box(leaf.clone());
        }
    });

    record_case(&mut summary, "decode_node4_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node4.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node4 as u8)
                    .expect("decode node4"),
            );
        }
    });

    record_case(&mut summary, "decode_leaf_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_leaf.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Leaf as u8)
                    .expect("decode leaf"),
            );
        }
    });

    record_case(&mut summary, "decode_node256_nohash", output_mode, || {
        for _ in 0..iters {
            let mut cursor = Cursor::new(encoded_node256.as_slice());
            black_box(
                bits::read_nodetype_at_head_nohash(&mut cursor, TrieNodeID::Node256 as u8)
                    .expect("decode node256"),
            );
        }
    });

    Some(summary)
}
