use std::hint::black_box;
use std::io::Cursor;

use blockstack_lib::chainstate::stacks::index::node::{
    TrieNode, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodeType, TriePtr,
    TRIEPTR_SIZE,
};
use blockstack_lib::chainstate::stacks::index::{bits, TrieLeaf};
use criterion::{criterion_group, BenchmarkId, Criterion};
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

use super::common::configured_criterion;

#[inline]
fn sample_path() -> [u8; TRIEHASH_ENCODED_SIZE] {
    std::array::from_fn(|i| i as u8)
}

#[inline]
fn sample_hash() -> TrieHash {
    TrieHash([0xAB; TRIEHASH_ENCODED_SIZE])
}

fn make_ptr_bytes(node_id: TrieNodeID) -> Vec<u8> {
    let num_ptrs = match node_id {
        TrieNodeID::Leaf => 1,
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        TrieNodeID::Empty => unreachable!("Empty is not encoded as a node body"),
    };

    let mut bytes = vec![0u8; 1 + num_ptrs * TRIEPTR_SIZE];
    bytes[0] = node_id as u8;

    for i in 0..num_ptrs {
        let off = 1 + i * TRIEPTR_SIZE;
        bytes[off] = TrieNodeID::Leaf as u8;
        bytes[off + 1] = i as u8;
        bytes[off + 2..off + 6].copy_from_slice(&(i as u32 + 1).to_be_bytes());
        bytes[off + 6..off + 10].copy_from_slice(&0u32.to_be_bytes());
    }

    bytes
}

fn make_node_variants() -> Vec<(&'static str, u8, TrieNodeType)> {
    let path = sample_path();

    let mut node4 = TrieNode4::new(&path);
    for i in 0..4u8 {
        node4.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1);
    }

    let mut node16 = TrieNode16::new(&path);
    for i in 0..16u8 {
        node16.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 10);
    }

    let mut node48 = TrieNode48::new(&path);
    for i in 0..48u8 {
        let inserted = node48.insert(&TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 100));
        debug_assert!(inserted);
    }

    let mut node256 = TrieNode256::new(&path);
    for i in 0..=255u8 {
        node256.ptrs[i as usize] = TriePtr::new(TrieNodeID::Leaf as u8, i, (i as u32) + 1000);
    }

    let leaf = TrieLeaf::new(&path, &[0x11u8; 40]);

    vec![
        ("node4", TrieNodeID::Node4 as u8, TrieNodeType::Node4(node4)),
        (
            "node16",
            TrieNodeID::Node16 as u8,
            TrieNodeType::Node16(node16),
        ),
        (
            "node48",
            TrieNodeID::Node48 as u8,
            TrieNodeType::Node48(Box::new(node48)),
        ),
        (
            "node256",
            TrieNodeID::Node256 as u8,
            TrieNodeType::Node256(Box::new(node256)),
        ),
        ("leaf", TrieNodeID::Leaf as u8, TrieNodeType::Leaf(leaf)),
    ]
}

fn serialize_nodetype(node: &TrieNodeType, hash: TrieHash) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::with_capacity(bits::get_node_byte_len(node)));
    bits::write_nodetype_bytes(&mut cursor, node, hash).expect("serialize nodetype");
    cursor.into_inner()
}

pub fn bench_path_from_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("index_bits/path_from_bytes");

    let empty = vec![0u8];
    group.bench_function("len_0", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(empty.as_slice());
            let out = bits::path_from_bytes(&mut cursor).expect("path decode");
            black_box(out);
        });
    });

    let path = sample_path();
    let mut max_len = Vec::with_capacity(1 + path.len());
    max_len.push(path.len() as u8);
    max_len.extend_from_slice(&path);
    group.bench_function("len_32", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(max_len.as_slice());
            let out = bits::path_from_bytes(&mut cursor).expect("path decode");
            black_box(out);
        });
    });

    group.finish();
}

pub fn bench_ptrs_from_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("index_bits/ptrs_from_bytes");

    let cases: &[(TrieNodeID, usize)] = &[
        (TrieNodeID::Node4, 4),
        (TrieNodeID::Node16, 16),
        (TrieNodeID::Node48, 48),
        (TrieNodeID::Node256, 256),
    ];

    for &(node_id, num_ptrs) in cases {
        let bytes = make_ptr_bytes(node_id);
        let mut ptrs = vec![TriePtr::default(); num_ptrs];
        group.bench_with_input(BenchmarkId::new("decode", num_ptrs), &bytes, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data.as_slice());
                let nid = bits::ptrs_from_bytes(node_id as u8, &mut cursor, ptrs.as_mut_slice())
                    .expect("ptr decode");
                black_box(nid);
                black_box(&ptrs);
            });
        });
    }

    group.finish();
}

pub fn bench_read_nodetype_at_head(c: &mut Criterion) {
    let hash = sample_hash();
    let encoded_cases: Vec<(&'static str, u8, Vec<u8>)> = make_node_variants()
        .into_iter()
        .map(|(name, ptr_id, node)| (name, ptr_id, serialize_nodetype(&node, hash)))
        .collect();

    let mut with_hash_group = c.benchmark_group("index_bits/read_nodetype_at_head");
    for (name, ptr_id, encoded) in &encoded_cases {
        with_hash_group.bench_with_input(BenchmarkId::new("decode", name), encoded, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data.as_slice());
                let out =
                    bits::read_nodetype_at_head(&mut cursor, *ptr_id).expect("node decode+hash");
                black_box(out);
            });
        });
    }
    with_hash_group.finish();

    let mut nohash_group = c.benchmark_group("index_bits/read_nodetype_at_head_nohash");
    for (name, ptr_id, encoded) in &encoded_cases {
        nohash_group.bench_with_input(BenchmarkId::new("decode", name), encoded, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data.as_slice());
                let out = bits::read_nodetype_at_head_nohash(&mut cursor, *ptr_id)
                    .expect("node decode nohash");
                black_box(out);
            });
        });
    }
    nohash_group.finish();
}

pub fn bench_write_nodetype_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("index_bits/write_nodetype_bytes");
    let hash = sample_hash();

    for (name, _ptr_id, node) in make_node_variants() {
        group.bench_function(BenchmarkId::new("encode", name), |b| {
            let mut cursor = Cursor::new(Vec::with_capacity(bits::get_node_byte_len(&node)));
            b.iter(|| {
                cursor.set_position(0);
                cursor.get_mut().clear();
                let written =
                    bits::write_nodetype_bytes(&mut cursor, &node, hash).expect("node encode");
                black_box(written);
                black_box(cursor.get_ref().len());
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets =
        bench_path_from_bytes,
        bench_ptrs_from_bytes,
        bench_read_nodetype_at_head,
        bench_write_nodetype_bytes
}
