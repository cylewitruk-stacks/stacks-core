use std::hint::black_box;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use blockstack_lib::chainstate::stacks::index::node::{CursorError, TrieCursor};
use blockstack_lib::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieHashCalculationMode, TrieStorageConnection,
};
use blockstack_lib::chainstate::stacks::index::trie::{InsertionPoint, Trie};
use blockstack_lib::chainstate::stacks::index::{Error, MARFValue, MarfTrieId, TrieLeaf};
use criterion::{criterion_group, Criterion};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

use super::common::{block_id, configured_criterion};

fn path_from_seed(seed: u8) -> TrieHash {
    let bytes: [u8; 32] = std::array::from_fn(|i| seed.wrapping_mul(17).wrapping_add(i as u8));
    TrieHash::from_bytes(&bytes).expect("failed to build trie path")
}

fn missing_path() -> TrieHash {
    // Ensure the first byte is not present in the seeded fixture keys.
    let bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_add(1));
    TrieHash::from_bytes(&bytes).expect("failed to build missing trie path")
}

fn walk_to_insertion_point<T: MarfTrieId>(
    storage: &mut TrieStorageConnection<T>,
    path: &TrieHash,
) -> Result<InsertionPoint<T>, Error> {
    let mut cursor = TrieCursor::new(path, storage.root_trieptr());
    let mut node = Trie::read_root_nohash(storage)?;

    for _ in 0..=32 {
        match Trie::walk_from_nohash(storage, &node, &mut cursor) {
            Ok(Some((_next_ptr, next_node))) => {
                node = next_node;
            }
            Ok(None) => return InsertionPoint::new(cursor, node),
            Err(Error::CursorError(CursorError::PathDiverged | CursorError::ChrNotFound)) => {
                return InsertionPoint::new(cursor, node);
            }
            Err(e) => return Err(e),
        }
    }

    Err(Error::CorruptionError(
        "Exceeded maximum trie walk depth while finding insertion point".to_string(),
    ))
}

struct TrieFixture {
    store: TrieFileStorage<StacksBlockId>,
    tip: StacksBlockId,
    walk_path: TrieHash,
    existing_path: TrieHash,
    missing_path: TrieHash,
}

fn make_fixture() -> TrieFixture {
    let mut store = TrieFileStorage::open(
        ":memory:",
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false),
    )
    .expect("failed to create trie store");

    let tip = block_id(1u32);
    let walk_path = path_from_seed(96);
    let existing_path = path_from_seed(42);
    let missing_path = missing_path();

    let mut tx = store
        .transaction()
        .expect("failed to create transaction for fixture");
    MARF::format(&mut tx, &tip).expect("failed to format trie fixture");
    tx.open_block(&tip).expect("failed to open fixture tip");

    for i in 0..192u32 {
        let path = path_from_seed(i as u8);
        let leaf = TrieLeaf::from_value(&[], MARFValue::from(i + 1));
        MARF::insert_leaf(&mut tx, &tip, &path, &leaf)
            .expect("failed to pre-populate trie fixture");
    }

    tx.commit_tx();

    TrieFixture {
        store,
        tip,
        walk_path,
        existing_path,
        missing_path,
    }
}

fn bench_read_root(c: &mut Criterion) {
    let mut fixture = make_fixture();
    let mut conn = fixture.store.connection();
    conn.open_block(&fixture.tip)
        .expect("failed to open fixture tip");

    let mut group = c.benchmark_group("marf_trie/read_root");
    group.bench_function("with_hash", |b| {
        b.iter(|| {
            let out = Trie::read_root(&mut conn).expect("read_root failed");
            black_box(out);
        });
    });

    group.bench_function("nohash", |b| {
        b.iter(|| {
            let out = Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed");
            black_box(out);
        });
    });
    group.finish();
}

fn bench_walk_from(c: &mut Criterion) {
    let mut fixture = make_fixture();
    let mut conn = fixture.store.connection();
    conn.open_block(&fixture.tip)
        .expect("failed to open fixture tip");

    let walk_path_with_hash = fixture.walk_path;
    let walk_path_nohash = fixture.walk_path;

    let mut group = c.benchmark_group("marf_trie/walk_from");
    group.bench_function("with_hash", |b| {
        b.iter(|| {
            let mut cursor = TrieCursor::new(&walk_path_with_hash, conn.root_trieptr());
            let (mut node, mut node_hash) = Trie::read_root(&mut conn).expect("read_root failed");

            for _ in 0..=32 {
                match Trie::walk_from(&mut conn, &node, &mut cursor) {
                    Ok(Some((_next_ptr, next_node, next_hash))) => {
                        node = next_node;
                        node_hash = next_hash;
                    }
                    Ok(None) => break,
                    Err(Error::CursorError(
                        CursorError::PathDiverged | CursorError::ChrNotFound,
                    )) => break,
                    Err(e) => panic!("walk_from failed: {e:?}"),
                }
            }

            black_box((cursor.ptr(), node_hash));
        });
    });

    group.bench_function("nohash", |b| {
        b.iter(|| {
            let mut cursor = TrieCursor::new(&walk_path_nohash, conn.root_trieptr());
            let mut node = Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed");

            for _ in 0..=32 {
                match Trie::walk_from_nohash(&mut conn, &node, &mut cursor) {
                    Ok(Some((_next_ptr, next_node))) => {
                        node = next_node;
                    }
                    Ok(None) => break,
                    Err(Error::CursorError(
                        CursorError::PathDiverged | CursorError::ChrNotFound,
                    )) => break,
                    Err(e) => panic!("walk_from_nohash failed: {e:?}"),
                }
            }

            black_box(cursor.ptr());
        });
    });
    group.finish();
}

fn bench_get_children_hashes(c: &mut Criterion) {
    let mut fixture = make_fixture();
    let mut conn = fixture.store.connection();
    conn.open_block(&fixture.tip)
        .expect("failed to open fixture tip");

    let mut group = c.benchmark_group("marf_trie/get_children_hashes");
    group.bench_function("root_node", |b| {
        b.iter(|| {
            let root = Trie::read_root_nohash(&mut conn).expect("read_root_nohash failed");
            let out = Trie::get_children_hashes(&mut conn, &root).expect("get_children_hashes");
            black_box(out);
        });
    });
    group.finish();
}

fn bench_add_value_update_root_hash(c: &mut Criterion) {
    let mut fixture = make_fixture();
    let mut next_value = 10_000u32;

    let mut group = c.benchmark_group("marf_trie/add_value_update_root_hash");
    group.bench_function("replace_leaf", |b| {
        b.iter(|| {
            next_value = next_value.wrapping_add(1);
            let mut tx = fixture
                .store
                .transaction()
                .expect("failed to start tx for replace bench");
            tx.open_block(&fixture.tip)
                .expect("failed to open fixture tip");

            let mut insertion_point =
                walk_to_insertion_point(&mut tx, &fixture.existing_path).expect("walk failed");
            let mut leaf = TrieLeaf::from_value(&[], MARFValue::from(next_value));
            let out = Trie::add_value(&mut tx, &mut insertion_point, &mut leaf)
                .expect("add_value failed");
            Trie::update_root_hash(&mut tx, insertion_point.cursor())
                .expect("update_root_hash failed");

            black_box(out);
            tx.rollback();
        });
    });

    group.bench_function("insert_missing_leaf", |b| {
        b.iter(|| {
            let mut tx = fixture
                .store
                .transaction()
                .expect("failed to start tx for insert bench");
            tx.open_block(&fixture.tip)
                .expect("failed to open fixture tip");

            let mut insertion_point =
                walk_to_insertion_point(&mut tx, &fixture.missing_path).expect("walk failed");
            let mut leaf = TrieLeaf::from_value(&[], MARFValue::from(0xA5A5_A5A5));
            let out = Trie::add_value(&mut tx, &mut insertion_point, &mut leaf)
                .expect("add_value failed");
            Trie::update_root_hash(&mut tx, insertion_point.cursor())
                .expect("update_root_hash failed");

            black_box(out);
            tx.rollback();
        });
    });
    group.finish();
}

fn bench_cursor_walk_add_value(c: &mut Criterion) {
    let mut fixture = make_fixture();
    let mut next_value = 50_000u32;

    let mut group = c.benchmark_group("marf_trie/cursor_walk_add_value");
    group.bench_function("replace_leaf", |b| {
        b.iter(|| {
            next_value = next_value.wrapping_add(1);
            let mut tx = fixture
                .store
                .transaction()
                .expect("failed to start tx for replace bench");
            tx.open_block(&fixture.tip)
                .expect("failed to open fixture tip");

            let mut insertion_point =
                walk_to_insertion_point(&mut tx, &fixture.existing_path).expect("walk failed");
            let mut leaf = TrieLeaf::from_value(&[], MARFValue::from(next_value));
            let out = Trie::add_value(&mut tx, &mut insertion_point, &mut leaf)
                .expect("add_value failed");

            black_box(out);
            tx.rollback();
        });
    });

    group.bench_function("insert_missing_leaf", |b| {
        b.iter(|| {
            let mut tx = fixture
                .store
                .transaction()
                .expect("failed to start tx for insert bench");
            tx.open_block(&fixture.tip)
                .expect("failed to open fixture tip");

            let mut insertion_point =
                walk_to_insertion_point(&mut tx, &fixture.missing_path).expect("walk failed");
            let mut leaf = TrieLeaf::from_value(&[], MARFValue::from(0x5A5A_5A5A));
            let out = Trie::add_value(&mut tx, &mut insertion_point, &mut leaf)
                .expect("add_value failed");

            black_box(out);
            tx.rollback();
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets =
        bench_read_root,
        bench_walk_from,
        bench_get_children_hashes,
        bench_add_value_update_root_hash,
        bench_cursor_walk_add_value
}
