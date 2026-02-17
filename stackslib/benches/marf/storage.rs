use std::hint::black_box;

use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use blockstack_lib::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieHashCalculationMode,
};
use blockstack_lib::chainstate::stacks::index::trie::Trie;
use blockstack_lib::chainstate::stacks::index::ClarityMarfTrieId;
use criterion::{criterion_group, Criterion};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::TempDir;

use super::common::{block_id, make_batch};

fn build_committed_chain(
    db_path: &str,
    cache_strategy: &str,
    first_block: &StacksBlockId,
    second_block: &StacksBlockId,
) {
    let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true);
    let mut marf = MARF::from_path(db_path, marf_opts).expect("failed to open MARF fixture");

    {
        let mut tx = marf
            .begin_tx()
            .expect("failed to begin transaction for first fixture block");
        tx.begin(&StacksBlockId::sentinel(), first_block)
            .expect("failed to begin first fixture block");
        let (keys, values) = make_batch("parent", 0, 192, 1);
        tx.insert_batch(&keys, values)
            .expect("failed to insert first fixture batch");
        tx.commit()
            .expect("failed to commit first fixture block transaction");
    }

    {
        let mut tx = marf
            .begin_tx()
            .expect("failed to begin transaction for second fixture block");
        tx.begin(first_block, second_block)
            .expect("failed to begin second fixture block");
        let (keys, values) = make_batch("tip", 10_000, 192, 100_000);
        tx.insert_batch(&keys, values)
            .expect("failed to insert second fixture batch");
        tx.commit()
            .expect("failed to commit second fixture block transaction");
    }
}

struct StorageFixture {
    _tmpdir: TempDir,
    store: TrieFileStorage<StacksBlockId>,
    parent: StacksBlockId,
    tip: StacksBlockId,
}

fn make_committed_fixture(cache_strategy: &str) -> StorageFixture {
    let tmpdir = tempfile::tempdir().expect("failed to create temp dir for storage fixture");
    let db_path = tmpdir.path().join("marf-storage.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert fixture DB path to UTF-8")
        .to_string();

    let parent = block_id(1);
    let tip = block_id(2);

    build_committed_chain(&db_path_str, cache_strategy, &parent, &tip);

    let store = TrieFileStorage::open(
        &db_path_str,
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true),
    )
    .expect("failed to reopen storage fixture after MARF setup");

    StorageFixture {
        _tmpdir: tmpdir,
        store,
        parent,
        tip,
    }
}

struct UncommittedFixture {
    _tmpdir: TempDir,
    store: TrieFileStorage<StacksBlockId>,
    uncommitted_tip: StacksBlockId,
}

fn make_uncommitted_fixture(cache_strategy: &str) -> UncommittedFixture {
    let StorageFixture {
        _tmpdir,
        mut store,
        parent: _,
        tip,
    } = make_committed_fixture(cache_strategy);

    let uncommitted_tip = block_id(3);

    let mut tx = store
        .transaction()
        .expect("failed to start uncommitted fixture transaction");
    tx.open_block(&tip)
        .expect("failed to open committed tip for uncommitted fixture");
    MARF::extend_trie(&mut tx, &uncommitted_tip)
        .expect("failed to extend uncommitted fixture block");

    // Intentionally commit without flush so reads hit the uncommitted in-RAM branch.
    tx.commit_tx();

    UncommittedFixture {
        _tmpdir,
        store,
        uncommitted_tip,
    }
}

struct FlushFixture {
    _tmpdir: TempDir,
    marf: MARF<StacksBlockId>,
    tip: StacksBlockId,
    seed: u32,
}

fn make_flush_fixture(cache_strategy: &str) -> FlushFixture {
    let tmpdir = tempfile::tempdir().expect("failed to create temp dir for flush fixture");
    let db_path = tmpdir.path().join("marf-storage-flush.sqlite");
    let db_path_str = db_path
        .to_str()
        .expect("failed to convert flush fixture DB path to UTF-8")
        .to_string();

    let parent = block_id(11);
    let tip = block_id(12);

    build_committed_chain(&db_path_str, cache_strategy, &parent, &tip);

    let marf = MARF::from_path(
        &db_path_str,
        MARFOpenOpts::new(TrieHashCalculationMode::Deferred, cache_strategy, true),
    )
    .expect("failed to reopen MARF for flush fixture");

    FlushFixture {
        _tmpdir: tmpdir,
        marf,
        tip,
        seed: 100_000,
    }
}

fn bench_open_block(c: &mut Criterion) {
    let mut fixture = make_committed_fixture("noop");
    let mut conn = fixture.store.connection();

    let mut group = c.benchmark_group("marf_storage/open_block");

    group.bench_function("switch_committed_blocks", |b| {
        b.iter(|| {
            conn.open_block(&fixture.parent)
                .expect("open parent block failed");
            conn.open_block(&fixture.tip)
                .expect("open tip block failed");
            black_box(conn.get_cur_block_and_id());
        });
    });

    group.bench_function("same_block_noop", |b| {
        conn.open_block(&fixture.tip)
            .expect("open tip block for noop benchmark failed");

        b.iter(|| {
            conn.open_block(&fixture.tip)
                .expect("open_block noop path failed");
            black_box(conn.get_cur_block_and_id());
        });
    });

    group.finish();
}

fn bench_read_nodetype(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_storage/read_nodetype");

    {
        let mut fixture = make_committed_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open tip for read_nodetype/noop");
        let root_ptr = conn.root_trieptr();

        group.bench_function("with_hash/noop", |b| {
            b.iter(|| {
                let out = conn
                    .read_nodetype(&root_ptr)
                    .expect("read_nodetype with hash failed");
                black_box(out);
            });
        });

        group.bench_function("nohash/noop", |b| {
            b.iter(|| {
                let out = conn
                    .read_nodetype_nohash(&root_ptr)
                    .expect("read_nodetype_nohash failed");
                black_box(out);
            });
        });
    }

    {
        let mut fixture = make_committed_fixture("everything");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open tip for read_nodetype/everything");
        let root_ptr = conn.root_trieptr();

        conn.read_nodetype(&root_ptr)
            .expect("cache priming read_nodetype failed");

        group.bench_function("with_hash/everything_hot", |b| {
            b.iter(|| {
                let out = conn
                    .read_nodetype(&root_ptr)
                    .expect("read_nodetype cache-hot failed");
                black_box(out);
            });
        });

        conn.read_nodetype_nohash(&root_ptr)
            .expect("cache priming read_nodetype_nohash failed");

        group.bench_function("nohash/everything_hot", |b| {
            b.iter(|| {
                let out = conn
                    .read_nodetype_nohash(&root_ptr)
                    .expect("read_nodetype_nohash cache-hot failed");
                black_box(out);
            });
        });
    }

    group.finish();
}

fn bench_read_node_hash_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_storage/read_node_hash_bytes");

    {
        let mut fixture = make_committed_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open tip for read_node_hash_bytes/noop");
        let root_ptr = conn.root_trieptr();

        group.bench_function("noop", |b| {
            b.iter(|| {
                let out = conn
                    .read_node_hash_bytes(&root_ptr)
                    .expect("read_node_hash_bytes noop failed");
                black_box(out);
            });
        });
    }

    {
        let mut fixture = make_committed_fixture("everything");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open tip for read_node_hash_bytes/everything");
        let root_ptr = conn.root_trieptr();

        conn.read_node_hash_bytes(&root_ptr)
            .expect("cache priming read_node_hash_bytes failed");

        group.bench_function("everything_hot", |b| {
            b.iter(|| {
                let out = conn
                    .read_node_hash_bytes(&root_ptr)
                    .expect("read_node_hash_bytes cache-hot failed");
                black_box(out);
            });
        });
    }

    group.finish();
}

fn bench_write_children_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("marf_storage/write_children_hashes");

    {
        let mut fixture = make_committed_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.tip)
            .expect("failed to open tip for committed write_children_hashes");
        let root_ptr = conn.root_trieptr();
        let root_node = conn
            .read_nodetype_nohash(&root_ptr)
            .expect("failed to read root node for committed write_children_hashes");

        group.bench_function("committed_root", |b| {
            let mut out = Vec::with_capacity(32 * 256);
            b.iter(|| {
                out.clear();
                conn.write_children_hashes(&root_node, &mut out)
                    .expect("write_children_hashes committed path failed");
                black_box(out.len());
            });
        });
    }

    {
        let mut fixture = make_uncommitted_fixture("noop");
        let mut conn = fixture.store.connection();
        conn.open_block(&fixture.uncommitted_tip)
            .expect("failed to open uncommitted tip for write_children_hashes");

        let root_node = Trie::read_root_nohash(&mut conn)
            .expect("failed to read uncommitted root node for write_children_hashes");

        group.bench_function("uncommitted_root", |b| {
            let mut out = Vec::with_capacity(32 * 256);
            b.iter(|| {
                out.clear();
                conn.write_children_hashes(&root_node, &mut out)
                    .expect("write_children_hashes uncommitted path failed");
                black_box(out.len());
            });
        });
    }

    group.finish();
}

fn bench_flush(c: &mut Criterion) {
    let mut fixture = make_flush_fixture("noop");

    let mut group = c.benchmark_group("marf_storage/flush");

    group.bench_function("extension_commit/populated_64", |b| {
        b.iter(|| {
            let next = block_id(fixture.seed);
            fixture.seed = fixture.seed.wrapping_add(1);
            let populate_seed = fixture.seed;

            let mut tx = fixture
                .marf
                .begin_tx()
                .expect("failed to start flush benchmark transaction");
            tx.begin(&fixture.tip, &next)
                .expect("failed to begin flush benchmark extension");

            let (keys, values) = make_batch(
                "flush",
                populate_seed.wrapping_mul(67),
                64,
                populate_seed.wrapping_mul(1024),
            );
            tx.insert_batch(&keys, values)
                .expect("failed to insert flush benchmark batch");
            tx.commit()
                .expect("failed to commit flush benchmark extension");

            fixture.tip = next;
            black_box(&fixture.tip);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_open_block,
    bench_read_nodetype,
    bench_read_node_hash_bytes,
    bench_write_children_hashes,
    bench_flush
);
