mod api;
mod bits;
mod storage;
mod trie;

fn main() {
    // SAFETY: This is the first thing we do in the process, before any
    // potential threads are spawned or any FFI into C libraries that might read
    // the environment.
    unsafe {
        std::env::set_var("STACKS_LOG_CRITONLY", "1");
    }

    bits::benches();
    storage::benches();
    trie::benches();
    api::benches();

    criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
}
