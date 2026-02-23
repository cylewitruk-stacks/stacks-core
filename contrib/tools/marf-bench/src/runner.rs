use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use tempfile::TempDir;

use crate::report::SummaryRow;
use crate::util::{
    combine_output_text, extract_summary_lines, log, print_output, run_checked, sanitize_revision,
};
use crate::{BenchKind, OutputFormat, TempBuilder};

const MARF_ALLOC_BENCH_FILES: [&str; 7] = [
    "allocator.rs",
    "common.rs",
    "main.rs",
    "node_alloc.rs",
    "read.rs",
    "utils.rs",
    "write.rs",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct BenchEnvOverrides {
    pub(crate) iters: Option<usize>,
    pub(crate) rounds: Option<usize>,
    pub(crate) chain_len: Option<u32>,
    pub(crate) write_depths: Option<String>,
    pub(crate) key_updates: Option<usize>,
    pub(crate) sqlite_wal_autocheckpoint: Option<usize>,
    pub(crate) sqlite_wal_checkpoint_mode: Option<String>,
    pub(crate) read_proofs: Option<bool>,
    pub(crate) keys_per_block: Option<u32>,
    pub(crate) depths: Option<String>,
    pub(crate) cache_strategies: Option<String>,
    pub(crate) key_search_max_tries: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct BenchRunRequest {
    pub(crate) kind: BenchKind,
    pub(crate) env: BenchEnvOverrides,
}

impl BenchRunRequest {
    pub(crate) fn new(kind: BenchKind, env: BenchEnvOverrides) -> Self {
        Self { kind, env }
    }
}

struct ManagedWorktree {
    path: PathBuf,
    _temp_root: Option<TempDir>,
}

pub struct Runner {
    repo_root: PathBuf,
    source_bench_dir: PathBuf,
    keep_worktrees: bool,
    worktrees: Vec<ManagedWorktree>,
    worktrees_by_revision: HashMap<String, PathBuf>,
    built_roots: HashSet<PathBuf>,
    overlay_changed_roots: HashMap<PathBuf, bool>,
}

impl Runner {
    pub(crate) fn new(repo_root: PathBuf, keep_worktrees: bool) -> Result<Self> {
        if !keep_worktrees {
            cleanup_stale_marf_bench_worktrees(&repo_root)?;
        } else {
            let cache_root = keep_worktrees_root(&repo_root);
            log(&format!(
                "Keep-worktrees cache root: {}",
                cache_root.display()
            ));
        }

        let source_bench_dir = repo_root.join("stackslib/benches/marf-alloc");
        if !source_bench_dir.is_dir() {
            bail!(
                "source bench directory not found: {}",
                source_bench_dir.display()
            );
        }

        for name in MARF_ALLOC_BENCH_FILES {
            let path = source_bench_dir.join(name);
            if !path.is_file() {
                bail!("missing source bench file: {}", path.display());
            }
        }

        Ok(Self {
            repo_root,
            source_bench_dir,
            keep_worktrees,
            worktrees: Vec::new(),
            worktrees_by_revision: HashMap::new(),
            built_roots: HashSet::new(),
            overlay_changed_roots: HashMap::new(),
        })
    }

    pub(crate) fn run_current_tree(
        &mut self,
        label: &str,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        let marf_bench_dir = self.repo_root.join("stackslib/benches/marf-alloc");
        if !marf_bench_dir.is_dir() {
            bail!(
                "current tree missing stackslib/benches/marf-alloc: {}",
                marf_bench_dir.display()
            );
        }

        let cargo_toml = self.repo_root.join("stackslib/Cargo.toml");
        let cargo_toml_text = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
        if !cargo_toml_text.contains("name = \"marf-alloc\"") {
            bail!(
                "current tree Cargo.toml missing marf-alloc bench target: {}",
                cargo_toml.display()
            );
        }

        let repo_root = self.repo_root.clone();
        self.run_benches(label, &repo_root, requests, output_format)
    }

    pub(crate) fn run_revision_via_worktree(
        &mut self,
        label: &str,
        revision: &str,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        let wt = if let Some(existing) = self.worktrees_by_revision.get(revision) {
            existing.clone()
        } else {
            let wt = self.create_worktree(revision)?;
            self.worktrees_by_revision
                .insert(revision.to_string(), wt.clone());
            wt
        };

        let overlay_changed = self.overlay_benches(&wt)?;
        self.ensure_bench_target(&wt.join("stackslib/Cargo.toml"))?;
        self.overlay_changed_roots
            .entry(wt.clone())
            .and_modify(|changed| *changed |= overlay_changed)
            .or_insert(overlay_changed);

        self.run_benches(label, &wt, requests, output_format)
    }

    fn create_worktree(&mut self, revision: &str) -> Result<PathBuf> {
        let revision_tag: String = sanitize_revision(revision).chars().take(40).collect();

        if self.keep_worktrees {
            let cache_root = keep_worktrees_root(&self.repo_root);
            fs::create_dir_all(&cache_root)
                .with_context(|| format!("failed to create {}", cache_root.display()))?;
            let path = cache_root.join(format!("marf-bench-{revision_tag}"));

            if path.is_dir() {
                if self.is_registered_worktree(&path)? {
                    log(&format!(
                        "Reusing worktree for {revision} at {}",
                        path.display()
                    ));
                    return Ok(path);
                }

                log(&format!(
                    "Removing unregistered cached worktree dir: {}",
                    path.display()
                ));
                fs::remove_dir_all(&path).with_context(|| {
                    format!(
                        "failed to remove stale cached worktree dir {}",
                        path.display()
                    )
                })?;
            }

            log(&format!(
                "Creating worktree for {revision} at {}",
                path.display()
            ));

            let mut cmd = Command::new("git");
            cmd.current_dir(&self.repo_root)
                .arg("worktree")
                .arg("add")
                .arg("--detach")
                .arg(&path)
                .arg(revision);
            run_checked(cmd, "failed to create git worktree")?;

            return Ok(path);
        }

        let temp_root = TempBuilder::new()
            .prefix(&format!("marf-bench-{}-", sanitize_revision(revision)))
            .tempdir()
            .context("failed to create temporary directory for worktree")?;
        let revision_tag: String = revision_tag.chars().take(12).collect();
        let path = temp_root.path().join(format!("marf-bench-{revision_tag}"));

        log(&format!(
            "Creating worktree for {revision} at {}",
            path.display()
        ));

        let mut cmd = Command::new("git");
        cmd.current_dir(&self.repo_root)
            .arg("worktree")
            .arg("add")
            .arg("--detach")
            .arg(&path)
            .arg(revision);
        run_checked(cmd, "failed to create git worktree")?;

        self.worktrees.push(ManagedWorktree {
            path: path.clone(),
            _temp_root: Some(temp_root),
        });
        Ok(path)
    }

    fn overlay_benches(&self, root: &Path) -> Result<bool> {
        let dest = root.join("stackslib/benches/marf-alloc");
        fs::create_dir_all(&dest)
            .with_context(|| format!("failed to create {}", dest.display()))?;

        let mut changed = false;

        for name in MARF_ALLOC_BENCH_FILES {
            let src = self.source_bench_dir.join(name);
            let dst = dest.join(name);
            changed |= copy_if_different(&src, &dst)?;
        }

        Ok(changed)
    }

    fn ensure_bench_target(&self, cargo_toml: &Path) -> Result<()> {
        let mut text = fs::read_to_string(cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;

        let mut updated = false;

        if !text.contains("name = \"marf-alloc\"") {
            text.push_str(
                "\n[[bench]]\nname = \"marf-alloc\"\nharness = false\npath = \"benches/marf-alloc/main.rs\"\n",
            );
            updated = true;
        }

        if !text.contains("tikv-jemallocator") {
            text.push_str(
                "\n# Included for profiling/benchmark entrypoints\n[target.'cfg(not(any(target_os = \"macos\", target_os=\"windows\", target_arch = \"arm\")))'.dev-dependencies]\ntikv-jemallocator = { workspace = true }\n",
            );
            updated = true;
        }

        if updated {
            fs::write(cargo_toml, text)
                .with_context(|| format!("failed to update {}", cargo_toml.display()))?;
        }

        Ok(())
    }

    pub(crate) fn run_benches(
        &mut self,
        label: &str,
        root: &Path,
        requests: &[BenchRunRequest],
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        if !self.built_roots.contains(root) {
            let overlay_changed = self
                .overlay_changed_roots
                .get(root)
                .copied()
                .unwrap_or(true);

            let can_reuse_cached_build =
                self.keep_worktrees && self.is_cached_worktree_path(root) && !overlay_changed;

            if can_reuse_cached_build {
                log(&format!(
                    "[{label}] Reusing existing marf-alloc build artifacts (worktree unchanged)"
                ));
            } else {
                self.build_bench_profile(label, root)?;
            }
            self.built_roots.insert(root.to_path_buf());
        }
        log(&format!("Running marf-alloc benches for {label}"));

        let mut rows = Vec::new();
        for request in requests {
            rows.extend(self.run_bench_case(label, root, request, output_format)?);
        }

        Ok(rows)
    }

    fn build_bench_profile(&self, label: &str, root: &Path) -> Result<()> {
        log(&format!(
            "[{label}] Building marf-alloc with 'bench' profile"
        ));

        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .arg("build")
            .arg("--profile")
            .arg("bench")
            .arg("-p")
            .arg("stackslib")
            .arg("--bench")
            .arg("marf-alloc");

        run_checked(cmd, "failed to build marf-alloc bench profile")
    }

    fn run_bench_case(
        &self,
        label: &str,
        root: &Path,
        request: &BenchRunRequest,
        output_format: OutputFormat,
    ) -> Result<Vec<SummaryRow>> {
        let bench = request.kind;
        log(&format!("[{label}] Running {}", bench.as_arg()));

        let marf_output_mode = if output_format == OutputFormat::Raw {
            "raw"
        } else {
            "summary"
        };

        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .arg("bench")
            .arg("-p")
            .arg("stackslib")
            .arg("--bench")
            .arg("marf-alloc")
            .arg("--")
            .arg(bench.as_arg())
            .env("MARF_ALLOC_OUTPUT", marf_output_mode);

        if let Some(iters) = request.env.iters {
            cmd.env("ITERS", iters.to_string());
        }
        if let Some(rounds) = request.env.rounds {
            cmd.env("ROUNDS", rounds.to_string());
        }
        if let Some(chain_len) = request.env.chain_len {
            cmd.env("CHAIN_LEN", chain_len.to_string());
        }
        if let Some(write_depths) = &request.env.write_depths {
            cmd.env("WRITE_DEPTHS", write_depths);
        }
        if let Some(key_updates) = request.env.key_updates {
            cmd.env("KEY_UPDATES", key_updates.to_string());
        }
        if let Some(sqlite_wal_autocheckpoint) = request.env.sqlite_wal_autocheckpoint {
            cmd.env(
                "SQLITE_WAL_AUTOCHECKPOINT",
                sqlite_wal_autocheckpoint.to_string(),
            );
        }
        if let Some(sqlite_wal_checkpoint_mode) = &request.env.sqlite_wal_checkpoint_mode {
            cmd.env("SQLITE_WAL_CHECKPOINT_MODE", sqlite_wal_checkpoint_mode);
        }
        if let Some(read_proofs) = request.env.read_proofs {
            cmd.env("READ_PROOFS", if read_proofs { "1" } else { "0" });
        }
        if let Some(keys_per_block) = request.env.keys_per_block {
            cmd.env("KEYS_PER_BLOCK", keys_per_block.to_string());
        }
        if let Some(depths) = &request.env.depths {
            cmd.env("DEPTHS", depths);
        }
        if let Some(cache_strategies) = &request.env.cache_strategies {
            cmd.env("CACHE_STRATEGIES", cache_strategies);
        }
        if let Some(key_search_max_tries) = request.env.key_search_max_tries {
            cmd.env("KEY_SEARCH_MAX_TRIES", key_search_max_tries.to_string());
        }

        let output = cmd
            .output()
            .with_context(|| format!("failed to launch cargo bench for {}", bench.as_arg()))?;

        if output_format == OutputFormat::Raw {
            print_output(&output);
        }

        if !output.status.success() {
            if output_format != OutputFormat::Raw {
                print_output(&output);
            }
            bail!("benchmark failed for {label} ({})", bench.as_arg());
        }

        let combined = combine_output_text(&output);
        Ok(extract_summary_lines(&combined))
    }

    fn is_registered_worktree(&self, path: &Path) -> Result<bool> {
        let mut list_cmd = Command::new("git");
        list_cmd
            .current_dir(&self.repo_root)
            .arg("worktree")
            .arg("list")
            .arg("--porcelain");

        let output = list_cmd
            .output()
            .context("failed to list git worktrees for cache lookup")?;
        if !output.status.success() {
            bail!(
                "failed to list git worktrees for cache lookup: {}",
                combine_output_text(&output)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let needle = path.to_string_lossy();
        Ok(stdout
            .lines()
            .filter_map(|line| line.strip_prefix("worktree "))
            .any(|p| p == needle))
    }

    fn is_cached_worktree_path(&self, path: &Path) -> bool {
        path.starts_with(keep_worktrees_root(&self.repo_root))
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        if !self.keep_worktrees {
            for worktree in self.worktrees.drain(..) {
                let path = worktree.path;
                if !path.is_dir() {
                    continue;
                }

                log(&format!("Removing worktree: {}", path.display()));
                let mut cmd = Command::new("git");
                cmd.current_dir(&self.repo_root)
                    .arg("worktree")
                    .arg("remove")
                    .arg("--force")
                    .arg(&path);
                let _ = cmd.output();
            }
        }

        let mut prune_cmd = Command::new("git");
        prune_cmd
            .current_dir(&self.repo_root)
            .arg("worktree")
            .arg("prune")
            .arg("--expire")
            .arg("now");
        let _ = prune_cmd.output();
    }
}

pub(crate) fn cleanup_stale_marf_bench_worktrees(repo_root: &Path) -> Result<()> {
    let mut list_cmd = Command::new("git");
    list_cmd
        .current_dir(repo_root)
        .arg("worktree")
        .arg("list")
        .arg("--porcelain");

    let output = list_cmd
        .output()
        .context("failed to list git worktrees for cleanup")?;
    if !output.status.success() {
        bail!(
            "failed to list git worktrees for cleanup: {}",
            combine_output_text(&output)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stale_paths: Vec<PathBuf> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(PathBuf::from)
        .filter(|path| is_marf_bench_worktree_path(path, repo_root))
        .collect();

    for stale in stale_paths {
        log(&format!(
            "Removing stale marf-bench worktree: {}",
            stale.display()
        ));
        let mut remove_cmd = Command::new("git");
        remove_cmd
            .current_dir(repo_root)
            .arg("worktree")
            .arg("remove")
            .arg("--force")
            .arg(&stale);
        let _ = remove_cmd.output();
    }

    let mut prune_cmd = Command::new("git");
    prune_cmd
        .current_dir(repo_root)
        .arg("worktree")
        .arg("prune")
        .arg("--expire")
        .arg("now");
    let _ = prune_cmd.output();

    Ok(())
}

fn is_marf_bench_worktree_path(path: &Path, repo_root: &Path) -> bool {
    if path.starts_with(keep_worktrees_root(repo_root)) {
        return false;
    }

    let path_text = path.to_string_lossy();
    if path_text.contains("/.marf-bench-worktrees/") {
        return false;
    }

    let name_matches = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "worktree" || n.starts_with("worktree-") || n.starts_with("marf-bench-"))
        .unwrap_or(false);

    path_text.contains("/marf-bench-") && name_matches
}

fn keep_worktrees_root(repo_root: &Path) -> PathBuf {
    let repo_tag: String = sanitize_revision(&repo_root.to_string_lossy())
        .chars()
        .take(96)
        .collect();
    std::env::temp_dir()
        .join("marf-bench-worktrees")
        .join(repo_tag)
}

fn copy_if_different(src: &Path, dst: &Path) -> Result<bool> {
    let should_copy = if dst.is_file() {
        let src_bytes =
            fs::read(src).with_context(|| format!("failed to read {}", src.display()))?;
        let dst_bytes =
            fs::read(dst).with_context(|| format!("failed to read {}", dst.display()))?;
        src_bytes != dst_bytes
    } else {
        true
    };

    if !should_copy {
        return Ok(false);
    }

    fs::copy(src, dst)
        .with_context(|| format!("failed to copy {} -> {}", src.display(), dst.display()))?;
    Ok(true)
}
