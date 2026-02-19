use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::util::run_checked;

pub fn current_repo_root() -> Result<PathBuf> {
    let repo_root = git_capture_output(["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(repo_root.trim()))
}

pub fn verify_revision(repo_root: &Path, revision: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .arg("rev-parse")
        .arg("--verify")
        .arg(format!("{revision}^{{commit}}"));

    run_checked(cmd, &format!("invalid revision: {revision}"))
}

pub fn resolve_base_revision(repo_root: &Path, base: &str) -> Result<(String, String)> {
    if base.eq_ignore_ascii_case("staged") {
        let commit = create_staged_snapshot_commit(repo_root)?;
        return Ok((commit, "staged".to_string()));
    }

    verify_revision(repo_root, base)?;
    Ok((base.to_string(), base.to_string()))
}

fn create_staged_snapshot_commit(repo_root: &Path) -> Result<String> {
    let tree = git_capture_output_in(repo_root, ["write-tree"])?;
    let tree = tree.trim().to_string();

    let head = git_capture_output_in(repo_root, ["rev-parse", "--verify", "HEAD^{commit}"])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .arg("commit-tree")
        .arg(&tree)
        .arg("-m")
        .arg("marf-bench staged snapshot");
    if let Some(head) = head {
        cmd.arg("-p").arg(head);
    }

    let out = cmd
        .output()
        .context("failed to create staged snapshot commit")?;
    if !out.status.success() {
        bail!(
            "failed to create staged snapshot commit: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let commit = String::from_utf8(out.stdout)
        .map_err(|err| anyhow!(err))?
        .trim()
        .to_string();
    if commit.is_empty() {
        bail!("failed to create staged snapshot commit: empty commit hash");
    }
    Ok(commit)
}

fn git_capture_output<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("git");
    cmd.args(args);

    let out = cmd.output().context("failed to run git command")?;
    if !out.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    String::from_utf8(out.stdout).map_err(|err| anyhow!(err))
}

fn git_capture_output_in<I, S>(repo_root: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root).args(args);

    let out = cmd.output().context("failed to run git command")?;
    if !out.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    String::from_utf8(out.stdout).map_err(|err| anyhow!(err))
}
