#!/usr/bin/env bash
#
# Extract the parts of a large stacks-node log that are usually useful for
# chainstate / MARF-squash investigations.
#
# The default output keeps:
#   - state-root mismatches and block rejections
#   - MARF/squash lifecycle, recovery, and corruption lines
#   - block receive / processing order
#   - sortition consensus and winning commits
#   - microblock batch / invalid microblock markers
#   - "Advanced to new tip" progression
#
# Usage:
#   contrib/tools/clean-stacks-log.sh /path/to/stacks.log > clean.log
#   contrib/tools/clean-stacks-log.sh --line 619774 --context 250 stacks.log > window.log
#   contrib/tools/clean-stacks-log.sh --with-order --line 619774 stacks.log > order.log
#   contrib/tools/clean-stacks-log.sh --hash ce9bdf... stacks.log > related.log

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  clean-stacks-log.sh [options] LOGFILE

Options:
  --line N         Include a raw context window around line N.
  --context N      Context lines before/after --line. Default: 200.
  --hash HASH      Also keep lines containing HASH. May be passed more than once.
  --with-order     Include broad block receive / sortition chronology.
  --no-defaults    Only emit requested --line/--hash matches.
  -h, --help       Show this help.

Examples:
  clean-stacks-log.sh /Volumes/Extern/marf-squash/stacks.log > clean.log
  clean-stacks-log.sh --line 619774 --context 300 stacks.log > focused.log
  clean-stacks-log.sh --with-order --line 619774 stacks.log > order.log
  clean-stacks-log.sh --hash ce9bdf3e --hash 9d18548e stacks.log > block.log
USAGE
}

context=200
target_line=""
use_defaults=1
with_order=0
hashes=()
logfile=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --line)
      [[ $# -ge 2 ]] || { echo "error: --line requires a value" >&2; exit 2; }
      target_line="$2"
      shift 2
      ;;
    --context)
      [[ $# -ge 2 ]] || { echo "error: --context requires a value" >&2; exit 2; }
      context="$2"
      shift 2
      ;;
    --hash)
      [[ $# -ge 2 ]] || { echo "error: --hash requires a value" >&2; exit 2; }
      hashes+=("$2")
      shift 2
      ;;
    --with-order)
      with_order=1
      shift
      ;;
    --no-defaults)
      use_defaults=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      if [[ -n "$logfile" ]]; then
        echo "error: multiple log files supplied: $logfile and $1" >&2
        exit 2
      fi
      logfile="$1"
      shift
      ;;
  esac
done

[[ -n "$logfile" ]] || { usage; exit 2; }
[[ -r "$logfile" ]] || { echo "error: cannot read log file: $logfile" >&2; exit 1; }
[[ "$context" =~ ^[0-9]+$ ]] || { echo "error: --context must be an integer" >&2; exit 2; }
if [[ -n "$target_line" && ! "$target_line" =~ ^[0-9]+$ ]]; then
  echo "error: --line must be an integer" >&2
  exit 2
fi

# Keep this list high-signal by default. It preserves failure causes, squash
# lifecycle, accepted-tip progression, and batch/microblock markers without
# dumping all burn commits or every inbound block.
default_pattern='state root mismatch|Reject block|Encountered invalid block|Unrecoverable error when processing blocks|Unexpected MARF failure|SnapshotTrimmed|CorruptionError|read_node_with_state failed|FATAL:|panic|Panic backtrace|maybe_squash|Auto-squash|squash|Squash|promotion|prepare worker finished|prepare complete|publish|Published|DiscardedStale|recovery|recover|trim_aged_root_sidecars|Advanced to new tip|Processing newly received Stacks blocks|confirmed microblocks|Invalid Stacks microblocks|Encountered invalid microblock|Parent microblock stream|PoX Anchor block selected|missing PoX anchor|Burnchain block processing stops|Atlas: New attachment'

# Optional chronology mode. Useful near a failure, noisy for whole-log summaries.
order_pattern='Handle incoming block|Handle incoming Nakamoto block|SORTITION\(|WINNER SELECTED|ACCEPTED\(|CONSENSUS\('

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/clean-stacks-log.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

emit_matches() {
  local label="$1"
  local pattern="$2"

  if command -v rg >/dev/null 2>&1; then
    rg -n --no-heading "$pattern" "$logfile" > "$tmp_dir/$label" || true
  else
    grep -nE "$pattern" "$logfile" > "$tmp_dir/$label" || true
  fi
}

if [[ "$use_defaults" -eq 1 ]]; then
  emit_matches defaults "$default_pattern"
else
  : > "$tmp_dir/defaults"
fi

if [[ "$with_order" -eq 1 ]]; then
  emit_matches order "$order_pattern"
else
  : > "$tmp_dir/order"
fi

if [[ "${#hashes[@]}" -gt 0 ]]; then
  : > "$tmp_dir/hashes"
  for hash in "${hashes[@]}"; do
    # Treat hashes as literal strings, not regexes.
    if command -v rg >/dev/null 2>&1; then
      rg -n --no-heading -F "$hash" "$logfile" >> "$tmp_dir/hashes" || true
    else
      grep -nF "$hash" "$logfile" >> "$tmp_dir/hashes" || true
    fi
  done
else
  : > "$tmp_dir/hashes"
fi

if [[ -n "$target_line" ]]; then
  start=$(( target_line > context ? target_line - context : 1 ))
  end=$(( target_line + context ))
  sed -n "${start},${end}p" "$logfile" \
    | awk -v start="$start" '{ print (start + NR - 1) ":" $0 }' \
    > "$tmp_dir/window"
else
  : > "$tmp_dir/window"
fi

{
  printf '# clean-stacks-log source=%s\n' "$logfile"
  if [[ -n "$target_line" ]]; then
    printf '# context_window line=%s context=%s\n' "$target_line" "$context"
  fi
  if [[ "${#hashes[@]}" -gt 0 ]]; then
    printf '# hashes=%s\n' "${hashes[*]}"
  fi
  if [[ "$with_order" -eq 1 ]]; then
    printf '# with_order=1\n'
  fi
  cat "$tmp_dir/defaults" "$tmp_dir/order" "$tmp_dir/hashes" "$tmp_dir/window" \
    | sort -t ':' -k1,1n -u
} 
