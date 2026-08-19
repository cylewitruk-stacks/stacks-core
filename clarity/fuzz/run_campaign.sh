#!/usr/bin/env bash
# Qualification gate for the packed value codec fuzz target.
set -euo pipefail

cd "$(dirname "$0")" || exit 1
export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER=""

readonly WORKERS="${WORKERS:-12}"
readonly SECONDS_TOTAL="${SECONDS_TOTAL:-3600}"
readonly MIN_EXECUTIONS="${MIN_EXECUTIONS:-25000000}"
readonly TARGET=packed_value_codec
readonly CORPUS="corpus/$TARGET"
readonly SEEDS="seed_corpus/$TARGET"
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly ARTIFACTS="artifacts/$TARGET/qualification/$RUN_ID"
readonly LOGDIR="runlogs/$TARGET/$RUN_ID"

mkdir -p "$CORPUS" "$ARTIFACTS" "$LOGDIR"
for stale_log in fuzz-*.log; do
    [ -f "$stale_log" ] || continue
    echo "FAIL: refusing to overwrite unarchived worker log $stale_log" >&2
    exit 1
done

# Curated findings are text-encoded for review. The target decodes their
# `hex:` prefix, so copying them into the generated corpus preserves both the
# reviewable source fixtures and cargo-fuzz's ordinary single-corpus workflow.
for seed in "$SEEDS"/*; do
    [ -f "$seed" ] || continue
    cp "$seed" "$CORPUS/seed-$(basename "$seed")"
done

echo "campaign start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "run id: $RUN_ID"
echo "artifact directory: $ARTIFACTS"
echo "worker-log directory: $LOGDIR"
STARTED_AT=$(date +%s)

if cargo +nightly fuzz run "$TARGET" "$CORPUS" -- \
    -max_total_time="$SECONDS_TOTAL" \
    -workers="$WORKERS" \
    -jobs="$WORKERS" \
    -timeout=25 \
    -rss_limit_mb=4096 \
    -artifact_prefix="$ARTIFACTS/" \
    -print_final_stats=1
then
    STATUS=0
else
    STATUS=$?
fi
FINISHED_AT=$(date +%s)
ELAPSED=$((FINISHED_AT - STARTED_AT))

echo "campaign end: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "cargo-fuzz exit status: $STATUS"
# Diagnostic only: qualification uses each worker's libFuzzer-reported time.
echo "wall elapsed seconds (includes build): $ELAPSED"

for log in fuzz-*.log; do
    [ -f "$log" ] || continue
    mv "$log" "$LOGDIR"/
done

echo "=== per-worker totals ==="
TOTAL=0
WORKER_LOGS=0
MIN_WORKER_SECONDS=""
for f in "$LOGDIR"/fuzz-*.log; do
    [ -f "$f" ] || continue
    WORKER_LOGS=$((WORKER_LOGS + 1))
    summary=$(grep -E '^Done [0-9]+ runs in [0-9]+ second' "$f" | tail -1 || true)
    if [ -n "$summary" ]; then
        runs=$(printf '%s\n' "$summary" | awk '{print $2}')
        worker_seconds=$(printf '%s\n' "$summary" | awk '{print $5}')
    else
        runs=$(grep -oE '^#[0-9]+' "$f" | tr -d '#' | tail -1 || true)
        runs=${runs:-0}
        worker_seconds=0
    fi
    if [ -z "$MIN_WORKER_SECONDS" ] || [ "$worker_seconds" -lt "$MIN_WORKER_SECONDS" ]; then
        MIN_WORKER_SECONDS=$worker_seconds
    fi
    echo "$f: $runs runs in $worker_seconds seconds"
    TOTAL=$((TOTAL + runs))
done
MIN_WORKER_SECONDS=${MIN_WORKER_SECONDS:-0}
echo "WORKER_LOGS=$WORKER_LOGS"
echo "MIN_WORKER_SECONDS=$MIN_WORKER_SECONDS"
echo "TOTAL_EXECUTIONS=$TOTAL"

echo "=== crash / oom / timeout artifacts ==="
ARTIFACT_COUNT=0
for artifact in "$ARTIFACTS"/*; do
    [ -f "$artifact" ] || continue
    echo "$artifact"
    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
done

echo "=== failure markers in logs ==="
FAILURE_LOGS=$(grep -lE 'ERROR: libFuzzer|SUMMARY: |panicked at|deadly signal' "$LOGDIR"/fuzz-*.log 2>/dev/null || true)
if [ -n "$FAILURE_LOGS" ]; then
    echo "$FAILURE_LOGS"
else
    echo "(none)"
fi

echo "=== final corpus size ==="
CORPUS_COUNT=0
for input in "$CORPUS"/*; do
    [ -f "$input" ] || continue
    CORPUS_COUNT=$((CORPUS_COUNT + 1))
done
echo "$CORPUS_COUNT"

FAILED=0
if [ "$STATUS" -ne 0 ]; then
    echo "FAIL: cargo-fuzz exited with status $STATUS" >&2
    FAILED=1
fi
if [ "$WORKER_LOGS" -ne "$WORKERS" ]; then
    echo "FAIL: campaign produced $WORKER_LOGS worker logs; expected $WORKERS" >&2
    FAILED=1
fi
if [ "$MIN_WORKER_SECONDS" -lt "$SECONDS_TOTAL" ]; then
    echo "FAIL: shortest worker ran for $MIN_WORKER_SECONDS seconds; required $SECONDS_TOTAL" >&2
    FAILED=1
fi
if [ "$TOTAL" -lt "$MIN_EXECUTIONS" ]; then
    echo "FAIL: campaign executed $TOTAL inputs; required $MIN_EXECUTIONS" >&2
    FAILED=1
fi
if [ "$ARTIFACT_COUNT" -ne 0 ]; then
    echo "FAIL: campaign produced $ARTIFACT_COUNT artifact(s)" >&2
    FAILED=1
fi
if [ -n "$FAILURE_LOGS" ]; then
    echo "FAIL: campaign logs contain sanitizer, panic, or fatal-signal markers" >&2
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "PASS: packed value codec qualification gate satisfied"
