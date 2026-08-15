#!/bin/bash
set -euo pipefail

# Kubernetes may continue reporting DiskPressure=False after the underlying
# filesystem has no allocatable bytes. Query kubelet's stats summary directly
# so the observability stack cannot turn a pre-existing full disk into a noisy,
# misleading set of CrashLoopBackOff failures.

KUBECTL="${ATTACKNET_KUBECTL:-kubectl}"
MIN_FREE_BYTES="${ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES:-2147483648}"
ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  echo "usage: $0 [OUTPUT.json]" >&2
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -*) usage; echo "unknown option: $1" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { usage; exit 2; }
OUTPUT="${1:-}"

[[ "${MIN_FREE_BYTES}" =~ ^[0-9]+$ ]] || {
  echo "ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES must be a non-negative integer" >&2
  exit 2
}

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
nodes_file="${temporary}/nodes"
results_file="${temporary}/results.jsonl"
evaluation_file="${temporary}/evaluation.json"

"${KUBECTL}" get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' >"${nodes_file}"
if [ ! -s "${nodes_file}" ]; then
  echo "storage preflight found no Kubernetes nodes" >&2
  exit 1
fi

summaries=()
while IFS= read -r node; do
  [ -n "${node}" ] || continue
  summary="${temporary}/${node}.json"
  if ! "${KUBECTL}" get --raw "/api/v1/nodes/${node}/proxy/stats/summary" >"${summary}"; then
    jq -cn --arg node "${node}" '{node:$node,ok:false,error:"kubelet-stats-unavailable"}' >>"${results_file}"
    continue
  fi
  summaries+=("${summary}")
done <"${nodes_file}"

status=0
if [ -s "${results_file}" ]; then
  jq -cs \
    --argjson minimumAvailableBytes "${MIN_FREE_BYTES}" \
    '{ok:false,minimumAvailableBytes:$minimumAvailableBytes,nodes:.,error:"one-or-more-kubelet-summaries-unavailable"}' \
    "${results_file}" >"${evaluation_file}"
  status=1
elif ! node "${ATTACKNET_DIR}/node-capacity.mjs" "${MIN_FREE_BYTES}" \
  "${summaries[@]}" >"${evaluation_file}"; then
  status=1
fi

report="$(jq -cn \
  --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile evaluation "${evaluation_file}" \
  '{schemaVersion:1,observedAt:$observedAt,source:"kubelet-stats-summary"} + $evaluation[0]')"

if [ -n "${OUTPUT}" ]; then
  mkdir -p "$(dirname "${OUTPUT}")"
  printf '%s\n' "${report}" >"${OUTPUT}"
fi
printf '%s\n' "${report}"

if [ "${status}" -ne 0 ]; then
  echo "observability storage preflight failed: node stats are unavailable/incomplete or a filesystem has less than ${MIN_FREE_BYTES} free bytes" >&2
  exit 1
fi
