#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
destination="${1:?usage: $0 DESTINATION START_RFC3339_OR_NS [END_RFC3339_OR_NS]}"
start="${2:?start timestamp is required}"
end="${3:-$(date -u +%FT%TZ)}"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
selector="app.kubernetes.io/name=attacknet-loki,testing.stacks.org/network=${network}"
mkdir -p "${destination}"

if [ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" = 0 ]; then
  printf '{"schemaVersion":"stacks-attacknet-loki-export/v1","complete":true,"source":"disabled-by-configuration","entryCount":0}\n' >"${destination}/export.json"
  : >"${destination}/logs.jsonl"
  exit 0
fi

services="$("${kubectl_bin}" -n "${namespace}" get services -l "${selector}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
count="$(grep -c . <<<"${services}" || true)"
[ "${count}" -eq 1 ] || { echo "expected exactly one Loki Service for ${network}; found ${count}" >&2; exit 1; }
service="${services}"
forward_log="$(mktemp)"
forward_pid=''
cleanup() {
  if [ -n "${forward_pid}" ]; then kill "${forward_pid}" 2>/dev/null || true; wait "${forward_pid}" 2>/dev/null || true; fi
  rm -f "${forward_log}"
}
trap cleanup EXIT INT TERM
"${kubectl_bin}" -n "${namespace}" port-forward "service/${service}" :3100 --address=127.0.0.1 >"${forward_log}" 2>&1 &
forward_pid=$!
port=''
for _ in $(seq 1 100); do
  port="$(sed -nE 's/^Forwarding from 127\.0\.0\.1:([0-9]+) -> 3100$/\1/p' "${forward_log}" | tail -1)"
  [ -n "${port}" ] && break
  kill -0 "${forward_pid}" 2>/dev/null || { cat "${forward_log}" >&2; exit 1; }
  sleep 0.1
done
[ -n "${port}" ] || { echo 'Loki port-forward did not become ready' >&2; cat "${forward_log}" >&2; exit 1; }

"${kubectl_bin}" -n "${namespace}" get configmaps,statefulsets,services,pods \
  -l "${selector}" -o json >"${destination}/kubernetes-source.json"
node "${root}/export-loki.mjs" \
  "--endpoint=http://127.0.0.1:${port}" "--network=${network}" \
  "--start=${start}" "--end=${end}" \
  "--limit=${ATTACKNET_LOKI_EXPORT_PAGE_LIMIT:-5000}" \
  "--max-pages=${ATTACKNET_LOKI_EXPORT_MAX_PAGES:-1000}" \
  "--destination=${destination}"
uncompressed_bytes="$(wc -c <"${destination}/logs.jsonl" | tr -d ' ')"
gzip -f "${destination}/logs.jsonl"
compressed_bytes="$(wc -c <"${destination}/logs.jsonl.gz" | tr -d ' ')"
jq --argjson uncompressedBytes "${uncompressed_bytes}" --argjson compressedBytes "${compressed_bytes}" \
  '.logArtifact="logs.jsonl.gz" | .compression="gzip" | .uncompressedBytes=$uncompressedBytes | .compressedBytes=$compressedBytes' \
  "${destination}/export.json" >"${destination}/export.json.tmp"
mv "${destination}/export.json.tmp" "${destination}/export.json"
(cd "${destination}" && find . -type f ! -name digests.sha256 -print0 | sort -z | xargs -0 shasum -a 256) >"${destination}/digests.sha256"
