#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ATTACKNET_DIR}/runtime-backend.sh"

manifest="${1:?manifest path required}"
action="${2:-snapshot}"
backend_require
evidence_actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" actors)"
evidence_nodes="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" nodes)"

unready="$(backend_unready_actors bitcoin bitcoin-miner stacker ${evidence_actors})"
if [ -n "${unready}" ]; then
  echo "Unready actors: ${unready}" >&2
  exit 1
fi

capture_cohort() {
  local output="$1" actor first=true info
  printf '[' >"${output}"
  for actor in ${evidence_nodes}; do
    info="$(backend_exec "${actor}" curl --fail --silent http://127.0.0.1:20443/v2/info)"
    if [ "${first}" = true ]; then first=false; else printf ',' >>"${output}"; fi
    ACTOR="${actor}" INFO="${info}" node -e '
      process.stdout.write(JSON.stringify({actor: process.env.ACTOR, info: JSON.parse(process.env.INFO)}));
    ' >>"${output}"
  done
  printf ']\n' >>"${output}"
}

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
capture_cohort "${temporary}/cohort.json"
node "${ATTACKNET_DIR}/invariants.mjs" cohort "${temporary}/cohort.json" "${ATTACKNET_HEIGHT_DRIFT_CEILING:-2}"

case "${action}" in
  snapshot) ;;
  progress)
    start="$(backend_exec bitcoin bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount)"
    sleep "${ATTACKNET_PROGRESS_WINDOW_SECONDS:-45}"
    end="$(backend_exec bitcoin bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount)"
    printf '{"start":{"burnHeight":%s},"end":{"burnHeight":%s}}\n' "${start}" "${end}" \
      >"${temporary}/progress.json"
    node "${ATTACKNET_DIR}/invariants.mjs" progress "${temporary}/progress.json" \
      "${ATTACKNET_MINIMUM_PROGRESS_BLOCKS:-1}"
    ;;
  *) echo "usage: $0 MANIFEST {snapshot|progress}" >&2; exit 2 ;;
esac
