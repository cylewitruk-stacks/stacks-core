#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ATTACKNET_DIR}/runtime-backend.sh"

manifest="${1:?manifest path required}"
action="${2:-snapshot}"
backend_require
evidence_actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" actors)"
evidence_nodes="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" nodes)"
probe_timeout="${ATTACKNET_PROBE_TIMEOUT_SECONDS:-10}"
progress_window="$(node "${ATTACKNET_DIR}/progress-window.mjs" \
  "${manifest}" "${ATTACKNET_PROGRESS_WINDOW_SECONDS:-}")"

unready="$(backend_unready_actors bitcoin bitcoin-miner stacker ${evidence_actors})"
if [ -n "${unready}" ]; then
  echo "Unready actors: ${unready}" >&2
  exit 1
fi

capture_cohort() {
  local output="$1" actor first=true info neighbors
  printf '[' >"${output}"
  for actor in ${evidence_nodes}; do
    if ! info="$(backend_exec_timeout "${probe_timeout}" "${actor}" \
      curl --fail --silent http://127.0.0.1:20443/v2/info)"; then
      echo "${actor} /v2/info probe failed within ${probe_timeout}s" >&2
      return 1
    fi
    if ! neighbors="$(backend_exec_timeout "${probe_timeout}" "${actor}" \
      curl --fail --silent http://127.0.0.1:20443/v2/neighbors)"; then
      echo "${actor} /v2/neighbors probe failed within ${probe_timeout}s" >&2
      return 1
    fi
    if [ "${first}" = true ]; then first=false; else printf ',' >>"${output}"; fi
    ACTOR="${actor}" INFO="${info}" NEIGHBORS="${neighbors}" node -e '
      process.stdout.write(JSON.stringify({
        actor: process.env.ACTOR,
        info: JSON.parse(process.env.INFO),
        neighbors: JSON.parse(process.env.NEIGHBORS),
      }));
    ' >>"${output}"
  done
  printf ']\n' >>"${output}"
}

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
capture_cohort "${temporary}/cohort.json"
cohort_status=0
node "${ATTACKNET_DIR}/invariants.mjs" cohort "${temporary}/cohort.json" \
  "${ATTACKNET_HEIGHT_DRIFT_CEILING:-2}" "${ATTACKNET_MINIMUM_STACKS_HEIGHT:-1}" \
  >"${temporary}/cohort-result.json" || cohort_status=$?

case "${action}" in
  snapshot)
    cat "${temporary}/cohort-result.json"
    exit "${cohort_status}"
    ;;
  progress)
    start="$(backend_exec_timeout "${probe_timeout}" bitcoin bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount)"
    sleep "${progress_window}"
    end="$(backend_exec_timeout "${probe_timeout}" bitcoin bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount)"
    capture_cohort "${temporary}/end-cohort.json"
    end_cohort_status=0
    node "${ATTACKNET_DIR}/invariants.mjs" cohort "${temporary}/end-cohort.json" \
      "${ATTACKNET_HEIGHT_DRIFT_CEILING:-2}" "${ATTACKNET_MINIMUM_STACKS_HEIGHT:-1}" \
      >"${temporary}/end-cohort-result.json" || end_cohort_status=$?
    START_BURN="${start}" END_BURN="${end}" node -e '
      const fs = require("node:fs");
      process.stdout.write(`${JSON.stringify({
        start: {
          burnHeight: Number(process.env.START_BURN),
          cohort: JSON.parse(fs.readFileSync(process.argv[1], "utf8")),
        },
        end: {
          burnHeight: Number(process.env.END_BURN),
          cohort: JSON.parse(fs.readFileSync(process.argv[2], "utf8")),
        },
      })}\n`);
    ' "${temporary}/cohort.json" "${temporary}/end-cohort.json" >"${temporary}/progress.json"
    progress_status=0
    node "${ATTACKNET_DIR}/invariants.mjs" progress "${temporary}/progress.json" \
      "${ATTACKNET_MINIMUM_PROGRESS_BLOCKS:-1}" "${ATTACKNET_MINIMUM_STACKS_PROGRESS_BLOCKS:-1}" \
      >"${temporary}/progress-result.json" || progress_status=$?
    node -e '
      const fs = require("node:fs");
      const startCohort = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const cohort = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
      const progress = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
      process.stdout.write(`${JSON.stringify({
        ok: startCohort.ok && cohort.ok && progress.ok,
        startCohort,
        cohort,
        progress,
      }, null, 2)}\n`);
    ' "${temporary}/cohort-result.json" "${temporary}/end-cohort-result.json" \
      "${temporary}/progress-result.json"
    if [ "${cohort_status}" -ne 0 ] || [ "${end_cohort_status}" -ne 0 ] \
      || [ "${progress_status}" -ne 0 ]; then
      exit 1
    fi
    ;;
  *) echo "usage: $0 MANIFEST {snapshot|progress}" >&2; exit 2 ;;
esac
