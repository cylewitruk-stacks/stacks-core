#!/bin/bash
set -euo pipefail

# Shared Kubernetes evidence collectors. Logical actor names remain stable
# filenames while admitted Pod and PVC state is captured separately.

EVIDENCE_HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! declare -F backend_exec >/dev/null; then
  source "${EVIDENCE_HARNESS_DIR}/runtime-backend.sh"
fi

evidence_inventory() {
  local manifest="$1"
  EVIDENCE_ACTORS="$(node "${EVIDENCE_HARNESS_DIR}/manifest-inventory.mjs" "${manifest}" actors)"
  EVIDENCE_NODES="$(node "${EVIDENCE_HARNESS_DIR}/manifest-inventory.mjs" "${manifest}" nodes)"
  EVIDENCE_SIGNERS="$(node "${EVIDENCE_HARNESS_DIR}/manifest-inventory.mjs" "${manifest}" signers)"
  EVIDENCE_COMPANIONS="$(node "${EVIDENCE_HARNESS_DIR}/manifest-inventory.mjs" "${manifest}" companions)"
}

evidence_capture_node_info() {
  local destination="$1"
  local service endpoint path
  local probe_timeout="${ATTACKNET_PROBE_TIMEOUT_SECONDS:-10}"
  mkdir -p "${destination}"
  for service in ${EVIDENCE_NODES}; do
    for endpoint in info neighbors diagnostics; do
      case "${endpoint}" in
        info) path=/v2/info ;;
        neighbors) path=/v2/neighbors ;;
        diagnostics) path=/v3/network/diagnostics ;;
      esac
      if ! backend_exec_timeout "${probe_timeout}" "${service}" \
        curl --fail --silent "http://127.0.0.1:20443${path}" \
        >"${destination}/${service}-${endpoint}.json" \
        2>"${destination}/${service}-${endpoint}.stderr"; then
        printf '{"attacknetCaptureError":true,"actor":"%s","probe":"%s"}\n' \
          "${service}" "${endpoint}" >"${destination}/${service}-${endpoint}.json"
      fi
    done
  done
}

evidence_capture_metrics() {
  local destination="$1"
  local service
  local probe_timeout="${ATTACKNET_PROBE_TIMEOUT_SECONDS:-10}"
  mkdir -p "${destination}"
  for service in ${EVIDENCE_SIGNERS}; do
    backend_exec_timeout "${probe_timeout}" "${service}" curl --fail --silent http://127.0.0.1:31000/metrics \
      >"${destination}/${service}.txt" || printf '# attacknet_capture_error probe=signer_metrics\n' \
      >"${destination}/${service}.txt"
  done
  for service in ${EVIDENCE_NODES}; do
    backend_exec_timeout "${probe_timeout}" "${service}" curl --fail --silent http://127.0.0.1:20446/metrics \
      >"${destination}/${service}.txt" || printf '# attacknet_capture_error probe=node_metrics\n' \
      >"${destination}/${service}.txt"
  done
}

evidence_capture_logs() {
  local destination="$1"
  local since="${2:-}"
  local service
  mkdir -p "${destination}"
  for service in bitcoin bitcoin-miner stacker telemetry-collector prometheus observer ${EVIDENCE_ACTORS}; do
    backend_logs 20000 "${since}" "${service}" >"${destination}/${service}.log" 2>&1 || true
  done
}

evidence_capture_all() {
  local destination="$1"
  local manifest="$2"
  local since="${3:-}"
  local run_descriptor run_id
  mkdir -p "${destination}"
  evidence_inventory "${manifest}"
  cp "${manifest}" "${destination}/manifest.json"
  backend_runtime_description >"${destination}/runtime.json" || \
    printf '{"attacknetCaptureError":true,"probe":"runtime_description"}\n' \
      >"${destination}/runtime.json"
  evidence_capture_node_info "${destination}/node-info"
  evidence_capture_metrics "${destination}/metrics"
  evidence_capture_logs "${destination}/logs" "${since}"
  run_descriptor="$(node "${EVIDENCE_HARNESS_DIR}/run-ledger.mjs" locate \
    "--target=${manifest}" "--namespace=${KUBE_NAMESPACE:-hacknet-system}" \
    "--network=${KUBE_NETWORK:-attacknet}" 2>/dev/null || true)"
  if [ -r "${run_descriptor}" ]; then
    run_id="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1],"utf8")).run.id)' "${run_descriptor}")"
    node "${EVIDENCE_HARNESS_DIR}/run-ledger.mjs" export "${run_descriptor}" \
      "${destination}/run" >/dev/null || \
      printf '{"attacknetCaptureError":true,"probe":"run_ledger_export"}\n' \
        >"${destination}/run-ledger-error.json"
    KUBE_NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}" \
      KUBE_NETWORK="${KUBE_NETWORK:-attacknet}" ATTACKNET_RUN_ID="${run_id}" \
      "${EVIDENCE_HARNESS_DIR}/observability/record-actor-states.sh" capture || true
    KUBE_NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}" \
      KUBE_NETWORK="${KUBE_NETWORK:-attacknet}" ATTACKNET_RUN_ID="${run_id}" \
      "${EVIDENCE_HARNESS_DIR}/observability/export-kubernetes-report.sh" \
      "${destination}/timeline" "${run_id}" >/dev/null || \
      printf '{"attacknetCaptureError":true,"probe":"timeline_export"}\n' \
        >"${destination}/timeline-export-error.json"
  else
    printf '{"attacknetCaptureError":true,"probe":"run_ledger_missing"}\n' \
      >"${destination}/run-ledger-error.json"
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  [ "$#" -ge 2 ] || {
    echo "usage: $0 EVIDENCE_DIR MANIFEST [LOG_SINCE]" >&2
    exit 2
  }
  backend_require
  evidence_capture_all "$@"
fi
