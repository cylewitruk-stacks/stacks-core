#!/bin/bash

# Shared evidence collectors. The payloads are deliberately backend-neutral:
# logical actor names are filenames, while runtime-specific admitted state is
# captured separately by runtime-backend.sh describe.

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
  local service
  mkdir -p "${destination}"
  for service in ${EVIDENCE_NODES}; do
    backend_exec "${service}" curl --fail --silent http://127.0.0.1:20443/v2/info \
      >"${destination}/${service}.json"
  done
}

evidence_capture_metrics() {
  local destination="$1"
  local service
  mkdir -p "${destination}"
  for service in ${EVIDENCE_SIGNERS}; do
    backend_exec "${service}" curl --fail --silent http://127.0.0.1:31000/metrics \
      >"${destination}/${service}.txt" || true
  done
  for service in ${EVIDENCE_COMPANIONS}; do
    backend_exec "${service}" curl --fail --silent http://127.0.0.1:20446/metrics \
      >"${destination}/${service}.txt" || true
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
  mkdir -p "${destination}"
  evidence_inventory "${manifest}"
  cp "${manifest}" "${destination}/manifest.json"
  backend_runtime_description >"${destination}/runtime.json"
  evidence_capture_node_info "${destination}/node-info"
  evidence_capture_metrics "${destination}/metrics"
  evidence_capture_logs "${destination}/logs" "${since}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  [ "$#" -ge 2 ] || {
    echo "usage: $0 EVIDENCE_DIR MANIFEST [LOG_SINCE]" >&2
    exit 2
  }
  backend_require
  evidence_capture_all "$@"
fi
