#!/bin/bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
NETWORK="${KUBE_NETWORK:-attacknet}"
export POC_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}"
source "${POC_DIR}/runtime-backend.sh"
FAST_UNTIL="${BURNCHAIN_FAST_UNTIL_HEIGHT:-222}"
FAST_INTERVAL="${BURNCHAIN_FAST_INTERVAL_SECONDS:-5}"
STEADY_INTERVAL="${BURNCHAIN_STEADY_INTERVAL_SECONDS:-20}"
STEADY_JITTER="${BURNCHAIN_STEADY_JITTER_SECONDS:-0}"

restore_steady() {
  KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
    "${POC_DIR}/hacknet-burnchain-policy.sh" run "${STEADY_INTERVAL}" "${STEADY_JITTER}" \
    >/dev/null 2>&1 || true
}
trap restore_steady EXIT INT TERM

KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
  "${POC_DIR}/hacknet-burnchain-policy.sh" run "${FAST_INTERVAL}" 0

while true; do
  height="$(backend_exec bitcoin \
    bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount 2>/dev/null || true)"
  if [[ "${height}" =~ ^[0-9]+$ ]] && [ "${height}" -ge "${FAST_UNTIL}" ]; then break; fi
  sleep 2
done

restore_steady
trap - EXIT INT TERM
echo "Burnchain baseline profile reached ${height}; steady cadence is ${STEADY_INTERVAL}s + [0,${STEADY_JITTER}]s"
