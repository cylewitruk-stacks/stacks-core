#!/bin/bash
set -euo pipefail

OBSERVABILITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
result="${1:?verification result JSON required}"
scope="${2:-verification}"
phase="${3:-verification}"

[ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" != 0 ] || exit 0

[ -r "${result}" ] || { echo "verification result is not readable: ${result}" >&2; exit 2; }

while IFS= read -r details; do
  passed="$(DETAILS="${details}" node -e 'console.log(JSON.parse(process.env.DETAILS).passed)')"
  KUBE_NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}" \
    KUBE_NETWORK="${KUBE_NETWORK:-attacknet}" \
    ATTACKNET_RUN_ID="${ATTACKNET_RUN_ID:-}" \
    "${OBSERVABILITY_DIR}/record-event.sh" \
      --kind=invariant.observed "--phase=${phase}" \
      "--outcome=$([ "${passed}" = true ] && echo pass || echo fail)" \
      "--details=${details}" >/dev/null
done < <(node "${OBSERVABILITY_DIR}/verification-events.mjs" "${result}" "${scope}")
