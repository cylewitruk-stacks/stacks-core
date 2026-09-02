#!/bin/bash
set -euo pipefail

OBSERVABILITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
phase="${1:-baseline}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
[ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" != 0 ] || exit 0
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

${kubectl_bin} -n "${namespace}" get pods \
  -l "testing.stacks.org/network=${network},testing.stacks.org/actor" \
  -o json >"${temporary}/pods.json"
while IFS= read -r observation; do
  read -r actor role details < <(OBSERVATION="${observation}" node -e '
    const event=JSON.parse(process.env.OBSERVATION);
    console.log(event.actor, event.role, Buffer.from(JSON.stringify(event.details)).toString("base64"));
  ')
  details="$(printf '%s' "${details}" | base64 --decode)"
  KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
    ATTACKNET_RUN_ID="${ATTACKNET_RUN_ID:-}" \
    "${OBSERVABILITY_DIR}/record-event.sh" \
      --kind=actor.state "--phase=${phase}" "--actor=${actor}" "--role=${role}" \
      "--details=${details}" >/dev/null
done < <(node "${OBSERVABILITY_DIR}/actor-states.mjs" "${temporary}/pods.json")
