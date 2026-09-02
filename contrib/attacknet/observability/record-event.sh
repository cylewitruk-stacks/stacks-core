#!/bin/bash
set -euo pipefail

OBSERVABILITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
run_id="${ATTACKNET_RUN_ID:-}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"

[ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" != 0 ] || exit 0

if [ -z "${run_id}" ]; then
  # lifecycle.sh persists the canonical run identity so independently invoked
  # policy, campaign, assertion, and capture commands attribute observations to
  # the same run without distributing the journal writer credential.
  run_id="$(${kubectl_bin} -n "${namespace}" get configmap "${network}-run-context" \
    -o 'go-template={{index .data "run-id"}}' 2>/dev/null || true)"
fi
if [ -z "${run_id}" ]; then
  echo "ATTACKNET_RUN_ID is unset and ${network}-run-context has no run-id" >&2
  exit 2
fi
if [ "$#" -eq 0 ]; then
  echo "usage: ATTACKNET_RUN_ID=ID $0 --kind=KIND [event options]" >&2
  exit 2
fi

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
event="${temporary}/event.json"

# Put the trusted execution context first. event.mjs selects the first value
# for an option, so a caller cannot override the network or run identity by
# smuggling duplicate arguments into a campaign or assertion payload.
node "${OBSERVABILITY_DIR}/event.mjs" \
  "--network=${network}" "--run-id=${run_id}" "$@" >"${event}"
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${OBSERVABILITY_DIR}/emit-kubernetes-event.sh" "${event}"
