#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
EVIDENCE_ROOT="${ATTACKNET_CAPACITY_EVIDENCE:-${ATTACKNET_DIR}/evidence/capacity-$(date -u +%Y%m%dT%H%M%SZ)}"
STAGES="${ATTACKNET_CAPACITY_STAGES:-1:1:1 2:4:2 3:10:5}"
NODE_IMAGE="${ATTACKNET_NODE_IMAGE:-stacks-core-attacknet:main}"
STACKER_IMAGE="${ATTACKNET_STACKER_IMAGE:-stacks-attacknet-stacker:local}"
KEEP_LAST="${ATTACKNET_KEEP_LAST:-1}"

mkdir -p "${EVIDENCE_ROOT}"
printf '%s\n' "${STAGES}" >"${EVIDENCE_ROOT}/stages.txt"
kubectl version -o json >"${EVIDENCE_ROOT}/kubernetes-version.json"
kubectl get nodes -o json >"${EVIDENCE_ROOT}/nodes.json"

stage_number=0
stage_total="$(wc -w <<<"${STAGES}" | tr -d ' ')"
for stage in ${STAGES}; do
  stage_number=$((stage_number + 1))
  IFS=: read -r miners signers followers <<<"${stage}"
  network="attacknet-capacity-${stage_number}"
  output="${EVIDENCE_ROOT}/stage-${stage_number}"
  mkdir -p "${output}"
  node "${ATTACKNET_DIR}/topology.mjs" \
    --network="${network}" --namespace="${NAMESPACE}" \
    --miners="${miners}" --signers="${signers}" --followers="${followers}" \
    --node-image="${NODE_IMAGE}" --stacker-image="${STACKER_IMAGE}" \
    --output="${output}/rendered"

  start="$(date +%s)"
  KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/lifecycle.sh" apply "${output}/rendered"
  end="$(date +%s)"
  duration=$((end - start))
  printf '{"stage":%s,"miners":%s,"signers":%s,"followers":%s,"readySeconds":%s}\n' \
    "${stage_number}" "${miners}" "${signers}" "${followers}" "${duration}" \
    >"${output}/result.json"

  KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/lifecycle.sh" capture "${output}/admitted"
  ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/verify.sh" "${output}/rendered/manifest.json" snapshot \
    >"${output}/verification.json"
  kubectl top pods -n "${NAMESPACE}" -l "testing.stacks.org/network=${network}" \
    >"${output}/pod-usage.txt" 2>&1 || true

  if [ "${stage_number}" -lt "${stage_total}" ] || [ "${KEEP_LAST}" != 1 ]; then
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/lifecycle.sh" delete
  fi
done

echo "Capacity evidence: ${EVIDENCE_ROOT}"
