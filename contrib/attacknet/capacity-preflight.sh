#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
EVIDENCE_ROOT="${ATTACKNET_CAPACITY_EVIDENCE:-${ATTACKNET_DIR}/evidence/capacity-$(date -u +%Y%m%dT%H%M%SZ)}"
STAGES="${ATTACKNET_CAPACITY_STAGES:-1:1:1 2:4:2 3:10:5}"
NODE_IMAGE="${ATTACKNET_NODE_IMAGE:-stacks-core-attacknet:main}"
STACKER_IMAGE="${ATTACKNET_STACKER_IMAGE:-stacks-attacknet-stacker:local}"
PROBES="${ATTACKNET_PROBES:-true}"
PROBE_IMAGE="${ATTACKNET_PROBE_IMAGE:-stacks-hacknet-probe:dev}"
KEEP_LAST="${ATTACKNET_KEEP_LAST:-1}"
MINIMUM_NODE_AVAILABLE_BYTES="${ATTACKNET_MINIMUM_NODE_AVAILABLE_BYTES:-8589934592}"
STAGE_CONVERGENCE_TIMEOUT_SECONDS="${ATTACKNET_STAGE_CONVERGENCE_TIMEOUT_SECONDS:-180}"

mkdir -p "${EVIDENCE_ROOT}"
printf '%s\n' "${STAGES}" >"${EVIDENCE_ROOT}/stages.txt"
kubectl version -o json >"${EVIDENCE_ROOT}/kubernetes-version.json"
kubectl get nodes -o json >"${EVIDENCE_ROOT}/nodes.json"
node_summaries=()
while IFS= read -r node_name; do
  summary="${EVIDENCE_ROOT}/node-${node_name}-stats-summary.json"
  kubectl get --raw "/api/v1/nodes/${node_name}/proxy/stats/summary" >"${summary}"
  node_summaries+=("${summary}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
node "${ATTACKNET_DIR}/node-capacity.mjs" "${MINIMUM_NODE_AVAILABLE_BYTES}" \
  "${node_summaries[@]}" >"${EVIDENCE_ROOT}/node-capacity.json"

stage_number=0
stage_total="$(wc -w <<<"${STAGES}" | tr -d ' ')"

capture_operator_metrics() {
  local output="$1" service
  service="$(kubectl -n "${NAMESPACE}" get services \
    -l 'app.kubernetes.io/component=operator' -o json \
    | jq -er 'if (.items | length) == 1 then .items[0].metadata.name else error("expected exactly one Hacknet operator metrics Service") end')"
  kubectl get --raw "/api/v1/namespaces/${NAMESPACE}/services/http:${service}:8080/proxy/metrics" \
    >"${output}"
}

wait_for_stage_convergence() {
  local network="$1" manifest="$2" output="$3"
  local deadline=$((SECONDS + STAGE_CONVERGENCE_TIMEOUT_SECONDS)) attempt=0
  mkdir -p "${output}/verification-attempts"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    attempt=$((attempt + 1))
    if ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/verify.sh" "${manifest}" progress \
      >"${output}/verification-attempts/${attempt}.json" \
      2>"${output}/verification-attempts/${attempt}.stderr"; then
      cp "${output}/verification-attempts/${attempt}.json" "${output}/verification.json"
      printf '{"attempts":%s,"converged":true}\n' "${attempt}" \
        >"${output}/convergence.json"
      return 0
    fi
    sleep 5
  done
  cp "${output}/verification-attempts/${attempt}.json" "${output}/verification.json"
  printf '{"attempts":%s,"converged":false,"timeoutSeconds":%s}\n' \
    "${attempt}" "${STAGE_CONVERGENCE_TIMEOUT_SECONDS}" >"${output}/convergence.json"
  echo "${network} did not produce and converge on a Stacks block within ${STAGE_CONVERGENCE_TIMEOUT_SECONDS}s" >&2
  return 1
}

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
    --probes="${PROBES}" --probe-image="${PROBE_IMAGE}" \
    --output="${output}/rendered"

  capture_operator_metrics "${output}/operator-before.prom"

  start="$(date +%s)"
  KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/lifecycle.sh" apply "${output}/rendered"
  end="$(date +%s)"
  capture_operator_metrics "${output}/operator-after.prom"
  node "${ATTACKNET_DIR}/operator-pressure.mjs" \
    "${output}/operator-before.prom" "${output}/operator-after.prom" \
    "${output}/operator-pressure.json"
  duration=$((end - start))
  printf '{"stage":%s,"miners":%s,"signers":%s,"followers":%s,"readySeconds":%s}\n' \
    "${stage_number}" "${miners}" "${signers}" "${followers}" "${duration}" \
    >"${output}/result.json"

  KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/lifecycle.sh" capture "${output}/admitted"
  wait_for_stage_convergence "${network}" "${output}/rendered/manifest.json" "${output}"
  kubectl top pods -n "${NAMESPACE}" -l "testing.stacks.org/network=${network}" \
    >"${output}/pod-usage.txt" 2>&1 || true

  if [ "${stage_number}" -lt "${stage_total}" ] || [ "${KEEP_LAST}" != 1 ]; then
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/lifecycle.sh" delete
  fi
done

echo "Capacity evidence: ${EVIDENCE_ROOT}"
