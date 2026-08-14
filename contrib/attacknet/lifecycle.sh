#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
NETWORK="${KUBE_NETWORK:-attacknet}"
TIMEOUT="${HACKNET_TIMEOUT_SECONDS:-900}"
AUTO_START_BURNCHAIN="${ATTACKNET_AUTO_START_BURNCHAIN:-1}"
STARTUP_SETTLE_SECONDS="${ATTACKNET_STARTUP_SETTLE_SECONDS:-5}"
BOOTSTRAP_INTERVAL_SECONDS="${ATTACKNET_BOOTSTRAP_INTERVAL_SECONDS:-2}"
OBSERVABILITY_ENABLED="${ATTACKNET_OBSERVABILITY_ENABLED:-1}"

[[ "${NETWORK}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "invalid Kubernetes network name: ${NETWORK}" >&2
  exit 2
}
[[ "${NAMESPACE}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "invalid Kubernetes namespace: ${NAMESPACE}" >&2
  exit 2
}

wait_ready() {
  local deadline=$((SECONDS + TIMEOUT))
  local phase desired ready generation observed
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    read -r phase desired ready generation observed < <(kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" \
      -o jsonpath='{.status.phase}{" "}{.status.desiredActors}{" "}{.status.readyActors}{" "}{.metadata.generation}{" "}{.status.observedGeneration}{"\n"}' \
      2>/dev/null || true)
    if [ "${phase:-}" = Ready ] && [ -n "${desired:-}" ] && [ "${desired}" = "${ready:-}" ] \
      && [ "${generation:-}" = "${observed:-}" ]; then
      printf 'Ready %s/%s\n' "${ready}" "${desired}"
      return 0
    fi
    if [ "${phase:-}" = Degraded ]; then
      kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o jsonpath='{.status.message}{"\n"}' >&2 || true
    fi
    sleep 3
  done
  echo "${NETWORK} did not become Ready within ${TIMEOUT}s" >&2
  kubectl -n "${NAMESPACE}" describe stacksnetwork "${NETWORK}" >&2 || true
  kubectl -n "${NAMESPACE}" get pods -l "testing.stacks.org/network=${NETWORK}" -o wide >&2 || true
  return 1
}

wait_deleted() {
  local deadline=$((SECONDS + TIMEOUT))
  local remaining
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    remaining="$(kubectl -n "${NAMESPACE}" get pods,pvc,statefulsets,services,configmaps \
      -l "testing.stacks.org/network=${NETWORK}" -o name 2>/dev/null || true)"
    if [ -z "${remaining}" ]; then
      echo "Deleted ${NETWORK} and all labeled children/PVCs"
      return 0
    fi
    sleep 2
  done
  echo "resources survived deletion of ${NETWORK}:" >&2
  printf '%s\n' "${remaining}" >&2
  return 1
}

wait_bootstrap_ready() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT))
  local actors expected pod_count unready
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" bootstrap)"
  expected="$(node -e '
    const fs = require("node:fs");
    console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).workloads.length);
  ' "${manifest}")"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    # Count only operator-managed actor Pods.  Observability and other harness
    # workloads deliberately share the network label but are not represented
    # in manifest.workloads and must not block protocol activation.
    pod_count="$(kubectl -n "${NAMESPACE}" get pods \
      -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | wc -w | tr -d ' ')"
    unready="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" unready ${actors} 2>/dev/null || true)"
    if [ "${pod_count}" = "${expected}" ] && [ -z "${unready}" ]; then
      printf 'Bootstrap cohort Ready (%s actors); %s/%s Pods admitted\n' \
        "$(wc -w <<<"${actors}" | tr -d ' ')" "${pod_count}" "${expected}"
      return 0
    fi
    sleep 3
  done
  echo "${NETWORK} bootstrap cohort did not become Ready within ${TIMEOUT}s; unready: ${unready:-unknown}" >&2
  return 1
}

wait_observability_ready() {
  [ "${OBSERVABILITY_ENABLED}" = 1 ] || return 0
  kubectl -n "${NAMESPACE}" wait --for=condition=Available deployment \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/part-of=stacks-attacknet" \
    --timeout="${TIMEOUT}s"
}

apply_network() {
  local generated="${1:?generated topology directory required}"
  local manifest="${generated}/manifest.json" gated desired_interval desired_jitter
  if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
    node "${ATTACKNET_DIR}/observability/render.mjs" "${manifest}" \
      --output="${generated}/observability.json" \
      --token-output="${generated}/event-token"
    kubectl -n "${NAMESPACE}" apply -f "${generated}/observability.json"
  fi
  kubectl -n "${NAMESPACE}" apply -f "${generated}/burnchain-policy.configmap.json"
  kubectl -n "${NAMESPACE}" apply -f "${generated}/stacksnetwork.json"
  gated="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" activation-gated)"
  desired_interval="$(sed -n 's/^INTERVAL_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  desired_jitter="$(sed -n 's/^JITTER_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  if [ "${AUTO_START_BURNCHAIN}" = 1 ] && [ -n "${gated}" ]; then
    wait_bootstrap_ready "${manifest}"
    sleep "${STARTUP_SETTLE_SECONDS}"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${BOOTSTRAP_INTERVAL_SECONDS}" 0
    wait_ready
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${desired_interval:-20}" "${desired_jitter:-0}"
  else
    wait_ready
  fi
  if [ "${AUTO_START_BURNCHAIN}" = 1 ] && [ -z "${gated}" ]; then
    sleep "${STARTUP_SETTLE_SECONDS}"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${desired_interval:-20}" "${desired_jitter:-0}"
  fi
  wait_observability_ready
}

delete_network() {
  kubectl -n "${NAMESPACE}" delete stacksnetwork "${NETWORK}" --ignore-not-found --wait=false
  kubectl -n "${NAMESPACE}" delete configmap "${NETWORK}-burnchain-policy" --ignore-not-found
  kubectl -n "${NAMESPACE}" delete deployments,services,configmaps,secrets,pvc \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/part-of=stacks-attacknet" \
    --ignore-not-found --wait=false
  wait_deleted
}

capture() {
  local destination="${1:?evidence directory required}"
  mkdir -p "${destination}"
  kubectl version -o json >"${destination}/kubernetes-version.json"
  kubectl get nodes -o json >"${destination}/nodes.json"
  kubectl get storageclasses -o json >"${destination}/storageclasses.json"
  kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o json \
    >"${destination}/stacksnetwork.admitted.json"
  kubectl -n "${NAMESPACE}" get pods -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/pods.admitted.json"
  kubectl -n "${NAMESPACE}" get statefulsets -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/statefulsets.admitted.json"
  kubectl -n "${NAMESPACE}" get pvc -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/pvcs.admitted.json"
  kubectl -n "${NAMESPACE}" get pv -o json >"${destination}/persistent-volumes.json"
  kubectl -n "${NAMESPACE}" get events --sort-by=.metadata.creationTimestamp -o json \
    >"${destination}/namespace-events.json"
  kubectl -n "${NAMESPACE}" logs -l 'app.kubernetes.io/name=hacknet' \
    --all-containers=true --since=1h --timestamps \
    >"${destination}/operator.log"
  ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
    "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/runtime.json"
}

case "${1:-}" in
  apply) shift; apply_network "$@" ;;
  wait) wait_ready ;;
  delete) delete_network ;;
  capture) shift; capture "$@" ;;
  *) echo "usage: $0 {apply GENERATED_DIR|wait|delete|capture EVIDENCE_DIR}" >&2; exit 2 ;;
esac
