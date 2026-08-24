#!/bin/bash

# Kubernetes runtime operations for logical Attacknet actor names. Assertions
# use this boundary instead of depending on generated Pod names.

KUBE_NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
KUBE_NETWORK="${KUBE_NETWORK:-attacknet}"

backend_require() {
  command -v kubectl >/dev/null
}

backend_pod() {
  local actor="$1"
  local pod
  pod="$(kubectl -n "${KUBE_NAMESPACE}" get pods \
    -l "testing.stacks.org/network=${KUBE_NETWORK},testing.stacks.org/actor=${actor}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | head -1)"
  if [ -z "${pod}" ]; then
    echo "no Pod found for ${KUBE_NETWORK}/${actor} in ${KUBE_NAMESPACE}" >&2
    return 1
  fi
  printf '%s\n' "${pod}"
}

backend_exec() {
  local actor="$1"
  shift
  local pod
  pod="$(backend_pod "${actor}")" || return
  kubectl -n "${KUBE_NAMESPACE}" exec "${pod}" -c actor -- "$@"
}

# Bound remote probes so a wedged actor becomes an explicit failed observation.
backend_exec_timeout() {
  local seconds="$1"
  local actor="$2"
  shift 2
  local pod
  pod="$(backend_pod "${actor}")" || return
  timeout --signal=TERM --kill-after=5 "${seconds}" kubectl -n "${KUBE_NAMESPACE}" \
    exec "${pod}" -c actor -- "$@"
}

# Usage: backend_exec_env ACTOR KEY=VALUE ... -- COMMAND ARG...
backend_exec_env() {
  local actor="$1"
  shift
  local assignments=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    assignments+=("$1")
    shift
  done
  [ "${1:-}" = "--" ] || {
    echo "backend_exec_env requires -- before the command" >&2
    return 2
  }
  shift
  backend_exec "${actor}" env "${assignments[@]}" "$@"
}

# Concatenate actor logs. Arguments are TAIL, SINCE (empty means all), ACTOR...
backend_logs() {
  local tail="$1"
  local since="$2"
  shift 2
  local actor pod args
  for actor in "$@"; do
    pod="$(backend_pod "${actor}")" || return
    args=(logs "${pod}" -c actor "--tail=${tail}" --timestamps=true)
    [ -z "${since}" ] || args+=(--since "${since}")
    kubectl -n "${KUBE_NAMESPACE}" "${args[@]}"
  done
}

backend_actor_exists() {
  local actor="$1"
  kubectl -n "${KUBE_NAMESPACE}" get stacksnetwork "${KUBE_NETWORK}" \
    -o jsonpath='{range .spec.actors[*]}{.name}{"\n"}{end}' 2>/dev/null \
    | grep -Fxq "${actor}"
}

# Print requested actor names that are absent, stopped, or not Ready. Telemetry
# and active-probe sidecars participate in Pod readiness.
backend_unready_actors() {
  local pods_json
  pods_json="$(kubectl -n "${KUBE_NAMESPACE}" get pods \
    -l "testing.stacks.org/network=${KUBE_NETWORK}" -o json)" || return
  node -e '
    const fs = require("node:fs");
    const pods = JSON.parse(fs.readFileSync(0, "utf8")).items;
    const byActor = new Map(pods.map(pod => [pod.metadata.labels["testing.stacks.org/actor"], pod]));
    const unready = process.argv.slice(1).filter(actor => {
      const pod = byActor.get(actor);
      const ready = pod?.status?.conditions?.some(item => item.type === "Ready" && item.status === "True");
      return pod?.status?.phase !== "Running" || !ready;
    });
    process.stdout.write(unready.join(" "));
  ' "$@" <<<"${pods_json}"
}

backend_signal() {
  local actor="$1"
  local signal="$2"
  backend_exec "${actor}" sh -c 'kill -"$1" 1' _ "${signal}"
}

backend_pause() {
  local actor="$1"
  echo "Kubernetes pause is not a process primitive; use a controller-owned FaultCampaign for ${actor}" >&2
  return 2
}

backend_resume() {
  local actor="$1"
  echo "Kubernetes resume is owned by FaultCampaign cleanup; no signal was sent to ${actor}" >&2
  return 2
}

backend_prometheus_query() {
  local network="$1"
  local query="$2"
  local probe_actor="${3:?manifest-derived probe actor required}"
  local endpoint="http://${network}-attacknet-prometheus:9090/api/v1/query"
  backend_exec_timeout "${ATTACKNET_PROBE_TIMEOUT_SECONDS:-10}" "${probe_actor}" \
    curl --fail --silent --get --data-urlencode "query=${query}" "${endpoint}"
}

backend_runtime_description() {
  kubectl -n "${KUBE_NAMESPACE}" get pods,pvc \
    -l "testing.stacks.org/network=${KUBE_NETWORK}" -o json
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  backend_require
  action="${1:-}"
  shift || true
  case "${action}" in
    exec) backend_exec "$@" ;;
    logs) backend_logs "$@" ;;
    exists) backend_actor_exists "$@" ;;
    unready) backend_unready_actors "$@" ;;
    signal) backend_signal "$@" ;;
    pause) backend_pause "$@" ;;
    resume) backend_resume "$@" ;;
    prometheus-query) backend_prometheus_query "$@" ;;
    describe) backend_runtime_description ;;
    *) echo "usage: $0 {exec|logs|exists|unready|signal|pause|resume|prometheus-query|describe} ..." >&2; exit 2 ;;
  esac
fi
