#!/bin/bash

# Backend adapter for the Stacks Attacknet behavioral harness. Assertions
# consume logical actor names and never need to know whether the process lives
# in a Compose container or a Kubernetes Pod.

RUNTIME_BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKNET_BACKEND="${ATTACKNET_BACKEND:-${POC_BACKEND:-kubernetes}}"
ATTACKNET_PROJECT="${ATTACKNET_PROJECT:-stacks-attacknet}"
ATTACKNET_COMPOSE="${ATTACKNET_COMPOSE:-${RUNTIME_BACKEND_DIR}/generated/compose.yaml}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
KUBE_NETWORK="${KUBE_NETWORK:-attacknet}"

backend_compose() {
  docker compose -p "${ATTACKNET_PROJECT}" -f "${ATTACKNET_COMPOSE}" "$@"
}

backend_require() {
  case "${ATTACKNET_BACKEND}" in
    compose) command -v docker >/dev/null ;;
    kubernetes) command -v kubectl >/dev/null ;;
    *) echo "unsupported ATTACKNET_BACKEND=${ATTACKNET_BACKEND}; expected compose or kubernetes" >&2; return 2 ;;
  esac
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
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose exec -T "${actor}" "$@" ;;
    kubernetes)
      local pod
      pod="$(backend_pod "${actor}")" || return
      kubectl -n "${KUBE_NAMESPACE}" exec "${pod}" -c actor -- "$@"
      ;;
  esac
}

# Bound a remote probe at the backend boundary.  A wedged actor must become an
# explicit failed observation instead of wedging the verifier or evidence run.
backend_exec_timeout() {
  local seconds="$1"
  local actor="$2"
  shift 2
  case "${ATTACKNET_BACKEND}" in
    compose) timeout --signal=TERM --kill-after=5 "${seconds}" docker compose \
      -p "${ATTACKNET_PROJECT}" -f "${ATTACKNET_COMPOSE}" exec -T "${actor}" "$@" ;;
    kubernetes)
      local pod
      pod="$(backend_pod "${actor}")" || return
      timeout --signal=TERM --kill-after=5 "${seconds}" kubectl -n "${KUBE_NAMESPACE}" \
        exec "${pod}" -c actor -- "$@"
      ;;
  esac
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
  case "${ATTACKNET_BACKEND}" in
    compose)
      local args=(exec -T)
      local assignment
      for assignment in "${assignments[@]}"; do args+=(-e "${assignment}"); done
      backend_compose "${args[@]}" "${actor}" "$@"
      ;;
    kubernetes) backend_exec "${actor}" env "${assignments[@]}" "$@" ;;
  esac
}

# Concatenate logs for one or more actors.  Arguments are deliberately simple
# and portable: TAIL, SINCE (empty means all available), ACTOR...
backend_logs() {
  local tail="$1"
  local since="$2"
  shift 2
  case "${ATTACKNET_BACKEND}" in
    compose)
      local args=(logs --no-color "--tail=${tail}")
      [ -z "${since}" ] || args+=(--since "${since}")
      backend_compose "${args[@]}" "$@"
      ;;
    kubernetes)
      local actor pod args
      for actor in "$@"; do
        pod="$(backend_pod "${actor}")" || return
        args=(logs "${pod}" -c actor "--tail=${tail}" --timestamps=true)
        [ -z "${since}" ] || args+=(--since "${since}")
        kubectl -n "${KUBE_NAMESPACE}" "${args[@]}"
      done
      ;;
  esac
}

backend_actor_exists() {
  local actor="$1"
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose config --services | grep -Fxq "${actor}" ;;
    kubernetes)
      kubectl -n "${KUBE_NAMESPACE}" get stacksnetwork "${KUBE_NETWORK}" \
        -o jsonpath='{range .spec.actors[*]}{.name}{"\n"}{end}' 2>/dev/null \
        | grep -Fxq "${actor}"
      ;;
  esac
}

# Print the requested logical actor names that are absent, stopped, or not
# Ready.  Telemetry sidecars are part of Pod readiness in Kubernetes.
backend_unready_actors() {
  case "${ATTACKNET_BACKEND}" in
    compose)
      local status_json
      status_json="$(backend_compose ps --all --format json)"
      node -e '
        const fs = require("node:fs");
        const rows = fs.readFileSync(0, "utf8").trim().split(/\n+/).filter(Boolean).map(JSON.parse);
        const byService = new Map(rows.map(row => [row.Service, row]));
        const unready = process.argv.slice(1).filter(service => {
          const row = byService.get(service);
          return !row || row.State !== "running" || (row.Health && row.Health !== "healthy");
        });
        process.stdout.write(unready.join(" "));
      ' "$@" <<<"${status_json}"
      ;;
    kubernetes)
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
          const running = pod?.status?.phase === "Running";
          return !running || !ready;
        });
        process.stdout.write(unready.join(" "));
      ' "$@" <<<"${pods_json}"
      ;;
  esac
}

backend_signal() {
  local actor="$1"
  local signal="$2"
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose kill -s "${signal}" "${actor}" >/dev/null ;;
    kubernetes) backend_exec "${actor}" sh -c 'kill -"$1" 1' _ "${signal}" ;;
  esac
}

backend_pause() {
  local actor="$1"
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose pause "${actor}" >/dev/null ;;
    # PID 1 is namespace init. Linux accepts the in-namespace kill(2) call but
    # does not deliver SIGSTOP to namespace init, so this used to return success
    # while the actor kept running. Kubernetes availability controls must use a
    # controller-owned FaultCampaign (normally PodChaos pod-failure) instead.
    kubernetes)
      echo "Kubernetes pause is not a process primitive; use a controller-owned FaultCampaign for ${actor}" >&2
      return 2
      ;;
  esac
}

backend_resume() {
  local actor="$1"
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose unpause "${actor}" >/dev/null ;;
    kubernetes)
      echo "Kubernetes resume is owned by FaultCampaign cleanup; no signal was sent to ${actor}" >&2
      return 2
      ;;
  esac
}

# Query the backend's enrolled Prometheus through an actor that already has a
# bounded HTTP client.  Assertions consume the same Prometheus API response on
# Compose and Kubernetes; only service discovery belongs in this adapter.
backend_prometheus_query() {
  local network="$1"
  local query="$2"
  local probe_actor="${3:?manifest-derived probe actor required}"
  local endpoint
  case "${ATTACKNET_BACKEND}" in
    compose) endpoint='http://prometheus:9090/api/v1/query' ;;
    kubernetes) endpoint="http://${network}-attacknet-prometheus:9090/api/v1/query" ;;
  esac
  backend_exec_timeout "${ATTACKNET_PROBE_TIMEOUT_SECONDS:-10}" "${probe_actor}" \
    curl --fail --silent --get --data-urlencode "query=${query}" "${endpoint}"
}

backend_runtime_description() {
  case "${ATTACKNET_BACKEND}" in
    compose) backend_compose ps --all --format json ;;
    kubernetes)
      kubectl -n "${KUBE_NAMESPACE}" get pods,pvc \
        -l "testing.stacks.org/network=${KUBE_NETWORK}" -o json
      ;;
  esac
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
