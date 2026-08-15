#!/usr/bin/env bash
set -euo pipefail

namespace="${KUBE_NAMESPACE:-hacknet-system}"
address="${ATTACKNET_GRAFANA_ADDRESS:-127.0.0.1}"
port="${ATTACKNET_GRAFANA_PORT:-3000}"
state_dir="${ATTACKNET_LOCAL_ACCESS_STATE_DIR:-${TMPDIR:-/tmp}/stacks-attacknet-local-access}"
pid_file="${state_dir}/supervisor.pid"
log_file="${state_dir}/supervisor.log"
selector='app.kubernetes.io/name=attacknet-grafana,app.kubernetes.io/part-of=stacks-attacknet'

[[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1024 ] && [ "${port}" -le 65535 ] || {
  echo "ATTACKNET_GRAFANA_PORT must be an unprivileged TCP port" >&2
  exit 2
}
[ "${address}" = 127.0.0.1 ] || {
  echo "local Grafana access is deliberately loopback-only" >&2
  exit 2
}

supervisor_alive() {
  local pid command
  [ -r "${pid_file}" ] || return 1
  pid="$(cat "${pid_file}")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  command="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command}" == *"local-access.sh run"* ]]
}

discover_service() {
  local services count
  services="$(kubectl -n "${namespace}" get service -l "${selector}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  count="$(grep -c . <<<"${services}" || true)"
  if [ "${count}" -gt 1 ]; then
    echo "refusing ambiguous Grafana access: ${count} enrolled Services in ${namespace}" >&2
    return 2
  fi
  [ "${count}" -eq 1 ] || return 1
  printf '%s\n' "${services}"
}

run_supervisor() {
  local service result
  trap 'rm -f "${pid_file}"' EXIT INT TERM
  mkdir -p "${state_dir}"
  printf '%s\n' "$$" >"${pid_file}"
  while true; do
    if service="$(discover_service)"; then
      echo "Forwarding Grafana at http://${address}:${port} via service/${service}" >&2
      result=0
      kubectl -n "${namespace}" port-forward "service/${service}" \
        "${port}:3000" "--address=${address}" || result=$?
      echo "Grafana forward ended with status ${result}; rediscovering" >&2
    else
      result=$?
      [ "${result}" -eq 1 ] || echo "Grafana discovery is ambiguous; waiting" >&2
    fi
    [ "${ATTACKNET_LOCAL_ACCESS_ONCE:-0}" = 1 ] && return "${result}"
    sleep 2
  done
}

start_supervisor() {
  mkdir -p "${state_dir}"
  if supervisor_alive; then
    echo "Grafana local access already supervised by PID $(cat "${pid_file}")"
    return 0
  fi
  rm -f "${pid_file}"
  nohup "$0" run >>"${log_file}" 2>&1 </dev/null &
  local pid=$!
  for _ in $(seq 1 30); do
    supervisor_alive && {
      echo "Grafana local access supervisor started as PID ${pid}; http://${address}:${port}"
      return 0
    }
    sleep 0.1
  done
  echo "Grafana local access supervisor failed to start; see ${log_file}" >&2
  return 1
}

stop_supervisor() {
  if ! supervisor_alive; then
    rm -f "${pid_file}"
    echo "Grafana local access supervisor is not running"
    return 0
  fi
  local pid="$(cat "${pid_file}")"
  kill "${pid}"
  for _ in $(seq 1 50); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  rm -f "${pid_file}"
  echo "Grafana local access supervisor stopped"
}

case "${1:-}" in
  run) run_supervisor ;;
  start) start_supervisor ;;
  stop) stop_supervisor ;;
  status)
    if supervisor_alive; then
      echo "running pid=$(cat "${pid_file}") url=http://${address}:${port} log=${log_file}"
    else
      echo "stopped url=http://${address}:${port} log=${log_file}"
      exit 1
    fi
    ;;
  *) echo "usage: $0 {start|stop|status|run}" >&2; exit 2 ;;
esac

