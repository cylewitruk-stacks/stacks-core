#!/usr/bin/env bash
set -euo pipefail

namespace="${KUBE_NAMESPACE:-hacknet-system}"
address="${ATTACKNET_GRAFANA_ADDRESS:-127.0.0.1}"
port="${ATTACKNET_GRAFANA_PORT:-3000}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root}/contrib/attacknet/local-access.sh"
state_dir="${ATTACKNET_LOCAL_ACCESS_STATE_DIR:-${TMPDIR:-/tmp}/stacks-attacknet-local-access}"
pid_file="${state_dir}/supervisor.pid"
log_file="${state_dir}/supervisor.log"
launchd_label="${ATTACKNET_GRAFANA_LAUNCHD_LABEL:-org.stacks.attacknet.grafana-access}"
kubectl_bin="${KUBECTL:-$(command -v kubectl || true)}"
selector='app.kubernetes.io/name=attacknet-grafana,app.kubernetes.io/part-of=stacks-attacknet'

[ -n "${kubectl_bin}" ] || { echo "kubectl is required" >&2; exit 1; }

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
  services="$("${kubectl_bin}" -n "${namespace}" get service -l "${selector}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  count="$(grep -c . <<<"${services}" || true)"
  if [ "${count}" -gt 1 ]; then
    echo "refusing ambiguous Grafana access: ${count} enrolled Services in ${namespace}" >&2
    return 2
  fi
  [ "${count}" -eq 1 ] || return 1
  printf '%s\n' "${services}"
}

launchd_available() {
  [ "${ATTACKNET_GRAFANA_USE_LAUNCHD:-1}" = 1 ] \
    && [ "$(uname -s)" = Darwin ] && command -v launchctl >/dev/null 2>&1
}

launchd_alive() {
  launchd_available || return 1
  launchctl print "gui/$(id -u)/${launchd_label}" >/dev/null 2>&1
}

run_supervisor() {
  local service result forward_pid=''
  cleanup_supervisor() {
    local code=$?
    trap - EXIT INT TERM
    if [ -n "${forward_pid:-}" ]; then
      kill "${forward_pid}" 2>/dev/null || true
      wait "${forward_pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}"
    exit "${code}"
  }
  trap cleanup_supervisor EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  mkdir -p "${state_dir}"
  printf '%s\n' "$$" >"${pid_file}"
  while true; do
    if service="$(discover_service)"; then
      echo "Forwarding Grafana at http://${address}:${port} via service/${service}" >&2
      result=0
      "${kubectl_bin}" -n "${namespace}" port-forward "service/${service}" \
        "${port}:3000" "--address=${address}" &
      forward_pid=$!
      wait "${forward_pid}" || result=$?
      forward_pid=''
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
  if launchd_alive; then
    echo "Grafana local access already supervised by launchd; http://${address}:${port}"
    return 0
  fi
  if supervisor_alive; then
    echo "Grafana local access already supervised by PID $(cat "${pid_file}")"
    return 0
  fi
  rm -f "${pid_file}"
  local pid
  if launchd_available; then
    launchctl submit -l "${launchd_label}" -o "${log_file}" -e "${log_file}" -- \
      /usr/bin/env "PATH=${PATH}" "KUBECTL=${kubectl_bin}" \
      "KUBE_NAMESPACE=${namespace}" "ATTACKNET_GRAFANA_PORT=${port}" \
      "ATTACKNET_GRAFANA_ADDRESS=${address}" \
      "ATTACKNET_LOCAL_ACCESS_STATE_DIR=${state_dir}" \
      "ATTACKNET_GRAFANA_LAUNCHD_LABEL=${launchd_label}" \
      /bin/bash "${script_path}" run
    pid=launchd
  else
    nohup "${script_path}" run >>"${log_file}" 2>&1 </dev/null &
    pid=$!
  fi
  for _ in $(seq 1 30); do
    supervisor_alive && {
      echo "Grafana local access supervisor started by ${pid}; http://${address}:${port}"
      return 0
    }
    sleep 0.1
  done
  echo "Grafana local access supervisor failed to start; see ${log_file}" >&2
  return 1
}

stop_supervisor() {
  if launchd_alive; then
    launchctl remove "${launchd_label}"
  elif ! supervisor_alive; then
    rm -f "${pid_file}"
    echo "Grafana local access supervisor is not running"
    return 0
  else
    local pid
    pid="$(cat "${pid_file}")"
    kill "${pid}"
    for _ in $(seq 1 50); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 0.1
    done
  fi
  rm -f "${pid_file}"
  echo "Grafana local access supervisor stopped"
}

case "${1:-}" in
  run) run_supervisor ;;
  start) start_supervisor ;;
  stop) stop_supervisor ;;
  status)
    if launchd_alive || supervisor_alive; then
      echo "running pid=$(cat "${pid_file}") url=http://${address}:${port} log=${log_file}"
    else
      echo "stopped url=http://${address}:${port} log=${log_file}"
      exit 1
    fi
    ;;
  *) echo "usage: $0 {start|stop|status|run}" >&2; exit 2 ;;
esac
