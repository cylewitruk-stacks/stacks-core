#!/usr/bin/env bash
set -euo pipefail

namespace="${CHAOS_MESH_NAMESPACE:-chaos-mesh}"
deployment="${CHAOS_DASHBOARD_DEPLOYMENT:-chaos-dashboard}"
service="${CHAOS_DASHBOARD_SERVICE:-chaos-dashboard}"
port="${CHAOS_DASHBOARD_PORT:-2333}"
address="${CHAOS_DASHBOARD_ADDRESS:-127.0.0.1}"
helm_release="${CHAOS_MESH_HELM_RELEASE:-chaos-mesh}"
helm_chart="${CHAOS_MESH_HELM_CHART:-chaos-mesh/chaos-mesh}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
access_manifest="${root}/contrib/attacknet/chaos-dashboard-cluster-access.yaml"
script_path="${root}/contrib/attacknet/chaos-dashboard.sh"
state_dir="${ATTACKNET_CHAOS_DASHBOARD_STATE_DIR:-${TMPDIR:-/tmp}/stacks-attacknet-chaos-dashboard-access}"
pid_file="${state_dir}/supervisor.pid"
log_file="${state_dir}/supervisor.log"
launchd_label="${ATTACKNET_CHAOS_DASHBOARD_LAUNCHD_LABEL:-org.stacks.attacknet.chaos-dashboard-access}"
kubectl_bin="${KUBECTL:-$(command -v kubectl || true)}"

[ -n "${kubectl_bin}" ] || { echo "kubectl is required" >&2; exit 1; }

[[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1024 ] && [ "${port}" -le 65535 ] || {
  echo "CHAOS_DASHBOARD_PORT must be an unprivileged TCP port" >&2
  exit 2
}
[ "${address}" = 127.0.0.1 ] || {
  echo "local Chaos Dashboard access is deliberately loopback-only" >&2
  exit 2
}

supervisor_alive() {
  local pid command
  [ -r "${pid_file}" ] || return 1
  pid="$(cat "${pid_file}")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  command="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command}" == *"chaos-dashboard.sh run"* ]]
}

dashboard_available() {
  "${kubectl_bin}" -n "${namespace}" get "service/${service}" >/dev/null 2>&1
}

launchd_available() {
  [ "${ATTACKNET_CHAOS_DASHBOARD_USE_LAUNCHD:-1}" = 1 ] \
    && [ "$(uname -s)" = Darwin ] && command -v launchctl >/dev/null 2>&1
}

launchd_alive() {
  launchd_available || return 1
  launchctl print "gui/$(id -u)/${launchd_label}" >/dev/null 2>&1
}

run_supervisor() {
  local result=0 forward_pid=''
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
    if dashboard_available; then
      echo "Forwarding Chaos Dashboard at http://${address}:${port} via service/${service}" >&2
      result=0
      "${kubectl_bin}" -n "${namespace}" port-forward "service/${service}" \
        "${port}:2333" "--address=${address}" &
      forward_pid=$!
      wait "${forward_pid}" || result=$?
      forward_pid=''
      echo "Chaos Dashboard forward ended with status ${result}; retrying" >&2
    else
      result=1
      echo "Chaos Dashboard service/${service} is unavailable; waiting" >&2
    fi
    [ "${ATTACKNET_CHAOS_DASHBOARD_ACCESS_ONCE:-0}" = 1 ] && return "${result}"
    sleep 2
  done
}

start_supervisor() {
  mkdir -p "${state_dir}"
  if supervisor_alive; then
    echo "Chaos Dashboard local access already supervised by PID $(cat "${pid_file}")"
    return 0
  fi
  rm -f "${pid_file}"
  local pid
  if launchd_available; then
    launchd_alive && launchctl remove "${launchd_label}" >/dev/null 2>&1 || true
    launchctl submit -l "${launchd_label}" -o "${log_file}" -e "${log_file}" -- \
      /usr/bin/env "PATH=${PATH}" "KUBECTL=${kubectl_bin}" \
      "CHAOS_MESH_NAMESPACE=${namespace}" "CHAOS_DASHBOARD_SERVICE=${service}" \
      "CHAOS_DASHBOARD_PORT=${port}" "CHAOS_DASHBOARD_ADDRESS=${address}" \
      "ATTACKNET_CHAOS_DASHBOARD_STATE_DIR=${state_dir}" \
      "ATTACKNET_CHAOS_DASHBOARD_LAUNCHD_LABEL=${launchd_label}" \
      /bin/bash "${script_path}" run
    pid=launchd
  else
    nohup "${script_path}" run >>"${log_file}" 2>&1 </dev/null &
    pid=$!
  fi
  for _ in $(seq 1 30); do
    supervisor_alive && {
      echo "Chaos Dashboard local access supervisor started by ${pid}; http://${address}:${port}"
      return 0
    }
    sleep 0.1
  done
  echo "Chaos Dashboard local access supervisor failed to start; see ${log_file}" >&2
  return 1
}

stop_supervisor() {
  if launchd_alive; then
    launchctl remove "${launchd_label}"
  elif ! supervisor_alive; then
    rm -f "${pid_file}"
    echo "Chaos Dashboard local access supervisor is not running"
    return 0
  else
    local pid
    pid="$(cat "${pid_file}")"
    kill "${pid}"
  fi
  for _ in $(seq 1 50); do
    supervisor_alive || break
    sleep 0.1
  done
  rm -f "${pid_file}"
  echo "Chaos Dashboard local access supervisor stopped"
}

set_security_mode() {
  local enabled="$1"
  local installed_chart version

  command -v helm >/dev/null 2>&1 || {
    printf 'helm is required to update the installed Chaos Mesh release\n' >&2
    return 1
  }
  installed_chart="$(
    helm list -n "${namespace}" --filter "^${helm_release}$" -o json \
      | jq -er 'if length == 1 then .[0].chart else error("release not found") end'
  )"
  version="${CHAOS_MESH_HELM_VERSION:-${installed_chart#chaos-mesh-}}"
  if [ -z "${version}" ] || [ "${version}" = "${installed_chart}" ]; then
    printf 'could not derive the installed Chaos Mesh chart version from %q\n' \
      "${installed_chart}" >&2
    return 1
  fi

  helm upgrade "${helm_release}" "${helm_chart}" \
    --namespace "${namespace}" \
    --version "${version}" \
    --reuse-values \
    --set "dashboard.securityMode=${enabled}" \
    --wait \
    --timeout 5m
}

usage() {
  printf '%s\n' \
    "usage: $0 local | secure | token | start | stop | status" \
    "" \
    "  local   disable Dashboard auth locally, then start resilient access" \
    "  secure  re-enable Dashboard auth" \
    "  token   install and print the persistent local cluster-manager token" \
    "  start   preserve auth mode and start resilient loopback access" \
    "  stop    stop resilient loopback access" \
    "  status  print admitted security mode and local-access status"
}

case "${1:-}" in
  local)
    set_security_mode false
    printf 'Chaos Dashboard authentication is disabled for this local cluster.\n' >&2
    start_supervisor
    ;;
  secure)
    set_security_mode true
    ;;
  token)
    "${kubectl_bin}" apply -f "${access_manifest}"
    printf 'Name: local-cluster-manager\nToken: '
    "${kubectl_bin}" -n "${namespace}" get secret attacknet-chaos-dashboard-token \
      -o jsonpath='{.data.token}' | base64 --decode
    printf '\n'
    ;;
  run)
    run_supervisor
    ;;
  start)
    start_supervisor
    ;;
  stop)
    stop_supervisor
    ;;
  status)
    "${kubectl_bin}" -n "${namespace}" get "deployment/${deployment}" \
      -o jsonpath='securityMode={.spec.template.spec.containers[0].env[?(@.name=="SECURITY_MODE")].value}{"\n"}'
    if supervisor_alive; then
      echo "access=running pid=$(cat "${pid_file}") url=http://${address}:${port} log=${log_file}"
    else
      echo "access=stopped url=http://${address}:${port} log=${log_file}"
      exit 1
    fi
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
