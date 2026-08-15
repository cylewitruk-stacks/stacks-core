#!/usr/bin/env bash
set -euo pipefail

namespace="${CHAOS_MESH_NAMESPACE:-chaos-mesh}"
deployment="${CHAOS_DASHBOARD_DEPLOYMENT:-chaos-dashboard}"
service="${CHAOS_DASHBOARD_SERVICE:-chaos-dashboard}"
port="${CHAOS_DASHBOARD_PORT:-2333}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
access_manifest="${root}/contrib/attacknet/chaos-dashboard-cluster-access.yaml"

usage() {
  printf '%s\n' \
    "usage: $0 local | secure | token | status" \
    "" \
    "  local   disable Dashboard auth for this local cluster, then port-forward" \
    "  secure  re-enable Dashboard auth" \
    "  token   install and print the persistent local cluster-manager token" \
    "  status  print the admitted Dashboard security mode"
}

case "${1:-}" in
  local)
    kubectl -n "${namespace}" set env "deployment/${deployment}" SECURITY_MODE=false
    kubectl -n "${namespace}" rollout status "deployment/${deployment}" --timeout=180s
    printf 'Chaos Dashboard authentication is disabled for this local cluster.\n' >&2
    printf 'Open http://127.0.0.1:%s after the port-forward reports ready.\n' "${port}" >&2
    exec kubectl -n "${namespace}" port-forward \
      "service/${service}" "${port}:2333" --address=127.0.0.1
    ;;
  secure)
    kubectl -n "${namespace}" set env "deployment/${deployment}" SECURITY_MODE=true
    kubectl -n "${namespace}" rollout status "deployment/${deployment}" --timeout=180s
    ;;
  token)
    kubectl apply -f "${access_manifest}"
    printf 'Name: local-cluster-manager\nToken: '
    kubectl -n "${namespace}" get secret attacknet-chaos-dashboard-token \
      -o jsonpath='{.data.token}' | base64 --decode
    printf '\n'
    ;;
  status)
    kubectl -n "${namespace}" get "deployment/${deployment}" \
      -o jsonpath='securityMode={.spec.template.spec.containers[0].env[?(@.name=="SECURITY_MODE")].value}{"\n"}'
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
