#!/usr/bin/env bash
set -euo pipefail

namespace="${CHAOS_MESH_NAMESPACE:-chaos-mesh}"
deployment="${CHAOS_DASHBOARD_DEPLOYMENT:-chaos-dashboard}"
service="${CHAOS_DASHBOARD_SERVICE:-chaos-dashboard}"
port="${CHAOS_DASHBOARD_PORT:-2333}"
helm_release="${CHAOS_MESH_HELM_RELEASE:-chaos-mesh}"
helm_chart="${CHAOS_MESH_HELM_CHART:-chaos-mesh/chaos-mesh}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
access_manifest="${root}/contrib/attacknet/chaos-dashboard-cluster-access.yaml"

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
    "usage: $0 local | secure | token | status" \
    "" \
    "  local   disable Dashboard auth for this local cluster, then port-forward" \
    "  secure  re-enable Dashboard auth" \
    "  token   install and print the persistent local cluster-manager token" \
    "  status  print the admitted Dashboard security mode"
}

case "${1:-}" in
  local)
    set_security_mode false
    printf 'Chaos Dashboard authentication is disabled for this local cluster.\n' >&2
    printf 'Open http://127.0.0.1:%s after the port-forward reports ready.\n' "${port}" >&2
    exec kubectl -n "${namespace}" port-forward \
      "service/${service}" "${port}:2333" --address=127.0.0.1
    ;;
  secure)
    set_security_mode true
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
