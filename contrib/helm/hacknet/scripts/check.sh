#!/usr/bin/env bash
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_status=passed
envtest_status=skipped-unavailable
helm_status=passed

if command -v go >/dev/null 2>&1; then
  unformatted="$(gofmt -l "${chart_dir}/operator")"
  if [[ -n "${unformatted}" ]]; then
    echo "Go operator sources are not formatted:" >&2
    printf '%s\n' "${unformatted}" >&2
    exit 1
  fi
  (cd "${chart_dir}/operator" && go vet ./...)
  (cd "${chart_dir}/operator" && go test ./...)
  (cd "${chart_dir}/operator" && go test -race ./...)
  if [[ -n "${KUBEBUILDER_ASSETS:-}" ]]; then
    (cd "${chart_dir}/operator" && go test -tags=integration ./internal/integration)
    envtest_status=passed
  else
    echo "KUBEBUILDER_ASSETS is unset; skipped controller-runtime envtest" >&2
  fi
else
  go_status=skipped-unavailable
  echo "go not installed; skipped controller and bounded I/O-pressure workload tests" >&2
fi
node --test "${chart_dir}/security-contract.test.mjs"
node --check "${chart_dir}/../../attacknet/images/probe/probe.mjs"
node --test "${chart_dir}/../../attacknet/images/probe/probe.test.mjs"
node --test "${chart_dir}/../../attacknet/images/io-pressure/image-context.test.mjs"
if [[ "${go_status}" = passed ]]; then
  (cd "${chart_dir}/../../attacknet/images/io-pressure" && go test ./...)
fi

helm_bin="${HELM_BIN:-helm}"
if command -v "${helm_bin}" >/dev/null 2>&1; then
  "${helm_bin}" lint "${chart_dir}"
  rendered="$("${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system --include-crds)"
  if [[ "${go_status}" = passed ]]; then
    printf '%s\n' "${rendered}" | (cd "${chart_dir}/operator" && go run ./cmd/rbac-check)
  fi
  "${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system \
    --set runOperator.enabled=false \
    --set serviceAccount.tokenExpirationSeconds=600 >/dev/null
else
  helm_status=skipped-unavailable
  echo "helm not installed; skipped chart lint/render (set HELM_BIN to an explicit binary)" >&2
fi

if [[ -n "${HACKNET_OFFLINE_RESULT:-}" ]]; then
  if [[ "${go_status}" = passed ]]; then
    optional=("--optional=go:passed")
  else
    optional=("--optional=go:skipped-unavailable:Go toolchain not installed")
  fi
  if [[ "${helm_status}" = passed ]]; then
    optional+=("--optional=helm:passed")
  else
    optional+=("--optional=helm:skipped-unavailable:Helm executable not installed")
  fi
  if [[ "${envtest_status}" = passed ]]; then
    optional+=("--optional=envtest:passed")
  else
    optional+=("--optional=envtest:skipped-unavailable:KUBEBUILDER_ASSETS not configured")
  fi
  node "${chart_dir}/../../attacknet/release/hacknet-offline-result.mjs" \
    "--output=${HACKNET_OFFLINE_RESULT}" \
    "--source-revision=$(git -C "${chart_dir}/../../.." rev-parse HEAD)" \
    --required=topology-operator,run-operator,crd-contracts,probe,image-context,chart-contract \
    "${optional[@]}"
fi
