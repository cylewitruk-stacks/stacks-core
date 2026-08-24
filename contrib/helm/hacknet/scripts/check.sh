#!/usr/bin/env bash
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_status=passed
helm_status=passed

python3 -m py_compile "${chart_dir}/operator/controller.py"
python3 -m unittest discover -s "${chart_dir}/operator" -p 'test_*.py' -v
node --check "${chart_dir}/run-operator/controller.mjs"
node --test "${chart_dir}/run-operator/controller.test.mjs"
node --test "${chart_dir}/run-operator/probe-client.test.mjs"
node --test "${chart_dir}/run-operator/image-context.test.mjs"
node --test "${chart_dir}/crds/attacknet-crds.test.mjs"
node --check "${chart_dir}/../../attacknet/probe/probe.mjs"
node --test "${chart_dir}/../../attacknet/probe/probe.test.mjs"
node --test "${chart_dir}/../../attacknet/io-pressure/image-context.test.mjs"
if command -v go >/dev/null 2>&1; then
  (cd "${chart_dir}/../../attacknet/io-pressure" && go test ./...)
else
  go_status=skipped-unavailable
  echo "go not installed; skipped bounded I/O-pressure workload tests" >&2
fi

helm_bin="${HELM_BIN:-helm}"
if command -v "${helm_bin}" >/dev/null 2>&1; then
  "${helm_bin}" lint "${chart_dir}"
  rendered="$("${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system --include-crds)"
  if [[ "${rendered}" != *'resources: ["podchaos", "networkchaos", "dnschaos", "iochaos", "timechaos"]'* ]]; then
    echo 'rendered run-operator RBAC is missing the bounded native Chaos resources' >&2
    exit 1
  fi
  if [[ "${rendered}" != *$'resources: ["pods"]\n    verbs: ["get", "list", "watch", "create", "patch", "delete"]'* ]]; then
    echo 'rendered run-operator RBAC lacks the exact controller-owned I/O-pressure Pod lifecycle verbs' >&2
    exit 1
  fi
  if [[ "${rendered}" == *'resources: ["podchaos", "networkchaos", "dnschaos", "iochaos", "stresschaos"'* ]]; then
    echo 'rendered run-operator RBAC still grants unused StressChaos authority' >&2
    exit 1
  fi
  if [[ "${rendered}" != *'"kind": {"type": "string", "enum": ["PodChaos", "NetworkChaos", "DNSChaos", "IOChaos", "IOPressurePod", "TimeChaos", "ClockSkewPolicy"]}'* ]]; then
    echo 'rendered FaultCampaign status schema is missing IOPressurePod' >&2
    exit 1
  fi
  "${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system \
    --set operator.developmentSource.enabled=true \
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
  node "${chart_dir}/../../attacknet/release/hacknet-offline-result.mjs" \
    "--output=${HACKNET_OFFLINE_RESULT}" \
    "--source-revision=$(git -C "${chart_dir}/../../.." rev-parse HEAD)" \
    --required=topology-operator,run-operator,crd-contracts,probe,image-context,chart-contract \
    "${optional[@]}"
fi
