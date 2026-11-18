#!/usr/bin/env bash
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -m py_compile "${chart_dir}/operator/controller.py"
python3 -m unittest discover -s "${chart_dir}/operator" -p 'test_*.py' -v

helm_bin="${HELM_BIN:-helm}"
if command -v "${helm_bin}" >/dev/null 2>&1; then
  "${helm_bin}" lint "${chart_dir}"
  "${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system --include-crds >/dev/null
  "${helm_bin}" template hacknet "${chart_dir}" --namespace hacknet-system \
    --set operator.developmentSource.enabled=true \
    --set serviceAccount.tokenExpirationSeconds=600 >/dev/null
else
  echo "helm not installed; skipped chart lint/render (set HELM_BIN to an explicit binary)" >&2
fi
