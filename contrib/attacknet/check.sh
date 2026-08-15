#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if rg -n 'require\(process\.argv' "${ATTACKNET_DIR}" -g '*.sh' -g '*.mjs' -g '*.js'; then
  echo 'caller-supplied JSON must use fs.readFileSync, not module require()' >&2
  exit 1
fi
REPO_ROOT="$(cd "${ATTACKNET_DIR}/../.." && pwd)"

node --test "${ATTACKNET_DIR}"/*.test.mjs
bash -n "${ATTACKNET_DIR}"/*.sh

rendered="$(mktemp -d)"
trap 'rm -rf "${rendered}"' EXIT
node "${ATTACKNET_DIR}/topology.mjs" \
  --miners=3 --signers=10 --followers=5 --output="${rendered}"
python3 - "${REPO_ROOT}" "${rendered}/stacksnetwork.json" <<'PY'
import importlib.util
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "hacknet_controller", root / "contrib/helm/hacknet/operator/controller.py"
)
controller = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = controller
spec.loader.exec_module(controller)
network = json.loads(pathlib.Path(sys.argv[2]).read_text())
network["metadata"]["uid"] = "offline-validation"
resources = controller.build_resources(network)
assert len(resources["statefulsets"]) == 31
assert len(resources["services"]) == 31
print("Offline operator validation passed for 31 workloads")
PY
