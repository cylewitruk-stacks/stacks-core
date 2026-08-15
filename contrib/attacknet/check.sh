#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if rg -n 'require\(process\.argv' "${ATTACKNET_DIR}" -g '*.sh' -g '*.mjs' -g '*.js'; then
  echo 'caller-supplied JSON must use fs.readFileSync, not module require()' >&2
  exit 1
fi
REPO_ROOT="$(cd "${ATTACKNET_DIR}/../.." && pwd)"

node --test "${ATTACKNET_DIR}"/*.test.mjs
node --test "${ATTACKNET_DIR}"/observability/*.test.mjs
bash -n "${ATTACKNET_DIR}"/*.sh
bash -n "${ATTACKNET_DIR}"/observability/*.sh
bash -c 'source "$1/lifecycle.sh"; RUN_DESCRIPTOR=""; ledger_assertion regression pass "{\"value\":1}"' \
  _ "${ATTACKNET_DIR}"
python3 -m py_compile "${ATTACKNET_DIR}/observability/event_bridge.py"
python3 -m unittest discover -s "${ATTACKNET_DIR}/observability" -p 'test_*.py'

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
