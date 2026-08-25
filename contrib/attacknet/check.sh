#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if rg -n 'require\(process\.argv' "${ATTACKNET_DIR}" -g '*.sh' -g '*.mjs' -g '*.js'; then
  echo 'caller-supplied JSON must use fs.readFileSync, not module require()' >&2
  exit 1
fi
REPO_ROOT="$(cd "${ATTACKNET_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

RESULT_SUITES=()
run_node_suite() {
  local name="$1"
  shift
  local output
  output="$(mktemp)"
  node --test "$@" 2>&1 | tee "${output}"
  local tests passed failed skipped
  # Node uses a TAP comment prefix when stdout is not a terminal and an info
  # glyph in its spec reporter. Match the named summary field, not the prefix.
  tests="$(awk '$2 == "tests" {value=$3} END {print value}' "${output}")"
  passed="$(awk '$2 == "pass" {value=$3} END {print value}' "${output}")"
  failed="$(awk '$2 == "fail" {value=$3} END {print value}' "${output}")"
  skipped="$(awk '$2 == "skipped" {value=$3} END {print value}' "${output}")"
  if [[ ! "${tests}" =~ ^[0-9]+$ || ! "${passed}" =~ ^[0-9]+$ \
      || ! "${failed}" =~ ^[0-9]+$ || ! "${skipped}" =~ ^[0-9]+$ \
      || "${tests}" -lt 1 || "${passed}" -ne "${tests}" \
      || "${failed}" -ne 0 || "${skipped}" -ne 0 ]]; then
    rm -f "${output}"
    echo "${name} did not produce an unqualified clean pass: tests=${tests:-missing} passed=${passed:-missing} failed=${failed:-missing} skipped=${skipped:-missing}" >&2
    return 1
  fi
  RESULT_SUITES+=("${name}:${tests}:${passed}:${failed}")
  rm -f "${output}"
}

run_node_suite attacknet-node "${ATTACKNET_DIR}"/*.test.mjs
run_node_suite instrumentation-node "${ATTACKNET_DIR}"/instrumentation/*.test.mjs
run_node_suite observability-node "${ATTACKNET_DIR}"/observability/*.test.mjs
run_node_suite release-node "${ATTACKNET_DIR}"/release/*.test.mjs
bash -n "${ATTACKNET_DIR}"/*.sh
bash -n "${ATTACKNET_DIR}"/observability/*.sh
bash -c 'source "$1/lifecycle.sh"; RUN_DESCRIPTOR=""; ledger_assertion regression pass "{\"value\":1}"' \
  _ "${ATTACKNET_DIR}"
python3 -m py_compile "${ATTACKNET_DIR}/observability/event_bridge.py"
python_output="$(mktemp)"
python3 -m unittest discover -s "${ATTACKNET_DIR}/observability" -p 'test_*.py' 2>&1 | tee "${python_output}"
python_tests="$(awk '/^Ran [0-9]+ tests?/ {value=$2} END {print value}' "${python_output}")"
if [[ ! "${python_tests}" =~ ^[1-9][0-9]*$ ]] || ! grep -qx 'OK' "${python_output}"; then
  rm -f "${python_output}"
  echo 'event-bridge-python did not produce an unqualified clean pass (skips and expected failures are not accepted)' >&2
  exit 1
fi
rm -f "${python_output}"
RESULT_SUITES+=("event-bridge-python:${python_tests}:${python_tests}:0")

rendered="$(mktemp -d)"
trap 'rm -rf "${rendered}"' EXIT
node "${ATTACKNET_DIR}/topology.mjs" \
  --miners=3 --signers=10 --followers=5 --output="${rendered}"
(cd "${REPO_ROOT}/contrib/helm/hacknet/operator" && \
  go run ./cmd/render-check --input "${rendered}/stacksnetwork.json" --expected-actors 31)

RESULT_SUITES+=("offline-operator-workloads:31:31:0")
if [[ -n "${ATTACKNET_OFFLINE_RESULT:-}" ]]; then
  result_args=()
  for result in "${RESULT_SUITES[@]}"; do result_args+=("--suite=${result}"); done
  node "${ATTACKNET_DIR}/release/offline-result.mjs" \
    "--output=${ATTACKNET_OFFLINE_RESULT}" \
    "--source-revision=$(git -C "${REPO_ROOT}" rev-parse HEAD)" \
    "${result_args[@]}"
fi
