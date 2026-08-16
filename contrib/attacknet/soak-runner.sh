#!/usr/bin/env bash
set -euo pipefail

attacknet_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
sample_seconds="${ATTACKNET_SOAK_SAMPLE_SECONDS:-60}"
pod_sample_seconds="${ATTACKNET_SOAK_POD_SAMPLE_SECONDS:-30}"
poll_seconds="${ATTACKNET_SOAK_POLL_SECONDS:-5}"

usage() {
  cat <<'EOF'
usage: soak-runner.sh EVIDENCE_DIR MANIFEST MINIMUM_NEW_BURN_BLOCKS [FAULT_RUN_LIST.json]

Runs a measured Kubernetes attacknet soak. The cadence is first paused and the
target is derived from the first exact paused cohort; a caller cannot claim an
earlier, unobserved start height. A supplied List must contain exactly one
AttacknetRun plus its FaultCampaign templates.
EOF
}

if [ "${1:-}" = --help ] || [ "${1:-}" = -h ]; then usage; exit 0; fi
[ "$#" -ge 3 ] && [ "$#" -le 4 ] || { usage >&2; exit 2; }

evidence_dir="$1"
manifest="$2"
minimum_blocks="$3"
fault_run_file="${4:-}"

[[ "${minimum_blocks}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'MINIMUM_NEW_BURN_BLOCKS must be a positive integer' >&2
  exit 2
}
[[ "${sample_seconds}" =~ ^[1-9][0-9]*$ && "${pod_sample_seconds}" =~ ^[1-9][0-9]*$ \
  && "${poll_seconds}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'soak sampling and poll intervals must be positive integers' >&2
  exit 2
}
[ -r "${manifest}" ] || { echo "manifest is not readable: ${manifest}" >&2; exit 2; }
[ -z "${fault_run_file}" ] || [ -r "${fault_run_file}" ] || {
  echo "fault run List is not readable: ${fault_run_file}" >&2
  exit 2
}

export ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}"
runtime="${attacknet_dir}/runtime-backend.sh"
policy="${attacknet_dir}/burnchain-policy.sh"
lock="${attacknet_dir}/environment-lock.sh"

"${lock}" environment-assert "${network}"
mkdir -p "${evidence_dir}/samples" "${evidence_dir}/resources"

fault_run_name=''
if [ -n "${fault_run_file}" ]; then
  fault_run_name="$(NAMESPACE="${namespace}" NETWORK="${network}" node -e '
    const fs = require("node:fs");
    const document = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const runs = (document.items ?? []).filter(item => item.kind === "AttacknetRun");
    if (document.kind !== "List" || runs.length !== 1) {
      throw new Error("fault run input must be a List containing exactly one AttacknetRun");
    }
    const run = runs[0];
    if (run.metadata?.namespace !== process.env.NAMESPACE || run.spec?.networkRef !== process.env.NETWORK) {
      throw new Error("fault run namespace/networkRef does not match the measured network");
    }
    process.stdout.write(run.metadata.name);
  ' "${fault_run_file}")"
fi

cadence_running=0
pause_after_exit() {
  local status="$?"
  trap - EXIT
  if [ "${cadence_running}" = 1 ]; then
    echo 'soak runner is stopping; requesting an acknowledged burnchain pause' >&2
    ATTACKNET_LOCK_OWNER="soak-runner:$$" "${policy}" pause \
      || echo 'warning: could not pause the burnchain cadence during failure cleanup' >&2
  fi
  exit "${status}"
}
trap pause_after_exit EXIT
trap 'exit 130' INT TERM

bitcoin_height() {
  "${runtime}" exec bitcoin bitcoin-cli -regtest -rpcuser=devnet -rpcpassword=devnet getblockcount
}

capture_cohort() {
  local destination="$1"
  ATTACKNET_MINIMUM_STACKS_HEIGHT=1 "${attacknet_dir}/verify.sh" "${manifest}" snapshot >"${destination}"
}

capture_signer_metrics() {
  local destination="$1" service inventory
  mkdir -p "${destination}"
  inventory="$(node "${attacknet_dir}/manifest-inventory.mjs" "${manifest}" signers)"
  for service in ${inventory}; do
    "${runtime}" exec "${service}" curl --fail --silent http://127.0.0.1:31000/metrics \
      >"${destination}/${service}.txt"
  done
}

capture_exact_paused_cohort() {
  local destination="$1" height_file="$2" deadline=$((SECONDS + 300)) candidate height
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    candidate="${destination}.candidate"
    if capture_cohort "${candidate}"; then
      height="$(bitcoin_height)"
      if node "${attacknet_dir}/soak-evidence.mjs" start \
          "--network=${network}" "--started-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          --minimum-blocks=1 "--bitcoin-height=${height}" "--cohort=${candidate}" \
          --output=/dev/null 2>/dev/null; then
        mv "${candidate}" "${destination}"
        printf '%s\n' "${height}" >"${height_file}"
        return 0
      fi
    fi
    rm -f "${candidate}"
    sleep 5
  done
  echo 'nodes did not reach an exact cohort at the acknowledged paused Bitcoin height within 300s' >&2
  return 1
}

append_cohort_sample() {
  local cohort_path="$1" height="$2" observed_at="$3"
  # JavaScript intentionally consumes the exported environment and positional
  # arguments; shell interpolation inside the program would be unsafe.
  # shellcheck disable=SC2016
  OBSERVED_AT="${observed_at}" BITCOIN_HEIGHT="${height}" node -e '
    const fs = require("node:fs");
    const row = {
      observedAt: process.env.OBSERVED_AT,
      bitcoinHeight: Number(process.env.BITCOIN_HEIGHT),
      cohort: JSON.parse(fs.readFileSync(process.argv[1], "utf8")),
    };
    fs.appendFileSync(process.argv[2], `${JSON.stringify(row)}\n`);
  ' "${cohort_path}" "${evidence_dir}/samples/cohorts.jsonl"
}

capture_pod_sample() {
  local sequence="$1"
  local pods="${evidence_dir}/samples/pods-${sequence}.json"
  local campaigns="${evidence_dir}/samples/campaigns-${sequence}.json"
  local health="${evidence_dir}/samples/pod-health-${sequence}.json"
  "${kubectl_bin}" -n "${namespace}" get pods \
    -l "testing.stacks.org/network=${network}" -o json >"${pods}"
  "${kubectl_bin}" -n "${namespace}" get faultcampaign \
    -l "testing.stacks.org/network=${network}" -o json >"${campaigns}"
  local baseline="${evidence_dir}/samples/pods-000001.json"
  if ! node "${attacknet_dir}/soak-observation.mjs" \
      "${pods}" "${campaigns}" "${baseline}" >"${health}"; then
    cat "${health}" >&2
    echo 'unexplained attacknet Pod readiness failure during measured soak' >&2
    return 1
  fi
  # shellcheck disable=SC2016
  node -e '
    const fs = require("node:fs");
    const row = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    fs.appendFileSync(process.argv[2], `${JSON.stringify(row)}\n`);
  ' "${health}" "${evidence_dir}/samples/pod-health.jsonl"
}

fault_phase() {
  [ -n "${fault_run_name}" ] || return 0
  "${kubectl_bin}" -n "${namespace}" get attacknetrun "${fault_run_name}" \
    -o jsonpath='{.status.phase}' 2>/dev/null || true
}

fail_if_fault_run_terminal_bad() {
  local phase
  phase="$(fault_phase)"
  case "${phase}" in
    Failed|Inconclusive|Paused|Aborted)
      "${kubectl_bin}" -n "${namespace}" get attacknetrun "${fault_run_name}" -o json \
        >"${evidence_dir}/resources/fault-run-failed.json" || true
      echo "deterministic fault run ${fault_run_name} entered ${phase}" >&2
      return 1
      ;;
  esac
}

# Establish an acknowledged pause before measuring the first sample. The
# contract itself rejects drift or a cohort behind Bitcoin, closing the prior
# evidence bug where an unsampled earlier height was treated as the start.
ATTACKNET_LOCK_OWNER="soak-runner:$$" "${policy}" pause
capture_exact_paused_cohort "${evidence_dir}/start-cohort.json" "${evidence_dir}/start-height"
capture_signer_metrics "${evidence_dir}/start-signer-metrics"
start_height="$(<"${evidence_dir}/start-height")"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

start_args=(start "--network=${network}" "--started-at=${started_at}" \
  "--minimum-blocks=${minimum_blocks}" "--bitcoin-height=${start_height}" \
  "--cohort=${evidence_dir}/start-cohort.json" "--output=${evidence_dir}/soak-contract.json")
[ -z "${fault_run_name}" ] || start_args+=("--fault-run=${fault_run_name}")
node "${attacknet_dir}/soak-evidence.mjs" "${start_args[@]}"
cp "${evidence_dir}/start-cohort.json" "${evidence_dir}/samples/cohort-000001.json"
append_cohort_sample "${evidence_dir}/start-cohort.json" "${start_height}" "${started_at}"
sample_count=1
pod_sequence=1
capture_pod_sample "$(printf '%06d' "${pod_sequence}")"

target_height="$(node -e '
  const fs = require("node:fs");
  process.stdout.write(String(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).targetHeight));
' "${evidence_dir}/soak-contract.json")"

ATTACKNET_LOCK_OWNER="soak-runner:$$" "${policy}" run 10 0
cadence_running=1
if [ -n "${fault_run_file}" ]; then
  "${lock}" run "${network}" "soak-runner:$$" deterministic-fault-run -- \
    "${kubectl_bin}" -n "${namespace}" apply -f "${fault_run_file}"
fi

echo "Measured soak started at burn ${start_height}; target is ${target_height}." >&2
next_cohort=$((SECONDS + sample_seconds))
next_pods=$((SECONDS + pod_sample_seconds))
while :; do
  fail_if_fault_run_terminal_bad
  current_height="$(bitcoin_height)"
  if [ "${current_height}" -ge "${target_height}" ]; then break; fi

  if [ "${SECONDS}" -ge "${next_pods}" ]; then
    pod_sequence=$((pod_sequence + 1))
    capture_pod_sample "$(printf '%06d' "${pod_sequence}")"
    next_pods=$((SECONDS + pod_sample_seconds))
  fi

  if [ "${SECONDS}" -ge "${next_cohort}" ]; then
    active_count="$(${kubectl_bin} -n "${namespace}" get faultcampaign \
      -l "testing.stacks.org/network=${network}" -o json | node -e '
        const fs = require("node:fs");
        const terminal = new Set(["Passed", "Failed", "Inconclusive"]);
        const items = JSON.parse(fs.readFileSync(0, "utf8")).items ?? [];
        console.log(items.filter(item => item.spec?.template !== true
          && !terminal.has(item.status?.phase)).length);
      ')"
    if [ "${active_count}" -eq 0 ]; then
      sample_count=$((sample_count + 1))
      cohort_path="${evidence_dir}/samples/cohort-$(printf '%06d' "${sample_count}").json"
      capture_cohort "${cohort_path}"
      append_cohort_sample "${cohort_path}" "${current_height}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    else
      printf '{"observedAt":"%s","bitcoinHeight":%s,"reason":"active-fault-campaign","activeCampaigns":%s}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${current_height}" "${active_count}" \
        >>"${evidence_dir}/samples/cohort-skips.jsonl"
    fi
    next_cohort=$((SECONDS + sample_seconds))
  fi
  sleep "${poll_seconds}"
done

ATTACKNET_LOCK_OWNER="soak-runner:$$" "${policy}" pause
cadence_running=0
capture_exact_paused_cohort "${evidence_dir}/end-cohort.json" "${evidence_dir}/end-height"
capture_signer_metrics "${evidence_dir}/end-signer-metrics"
node "${attacknet_dir}/signer-metric-deltas.mjs" \
  "${evidence_dir}/start-signer-metrics" "${evidence_dir}/end-signer-metrics" \
  "${evidence_dir}/signer-metric-deltas.json"
end_height="$(<"${evidence_dir}/end-height")"
sample_count=$((sample_count + 1))
cp "${evidence_dir}/end-cohort.json" \
  "${evidence_dir}/samples/cohort-$(printf '%06d' "${sample_count}").json"
append_cohort_sample "${evidence_dir}/end-cohort.json" "${end_height}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pod_sequence=$((pod_sequence + 1))
capture_pod_sample "$(printf '%06d' "${pod_sequence}")"

final_fault_phase=''
if [ -n "${fault_run_name}" ]; then
  final_fault_phase="$(fault_phase)"
  [ "${final_fault_phase}" = Passed ] || {
    echo "fault run ${fault_run_name} is ${final_fault_phase:-<missing>} at the soak boundary" >&2
    exit 1
  }
  "${kubectl_bin}" -n "${namespace}" get attacknetrun "${fault_run_name}" -o json \
    >"${evidence_dir}/resources/fault-run.json"
  "${kubectl_bin}" -n "${namespace}" get faultcampaign \
    -l "testing.stacks.org/network=${network}" -o json \
    >"${evidence_dir}/resources/fault-campaigns.json"
fi
"${kubectl_bin}" -n "${namespace}" get pods,pvc,stacksnetwork \
  -l "testing.stacks.org/network=${network}" -o json \
  >"${evidence_dir}/resources/final-network-resources.json"

finish_args=(finish "--contract=${evidence_dir}/soak-contract.json" \
  "--completed-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" "--bitcoin-height=${end_height}" \
  "--cohort=${evidence_dir}/end-cohort.json" "--sample-count=${sample_count}" \
  "--output=${evidence_dir}/result.json")
[ -z "${fault_run_name}" ] || finish_args+=("--fault-run-phase=${final_fault_phase}")
node "${attacknet_dir}/soak-evidence.mjs" "${finish_args[@]}"
cat "${evidence_dir}/result.json"
