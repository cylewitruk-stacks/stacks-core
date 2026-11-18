#!/bin/bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${POC_PROJECT:-stacks-libp2p-scale}"
BASE_COMPOSE="${POC_DIR}/compose.yaml"
GENERATED_COMPOSE="${POC_DIR}/generated/compose.yaml"
MANIFEST="${POC_DIR}/generated/manifest.json"
source "${POC_DIR}/signer-companion-drift.sh"
SOURCE_ROOT="$(cd "${POC_DIR}/../.." && pwd)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${SOAK_EVIDENCE_DIR:-${POC_DIR}/generated/evidence/${run_id}}"
SOAK_NEW_BURN_BLOCKS="${SOAK_NEW_BURN_BLOCKS:-300}"
SOAK_POST_CHAOS_BLOCKS="${SOAK_POST_CHAOS_BLOCKS:-30}"

[[ "${SOAK_NEW_BURN_BLOCKS}" =~ ^[1-9][0-9]*$ ]] || {
  echo "SOAK_NEW_BURN_BLOCKS must be a positive integer" >&2
  exit 2
}
[[ "${SOAK_POST_CHAOS_BLOCKS}" =~ ^[1-9][0-9]*$ ]] || {
  echo "SOAK_POST_CHAOS_BLOCKS must be a positive integer" >&2
  exit 2
}

compose() {
  docker compose -p "${PROJECT}" -f "${BASE_COMPOSE}" -f "${GENERATED_COMPOSE}" "$@"
}

rpc_info() {
  compose exec -T miner-1 curl --fail --silent http://127.0.0.1:20443/v2/info
}

json_number() {
  local field="$1"
  sed -n "s/.*\"${field}\":\([0-9][0-9]*\).*/\1/p"
}

burn_height() {
  rpc_info | json_number burn_block_height
}

capture_network_diagnostics() {
  local destination="$1"
  local service
  mkdir -p "${destination}"
  for service in ${node_services}; do
    compose exec -T "${service}" curl --fail --silent \
      -H 'authorization: 12345' http://127.0.0.1:20443/v3/network/diagnostics \
      >"${destination}/${service}.json"
  done
}

capture_signer_metrics() {
  local destination="$1"
  local signer
  mkdir -p "${destination}"
  for signer in ${signer_services}; do
    compose exec -T "${signer}" curl --fail --silent http://127.0.0.1:31000/metrics \
      >"${destination}/${signer}.txt"
  done
}

assert_signer_lifecycle_evidence() {
  local baseline_dir="$1"
  local final_dir="$2"
  node "${POC_DIR}/signer-lifecycle-evidence.mjs" "${baseline_dir}" "${final_dir}"
}

capture_released_proposal_evidence() {
  local destination="$1"
  local since="$2"
  local signer
  local classification
  : >"${destination}"
  for signer in ${signer_services}; do
    if classification="$(compose logs --no-color --since "${since}" "${signer}" 2>&1 \
      | node "${POC_DIR}/released-proposal-evidence.mjs" "${signer}" --all)"; then
      printf '%s\n' "${classification}" >>"${destination}"
    else
      # This classifier is diagnostic evidence, not an acceptance gate. Keep
      # failures visible without invalidating an otherwise sound long soak.
      printf '{"signer":"%s","classificationError":true}\n' "${signer}" \
        >>"${destination}"
      echo "Warning: could not classify released proposals for ${signer}" >&2
    fi
  done
}

assert_no_stable_window_amplification() {
  local baseline_dir="$1"
  local final_dir="$2"
  local burn_delta="$3"
  local max_events_per_burn="${SOAK_MAX_FAILURE_EVENTS_PER_BURN:-100}"
  node - "${baseline_dir}" "${final_dir}" "${burn_delta}" "${max_events_per_burn}" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [baselineDir, finalDir, burnDeltaText, maxRateText] = process.argv.slice(2);
const burnDelta = Number(burnDeltaText);
const maxRate = Number(maxRateText);
if (!Number.isSafeInteger(burnDelta) || burnDelta < 1 ||
    !Number.isSafeInteger(maxRate) || maxRate < 1) {
  throw new Error('invalid stable-window amplification bound');
}
const counters = [
  'command_queue_full',
  'direct_signer_failures',
  'event_queue_full',
  'outbound_failures',
  'resource_budget_rejections',
  'signer_replay_rejections',
];
const failures = [];
for (const name of fs.readdirSync(baselineDir).filter(name => name.endsWith('.json'))) {
  const before = JSON.parse(fs.readFileSync(path.join(baselineDir, name), 'utf8'));
  const after = JSON.parse(fs.readFileSync(path.join(finalDir, name), 'utf8'));
  const limit = 512 + burnDelta * maxRate;
  for (const counter of counters) {
    const start = Number(before[counter] ?? 0);
    const end = Number(after[counter] ?? 0);
    const delta = Math.max(0, end - start);
    if (delta > limit) failures.push(`${name}:${counter} delta=${delta} limit=${limit}`);
  }
  if (Number(after.validation_queue_depth ?? 0) !== 0) {
    failures.push(`${name}:validation_queue_depth=${after.validation_queue_depth}`);
  }
  if (Number(after.oldest_command_queue_wait_ms ?? 0) > 2_000) {
    failures.push(`${name}:oldest_command_queue_wait_ms=${after.oldest_command_queue_wait_ms}`);
  }
  if (Number(after.direct_signer_deliveries_pending ?? 0) > 8) {
    failures.push(`${name}:direct_signer_deliveries_pending=${after.direct_signer_deliveries_pending}`);
  }
}
if (failures.length) throw new Error(`stable-window retry/queue amplification: ${failures.join(', ')}`);
NODE
}

wait_for_services() {
  local expected_services
  expected_services="$(compose config --services | wc -l | tr -d ' ')"
  local deadline=$((SECONDS + ${SOAK_STARTUP_TIMEOUT_SECONDS:-900}))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    local status_json
    status_json="$(compose ps --all --format json 2>/dev/null || true)"
    if [ -n "${status_json}" ] && node -e '
      const fs = require("node:fs");
      const rows = fs.readFileSync(0, "utf8").trim().split(/\n+/).filter(Boolean).map(JSON.parse);
      const expected = Number(process.argv[1]);
      process.exit(rows.length === expected && rows.every(row =>
        row.State === "running" && (!row.Health || row.Health === "healthy")) ? 0 : 1);
    ' "${expected_services}" <<<"${status_json}"; then
      return 0
    fi
    sleep 3
  done
  echo "PoC services did not become healthy before the soak deadline" >&2
  return 1
}

wait_for_burn() {
  local target="$1"
  local deadline=$((SECONDS + ${SOAK_PROGRESS_TIMEOUT_SECONDS:-10800}))
  local current=0
  local drift_violations=0
  local drift_report=""
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    current="$(burn_height 2>/dev/null || printf 0)"
    if [[ "${current}" =~ ^[0-9]+$ ]] \
      && [ "${current}" -ge "${SIGNER_DRIFT_CHECK_MIN_BURN:-227}" ]; then
      if drift_report="$(signer_companion_drift_report "${SIGNER_MAX_BURN_DRIFT:-2}")"; then
        drift_violations=0
      else
        drift_violations=$((drift_violations + 1))
        if [ "${drift_violations}" -ge "${SIGNER_DRIFT_CONSECUTIVE_FAILURES:-3}" ]; then
          echo "Persistent signer/companion burn-height drift during soak:" >&2
          echo "${drift_report}" >&2
          return 1
        fi
      fi
    fi
    if [[ "${current}" =~ ^[0-9]+$ ]] && [ "${current}" -ge "${target}" ]; then
      printf '%s\n' "${current}"
      return 0
    fi
    sleep 5
  done
  echo "Burnchain did not reach ${target}; last observed ${current}" >&2
  return 1
}

cleanup() {
  if [ "${SOAK_KEEP_FAILED_ENV:-0}" = 1 ] && [ "${soak_succeeded:-0}" -ne 1 ]; then
    echo "Keeping failed environment ${PROJECT} for diagnosis" >&2
    return
  fi
  compose down --remove-orphans ${soak_succeeded:+--volumes} >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "${EVIDENCE_DIR}"
printf 'run_id=%s\nproject=%s\nnew_burn_blocks=%s\npost_chaos_blocks=%s\n' \
  "${run_id}" "${PROJECT}" "${SOAK_NEW_BURN_BLOCKS}" "${SOAK_POST_CHAOS_BLOCKS}" \
  >"${EVIDENCE_DIR}/run.env"

git -C "${SOURCE_ROOT}" rev-parse HEAD >"${EVIDENCE_DIR}/git-head.txt"
git -C "${SOURCE_ROOT}" status --short >"${EVIDENCE_DIR}/git-status.txt"
git -C "${SOURCE_ROOT}" diff --binary HEAD >"${EVIDENCE_DIR}/source.diff"
git -C "${SOURCE_ROOT}" ls-files -co --exclude-standard -z \
  | sort -z \
  | while IFS= read -r -d '' source; do
      if [ -f "${SOURCE_ROOT}/${source}" ]; then
        shasum -a 256 "${SOURCE_ROOT}/${source}"
      fi
    done >"${EVIDENCE_DIR}/source-sha256.txt"

# Archive deterministic proofs for the two low-frequency paths alongside the
# exact-source soak. Runtime chaos must additionally observe a real release.
(cd "${SOURCE_ROOT}" && cargo test -p stacks-signer --features monitoring_prom \
  network::tests::same_envelope_deferral_releases_to_normal_signer_proposal_processing \
  -- --exact) 2>&1 | tee "${EVIDENCE_DIR}/test-deferral-release.log"
(cd "${SOURCE_ROOT}" && cargo test -p stacks-node \
  nakamoto_node::signer_message_processor::unavailable_tests::genuine_validation_rejection_survives_unavailable_reset_and_terminates_round \
  -- --exact) 2>&1 | tee "${EVIDENCE_DIR}/test-genuine-rejection.log"
node --test "${POC_DIR}/topology.test.mjs" \
  "${POC_DIR}/hacknet-topology.test.mjs" \
  "${POC_DIR}/signer-lifecycle-evidence.test.mjs" \
  "${POC_DIR}/released-proposal-evidence.test.mjs" \
  2>&1 | tee "${EVIDENCE_DIR}/test-poc-harness.log"

POC_PROJECT="${PROJECT}" "${POC_DIR}/poc.sh" down --volumes --remove-orphans >/dev/null 2>&1 || true
POC_SIGNERS=10 POC_MINERS=3 POC_FOLLOWERS=5 "${POC_DIR}/poc.sh" generate
cp "${MANIFEST}" "${EVIDENCE_DIR}/manifest.json"
node_services="$(node "${POC_DIR}/manifest-inventory.mjs" "${MANIFEST}" nodes)"
signer_services="$(node "${POC_DIR}/manifest-inventory.mjs" "${MANIFEST}" signers)"
companion_services="$(node "${POC_DIR}/manifest-inventory.mjs" "${MANIFEST}" companions)"
compose config >"${EVIDENCE_DIR}/compose.rendered.yaml"
compose build --pull=false
compose up --detach
wait_for_services
compose images --format json >"${EVIDENCE_DIR}/images.json"

start_info="$(rpc_info)"
printf '%s\n' "${start_info}" >"${EVIDENCE_DIR}/start-info.json"
start_burn="$(json_number burn_block_height <<<"${start_info}")"
start_stacks="$(json_number stacks_tip_height <<<"${start_info}")"
started_at="$(date -u +%FT%TZ)"
[[ "${start_burn}" =~ ^[0-9]+$ ]] || { echo "Missing soak start burn height" >&2; exit 1; }
printf 'start_burn=%s\nstart_stacks=%s\nstarted_at=%s\n' \
  "${start_burn}" "${start_stacks}" "${started_at}" \
  >>"${EVIDENCE_DIR}/run.env"

# Warm through Epoch 4 and require one complete healthy signer round before
# fault injection. The measured 300-block interval still begins at start_burn.
warmup_target=$((start_burn + 70))
if [ "${warmup_target}" -lt 270 ]; then warmup_target=270; fi
wait_for_burn "${warmup_target}" >/dev/null
VERIFY_BURN_HEIGHT="${warmup_target}" VERIFY_TIMEOUT_SECONDS=2400 \
  POC_PROJECT="${PROJECT}" "${POC_DIR}/verify.sh" \
  | tee "${EVIDENCE_DIR}/verify-warmup.log"

# Execute each required failure class once with deterministic, separately
# archived ledgers. A companion-only outage has a longer bounded window that
# covers the maximum 60-second cadence interval plus the accelerated 15-second
# PoC validation timeout, and ends early once abstention is observable.
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1201 \
  CHAOS_TARGETS=companion:1 CHAOS_COMPANION_OUTAGE_SECONDS=90 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-companion.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1202 \
  CHAOS_TARGETS=signer:2 CHAOS_OUTAGE_SECONDS=8 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-signer.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1203 \
  CHAOS_TARGETS=pair:3 CHAOS_OUTAGE_SECONDS=8 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-pair.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1204 \
  CHAOS_TARGETS=pause:follower-1 CHAOS_OUTAGE_SECONDS=8 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-follower.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1205 \
  CHAOS_TARGETS=pause:telemetry-collector CHAOS_OUTAGE_SECONDS=25 \
  CHAOS_ASSERT_BLIND_SPOT=1 CHAOS_LOG="${EVIDENCE_DIR}/chaos-telemetry.log" \
  POC_PROJECT="${PROJECT}" "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1206 \
  CHAOS_TARGETS=pause:miner-2 CHAOS_OUTAGE_SECONDS=8 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-miner.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"
CHAOS_DURATION_SECONDS=1 CHAOS_INTERVAL_SECONDS=0 CHAOS_SEED=1207 \
  CHAOS_TARGETS=cadence:flash CHAOS_OUTAGE_SECONDS=1 \
  CHAOS_LOG="${EVIDENCE_DIR}/chaos-cadence.log" POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/chaos.sh"

chaos_end_burn="$(burn_height)"
capture_network_diagnostics "${EVIDENCE_DIR}/diagnostics-stable-start"
capture_signer_metrics "${EVIDENCE_DIR}/metrics-stable-start"
printf 'chaos_end_burn=%s\nchaos_completed_at=%s\n' \
  "${chaos_end_burn}" "$(date -u +%FT%TZ)" >>"${EVIDENCE_DIR}/run.env"
minimum_target=$((start_burn + SOAK_NEW_BURN_BLOCKS))
recovery_target=$((chaos_end_burn + SOAK_POST_CHAOS_BLOCKS))
final_target="${minimum_target}"
if [ "${recovery_target}" -gt "${final_target}" ]; then final_target="${recovery_target}"; fi
wait_for_burn "${final_target}" >/dev/null
capture_network_diagnostics "${EVIDENCE_DIR}/diagnostics-stable-end"
capture_signer_metrics "${EVIDENCE_DIR}/metrics-stable-end"
assert_no_stable_window_amplification \
  "${EVIDENCE_DIR}/diagnostics-stable-start" \
  "${EVIDENCE_DIR}/diagnostics-stable-end" \
  "$((final_target - chaos_end_burn))"
assert_signer_lifecycle_evidence \
  "${EVIDENCE_DIR}/metrics-stable-start" \
  "${EVIDENCE_DIR}/metrics-stable-end" \
  | tee "${EVIDENCE_DIR}/signer-lifecycle-conservation.json"

VERIFY_START_BURN_HEIGHT="${start_burn}" \
VERIFY_BURN_BLOCK_DELTA="$((final_target - start_burn))" \
VERIFY_REQUIRE_SIGNER_RELEASE=1 \
VERIFY_TIMEOUT_SECONDS=3600 POC_PROJECT="${PROJECT}" \
  "${POC_DIR}/verify.sh" | tee "${EVIDENCE_DIR}/verify-final.log"

end_info="$(rpc_info)"
printf '%s\n' "${end_info}" >"${EVIDENCE_DIR}/end-info.json"
end_burn="$(json_number burn_block_height <<<"${end_info}")"
end_stacks="$(json_number stacks_tip_height <<<"${end_info}")"
printf 'end_burn=%s\nend_stacks=%s\nburn_delta=%s\ncompleted_at=%s\n' \
  "${end_burn}" "${end_stacks}" "$((end_burn - start_burn))" "$(date -u +%FT%TZ)" \
  >>"${EVIDENCE_DIR}/run.env"

compose ps --all --format json >"${EVIDENCE_DIR}/container-health.jsonl"
compose logs --no-color --tail=2000 >"${EVIDENCE_DIR}/final-logs.txt"
for service in ${node_services}; do
  compose exec -T "${service}" curl --fail --silent \
    -H 'authorization: 12345' http://127.0.0.1:20443/v3/network/diagnostics \
    >"${EVIDENCE_DIR}/diagnostics-${service}.json"
done
for service in ${signer_services}; do
  compose exec -T "${service}" curl --fail --silent http://127.0.0.1:31000/metrics \
    >"${EVIDENCE_DIR}/metrics-${service}.txt"
done
for service in ${companion_services}; do
  compose exec -T "${service}" curl --fail --silent http://127.0.0.1:20446/metrics \
    >"${EVIDENCE_DIR}/metrics-${service}.txt"
done
capture_released_proposal_evidence \
  "${EVIDENCE_DIR}/released-proposal-classification.jsonl" "${started_at}"

soak_succeeded=1
compose down --volumes --remove-orphans
trap - EXIT INT TERM
echo "Soak accepted: burn ${start_burn} -> ${end_burn} ($((end_burn - start_burn)) new), evidence ${EVIDENCE_DIR}"
