#!/bin/bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${POC_DIR}/canonical-progress.sh"
PROJECT="${POC_PROJECT:-stacks-libp2p-scale}"
BASE_COMPOSE="${POC_DIR}/compose.yaml"
GENERATED_COMPOSE="${POC_DIR}/generated/compose.yaml"
MANIFEST="${POC_DIR}/generated/manifest.json"
LOG="${CHAOS_LOG:-${POC_DIR}/generated/chaos.log}"
duration="${CHAOS_DURATION_SECONDS:-180}"
interval="${CHAOS_INTERVAL_SECONDS:-20}"
outage="${CHAOS_OUTAGE_SECONDS:-8}"
seed="${CHAOS_SEED:-4242}"

compose() {
  docker compose -p "${PROJECT}" -f "${BASE_COMPOSE}" -f "${GENERATED_COMPOSE}" "$@"
}

manifest_list() {
  local expression="$1"
  node -e "const m=require(process.argv[1]); console.log(${expression})" "${MANIFEST}"
}

burn_height() {
  compose exec -T miner-1 curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:20443/v2/info \
    | sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p'
}

signer_validation_counter() {
  local signer="$1"
  local outcome="$2"
  local value
  value="$(compose exec -T "${signer}" curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:31000/metrics \
    | sed -n "s/^stacks_signer_block_validation_responses{response_type=\"${outcome}\"} \([0-9][0-9.]*\).*$/\1/p" \
    | tail -1)" || return 1
  printf '%s\n' "${value:-0}"
}

wait_for_signer_validation_counter() {
  local signer="$1"
  local outcome="$2"
  local timeout_seconds="${3:-10}"
  local deadline=$((SECONDS + timeout_seconds))
  local value
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if value="$(signer_validation_counter "${signer}" "${outcome}" 2>/dev/null)"; then
      printf '%s\n' "${value}"
      return 0
    fi
    sleep 1
  done
  echo "Timed out reading ${outcome} validation counter from ${signer}" >&2
  return 1
}

signer_deferred_counter() {
  local signer="$1"
  local resolution="$2"
  local value
  value="$(compose exec -T "${signer}" curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:31000/metrics \
    | awk -v base='stacks_signer_deferred_miner_authorizations_resolved' \
      -v labels="{resolution=\"${resolution}\"}" \
      '$1 == base labels || $1 == base "_total" labels { print $2 }' \
    | tail -1)" || return 1
  printf '%s\n' "${value:-0}"
}

wait_for_signer_deferred_counter() {
  local signer="$1"
  local resolution="$2"
  local timeout_seconds="${3:-10}"
  local deadline=$((SECONDS + timeout_seconds))
  local value
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if value="$(signer_deferred_counter "${signer}" "${resolution}" 2>/dev/null)"; then
      printf '%s\n' "${value}"
      return 0
    fi
    sleep 1
  done
  echo "Timed out reading deferred ${resolution} counter from ${signer}" >&2
  return 1
}

signer_deferred_admitted_counter() {
  local signer="$1"
  local value
  value="$(compose exec -T "${signer}" curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:31000/metrics \
    | awk '$1 == "stacks_signer_deferred_miner_authorizations_admitted" || $1 == "stacks_signer_deferred_miner_authorizations_admitted_total" { print $2 }' \
    | tail -1)" || return 1
  printf '%s\n' "${value:-0}"
}

signer_deferred_observation_counter() {
  local signer="$1"
  local observation="$2"
  local value
  value="$(compose exec -T "${signer}" curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:31000/metrics \
    | awk -v base='stacks_signer_deferred_miner_authorization_observations' \
      -v labels="{observation=\"${observation}\"}" \
      '$1 == base labels || $1 == base "_total" labels { print $2 }' \
    | tail -1)" || return 1
  printf '%s\n' "${value:-0}"
}

assert_released_proposal_reached_bounded_terminal() {
  local signer="$1"
  local since="$2"
  compose logs --no-color --since "${since}" --tail=20000 "${signer}" 2>&1 \
    | node "${POC_DIR}/released-proposal-evidence.mjs" "${signer}"
}

chain_snapshot() {
  local info
  local burn
  local height
  local tip
  info="$(compose exec -T miner-1 curl --fail --silent \
    --connect-timeout "${CHAOS_CONNECT_TIMEOUT_SECONDS:-2}" \
    --max-time "${CHAOS_RPC_TIMEOUT_SECONDS:-5}" \
    http://127.0.0.1:20443/v2/info)" \
    || return 1
  burn="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${info}")"
  height="$(sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${info}")"
  tip="$(sed -n 's/.*"stacks_tip":"\([0-9a-f][0-9a-f]*\)".*/\1/p' <<<"${info}")"
  [[ "${burn}" =~ ^[0-9]+$ ]] || return 1
  [[ "${height}" =~ ^[0-9]+$ ]] || return 1
  [[ "${tip}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s %s %s\n' "${burn}" "${height}" "${tip}"
}

wait_for_chain_snapshot() {
  local deadline=$((SECONDS + ${1:-30}))
  local snapshot
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if snapshot="$(chain_snapshot 2>/dev/null)"; then
      printf '%s\n' "${snapshot}"
      return 0
    fi
    sleep 1
  done
  return 1
}

current_tenure_miner() {
  local height="$1"
  local index
  for index in $(seq 1 "${miner_count}"); do
    if compose logs --no-color --since 2m "miner-${index}" 2>&1 \
      | grep -F "burn_height: ${height}," \
      | grep -Fq 'won_sortition?: true'; then
      printf 'miner-%s\n' "${index}"
      return 0
    fi
  done
  return 1
}

assert_authenticated_blind_spot() {
  compose exec -T observer node -e '
    const base = "http://127.0.0.1:4319";
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    (async () => {
      const login = await fetch(`${base}/api/session/login`, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
          email: process.env.STACKS_OBSERVER_DEV_EMAIL,
          password: "stacks123",
        }),
      });
      if (!login.ok) throw new Error(`observer login returned ${login.status}`);
      const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const response = await fetch(`${base}/api/federation/snapshot`, {headers: {cookie}});
        if (!response.ok) throw new Error(`snapshot returned ${response.status}`);
        const snapshot = await response.json();
        if (snapshot.incidents?.some(incident => incident.kind === "telemetry-blind-spot")) {
          console.log(`authenticated observer exposed ${snapshot.incidents.filter(incident => incident.kind === "telemetry-blind-spot").length} telemetry blind spot(s)`);
          return;
        }
        await sleep(1_000);
      }
      throw new Error("authenticated observer did not expose the collector outage as a telemetry blind spot");
    })().catch(error => { console.error(error); process.exit(1); });
  '
}

active=()
recover() {
  if [ "${#active[@]}" -gt 0 ]; then
    # Resolve and operate on only the selected containers. `docker compose
    # start` traverses declared dependencies and can fail companion recovery
    # merely because the independently restarting cadence controller is still
    # unhealthy. Direct unpause+start remains idempotent for both paused and
    # stopped targets without broadening the chaos failure domain.
    local service
    local container_id
    for service in "${active[@]}"; do
      container_id="$(compose ps --all -q "${service}")"
      [[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] || {
        echo "Could not resolve chaos target container: ${service}" >&2
        return 1
      }
      docker unpause "${container_id}" >/dev/null 2>&1 || true
      docker start "${container_id}" >/dev/null
    done
    local deadline=$((SECONDS + ${CHAOS_RECOVERY_TIMEOUT_SECONDS:-90}))
    local state
    while true; do
      local ready=true
      for service in "${active[@]}"; do
        container_id="$(compose ps -q "${service}")"
        state="$(docker inspect --format '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${container_id}" 2>/dev/null || true)"
        if [ "${state}" != 'true|none' ] && [ "${state}" != 'true|healthy' ]; then
          ready=false
          break
        fi
      done
      if [ "${ready}" = true ]; then break; fi
      if [ "${SECONDS}" -ge "${deadline}" ]; then
        echo "Chaos target failed to become healthy after recovery: ${active[*]}" >&2
        return 1
      fi
      sleep 1
    done
    active=()
  fi
}
cleanup() {
  recover || true
}
trap cleanup EXIT INT TERM

signer_count="$(manifest_list 'm.signerCount')"
miner_count="$(manifest_list 'm.minerCount')"
follower_count="$(manifest_list 'm.followerCount')"
targets=()
for index in $(seq 1 "${signer_count}"); do
  targets+=("companion:${index}" "signer:${index}" "pair:${index}")
done
for index in $(seq 1 "${follower_count}"); do targets+=("pause:follower-${index}"); done
if [ "${miner_count}" -gt 1 ]; then
  targets+=("pause:tenure-miner")
  for index in $(seq 2 "${miner_count}"); do targets+=("pause:miner-${index}"); done
fi
targets+=("pause:telemetry-collector")
targets+=("cadence:flash" "cadence:slow")

if [ -n "${CHAOS_TARGETS:-}" ]; then
  IFS=',' read -ra requested_targets <<<"${CHAOS_TARGETS}"
  for requested in "${requested_targets[@]}"; do
    allowed=false
    for candidate in "${targets[@]}"; do
      if [ "${requested}" = "${candidate}" ]; then
        allowed=true
        break
      fi
    done
    if [ "${allowed}" != true ]; then
      echo "CHAOS_TARGETS contains a non-allowlisted target: ${requested}" >&2
      exit 2
    fi
  done
  targets=("${requested_targets[@]}")
fi

RANDOM="${seed}"
started="${SECONDS}"
printf 'seed=%s duration=%s interval=%s outage=%s\n' "${seed}" "${duration}" "${interval}" "${outage}" >"${LOG}"
while [ $((SECONDS - started)) -lt "${duration}" ]; do
  if ! read -r before before_stacks before_tip \
    < <(wait_for_chain_snapshot "${CHAOS_SNAPSHOT_TIMEOUT_SECONDS:-30}"); then
    echo "Unable to establish a canonical Stacks baseline before disruption" >&2
    exit 1
  fi
  target="${targets[$((RANDOM % ${#targets[@]}))]}"
  kind="${target%%:*}"
  value="${target#*:}"
  target_label="${target}"
  companion_signer=""
  disruption_started_at="$(date -u +%FT%TZ)"
  abstained_before=0
  accepted_before=0
  rejected_before=0
  if [ "${kind}" = pause ] && [ "${value}" = tenure-miner ]; then
    value="$(current_tenure_miner "${before}")" || {
      printf '%s disruption_skipped=%s burn=%s reason=no-current-sortition-winner\n' \
        "$(date -u +%FT%TZ)" "${target}" "${before}" | tee -a "${LOG}"
      sleep "${interval}"
      continue
    }
    target_label="${target}(${value})"
  fi
  if [ "${kind}" = cadence ]; then
    active=()
    if [ "${value}" = flash ]; then
      compose kill -s USR1 bitcoin-miner >/dev/null
    else
      compose kill -s USR2 bitcoin-miner >/dev/null
    fi
  elif [ "${kind}" = companion ]; then
    companion_signer="signer-${value}"
    abstained_before="$(wait_for_signer_validation_counter "${companion_signer}" abstained)"
    accepted_before="$(wait_for_signer_validation_counter "${companion_signer}" accepted)"
    rejected_before="$(wait_for_signer_validation_counter "${companion_signer}" rejected)"
    released_before="$(wait_for_signer_deferred_counter "${companion_signer}" released)"
    admitted_before="$(signer_deferred_admitted_counter "${companion_signer}")"
    observation_retries_before="$(signer_deferred_observation_counter "${companion_signer}" retry)"
    active=("signer-node-${value}")
    compose pause "${active[@]}" >/dev/null
    # Exercise the unavailable path, not merely a container pause. Interrupt
    # the cadence controller's current bounded sleep so a fresh sortition and
    # proposal arrive while the companion is unavailable.
    compose kill -s USR1 bitcoin-miner >/dev/null
  elif [ "${kind}" = signer ]; then
    active=("signer-${value}")
    compose stop "${active[@]}" >/dev/null
  elif [ "${kind}" = pair ]; then
    # One signer and its companion node fail as one operator failure domain.
    # With the generated weight schedule, no single pair reaches one third of
    # total signer weight, so this exercises recovery without deliberately
    # destroying quorum.
    active=("signer-${value}" "signer-node-${value}")
    compose stop "${active[@]}" >/dev/null
  else
    active=("${value}")
    compose pause "${active[@]}" >/dev/null
  fi
  printf '%s disrupt=%s burn_before=%s\n' "${disruption_started_at}" "${target_label}" "${before}" | tee -a "${LOG}"
  if [ "${kind}" != cadence ]; then
    effective_outage="${outage}"
    if [ "${kind}" = companion ] \
      && [ "${effective_outage}" -lt "${CHAOS_COMPANION_OUTAGE_SECONDS:-90}" ]; then
      effective_outage="${CHAOS_COMPANION_OUTAGE_SECONDS:-90}"
    fi
    if [ "${kind}" = companion ]; then
      # Cadence entropy permits a 60-second Bitcoin interval, so a fixed short
      # sleep can contain no proposal at all. Hold the outage until its
      # behavioural assertion is observable or the bounded deadline expires,
      # and periodically request another bounded flash interval. A flash only
      # advances Bitcoin through the cadence controller; it does not create a
      # Stacks proposal, so several sortitions may be required before one
      # crosses this signer's canonically-pending path.
      abstention_deadline=$((SECONDS + effective_outage))
      companion_flash_interval="${CHAOS_COMPANION_FLASH_SECONDS:-15}"
      [[ "${companion_flash_interval}" =~ ^[1-9][0-9]*$ ]] || {
        echo "CHAOS_COMPANION_FLASH_SECONDS must be a positive integer" >&2
        exit 1
      }
      next_companion_flash=$((SECONDS + companion_flash_interval))
      abstained_after="${abstained_before}"
      admitted_after="${admitted_before}"
      while [ "${SECONDS}" -lt "${abstention_deadline}" ]; do
        abstained_after="$(wait_for_signer_validation_counter "${companion_signer}" abstained 5)"
        admitted_after="$(signer_deferred_admitted_counter "${companion_signer}")"
        if awk -v before="${abstained_before}" -v after="${abstained_after}" \
          'BEGIN { exit !(after > before) }' \
          && awk -v before="${admitted_before}" -v after="${admitted_after}" \
            'BEGIN { exit !(after > before) }'; then
          break
        fi
        if [ "${SECONDS}" -ge "${next_companion_flash}" ]; then
          compose kill -s USR1 bitcoin-miner >/dev/null
          next_companion_flash=$((SECONDS + companion_flash_interval))
        fi
        sleep 2
      done

      # A deferral can occur at the very end of the bounded outage while the
      # Prometheus mirror is between refreshes. Keep the companion paused for
      # a short observation-only grace period so the behavioural assertion
      # cannot race a counter that has already changed in the network service.
      # No additional sortitions are forced here, and the default 15 seconds
      # keeps recovery comfortably inside the 120-second proposal lifetime.
      counter_settle_seconds="${CHAOS_COUNTER_SETTLE_SECONDS:-15}"
      [[ "${counter_settle_seconds}" =~ ^[0-9]+$ ]] || {
        echo "CHAOS_COUNTER_SETTLE_SECONDS must be a non-negative integer" >&2
        exit 1
      }
      counter_settle_deadline=$((SECONDS + counter_settle_seconds))
      while [ "${SECONDS}" -lt "${counter_settle_deadline}" ]; do
        if awk -v before="${abstained_before}" -v after="${abstained_after}" \
          'BEGIN { exit !(after > before) }' \
          && awk -v before="${admitted_before}" -v after="${admitted_after}" \
            'BEGIN { exit !(after > before) }'; then
          break
        fi
        abstained_after="$(wait_for_signer_validation_counter "${companion_signer}" abstained 5)"
        admitted_after="$(signer_deferred_admitted_counter "${companion_signer}")"
        sleep 1
      done
    else
      sleep "${effective_outage}"
    fi
    if [ "${value}" = telemetry-collector ] && [ "${CHAOS_ASSERT_BLIND_SPOT:-0}" = 1 ]; then
      assert_authenticated_blind_spot | tee -a "${LOG}"
    fi
    if [ "${kind}" = companion ]; then
      abstained_after="$(wait_for_signer_validation_counter "${companion_signer}" abstained)"
      rejected_after="$(wait_for_signer_validation_counter "${companion_signer}" rejected)"
      admitted_after="$(signer_deferred_admitted_counter "${companion_signer}")"
      observation_retries_after="$(signer_deferred_observation_counter "${companion_signer}" retry)"
      lifecycle_settle_deadline=$((SECONDS + counter_settle_seconds))
      while [ "${SECONDS}" -lt "${lifecycle_settle_deadline}" ]; do
        if awk -v before="${admitted_before}" -v after="${admitted_after}" \
          'BEGIN { exit !(after > before) }'; then
          break
        fi
        sleep 1
        admitted_after="$(signer_deferred_admitted_counter "${companion_signer}")"
        observation_retries_after="$(signer_deferred_observation_counter "${companion_signer}" retry)"
      done
      if ! awk -v before="${abstained_before}" -v after="${abstained_after}" 'BEGIN { exit !(after > before) }'; then
        echo "Companion-only outage produced no signer abstention (${abstained_before} -> ${abstained_after})" >&2
        exit 1
      fi
      if ! awk -v before="${rejected_before}" -v after="${rejected_after}" 'BEGIN { exit !(after == before) }'; then
        echo "Companion-only outage overlapped a validation rejection (${rejected_before} -> ${rejected_after}); proposal correlation is required before classifying it" >&2
        exit 1
      fi
      # A failed application-queue delivery is retried with bounded exponential
      # backoff. Keep a deliberately generous per-admission ceiling so this
      # behavioural test still tolerates a busy signer, while making the old
      # 100 ms retry loop (hundreds of attempts per outage) impossible to miss.
      if ! awk -v before="${admitted_before}" -v after="${admitted_after}" \
        'BEGIN { exit !(after > before) }'; then
        echo "Companion-only outage produced no canonically-pending signer deferral (${admitted_before} -> ${admitted_after})" >&2
        exit 1
      fi
      if ! awk -v admitted_before="${admitted_before}" -v admitted_after="${admitted_after}" \
        -v retries_before="${observation_retries_before}" -v retries_after="${observation_retries_after}" \
        'BEGIN {
          admitted_delta = admitted_after - admitted_before;
          retry_delta = retries_after - retries_before;
          ceiling = 32 * (admitted_delta + 1);
          exit !(retry_delta >= 0 && retry_delta <= ceiling);
        }'; then
        echo "Deferred-observation retries exceeded the bounded outage budget: admitted ${admitted_before} -> ${admitted_after}, retries ${observation_retries_before} -> ${observation_retries_after}" >&2
        exit 1
      fi
      printf '%s abstention=%s signer=%s before=%s after=%s false_rejections=0\n' \
        "$(date -u +%FT%TZ)" "${target_label}" "${companion_signer}" \
        "${abstained_before}" "${abstained_after}" | tee -a "${LOG}"
      printf '%s deferred_retry_budget=%s signer=%s admitted_before=%s admitted_after=%s retries_before=%s retries_after=%s\n' \
        "$(date -u +%FT%TZ)" "${target_label}" "${companion_signer}" \
        "${admitted_before}" "${admitted_after}" \
        "${observation_retries_before}" "${observation_retries_after}" | tee -a "${LOG}"
    fi
    recover
  fi

  cadence_allowance=0
  if [ "${kind}" = cadence ] && [ "${value}" = slow ]; then
    cadence_allowance="${CHAOS_SLOW_INTERVAL:-90}"
  fi
  deadline=$((SECONDS + interval + cadence_allowance + 120))
  after="${before}"
  after_stacks="${before_stacks}"
  after_tip="${before_tip}"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if read -r after after_stacks after_tip < <(chain_snapshot 2>/dev/null) \
      && { [ "${kind}" != cadence ] || [ "${after}" -gt "${before}" ]; } \
      && canonical_tip_advanced \
        "${before_stacks}" "${before_tip}" "${after_stacks}" "${after_tip}"; then
      break
    fi
    sleep 2
  done
  if { [ "${kind}" = cadence ] && [ "${after}" -le "${before}" ]; } \
    || ! canonical_tip_advanced \
      "${before_stacks}" "${before_tip}" "${after_stacks}" "${after_tip}"; then
    printf '%s recovery_failed=%s burn_before=%s burn_after=%s stacks_before=%s stacks_after=%s\n' \
      "$(date -u +%FT%TZ)" "${target_label}" "${before}" "${after:-unknown}" \
      "${before_stacks}" "${after_stacks:-unknown}" | tee -a "${LOG}" >&2
    exit 1
  fi
  printf '%s recovered=%s burn_after=%s stacks_after=%s\n' \
    "$(date -u +%FT%TZ)" "${target_label}" "${after}" "${after_stacks}" | tee -a "${LOG}"
  if [ "${kind}" = companion ]; then
    rejoin_deadline=$((SECONDS + ${CHAOS_REJOIN_TIMEOUT_SECONDS:-180}))
    accepted_after="${accepted_before}"
    released_after="${released_before}"
    while [ "${SECONDS}" -lt "${rejoin_deadline}" ]; do
      accepted_after="$(wait_for_signer_validation_counter "${companion_signer}" accepted 5)"
      released_after="$(wait_for_signer_deferred_counter "${companion_signer}" released 5)"
      if awk -v before="${accepted_before}" -v after="${accepted_after}" 'BEGIN { exit !(after > before) }' \
        && awk -v before="${released_before}" -v after="${released_after}" 'BEGIN { exit !(after > before) }'; then
        break
      fi
      sleep 2
    done
    if ! awk -v before="${accepted_before}" -v after="${accepted_after}" 'BEGIN { exit !(after > before) }'; then
      echo "Recovered companion did not rejoin successful validation" >&2
      exit 1
    fi
    if ! awk -v before="${released_before}" -v after="${released_after}" 'BEGIN { exit !(after > before) }'; then
      echo "Recovered companion did not release a held canonical-view proposal (${released_before} -> ${released_after})" >&2
      exit 1
    fi
    terminal_deadline=$((SECONDS + ${CHAOS_RELEASE_TERMINAL_TIMEOUT_SECONDS:-10}))
    released_processing=""
    while [ "${SECONDS}" -lt "${terminal_deadline}" ]; do
      if released_processing="$(assert_released_proposal_reached_bounded_terminal \
        "${companion_signer}" "${disruption_started_at}")"; then
        break
      fi
      sleep 2
    done
    if [ -z "${released_processing}" ] \
      && [ "${CHAOS_REQUIRE_RELEASE_TERMINAL:-0}" = 1 ]; then
      echo "Released proposal did not reach companion processing or a canonical bounded terminal outcome" >&2
      exit 1
    fi
    printf '%s rejoined=%s signer=%s accepted_before=%s accepted_after=%s released_before=%s released_after=%s\n' \
      "$(date -u +%FT%TZ)" "${target_label}" "${companion_signer}" \
      "${accepted_before}" "${accepted_after}" "${released_before}" "${released_after}" | tee -a "${LOG}"
    printf '%s released_processing=%s\n' "$(date -u +%FT%TZ)" \
      "${released_processing:-not-observed-within-bound}" | tee -a "${LOG}"
  fi
  sleep "${interval}"
done

if read -r final_burn final_stacks _ < <(wait_for_chain_snapshot 30); then
  printf '%s chaos_complete=true burn=%s stacks=%s\n' \
    "$(date -u +%FT%TZ)" "${final_burn}" "${final_stacks}" | tee -a "${LOG}"
else
  echo "Chaos completed but the canonical Stacks view is unavailable" >&2
  exit 1
fi
