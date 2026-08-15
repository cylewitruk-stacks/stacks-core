#!/bin/bash
set -Eeuo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
NETWORK="${KUBE_NETWORK:-attacknet}"
TIMEOUT="${HACKNET_TIMEOUT_SECONDS:-900}"
AUTO_START_BURNCHAIN="${ATTACKNET_AUTO_START_BURNCHAIN:-1}"
STARTUP_SETTLE_SECONDS="${ATTACKNET_STARTUP_SETTLE_SECONDS:-5}"
BOOTSTRAP_INTERVAL_SECONDS="${ATTACKNET_BOOTSTRAP_INTERVAL_SECONDS:-2}"
OBSERVABILITY_ENABLED="${ATTACKNET_OBSERVABILITY_ENABLED:-1}"
OBSERVABILITY_STORAGE_PREFLIGHT="${ATTACKNET_OBSERVABILITY_STORAGE_PREFLIGHT:-1}"
LOCAL_ACCESS_ENABLED="${ATTACKNET_LOCAL_ACCESS_ENABLED:-1}"
CHAOS_DASHBOARD_LOCAL_ACCESS_ENABLED="${ATTACKNET_CHAOS_DASHBOARD_LOCAL_ACCESS_ENABLED:-1}"
RUN_DESCRIPTOR=""
RUN_ID="${ATTACKNET_RUN_ID:-}"
RUN_SEED="${ATTACKNET_RUN_SEED:-}"
ENVIRONMENT_LOCK="${ATTACKNET_DIR}/environment-lock.sh"

[[ "${NETWORK}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "invalid Kubernetes network name: ${NETWORK}" >&2
  exit 2
}
[[ "${NAMESPACE}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "invalid Kubernetes namespace: ${NAMESPACE}" >&2
  exit 2
}

ledger_append() {
  local type="$1" payload="$2"
  [ -n "${RUN_DESCRIPTOR}" ] || return 0
  node "${ATTACKNET_DIR}/run-ledger.mjs" append "${RUN_DESCRIPTOR}" "${type}" "${payload}" >/dev/null
}

ledger_assertion() {
  local assertion="$1" status="$2" details="${3:-}" payload
  [ -n "${details}" ] || details='{}'
  payload="$(ASSERTION="${assertion}" STATUS="${status}" DETAILS="${details}" node -e '
    console.log(JSON.stringify({
      assertion: process.env.ASSERTION,
      status: process.env.STATUS,
      details: JSON.parse(process.env.DETAILS),
    }));
  ')"
  ledger_append assertion-result "${payload}"
}

ledger_cadence() {
  local from="$1" to="$2" reason="$3" requested_height="${4:-}" observed_height="${5:-}" payload
  payload="$(FROM="${from}" TO="${to}" REASON="${reason}" REQUESTED_HEIGHT="${requested_height}" OBSERVED_HEIGHT="${observed_height}" node -e '
    const value = {policy: "burnchain", from: process.env.FROM, to: process.env.TO, reason: process.env.REASON};
    if (process.env.REQUESTED_HEIGHT) value.requestedHeight = Number(process.env.REQUESTED_HEIGHT);
    if (process.env.OBSERVED_HEIGHT) value.observedHeight = Number(process.env.OBSERVED_HEIGHT);
    console.log(JSON.stringify(value));
  ')"
  ledger_append cadence-transition "${payload}"
}

ledger_refresh_context() {
  [ -n "${RUN_DESCRIPTOR}" ] || return 0
  node "${ATTACKNET_DIR}/run-ledger.mjs" context \
    "${RUN_DESCRIPTOR}" "${NAMESPACE}" "${NETWORK}" | kubectl apply -f - >/dev/null
}

ledger_capture_runtime() {
  local artifacts network_json children_json admitted_json pods_json
  [ -n "${RUN_DESCRIPTOR}" ] || return 0
  artifacts="$(dirname "${RUN_DESCRIPTOR}")/run-artifacts"
  mkdir -p "${artifacts}"
  network_json="${artifacts}/stacksnetwork.admitted.json"
  children_json="${artifacts}/children.admitted.json"
  admitted_json="${artifacts}/kubernetes.admitted.json"
  pods_json="${artifacts}/pods.admitted.json"
  kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o json >"${network_json}"
  kubectl -n "${NAMESPACE}" get statefulsets,services,configmaps,pods \
    -l "testing.stacks.org/network=${NETWORK}" -o json >"${children_json}"
  kubectl -n "${NAMESPACE}" get pods \
    -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor" -o json >"${pods_json}"
  node -e '
    const fs=require("node:fs");
    const network=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const children=JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
    console.log(JSON.stringify({apiVersion:"v1",kind:"List",items:[network,...children.items]}, null, 2));
  ' "${network_json}" "${children_json}" >"${admitted_json}"
  node "${ATTACKNET_DIR}/run-ledger.mjs" resolve \
    "${RUN_DESCRIPTOR}" "${admitted_json}" "${pods_json}" >/dev/null
  ledger_refresh_context
}

ledger_export() {
  local destination="$1"
  [ -n "${RUN_DESCRIPTOR}" ] || return 0
  node "${ATTACKNET_DIR}/run-ledger.mjs" export "${RUN_DESCRIPTOR}" "${destination}" >/dev/null
}

locate_ledger() {
  node "${ATTACKNET_DIR}/run-ledger.mjs" locate \
    "--namespace=${NAMESPACE}" "--network=${NETWORK}" 2>/dev/null
}

wait_ready() {
  local deadline=$((SECONDS + TIMEOUT))
  local phase desired ready generation observed
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    read -r phase desired ready generation observed < <(kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" \
      -o jsonpath='{.status.phase}{" "}{.status.desiredActors}{" "}{.status.readyActors}{" "}{.metadata.generation}{" "}{.status.observedGeneration}{"\n"}' \
      2>/dev/null || true)
    if [ "${phase:-}" = Ready ] && [ -n "${desired:-}" ] && [ "${desired}" = "${ready:-}" ] \
      && [ "${generation:-}" = "${observed:-}" ]; then
      printf 'Ready %s/%s\n' "${ready}" "${desired}"
      return 0
    fi
    if [ "${phase:-}" = Degraded ]; then
      kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o jsonpath='{.status.message}{"\n"}' >&2 || true
    fi
    sleep 3
  done
  echo "${NETWORK} did not become Ready within ${TIMEOUT}s" >&2
  kubectl -n "${NAMESPACE}" describe stacksnetwork "${NETWORK}" >&2 || true
  kubectl -n "${NAMESPACE}" get pods -l "testing.stacks.org/network=${NETWORK}" -o wide >&2 || true
  return 1
}

wait_deleted() {
  local deadline=$((SECONDS + TIMEOUT))
  local owner remaining
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    owner="$(kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o name 2>/dev/null || true)"
    remaining="$(kubectl -n "${NAMESPACE}" get pods,pvc,deployments,statefulsets,daemonsets,services,configmaps,secrets,serviceaccounts,roles,rolebindings \
      -l "testing.stacks.org/network=${NETWORK},!testing.stacks.org/artifact" -o name 2>/dev/null || true)"
    if [ -z "${owner}" ] && [ -z "${remaining}" ]; then
      echo "Deleted ${NETWORK} and all labeled children/PVCs"
      return 0
    fi
    sleep 2
  done
  echo "resources survived deletion of ${NETWORK}:" >&2
  [ -z "${owner}" ] || printf '%s\n' "${owner}" >&2
  printf '%s\n' "${remaining}" >&2
  return 1
}

wait_bootstrap_foundation_ready() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT))
  local actors total_expected statefulsets statefulset_count active_expected pod_count unready generation observed_generation
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" bootstrap-foundation)"
  total_expected="$(node -e '
    const fs = require("node:fs");
    console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).workloads.length);
  ' "${manifest}")"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    # Count only operator-managed actor Pods.  Observability and other harness
    # workloads deliberately share the network label but are not represented
    # in manifest.workloads and must not block protocol activation.
    pod_count="$(kubectl -n "${NAMESPACE}" get pods \
      -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | wc -w | tr -d ' ')"
    statefulsets="$(kubectl -n "${NAMESPACE}" get statefulsets \
      -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor" \
      -o json 2>/dev/null || echo '{"items":[]}')"
    statefulset_count="$(jq -r '.items | length' <<<"${statefulsets}")"
    active_expected="$(jq -r '[.items[] | select((.spec.replicas // 0) > 0)] | length' <<<"${statefulsets}")"
    read -r generation observed_generation < <(kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" \
      -o jsonpath='{.metadata.generation}{" "}{.status.observedGeneration}{"\n"}' 2>/dev/null || true)
    unready="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" unready ${actors} 2>/dev/null || true)"
    if [ -n "${generation:-}" ] && [ "${generation}" = "${observed_generation:-}" ] \
      && [ "${statefulset_count}" = "${total_expected}" ] \
      && [ "${pod_count}" = "${active_expected}" ] && [ -z "${unready}" ]; then
      printf 'Bootstrap foundation Ready (%s actors); %s/%s active Pods, %s/%s StatefulSets admitted\n' \
        "$(wc -w <<<"${actors}" | tr -d ' ')" "${pod_count}" "${active_expected}" \
        "${statefulset_count}" "${total_expected}"
      return 0
    fi
    sleep 3
  done
  echo "${NETWORK} bootstrap foundation did not become Ready within ${TIMEOUT}s; generation=${observed_generation:-0}/${generation:-0}, StatefulSets=${statefulset_count:-0}/${total_expected}, active Pods=${pod_count:-0}/${active_expected:-0}, unready: ${unready:-unknown}" >&2
  return 1
}

wait_actor_group_ready() {
  local manifest="$1" group="$2" deadline=$((SECONDS + TIMEOUT))
  local actors unready
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" "${group}")"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    unready="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" unready ${actors} 2>/dev/null || true)"
    if [ -z "${unready}" ]; then
      printf '%s Ready (%s actors)\n' "${group}" "$(wc -w <<<"${actors}" | tr -d ' ')"
      return 0
    fi
    sleep 3
  done
  echo "${NETWORK} group ${group} did not become Ready within ${TIMEOUT}s; unready: ${unready:-unknown}" >&2
  return 1
}

manifest_protocol_value() {
  local manifest="$1" key="$2"
  node -e '
    const fs = require("node:fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const value = manifest.protocol?.[process.argv[2]];
    if (!Number.isSafeInteger(value) || value < 0) process.exit(2);
    process.stdout.write(String(value));
  ' "${manifest}" "${key}"
}

clock_status_value() {
  local key="$1"
  ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
    "${ATTACKNET_DIR}/runtime-backend.sh" exec bitcoin-miner \
    sed -n "s/^${key}=//p" /tmp/hacknet-burnchain-clock.env 2>/dev/null | tail -1
}

wait_clock_paused_at() {
  local target="$1" deadline=$((SECONDS + TIMEOUT)) height state
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    height="$(clock_status_value bitcoin_height || true)"
    state="$(clock_status_value state || true)"
    if [ "${height}" = "${target}" ] && [ "${state}" = paused ]; then
      printf 'Burnchain paused exactly at height %s\n' "${target}"
      return 0
    fi
    if [[ "${height}" =~ ^[0-9]+$ ]] && [ "${height}" -gt "${target}" ]; then
      echo "burnchain overshot phase barrier ${target}; observed ${height}" >&2
      return 1
    fi
    sleep 1
  done
  echo "burnchain did not pause at height ${target} within ${TIMEOUT}s (height=${height:-unknown}, state=${state:-unknown})" >&2
  return 1
}

wait_nodes_at_burn_height() {
  local manifest="$1" group="$2" target="$3" deadline=$((SECONDS + TIMEOUT))
  local actors actor info height lagging
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" "${group}")"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    lagging=""
    for actor in ${actors}; do
      info="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec "${actor}" \
        curl --fail --silent --max-time 3 http://127.0.0.1:20443/v2/info 2>/dev/null || true)"
      height="$(printf '%s' "${info}" | node -e '
        let raw = ""; process.stdin.on("data", chunk => raw += chunk);
        process.stdin.on("end", () => {
          try { process.stdout.write(String(JSON.parse(raw).burn_block_height ?? "")); } catch {}
        });
      ')"
      if ! [[ "${height}" =~ ^[0-9]+$ ]] || [ "${height}" -lt "${target}" ]; then
        lagging="${lagging} ${actor}:${height:-unavailable}"
      fi
    done
    if [ -z "${lagging}" ]; then
      printf '%s nodes reached burn height %s\n' "${group}" "${target}"
      return 0
    fi
    sleep 2
  done
  echo "nodes did not converge to burn height ${target}: ${lagging}" >&2
  return 1
}

wait_live_peer_connectivity() {
  local manifest="$1" group="$2" deadline=$((SECONDS + TIMEOUT))
  local actors actor neighbors first samples result invariant_status
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" "${group}")"
  samples="$(mktemp)"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    first=true
    printf '[' >"${samples}"
    for actor in ${actors}; do
      neighbors="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec "${actor}" \
        curl --fail --silent --max-time 3 http://127.0.0.1:20443/v2/neighbors 2>/dev/null || true)"
      if [ "${first}" = true ]; then first=false; else printf ',' >>"${samples}"; fi
      ACTOR="${actor}" NEIGHBORS="${neighbors}" node -e '
        let neighbors = {};
        try { neighbors = JSON.parse(process.env.NEIGHBORS); } catch {}
        process.stdout.write(JSON.stringify({actor: process.env.ACTOR, neighbors}));
      ' >>"${samples}"
    done
    printf ']\n' >>"${samples}"
    # A failed sample is the expected retry signal, not a lifecycle failure.
    # ERR traps are inherited by command substitutions under `set -E`; remove
    # the trap inside this bounded probe and preserve its status explicitly so
    # an ordinary not-yet-connected sample cannot seal the run as failed.
    invariant_status=0
    result="$(trap - ERR; node "${ATTACKNET_DIR}/invariants.mjs" peers "${samples}" 2>/dev/null)" \
      || invariant_status=$?
    if [ "${invariant_status}" -eq 0 ]; then
      rm -f "${samples}"
      printf '%s live authenticated P2P connectivity proven for %s nodes\n' \
        "${group}" "$(wc -w <<<"${actors}" | tr -d ' ')"
      return 0
    fi
    sleep 2
  done
  echo "${group} nodes did not establish live authenticated P2P connectivity: ${result:-unavailable}" >&2
  rm -f "${samples}"
  return 1
}

signer_metric_value() {
  local metrics="$1" name="$2"
  awk -v metric="${name}" '$1 == metric { print $2; exit }' <<<"${metrics}"
}

wait_signer_global_state() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT)) signers signer metrics
  local available known maximum canonical missing stable=0
  signers="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" signers)"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    missing=""
    for signer in ${signers}; do
      metrics="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec "${signer}" \
        curl --fail --silent --max-time 3 http://127.0.0.1:31000/metrics 2>/dev/null || true)"
      available="$(signer_metric_value "${metrics}" stacks_signer_global_state_available)"
      known="$(signer_metric_value "${metrics}" stacks_signer_global_state_known_weight)"
      maximum="$(signer_metric_value "${metrics}" stacks_signer_global_state_maximum_view_weight)"
      canonical="$(signer_metric_value "${metrics}" stacks_signer_global_state_canonical_threshold_weight)"
      if [ "${available}" != 1 ] || ! [[ "${known}" =~ ^[0-9]+$ ]] \
        || ! [[ "${maximum}" =~ ^[0-9]+$ ]] || ! [[ "${canonical}" =~ ^[0-9]+$ ]] \
        || [ "${known:-0}" -lt "${canonical:-1}" ] \
        || [ "${maximum:-0}" -lt "${canonical:-1}" ]; then
        missing="${missing} ${signer}:available=${available:-?},known=${known:-?},view=${maximum:-?},required=${canonical:-?}"
      fi
    done
    if [ -z "${missing}" ]; then
      stable=$((stable + 1))
      if [ "${stable}" -ge 3 ]; then
        printf 'All %s signers retained a canonical-threshold global state for three samples\n' \
          "$(wc -w <<<"${signers}" | tr -d ' ')"
        return 0
      fi
    else
      stable=0
    fi
    sleep 2
  done
  echo "signers did not establish canonical-threshold global state:${missing}" >&2
  return 1
}

wait_signer_set_parity() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT)) pox reward_set cycle
  local response_file report_file status
  response_file="$(mktemp)"
  report_file="$(mktemp)"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    pox="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec miner-1 \
      curl --fail --silent --max-time 3 http://127.0.0.1:20443/v2/pox 2>/dev/null || true)"
    cycle="$(POX="${pox}" node -e '
      try {
        const value = JSON.parse(process.env.POX).current_cycle?.id;
        if (Number.isSafeInteger(value) && value >= 0) process.stdout.write(String(value));
      } catch {}
    ')"
    if [[ "${cycle}" =~ ^[0-9]+$ ]]; then
      reward_set="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec miner-1 \
        curl --fail --silent --max-time 3 \
        "http://127.0.0.1:20443/v3/stacker_set/${cycle}" 2>/dev/null || true)"
      if REWARD_SET="${reward_set}" node -e '
        try {
          const parsed = JSON.parse(process.env.REWARD_SET);
          if (!Array.isArray(parsed.stacker_set?.signers)) process.exit(1);
        } catch { process.exit(1); }
      '; then
        printf '%s\n' "${reward_set}" >"${response_file}"
        status=0
        ATTACKNET_REWARD_CYCLE="${cycle}" node "${ATTACKNET_DIR}/signer-set-parity.mjs" \
          "${manifest}" "${response_file}" "${report_file}" || status=$?
        if [ "${status}" -eq 0 ]; then
          jq -c . "${report_file}"
          rm -f "${response_file}" "${report_file}"
          return 0
        fi
        if [ "${status}" -eq 1 ]; then
          echo "declared signer ownership is unsafe for fault admission:" >&2
          jq . "${report_file}" >&2
          rm -f "${response_file}" "${report_file}"
          return 1
        fi
      fi
    fi
    sleep 2
  done
  rm -f "${response_file}" "${report_file}"
  echo "could not prove declared signer weights against the canonical reward set" >&2
  return 1
}

minimum_node_stacks_height() {
  local manifest="$1" group="$2" actors actor info height minimum=""
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" "${group}")"
  for actor in ${actors}; do
    info="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec "${actor}" \
      curl --fail --silent --max-time 3 http://127.0.0.1:20443/v2/info 2>/dev/null || true)"
    height="$(INFO="${info}" node -e '
      try {
        const value = JSON.parse(process.env.INFO).stacks_tip_height;
        if (Number.isSafeInteger(value) && value >= 0) process.stdout.write(String(value));
      } catch {}
    ')"
    [[ "${height}" =~ ^[0-9]+$ ]] || return 1
    if [ -z "${minimum}" ] || [ "${height}" -lt "${minimum}" ]; then minimum="${height}"; fi
  done
  printf '%s\n' "${minimum}"
}

wait_nodes_at_stacks_height() {
  local manifest="$1" group="$2" target="$3" deadline=$((SECONDS + TIMEOUT)) observed
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    observed="$(minimum_node_stacks_height "${manifest}" "${group}" || true)"
    if [[ "${observed}" =~ ^[0-9]+$ ]] && [ "${observed}" -ge "${target}" ]; then
      printf '%s nodes reached Stacks height %s (minimum %s)\n' "${group}" "${target}" "${observed}"
      return 0
    fi
    sleep 2
  done
  echo "${group} nodes did not reach Stacks height ${target}; minimum=${observed:-unavailable}" >&2
  return 1
}

wait_signers_registered() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT)) signers signer metrics missing
  signers="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" signers)"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    missing=""
    for signer in ${signers}; do
      metrics="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec "${signer}" \
        curl --fail --silent --max-time 3 http://127.0.0.1:31000/metrics 2>/dev/null || true)"
      if ! grep -q '^stacks_signer_runloop_ready 1$' <<<"${metrics}" \
        || ! grep -q '^stacks_signer_registered_for_current_reward_cycle 1$' <<<"${metrics}"; then
        missing="${missing} ${signer}"
      fi
    done
    if [ -z "${missing}" ]; then
      printf 'All %s signers are registered for the current reward cycle\n' \
        "$(wc -w <<<"${signers}" | tr -d ' ')"
      return 0
    fi
    sleep 2
  done
  echo "signers did not become current-cycle participants: ${missing}" >&2
  return 1
}

wait_stacker_submission_window() {
  local seconds="$1" cutoff_height="$2" deadline
  local status phase burn_height
  deadline=$((SECONDS + seconds))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    status="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec stacker \
      cat /tmp/attacknet-stacker-status.json 2>/dev/null || true)"
    read -r phase burn_height < <(STATUS="${status}" node -e '
      try {
        const status = JSON.parse(process.env.STATUS);
        console.log(`${status.phase ?? ""} ${status.burnHeight ?? ""}`);
      } catch {}
    ')
    case "${phase:-}" in
      pox4-submitted|pox4-confirmed)
        if ! [[ "${burn_height:-}" =~ ^[0-9]+$ ]] || [ "${burn_height}" -ge "${cutoff_height}" ]; then
          echo "stacker reported ${phase} at unsafe burn height ${burn_height:-unknown}; cutoff is ${cutoff_height}" >&2
          return 2
        fi
        printf 'Stacker reported %s at burn height %s\n' "${phase}" "${burn_height}"
        return 0
        ;;
      pox5-active)
        echo 'PoX-4 signer enrollment was missed before PoX-5 became active' >&2
        return 2
        ;;
    esac
    sleep 1
  done
  return 1
}

signer_accounts_locked() {
  local manifest="$1" addresses address account locked
  addresses="$(node -e '
    const fs = require("node:fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const signers = (manifest.workloads ?? manifest.actors ?? []).filter(actor => actor.type === "signer");
    if (!signers.length || signers.some(actor => typeof actor.stacksAddress !== "string")) process.exit(2);
    process.stdout.write(signers.map(actor => actor.stacksAddress).join(" "));
  ' "${manifest}")" || return 2
  for address in ${addresses}; do
    account="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec miner-1 \
      curl --fail --silent --max-time 3 \
      "http://127.0.0.1:20443/v2/accounts/${address}?proof=0" 2>/dev/null || true)"
    locked="$(ACCOUNT="${account}" node -e '
      try {
        const value = JSON.parse(process.env.ACCOUNT).locked;
        if (typeof value === "string" && BigInt(value) > 0n) process.stdout.write("1");
      } catch {}
    ')"
    [ "${locked}" = 1 ] || return 1
  done
  return 0
}

establish_signer_set() {
  local manifest="$1" enrollment_height="$2" cutoff_height="$3"
  local height current submitted=false result
  [ "${enrollment_height}" -lt "${cutoff_height}" ] || {
    echo "signer enrollment height ${enrollment_height} must precede cutoff ${cutoff_height}" >&2
    return 2
  }

  # Do not race through the PoX-4 enrollment window. Pause at every burn
  # height, wait for nodes to process it, and give the stacker at least one
  # complete polling interval to publish. Once submission is observed, mine
  # only as many blocks as needed to prove the lock in canonical chainstate.
  for ((height = enrollment_height; height < cutoff_height; height += 1)); do
    burst_to_height "${height}" "signer-enrollment-${height}"
    wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${height}"
    if signer_accounts_locked "${manifest}"; then
      ledger_assertion signer-set-established pass \
        "{\"confirmedHeight\":${height},\"cutoffHeight\":${cutoff_height}}"
      printf 'Signer accounts locked at burn height %s before cutoff %s\n' "${height}" "${cutoff_height}"
      return 0
    fi
    result=0
    wait_stacker_submission_window "$((BOOTSTRAP_INTERVAL_SECONDS + 4))" "${cutoff_height}" || result=$?
    if [ "${result}" -eq 0 ]; then
      submitted=true
      break
    fi
    [ "${result}" -eq 1 ] || return "${result}"
  done

  [ "${submitted}" = true ] || {
    echo "stacker did not submit PoX-4 enrollment before burn height ${cutoff_height}" >&2
    return 1
  }
  current="$(clock_status_value bitcoin_height)"
  for ((height = current + 1; height < cutoff_height; height += 1)); do
    burst_to_height "${height}" "signer-confirmation-${height}"
    wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${height}"
    if signer_accounts_locked "${manifest}"; then
      ledger_assertion signer-set-established pass \
        "{\"confirmedHeight\":${height},\"cutoffHeight\":${cutoff_height}}"
      printf 'Signer accounts locked at burn height %s before cutoff %s\n' "${height}" "${cutoff_height}"
      return 0
    fi
  done
  echo "signer accounts were not locked before reward-set cutoff ${cutoff_height}" >&2
  return 1
}

wait_companion_stackerdb_subscriptions() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT)) companions companion status missing
  companions="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" companions)"
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    missing=""
    for companion in ${companions}; do
      status="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
        "${ATTACKNET_DIR}/runtime-backend.sh" exec "${companion}" \
        curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 \
        http://127.0.0.1:20443/v2/stackerdb/ST000000000000000000002AMW42H/miners \
        2>/dev/null || true)"
      if [ "${status}" != 200 ]; then
        missing="${missing} ${companion}:${status:-unavailable}"
      fi
    done
    if [ -z "${missing}" ]; then
      printf 'All %s signer companions subscribe to the legacy .miners StackerDB\n' \
        "$(wc -w <<<"${companions}" | tr -d ' ')"
      return 0
    fi
    sleep 2
  done
  echo "signer companions did not instantiate the .miners StackerDB:${missing}" >&2
  return 1
}

burst_to_height() {
  local target="$1" phase="$2" current delta observed
  current="$(clock_status_value bitcoin_height)"
  [[ "${current}" =~ ^[0-9]+$ ]] || {
    echo "could not read current burnchain height" >&2
    return 1
  }
  if [ "${current}" -gt "${target}" ]; then
    echo "fresh lifecycle requires burn height <= ${target}; observed ${current}" >&2
    return 1
  fi
  delta=$((target - current))
  if [ "${delta}" -gt 0 ]; then
    ledger_cadence paused "burst:${delta}" "advance-to-${phase}" "${target}" "${current}"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" burst "${delta}" "${BOOTSTRAP_INTERVAL_SECONDS}"
  fi
  wait_clock_paused_at "${target}"
  observed="$(clock_status_value bitcoin_height)"
  if [ "${delta}" -gt 0 ]; then
    ledger_cadence "burst:${delta}" paused "reached-${phase}" "${target}" "${observed}"
  fi
  ledger_assertion "burn-height-${phase}" pass \
    "{\"requestedHeight\":${target},\"observedHeight\":${observed}}"
}

wait_observability_ready() {
  [ "${OBSERVABILITY_ENABLED}" = 1 ] || return 0
  kubectl -n "${NAMESPACE}" rollout status statefulset \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/name=attacknet-loki" \
    --timeout="${TIMEOUT}s"
  kubectl -n "${NAMESPACE}" rollout status daemonset \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/name=attacknet-alloy" \
    --timeout="${TIMEOUT}s"
  kubectl -n "${NAMESPACE}" wait --for=condition=Available deployment \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/part-of=stacks-attacknet" \
    --timeout="${TIMEOUT}s"
  if [ "${LOCAL_ACCESS_ENABLED}" = 1 ]; then
    KUBE_NAMESPACE="${NAMESPACE}" "${ATTACKNET_DIR}/local-access.sh" start
  fi
  if [ "${CHAOS_DASHBOARD_LOCAL_ACCESS_ENABLED}" = 1 ] \
      && kubectl -n chaos-mesh get service/chaos-dashboard >/dev/null 2>&1; then
    "${ATTACKNET_DIR}/chaos-dashboard.sh" start
  fi
}

ensure_burnchain_policy() {
  local rendered_policy="$1"
  if kubectl -n "${NAMESPACE}" get configmap "${NETWORK}-burnchain-policy" >/dev/null 2>&1; then
    # The clock treats GENERATION as a monotonic process-level command ID.
    # Reapplying a rendered generation-1 ConfigMap during resume can reuse an
    # already-acknowledged generation and make a new burst look applied while
    # the clock correctly ignores it. Preserve the admitted policy verbatim.
    echo "Preserving admitted burnchain policy and monotonic generation for ${NETWORK}"
    return 0
  fi
  kubectl -n "${NAMESPACE}" apply -f "${rendered_policy}"
}

needs_post_ready_clock_start() {
  local gated="$1" bootstrap_network="$2"
  [ "${AUTO_START_BURNCHAIN}" = 1 ] && [ -z "${gated}" ] && [ ! -f "${bootstrap_network}" ]
}

apply_network() {
  local generated="${1:?generated topology directory required}"
  local manifest="${generated}/manifest.json" final_network="${generated}/stacksnetwork.json"
  local bootstrap_network="${generated}/stacksnetwork.bootstrap.json"
  local gated desired_interval desired_jitter enrollment_height cutoff_height observer_height registration_height activation_height start_details storage_report pre_activation_stacks_height signer_set_report
  if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
    node "${ATTACKNET_DIR}/observability/render.mjs" "${manifest}" \
      --output="${generated}/observability.json" \
      --token-output="${generated}/event-token"
  fi
  RUN_DESCRIPTOR="$(node "${ATTACKNET_DIR}/run-ledger.mjs" init "${generated}")"
  RUN_ID="$(node -e '
    const fs=require("node:fs");
    process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).run.id);
  ' "${RUN_DESCRIPTOR}")"
  RUN_SEED="$(node -e '
    const fs=require("node:fs");
    process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).randomness.seed);
  ' "${RUN_DESCRIPTOR}")"
  ledger_refresh_context
  ledger_assertion lifecycle-initialized pass \
    "{\"network\":\"${NETWORK}\",\"namespace\":\"${NAMESPACE}\"}"
  if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
    if [ "${OBSERVABILITY_STORAGE_PREFLIGHT}" = 1 ]; then
      if "${ATTACKNET_DIR}/observability/storage-preflight.sh" \
        "${generated}/observability-storage-preflight.json"; then
        storage_report="$(jq -c . "${generated}/observability-storage-preflight.json")"
        ledger_assertion observability-storage-capacity pass "${storage_report}"
      else
        storage_report="$(jq -c . "${generated}/observability-storage-preflight.json")"
        ledger_assertion observability-storage-capacity fail "${storage_report}"
        return 1
      fi
    elif [ "${ATTACKNET_NEGATIVE_CONTROL:-0}" != 1 ]; then
      echo "disabling the observability storage preflight requires ATTACKNET_NEGATIVE_CONTROL=1" >&2
      return 2
    else
      storage_report='{"schemaVersion":1,"ok":false,"source":"disabled-for-explicit-negative-control"}'
      printf '%s\n' "${storage_report}" >"${generated}/observability-storage-preflight.json"
      ledger_assertion observability-storage-capacity skipped "${storage_report}"
    fi
    kubectl -n "${NAMESPACE}" apply -f "${generated}/observability.json"
    wait_observability_ready
    start_details="$(RUN_SEED="${RUN_SEED}" node -e '
      console.log(JSON.stringify({seed:process.env.RUN_SEED,descriptorSchema:"stacks-attacknet-run/v1"}));
    ')"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
      "${ATTACKNET_DIR}/observability/record-event.sh" \
      --kind=run.started --phase=setup \
      "--details=${start_details}" >/dev/null
  fi
  ensure_burnchain_policy "${generated}/burnchain-policy.configmap.json"
  if [ -f "${bootstrap_network}" ]; then
    kubectl -n "${NAMESPACE}" apply -f "${bootstrap_network}"
  else
    kubectl -n "${NAMESPACE}" apply -f "${final_network}"
  fi
  gated="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" activation-gated)"
  desired_interval="$(sed -n 's/^INTERVAL_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  desired_jitter="$(sed -n 's/^JITTER_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  observer_height="$(manifest_protocol_value "${manifest}" observerEnableHeight)"
  enrollment_height="$(manifest_protocol_value "${manifest}" signerEnrollmentHeight)"
  cutoff_height="$(manifest_protocol_value "${manifest}" signerSetCutoffHeight)"
  registration_height="$(manifest_protocol_value "${manifest}" signerRegistrationHeight)"
  activation_height="$(manifest_protocol_value "${manifest}" nakamotoActivationHeight)"
  if [ "${AUTO_START_BURNCHAIN}" = 1 ] && { [ -n "${gated}" ] || [ -f "${bootstrap_network}" ]; }; then
    # Advance in exact, paused phases. Kubernetes Ready is deliberately not a
    # protocol gate: a signer may serve its event socket while it has no active
    # signer for the current reward cycle.
    wait_bootstrap_foundation_ready "${manifest}"
    establish_signer_set "${manifest}" "${enrollment_height}" "${cutoff_height}"
    burst_to_height "${observer_height}" observer-enable
    wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${observer_height}"
    ledger_assertion nodes-at-observer-height pass \
      "{\"requestedHeight\":${observer_height},\"observedHeight\":$(clock_status_value bitcoin_height)}"
    if [ -f "${bootstrap_network}" ]; then
      echo "Enabling companion observers at burn height ${observer_height}"
      kubectl -n "${NAMESPACE}" apply -f "${final_network}"
      wait_bootstrap_foundation_ready "${manifest}"
    fi
    burst_to_height "${registration_height}" signer-registration
    wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${registration_height}"
    wait_actor_group_ready "${manifest}" bootstrap
    wait_signers_registered "${manifest}"
    wait_companion_stackerdb_subscriptions "${manifest}"
    wait_live_peer_connectivity "${manifest}" pre-activation-nodes
    ledger_assertion signers-registered pass \
      "{\"requestedHeight\":${registration_height},\"observedHeight\":$(clock_status_value bitcoin_height)}"
    ledger_assertion companion-stackerdb-subscriptions pass \
      "{\"contract\":\"ST000000000000000000002AMW42H.miners\",\"observedHeight\":$(clock_status_value bitcoin_height)}"
    [ "${registration_height}" -lt "${activation_height}" ] || {
      echo "signer registration barrier must precede Nakamoto activation" >&2
      return 1
    }
    pre_activation_stacks_height="$(minimum_node_stacks_height "${manifest}" pre-activation-nodes)"
    burst_to_height "${activation_height}" nakamoto-activation
    wait_nodes_at_burn_height "${manifest}" nodes "${activation_height}"
    wait_ready
    wait_live_peer_connectivity "${manifest}" nodes
    wait_signer_global_state "${manifest}"
    signer_set_report="$(wait_signer_set_parity "${manifest}")"
    wait_nodes_at_stacks_height "${manifest}" nodes "$((pre_activation_stacks_height + 1))"
    ledger_assertion live-peer-connectivity pass \
      "{\"observedHeight\":$(clock_status_value bitcoin_height)}"
    ledger_assertion signer-global-state pass \
      "{\"threshold\":\"canonical-rounded-up\",\"observedHeight\":$(clock_status_value bitcoin_height)}"
    ledger_assertion signer-set-parity pass "${signer_set_report}"
    ledger_assertion first-nakamoto-block pass \
      "{\"minimumStacksHeight\":$((pre_activation_stacks_height + 1)),\"observedHeight\":$(clock_status_value bitcoin_height)}"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${desired_interval:-60}" "${desired_jitter:-0}"
    ledger_cadence paused "run:${desired_interval:-60}s:jitter-${desired_jitter:-0}s" \
      steady-state-after-nakamoto-proof "${activation_height}" "$(clock_status_value bitcoin_height)"
  else
    wait_ready
    if [ -f "${bootstrap_network}" ]; then
      echo 'Signer runloops initialized; enabling companion event observers'
      kubectl -n "${NAMESPACE}" apply -f "${final_network}"
      wait_ready
    fi
  fi
  if needs_post_ready_clock_start "${gated}" "${bootstrap_network}"; then
    sleep "${STARTUP_SETTLE_SECONDS}"
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${desired_interval:-60}" "${desired_jitter:-0}"
    ledger_cadence paused "run:${desired_interval:-60}s:jitter-${desired_jitter:-0}s" startup-complete
  fi
  ledger_capture_runtime
  ledger_assertion lifecycle-ready pass \
    "{\"burnHeight\":$(clock_status_value bitcoin_height || echo null)}"
  ledger_refresh_context
  if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
      "${ATTACKNET_DIR}/observability/record-actor-states.sh" baseline
  fi
}

delete_network() {
  local final_status="${ATTACKNET_RUN_FINAL_STATUS:-}" bundle descriptor_status
  RUN_DESCRIPTOR="$(locate_ledger || true)"
  if [ -n "${RUN_DESCRIPTOR}" ] && [ -r "${RUN_DESCRIPTOR}" ]; then
    read -r RUN_ID descriptor_status < <(node -e '
      const fs=require("node:fs"); const value=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      console.log(value.run.id, value.run.status);
    ' "${RUN_DESCRIPTOR}")
    if [ -z "${final_status}" ]; then
      [ "${descriptor_status}" = running ] && final_status=aborted || final_status="${descriptor_status}"
    elif [ "${descriptor_status}" != running ] && [ "${final_status}" != "${descriptor_status}" ]; then
      echo "warning: finalized run status is ${descriptor_status}; ignoring teardown override ${final_status}" >&2
      final_status="${descriptor_status}"
    fi
    bundle="${ATTACKNET_RUN_EXPORT_DIR:-$(dirname "${RUN_DESCRIPTOR}")/bundle}"
    if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/record-actor-states.sh" teardown || \
        echo 'warning: failed to record teardown actor states' >&2
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/record-event.sh" \
        --kind=run.finished --phase=teardown "--outcome=${final_status}" \
        "--details={\"status\":\"${final_status}\"}" >/dev/null || \
        echo 'warning: failed to record run.finished before teardown' >&2
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" "${bundle}/timeline" "${RUN_ID}"
    fi
    if [ "${descriptor_status}" = running ]; then
      ledger_assertion run-final-status \
        "$([ "${final_status}" = passed ] && echo pass || { [ "${final_status}" = failed ] && echo fail || echo skipped; })" \
        "{\"status\":\"${final_status}\"}"
      node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${RUN_DESCRIPTOR}" "${final_status}" >/dev/null
    else
      echo "Run ledger already finalized as ${descriptor_status}; exporting without rewriting it"
    fi
    ledger_export "${bundle}/descriptor"
    echo "Run evidence exported before teardown: ${bundle}"
  fi
  kubectl -n "${NAMESPACE}" delete stacksnetwork "${NETWORK}" --ignore-not-found --wait=false
  kubectl -n "${NAMESPACE}" delete configmap "${NETWORK}-burnchain-policy" --ignore-not-found
  kubectl -n "${NAMESPACE}" delete deployments,statefulsets,daemonsets,services,configmaps,secrets,pvc,serviceaccounts,roles,rolebindings \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/part-of=stacks-attacknet" \
    --ignore-not-found --wait=false
  wait_deleted
}

capture() {
  local destination="${1:?evidence directory required}"
  mkdir -p "${destination}"
  kubectl version -o json >"${destination}/kubernetes-version.json"
  kubectl get nodes -o json >"${destination}/nodes.json"
  kubectl get storageclasses -o json >"${destination}/storageclasses.json"
  kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" -o json \
    >"${destination}/stacksnetwork.admitted.json"
  kubectl -n "${NAMESPACE}" get pods -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/pods.admitted.json"
  kubectl -n "${NAMESPACE}" get statefulsets -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/statefulsets.admitted.json"
  kubectl -n "${NAMESPACE}" get pvc -l "testing.stacks.org/network=${NETWORK}" -o json \
    >"${destination}/pvcs.admitted.json"
  kubectl -n "${NAMESPACE}" get pv -o json >"${destination}/persistent-volumes.json"
  kubectl -n "${NAMESPACE}" get events --sort-by=.metadata.creationTimestamp -o json \
    >"${destination}/namespace-events.json"
  kubectl -n "${NAMESPACE}" get faultcampaigns,attacknetruns -o json \
    >"${destination}/attacknet-orchestration.json"
  kubectl -n "${NAMESPACE}" get podchaos,networkchaos,dnschaos,iochaos,timechaos -o json \
    >"${destination}/chaos-mesh.json"
  kubectl -n "${NAMESPACE}" get configmaps \
    attacknet-environment-lease attacknet-mutation-lease --ignore-not-found -o json \
    >"${destination}/attacknet-leases.json"
  kubectl -n "${NAMESPACE}" logs -l 'app.kubernetes.io/name=hacknet' \
    --all-containers=true --since=1h --timestamps \
    >"${destination}/operator.log"
  kubectl -n "${NAMESPACE}" logs -l 'app.kubernetes.io/component=run-operator' \
    --all-containers=true --since=1h --timestamps \
    >"${destination}/run-operator.log"
  ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
    "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/runtime.json"
  RUN_DESCRIPTOR="$(locate_ledger || true)"
  if [ -n "${RUN_DESCRIPTOR}" ] && [ -r "${RUN_DESCRIPTOR}" ]; then
    RUN_ID="$(node -e 'const fs=require("node:fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).run.id)' "${RUN_DESCRIPTOR}")"
    ledger_export "${destination}/run"
    if [ "${OBSERVABILITY_ENABLED}" = 1 ]; then
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/record-actor-states.sh" capture || \
        echo 'warning: failed to record capture actor states' >&2
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" \
        "${destination}/timeline" "${RUN_ID}" || \
        echo 'warning: failed to export trusted timeline during capture' >&2
    fi
  fi
}

apply_error() {
  local status="$1" line="$2" bundle
  trap - ERR
  set +e
  echo "attacknet apply failed at lifecycle.sh:${line}; preserving the admitted network" >&2
  if [ -n "${RUN_DESCRIPTOR}" ] && [ -r "${RUN_DESCRIPTOR}" ]; then
    ledger_assertion lifecycle-apply fail "{\"exitStatus\":${status},\"line\":${line}}"
    ledger_capture_runtime >/dev/null 2>&1
    node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${RUN_DESCRIPTOR}" failed >/dev/null
    bundle="${ATTACKNET_RUN_EXPORT_DIR:-$(dirname "${RUN_DESCRIPTOR}")/bootstrap-failure-bundle}"
    ledger_export "${bundle}/descriptor"
    if [ "${OBSERVABILITY_ENABLED}" = 1 ] && [ -n "${RUN_ID}" ]; then
      KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" ATTACKNET_RUN_ID="${RUN_ID}" \
        "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" \
        "${bundle}/timeline" "${RUN_ID}" >/dev/null 2>&1
    fi
    echo "Bootstrap failure evidence: ${bundle}" >&2
  fi
  # A failure before admitting any network-owned object must not reserve the
  # single-environment lease forever. If anything was admitted, preserve both
  # the environment and its lease for attribution and incident capture.
  if ! kubectl -n "${NAMESPACE}" get stacksnetwork "${NETWORK}" >/dev/null 2>&1 \
    && [ -z "$(kubectl -n "${NAMESPACE}" get pods,pvc,deployments,statefulsets,daemonsets,services,configmaps,secrets,serviceaccounts,roles,rolebindings \
      -l "testing.stacks.org/network=${NETWORK}" -o name 2>/dev/null)" ]; then
    "${ENVIRONMENT_LOCK}" release "${NETWORK}" || true
  fi
  exit "${status}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  command="${1:-}"
  if [ "${command}" = apply ]; then
    generated="${2:?usage: $0 apply GENERATED_DIR}"
    identity="$(node "${ATTACKNET_DIR}/manifest-identity.mjs" "${generated}")"
    rendered_network="$(jq -er .network <<<"${identity}")"
    rendered_namespace="$(jq -er .namespace <<<"${identity}")"
    if [ -n "${KUBE_NETWORK+x}" ] && [ "${KUBE_NETWORK}" != "${rendered_network}" ]; then
      echo "KUBE_NETWORK=${KUBE_NETWORK} does not match rendered network ${rendered_network}" >&2
      exit 2
    fi
    if [ -n "${KUBE_NAMESPACE+x}" ] && [ "${KUBE_NAMESPACE}" != "${rendered_namespace}" ]; then
      echo "KUBE_NAMESPACE=${KUBE_NAMESPACE} does not match rendered namespace ${rendered_namespace}" >&2
      exit 2
    fi
    NETWORK="${rendered_network}"
    NAMESPACE="${rendered_namespace}"
  fi
  case "${command}" in
    apply|delete)
      if [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
        "${ENVIRONMENT_LOCK}" claim "${NETWORK}" "${ATTACKNET_LOCK_OWNER:-lifecycle:$$}" "lifecycle-${command}"
        exec "${ENVIRONMENT_LOCK}" run "${NETWORK}" \
          "${ATTACKNET_LOCK_OWNER:-lifecycle:$$}" "lifecycle-${command}" -- "$0" "$@"
      fi
      "${ENVIRONMENT_LOCK}" assert "${NETWORK}" "${ATTACKNET_MUTATION_TOKEN}"
      ;;
    capture)
      "${ENVIRONMENT_LOCK}" environment-assert "${NETWORK}"
      if [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
        exec "${ENVIRONMENT_LOCK}" run "${NETWORK}" \
          "${ATTACKNET_LOCK_OWNER:-lifecycle:$$}" lifecycle-capture -- "$0" "$@"
      fi
      "${ENVIRONMENT_LOCK}" assert "${NETWORK}" "${ATTACKNET_MUTATION_TOKEN}"
      ;;
    wait)
      "${ENVIRONMENT_LOCK}" environment-assert "${NETWORK}"
      ;;
  esac
  case "${1:-}" in
    apply) shift; trap 'apply_error $? ${LINENO}' ERR; apply_network "$@"; trap - ERR ;;
    wait) wait_ready ;;
    delete) delete_network; "${ENVIRONMENT_LOCK}" release "${NETWORK}" ;;
    capture) shift; capture "$@" ;;
    *) echo "usage: $0 {apply GENERATED_DIR|wait|delete|capture EVIDENCE_DIR}" >&2; exit 2 ;;
  esac
fi
