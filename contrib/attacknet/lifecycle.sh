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
RUN_DESCRIPTOR=""
RUN_ID="${ATTACKNET_RUN_ID:-}"
RUN_SEED="${ATTACKNET_RUN_SEED:-}"

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
  local remaining
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    remaining="$(kubectl -n "${NAMESPACE}" get pods,pvc,statefulsets,services,configmaps \
      -l "testing.stacks.org/network=${NETWORK}" -o name 2>/dev/null || true)"
    if [ -z "${remaining}" ]; then
      echo "Deleted ${NETWORK} and all labeled children/PVCs"
      return 0
    fi
    sleep 2
  done
  echo "resources survived deletion of ${NETWORK}:" >&2
  printf '%s\n' "${remaining}" >&2
  return 1
}

wait_bootstrap_foundation_ready() {
  local manifest="$1" deadline=$((SECONDS + TIMEOUT))
  local actors expected pod_count unready
  actors="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" bootstrap-foundation)"
  expected="$(node -e '
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
    unready="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" unready ${actors} 2>/dev/null || true)"
    if [ "${pod_count}" = "${expected}" ] && [ -z "${unready}" ]; then
      printf 'Bootstrap foundation Ready (%s actors); %s/%s Pods admitted\n' \
        "$(wc -w <<<"${actors}" | tr -d ' ')" "${pod_count}" "${expected}"
      return 0
    fi
    sleep 3
  done
  echo "${NETWORK} bootstrap foundation did not become Ready within ${TIMEOUT}s; unready: ${unready:-unknown}" >&2
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
  kubectl -n "${NAMESPACE}" wait --for=condition=Available deployment \
    -l "testing.stacks.org/network=${NETWORK},app.kubernetes.io/part-of=stacks-attacknet" \
    --timeout="${TIMEOUT}s"
}

apply_network() {
  local generated="${1:?generated topology directory required}"
  local manifest="${generated}/manifest.json" final_network="${generated}/stacksnetwork.json"
  local bootstrap_network="${generated}/stacksnetwork.bootstrap.json"
  local gated desired_interval desired_jitter observer_height registration_height activation_height start_details
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
  kubectl -n "${NAMESPACE}" apply -f "${generated}/burnchain-policy.configmap.json"
  if [ -f "${bootstrap_network}" ]; then
    kubectl -n "${NAMESPACE}" apply -f "${bootstrap_network}"
  else
    kubectl -n "${NAMESPACE}" apply -f "${final_network}"
  fi
  gated="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" activation-gated)"
  desired_interval="$(sed -n 's/^INTERVAL_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  desired_jitter="$(sed -n 's/^JITTER_SECONDS=//p' "${generated}/policy.env" | tail -1)"
  observer_height="$(manifest_protocol_value "${manifest}" observerEnableHeight)"
  registration_height="$(manifest_protocol_value "${manifest}" signerRegistrationHeight)"
  activation_height="$(manifest_protocol_value "${manifest}" nakamotoActivationHeight)"
  if [ "${AUTO_START_BURNCHAIN}" = 1 ] && { [ -n "${gated}" ] || [ -f "${bootstrap_network}" ]; }; then
    # Advance in exact, paused phases. Kubernetes Ready is deliberately not a
    # protocol gate: a signer may serve its event socket while it has no active
    # signer for the current reward cycle.
    wait_bootstrap_foundation_ready "${manifest}"
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
    ledger_assertion signers-registered pass \
      "{\"requestedHeight\":${registration_height},\"observedHeight\":$(clock_status_value bitcoin_height)}"
    [ "${registration_height}" -lt "${activation_height}" ] || {
      echo "signer registration barrier must precede Nakamoto activation" >&2
      return 1
    }
    KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
      "${ATTACKNET_DIR}/burnchain-policy.sh" run "${desired_interval:-60}" "${desired_jitter:-0}"
    ledger_cadence paused "run:${desired_interval:-60}s:jitter-${desired_jitter:-0}s" \
      nakamoto-activation "${activation_height}" "$(clock_status_value bitcoin_height)"
    wait_ready
  else
    wait_ready
    if [ -f "${bootstrap_network}" ]; then
      echo 'Signer runloops initialized; enabling companion event observers'
      kubectl -n "${NAMESPACE}" apply -f "${final_network}"
      wait_ready
    fi
  fi
  if [ "${AUTO_START_BURNCHAIN}" = 1 ] && [ -z "${gated}" ]; then
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
    ledger_assertion run-final-status \
      "$([ "${final_status}" = passed ] && echo pass || { [ "${final_status}" = failed ] && echo fail || echo skipped; })" \
      "{\"status\":\"${final_status}\"}"
    node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${RUN_DESCRIPTOR}" "${final_status}" >/dev/null
    ledger_export "${bundle}/descriptor"
    echo "Run evidence exported before teardown: ${bundle}"
  fi
  kubectl -n "${NAMESPACE}" delete stacksnetwork "${NETWORK}" --ignore-not-found --wait=false
  kubectl -n "${NAMESPACE}" delete configmap "${NETWORK}-burnchain-policy" --ignore-not-found
  kubectl -n "${NAMESPACE}" delete deployments,services,configmaps,secrets,pvc \
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
  kubectl -n "${NAMESPACE}" logs -l 'app.kubernetes.io/name=hacknet' \
    --all-containers=true --since=1h --timestamps \
    >"${destination}/operator.log"
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
  exit "${status}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    apply) shift; trap 'apply_error $? ${LINENO}' ERR; apply_network "$@"; trap - ERR ;;
    wait) wait_ready ;;
    delete) delete_network ;;
    capture) shift; capture "$@" ;;
    *) echo "usage: $0 {apply GENERATED_DIR|wait|delete|capture EVIDENCE_DIR}" >&2; exit 2 ;;
  esac
fi
