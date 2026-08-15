#!/bin/bash
set -euo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
campaign="${1:?campaign JSON required}"
manifest="${2:?manifest JSON required}"
destination="${3:-${ATTACKNET_DIR}/evidence/campaign-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${destination}"

resource="${destination}/chaos.json"
node "${ATTACKNET_DIR}/fault-campaign.mjs" "${campaign}" "${manifest}" "${resource}"
cp "${campaign}" "${destination}/campaign.requested.json"
cp "${manifest}" "${destination}/manifest.json"

namespace="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).metadata.namespace)' "${resource}")"
network="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).metadata.labels["testing.stacks.org/network"])' "${resource}")"
resource_kind="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).kind)' "${resource}")"
kind="$(printf '%s' "${resource_kind}" | tr '[:upper:]' '[:lower:]')"
name="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).metadata.name)' "${resource}")"
duration_seconds="$(node -e '
  const fs=require("node:fs");
  const value=JSON.parse(fs.readFileSync(process.argv[1], "utf8")).spec.duration;
  const match=/^(\d+)(ms|s|m|h)$/.exec(value);
  const scalar={ms:.001,s:1,m:60,h:3600}[match[2]];
  console.log(Math.ceil(Number(match[1])*scalar));
' "${resource}")"
selected_actors="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).selectedActors.join(" "))' "${resource}.evidence.json")"
run_descriptor="$(node "${ATTACKNET_DIR}/run-ledger.mjs" locate \
  "--target=${manifest}" "--namespace=${namespace}" "--network=${network}" 2>/dev/null || true)"
run_id="${ATTACKNET_RUN_ID:-}"
if [ -z "${run_id}" ] && [ -r "${run_descriptor}" ]; then
  run_id="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).run.id)' "${run_descriptor}")"
fi
event_phase=baseline
injected=false
cleared=false
incident_captured=false

ledger_append() {
  local type="$1" payload="$2"
  [ -r "${run_descriptor}" ] || return 0
  node "${ATTACKNET_DIR}/run-ledger.mjs" append "${run_descriptor}" "${type}" "${payload}" >/dev/null
}

ledger_fault() {
  local decision="$1" payload
  payload="$(DECISION="${decision}" CAMPAIGN="${name}" FAULT_KIND="${resource_kind}" \
    TARGETS="${selected_actors}" RESOURCE="${resource}" node -e '
      const fs=require("node:fs");
      console.log(JSON.stringify({
        campaign:process.env.CAMPAIGN, decision:process.env.DECISION,
        faultKind:process.env.FAULT_KIND, targets:process.env.TARGETS.split(/\s+/).filter(Boolean),
        parameters:JSON.parse(fs.readFileSync(process.env.RESOURCE,"utf8")).spec,
      }));
    ')"
  ledger_append fault-decision "${payload}"
}

ledger_assertion() {
  local assertion="$1" status="$2" details="${3:-}" payload
  [ -n "${details}" ] || details='{}'
  payload="$(ASSERTION="${assertion}" STATUS="${status}" DETAILS="${details}" node -e '
    console.log(JSON.stringify({assertion:process.env.ASSERTION,status:process.env.STATUS,details:JSON.parse(process.env.DETAILS)}));
  ')"
  ledger_append assertion-result "${payload}"
}

emit_event() {
  local event_kind="$1" phase="$2" actor="$3" details="$4" event_id
  [ -n "${run_id}" ] || return 0
  event_id="${run_id}-${name}-${event_kind//./-}-${actor:-all}"
  KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
    "${ATTACKNET_DIR}/observability/record-event.sh" \
    "--kind=${event_kind}" "--phase=${phase}" "--event-id=${event_id}" \
    "--campaign=${name}" "--fault-type=${kind}" "--actor=${actor}" "--details=${details}" \
    >>"${destination}/events-emitted.jsonl"
}

emit_invariant() {
  local invariant="$1" passed="$2" phase="$3" details
  details="$(node -e '
    console.log(JSON.stringify({name: process.argv[1], passed: process.argv[2] === "true"}));
  ' "${invariant}" "${passed}")"
  if [ -n "${run_id}" ]; then
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
      "${ATTACKNET_DIR}/observability/record-event.sh" \
      --kind=invariant.observed \
      "--phase=${phase}" "--event-id=${run_id}-${name}-${invariant}-${phase}" \
      "--campaign=${name}" "--outcome=$([ "${passed}" = true ] && echo pass || echo fail)" \
      "--details=${details}" \
      >>"${destination}/events-emitted.jsonl"
  fi
}

capture_clocks() {
  local output="$1" actor wall monotonic
  : >"${output}"
  for actor in ${selected_actors}; do
    wall="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec "${actor}" date +%s)"
    monotonic="$(ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/runtime-backend.sh" exec "${actor}" sh -c "cut -d' ' -f1 /proc/uptime")"
    printf '{"actor":"%s","wallEpoch":%s,"monotonicSeconds":%s}\n' \
      "${actor}" "${wall}" "${monotonic}" >>"${output}"
  done
}

cleanup() {
  local actor
  kubectl -n "${namespace}" delete -f "${resource}" --ignore-not-found --wait=true \
    >"${destination}/cleanup.log" 2>&1 || true
  if [ "${injected}" = true ] && [ "${cleared}" = false ]; then
    for actor in ${selected_actors}; do
      emit_event fault.cleared recovering "${actor}" '{"cleared":true}' || true
    done
    cleared=true
  fi
}

capture_incident() {
  local reason="$1" status="${2:-1}" details
  [ "${incident_captured}" = false ] || return 0
  incident_captured=true
  # Stop amplifying the active bounded fault, but preserve the network, PVCs,
  # and admitted state. A failed campaign never recreates the system under test.
  set +e
  cleanup
  details="$(REASON="${reason}" STATUS="${status}" node -e '
    console.log(JSON.stringify({reason: process.env.REASON, status: Number(process.env.STATUS)}));
  ')"
  emit_event incident.opened incident "" "${details}"
  ATTACKNET_RUN_ID="${run_id}" KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/incident-capture.sh" "${destination}/incident" "${manifest}" \
    "${event_phase}" "${reason}"
  set -e
}

fail_campaign() {
  local reason="$1" status="${2:-1}"
  echo "Campaign failed during ${event_phase}: ${reason}" >&2
  ledger_assertion "campaign-${name}-${event_phase}" fail \
    "$(REASON="${reason}" STATUS="${status}" node -e 'console.log(JSON.stringify({reason:process.env.REASON,exitStatus:Number(process.env.STATUS)}))')" || true
  if [ -r "${run_descriptor}" ]; then
    node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${run_descriptor}" failed >/dev/null || true
    mkdir -p "${destination}/incident"
    node "${ATTACKNET_DIR}/run-ledger.mjs" export "${run_descriptor}" \
      "${destination}/incident/run" >/dev/null || true
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
      "${ATTACKNET_DIR}/observability/record-actor-states.sh" incident || true
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
      "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" \
      "${destination}/incident/timeline-pre-capture" "${run_id}" >/dev/null || true
  fi
  capture_incident "${reason}" "${status}"
  exit "${status}"
}

on_error() {
  local status=$? line="$1"
  trap - ERR
  fail_campaign "unhandled command failure at campaign-runner.sh:${line}" "${status}"
}

trap 'on_error ${LINENO}' ERR
trap cleanup EXIT INT TERM

if ! ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot \
  >"${destination}/before-verification.json" 2>"${destination}/before-verification.stderr"; then
  ledger_assertion "campaign-${name}-baseline-health" fail '{"phase":"baseline"}' || true
  [ ! -s "${destination}/before-verification.json" ] || \
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
      "${ATTACKNET_DIR}/observability/record-verification.sh" \
      "${destination}/before-verification.json" "campaign-${name}-baseline" baseline || true
  emit_invariant baseline-health false baseline || true
  fail_campaign 'baseline invariant failed before fault injection'
fi
ledger_assertion "campaign-${name}-baseline-health" pass '{"phase":"baseline"}'
emit_invariant baseline-health true baseline
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/record-verification.sh" \
  "${destination}/before-verification.json" "campaign-${name}-baseline" baseline
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/before-runtime.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-before.jsonl"; fi

scheduled_details="$(node -e '
  const fs=require("node:fs");
  const e=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  console.log(JSON.stringify({actors:e.selectedActors,signerImpact:e.signerImpact,safety:e.safety}));
' "${resource}.evidence.json")"
event_phase=injecting
ledger_fault selected
emit_event fault.scheduled injecting "" "${scheduled_details}"
kubectl -n "${namespace}" apply -f "${resource}" >"${destination}/apply.log"
kubectl -n "${namespace}" wait --for=condition=AllInjected "${kind}/${name}" \
  --timeout="${ATTACKNET_INJECTION_TIMEOUT:-90s}" >"${destination}/injected.log"
injected=true
ledger_fault applied
event_phase=fault-active
for actor in ${selected_actors}; do
  emit_event fault.injected fault-active "${actor}" '{"injected":true}'
done
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/record-actor-states.sh" fault-active
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/during-chaos.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-during.jsonl"; fi
sleep "$((duration_seconds + ${ATTACKNET_CHAOS_SETTLE_SECONDS:-5}))"
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/after-duration.json" 2>/dev/null || true
cleanup
ledger_fault reverted
trap - EXIT INT TERM

event_phase=recovering
recovery_started="$(date +%s)"
deadline=$((SECONDS + ${ATTACKNET_RECOVERY_TIMEOUT_SECONDS:-300}))
until ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot >"${destination}/after-verification.json" 2>"${destination}/recovery-errors.log"; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    ledger_assertion "campaign-${name}-recovery-health" fail '{"phase":"verification"}' || true
    [ ! -s "${destination}/after-verification.json" ] || \
      KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
        "${ATTACKNET_DIR}/observability/record-verification.sh" \
        "${destination}/after-verification.json" "campaign-${name}-recovery" verification || true
    emit_invariant recovery-health false verification || true
    fail_campaign 'network did not recover before the campaign deadline'
  fi
  sleep 5
done
ledger_assertion "campaign-${name}-recovery-health" pass '{"phase":"verification"}'
emit_invariant recovery-health true verification
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/record-verification.sh" \
  "${destination}/after-verification.json" "campaign-${name}-recovery" verification
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/record-actor-states.sh" verification
recovery_duration=$(( $(date +%s) - recovery_started ))
emit_event recovery.complete verification "" "{\"durationSeconds\":${recovery_duration}}"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-after.jsonl"; fi
event_phase=verification
if ! ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  ATTACKNET_PROGRESS_WINDOW_SECONDS="${ATTACKNET_POST_CHAOS_PROGRESS_SECONDS:-45}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" progress \
  >"${destination}/post-chaos-progress.json" 2>"${destination}/post-chaos-progress.stderr"; then
  ledger_assertion "campaign-${name}-post-chaos-progress" fail '{"phase":"verification"}' || true
  [ ! -s "${destination}/post-chaos-progress.json" ] || \
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
      "${ATTACKNET_DIR}/observability/record-verification.sh" \
      "${destination}/post-chaos-progress.json" "campaign-${name}-progress" verification || true
  emit_invariant post-chaos-progress false verification || true
  fail_campaign 'post-chaos burnchain and Stacks progress invariant failed'
fi
ledger_assertion "campaign-${name}-post-chaos-progress" pass '{"phase":"verification"}'
emit_invariant post-chaos-progress true verification
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/record-verification.sh" \
  "${destination}/post-chaos-progress.json" "campaign-${name}-progress" verification
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/after-runtime.json"
if [ -r "${run_descriptor}" ]; then
  node "${ATTACKNET_DIR}/run-ledger.mjs" export "${run_descriptor}" \
    "${destination}/run" >/dev/null
fi
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
  "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" \
  "${destination}/timeline" "${run_id}" >/dev/null || \
  echo 'warning: campaign completed but its trusted timeline export failed' >&2
echo "Campaign evidence: ${destination}"
