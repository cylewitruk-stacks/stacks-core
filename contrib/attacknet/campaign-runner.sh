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
kind="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).kind.toLowerCase())' "${resource}")"
name="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).metadata.name)' "${resource}")"
duration_seconds="$(node -e '
  const fs=require("node:fs");
  const value=JSON.parse(fs.readFileSync(process.argv[1], "utf8")).spec.duration;
  const match=/^(\d+)(ms|s|m|h)$/.exec(value);
  const scalar={ms:.001,s:1,m:60,h:3600}[match[2]];
  console.log(Math.ceil(Number(match[1])*scalar));
' "${resource}")"
selected_actors="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).selectedActors.join(" "))' "${resource}.evidence.json")"
run_id="${ATTACKNET_RUN_ID:-}"
event_phase=baseline
injected=false
cleared=false
incident_captured=false

emit_event() {
  local event_kind="$1" phase="$2" actor="$3" details="$4" event_id
  [ -n "${run_id}" ] || return 0
  event_id="${run_id}-${name}-${event_kind//./-}-${actor:-all}"
  node "${ATTACKNET_DIR}/observability/event.mjs" \
    "--kind=${event_kind}" "--network=${network}" "--run-id=${run_id}" \
    "--phase=${phase}" "--event-id=${event_id}" "--campaign=${name}" \
    "--fault-type=${kind}" "--actor=${actor}" "--details=${details}" \
    >"${destination}/event.json"
  KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
    "${ATTACKNET_DIR}/observability/emit-kubernetes-event.sh" "${destination}/event.json" \
    >>"${destination}/events-emitted.jsonl"
}

emit_invariant() {
  local invariant="$1" passed="$2" phase="$3" details
  details="$(node -e '
    console.log(JSON.stringify({name: process.argv[1], passed: process.argv[2] === "true"}));
  ' "${invariant}" "${passed}")"
  if [ -n "${run_id}" ]; then
    node "${ATTACKNET_DIR}/observability/event.mjs" \
      --kind=invariant.observed "--network=${network}" "--run-id=${run_id}" \
      "--phase=${phase}" "--event-id=${run_id}-${name}-${invariant}-${phase}" \
      "--campaign=${name}" "--outcome=$([ "${passed}" = true ] && echo pass || echo fail)" \
      "--details=${details}" >"${destination}/event.json"
    KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
      "${ATTACKNET_DIR}/observability/emit-kubernetes-event.sh" "${destination}/event.json" \
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
  emit_invariant baseline-health false baseline || true
  fail_campaign 'baseline invariant failed before fault injection'
fi
emit_invariant baseline-health true baseline
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/before-runtime.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-before.jsonl"; fi

scheduled_details="$(node -e '
  const fs=require("node:fs");
  const e=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  console.log(JSON.stringify({actors:e.selectedActors,signerImpact:e.signerImpact,safety:e.safety}));
' "${resource}.evidence.json")"
event_phase=injecting
emit_event fault.scheduled injecting "" "${scheduled_details}"
kubectl -n "${namespace}" apply -f "${resource}" >"${destination}/apply.log"
kubectl -n "${namespace}" wait --for=condition=AllInjected "${kind}/${name}" \
  --timeout="${ATTACKNET_INJECTION_TIMEOUT:-90s}" >"${destination}/injected.log"
injected=true
event_phase=fault-active
for actor in ${selected_actors}; do
  emit_event fault.injected fault-active "${actor}" '{"injected":true}'
done
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/during-chaos.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-during.jsonl"; fi
sleep "$((duration_seconds + ${ATTACKNET_CHAOS_SETTLE_SECONDS:-5}))"
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/after-duration.json" 2>/dev/null || true
cleanup
trap - EXIT INT TERM

event_phase=recovering
recovery_started="$(date +%s)"
deadline=$((SECONDS + ${ATTACKNET_RECOVERY_TIMEOUT_SECONDS:-300}))
until ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot >"${destination}/after-verification.json" 2>"${destination}/recovery-errors.log"; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    emit_invariant recovery-health false verification || true
    fail_campaign 'network did not recover before the campaign deadline'
  fi
  sleep 5
done
emit_invariant recovery-health true verification
recovery_duration=$(( $(date +%s) - recovery_started ))
emit_event recovery.complete verification "" "{\"durationSeconds\":${recovery_duration}}"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-after.jsonl"; fi
event_phase=verification
if ! ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  ATTACKNET_PROGRESS_WINDOW_SECONDS="${ATTACKNET_POST_CHAOS_PROGRESS_SECONDS:-45}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" progress \
  >"${destination}/post-chaos-progress.json" 2>"${destination}/post-chaos-progress.stderr"; then
  emit_invariant post-chaos-progress false verification || true
  fail_campaign 'post-chaos burnchain and Stacks progress invariant failed'
fi
emit_invariant post-chaos-progress true verification
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/after-runtime.json"
echo "Campaign evidence: ${destination}"
