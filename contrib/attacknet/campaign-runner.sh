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

namespace="$(node -e 'console.log(require(process.argv[1]).metadata.namespace)' "${resource}")"
network="$(node -e 'console.log(require(process.argv[1]).metadata.labels["testing.stacks.org/network"])' "${resource}")"
kind="$(node -e 'console.log(require(process.argv[1]).kind.toLowerCase())' "${resource}")"
name="$(node -e 'console.log(require(process.argv[1]).metadata.name)' "${resource}")"
duration_seconds="$(node -e '
  const value=require(process.argv[1]).spec.duration;
  const match=/^(\d+)(ms|s|m|h)$/.exec(value);
  const scalar={ms:.001,s:1,m:60,h:3600}[match[2]];
  console.log(Math.ceil(Number(match[1])*scalar));
' "${resource}")"
selected_actors="$(node -e 'console.log(require(process.argv[1]).selectedActors.join(" "))' "${resource}.evidence.json")"

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
  kubectl -n "${namespace}" delete -f "${resource}" --ignore-not-found --wait=true \
    >"${destination}/cleanup.log" 2>&1 || true
}
trap cleanup EXIT INT TERM

ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot >"${destination}/before-verification.json"
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/before-runtime.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-before.jsonl"; fi

kubectl -n "${namespace}" apply -f "${resource}" >"${destination}/apply.log"
kubectl -n "${namespace}" wait --for=condition=AllInjected "${kind}/${name}" \
  --timeout="${ATTACKNET_INJECTION_TIMEOUT:-90s}" >"${destination}/injected.log"
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/during-chaos.json"
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-during.jsonl"; fi
sleep "$((duration_seconds + ${ATTACKNET_CHAOS_SETTLE_SECONDS:-5}))"
kubectl -n "${namespace}" get "${kind}/${name}" -o json >"${destination}/after-duration.json" 2>/dev/null || true
cleanup
trap - EXIT INT TERM

deadline=$((SECONDS + ${ATTACKNET_RECOVERY_TIMEOUT_SECONDS:-300}))
until ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot >"${destination}/after-verification.json" 2>"${destination}/recovery-errors.log"; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "network did not recover before the campaign deadline" >&2
    exit 1
  fi
  sleep 5
done
if [ "${kind}" = timechaos ]; then capture_clocks "${destination}/clocks-after.jsonl"; fi
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  ATTACKNET_PROGRESS_WINDOW_SECONDS="${ATTACKNET_POST_CHAOS_PROGRESS_SECONDS:-45}" \
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" progress >"${destination}/post-chaos-progress.json"
ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/runtime-backend.sh" describe >"${destination}/after-runtime.json"
echo "Campaign evidence: ${destination}"
