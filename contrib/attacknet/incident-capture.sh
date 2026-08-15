#!/bin/bash
set -u

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
original_args=("$@")
usage() {
  echo "usage: $0 DESTINATION MANIFEST PHASE REASON" >&2
  echo "   or: $0 --destination=PATH --manifest=PATH --phase=NAME --reason=TEXT" >&2
}

destination= manifest= phase= reason=
if [[ "${1:-}" == --* ]]; then
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --destination=*) destination="${1#*=}" ;;
      --manifest=*) manifest="${1#*=}" ;;
      --phase=*) phase="${1#*=}" ;;
      --reason=*) reason="${1#*=}" ;;
      --help) usage; exit 0 ;;
      *) echo "unknown incident-capture option: $1" >&2; usage; exit 2 ;;
    esac
    shift
  done
else
  [ "$#" -eq 4 ] || { usage; exit 2; }
  destination="$1"
  manifest="$2"
  phase="$3"
  reason="$4"
fi

[ -n "${destination}" ] && [ -n "${manifest}" ] && [ -n "${phase}" ] && [ -n "${reason}" ] \
  || { echo 'all incident-capture fields are required' >&2; usage; exit 2; }
read -r manifest_network manifest_namespace < <(node -e '
  const fs = require("node:fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!manifest.network || !manifest.namespace) {
    throw new Error("manifest must define network and namespace");
  }
  process.stdout.write(`${manifest.network} ${manifest.namespace}\n`);
' "${manifest}") || exit 2
namespace="${KUBE_NAMESPACE:-${manifest_namespace}}"
network="${KUBE_NETWORK:-${manifest_network}}"
lock_script="${ATTACKNET_DIR}/environment-lock.sh"
if [ "${ATTACKNET_LOCK_DISABLED:-0}" = 1 ]; then
  [ "${ATTACKNET_NEGATIVE_CONTROL:-0}" = 1 ] || {
    echo 'ATTACKNET_LOCK_DISABLED=1 requires ATTACKNET_NEGATIVE_CONTROL=1' >&2
    exit 2
  }
elif [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
  exec "${lock_script}" run "${network}" "${ATTACKNET_LOCK_OWNER:-incident:$$}" \
    incident-capture -- "$0" "${original_args[@]}"
else
  "${lock_script}" assert "${network}" "${ATTACKNET_MUTATION_TOKEN}"
fi
run_descriptor="$(node "${ATTACKNET_DIR}/run-ledger.mjs" locate \
  "--target=${manifest}" "--namespace=${namespace}" "--network=${network}" 2>/dev/null || true)"
run_id="${ATTACKNET_RUN_ID:-}"
if [ -z "${run_id}" ] && [ -r "${run_descriptor}" ]; then
  run_id="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1],"utf8")).run.id)' "${run_descriptor}")"
fi
run_id="${run_id:-unknown}"
printf 'Capturing incident network=%s namespace=%s phase=%s destination=%s\n' \
  "${network}" "${namespace}" "${phase}" "${destination}"
mkdir -p "${destination}"

source "${ATTACKNET_DIR}/runtime-backend.sh"
source "${ATTACKNET_DIR}/evidence-harness.sh"

errors="${destination}/capture-errors.jsonl"
: >"${errors}"
capture_error() {
  local probe="$1" status="$2"
  PROBE="${probe}" STATUS="${status}" node -e '
    console.log(JSON.stringify({
      probe: process.env.PROBE,
      status: Number(process.env.STATUS),
      occurredAt: new Date().toISOString(),
    }));
  ' >>"${errors}"
}

# Seal and export the causal record before any cleanup or broad evidence probe.
# A campaign may already have finalized it; direct incident capture must be
# equally safe and finalize a still-running descriptor as failed.
if [ -r "${run_descriptor}" ]; then
  descriptor_status="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1],"utf8")).run.status)' "${run_descriptor}")"
  if [ "${descriptor_status}" = running ]; then
    incident_assertion="$(REASON="${reason}" PHASE="${phase}" node -e '
      console.log(JSON.stringify({assertion:`incident-${process.env.PHASE}`,status:"fail",details:{reason:process.env.REASON}}));
    ')"
    node "${ATTACKNET_DIR}/run-ledger.mjs" append "${run_descriptor}" assertion-result \
      "${incident_assertion}" >/dev/null || capture_error run-ledger-append "$?"
    node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${run_descriptor}" failed >/dev/null \
      || capture_error run-ledger-finalize "$?"
  fi
  node "${ATTACKNET_DIR}/run-ledger.mjs" export "${run_descriptor}" "${destination}/run" >/dev/null \
    || capture_error run-ledger-export "$?"
fi
if [ "${run_id}" != unknown ]; then
  incident_details="$(REASON="${reason}" node -e 'console.log(JSON.stringify({reason:process.env.REASON}))')"
  KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
    "${ATTACKNET_DIR}/observability/record-event.sh" --kind=incident.opened --phase=incident \
    "--details=${incident_details}" >/dev/null || capture_error incident-event "$?"
  KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${run_id}" \
    "${ATTACKNET_DIR}/observability/record-actor-states.sh" incident \
    || capture_error incident-actor-states "$?"
fi
timeline_run_id="${run_id}"
[ "${timeline_run_id}" != unknown ] || timeline_run_id=""
KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" ATTACKNET_RUN_ID="${timeline_run_id}" \
  "${ATTACKNET_DIR}/observability/export-kubernetes-report.sh" \
  "${destination}/timeline" "${timeline_run_id}" >/dev/null \
  || capture_error incident-timeline-export "$?"

SOURCE_REVISION="$(git -C "${ATTACKNET_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  INCIDENT_PHASE="${phase}" INCIDENT_REASON="${reason}" RUN_ID="${run_id}" \
  NETWORK="${network}" NAMESPACE="${namespace}" node -e '
    console.log(JSON.stringify({
      schemaVersion: "stacks-attacknet-incident/v1",
      attribution: "Untriaged",
      capturedAt: new Date().toISOString(),
      runId: process.env.RUN_ID,
      network: process.env.NETWORK,
      namespace: process.env.NAMESPACE,
      phase: process.env.INCIDENT_PHASE,
      reason: process.env.INCIDENT_REASON,
      sourceRevision: process.env.SOURCE_REVISION,
      preservation: "network-left-running; no-new-faults",
    }, null, 2));
  ' >"${destination}/incident.json"

cp "${manifest}" "${destination}/manifest.json" || capture_error manifest-copy "$?"

ATTACKNET_BACKEND=kubernetes KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  evidence_capture_all "${destination}/actors" "${manifest}" \
  "${ATTACKNET_INCIDENT_LOG_SINCE:-2h}" || capture_error actor-evidence "$?"

KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" \
  "${ATTACKNET_DIR}/lifecycle.sh" capture "${destination}/kubernetes" \
  || capture_error kubernetes-evidence "$?"

kubectl -n "${namespace}" get configmap "${network}-burnchain-policy" -o json \
  >"${destination}/burnchain-policy.admitted.json" 2>"${destination}/burnchain-policy.stderr" \
  || capture_error burnchain-policy "$?"
kubectl -n "${namespace}" get podchaos,networkchaos,dnschaos,iochaos,timechaos \
  -l "testing.stacks.org/network=${network}" -o json \
  >"${destination}/chaos-mesh.json" 2>"${destination}/chaos-mesh.stderr" \
  || capture_error chaos-mesh "$?"

mkdir -p "${destination}/previous-logs"
evidence_inventory "${manifest}"
for actor in bitcoin bitcoin-miner stacker ${EVIDENCE_ACTORS}; do
  pod="$(KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}" backend_pod "${actor}" 2>/dev/null || true)"
  if [ -z "${pod}" ]; then
    capture_error "previous-log:${actor}:pod-missing" 1
    continue
  fi
  if ! kubectl -n "${namespace}" logs "${pod}" -c actor --previous --timestamps \
    --tail=20000 >"${destination}/previous-logs/${actor}.log" 2>"${destination}/previous-logs/${actor}.stderr"; then
    # No previous container is normal; retain stderr so absence is explicit.
    printf '# no previous actor container log available\n' >"${destination}/previous-logs/${actor}.log"
  fi
done

(cd "${destination}" && find . -type f ! -name digests.sha256 -print0 \
  | sort -z | xargs -0 shasum -a 256) >"${destination}/digests.sha256" \
  || capture_error digest-inventory "$?"

DESTINATION="${destination}" node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const root = process.env.DESTINATION;
  const required = [
    "incident.json", "manifest.json", "actors/runtime.json",
    "kubernetes/stacksnetwork.admitted.json", "kubernetes/pods.admitted.json",
    "burnchain-policy.admitted.json", "chaos-mesh.json", "digests.sha256",
    "timeline/export.json", "timeline/timeline.jsonl", "timeline/timeline.html",
  ];
  const missing = required.filter(file => !fs.existsSync(path.join(root, file)));
  const captureErrors = fs.readFileSync(path.join(root, "capture-errors.jsonl"), "utf8")
    .trim().split(/\n+/).filter(Boolean).map(JSON.parse);
  console.log(JSON.stringify({
    schemaVersion: "stacks-attacknet-capture/v1",
    complete: missing.length === 0 && captureErrors.length === 0,
    required,
    missing,
    captureErrors,
  }, null, 2));
' >"${destination}/completeness.json"

echo "Incident evidence preserved at ${destination}"
