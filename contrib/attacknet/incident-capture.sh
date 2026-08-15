#!/bin/bash
set -u

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
destination="${1:?incident evidence directory required}"
manifest="${2:?manifest path required}"
phase="${3:?incident phase required}"
reason="${4:?incident reason required}"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
run_id="${ATTACKNET_RUN_ID:-unknown}"
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

event_pod="$(kubectl -n "${namespace}" get pods \
  -l "testing.stacks.org/network=${network},app.kubernetes.io/name=attacknet-events" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -n "${event_pod}" ]; then
  if kubectl -n "${namespace}" exec "${event_pod}" -c events -- python3 -c \
    'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9464/api/v1/events?after=0&limit=10000", timeout=10).read().decode())' \
    >"${destination}/trusted-events.json" 2>"${destination}/trusted-events.stderr"; then
    node -e '
      const fs = require("node:fs");
      const page = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const runId = process.argv[3];
      for (const event of page.events.filter(event => runId === "unknown" || event.runId === runId)) {
        process.stdout.write(`${JSON.stringify(event)}\n`);
      }
    ' "${destination}/trusted-events.json" "${destination}/trusted-events.jsonl" "${run_id}" \
      >"${destination}/trusted-events.jsonl"
    node "${ATTACKNET_DIR}/observability/report.mjs" \
      "${destination}/trusted-events.jsonl" "${destination}/timeline.html" \
      || capture_error timeline-report "$?"
  else
    capture_error trusted-event-journal "$?"
  fi
else
  capture_error trusted-event-pod-missing 1
fi

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
