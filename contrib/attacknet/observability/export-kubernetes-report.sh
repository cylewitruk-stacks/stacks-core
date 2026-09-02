#!/bin/bash
set -euo pipefail

OBSERVABILITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
output="${1:?output directory required}"
run_id="${2:-${ATTACKNET_RUN_ID:-}}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
page_limit="${ATTACKNET_EVENT_PAGE_LIMIT:-10000}"

if [ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" = 0 ]; then
  mkdir -p "${output}/timeline-pages"
  : >"${output}/timeline.all.jsonl"
  : >"${output}/timeline.jsonl"
  node "${OBSERVABILITY_DIR}/report.mjs" \
    "${output}/timeline.jsonl" "${output}/timeline.html" >/dev/null
  NAMESPACE="${namespace}" NETWORK="${network}" RUN_ID="${run_id:-all}" node -e '
    console.log(JSON.stringify({
      schemaVersion:"stacks-attacknet-timeline-export/v1",
      exportedAt:new Date().toISOString(), namespace:process.env.NAMESPACE,
      network:process.env.NETWORK, runId:process.env.RUN_ID,
      pageCount:0, eventCount:0, source:"disabled-by-configuration",
    }, null, 2));
  ' >"${output}/export.json"
  echo "Attacknet timeline disabled by configuration: ${output}/timeline.html"
  exit 0
fi

[[ "${page_limit}" =~ ^[1-9][0-9]*$ ]] && [ "${page_limit}" -le 10000 ] || {
  echo 'ATTACKNET_EVENT_PAGE_LIMIT must be within [1, 10000]' >&2
  exit 2
}

pod="$(${kubectl_bin} -n "${namespace}" get pods \
  -l "testing.stacks.org/network=${network},app.kubernetes.io/name=attacknet-events" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [ -z "${pod}" ]; then
  echo "no running trusted event-journal Pod for ${network}" >&2
  exit 1
fi

mkdir -p "${output}/timeline-pages"
: >"${output}/timeline.all.jsonl"
after=0
page=0
while true; do
  page=$((page + 1))
  response="${output}/timeline-pages/page-${page}.json"
  ${kubectl_bin} -n "${namespace}" exec "${pod}" -c events -- \
    python3 -c 'import sys, urllib.request
after, limit = sys.argv[1:]
url = f"http://127.0.0.1:9464/api/v1/events?after={after}&limit={limit}"
print(urllib.request.urlopen(url, timeout=10).read().decode())' \
    "${after}" "${page_limit}" >"${response}"
  read -r count last_sequence < <(node -e '
    const fs=require("node:fs");
    const page=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!Array.isArray(page.events)) throw new Error("event API response has no events array");
    console.log(page.events.length, page.events.at(-1)?.sequence ?? 0);
  ' "${response}")
  if [ "${count}" -eq 0 ]; then break; fi
  node -e '
    const fs=require("node:fs");
    const page=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    for (const event of page.events) process.stdout.write(`${JSON.stringify(event)}\n`);
  ' "${response}" >>"${output}/timeline.all.jsonl"
  after="${last_sequence}"
  if [ "${count}" -lt "${page_limit}" ]; then break; fi
done

if [ -n "${run_id}" ]; then
  RUN_ID="${run_id}" node -e '
    const fs=require("node:fs");
    const input=fs.readFileSync(process.argv[1], "utf8").split(/\n/).filter(Boolean);
    for (const line of input) {
      const event=JSON.parse(line);
      if (event.runId === process.env.RUN_ID) process.stdout.write(`${line}\n`);
    }
  ' "${output}/timeline.all.jsonl" >"${output}/timeline.jsonl"
else
  cp "${output}/timeline.all.jsonl" "${output}/timeline.jsonl"
fi

node "${OBSERVABILITY_DIR}/report.mjs" \
  "${output}/timeline.jsonl" "${output}/timeline.html" >/dev/null
event_count="$(wc -l <"${output}/timeline.jsonl" | tr -d ' ')"
NAMESPACE="${namespace}" NETWORK="${network}" RUN_ID="${run_id:-all}" \
  PAGE_COUNT="${page}" EVENT_COUNT="${event_count}" node -e '
    console.log(JSON.stringify({
      schemaVersion: "stacks-attacknet-timeline-export/v1",
      exportedAt: new Date().toISOString(),
      namespace: process.env.NAMESPACE,
      network: process.env.NETWORK,
      runId: process.env.RUN_ID,
      pageCount: Number(process.env.PAGE_COUNT),
      eventCount: Number(process.env.EVENT_COUNT),
      source: "trusted-event-journal-loopback",
    }, null, 2));
  ' >"${output}/export.json"
echo "Attacknet timeline (${event_count} events): ${output}/timeline.html"
