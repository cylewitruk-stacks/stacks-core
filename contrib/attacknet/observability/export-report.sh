#!/bin/bash
set -euo pipefail

OBSERVABILITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
endpoint="${1:?event endpoint required}"
output="${2:?output directory required}"
mkdir -p "${output}"

after=0
page=0
: >"${output}/timeline.jsonl"
while true; do
  page=$((page + 1))
  response="${output}/timeline-page-${page}.json"
  curl --fail --silent --show-error "${endpoint%/}/api/v1/events?after=${after}&limit=10000" >"${response}"
  count="$(node -e 'const fs=require("node:fs"); const p=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); console.log(p.events.length)' "${response}")"
  if [ "${count}" -eq 0 ]; then
    break
  fi
  node -e 'const fs=require("node:fs"); const p=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); for (const e of p.events) console.log(JSON.stringify(e))' "${response}" >>"${output}/timeline.jsonl"
  after="$(node -e 'const fs=require("node:fs"); const p=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); console.log(p.events.at(-1).sequence)' "${response}")"
  if [ "${count}" -lt 10000 ]; then
    break
  fi
done

node "${OBSERVABILITY_DIR}/report.mjs" "${output}/timeline.jsonl" "${output}/timeline.html"
echo "Attacknet timeline: ${output}/timeline.html"
