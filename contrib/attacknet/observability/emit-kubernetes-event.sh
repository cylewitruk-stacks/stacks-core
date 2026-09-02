#!/bin/bash
set -euo pipefail

namespace="${KUBE_NAMESPACE:-hacknet-system}"
network="${KUBE_NETWORK:-attacknet}"
event_file="${1:--}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
attempts="${ATTACKNET_EVENT_WRITE_ATTEMPTS:-3}"

[[ "${attempts}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'ATTACKNET_EVENT_WRITE_ATTEMPTS must be a positive integer' >&2
  exit 2
}

if [ "${event_file}" != - ] && [ ! -r "${event_file}" ]; then
  echo "event file is not readable: ${event_file}" >&2
  exit 2
fi

pod="$(${kubectl_bin} -n "${namespace}" get pods \
  -l "testing.stacks.org/network=${network},app.kubernetes.io/name=attacknet-events" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [ -z "${pod}" ]; then
  echo "no running trusted event-journal Pod for ${network}" >&2
  exit 1
fi

# The bearer token never enters an actor Pod, host process arguments, or shell
# output. The trusted journal reads its projected Secret and posts the
# orchestrator-supplied event to loopback.
post=(${kubectl_bin} -n "${namespace}" exec -i "${pod}" -c events -- python3 -c '
import json, pathlib, sys, urllib.request
body = sys.stdin.buffer.read()
json.loads(body)
token = pathlib.Path("/run/secrets/attacknet/token").read_text().strip()
request = urllib.request.Request("http://127.0.0.1:9464/api/v1/events", data=body,
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(request, timeout=10) as response:
    print(response.read().decode())
')
payload_file="${event_file}"
temporary=""
if [ "${event_file}" = - ]; then
  temporary="$(mktemp)"
  trap 'rm -f "${temporary}"' EXIT
  cat >"${temporary}"
  payload_file="${temporary}"
fi

for ((attempt = 1; attempt <= attempts; attempt++)); do
  if "${post[@]}" <"${payload_file}"; then
    exit 0
  fi
  if [ "${attempt}" -lt "${attempts}" ]; then
    echo "trusted event write attempt ${attempt}/${attempts} failed; retrying" >&2
    sleep 1
  fi
done
echo "trusted event write failed after ${attempts} attempts" >&2
exit 1
