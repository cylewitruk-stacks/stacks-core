#!/bin/bash
set -euo pipefail

endpoint="${ATTACKNET_EVENT_ENDPOINT:-${1:-}}"
token_file="${ATTACKNET_EVENT_TOKEN_FILE:-${2:-}}"
event_file="${3:-}"

if [ -z "${endpoint}" ] || [ -z "${token_file}" ] || [ -z "${event_file}" ]; then
  echo "usage: emit-event.sh EVENT_ENDPOINT TOKEN_FILE EVENT_JSON" >&2
  exit 2
fi
if [ ! -r "${token_file}" ] || [ ! -r "${event_file}" ]; then
  echo "token and event files must be readable" >&2
  exit 2
fi

token="$(tr -d '\r\n' <"${token_file}")"
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  --data-binary "@${event_file}" \
  "${endpoint%/}/api/v1/events"
echo
