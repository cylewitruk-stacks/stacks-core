#!/usr/bin/env bash
set -euo pipefail

resource="${1:?Chaos resource JSON required}"
output="${2:?clearance output JSON required}"
timeout="${ATTACKNET_CHAOS_RECOVERY_TIMEOUT:-90s}"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"

read -r namespace kind name < <(node -e '
  const fs=require("node:fs");
  const value=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  console.log(value.metadata.namespace, value.kind.toLowerCase(), value.metadata.name);
' "${resource}")

mkdir -p "$(dirname "${output}")"
present=true recovered=false delete_succeeded=false absent=false
if ! "${kubectl_bin}" -n "${namespace}" get "${kind}/${name}" >/dev/null 2>&1; then
  present=false
  recovered=true
  delete_succeeded=true
  absent=true
else
  if "${kubectl_bin}" -n "${namespace}" wait --for=condition=AllRecovered \
    "${kind}/${name}" --timeout="${timeout}" >/dev/null 2>&1; then
    recovered=true
  fi
  if "${kubectl_bin}" -n "${namespace}" delete -f "${resource}" \
    --ignore-not-found --wait=true >/dev/null 2>&1; then
    delete_succeeded=true
  fi
  if ! "${kubectl_bin}" -n "${namespace}" get "${kind}/${name}" >/dev/null 2>&1; then
    absent=true
  fi
fi

PRESENT="${present}" RECOVERED="${recovered}" DELETE_SUCCEEDED="${delete_succeeded}" \
ABSENT="${absent}" NAMESPACE="${namespace}" KIND="${kind}" NAME="${name}" node -e '
  const yes = value => value === "true";
  const result = {
    schemaVersion: 1,
    namespace: process.env.NAMESPACE,
    resource: `${process.env.KIND}/${process.env.NAME}`,
    initiallyPresent: yes(process.env.PRESENT),
    allRecoveredObserved: yes(process.env.RECOVERED),
    deleteSucceeded: yes(process.env.DELETE_SUCCEEDED),
    resourceAbsent: yes(process.env.ABSENT),
  };
  result.cleared = result.deleteSucceeded && result.resourceAbsent;
  result.graceful = result.allRecoveredObserved && result.cleared;
  console.log(JSON.stringify(result, null, 2));
' >"${output}"

jq -e '.graceful == true' "${output}" >/dev/null
