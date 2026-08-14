#!/bin/bash
set -euo pipefail

NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
NETWORK="${KUBE_NETWORK:-attacknet}"
CONFIG_MAP="${NETWORK}-burnchain-policy"

current_policy="$(kubectl -n "${NAMESPACE}" get configmap "${CONFIG_MAP}" \
  -o jsonpath='{.data.policy\.env}')"
value() {
  local key="$1" fallback="$2" result
  result="$(sed -n "s/^${key}=//p" <<<"${current_policy}" | tail -1)"
  printf '%s\n' "${result:-${fallback}}"
}

generation="$(value GENERATION 0)"
[[ "${generation}" =~ ^[0-9]+$ ]] || generation=0
generation=$((generation + 1))
mode="$(value MODE run)"
interval="$(value INTERVAL_SECONDS 20)"
jitter="$(value JITTER_SECONDS 0)"
burst=0
address_mode="$(value ADDRESS_MODE round-robin)"
fixed_index="$(value FIXED_ADDRESS_INDEX 0)"

case "${1:-}" in
  run)
    mode=run
    interval="${2:-${interval}}"
    jitter="${3:-${jitter}}"
    ;;
  pause) mode=pause ;;
  burst)
    mode=run
    burst="${2:?burst block count required}"
    ;;
  fixed-address)
    address_mode=fixed
    fixed_index="${2:?zero-based address index required}"
    ;;
  round-robin) address_mode=round-robin ;;
  *)
    echo "usage: $0 {run [interval [jitter]]|pause|burst BLOCKS|fixed-address INDEX|round-robin}" >&2
    exit 2
    ;;
esac

[[ "${interval}" =~ ^[0-9]+$ && "${jitter}" =~ ^[0-9]+$ \
  && "${burst}" =~ ^[0-9]+$ && "${fixed_index}" =~ ^[0-9]+$ ]] || {
  echo "interval, jitter, burst, and address index must be non-negative integers" >&2
  exit 2
}
[ "${interval}" -le 3600 ] && [ "${jitter}" -le 3600 ] || {
  echo "interval and jitter must not exceed 3600 seconds" >&2
  exit 2
}

policy="$(printf 'GENERATION=%s\nMODE=%s\nINTERVAL_SECONDS=%s\nJITTER_SECONDS=%s\nBURST_BLOCKS=%s\nADDRESS_MODE=%s\nFIXED_ADDRESS_INDEX=%s\n' \
  "${generation}" "${mode}" "${interval}" "${jitter}" "${burst}" "${address_mode}" "${fixed_index}")"
patch="$(POLICY="${policy}" node -e 'process.stdout.write(JSON.stringify({data:{"policy.env":process.env.POLICY}}))')"
kubectl -n "${NAMESPACE}" patch configmap "${CONFIG_MAP}" --type=merge -p "${patch}" >/dev/null
# Changing a Pod annotation asks kubelet to refresh projected volumes promptly;
# it does not roll or mutate the actor container. Wait for the admitted policy
# to be visible, then interrupt the current sleep with a no-op signal so the
# clock applies it immediately.
pod="$(kubectl -n "${NAMESPACE}" get pods \
  -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor=bitcoin-miner" \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "${NAMESPACE}" annotate pod "${pod}" \
  "testing.stacks.org/policy-generation=${generation}" --overwrite >/dev/null
deadline=$((SECONDS + ${BURNCHAIN_POLICY_APPLY_TIMEOUT_SECONDS:-30}))
while [ "${SECONDS}" -lt "${deadline}" ]; do
  admitted="$(kubectl -n "${NAMESPACE}" exec "${pod}" -c actor -- \
    sed -n 's/^GENERATION=//p' /run/hacknet-policy/policy.env 2>/dev/null | tail -1 || true)"
  if [ "${admitted}" = "${generation}" ]; then break; fi
  sleep 1
done
if [ "${admitted:-}" != "${generation}" ]; then
  echo "policy generation ${generation} was not projected before the deadline" >&2
  exit 1
fi
kubectl -n "${NAMESPACE}" exec "${pod}" -c actor -- sh -c 'kill -USR2 1'
printf 'Applied %s generation %s: mode=%s interval=%ss jitter=%ss burst=%s address=%s:%s\n' \
  "${CONFIG_MAP}" "${generation}" "${mode}" "${interval}" "${jitter}" "${burst}" \
  "${address_mode}" "${fixed_index}"
