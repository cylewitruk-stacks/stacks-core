#!/bin/bash
set -euo pipefail

NAMESPACE="${KUBE_NAMESPACE:-hacknet-system}"
NETWORK="${KUBE_NETWORK:-attacknet}"
CONFIG_MAP="${NETWORK}-burnchain-policy"
kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
lock_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/environment-lock.sh"

if [ "${ATTACKNET_LOCK_DISABLED:-0}" = 1 ]; then
  [ "${ATTACKNET_NEGATIVE_CONTROL:-0}" = 1 ] || {
    echo 'ATTACKNET_LOCK_DISABLED=1 requires ATTACKNET_NEGATIVE_CONTROL=1' >&2
    exit 2
  }
elif [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
  exec "${lock_script}" run "${NETWORK}" "${ATTACKNET_LOCK_OWNER:-burnchain-policy:$$}" \
    burnchain-policy -- "$0" "$@"
else
  "${lock_script}" assert "${NETWORK}" "${ATTACKNET_MUTATION_TOKEN}"
fi

current_policy="$(${kubectl_bin} -n "${NAMESPACE}" get configmap "${CONFIG_MAP}" \
    -o jsonpath='{.data.policy\.env}')"

clock_status_value() {
  local key="$1" status
  local clock_pod
  clock_pod="$(${kubectl_bin} -n "${NAMESPACE}" get pods \
    -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor=bitcoin-miner" \
    -o jsonpath='{.items[0].metadata.name}')"
  status="$(${kubectl_bin} -n "${NAMESPACE}" exec "${clock_pod}" -c actor -- \
    cat /tmp/hacknet-burnchain-clock.env 2>/dev/null || true)"
  sed -n "s/^${key}=//p" <<<"${status}" | tail -1
}

value() {
  local key="$1" fallback="$2" result
  result="$(sed -n "s/^${key}=//p" <<<"${current_policy}" | tail -1)"
  printf '%s\n' "${result:-${fallback}}"
}

generation="$(value GENERATION 0)"
[[ "${generation}" =~ ^[0-9]+$ ]] || generation=0
generation=$((generation + 1))
mode="$(value MODE run)"
interval="$(value INTERVAL_SECONDS 60)"
jitter="$(value JITTER_SECONDS 0)"
burst=0
burst_target=0
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
    # A burst is an exact number of blocks followed by a paused clock.  Keeping
    # MODE=run here used to let the next loop iteration continue mining after
    # BURST_BLOCKS reached zero, so lifecycle phase barriers were aspirational.
    mode=pause
    burst="${2:?burst block count required}"
    interval="${3:-${interval}}"
    current_height="$(clock_status_value bitcoin_height)"
    [[ "${current_height}" =~ ^[0-9]+$ ]] || {
      echo "could not derive the current Bitcoin height for an idempotent burst" >&2
      exit 1
    }
    burst_target=$((current_height + burst))
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

policy="$(printf 'GENERATION=%s\nMODE=%s\nINTERVAL_SECONDS=%s\nJITTER_SECONDS=%s\nBURST_BLOCKS=%s\nBURST_TARGET_HEIGHT=%s\nADDRESS_MODE=%s\nFIXED_ADDRESS_INDEX=%s\n' \
  "${generation}" "${mode}" "${interval}" "${jitter}" "${burst}" "${burst_target}" "${address_mode}" "${fixed_index}")"
patch="$(POLICY="${policy}" node -e 'process.stdout.write(JSON.stringify({data:{"policy.env":process.env.POLICY}}))')"
${kubectl_bin} -n "${NAMESPACE}" patch configmap "${CONFIG_MAP}" --type=merge -p "${patch}" >/dev/null
# Changing a Pod annotation asks kubelet to refresh projected volumes promptly;
# it does not roll or mutate the actor container. Wait for the admitted policy
# to be visible, then interrupt the current sleep with a no-op signal so the
# clock applies it immediately.
pod="$(${kubectl_bin} -n "${NAMESPACE}" get pods \
  -l "testing.stacks.org/network=${NETWORK},testing.stacks.org/actor=bitcoin-miner" \
  -o jsonpath='{.items[0].metadata.name}')"
${kubectl_bin} -n "${NAMESPACE}" annotate pod "${pod}" \
  "testing.stacks.org/policy-generation=${generation}" --overwrite >/dev/null
deadline=$((SECONDS + ${BURNCHAIN_POLICY_APPLY_TIMEOUT_SECONDS:-30}))
while [ "${SECONDS}" -lt "${deadline}" ]; do
  admitted="$(${kubectl_bin} -n "${NAMESPACE}" exec "${pod}" -c actor -- \
    sed -n 's/^GENERATION=//p' /run/hacknet-policy/policy.env 2>/dev/null | tail -1 || true)"
  if [ "${admitted}" = "${generation}" ]; then break; fi
  sleep 1
done
if [ "${admitted:-}" != "${generation}" ]; then
  echo "policy generation ${generation} was not projected before the deadline" >&2
  exit 1
fi
${kubectl_bin} -n "${NAMESPACE}" exec "${pod}" -c actor -- sh -c 'kill -USR2 1'
# Projection proves what kubelet mounted; this second acknowledgment proves the
# long-lived clock process has read and applied it.  In pause mode it also
# establishes the upper bound on any already-in-flight generatetoaddress call.
deadline=$((SECONDS + ${BURNCHAIN_POLICY_APPLY_TIMEOUT_SECONDS:-30}))
while [ "${SECONDS}" -lt "${deadline}" ]; do
  applied="$(${kubectl_bin} -n "${NAMESPACE}" exec "${pod}" -c actor -- \
    sed -n 's/^policy_generation=//p' /tmp/hacknet-burnchain-clock.env 2>/dev/null | tail -1 || true)"
  if [ "${applied}" = "${generation}" ]; then break; fi
  sleep 1
done
if [ "${applied:-}" != "${generation}" ]; then
  echo "burnchain clock did not acknowledge policy generation ${generation} before the deadline" >&2
  exit 1
fi
printf 'Applied %s generation %s: mode=%s interval=%ss jitter=%ss burst=%s target=%s address=%s:%s\n' \
  "${CONFIG_MAP}" "${generation}" "${mode}" "${interval}" "${jitter}" "${burst}" \
  "${burst_target}" "${address_mode}" "${fixed_index}"

# This observation is intentionally emitted only after both kubelet projection
# and the long-lived clock process acknowledge the generation. Actor Pods never
# receive the journal token; the trusted bridge posts this orchestrator-created
# record to loopback using its own projected credential.
if [ "${ATTACKNET_OBSERVABILITY_ENABLED:-1}" = 1 ]; then
  event_args=(--kind=policy.changed "--phase=${ATTACKNET_EVENT_PHASE:-baseline}")
  if [ -n "${ATTACKNET_EVENT_CAMPAIGN:-}" ]; then
    event_args+=("--campaign=${ATTACKNET_EVENT_CAMPAIGN}")
  fi
  details="$(MODE="${mode}" GENERATION="${generation}" INTERVAL="${interval}" \
    JITTER="${jitter}" BURST="${burst}" BURST_TARGET="${burst_target}" ADDRESS_MODE="${address_mode}" \
    FIXED_INDEX="${fixed_index}" node -e '
      console.log(JSON.stringify({
        mode: process.env.MODE,
        generation: Number(process.env.GENERATION),
        intervalSeconds: Number(process.env.INTERVAL),
        jitterSeconds: Number(process.env.JITTER),
        burstBlocks: Number(process.env.BURST),
        burstTargetHeight: Number(process.env.BURST_TARGET),
        addressMode: process.env.ADDRESS_MODE,
        fixedAddressIndex: Number(process.env.FIXED_INDEX),
        applied: true,
      }));
    ')"
  if ! KUBE_NAMESPACE="${NAMESPACE}" KUBE_NETWORK="${NETWORK}" \
    "$(dirname "${BASH_SOURCE[0]}")/../../../observability/record-event.sh" \
      "${event_args[@]}" "--details=${details}" >/dev/null; then
    echo "warning: applied policy generation ${generation}, but could not journal policy.changed" >&2
    [ "${ATTACKNET_EVENT_STRICT:-0}" != 1 ] || exit 1
  fi
fi
