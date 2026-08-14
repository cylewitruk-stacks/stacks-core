#!/bin/bash

# Shared PoC invariant: a signer's event-driven state machine must follow its
# own companion, not merely the network's primary node. Callers provide the
# backend_exec() helper and generated MANIFEST path.
signer_companion_drift_report() {
  local max_drift="${1:-2}"
  local signer_count
  local index
  local signer_burn
  local companion_info
  local companion_burn
  local drift
  local failed=0

  signer_count="$(node -e 'const m=require(process.argv[1]); console.log(m.signerCount)' "${MANIFEST}")"
  for index in $(seq 1 "${signer_count}"); do
    signer_burn="$(backend_exec "signer-${index}" \
      curl --fail --silent http://127.0.0.1:31000/metrics 2>/dev/null \
      | sed -n 's/^stacks_signer_state_burn_block_height \([0-9][0-9]*\).*$/\1/p' \
      | tail -1)" || true
    companion_info="$(backend_exec "signer-node-${index}" \
      curl --fail --silent http://127.0.0.1:20443/v2/info 2>/dev/null)" || true
    companion_burn="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' \
      <<<"${companion_info}")"
    if ! [[ "${signer_burn}" =~ ^[0-9]+$ && "${companion_burn}" =~ ^[0-9]+$ ]]; then
      echo "signer-${index}/signer-node-${index}: missing authenticated burn-height evidence"
      failed=1
      continue
    fi
    if [ "${signer_burn}" -gt "${companion_burn}" ]; then
      echo "signer-${index}: state burn ${signer_burn} is ahead of companion burn ${companion_burn}"
      failed=1
      continue
    fi
    drift=$((companion_burn - signer_burn))
    if [ "${drift}" -gt "${max_drift}" ]; then
      echo "signer-${index}: state burn ${signer_burn} trails companion burn ${companion_burn} by ${drift} blocks (max ${max_drift})"
      failed=1
    fi
  done
  return "${failed}"
}
