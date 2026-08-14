#!/bin/bash

# Report whether the canonical Stacks view advanced after a Bitcoin block.
#
# Height alone is insufficient in a multi-miner network: a winning commit can
# legitimately replace the current Stacks tip with a different block at the
# same height. The replacement is canonical progress and has already passed
# signer validation by the time it appears in /v2/info.
canonical_tip_advanced() {
  local prior_height="$1"
  local prior_id="$2"
  local current_height="$3"
  local current_id="$4"

  [[ "${prior_height}" =~ ^[0-9]+$ ]] || return 1
  [[ "${current_height}" =~ ^[0-9]+$ ]] || return 1
  [[ "${prior_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "${current_id}" =~ ^[0-9a-f]{64}$ ]] || return 1

  [ "${current_height}" -gt "${prior_height}" ] \
    || { [ "${current_height}" -eq "${prior_height}" ] \
      && [ "${current_id}" != "${prior_id}" ]; }
}

# A cadence *container* can restart while its Pod/Compose container and the
# live bitcoind stay intact.  In that case the progress file survives and an
# in-flight commit in bitcoind's non-persistent mempool is still part of the
# same canonical burnchain process.  A Pod/container replacement loses the
# marker and must fail closed instead of guessing whether a transaction came
# from a stale restored view.
cadence_restart_can_reuse_mempool() {
  local prior_bitcoin_height="$1"
  local current_bitcoin_height="$2"
  local mempool_size="$3"

  [[ "${prior_bitcoin_height}" =~ ^[0-9]+$ ]] || return 1
  [[ "${current_bitcoin_height}" =~ ^[0-9]+$ ]] || return 1
  [[ "${mempool_size}" =~ ^[1-9][0-9]*$ ]] || return 1
  [ "${current_bitcoin_height}" -ge "${prior_bitcoin_height}" ]
}
