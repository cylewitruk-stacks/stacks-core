#!/bin/bash
set -euo pipefail

source /canonical-progress.sh

BTC_CLI=(bitcoin-cli -regtest -rpcconnect=bitcoin -rpcuser=devnet -rpcpassword=devnet)
PROGRESS_FILE="${PROGRESS_FILE:-/tmp/libp2p-poc-progress}"

btc_retry() {
  local attempts="${BITCOIN_RPC_RETRIES:-30}"
  local delay="${BITCOIN_RPC_RETRY_SECONDS:-1}"
  local attempt=1
  local output
  while true; do
    if output="$("${BTC_CLI[@]}" "$@" 2>&1)"; then
      printf '%s\n' "${output}"
      return 0
    fi
    if [ "${attempt}" -ge "${attempts}" ]; then
      echo "Bitcoin RPC failed after ${attempts} attempts: ${output}" >&2
      return 1
    fi
    echo "Transient Bitcoin RPC failure (${attempt}/${attempts}); retrying: ${output}" >&2
    attempt=$((attempt + 1))
    sleep "${delay}"
  done
}

progress_value() {
  local key="$1"
  if [ -r "${PROGRESS_FILE}" ]; then
    sed -n "s/^${key}=//p" "${PROGRESS_FILE}" | tail -1
  fi
}

write_progress() {
  local status="$1"
  local stage="$2"
  local bitcoin_height="${3:-unknown}"
  local burn_height="${4:-unknown}"
  local stacks_height="${5:-unknown}"
  local canonical_progress="${6:-}"
  local canonical_progress_at="${7:-}"
  local follower_burn_height="${8:-}"
  local follower_stacks_height="${9:-}"
  local follower_converged_at="${10:-}"
  local updated_at
  canonical_progress="${canonical_progress:-$(progress_value canonical_progress)}"
  canonical_progress_at="${canonical_progress_at:-$(progress_value canonical_progress_at)}"
  follower_burn_height="${follower_burn_height:-$(progress_value follower_burn_height)}"
  follower_stacks_height="${follower_stacks_height:-$(progress_value follower_stacks_height)}"
  follower_converged_at="${follower_converged_at:-$(progress_value follower_converged_at)}"
  updated_at="$(date +%s)"
  printf 'status=%s\nstage=%s\nbitcoin_height=%s\nburn_height=%s\nstacks_height=%s\ncanonical_progress=%s\ncanonical_progress_at=%s\nfollower_burn_height=%s\nfollower_stacks_height=%s\nfollower_converged_at=%s\nupdated_at=%s\n' \
    "${status}" "${stage}" "${bitcoin_height}" "${burn_height}" "${stacks_height}" \
    "${canonical_progress:-unknown}" "${canonical_progress_at:-unknown}" \
    "${follower_burn_height:-unknown}" "${follower_stacks_height:-unknown}" \
    "${follower_converged_at:-unknown}" "${updated_at}" >"${PROGRESS_FILE}.tmp"
  mv "${PROGRESS_FILE}.tmp" "${PROGRESS_FILE}"
}

# Preserve the Pod/container-local marker before updating it. Kubernetes
# restarts a failed container without replacing its emptyDir, and Docker
# restarts preserve the container filesystem. That is materially different
# from a new Pod/container, which has no marker and must fail closed.
previous_cadence_bitcoin_height="$(progress_value bitcoin_height)"
write_progress starting bitcoin-rpc unknown unknown unknown
"${BTC_CLI[@]}" -rpcwait getblockchaininfo >/dev/null
IFS=',' read -ra miner_wallets <<<"${MINER_WALLETS}"
IFS=',' read -ra miner_addresses <<<"${MINER_BTC_ADDRS}"
if [ "${#miner_wallets[@]}" -eq 0 ] || [ "${#miner_wallets[@]}" -ne "${#miner_addresses[@]}" ]; then
  echo "MINER_WALLETS and MINER_BTC_ADDRS must contain the same non-zero number of entries" >&2
  exit 1
fi
for index in "${!miner_wallets[@]}"; do
  wallet="${miner_wallets[$index]}"
  address="${miner_addresses[$index]}"
  # stacks-node imports a watch-only addr() descriptor for its deterministic
  # burnchain key. Bitcoin Core rejects that descriptor in a wallet with
  # private keys enabled, while a legacy wallet cannot use importdescriptors at
  # all. Match the controller's contract with a watch-only descriptor wallet.
  if ! "${BTC_CLI[@]}" -named createwallet wallet_name="${wallet}" \
    disable_private_keys=true descriptors=true load_on_startup=true >/dev/null 2>&1; then
    # `-nosettings` deliberately prevents implicit wallet persistence across a
    # bitcoind restart. An existing on-disk wallet therefore needs an explicit
    # load before the Stacks burnchain controller can inspect or spend it.
    "${BTC_CLI[@]}" loadwallet "${wallet}" >/dev/null 2>&1 || true
  fi
  if ! "${BTC_CLI[@]}" -rpcwallet="${wallet}" getwalletinfo >/dev/null; then
    echo "Miner wallet ${wallet} exists but could not be loaded" >&2
    exit 1
  fi
done

abandon_unconfirmed_wallet_transactions() {
  local wallet="$1"
  local line
  local txid=""
  local confirmations=""
  local abandoned=0
  while IFS= read -r line; do
    if [[ "${line}" =~ \"confirmations\":[[:space:]]*(-?[0-9]+) ]]; then
      confirmations="${BASH_REMATCH[1]}"
    elif [[ "${line}" =~ \"txid\":[[:space:]]*\"([0-9a-fA-F]+)\" ]]; then
      txid="${BASH_REMATCH[1]}"
    elif [[ "${line}" =~ ^[[:space:]]*\} ]]; then
      if [ "${confirmations}" = 0 ] && [ -n "${txid}" ]; then
        if "${BTC_CLI[@]}" -rpcwallet="${wallet}" abandontransaction "${txid}" \
          >/dev/null 2>&1; then
          abandoned=$((abandoned + 1))
        fi
      fi
      txid=""
      confirmations=""
    fi
  done < <("${BTC_CLI[@]}" -rpcwallet="${wallet}" listtransactions "*" 10000 0 true)
  if [ "${abandoned}" -gt 0 ]; then
    echo "Released ${abandoned} discarded unconfirmed transaction chain(s) from ${wallet}"
  fi
}

# `persistmempool=0` and `walletbroadcast=0` keep these transactions out of the
# live mempool, but the wallet still remembers their spends. Abandon them so
# each miner can construct its first fresh post-restart commit from a confirmed
# input. A live transaction remains protected by the mempool assertion below.
for wallet in "${miner_wallets[@]}"; do
  abandon_unconfirmed_wallet_transactions "${wallet}"
done
WALLET_NAME="${miner_wallets[0]}"
BTC_ADDR="${miner_addresses[0]}"
bootstrap_height="$("${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" getblockcount)"
if [ "${bootstrap_height}" -eq 0 ]; then
  # Fund each independently-keyed miner before coinbase maturity. Mining all
  # bootstrap blocks to one address would leave miners 2 and 3 unable to
  # submit block commits even though their processes appeared healthy.
  for address in "${miner_addresses[@]}"; do
    "${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" generatetoaddress 1 "${address}" >/dev/null
  done
  bootstrap_height="$("${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" getblockcount)"
fi
if [ "${bootstrap_height}" -lt 202 ]; then
  "${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" generatetoaddress "$((202 - bootstrap_height))" "${BTC_ADDR}" >/dev/null
fi

bitcoin_height="$("${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" getblockcount)"
initial_mempool_size="$(bitcoin-cli -regtest -rpcconnect=bitcoin -rpcuser=devnet -rpcpassword=devnet getmempoolinfo \
  | sed -n 's/.*"size": \([0-9][0-9]*\).*/\1/p')"
if [ "${bitcoin_height}" -gt "${NAKAMOTO_ACTIVATION_HEIGHT:-999999999}" ] \
  && [ "${initial_mempool_size:-unknown}" != 0 ]; then
  if cadence_restart_can_reuse_mempool \
    "${previous_cadence_bitcoin_height}" "${bitcoin_height}" "${initial_mempool_size}"; then
    echo "Resuming the same cadence instance at Bitcoin height ${bitcoin_height} with ${initial_mempool_size} live mempool transaction(s)"
  else
    write_progress failed stale-mining-commit "${bitcoin_height}" unknown unknown
    echo "Refusing to resume with ${initial_mempool_size:-unknown} unowned Bitcoin mempool transaction(s)." >&2
    echo "No surviving cadence-instance marker proves that the live mempool belongs to this burnchain process." >&2
    exit 1
  fi
fi
if [ "${bitcoin_height}" -gt "${NAKAMOTO_ACTIVATION_HEIGHT:-999999999}" ]; then
  # A restarted node remembers that it already submitted the commit which was
  # intentionally discarded with bitcoind's non-persistent mempool. It will
  # not submit another until it observes a new burn view, so waiting for a
  # fresh transaction here deadlocks. Mine exactly one empty recovery block:
  # it cannot select a stale commit (the mempool was proven empty), and it
  # gives every miner a new canonical view from which to publish a fresh one.
  echo "Verified empty restart mempool at Bitcoin height ${bitcoin_height}; mining one empty recovery block"
  "${BTC_CLI[@]}" -rpcwallet="${WALLET_NAME}" generatetoaddress 1 "${BTC_ADDR}" >/dev/null
  bitcoin_height="$((bitcoin_height + 1))"
fi
write_progress ready burnchain-available "${bitcoin_height}" unknown unknown

stacks_burn_height() {
  local response
  # Compose can briefly withdraw the service DNS record while recreating the
  # node. Treat that as an ordinary readiness miss; the caller retries.
  if ! { exec 3<>"/dev/tcp/${STACKS_RPC_HOST:-stacks-node}/${STACKS_RPC_PORT:-20443}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v2/info HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "${STACKS_RPC_HOST:-stacks-node}" >&3
  if ! response="$(timeout "${STACKS_RPC_TIMEOUT:-2}" sed -n '/^{/,$p' <&3 2>/dev/null)"; then
    exec 3<&-
    exec 3>&-
    return 1
  fi
  exec 3<&-
  exec 3>&-
  sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${response}"
}

stacks_tip_height() {
  local response
  if ! { exec 3<>"/dev/tcp/${STACKS_RPC_HOST:-stacks-node}/${STACKS_RPC_PORT:-20443}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v2/info HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "${STACKS_RPC_HOST:-stacks-node}" >&3
  if ! response="$(timeout "${STACKS_RPC_TIMEOUT:-2}" sed -n '/^{/,$p' <&3 2>/dev/null)"; then
    exec 3<&-
    exec 3>&-
    return 1
  fi
  exec 3<&-
  exec 3>&-
  sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${response}"
}

stacks_info_for_host() {
  local host="$1"
  local port="$2"
  local response
  if ! { exec 3<>"/dev/tcp/${host}/${port}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v2/info HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${host}" >&3
  if ! response="$(timeout "${STACKS_RPC_TIMEOUT:-2}" sed -n '/^{/,$p' <&3 2>/dev/null)"; then
    exec 3<&-
    exec 3>&-
    return 1
  fi
  exec 3<&-
  exec 3>&-
  printf '%s\n' "${response}"
}

stacks_diagnostics() {
  local response
  if ! { exec 3<>"/dev/tcp/${STACKS_RPC_HOST:-stacks-node}/${STACKS_RPC_PORT:-20443}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v3/network/diagnostics HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\nConnection: close\r\n\r\n' \
    "${STACKS_RPC_HOST:-stacks-node}" "${STACKS_RPC_AUTH:-12345}" >&3
  if ! response="$(timeout "${STACKS_RPC_TIMEOUT:-2}" sed -n '/^{/,$p' <&3 2>/dev/null)"; then
    exec 3<&-
    exec 3>&-
    return 1
  fi
  exec 3<&-
  exec 3>&-
  printf '%s\n' "${response}"
}

connected_peer_count() {
  stacks_diagnostics \
    | sed -n 's/.*"connected_peers":\[\([^]]*\)\].*/\1/p' \
    | grep -o '"[^"]*"' \
    | wc -l | tr -d ' '
}

bitcoin_mempool_size() {
  btc_retry getmempoolinfo \
    | sed -n 's/.*"size": \([0-9][0-9]*\).*/\1/p'
}

stacks_contract_exists() {
  local contract_name="$1"
  # The node may close this socket while Compose is restarting it. Initialize
  # before the fallible read so `set -u` turns that race into a retry instead
  # of terminating the cadence controller.
  local status_line=""
  if ! { exec 3<>"/dev/tcp/${STACKS_RPC_HOST:-stacks-node}/${STACKS_RPC_PORT:-20443}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v2/contracts/source/%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "${EPOCH_4_CONTRACT_ADDRESS}" "${contract_name}" \
    "${STACKS_RPC_HOST:-stacks-node}" >&3
  IFS= read -r -t "${STACKS_RPC_TIMEOUT:-2}" status_line <&3 || true
  exec 3<&-
  exec 3>&-
  [[ "${status_line}" == *" 200 "* ]]
}

wait_for_epoch_4_contracts() {
  local deadline=$((SECONDS + ${READINESS_TIMEOUT:-180}))
  while ! stacks_contract_exists sbtc-token \
    || ! stacks_contract_exists sbtc-registry; do
    echo "Waiting for confirmed sBTC interface fixtures before Epoch 4.0"
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "Timed out waiting for the Epoch 4.0 sBTC interface fixtures" >&2
      return 1
    fi
    sleep 1
  done
}

stacks_account_locked() {
  local account="$1"
  local response
  if ! { exec 3<>"/dev/tcp/${STACKS_RPC_HOST:-stacks-node}/${STACKS_RPC_PORT:-20443}"; } 2>/dev/null; then
    return 1
  fi
  printf 'GET /v2/accounts/%s?proof=0 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "${account}" "${STACKS_RPC_HOST:-stacks-node}" >&3
  if ! response="$(timeout "${STACKS_RPC_TIMEOUT:-2}" sed -n '/^{/,$p' <&3 2>/dev/null)"; then
    exec 3<&-
    exec 3>&-
    return 1
  fi
  exec 3<&-
  exec 3>&-
  [[ "${response}" =~ \"locked\":\"0x0*[1-9a-fA-F][0-9a-fA-F]*\" ]] \
    || [[ "${response}" =~ \"locked\":\"[1-9][0-9]*\" ]]
}

POX5_READY_LOGGED=false
EPOCH4_READY=false
wait_for_pox5_signers() {
  local deadline=$((SECONDS + ${READINESS_TIMEOUT:-180}))
  local account
  local ready
  while true; do
    ready=true
    IFS=',' read -ra accounts <<<"${POX5_SIGNER_ACCOUNTS}"
    for account in "${accounts[@]}"; do
      if ! stacks_account_locked "${account}"; then
        ready=false
        break
      fi
    done
    if [ "${ready}" = true ]; then
      if [ "${POX5_READY_LOGGED}" = false ]; then
        echo "All PoX-5 signer stakes are confirmed"
        POX5_READY_LOGGED=true
      fi
      return
    fi
    echo "Waiting for PoX-5 signer registration and stake confirmation"
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "Timed out waiting for PoX-5 signer registration" >&2
      return 1
    fi
    sleep 1
  done
}

observe_stacks_tip() {
  local bitcoin_height="$1"
  local prior_marker="$2"
  local prior_tip="${prior_marker%%:*}"
  local prior_tip_id="${prior_marker#*:}"
  local node_info
  local stacks_height
  local stacks_tip
  local stacks_tip_id
  local follower_info
  local follower_burn_height
  local follower_stacks_height
  local follower_tip_id
  local follower_converged_at
  local previous_status
  local last_progress_at
  local now
  local progress_age

  now="$(date +%s)"
  previous_status="$(progress_value status)"
  last_progress_at="$(progress_value canonical_progress_at)"
  if ! [[ "${last_progress_at}" =~ ^[0-9]+$ ]]; then
    last_progress_at="${now}"
  fi

  node_info="$(stacks_info_for_host "${STACKS_RPC_HOST:-stacks-node}" "${STACKS_RPC_PORT:-20443}" || true)"
  stacks_height="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${node_info}")"
  stacks_tip="$(sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${node_info}")"
  stacks_tip_id="$(sed -n 's/.*"stacks_tip":"\([0-9a-f][0-9a-f]*\)".*/\1/p' <<<"${node_info}")"
  follower_info="$(stacks_info_for_host "${STACKS_FOLLOWER_RPC_HOST:-stacks-follower}" "${STACKS_FOLLOWER_RPC_PORT:-21443}" || true)"
  follower_burn_height="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${follower_info}")"
  follower_stacks_height="$(sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${follower_info}")"
  follower_tip_id="$(sed -n 's/.*"stacks_tip":"\([0-9a-f][0-9a-f]*\)".*/\1/p' <<<"${follower_info}")"
  follower_converged_at=""
  if [ -n "${stacks_height}" ] && [ "${follower_burn_height}" = "${stacks_height}" ] \
    && [ -n "${stacks_tip}" ] && [ "${follower_stacks_height}" = "${stacks_tip}" ] \
    && [ -n "${stacks_tip_id}" ] && [ "${follower_tip_id}" = "${stacks_tip_id}" ]; then
    follower_converged_at="${now}"
  fi

  if canonical_tip_advanced \
    "${prior_tip}" "${prior_tip_id}" "${stacks_tip}" "${stacks_tip_id}"; then
    write_progress live canonical-progress "${bitcoin_height}" "${stacks_height:-unknown}" "${stacks_tip}" \
      accepted "${now}" "${follower_burn_height:-unknown}" \
      "${follower_stacks_height:-unknown}" "${follower_converged_at}"
    printf '%s:%s\n' "${stacks_tip}" "${stacks_tip_id}"
    return 0
  fi

  progress_age=$((now - last_progress_at))
  if [ "${progress_age}" -ge "${PROGRESS_STALL_AFTER:-60}" ]; then
    write_progress stalled stacks-not-advancing "${bitcoin_height}" \
      "${stacks_height:-unknown}" "${stacks_tip:-unknown}" pending "${last_progress_at}" \
      "${follower_burn_height:-unknown}" "${follower_stacks_height:-unknown}" "${follower_converged_at}"
    if [ "${previous_status}" != stalled ]; then
      echo "Stacks canonical tip has not advanced for ${progress_age}s (Bitcoin=${bitcoin_height}, burn=${stacks_height:-unknown}, Stacks=${stacks_tip:-unknown}); Bitcoin mining continues" >&2
    fi
  else
    write_progress live awaiting-stacks-progress "${bitcoin_height}" \
      "${stacks_height:-unknown}" "${stacks_tip:-unknown}" pending "${last_progress_at}" \
      "${follower_burn_height:-unknown}" "${follower_stacks_height:-unknown}" "${follower_converged_at}"
  fi
  printf '%s\n' "${prior_marker}"
}

mark_miner_exit() {
  local status="$?"
  if [ "${status}" -ne 0 ]; then
    write_progress failed "miner-exit-${status}" unknown unknown unknown || true
  fi
}
trap mark_miner_exit EXIT

# Chaos cadence signals alter exactly one inter-block delay. They never change
# sortition eligibility, bypass a Stacks readiness condition, or mine outside
# this single-owner controller. A flash signal interrupts the current sleep;
# a slow signal replaces the interrupted remainder with a bounded long delay.
cadence_override=""
RANDOM="${MINE_ENTROPY_SEED:-4242}"
selected_cadence_delay=""
request_flash_block() {
  cadence_override=flash
}
request_slow_block() {
  cadence_override=slow
}
trap request_flash_block USR1
trap request_slow_block USR2

select_steady_state_delay() {
  local nominal="$1"
  local roll
  if [ "${MINE_ENTROPY_ENABLED:-false}" != true ]; then
    selected_cadence_delay="${nominal}"
    return
  fi

  # Reproducible weighted timing entropy for the steady-state Epoch 4 network:
  # 75% clusters around the nominal 20s cadence, 10% exercises flash blocks,
  # and 15% exercises a long tail up to one minute. Keep the RNG in this shell
  # (rather than command substitution) so its seeded state advances per block.
  roll=$((RANDOM % 100))
  if [ "${roll}" -lt 10 ]; then
    selected_cadence_delay=$((5 + RANDOM % 10))
  elif [ "${roll}" -lt 85 ]; then
    selected_cadence_delay=$((15 + RANDOM % 11))
  else
    selected_cadence_delay=$((26 + RANDOM % 35))
  fi
}

wait_for_initial_stacks_tip() {
  local bitcoin_height
  local burn_height
  local fully_synced
  local node_info
  local stacks_tip
  local stacks_tip_id
  local follower_info
  local follower_burn_height
  local follower_stacks_height
  local follower_tip_id
  local connected_peers
  local mempool_size
  local marker
  local stable_marker=""
  local stable_observations=0
  local deadline=$((SECONDS + ${READINESS_TIMEOUT:-180}))
  while true; do
    bitcoin_height="$(btc_retry -rpcwallet="${WALLET_NAME}" getblockcount)"
    node_info="$(stacks_info_for_host "${STACKS_RPC_HOST:-stacks-node}" "${STACKS_RPC_PORT:-20443}" || true)"
    burn_height="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${node_info}")"
    stacks_tip="$(sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${node_info}")"
    stacks_tip_id="$(sed -n 's/.*"stacks_tip":"\([0-9a-f][0-9a-f]*\)".*/\1/p' <<<"${node_info}")"
    fully_synced="$(sed -n 's/.*"is_fully_synced":\(true\|false\).*/\1/p' <<<"${node_info}")"
    follower_info="$(stacks_info_for_host "${STACKS_FOLLOWER_RPC_HOST:-stacks-follower}" "${STACKS_FOLLOWER_RPC_PORT:-21443}" || true)"
    follower_burn_height="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${follower_info}")"
    follower_stacks_height="$(sed -n 's/.*"stacks_tip_height":\([0-9][0-9]*\).*/\1/p' <<<"${follower_info}")"
    follower_tip_id="$(sed -n 's/.*"stacks_tip":"\([0-9a-f][0-9a-f]*\)".*/\1/p' <<<"${follower_info}")"
    connected_peers=0
    mempool_size="$(bitcoin_mempool_size || true)"
    if [ "${bitcoin_height}" -gt "${NAKAMOTO_ACTIVATION_HEIGHT:-999999999}" ]; then
      connected_peers="$(connected_peer_count || true)"
    fi

    # A persistent Stacks node cannot legitimately have processed a burn
    # height that no longer exists in bitcoind's active chain. This indicates
    # an unclean regtest rollback (for example, Docker Desktop restoring an
    # older durable bitcoind checkpoint) and cannot be repaired by waiting for
    # ordinary readiness or by mining on the divergent view.
    if [[ "${burn_height}" =~ ^[0-9]+$ ]] \
      && [ "${burn_height}" -gt "${bitcoin_height}" ]; then
      write_progress failed burnchain-rollback "${bitcoin_height}" \
        "${burn_height}" "${stacks_tip:-unknown}"
      echo "Refusing to resume: Stacks burn height ${burn_height} is ahead of bitcoind ${bitcoin_height}; recreate this PoC project's volumes." >&2
      return 1
    fi

    # `ready` lets Compose start the consumers of the persisted chain. Mining
    # remains blocked until the node and follower agree on a stable canonical
    # view, every expected native peer is connected, and the restarted node
    # has submitted a fresh block commit using its persisted active VRF key.
    write_progress ready restart-readiness "${bitcoin_height}" \
      "${burn_height:-unknown}" "${stacks_tip:-unknown}" "" "" \
      "${follower_burn_height:-unknown}" "${follower_stacks_height:-unknown}"
    if [ -n "${burn_height}" ] && [ -n "${stacks_tip}" ] && [ -n "${stacks_tip_id}" ] \
      && [ "${fully_synced}" = true ] && [ "${burn_height}" -ge "${bitcoin_height}" ] \
      && [ "${follower_burn_height}" = "${burn_height}" ] \
      && [ "${follower_stacks_height}" = "${stacks_tip}" ] \
      && [ "${follower_tip_id}" = "${stacks_tip_id}" ] \
      && { [ "${bitcoin_height}" -le "${NAKAMOTO_ACTIVATION_HEIGHT:-999999999}" ] \
        || { [ "${connected_peers:-0}" -ge "${EXPECTED_NATIVE_PEERS:-4}" ] \
          && [ "${mempool_size:-0}" -ge 1 ]; }; }; then
      marker="${burn_height}:${stacks_tip}:${stacks_tip_id}"
      if [ "${marker}" = "${stable_marker}" ]; then
        stable_observations=$((stable_observations + 1))
      else
        stable_marker="${marker}"
        stable_observations=1
      fi
    else
      stable_marker=""
      stable_observations=0
    fi
    if [ "${stable_observations}" -ge "${INITIAL_VIEW_CONFIRMATIONS:-3}" ]; then
      printf '%s:%s\n' "${stacks_tip}" "${stacks_tip_id}"
      return
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      write_progress failed node-readiness-timeout "${bitcoin_height}" unknown unknown
      echo "Timed out waiting for the Stacks node before initializing the canonical-tip gate" >&2
      return 1
    fi
    sleep 1
  done
}

# This baseline is sampled after the node becomes reachable so the progress
# observer distinguishes a fresh canonical transition from persisted state.
last_stacks_marker="$(wait_for_initial_stacks_tip)"
write_progress live canonical-baseline \
  "$(btc_retry -rpcwallet="${WALLET_NAME}" getblockcount)" \
  "$(stacks_burn_height || true)" "${last_stacks_marker%%:*}" observed "$(date +%s)"
while true; do
  current_height="$(btc_retry -rpcwallet="${WALLET_NAME}" getblockcount)"
  if [ "${EPOCH4_READY}" = false ] \
    && [ "${current_height}" -ge "${EPOCH_4_CONTRACT_GATE_HEIGHT:-999999999}" ]; then
    wait_for_epoch_4_contracts
    EPOCH4_READY=true
  fi
  if [ "${POX5_READY_LOGGED}" = false ] \
    && [ "${current_height}" -ge "${POX5_SIGNER_GATE_HEIGHT:-999999999}" ]; then
    wait_for_pox5_signers
  fi
  btc_retry -rpcwallet="${WALLET_NAME}" generatetoaddress 1 "${BTC_ADDR}" >/dev/null
  current_height="$(btc_retry -rpcwallet="${WALLET_NAME}" getblockcount)"
  # Bitcoin cadence is independent of Stacks liveness, as it is on public
  # networks. Observe height and ID so same-height canonical replacement counts
  # as progress, but never stop Bitcoin merely because Stacks is stalled.
  last_stacks_marker="$(observe_stacks_tip "${current_height}" "${last_stacks_marker}")"
  if [ "${current_height}" -le "${MINE_FAST_UNTIL_HEIGHT:-0}" ]; then
    delay="${MINE_FAST_INTERVAL:-0}"
  else
    delay="${MINE_INTERVAL:-60}"
    if [ "${current_height}" -ge "${MINE_ENTROPY_START_HEIGHT:-999999999}" ]; then
      select_steady_state_delay "${delay}"
      delay="${selected_cadence_delay}"
    fi
  fi
  if [ "${delay}" != 0 ]; then
    # A cadence-chaos signal intentionally interrupts sleep. `set -e` must not
    # turn that expected interruption into a controller exit.
    sleep "${delay}" || true
  fi
  if [ "${cadence_override}" = slow ]; then
    cadence_override=""
    echo "Injecting one slow Bitcoin interval (${CHAOS_SLOW_INTERVAL:-90}s)"
    sleep "${CHAOS_SLOW_INTERVAL:-90}" || true
  elif [ "${cadence_override}" = flash ]; then
    cadence_override=""
    echo "Injecting one flash Bitcoin interval"
  fi
done
