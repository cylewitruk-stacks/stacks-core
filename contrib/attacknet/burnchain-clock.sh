#!/bin/bash
set -uo pipefail

# Deliberately Stacks-blind Bitcoin regtest clock. It owns only idempotent
# burnchain setup and block production.  Readiness, protocol fixtures, and
# acceptance assertions belong to observers/policy and can never terminate
# this process or implicitly stop Bitcoin.

BTC_CLI=(bitcoin-cli -regtest -rpcconnect="${BITCOIN_RPC_HOST:-bitcoin}" \
  -rpcuser="${BITCOIN_RPC_USER:-devnet}" -rpcpassword="${BITCOIN_RPC_PASSWORD:-devnet}")
POLICY_FILE="${BURNCHAIN_POLICY_FILE:-/run/hacknet-policy/policy.env}"
STATUS_FILE="${BURNCHAIN_STATUS_FILE:-/tmp/hacknet-burnchain-clock.env}"
DEFAULT_INTERVAL_SECONDS="${BURNCHAIN_DEFAULT_INTERVAL_SECONDS:-60}"
MAX_INTERVAL_SECONDS="${BURNCHAIN_MAX_INTERVAL_SECONDS:-3600}"
running=true
force_block=false
applied_generation=""
burst_remaining=0
address_cursor=0
health_pid=""

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

write_status() {
  local state="$1" height="${2:-unknown}" detail="${3:-}"
  local tmp="${STATUS_FILE}.tmp"
  printf 'state=%s\nbitcoin_height=%s\npolicy_generation=%s\ndetail=%s\nupdated_at=%s\n' \
    "${state}" "${height}" "${applied_generation:-unknown}" "${detail}" "$(date +%s)" >"${tmp}"
  mv "${tmp}" "${STATUS_FILE}"
}

btc_until_success() {
  local delay=1 output
  while [ "${running}" = true ]; do
    if output="$("${BTC_CLI[@]}" "$@" 2>&1)"; then
      printf '%s\n' "${output}"
      return 0
    fi
    write_status degraded unknown "bitcoin-rpc-retry"
    log "Bitcoin RPC unavailable; retrying in ${delay}s: ${output}" >&2
    sleep "${delay}" || true
    if [ "${delay}" -lt 10 ]; then delay=$((delay + 1)); fi
  done
  return 1
}

policy_value() {
  local key="$1" fallback="$2" value=""
  if [ -r "${POLICY_FILE}" ]; then
    value="$(sed -n "s/^${key}=//p" "${POLICY_FILE}" 2>/dev/null | tail -1)"
  fi
  printf '%s\n' "${value:-${fallback}}"
}

read_policy() {
  policy_mode="$(policy_value MODE run)"
  policy_interval="$(policy_value INTERVAL_SECONDS "${DEFAULT_INTERVAL_SECONDS}")"
  policy_jitter="$(policy_value JITTER_SECONDS 0)"
  policy_generation="$(policy_value GENERATION 0)"
  policy_burst="$(policy_value BURST_BLOCKS 0)"
  policy_address_mode="$(policy_value ADDRESS_MODE round-robin)"
  policy_fixed_index="$(policy_value FIXED_ADDRESS_INDEX 0)"

  [[ "${policy_mode}" =~ ^(run|pause)$ ]] || policy_mode=run
  [[ "${policy_interval}" =~ ^[0-9]+$ ]] || policy_interval="${DEFAULT_INTERVAL_SECONDS}"
  [[ "${policy_jitter}" =~ ^[0-9]+$ ]] || policy_jitter=0
  [[ "${policy_generation}" =~ ^[0-9]+$ ]] || policy_generation=0
  [[ "${policy_burst}" =~ ^[0-9]+$ ]] || policy_burst=0
  [[ "${policy_fixed_index}" =~ ^[0-9]+$ ]] || policy_fixed_index=0
  if [ "${policy_interval}" -gt "${MAX_INTERVAL_SECONDS}" ]; then policy_interval="${MAX_INTERVAL_SECONDS}"; fi
  if [ "${policy_jitter}" -gt "${MAX_INTERVAL_SECONDS}" ]; then policy_jitter="${MAX_INTERVAL_SECONDS}"; fi
  [[ "${policy_address_mode}" =~ ^(round-robin|fixed)$ ]] || policy_address_mode=round-robin

  if [ "${policy_generation}" != "${applied_generation}" ]; then
    burst_remaining="${policy_burst}"
    applied_generation="${policy_generation}"
    log "Applied burnchain policy generation=${policy_generation} mode=${policy_mode} interval=${policy_interval}s jitter=${policy_jitter}s burst=${policy_burst} addressMode=${policy_address_mode}"
  fi
}

ensure_wallets() {
  local index wallet
  while [ "${running}" = true ]; do
    wallet_setup_ok=true
    for index in "${!miner_wallets[@]}"; do
      wallet="${miner_wallets[$index]}"
      if ! "${BTC_CLI[@]}" -named createwallet wallet_name="${wallet}" \
        disable_private_keys=true descriptors=true load_on_startup=true >/dev/null 2>&1; then
        "${BTC_CLI[@]}" loadwallet "${wallet}" >/dev/null 2>&1 || true
      fi
      if ! "${BTC_CLI[@]}" -rpcwallet="${wallet}" getwalletinfo >/dev/null 2>&1; then
        wallet_setup_ok=false
        break
      fi
    done
    if [ "${wallet_setup_ok}" = true ]; then return 0; fi
    write_status degraded unknown wallet-setup-retry
    log "Bitcoin wallet setup incomplete; retrying" >&2
    sleep 2 || true
  done
}

mine_to_address() {
  local address="$1" wallet="${miner_wallets[0]}"
  btc_until_success -rpcwallet="${wallet}" generatetoaddress 1 "${address}" >/dev/null
}

bootstrap_regtest() {
  local height index
  height="$(btc_until_success getblockcount)" || return
  if [ "${height}" -eq 0 ]; then
    for index in "${!miner_addresses[@]}"; do mine_to_address "${miner_addresses[$index]}"; done
    height="$(btc_until_success getblockcount)" || return
  fi
  while [ "${running}" = true ] && [ "${height}" -lt "${BURNCHAIN_BOOTSTRAP_HEIGHT:-202}" ]; do
    mine_to_address "${miner_addresses[0]}"
    height=$((height + 1))
  done
  write_status running "${height}" bootstrapped
  log "Bitcoin regtest clock ready at height ${height}"
}

select_address() {
  local count="${#miner_addresses[@]}" index
  if [ "${policy_address_mode}" = fixed ]; then
    index=$((policy_fixed_index % count))
  else
    index=$((address_cursor % count))
    address_cursor=$((address_cursor + 1))
  fi
  selected_address="${miner_addresses[$index]}"
}

ensure_health_server() {
  if [ -n "${health_pid}" ] && kill -0 "${health_pid}" 2>/dev/null; then return; fi
  perl -MIO::Socket::INET -e '
    my $listener = IO::Socket::INET->new(LocalPort => $ENV{BURNCHAIN_HEALTH_PORT} || 18500, Listen => 16, Reuse => 1) or die $!;
    while (my $client = $listener->accept()) {
      print $client "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
      close $client;
    }
  ' &
  health_pid="$!"
}

stop() { running=false; [ -z "${health_pid}" ] || kill "${health_pid}" 2>/dev/null || true; }
request_block() { force_block=true; }
wake_for_policy() { :; }
trap stop TERM INT
trap request_block USR1
trap wake_for_policy USR2

IFS=',' read -ra miner_wallets <<<"${MINER_WALLETS:?MINER_WALLETS is required}"
IFS=',' read -ra miner_addresses <<<"${MINER_BTC_ADDRS:?MINER_BTC_ADDRS is required}"
if [ "${#miner_wallets[@]}" -eq 0 ] || [ "${#miner_wallets[@]}" -ne "${#miner_addresses[@]}" ]; then
  log "MINER_WALLETS and MINER_BTC_ADDRS must contain the same non-zero number of entries" >&2
  while true; do write_status degraded unknown invalid-address-inventory; sleep 60; done
fi

write_status starting unknown bitcoin-rpc
btc_until_success -rpcwait getblockchaininfo >/dev/null || exit 0
ensure_wallets
bootstrap_regtest
ensure_health_server

while [ "${running}" = true ]; do
  ensure_health_server
  read_policy
  height="$(btc_until_success getblockcount)" || break
  if [ "${policy_mode}" = pause ] && [ "${force_block}" = false ] && [ "${burst_remaining}" -eq 0 ]; then
    write_status paused "${height}" "policy-generation-${applied_generation}"
    sleep 1 || true
    continue
  fi

  select_address
  address="${selected_address}"
  if mine_to_address "${address}"; then
    height="$(btc_until_success getblockcount)" || break
    write_status running "${height}" "mined-to-${address}"
    log "Mined Bitcoin block ${height} to ${address}"
  fi
  force_block=false
  if [ "${burst_remaining}" -gt 0 ]; then
    burst_remaining=$((burst_remaining - 1))
    # Exact-height bootstrap phases still need wall-clock room for Stacks
    # transactions, node processing, and signer registration between Bitcoin
    # blocks. Skip the delay after the final block so the clock acknowledges
    # the paused barrier promptly.
    if [ "${burst_remaining}" -gt 0 ]; then
      delay="${policy_interval}"
      if [ "${policy_jitter}" -gt 0 ]; then delay=$((delay + RANDOM % (policy_jitter + 1))); fi
      sleep "${delay}" || true
    fi
    continue
  fi
  delay="${policy_interval}"
  if [ "${policy_jitter}" -gt 0 ]; then delay=$((delay + RANDOM % (policy_jitter + 1))); fi
  sleep "${delay}" || true
done

write_status stopped "${height:-unknown}" terminated
wait "${health_pid}" 2>/dev/null || true
