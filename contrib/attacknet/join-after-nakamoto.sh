#!/bin/bash
set -euo pipefail

source_host="${NAKAMOTO_SOURCE_HOST:-miner-1}"
activation_height="${NAKAMOTO_ACTIVATION_HEIGHT:-223}"

while true; do
  response="$(curl --fail --silent --max-time 2 "http://${source_host}:20443/v2/info" || true)"
  burn_height="$(sed -n 's/.*"burn_block_height":\([0-9][0-9]*\).*/\1/p' <<<"${response}")"
  if [ -n "${burn_height}" ] && [ "${burn_height}" -ge "${activation_height}" ]; then
    echo "Joining as an additional miner after Nakamoto activation at burn height ${burn_height}"
    exec stacks-node start --config /etc/stacks/config.toml
  fi
  sleep 1
done
