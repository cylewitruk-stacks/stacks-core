#!/bin/bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${POC_PROJECT:-stacks-libp2p-scale}"
GENERATED="${POC_DIR}/generated"
BASE_COMPOSE="${POC_DIR}/compose.yaml"
GENERATED_COMPOSE="${GENERATED}/compose.yaml"

generate() {
  node "${POC_DIR}/topology.mjs" \
    "--signers=${POC_SIGNERS:-10}" \
    "--miners=${POC_MINERS:-3}" \
    "--followers=${POC_FOLLOWERS:-5}"
}

compose() {
  docker compose -p "${PROJECT}" -f "${BASE_COMPOSE}" -f "${GENERATED_COMPOSE}" "$@"
}

action="${1:-up}"
shift || true
case "${action}" in
  generate)
    generate
    ;;
  up|build|config|create)
    generate
    compose "${action}" "$@"
    ;;
  down|stop|ps|logs)
    if [ ! -r "${GENERATED_COMPOSE}" ]; then
      generate
    fi
    compose "${action}" "$@"
    ;;
  restart)
    generate
    # Post-Nakamoto block commits must not survive a node restart. Stop all
    # actors first, start bitcoind with persistmempool=0, and let the cadence
    # controller load every wallet and establish one empty recovery view before
    # the Stacks processes can publish fresh commits. A plain concurrent
    # `docker compose restart` has a race in which live nodes refill the
    # just-cleared mempool.
    compose stop
    compose up -d --force-recreate bitcoin-miner
    compose up -d "$@"
    ;;
  verify)
    if [ ! -r "${GENERATED_COMPOSE}" ]; then
      generate
    fi
    POC_PROJECT="${PROJECT}" "${POC_DIR}/verify.sh" "$@"
    ;;
  chaos)
    if [ ! -r "${GENERATED_COMPOSE}" ]; then
      generate
    fi
    POC_PROJECT="${PROJECT}" "${POC_DIR}/chaos.sh" "$@"
    ;;
  soak)
    POC_PROJECT="${PROJECT}" "${POC_DIR}/soak.sh" "$@"
    ;;
  *)
    echo "usage: $0 {generate|up|build|config|create|down|stop|restart|ps|logs|verify|chaos|soak} [arguments...]" >&2
    exit 2
    ;;
esac
