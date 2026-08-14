#!/bin/bash
set -euo pipefail

template="${STACKS_ATTACKNET_CONFIG_TEMPLATE:-/etc/stacks/config.toml}"
rendered="${STACKS_ATTACKNET_CONFIG:-/tmp/stacks-attacknet-config.toml}"
node_ip="${STACKS_ATTACKNET_NODE_IP:-}"

if [ -z "${node_ip}" ]; then
  node_ip="$(hostname -i | awk '{ print $1 }')"
fi

case "${node_ip}" in
  *:*|'')
    echo "could not derive an IPv4 address for this actor: ${node_ip:-empty}" >&2
    exit 1
    ;;
esac

sed "s/__NODE_IP__/${node_ip}/g" "${template}" >"${rendered}"
export STACKS_ATTACKNET_CONFIG="${rendered}"
exec "$@"
