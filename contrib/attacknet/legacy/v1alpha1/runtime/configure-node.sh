#!/bin/bash
set -euo pipefail

template="${STACKS_ATTACKNET_CONFIG_TEMPLATE:-/etc/stacks/config.toml}"
rendered="${STACKS_ATTACKNET_CONFIG:-/tmp/stacks-attacknet-config.toml}"
node_ip="${STACKS_ATTACKNET_NODE_IP:-}"

if [ -z "${node_ip}" ]; then
  node_ip="$(hostname -i | awk '{ print $1 }')"
fi

if ! awk -v ip="${node_ip}" 'BEGIN {
  count = split(ip, octets, ".")
  if (count != 4) exit 1
  for (i = 1; i <= 4; i++) {
    if (octets[i] !~ /^[0-9]+$/ || octets[i] < 0 || octets[i] > 255) exit 1
  }
}' </dev/null; then
  echo "could not derive a numeric IPv4 address for this actor: ${node_ip:-empty}" >&2
  exit 1
fi

temporary="${rendered}.tmp.$$"
trap 'rm -f "${temporary}"' EXIT
sed "s/__NODE_IP__/${node_ip}/g" "${template}" >"${temporary}"
mv "${temporary}" "${rendered}"
trap - EXIT
export STACKS_ATTACKNET_CONFIG="${rendered}"
exec "$@"
