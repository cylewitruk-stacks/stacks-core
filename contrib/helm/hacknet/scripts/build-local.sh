#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

docker build \
  --tag stacks-hacknet-operator:dev \
  "${repo_root}/contrib/helm/hacknet/operator"

if [[ "${BUILD_STACKS_IMAGE:-0}" == "1" ]]; then
  docker build \
    --tag stacks-core-libp2p-poc:local \
    --file "${repo_root}/docker/libp2p-poc/Dockerfile" \
    "${repo_root}"
fi

