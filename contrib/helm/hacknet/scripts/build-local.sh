#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

docker build \
  --tag stacks-hacknet-operator:dev \
  "${repo_root}/contrib/helm/hacknet/operator"

docker build \
  --tag stacks-hacknet-run-operator:dev \
  --file "${repo_root}/contrib/helm/hacknet/run-operator/Dockerfile" \
  "${repo_root}"

if [[ "${BUILD_STACKS_IMAGE:-0}" == "1" ]]; then
  docker build \
    --tag stacks-core-attacknet:main \
    --file "${repo_root}/contrib/attacknet/Dockerfile" \
    "${repo_root}"
fi
