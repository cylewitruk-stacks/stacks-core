#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

docker build \
  --build-arg BINARY=topology-operator \
  --tag stacks-hacknet-operator:dev \
  "${repo_root}/contrib/helm/hacknet/operator"

docker build \
  --build-arg BINARY=run-operator \
  --tag stacks-hacknet-run-operator:dev \
  "${repo_root}/contrib/helm/hacknet/operator"

docker build \
  --build-arg BINARY=burnchain-clock \
  --tag stacks-hacknet-burnchain-clock:dev \
  "${repo_root}/contrib/helm/hacknet/operator"

docker build \
  --tag stacks-hacknet-probe:dev \
  "${repo_root}/contrib/attacknet/probe"

docker build \
  --tag stacks-hacknet-io-pressure:dev \
  --file "${repo_root}/contrib/attacknet/io-pressure/Dockerfile" \
  "${repo_root}"

if [[ "${BUILD_STACKS_IMAGE:-0}" == "1" ]]; then
  docker build \
    --tag stacks-core-attacknet:main \
    --file "${repo_root}/contrib/attacknet/Dockerfile" \
    "${repo_root}"
fi
