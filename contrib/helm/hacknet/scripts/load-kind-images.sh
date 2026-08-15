#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: load-kind-images.sh [--mode=auto|require] [--output=RECEIPT.json] IMAGE...

Loads exact local Docker image references into every node of the current kind
cluster and verifies the references in each node's containerd store. `auto`
prints a skipped receipt when the current cluster is not entirely
kind-on-Docker; `require` fails instead. It never mutates Kubernetes objects.
EOF
}

mode=auto
output=
images=()
for argument in "$@"; do
  case "${argument}" in
    -h|--help) usage; exit 0 ;;
    --mode=auto|--mode=require) mode="${argument#*=}" ;;
    --mode=*) echo "unsupported load mode: ${argument#*=}" >&2; exit 2 ;;
    --output=*) output="${argument#*=}" ;;
    --*) echo "unknown option: ${argument}" >&2; usage; exit 2 ;;
    *) images+=("${argument}") ;;
  esac
done
[ "${#images[@]}" -gt 0 ] || { echo 'at least one image is required' >&2; usage; exit 2; }

kubectl_bin="${ATTACKNET_KUBECTL:-kubectl}"
docker_bin="${ATTACKNET_DOCKER:-docker}"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT INT TERM
nodes_tsv="${temporary}/nodes.tsv"
imports_tsv="${temporary}/imports.tsv"
: >"${imports_tsv}"

"${kubectl_bin}" get nodes -o json | jq -r \
  '.items[] | [.metadata.name, (.spec.providerID // "")] | @tsv' >"${nodes_tsv}"
[ -s "${nodes_tsv}" ] || { echo 'current cluster has no nodes' >&2; exit 1; }

all_kind=true
while IFS=$'\t' read -r node provider; do
  if [[ "${provider}" != kind://docker/*/"${node}" ]]; then all_kind=false; fi
done <"${nodes_tsv}"
if [ "${all_kind}" != true ]; then
  [ "${mode}" = auto ] || {
    echo 'current cluster is not entirely kind-on-Docker' >&2
    exit 1
  }
  receipt='{"schemaVersion":"stacks-attacknet-kind-image-load/v1","outcome":"Skipped","reason":"cluster is not entirely kind-on-Docker","nodes":[],"images":[]}'
  if [ -n "${output}" ]; then
    mkdir -p "$(dirname "${output}")"
    printf '%s\n' "${receipt}" >"${output}"
  else
    printf '%s\n' "${receipt}"
  fi
  exit 0
fi

normalize_reference() {
  local reference="$1" first
  if [[ "${reference}" != */* ]]; then
    printf 'docker.io/library/%s\n' "${reference}"
    return
  fi
  first="${reference%%/*}"
  if [[ "${first}" == *.* || "${first}" == *:* || "${first}" == localhost ]]; then
    printf '%s\n' "${reference}"
  else
    printf 'docker.io/%s\n' "${reference}"
  fi
}

archive="${temporary}/images.tar"
host_records="${temporary}/host-images.tsv"
: >"${host_records}"
for image in "${images[@]}"; do
  image_id="$(${docker_bin} image inspect --format '{{.Id}}' "${image}")"
  [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "could not resolve immutable local image ID for ${image}" >&2
    exit 1
  }
  printf '%s\t%s\t%s\n' "${image}" "$(normalize_reference "${image}")" "${image_id}" \
    >>"${host_records}"
done
"${docker_bin}" save --output "${archive}" "${images[@]}"

while IFS=$'\t' read -r node provider; do
  "${docker_bin}" container inspect "${node}" >/dev/null
  "${docker_bin}" exec -i "${node}" ctr -n k8s.io images import --all-platforms - \
    <"${archive}" >/dev/null
  loaded="$(${docker_bin} exec "${node}" ctr -n k8s.io images ls -q)"
  while IFS=$'\t' read -r image normalized image_id; do
    grep -Fx -- "${normalized}" <<<"${loaded}" >/dev/null || {
      echo "kind node ${node} did not retain ${normalized}" >&2
      exit 1
    }
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "${node}" "${provider}" "${image}" "${normalized}" "${image_id}" >>"${imports_tsv}"
  done <"${host_records}"
done <"${nodes_tsv}"

receipt="$(NODE_FILE="${nodes_tsv}" IMPORT_FILE="${imports_tsv}" node -e '
  const fs = require("node:fs");
  const rows = path => fs.readFileSync(path, "utf8").trim().split(/\n/).filter(Boolean)
    .map(line => line.split("\t"));
  const nodes = rows(process.env.NODE_FILE).map(([name, providerID]) => ({name, providerID}));
  const imports = rows(process.env.IMPORT_FILE).map(
    ([node, providerID, requestedRef, importedRef, hostImageID]) =>
      ({node, providerID, requestedRef, importedRef, hostImageID, verified: true}));
  console.log(JSON.stringify({
    schemaVersion: "stacks-attacknet-kind-image-load/v1",
    outcome: "Loaded",
    capturedAt: new Date().toISOString(),
    nodes,
    images: imports,
  }, null, 2));
')"
if [ -n "${output}" ]; then
  mkdir -p "$(dirname "${output}")"
  printf '%s\n' "${receipt}" >"${output}"
else
  printf '%s\n' "${receipt}"
fi
