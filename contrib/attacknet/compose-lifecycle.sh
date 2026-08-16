#!/usr/bin/env bash
set -Eeuo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command="${1:-}"
generated="${2:-}"

case "${command}" in
  apply|wait|delete|capture) ;;
  *) echo "usage: $0 {apply|wait|delete} GENERATED_DIR | capture GENERATED_DIR EVIDENCE_DIR" >&2; exit 2 ;;
esac
[ -n "${generated}" ] && [ -r "${generated}/manifest.json" ] || {
  echo "generated topology directory with manifest.json required" >&2
  exit 2
}

identity="$(node "${ATTACKNET_DIR}/manifest-identity.mjs" "${generated}")"
rendered_network="$(jq -er .network <<<"${identity}")"
rendered_namespace="$(jq -er .namespace <<<"${identity}")"
project="${ATTACKNET_PROJECT:-${rendered_network}}"
NETWORK="${project}"
NAMESPACE="${KUBE_NAMESPACE:-${rendered_namespace}}"
[[ "${NETWORK}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "invalid Compose project/network name: ${NETWORK}" >&2
  exit 2
}

bootstrap_file="${generated}/compose.bootstrap.yaml"
final_file="${generated}/compose.yaml"
observability_file="${generated}/compose.observability.yaml"
policy_file="${generated}/policy.env"
manifest="${generated}/manifest.json"
for required in "${bootstrap_file}" "${final_file}" "${observability_file}" "${policy_file}"; do
  [ -r "${required}" ] || { echo "missing rendered Compose input ${required}" >&2; exit 2; }
done

export ATTACKNET_BACKEND=compose ATTACKNET_PROJECT="${project}"
export ATTACKNET_COMPOSE="${bootstrap_file}"
export ATTACKNET_COMPOSE_EXTRA="${observability_file}"
export ATTACKNET_COMPOSE_POLICY="${policy_file}"
export KUBE_NETWORK="${rendered_network}" KUBE_NAMESPACE="${NAMESPACE}"
# shellcheck source=lifecycle.sh
source "${ATTACKNET_DIR}/lifecycle.sh"

COMPOSE_PROJECT="${project}"
COMPOSE_FILE="${bootstrap_file}"
COMPOSE_EXTRA="${observability_file}"
COMPOSE_POLICY="${policy_file}"
LIFECYCLE_BACKEND=compose

compose_ctl() {
  local file="$1"
  shift
  docker compose -p "${COMPOSE_PROJECT}" -f "${file}" -f "${observability_file}" "$@"
}

set_compose_file() {
  COMPOSE_FILE="$1"
  ATTACKNET_COMPOSE="$1"
  export ATTACKNET_COMPOSE
}

wait_compose_group() {
  local group="$1"
  wait_actor_group_ready "${manifest}" "${group}"
}

wait_compose_telemetry() {
  local deadline=$((SECONDS + TIMEOUT)) result=""
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if result="$(ATTACKNET_BACKEND=compose ATTACKNET_PROJECT="${COMPOSE_PROJECT}" \
        ATTACKNET_COMPOSE="${COMPOSE_FILE}" ATTACKNET_COMPOSE_EXTRA="${observability_file}" \
        "${ATTACKNET_DIR}/verify.sh" "${manifest}" telemetry 2>/dev/null)"; then
      printf '%s\n' "${result}"
      return 0
    fi
    sleep 2
  done
  echo "Compose telemetry coverage did not become healthy: ${result:-no result}" >&2
  return 1
}

ensure_fresh_project() {
  local containers volumes
  containers="$(compose_ctl "${final_file}" ps --all --quiet 2>/dev/null || true)"
  volumes="$(docker volume ls --quiet --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}")"
  if [ -n "${containers}" ] || [ -n "${volumes}" ]; then
    echo "Compose project ${COMPOSE_PROJECT} already has containers or volumes; delete it or set ATTACKNET_COMPOSE_RESUME=1 explicitly" >&2
    [ "${ATTACKNET_COMPOSE_RESUME:-0}" = 1 ] || return 1
  fi
}

capture_compose() {
  local destination="$1" ids
  mkdir -p "${destination}"
  cp "${manifest}" "${destination}/manifest.json"
  compose_ctl "${final_file}" config --format json >"${destination}/compose.admitted.json"
  compose_ctl "${final_file}" ps --all --format json >"${destination}/containers.json"
  ids="$(compose_ctl "${final_file}" ps --all --quiet | tr '\n' ' ')"
  if [ -n "${ids// /}" ]; then
    # shellcheck disable=SC2086
    docker inspect ${ids} >"${destination}/containers.inspected.json"
  else
    printf '[]\n' >"${destination}/containers.inspected.json"
  fi
  docker volume ls --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format json \
    >"${destination}/volumes.jsonl"
  compose_ctl "${final_file}" logs --no-color --timestamps --tail="${ATTACKNET_EVIDENCE_LOG_TAIL:-10000}" \
    >"${destination}/actors.log" 2>&1 || true
  LIFECYCLE_BACKEND=compose COMPOSE_FILE="${final_file}" runtime_backend describe \
    >"${destination}/runtime.json"
}

compose_apply_error() {
  local status="$1" line="$2" destination
  trap - ERR
  set +e
  destination="${generated}/runs/compose-bootstrap-failure"
  echo "Compose attacknet apply failed at compose-lifecycle.sh:${line}; preserving project ${COMPOSE_PROJECT}" >&2
  capture_compose "${destination}"
  if [ -n "${RUN_DESCRIPTOR}" ] && [ -r "${RUN_DESCRIPTOR}" ]; then
    ledger_assertion lifecycle-apply fail "{\"exitStatus\":${status},\"line\":${line},\"backend\":\"compose\"}"
    node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${RUN_DESCRIPTOR}" failed >/dev/null
    ledger_export "${destination}/descriptor"
  fi
  echo "Compose bootstrap failure evidence: ${destination}" >&2
  exit "${status}"
}

apply_compose() {
  local enrollment_height cutoff_height observer_height registration_height activation_height
  local pre_activation_stacks_height desired_interval desired_jitter peer_result signer_report admitted
  ensure_fresh_project
  RUN_DESCRIPTOR="$(node "${ATTACKNET_DIR}/run-ledger.mjs" init "${generated}")"
  ledger_assertion lifecycle-initialized pass \
    "{\"network\":\"${rendered_network}\",\"backend\":\"compose\"}"

  compose_ctl "${bootstrap_file}" up -d
  set_compose_file "${bootstrap_file}"
  wait_compose_group bootstrap-foundation

  enrollment_height="$(manifest_protocol_value "${manifest}" signerEnrollmentHeight)"
  cutoff_height="$(manifest_protocol_value "${manifest}" signerSetCutoffHeight)"
  observer_height="$(manifest_protocol_value "${manifest}" observerEnableHeight)"
  registration_height="$(manifest_protocol_value "${manifest}" signerRegistrationHeight)"
  activation_height="$(manifest_protocol_value "${manifest}" nakamotoActivationHeight)"
  desired_interval="$(sed -n 's/^INTERVAL_SECONDS=//p' "${policy_file}" | tail -1)"
  desired_jitter="$(sed -n 's/^JITTER_SECONDS=//p' "${policy_file}" | tail -1)"

  establish_signer_set "${manifest}" "${enrollment_height}" "${cutoff_height}"
  burst_to_height "${observer_height}" observer-enable
  wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${observer_height}"

  echo "Enabling Compose companion observers and signer processes at burn height ${observer_height}"
  compose_ctl "${final_file}" up -d --remove-orphans
  set_compose_file "${final_file}"
  wait_compose_group pre-activation-nodes
  wait_live_peer_connectivity "${manifest}" pre-activation-nodes

  burst_to_height "${registration_height}" signer-registration
  wait_nodes_at_burn_height "${manifest}" pre-activation-nodes "${registration_height}"
  wait_compose_group bootstrap
  wait_signers_registered "${manifest}"
  wait_companion_stackerdb_subscriptions "${manifest}"
  wait_live_peer_connectivity "${manifest}" pre-activation-nodes

  pre_activation_stacks_height="$(minimum_node_stacks_height "${manifest}" pre-activation-nodes)"
  burst_to_height "${activation_height}" nakamoto-activation
  wait_nodes_at_burn_height "${manifest}" nodes "${activation_height}"
  wait_compose_group actors
  wait_live_peer_connectivity "${manifest}" nodes
  peer_result="${LIVE_PEER_CONNECTIVITY_RESULT}"
  wait_signer_global_state "${manifest}"
  signer_report="$(wait_signer_set_parity "${manifest}")"
  wait_nodes_at_stacks_height "${manifest}" nodes "$((pre_activation_stacks_height + 1))"
  wait_compose_telemetry

  burnchain_policy run "${desired_interval:-60}" "${desired_jitter:-0}"
  ledger_assertion live-peer-connectivity pass "${peer_result}"
  ledger_assertion signer-set-parity pass "${signer_report}"
  ledger_assertion lifecycle-ready pass \
    "{\"backend\":\"compose\",\"burnHeight\":$(clock_status_value bitcoin_height)}"
  admitted="$(dirname "${RUN_DESCRIPTOR}")/run-artifacts/compose"
  capture_compose "${admitted}"
  node "${ATTACKNET_DIR}/run-ledger.mjs" resolve-compose "${RUN_DESCRIPTOR}" \
    "${admitted}/compose.admitted.json" "${admitted}/containers.inspected.json" >/dev/null
  printf 'Compose attacknet %s is Ready and protocol-active\n' "${COMPOSE_PROJECT}"
}

delete_compose() {
  local descriptor status final_status bundle
  set_compose_file "${final_file}"
  descriptor="$(node "${ATTACKNET_DIR}/run-ledger.mjs" locate \
    "--target=${generated}" "--namespace=${rendered_namespace}" "--network=${rendered_network}" 2>/dev/null || true)"
  if [ -n "${descriptor}" ] && [ -r "${descriptor}" ]; then
    RUN_DESCRIPTOR="${descriptor}"
    status="$(node -e 'const fs=require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1])).run.status)' "${descriptor}")"
    final_status="${ATTACKNET_RUN_FINAL_STATUS:-aborted}"
    bundle="${ATTACKNET_RUN_EXPORT_DIR:-$(dirname "${descriptor}")/bundle}"
    capture_compose "${bundle}/compose"
    # Runtime resolution is a hard prerequisite only for a passed run. A
    # failed bootstrap can be intentionally torn down while retaining its
    # truthful incomplete-resolution record; attempting to mutate that sealed
    # descriptor would otherwise make cleanup impossible.
    if [ "${status}" = running ] && [ "${final_status}" = passed ] \
        && [ "$(node -e 'const fs=require("node:fs"); const v=JSON.parse(fs.readFileSync(process.argv[1])); console.log(v.inputs.kubernetes.resolution.complete)' "${descriptor}")" != true ]; then
      node "${ATTACKNET_DIR}/run-ledger.mjs" resolve-compose "${descriptor}" \
        "${bundle}/compose/compose.admitted.json" \
        "${bundle}/compose/containers.inspected.json" >/dev/null
    fi
    if [ "${status}" = running ]; then
      node "${ATTACKNET_DIR}/run-ledger.mjs" finalize "${descriptor}" \
        "${final_status}" >/dev/null
    fi
    ledger_export "${bundle}/descriptor"
    echo "Compose run evidence exported before teardown: ${bundle}"
  fi
  compose_ctl "${final_file}" down --volumes --remove-orphans
  if [ -n "$(docker volume ls --quiet --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}")" ]; then
    echo "Compose project volumes survived teardown" >&2
    return 1
  fi
  echo "Deleted Compose project ${COMPOSE_PROJECT} and its named volumes"
}

lock="${ATTACKNET_DIR}/environment-lock.sh"
case "${command}" in
  apply|delete)
    if [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
      "${lock}" claim "${rendered_network}" "${ATTACKNET_LOCK_OWNER:-compose-lifecycle:$$}" "compose-${command}"
      exec "${lock}" run "${rendered_network}" "${ATTACKNET_LOCK_OWNER:-compose-lifecycle:$$}" \
        "compose-${command}" -- "$0" "$@"
    fi
    "${lock}" assert "${rendered_network}" "${ATTACKNET_MUTATION_TOKEN}"
    ;;
  wait|capture) "${lock}" environment-assert "${rendered_network}" ;;
esac

case "${command}" in
  apply) trap 'compose_apply_error $? ${LINENO}' ERR; apply_compose; trap - ERR ;;
  wait)
    set_compose_file "${final_file}"
    wait_compose_group actors
    ATTACKNET_BACKEND=compose ATTACKNET_PROJECT="${COMPOSE_PROJECT}" \
      ATTACKNET_COMPOSE="${final_file}" ATTACKNET_COMPOSE_EXTRA="${observability_file}" \
      "${ATTACKNET_DIR}/verify.sh" "${manifest}" snapshot
    ;;
  capture) capture_compose "${3:?evidence directory required}" ;;
  delete) delete_compose; "${lock}" release "${rendered_network}" ;;
esac
