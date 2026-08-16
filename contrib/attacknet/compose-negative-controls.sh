#!/usr/bin/env bash
set -Eeuo pipefail

ATTACKNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generated="${1:?generated topology directory required}"
destination="${2:?evidence directory required}"
manifest="${generated}/manifest.json"
final_file="${generated}/compose.yaml"
observability_file="${generated}/compose.observability.yaml"
policy_file="${generated}/policy.env"
[ -r "${manifest}" ] && [ -r "${final_file}" ] && [ -r "${observability_file}" ] || {
  echo "incomplete generated Compose topology" >&2
  exit 2
}
network="$(node -e 'const fs=require("node:fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1])).network)' "${manifest}")"
project="${ATTACKNET_PROJECT:-${network}}"
lock="${ATTACKNET_DIR}/environment-lock.sh"
if [ -z "${ATTACKNET_MUTATION_TOKEN:-}" ]; then
  exec "${lock}" run "${network}" "${ATTACKNET_LOCK_OWNER:-compose-controls:$$}" \
    compose-negative-controls -- "$0" "$@"
fi
"${lock}" assert "${network}" "${ATTACKNET_MUTATION_TOKEN}"
follower="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" followers | awk '{print $1}')"
signer="$(node "${ATTACKNET_DIR}/manifest-inventory.mjs" "${manifest}" signers | awk '{print $1}')"
[ -n "${follower}" ] && [ -n "${signer}" ] || {
  echo "paired controls require at least one follower and signer" >&2
  exit 2
}
mkdir -p "${destination}"

export ATTACKNET_BACKEND=compose ATTACKNET_PROJECT="${project}"
export ATTACKNET_COMPOSE="${final_file}" ATTACKNET_COMPOSE_EXTRA="${observability_file}"
export ATTACKNET_COMPOSE_POLICY="${policy_file}" KUBE_NETWORK="${network}"
source "${ATTACKNET_DIR}/runtime-backend.sh"

verify() {
  "${ATTACKNET_DIR}/verify.sh" "${manifest}" "$@"
}

policy() {
  "${ATTACKNET_DIR}/burnchain-policy.sh" "$@"
}

wait_verify() {
  local action="$1" output="$2" deadline=$((SECONDS + ${ATTACKNET_CONTROL_TIMEOUT_SECONDS:-180}))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if verify "${action}" >"${output}" 2>"${output}.stderr"; then return 0; fi
    sleep 2
  done
  return 1
}

record_assertion() {
  local assertion="$1" details="$2" descriptor
  descriptor="$(node "${ATTACKNET_DIR}/run-ledger.mjs" locate "--target=${generated}" \
    "--namespace=$(node -e 'const fs=require("node:fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1])).namespace)' "${manifest}")" \
    "--network=${network}" 2>/dev/null || true)"
  [ -n "${descriptor}" ] || return 0
  node "${ATTACKNET_DIR}/run-ledger.mjs" append "${descriptor}" assertion-result \
    "$(ASSERTION="${assertion}" DETAILS="${details}" node -e '
      console.log(JSON.stringify({assertion:process.env.ASSERTION,status:"pass",details:JSON.parse(process.env.DETAILS)}));
    ')" >/dev/null
}

wait_actor_burn_at_least() {
  local actor="$1" target="$2" deadline=$((SECONDS + ${ATTACKNET_CONTROL_TIMEOUT_SECONDS:-180}))
  local info height=""
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    info="$(backend_exec "${actor}" curl --fail --silent --max-time 3 \
      http://127.0.0.1:20443/v2/info 2>/dev/null || true)"
    height="$(INFO="${info}" node -e '
      try { const value=JSON.parse(process.env.INFO).burn_block_height;
        if (Number.isSafeInteger(value)) process.stdout.write(String(value)); } catch {}
    ')"
    if [[ "${height}" =~ ^[0-9]+$ ]] && [ "${height}" -ge "${target}" ]; then return 0; fi
    sleep 1
  done
  echo "${actor} did not reach burn height ${target}; observed ${height:-unavailable}" >&2
  return 1
}

follower_paused=false
signer_paused=false
burnchain_disconnected=false
follower_container=""
burnchain_network=""
cleanup() {
  trap - EXIT INT TERM
  set +e
  if [ "${follower_paused}" = true ]; then backend_resume "${follower}"; fi
  if [ "${signer_paused}" = true ]; then backend_resume "${signer}"; fi
  if [ "${burnchain_disconnected}" = true ]; then
    docker network connect "${burnchain_network}" "${follower_container}"
  fi
  policy pause >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Freeze autonomous cadence before the reference sample. Every subsequent
# transition is explicit, acknowledged by the clock process, and captured in
# the run ledger. This prevents a slow control from changing its own baseline.
policy pause
wait_verify snapshot "${destination}/baseline-cohort.json"
wait_verify telemetry "${destination}/baseline-telemetry.json"

# Control 1: a paused actor remains enrolled but cannot answer Prometheus. The
# exact invariant must identify that actor as scrape-down and recover without
# accepting stale or missing samples.
backend_pause "${follower}"
follower_paused=true
sleep 7
telemetry_status=0
verify telemetry >"${destination}/telemetry-fault.json" 2>"${destination}/telemetry-fault.stderr" \
  || telemetry_status=$?
[ "${telemetry_status}" -ne 0 ] || { echo "telemetry negative control unexpectedly passed" >&2; exit 1; }
jq -e --arg actor "${follower}" '
  (.ok == false)
  and ([.rows[] | select(.actor == $actor) | .reasons[]] | index("scrape-down") != null)
  and ([.rows[] | select(.actor != $actor) | .reasons | length] | all(. == 0))
' "${destination}/telemetry-fault.json" >/dev/null
backend_resume "${follower}"
follower_paused=false
wait_verify telemetry "${destination}/telemetry-recovered.json"
record_assertion compose-telemetry-negative-control \
  "$(jq -c '{fault:.rows,recovered:true}' "${destination}/telemetry-fault.json")"

# Control 2: disconnect only the follower's burnchain network. Stacks P2P and
# Prometheus remain attached to the default network, so burn drift is the
# attributed effect rather than generic actor loss.
follower_container="$(backend_compose ps --quiet "${follower}")"
burnchain_network="$(docker network ls --filter "label=com.docker.compose.project=${project}" \
  --filter 'label=com.docker.compose.network=burnchain' --format '{{.Name}}' | head -1)"
[ -n "${follower_container}" ] && [ -n "${burnchain_network}" ] || {
  echo "could not resolve follower container or Compose burnchain network" >&2
  exit 1
}
wait_verify snapshot "${destination}/burnchain-pre-partition.json"
partition_start="$(jq -er --arg actor "${follower}" '.rows[] | select(.actor == $actor) | .burnHeight' \
  "${destination}/burnchain-pre-partition.json")"
docker network disconnect "${burnchain_network}" "${follower_container}"
burnchain_disconnected=true
policy burst 5 2
wait_actor_burn_at_least miner-1 "$((partition_start + 3))"
drift_status=0
verify snapshot-allow-unready >"${destination}/burnchain-partition.json" \
  2>"${destination}/burnchain-partition.stderr" || drift_status=$?
[ "${drift_status}" -ne 0 ] || { echo "burnchain partition negative control unexpectedly passed" >&2; exit 1; }
jq -e '.ok == false and .burnDrift > .ceiling' "${destination}/burnchain-partition.json" >/dev/null
docker network connect "${burnchain_network}" "${follower_container}"
burnchain_disconnected=false
wait_verify snapshot "${destination}/burnchain-recovered.json"
record_assertion compose-burnchain-partition-negative-control \
  "$(jq -c '{burnDrift,stacksDrift,recovered:true}' "${destination}/burnchain-partition.json")"

# Control 3: with the only signer unavailable, Bitcoin must continue while no
# Stacks block can be finalized. This deliberately allows an unready signer so
# the shared progress invariant, rather than readiness, classifies the effect.
backend_pause "${signer}"
signer_paused=true
policy run 2 0
stall_status=0
ATTACKNET_PROGRESS_WINDOW_SECONDS="${ATTACKNET_CONTROL_PROGRESS_SECONDS:-12}" \
  verify progress-allow-unready >"${destination}/signer-stall.json" \
  2>"${destination}/signer-stall.stderr" || stall_status=$?
policy pause
[ "${stall_status}" -ne 0 ] || { echo "signer stall negative control unexpectedly passed" >&2; exit 1; }
jq -e '.progress.ok == false and .progress.burn.delta >= 1 and .progress.stacks.delta == 0' \
  "${destination}/signer-stall.json" >/dev/null
backend_resume "${signer}"
signer_paused=false
wait_verify snapshot "${destination}/signer-ready.json"
policy run 2 0
ATTACKNET_PROGRESS_WINDOW_SECONDS="${ATTACKNET_CONTROL_RECOVERY_SECONDS:-30}" \
  verify progress >"${destination}/signer-recovered.json"
policy pause
record_assertion compose-signer-stall-negative-control \
  "$(jq -c '{fault:.progress,recovery:true}' "${destination}/signer-stall.json")"

backend_compose ps --all --format json >"${destination}/containers.final.json"
docker network inspect "${burnchain_network}" >"${destination}/burnchain-network.final.json"
jq -n --arg network "${network}" --arg project "${project}" \
  --arg follower "${follower}" --arg signer "${signer}" \
  '{schemaVersion:1,ok:true,backend:"compose",network:$network,project:$project,
    controls:[
      {id:"telemetry-loss",target:$follower,effect:"scrape-down",recovered:true},
      {id:"burnchain-partition",target:$follower,effect:"burn-height-drift",recovered:true},
      {id:"signer-stall",target:$signer,effect:"burn-progress-with-zero-stacks-progress",recovered:true}
    ]}' >"${destination}/result.json"
trap - EXIT INT TERM
echo "Compose negative controls passed; evidence: ${destination}"
