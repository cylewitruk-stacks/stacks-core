#!/bin/bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${POC_DIR}/canonical-progress.sh"
source "${POC_DIR}/runtime-backend.sh"
source "${POC_DIR}/signer-companion-drift.sh"
MANIFEST="${POC_MANIFEST:-${POC_DIR}/generated/manifest.json}"

manifest_list() {
  local expression="$1"
  node -e "const m=require(process.argv[1]); console.log(${expression})" "${MANIFEST}"
}

rpc() {
  local service="$1"
  shift
  backend_exec "${service}" curl --fail --silent "$@"
}

rpc_retry() {
  local service="$1"
  shift
  local deadline=$((SECONDS + ${VERIFY_RPC_RETRY_SECONDS:-30}))
  local response
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if response="$(rpc "${service}" "$@" 2>/dev/null)"; then
      printf '%s\n' "${response}"
      return 0
    fi
    sleep 1
  done
  echo "timed out reading ${service} RPC: $*" >&2
  return 1
}

json_number() {
  local field="$1"
  sed -n "s/.*\"${field}\":\([0-9][0-9]*\).*/\1/p"
}

json_string() {
  local field="$1"
  sed -n "s/.*\"${field}\":\"\([0-9a-f][0-9a-f]*\)\".*/\1/p"
}

json_text() {
  local field="$1"
  sed -n "s/.*\"${field}\":\"\([^\"]*\)\".*/\1/p"
}

if [ -n "${VERIFY_START_BURN_HEIGHT:-}" ]; then
  [[ "${VERIFY_START_BURN_HEIGHT}" =~ ^[0-9]+$ ]] || {
    echo "VERIFY_START_BURN_HEIGHT must be a non-negative integer" >&2
    exit 2
  }
  burn_block_delta="${VERIFY_BURN_BLOCK_DELTA:-300}"
  [[ "${burn_block_delta}" =~ ^[1-9][0-9]*$ ]] || {
    echo "VERIFY_BURN_BLOCK_DELTA must be a positive integer" >&2
    exit 2
  }
  target_burn_height=$((VERIFY_START_BURN_HEIGHT + burn_block_delta))
else
  target_burn_height="${VERIFY_BURN_HEIGHT:-300}"
fi

# The verifier proves the generated Epoch 4 and PoX-5 fixtures below, so an
# earlier requested height cannot satisfy its own acceptance contract.  The
# cadence controller checks each fixture at the configured gate *before*
# producing the following burn block; waiting for that following block makes
# fixture availability a causal precondition instead of racing an HTTP 404.
epoch_4_contract_gate_height="${EPOCH_4_CONTRACT_GATE_HEIGHT:-244}"
pox5_signer_gate_height="${POX5_SIGNER_GATE_HEIGHT:-255}"
for gate in "${epoch_4_contract_gate_height}" "${pox5_signer_gate_height}"; do
  [[ "${gate}" =~ ^[0-9]+$ ]] || {
    echo "protocol fixture gate heights must be non-negative integers" >&2
    exit 2
  }
done
protocol_evidence_height=$((
  (epoch_4_contract_gate_height > pox5_signer_gate_height
    ? epoch_4_contract_gate_height
    : pox5_signer_gate_height) + 1
))
if [ "${target_burn_height}" -lt "${protocol_evidence_height}" ]; then
  echo "Raising verification target from burn ${target_burn_height} to ${protocol_evidence_height} so protocol fixtures are provably active"
  target_burn_height="${protocol_evidence_height}"
fi
verify_timeout_seconds="${VERIFY_TIMEOUT_SECONDS:-1800}"
stacks_progress_timeout_seconds="${VERIFY_STACKS_PROGRESS_TIMEOUT_SECONDS:-180}"
expected_actors="$(manifest_list 'm.actors.length')"
signer_count="$(manifest_list 'm.signerCount')"
miner_count="$(manifest_list 'm.minerCount')"
actor_connection_cap="$(manifest_list 'm.connectionLimits.actor')"
signer_connection_cap="$(manifest_list 'm.connectionLimits.signer')"
miner_connection_cap="$(manifest_list 'm.connectionLimits.miner')"
bootstrap_connection_cap="$(manifest_list 'm.connectionLimits.bootstrap')"
node_services="$(manifest_list 'm.actors.filter(a => a.type === "node").map(a => a.service).join(" ")')"
signer_services="$(manifest_list 'm.actors.filter(a => a.type === "signer").map(a => a.service).join(" ")')"
miner_services="$(manifest_list 'm.actors.filter(a => a.role === "miner").map(a => a.service).join(" ")')"
actor_services="$(manifest_list 'm.actors.map(a => a.service).join(" ")')"

services="bitcoin bitcoin-miner stacker telemetry-collector prometheus observer ${actor_services}"
if [ "${POC_BACKEND}" = compose ]; then
  for actor in ${actor_services}; do
    services+=" telemetry-${actor}"
  done
fi

backend_require

echo "Waiting for ${expected_actors} enrolled actors (${miner_count} miners, ${signer_count} signer/companion pairs), target burn ${target_burn_height}"
readiness_deadline=$((SECONDS + 360))
while :; do
  unready="$(backend_unready_actors ${services})"
  if [ -z "${unready}" ]; then break; fi
  if [ "${SECONDS}" -ge "${readiness_deadline}" ]; then
    echo "services did not become ready: ${unready}" >&2
    for service in ${unready}; do backend_logs 100 "" "${service}" >&2 || true; done
    exit 1
  fi
  sleep 2
done

primary_info="$(rpc miner-1 http://127.0.0.1:20443/v2/info || true)"
baseline_height="$(json_number stacks_tip_height <<<"${primary_info}")"
baseline_tip="$(json_string stacks_tip <<<"${primary_info}")"
if [ -z "${baseline_height}" ] || [ -z "${baseline_tip}" ]; then
  echo "could not establish the canonical Stacks baseline for progress verification" >&2
  exit 1
fi

target_deadline=$((SECONDS + verify_timeout_seconds))
while [ "${SECONDS}" -lt "${target_deadline}" ]; do
  primary_info="$(rpc miner-1 http://127.0.0.1:20443/v2/info || true)"
  primary_burn="$(json_number burn_block_height <<<"${primary_info}")"
  if [ -n "${primary_burn}" ] && [ "${primary_burn}" -ge "${target_burn_height}" ]; then
    break
  fi
  sleep 5
done
if [ -z "${primary_burn:-}" ] || [ "${primary_burn}" -lt "${target_burn_height}" ]; then
  echo "primary miner did not reach required burn height ${target_burn_height}" >&2
  backend_logs 160 "" bitcoin-miner miner-1 >&2
  exit 1
fi

# Burn-height reachability alone is insufficient: Bitcoin intentionally keeps
# moving through a Stacks outage. Require a fresh canonical Stacks transition
# independently, so verification fails without killing the cadence producer.
fresh_progress=0
progress_deadline=$((SECONDS + stacks_progress_timeout_seconds))
while [ "${SECONDS}" -lt "${progress_deadline}" ]; do
  primary_info="$(rpc miner-1 http://127.0.0.1:20443/v2/info || true)"
  primary_height="$(json_number stacks_tip_height <<<"${primary_info}")"
  primary_tip="$(json_string stacks_tip <<<"${primary_info}")"
  if canonical_tip_advanced \
    "${baseline_height}" "${baseline_tip}" "${primary_height}" "${primary_tip}"; then
    fresh_progress=1
    break
  fi
  sleep 2
done
if [ "${fresh_progress}" -ne 1 ]; then
  echo "Bitcoin reached burn ${primary_burn}, but Stacks did not make a fresh canonical transition within ${stacks_progress_timeout_seconds}s (baseline=${baseline_height}:${baseline_tip})" >&2
  exit 1
fi

deadline=$((SECONDS + verify_timeout_seconds))

# Freeze only Bitcoin production while all independently scheduled nodes
# converge. This does not stop Stacks/libp2p processing and avoids trying to
# compare 18 moving tips in one polling instant.
paused=0
pause_guard_pid=""
cleanup() {
  if [ -n "${pause_guard_pid}" ]; then
    kill "${pause_guard_pid}" >/dev/null 2>&1 || true
    wait "${pause_guard_pid}" >/dev/null 2>&1 || true
    pause_guard_pid=""
  fi
  if [ "${paused}" -eq 1 ]; then backend_resume bitcoin-miner >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
if [ "${VERIFY_PAUSE_MINING:-1}" = 1 ]; then
  backend_pause bitcoin-miner >/dev/null
  paused=1
  # A verifier can be externally terminated before Bash runs its EXIT trap.
  # Keep a detached bounded failsafe so an abandoned verification cannot
  # strand Bitcoin production in the paused state.
  nohup bash -c 'sleep "$1"; shift; exec "$@"' _ \
    "${VERIFY_PAUSE_FAILSAFE_SECONDS:-3000}" \
    env POC_BACKEND="${POC_BACKEND}" POC_PROJECT="${POC_PROJECT}" \
      KUBE_NAMESPACE="${KUBE_NAMESPACE}" KUBE_NETWORK="${KUBE_NETWORK}" \
      "${POC_DIR}/runtime-backend.sh" resume bitcoin-miner \
    >/dev/null 2>&1 &
  pause_guard_pid="$!"
  sleep 5
fi

converged=0
while [ "${SECONDS}" -lt "${deadline}" ]; do
  primary_info="$(rpc miner-1 http://127.0.0.1:20443/v2/info || true)"
  primary_burn="$(json_number burn_block_height <<<"${primary_info}")"
  primary_height="$(json_number stacks_tip_height <<<"${primary_info}")"
  primary_tip="$(json_string stacks_tip <<<"${primary_info}")"
  converged=1
  for service in ${node_services}; do
    info="$(rpc "${service}" http://127.0.0.1:20443/v2/info || true)"
    burn="$(json_number burn_block_height <<<"${info}")"
    height="$(json_number stacks_tip_height <<<"${info}")"
    tip="$(json_string stacks_tip <<<"${info}")"
    if [ "${burn}" != "${primary_burn}" ] || [ "${height}" != "${primary_height}" ] \
      || [ "${tip}" != "${primary_tip}" ] || ! grep -q '"is_fully_synced":true' <<<"${info}"; then
      converged=0
      break
    fi
  done
  if [ "${converged}" -eq 1 ]; then break; fi
  sleep 3
done
if [ "${converged}" -ne 1 ]; then
  echo "all generated Stacks nodes failed to converge on one canonical tip" >&2
  echo "reference: burn=${primary_burn:-unknown} stacks=${primary_height:-unknown} tip=${primary_tip:-unknown}" >&2
  for service in ${node_services}; do
    info="$(rpc "${service}" http://127.0.0.1:20443/v2/info 2>/dev/null || true)"
    echo "${service}: burn=$(json_number burn_block_height <<<"${info}") stacks=$(json_number stacks_tip_height <<<"${info}") tip=$(json_string stacks_tip <<<"${info}")" >&2
  done
  exit 1
fi

if ! signer_drift="$(signer_companion_drift_report "${VERIFY_SIGNER_MAX_BURN_DRIFT:-2}")"; then
  echo "signer state machines are not following their enrolled companions:" >&2
  echo "${signer_drift}" >&2
  exit 1
fi

for service in ${node_services}; do
  diagnostics="$(rpc_retry "${service}" -H 'authorization: 12345' http://127.0.0.1:20443/v3/network/diagnostics)"
  if [ "$(json_text peer_transport_mode <<<"${diagnostics}")" != "libp2p-only" ] \
    || ! grep -q '"legacy_listener_enabled":false' <<<"${diagnostics}" \
    || [ "$(json_text signer_bridge_mode <<<"${diagnostics}")" != "off" ]; then
    echo "${service} did not confirm live libp2p-only operation" >&2
    exit 1
  fi
  if ! grep -q '"peer_store_enabled":true' <<<"${diagnostics}"; then
    echo "${service} has no bounded persistent libp2p peer store" >&2
    exit 1
  fi
done

primary_diagnostics="$(rpc_retry miner-1 -H 'authorization: 12345' http://127.0.0.1:20443/v3/network/diagnostics)"
resource_rejections="$(json_number resource_budget_rejections <<<"${primary_diagnostics}")"
if [ "${resource_rejections:-0}" -gt 100000 ]; then
  echo "delivery retry amplification detected: resource_rejections=${resource_rejections:-0}" >&2
  exit 1
fi

# A new process has no in-memory last-commit marker. The generated one-second
# delay must keep it active even when Bitcoin produces five-second flash blocks.
# Falling below the consensus 3-of-6 rule can otherwise leave a whole compact
# PoX prepare phase without a canonical anchor.
inactive_miner_rejections="$(backend_logs 10000 "" ${miner_services} 2>&1 \
  | grep -c 'WINNER REJECTED.*Miner did not mine often enough' || true)"
if [ "${inactive_miner_rejections}" -ne 0 ]; then
  echo "Observed ${inactive_miner_rejections} mining-frequency winner rejection(s); accelerated commit cadence is unsafe" >&2
  exit 1
fi

forwarded_gossip_signers=0
for signer in ${signer_services}; do
  logs="$(backend_logs 10000 "" "${signer}")"
  for evidence in \
    'accepted challenge-bound libp2p hello response' \
    'published role-signed libp2p signer semantic envelope' \
    'received a block proposal for a new block' \
    'submitting block proposal for validation'; do
    if ! grep -q "${evidence}" <<<"${logs}"; then
      echo "${signer} is missing evidence: ${evidence}" >&2
      exit 1
    fi
  done
  if grep -q 'Sending signer update through temporary StackerDB compatibility writer' <<<"${logs}"; then
    echo "${signer} unexpectedly used the legacy signer bridge" >&2
    exit 1
  fi
  if grep -Eq 'queued block validation over authenticated native libp2p|SubmitBlockProposal|peer validation result|gateway validation' <<<"${logs}"; then
    echo "${signer} exposed obsolete peer-validation machinery" >&2
    exit 1
  fi
  # A sparse connection count alone does not prove mesh forwarding. The typed
  # GossipSub event preserves both the signed envelope's original source and
  # the immediate propagation peer. Different values are positive evidence
  # that this process accepted the envelope after at least one relay hop.
  if node -e '
    const fs = require("node:fs");
    const logs = fs.readFileSync(0, "utf8").replace(/\x1b\[[0-9;]*m/g, "");
    const relayed = logs.split("\n").some(line => {
      if (!line.includes("accepted role-signed libp2p signer semantic envelope")) return false;
      const immediate = line.match(/peer_id=([1-9A-HJ-NP-Za-km-z]+)/)?.[1];
      const original = line.match(/source=([1-9A-HJ-NP-Za-km-z]+)/)?.[1];
      return Boolean(immediate && original && immediate !== original);
    });
    process.exit(relayed ? 0 : 1);
  ' <<<"${logs}"; then
    forwarded_gossip_signers=$((forwarded_gossip_signers + 1))
  fi
done
if [ "${signer_count}" -gt 5 ]; then
  required_forwarded_signers=$(((signer_count + 1) / 2))
  if [ "${forwarded_gossip_signers}" -lt "${required_forwarded_signers}" ]; then
    echo "only ${forwarded_gossip_signers}/${signer_count} signers have accepted multi-hop GossipSub evidence; require ${required_forwarded_signers}" >&2
    exit 1
  fi
fi

for index in $(seq 0 $((signer_count - 1))); do
  address="$(node -e 'const m=require(process.argv[1]); console.log(m.signers[Number(process.argv[2])][2])' "${MANIFEST}" "${index}")"
  rpc miner-1 "http://127.0.0.1:20443/v2/contracts/source/${address}/pox5-signer-${index}" >/dev/null
  account="$(rpc miner-1 "http://127.0.0.1:20443/v2/accounts/${address}?proof=0")"
  if ! grep -Eq '"locked":"(0x0*[1-9a-fA-F][0-9a-fA-F]*|[1-9][0-9]*)"' <<<"${account}"; then
    echo "PoX-5 signer ${index} has no locked stake" >&2
    exit 1
  fi
done

for contract in sbtc-token sbtc-registry; do
  rpc miner-1 "http://127.0.0.1:20443/v2/contracts/source/ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H/${contract}" >/dev/null
done
if ! grep -q '"current_epoch":"Epoch40"' <<<"$(rpc miner-1 http://127.0.0.1:20443/v2/pox)"; then
  echo "network is not in Epoch 4.0" >&2
  exit 1
fi

# Poll the authenticated view until every generated token-attributed actor is
# fresh. Public and authenticated views remain separate even in this PoC.
observer_summary="$(backend_exec_env observer \
  EXPECTED_ACTORS="${expected_actors}" \
  EXPECTED_SIGNERS="${signer_count}" \
  EXPECTED_MINERS="${miner_count}" \
  ACTOR_CONNECTION_CAP="${actor_connection_cap}" \
  SIGNER_CONNECTION_CAP="${signer_connection_cap}" \
  MINER_CONNECTION_CAP="${miner_connection_cap}" \
  BOOTSTRAP_CONNECTION_CAP="${bootstrap_connection_cap}" \
  REQUIRE_SIGNER_RELEASE="${VERIFY_REQUIRE_SIGNER_RELEASE:-0}" \
  -- node -e '
  const base = "http://127.0.0.1:4319";
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  (async () => {
    const login = await fetch(`${base}/api/session/login`, {
      method: "POST", headers: {"content-type": "application/json"},
      body: JSON.stringify({email: process.env.STACKS_OBSERVER_DEV_EMAIL, password: "stacks123"}),
    });
    if (!login.ok) throw new Error(`login returned ${login.status}`);
    const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
    const expectedActors = Number(process.env.EXPECTED_ACTORS);
    const expectedSigners = Number(process.env.EXPECTED_SIGNERS);
    const expectedMiners = Number(process.env.EXPECTED_MINERS);
    const requireSignerRelease = process.env.REQUIRE_SIGNER_RELEASE === "1";
    let snapshot;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const response = await fetch(`${base}/api/federation/snapshot`, {headers: {cookie}});
      if (!response.ok) throw new Error(`snapshot returned ${response.status}`);
      snapshot = await response.json();
      if (snapshot.summary?.reportingNodes === expectedActors
        && snapshot.actorMetrics?.length === expectedActors
        && snapshot.nodes?.filter(node => node.role === "signer").length === expectedSigners
        && snapshot.publicNetwork?.signers?.length === expectedSigners) break;
      await sleep(1_000);
    }
    const serialized = JSON.stringify(snapshot);
    const quorum = snapshot.signerQuorumRounds?.find(round =>
      round.status === "approved" && round.approvedWeight >= round.thresholdWeight);
    const capFor = node => node.id === "poc-miner-1"
      ? Number(process.env.BOOTSTRAP_CONNECTION_CAP)
      : node.role === "signer"
        ? Number(process.env.SIGNER_CONNECTION_CAP)
      : node.role === "miner"
        ? Number(process.env.MINER_CONNECTION_CAP)
        : Number(process.env.ACTOR_CONNECTION_CAP);
    const peerLimitFailures = snapshot.nodes?.filter(node =>
      node.inboundPeers === null || node.inboundPeers > capFor(node)) ?? [];
    const signerRendezvousFailures = snapshot.actorMetrics
      ?.filter(actor => actor.role === "signer")
      .filter(actor => actor.readings?.find(reading =>
        reading.name === "stacks_p2p_rendezvous_connections")?.value !== expectedMiners) ?? [];
    const companionExecutionFailures = snapshot.actorMetrics
      ?.filter(actor => actor.role === "companion")
      .filter(actor => !(actor.readings?.find(reading =>
        reading.name === "stacks_node_block_proposal_validation_executions_total")?.value > 0)) ?? [];
    const signerObservationFailures = snapshot.actorMetrics
      ?.filter(actor => actor.role === "signer")
      .filter(actor => !(actor.readings ?? [])
        .filter(reading => reading.name === "stacks_signer_block_validation_responses_total")
        .some(reading => reading.value > 0)) ?? [];
    const signerDriftIncidents = snapshot.incidents
      ?.filter(incident => incident.id.startsWith("signer-companion-drift-")) ?? [];
    const signerLifecycle = snapshot.actorMetrics?.filter(actor => actor.role === "signer").map(actor => {
      const metric = (name, key, value) => (actor.readings ?? [])
        .filter(reading => reading.name === name && (!key || reading.attributes?.some(attribute => attribute.key === key && attribute.value === value)))
        .reduce((total, reading) => total + Number(reading.value ?? 0), 0);
      const admitted = metric("stacks_signer_deferred_miner_authorizations_admitted_total");
      const pending = metric("stacks_signer_deferred_miner_authorizations_pending");
      const resolutions = Object.fromEntries(["released", "expired", "unauthorized", "redundant", "binding_failed", "malformed"]
        .map(value => [value, metric("stacks_signer_deferred_miner_authorizations_resolved_total", "resolution", value)]));
      const resolved = Object.values(resolutions).reduce((total, value) => total + value, 0);
      const generation = metric("stacks_signer_native_network_generation_start_timestamp_seconds");
      return {actor: actor.actorId, admitted, pending, resolutions, generation, conserved: admitted === pending + resolved};
    }) ?? [];
    const signerLifecycleFailures = signerLifecycle.filter(item => !item.conserved || !(item.generation > 0));
    const releasedDeferred = signerLifecycle.reduce((total, item) => total + item.resolutions.released, 0);
    const linkedActors = new Set((snapshot.links ?? []).flatMap(link => [link.source, link.target]));
    const unlinkedActors = snapshot.nodes?.filter(node => !linkedActors.has(node.id)) ?? [];
    if (snapshot.summary?.reportingNodes !== expectedActors
      || snapshot.actorMetrics?.length !== expectedActors
      || snapshot.nodes?.filter(node => node.role === "signer").length !== expectedSigners
      || snapshot.publicNetwork?.signers?.length !== expectedSigners
      || !snapshot.nodes?.some(node => node.role === "companion")
      || !quorum || quorum.votes?.length !== expectedSigners
      || quorum.approvedWeight < quorum.thresholdWeight
      || quorum.unavailableWeight !== 0
      || peerLimitFailures.length !== 0
      || signerRendezvousFailures.length !== 0
      || companionExecutionFailures.length !== 0
      || signerObservationFailures.length !== 0
      || signerDriftIncidents.length !== 0
      || signerLifecycleFailures.length !== 0
      || (requireSignerRelease && releasedDeferred < 1)
      || unlinkedActors.length !== 0
      || serialized.includes("16Uiu") || serialized.includes("/ip4/")) {
      throw new Error(`incomplete or unsafe observer projection: ${JSON.stringify({reporting: snapshot.summary?.reportingNodes, metrics: snapshot.actorMetrics?.length, signers: snapshot.publicNetwork?.signers?.length, quorumVotes: quorum?.votes?.length, unavailableWeight: quorum?.unavailableWeight, peerLimitFailures: peerLimitFailures.map(node => ({id: node.id, peers: node.inboundPeers, cap: capFor(node)})), signerRendezvousFailures: signerRendezvousFailures.map(actor => actor.actorId), companionExecutionFailures: companionExecutionFailures.map(actor => actor.actorId), signerObservationFailures: signerObservationFailures.map(actor => actor.actorId), signerDriftIncidents: signerDriftIncidents.map(incident => incident.id), signerLifecycleFailures, releasedDeferred, unlinkedActors: unlinkedActors.map(node => node.id)})}`);
    }
    console.log(JSON.stringify({burn: snapshot.summary.burnHeight, stacks: snapshot.summary.stacksHeight, actors: snapshot.summary.reportingNodes, signers: expectedSigners, links: snapshot.summary.observedLinks, quorum: quorum.status, releasedDeferred}));
  })().catch(error => { console.error(error); process.exit(1); });
')"

if backend_actor_exists observer-reporter; then
  echo "obsolete polling observer adapter is still present" >&2
  exit 1
fi

cleanup
paused=0
trap - EXIT
echo "Verified ${miner_count} miners, ${signer_count} signer/companion pairs, and $((${expected_actors} - ${miner_count} - 2 * ${signer_count})) outsider followers at burn ${primary_burn}, Stacks ${primary_height}: ${observer_summary}"
