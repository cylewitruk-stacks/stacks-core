import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {actorServiceInventory} from './manifest-inventory.mjs';
import {buildTopology, renderTopology} from './topology.mjs';

const canonicalProgress = join(import.meta.dirname, 'canonical-progress.sh');
const miningController = join(import.meta.dirname, 'mine.sh');
const baseCompose = join(import.meta.dirname, 'compose.yaml');
const chaosRunner = join(import.meta.dirname, 'chaos.sh');
const verifier = join(import.meta.dirname, 'verify.sh');
const soakRunner = join(import.meta.dirname, 'soak.sh');

function canonicalTipAdvanced(priorHeight, priorId, currentHeight, currentId) {
  return spawnSync(
    'bash',
    [
      '-c',
      'source "$1"; canonical_tip_advanced "$2" "$3" "$4" "$5"',
      '_',
      canonicalProgress,
      String(priorHeight),
      priorId,
      String(currentHeight),
      currentId,
    ],
  ).status === 0;
}

function cadenceRestartCanReuseMempool(priorHeight, currentHeight, mempoolSize) {
  return spawnSync(
    'bash',
    [
      '-c',
      'source "$1"; cadence_restart_can_reuse_mempool "$2" "$3" "$4"',
      '_',
      canonicalProgress,
      String(priorHeight),
      String(currentHeight),
      String(mempoolSize),
    ],
  ).status === 0;
}

test('canonical progress recognizes same-height tip replacement and fails closed', () => {
  const first = '1'.repeat(64);
  const second = '2'.repeat(64);
  assert.equal(canonicalTipAdvanced(21, first, 22, second), true);
  assert.equal(canonicalTipAdvanced(21, first, 21, second), true);
  assert.equal(canonicalTipAdvanced(21, first, 21, first), false);
  assert.equal(canonicalTipAdvanced(21, first, 20, first), false);
  assert.equal(canonicalTipAdvanced(21, first, 20, second), false);
  assert.equal(canonicalTipAdvanced(21, 'not-a-tip', 22, second), false);
});

test('cadence restart only reuses a live mempool with a surviving instance marker', () => {
  assert.equal(cadenceRestartCanReuseMempool(255, 255, 1), true);
  assert.equal(cadenceRestartCanReuseMempool(255, 256, 2), true);
  assert.equal(cadenceRestartCanReuseMempool('unknown', 255, 1), false);
  assert.equal(cadenceRestartCanReuseMempool(256, 255, 1), false);
  assert.equal(cadenceRestartCanReuseMempool(255, 255, 0), false);
});

test('Bitcoin cadence reports Stacks stalls without depending on them', () => {
  const miner = readFileSync(miningController, 'utf8');
  const compose = readFileSync(baseCompose, 'utf8');
  const chaos = readFileSync(chaosRunner, 'utf8');
  const verification = readFileSync(verifier, 'utf8');
  assert.match(miner, /observe_stacks_tip/);
  assert.match(miner, /Bitcoin mining continues/);
  assert.match(miner, /timeout "\$\{STACKS_RPC_TIMEOUT:-2\}"/);
  assert.doesNotMatch(miner, /Timed out waiting for Stacks progress/);
  assert.match(compose, /MINE_FAST_INTERVAL: \$\{MINE_FAST_INTERVAL:-5\}/);
  assert.match(compose, /MINE_INTERVAL: \$\{MINE_INTERVAL:-20\}/);
  assert.match(compose, /MINE_FAST_UNTIL_HEIGHT: 222/);
  assert.match(compose, /MINE_ENTROPY_ENABLED: \$\{MINE_ENTROPY_ENABLED:-true\}/);
  assert.match(compose, /MINE_ENTROPY_START_HEIGHT: 245/);
  assert.match(compose, /EPOCH_4_FIXTURE_DEPLOY_HEIGHT: 223/);
  assert.match(miner, /select_steady_state_delay/);
  assert.match(miner, /selected_cadence_delay=\$\(\(5 \+ RANDOM % 10\)\)/);
  assert.match(miner, /selected_cadence_delay=\$\(\(26 \+ RANDOM % 35\)\)/);
  assert.match(compose, /status.*stalled/);
  assert.doesNotMatch(chaos, /chaos-failover/);
  assert.match(chaos, /canonical_tip_advanced/);
  assert.match(chaos, /wait_for_chain_snapshot/);
  assert.match(chaos, /CHAOS_RPC_TIMEOUT_SECONDS/);
  assert.match(chaos, /cadence:flash/);
  assert.match(chaos, /cadence:slow/);
  assert.match(chaos, /kill -s USR1 bitcoin-miner/);
  assert.match(chaos, /kill -s USR2 bitcoin-miner/);
  assert.match(chaos, /CHAOS_COMPANION_OUTAGE_SECONDS:-90/);
  assert.match(chaos, /abstention_deadline/);
  assert.match(miner, /trap request_flash_block USR1/);
  assert.match(miner, /trap request_slow_block USR2/);
  assert.match(verification, /peerLimitFailures/);
  assert.match(verification, /signerRendezvousFailures/);
  assert.match(verification, /forwarded_gossip_signers/);
  assert.match(verification, /required_forwarded_signers/);
  assert.match(verification, /immediate !== original/);
  assert.match(verification, /stacks_p2p_rendezvous_connections/);
  assert.match(verification, /json_text peer_transport_mode/);
  assert.match(verification, /legacy_listener_enabled.*false/);
  assert.match(verification, /json_text signer_bridge_mode/);
  assert.doesNotMatch(verification, /Legacy P2P listener disabled/);
  assert.match(verification, /stacks_signer_block_validation_responses_total/);
  assert.match(verification, /VERIFY_PAUSE_FAILSAFE_SECONDS/);
  assert.match(verification, /backend_pause bitcoin-miner/);
  assert.match(verification, /runtime-backend\.sh" resume bitcoin-miner/);
});

test('maximum topology has unique paired identities and enrolled telemetry', () => {
  const topology = buildTopology({signerCount: 10, minerCount: 3, followerCount: 5});
  assert.equal(topology.actors.length, 28);
  assert.equal(new Set(topology.actors.map(actor => actor.id)).size, 28);
  assert.equal(new Set(topology.actors.map(actor => actor.transportPeerId)).size, 28);
  assert.equal(topology.actors.every(actor => /^[1-9A-HJ-NP-Za-km-z]{32,128}$/.test(actor.transportPeerId)), true);
  assert.equal(new Set(topology.signers.map(signer => signer[0])).size, 10);
  assert.equal(
    topology.signers[0][1],
    '035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46',
  );
  assert.equal(
    topology.signers[2][1],
    '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c',
  );
  for (let index = 1; index <= 10; index++) {
    const signer = topology.actors.find(actor => actor.id === `poc-signer-${index}`);
    assert.equal(signer?.companionActorId, `poc-signer-node-${index}`);
  }
});

test('topology limits fail closed', () => {
  assert.throws(() => buildTopology({signerCount: 11, minerCount: 1, followerCount: 1}), /signers/);
  assert.throws(() => buildTopology({signerCount: 1, minerCount: 4, followerCount: 1}), /miners/);
  assert.throws(() => buildTopology({signerCount: 1, minerCount: 1, followerCount: 6}), /followers/);
});

test('manifest inventory follows rendered topology cardinality', () => {
  const soak = readFileSync(soakRunner, 'utf8');
  assert.doesNotMatch(soak, /seq 1 10/);
  assert.match(soak, /manifest-inventory\.mjs/);

  for (const signerCount of [1, 4, 10]) {
    const topology = buildTopology({signerCount, minerCount: 2, followerCount: 1});
    const output = mkdtempSync(join(tmpdir(), `stacks-libp2p-inventory-${signerCount}-`));
    renderTopology(topology, output);
    const manifest = JSON.parse(readFileSync(join(output, 'manifest.json'), 'utf8'));
    const inventory = actorServiceInventory(manifest);
    assert.equal(inventory.signers.length, signerCount);
    assert.equal(inventory.companions.length, signerCount);
    assert.deepEqual(
      inventory.signers,
      manifest.actors.filter(actor => actor.type === 'signer').map(actor => actor.service),
    );
    assert.deepEqual(
      inventory.companions,
      manifest.actors.filter(actor => actor.role === 'companion').map(actor => actor.service),
    );
  }
});

test('manifest inventory rejects ambiguous actor services', () => {
  assert.throws(() => actorServiceInventory({
    actors: [
      {service: 'signer-1', type: 'signer', role: 'signer'},
      {service: 'signer-1', type: 'node', role: 'companion'},
    ],
  }), /duplicate topology actor service signer-1/);
});

test('rendered topology uses unique wallets, companions, tokens, and volumes', () => {
  const output = mkdtempSync(join(tmpdir(), 'stacks-libp2p-topology-'));
  const topology = buildTopology({signerCount: 4, minerCount: 3, followerCount: 2});
  renderTopology(topology, output);
  const compose = readFileSync(join(output, 'compose.yaml'), 'utf8');
  const collector = readFileSync(join(output, 'collector.yaml'), 'utf8');
  const environment = readFileSync(join(output, 'topology.env'), 'utf8');
  const manifest = JSON.parse(readFileSync(join(output, 'manifest.json'), 'utf8'));
  const signer = readFileSync(join(output, 'configs/signer-4.toml'), 'utf8');
  const miner = readFileSync(join(output, 'configs/miner-1.toml'), 'utf8');
  const secondaryMiner = readFileSync(join(output, 'configs/miner-2.toml'), 'utf8');
  const signerNode = readFileSync(join(output, 'configs/signer-node-4.toml'), 'utf8');
  assert.match(compose, /signer-node-4:/);
  assert.match(
    compose,
    /signer-4:[\s\S]*signer-node-4:\n\s+condition: service_started/,
  );
  assert.match(compose, /follower-2:/);
  assert.match(compose, /miner-2:[\s\S]*join-after-nakamoto\.sh/);
  assert.match(environment, /MINER_WALLETS=libp2p-poc-miner-1,libp2p-poc-miner-2,libp2p-poc-miner-3/);
  assert.match(signer, /rendezvous_peers = \["\/dns4\/miner-1\/tcp\/20445\/p2p\//);
  assert.match(signer, /"\/dns4\/miner-2\/tcp\/20445\/p2p\//);
  assert.match(signer, /"\/dns4\/miner-3\/tcp\/20445\/p2p\//);
  assert.doesNotMatch(signer, /rendezvous_peers = \[[^\n]*signer-node-4/);
  assert.match(signer, /block_proposal_validation_timeout_ms = 15000/);
  assert.match(signer, /\[libp2p\.limits\][\s\S]*max_established_total = 16/);
  assert.match(signer, /\[libp2p\.limits\][\s\S]*max_connections_per_prefix = 16/);
  assert.match(signer, /\[libp2p\.limits\][\s\S]*peer_store_startup_dials = 8/);
  assert.match(signerNode, /\[node\.libp2p\.limits\][\s\S]*max_established_total = 12/);
  assert.match(
    signerNode,
    /\[\[events_observer\]\]\nendpoint = "signer-4:30000"\nevents_keys = \["stackerdb", "block_proposal", "burn_blocks"\]/,
  );
  assert.doesNotMatch(miner, /\[\[events_observer\]\]/);
  assert.doesNotMatch(secondaryMiner, /\[\[events_observer\]\]/);
  assert.match(secondaryMiner, /\[node\.libp2p\.limits\][\s\S]*max_established_total = 32/);
  assert.match(miner, /\[node\.libp2p\.limits\][\s\S]*max_established_total = 64/);
  assert.match(miner, /block_commit_delay_ms = 1000/);
  assert.deepEqual(manifest.connectionLimits, {actor: 12, signer: 16, miner: 32, bootstrap: 64});
  assert.match(collector, /stacks_p2p_connected_peer/);
  assert.match(collector, /attributes\["peer_id"\].*\[1-9A-HJ-NP-Za-km-z\]\{32,128\}/);
  assert.equal(miner.match(/amount = 10000000000000000/g)?.length, 4);
  for (const actor of topology.actors) {
    assert.match(collector, new RegExp(`bearertokenauth/${actor.id}`));
    assert.match(compose, new RegExp(`telemetry-${actor.service}:`));
  }
});
