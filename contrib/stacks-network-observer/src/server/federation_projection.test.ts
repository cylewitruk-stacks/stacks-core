import assert from 'node:assert/strict';
import test from 'node:test';

import {ChainProgressTracker, projectFederation} from './federation_projection.js';
import type {PublicNetworkState} from '../shared/model.js';
import type { PrometheusSample } from './prometheus.js';

const now = 1_800_000_000_000;

test('projects independent token-bound actors and exposes missing coverage', () => {
  const snapshot = projectFederation([
    sample('stacks_node_burn_block_height', 'poc-miner', 'miner', 310, now),
    sample('stacks_node_stacks_tip_height', 'poc-miner', 'miner', 102, now),
    sample('stacks_p2p_connections', 'poc-miner', 'miner', 4, now),
  ], [
    { id: 'poc-miner', label: 'Miner', role: 'miner' },
    { id: 'poc-signer-1', label: 'Signer 1', role: 'signer' },
  ], now);
  assert.equal(snapshot.summary.burnHeight, 310);
  assert.equal(snapshot.summary.reportingNodes, 1);
  assert.equal(snapshot.nodes.find(node => node.id === 'poc-miner')?.inboundPeers, 4);
  assert.equal(snapshot.incidents[0]?.kind, 'telemetry-blind-spot');
});

test('stale receipt time cannot report healthy coverage', () => {
  const snapshot = projectFederation([
    sample('stacks_node_burn_block_height', 'poc-miner', 'miner', 310, now - 21_000),
  ], [{ id: 'poc-miner', label: 'Miner', role: 'miner' }], now);
  assert.equal(snapshot.summary.health, 'critical');
  assert.equal(snapshot.reporters[0]?.health, 'critical');
});

test('preserves label variants and projects signer self-observation without identities', () => {
  const blocked = sample('stacks_observability_blocked_on', 'poc-signer-1', 'signer', 1, now);
  blocked.metric.reason = 'local_node_rpc';
  const idle = sample('stacks_observability_blocked_on', 'poc-signer-1', 'signer', 0, now);
  idle.metric.reason = 'none';
  const accepted = sample('stacks_signer_block_responses_sent_total', 'poc-signer-1', 'signer', 7, now);
  accepted.metric.response_type = 'accepted';
  const rejected = sample('stacks_signer_block_responses_sent_total', 'poc-signer-1', 'signer', 2, now);
  rejected.metric.response_type = 'rejected';
  const snapshot = projectFederation([blocked, idle, accepted, rejected], [
    { id: 'poc-signer-1', label: 'Signer 1', role: 'signer' },
  ], now);
  assert.equal(snapshot.nodes[0]?.blockedOn, 'local_node_rpc');
  assert.equal(snapshot.nodes[0]?.signerResponses, 9);
  assert.equal(snapshot.nodes[0]?.health, 'degraded');
  assert.match(snapshot.incidents[0]?.evidence[0] ?? '', /local_node_rpc/);
});

test('raises a critical incident when a signer state persistently trails its enrolled companion', () => {
  const stateChanged = sample(
    'stacks_signer_state_last_changed_timestamp_seconds',
    'poc-signer-1',
    'signer',
    (now - 60_000) / 1_000,
    now,
  );
  const snapshot = projectFederation([
    sample('stacks_signer_state_burn_block_height', 'poc-signer-1', 'signer', 225, now),
    stateChanged,
    sample('stacks_node_burn_block_height', 'poc-companion-1', 'companion', 234, now),
  ], [
    {id: 'poc-companion-1', label: 'Companion 1', role: 'companion'},
    {
      id: 'poc-signer-1',
      label: 'Signer 1',
      role: 'signer',
      signerPublicKey: '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c',
      companionActorId: 'poc-companion-1',
    },
  ], now, {
    expectedBurnCadenceSeconds: 10,
    publicNetwork: publicState(),
  });

  const incident = snapshot.incidents.find(item => item.id === 'signer-companion-drift-poc-signer-1');
  assert.equal(snapshot.nodes.find(node => node.id === 'poc-signer-1')?.companionActorId, 'poc-companion-1');
  assert.equal(incident?.severity, 'critical');
  assert.equal(incident?.kind, 'sync');
  assert.match(incident?.evidence[0] ?? '', /trails companion.*by 9 blocks/);
  assert.equal(snapshot.summary.health, 'critical');
});

test('allows bounded or freshly changing signer-companion burn drift', () => {
  const snapshot = projectFederation([
    sample('stacks_signer_state_burn_block_height', 'poc-signer-1', 'signer', 231, now),
    sample(
      'stacks_signer_state_last_changed_timestamp_seconds',
      'poc-signer-1',
      'signer',
      (now - 5_000) / 1_000,
      now,
    ),
    sample('stacks_node_burn_block_height', 'poc-companion-1', 'companion', 234, now),
  ], [
    {id: 'poc-companion-1', label: 'Companion 1', role: 'companion'},
    {
      id: 'poc-signer-1',
      label: 'Signer 1',
      role: 'signer',
      signerPublicKey: '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c',
      companionActorId: 'poc-companion-1',
    },
  ], now, {expectedBurnCadenceSeconds: 10, publicNetwork: publicState()});

  assert.equal(snapshot.incidents.some(item => item.id.startsWith('signer-companion-drift-')), false);
});

test('joins public signer identity to authenticated state and endpoint-free links', () => {
  const key = '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c';
  const link = sample('stacks_p2p_authenticated_signer_link', 'poc-miner', 'miner', 1, now);
  link.metric.signer_public_key = key;
  const rendezvous = sample('stacks_p2p_rendezvous_connections', 'poc-signer-1', 'signer', 1, now);
  const lifecycle = sample('stacks_signer_local_state', 'poc-signer-1', 'signer', 1, now);
  lifecycle.metric.state = 'initialized';
  const minerState = sample('stacks_signer_miner_state', 'poc-signer-1', 'signer', 1, now);
  minerState.metric.state = 'active_miner';
  const snapshot = projectFederation([link, rendezvous, lifecycle, minerState], [
    {id: 'poc-miner', label: 'Miner', role: 'miner'},
    {id: 'poc-signer-1', label: 'Signer 1', role: 'signer', signerPublicKey: key, entityName: 'Example signer'},
  ], now, {publicNetwork: publicState(key)});
  const signer = snapshot.nodes.find(node => node.id === 'poc-signer-1');
  assert.equal(signer?.signerPublicKey, key);
  assert.equal(signer?.signerEntityName, 'Example signer');
  assert.equal(signer?.signerWeight, 15);
  assert.equal(signer?.signerState?.lifecycle, 'initialized');
  assert.equal(signer?.signerState?.minerState, 'active_miner');
  assert.equal(signer?.inboundPeers, null, 'an absent peer gauge must remain unknown');
  assert.equal(snapshot.links.length, 1);
  assert.equal(snapshot.links[0]?.corroborated, false);
  assert.deepEqual(snapshot.links[0]?.reportedBy, ['poc-miner']);
  assert.deepEqual(snapshot.links[0]?.evidence, ['authenticated-signer-envelope']);
});

test('joins corroborated transport links across every enrolled actor role', () => {
  const companionPeer = '16Uiu2HAkxh98QxUjCcFzVXtyDvcWZGZmBSgPS3S6Wn4XiuHzam3y';
  const signerPeer = '16Uiu2HAm7K2fEAn5W93hqHt3qhjMKTdDCDDPfyykqEcrgNNBAoqn';
  const companionReport = sample('stacks_p2p_connected_peer', 'poc-companion-1', 'companion', 1, now);
  companionReport.metric.peer_id = signerPeer;
  const signerReport = sample('stacks_p2p_connected_peer', 'poc-signer-1', 'signer', 1, now);
  signerReport.metric.peer_id = companionPeer;
  const snapshot = projectFederation([companionReport, signerReport], [
    {id: 'poc-companion-1', label: 'Companion 1', role: 'companion', transportPeerId: companionPeer},
    {
      id: 'poc-signer-1',
      label: 'Signer 1',
      role: 'signer',
      signerPublicKey: '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c',
      transportPeerId: signerPeer,
      companionActorId: 'poc-companion-1',
    },
  ], now, {publicNetwork: publicState()});

  assert.equal(snapshot.links.length, 1);
  assert.equal(snapshot.links[0]?.corroborated, true);
  assert.deepEqual(snapshot.links[0]?.reportedBy, ['poc-companion-1', 'poc-signer-1']);
  assert.deepEqual(snapshot.links[0]?.evidence, ['enrolled-transport-peer']);
  assert.doesNotMatch(JSON.stringify(snapshot), /16Uiu/);
});

test('reconstructs one bounded quorum round only for enrolled public signers', () => {
  const key = '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c';
  const status = sample('stacks_miner_signer_round_status', 'poc-miner', 'miner', 1, now);
  status.metric.status = 'approved';
  const weight = sample('stacks_miner_signer_vote_weight', 'poc-miner', 'miner', 15, now);
  weight.metric.signer_public_key = key;
  weight.metric.decision = 'approved';
  const latency = sample('stacks_miner_signer_vote_latency_seconds', 'poc-miner', 'miner', 0.42, now);
  latency.metric.signer_public_key = key;
  latency.metric.decision = 'approved';
  const snapshot = projectFederation([
    status,
    sample('stacks_miner_signer_round_block_height', 'poc-miner', 'miner', 103, now),
    sample('stacks_miner_signer_round_started_timestamp_seconds', 'poc-miner', 'miner', now / 1_000 - 2, now),
    sample('stacks_miner_signer_round_threshold_weight', 'poc-miner', 'miner', 11, now),
    sample('stacks_miner_signer_round_total_weight', 'poc-miner', 'miner', 15, now),
    sample('stacks_miner_signer_round_approved_weight', 'poc-miner', 'miner', 15, now),
    sample('stacks_miner_signer_round_rejected_weight', 'poc-miner', 'miner', 0, now),
    sample('stacks_miner_signer_round_unavailable_weight', 'poc-miner', 'miner', 0, now),
    weight,
    latency,
  ], [
    {id: 'poc-miner', label: 'Miner', role: 'miner'},
    {id: 'poc-signer-1', label: 'Signer 1', role: 'signer', signerPublicKey: key, entityName: 'Example signer'},
    {
      id: 'poc-signer-not-public',
      label: 'Unjoined signer',
      role: 'signer',
      signerPublicKey: '031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380',
    },
  ], now, {publicNetwork: publicState(key)});

  assert.equal(snapshot.signerQuorumRounds.length, 1);
  assert.deepEqual(snapshot.signerQuorumRounds[0], {
    minerActorId: 'poc-miner',
    minerLabel: 'Miner',
    blockHeight: 103,
    startedAt: new Date(now - 2_000).toISOString(),
    observedAt: new Date(now).toISOString(),
    status: 'approved',
    thresholdWeight: 11,
    totalWeight: 15,
    approvedWeight: 15,
    rejectedWeight: 0,
    unavailableWeight: 0,
    votes: [{
      signerPublicKey: key,
      entityName: 'Example signer',
      weight: 15,
      decision: 'approved',
      latencyMs: 420,
    }],
    source: 'authenticated-miner-telemetry',
  });
});

test('orders bounded quorum rounds by chain recency rather than enrollment order', () => {
  const minerOne = sample('stacks_miner_signer_round_status', 'poc-miner-1', 'miner', 1, now);
  minerOne.metric.status = 'approved';
  const minerTwo = sample('stacks_miner_signer_round_status', 'poc-miner-2', 'miner', 1, now);
  minerTwo.metric.status = 'collecting';
  const roundMetrics = (actorId: string, role: string, blockHeight: number, startedAt: number) => [
    sample('stacks_miner_signer_round_block_height', actorId, role, blockHeight, now),
    sample('stacks_miner_signer_round_started_timestamp_seconds', actorId, role, startedAt, now),
    sample('stacks_miner_signer_round_threshold_weight', actorId, role, 11, now),
    sample('stacks_miner_signer_round_total_weight', actorId, role, 15, now),
    sample('stacks_miner_signer_round_approved_weight', actorId, role, 0, now),
    sample('stacks_miner_signer_round_rejected_weight', actorId, role, 0, now),
    sample('stacks_miner_signer_round_unavailable_weight', actorId, role, 0, now),
  ];
  const snapshot = projectFederation([
    minerOne,
    ...roundMetrics('poc-miner-1', 'miner', 100, now / 1_000 - 5),
    minerTwo,
    ...roundMetrics('poc-miner-2', 'miner', 102, now / 1_000 - 1),
  ], [
    {id: 'poc-miner-1', label: 'Miner 1', role: 'miner'},
    {id: 'poc-miner-2', label: 'Miner 2', role: 'miner'},
  ], now, {publicNetwork: publicState()});

  assert.deepEqual(
    snapshot.signerQuorumRounds.map(round => [round.minerActorId, round.blockHeight]),
    [['poc-miner-2', 102], ['poc-miner-1', 100]],
  );
});

test('classifies fresh telemetry with frozen chain progress as a critical stall', () => {
  const tracker = new ChainProgressTracker();
  const samples = [
    sample('stacks_node_burn_block_height', 'poc-miner', 'miner', 496, now),
    sample('stacks_node_stacks_tip_height', 'poc-miner', 'miner', 288, now),
  ];
  tracker.observe(samples, now);
  const progress = tracker.observe(samples.map(item => ({...item, value: [(now + 41_000) / 1_000, item.value[1]]})), now + 41_000);
  const snapshot = projectFederation(samples.map(item => ({...item, value: [(now + 41_000) / 1_000, item.value[1]]})), [
    {id: 'poc-miner', label: 'Miner', role: 'miner'},
  ], now + 41_000, {progress, expectedBurnCadenceSeconds: 10, publicNetwork: publicState()});
  assert.equal(snapshot.summary.health, 'critical');
  assert.equal(snapshot.summary.stall, 'burnchain');
  assert.match(snapshot.incidents.find(item => item.id === 'burnchain-progress')?.evidence[0] ?? '', /41s/);
});

test('honors node-reported change time on the first observation', () => {
  const tracker = new ChainProgressTracker();
  const burnHeight = sample('stacks_node_burn_block_height', 'poc-miner', 'miner', 496, now);
  const burnChanged = sample(
    'stacks_node_burn_block_last_changed_timestamp_seconds',
    'poc-miner',
    'miner',
    (now - 45_000) / 1_000,
    now,
  );
  const stacksHeight = sample('stacks_node_stacks_tip_height', 'poc-miner', 'miner', 288, now);
  const stacksChanged = sample(
    'stacks_node_stacks_tip_last_changed_timestamp_seconds',
    'poc-miner',
    'miner',
    (now - 75_000) / 1_000,
    now,
  );

  assert.deepEqual(tracker.observe([burnHeight, burnChanged, stacksHeight, stacksChanged], now), {
    burnAgeSeconds: 45,
    stacksAgeSeconds: 75,
  });
});

test('projects equal-height tip adoption spread without a peer or block identity', () => {
  const minerHeight = sample('stacks_node_stacks_tip_height', 'poc-miner', 'miner', 288, now);
  const minerChanged = sample('stacks_node_stacks_tip_last_changed_timestamp_seconds', 'poc-miner', 'miner', (now - 1_200) / 1_000, now);
  const followerHeight = sample('stacks_node_stacks_tip_height', 'poc-follower', 'follower', 288, now);
  const followerChanged = sample('stacks_node_stacks_tip_last_changed_timestamp_seconds', 'poc-follower', 'follower', now / 1_000, now);
  const snapshot = projectFederation([minerHeight, minerChanged, followerHeight, followerChanged], [
    {id: 'poc-miner', label: 'Miner', role: 'miner'},
    {id: 'poc-follower', label: 'Follower', role: 'follower'},
  ], now, {publicNetwork: publicState()});

  assert.equal(snapshot.propagation.length, 1);
  assert.equal(snapshot.propagation[0]?.objectId, 'height-288');
  assert.equal(snapshot.propagation[0]?.p95Ms, 1_200);
  assert.equal(snapshot.propagation[0]?.coverage, 1);
  assert.equal(snapshot.propagation[0]?.hops[1]?.source, 'tip-observation');
  assert.equal(snapshot.propagation[0]?.publicBlockId, undefined);
});

test('treats a single leading node as propagation while the largest height cohort remains healthy', () => {
  const expected = Array.from({length: 10}, (_, index) => ({
    id: `poc-node-${index + 1}`,
    label: `Node ${index + 1}`,
    role: 'follower' as const,
  }));
  const samples = expected.flatMap((actor, index) => [
    sample('stacks_node_stacks_tip_height', actor.id, actor.role, index === 0 ? 289 : 288, now),
    sample('stacks_node_stacks_tip_last_changed_timestamp_seconds', actor.id, actor.role, now / 1_000, now),
  ]);
  const snapshot = projectFederation(samples, expected, now, {publicNetwork: publicState()});

  assert.equal(snapshot.summary.stacksHeight, 289);
  assert.equal(snapshot.summary.heightAgreement, 0.9);
  assert.equal(snapshot.propagation[0]?.objectId, 'height-289');
  assert.equal(snapshot.propagation[0]?.coverage, 0.1);
});

test('projects every bounded actor metric and aggregates signer histograms', () => {
  const event = sample('stacks_p2p_events_total', 'poc-miner', 'miner', 7, now);
  event.metric.event = 'announcement_received';
  const count = sample('stacks_signer_block_response_latencies_histogram_count', 'poc-signer-1', 'signer', 10, now);
  const sum = sample('stacks_signer_block_response_latencies_histogram_sum', 'poc-signer-1', 'signer', 4, now);
  const low = sample('stacks_signer_block_response_latencies_histogram_bucket', 'poc-signer-1', 'signer', 8, now);
  low.metric.le = '0.5';
  const high = sample('stacks_signer_block_response_latencies_histogram_bucket', 'poc-signer-1', 'signer', 10, now);
  high.metric.le = '1';
  const observed = sample('stacks_signer_stacks_node_height_last_observed_timestamp_seconds', 'poc-signer-1', 'signer', now / 1_000 - 3, now);
  const released = sample('stacks_signer_deferred_miner_authorizations_resolved_total', 'poc-signer-1', 'signer', 2, now);
  released.metric.resolution = 'released';
  const policyRejected = sample('stacks_signer_block_policy_rejections_total', 'poc-signer-1', 'signer', 4, now);
  policyRejected.metric.reject_code = '4';
  const snapshot = projectFederation([
    sample('stacks_p2p_object_cache_bytes', 'poc-miner', 'miner', 4096, now),
    event,
    sample('stacks_signer_stacks_node_height', 'poc-signer-1', 'signer', 287, now),
    observed,
    released,
    policyRejected,
    count,
    sum,
    low,
    high,
  ], [
    {id: 'poc-miner', label: 'Miner', role: 'miner'},
    {id: 'poc-signer-1', label: 'Signer', role: 'signer'},
  ], now, {publicNetwork: publicState()});

  const miner = snapshot.actorMetrics.find(actor => actor.actorId === 'poc-miner');
  assert.equal(miner?.readings.find(reading => reading.name === 'stacks_p2p_object_cache_bytes')?.value, 4096);
  assert.deepEqual(miner?.readings.find(reading => reading.name === 'stacks_p2p_events_total')?.attributes, [
    {key: 'event', value: 'announcement_received'},
  ]);
  const signer = snapshot.actorMetrics.find(actor => actor.actorId === 'poc-signer-1');
  assert.equal(signer?.readings.find(reading => reading.name.endsWith('_mean'))?.value, 0.4);
  assert.equal(signer?.readings.find(reading => reading.name.endsWith('_p95'))?.value, 1);
  assert.deepEqual(signer?.readings.find(reading => reading.name ===
    'stacks_signer_deferred_miner_authorizations_resolved_total')?.attributes, [
    {key: 'resolution', value: 'released'},
  ]);
  assert.deepEqual(signer?.readings.find(reading => reading.name ===
    'stacks_signer_block_policy_rejections_total')?.attributes, [
    {key: 'reject_code', value: '4'},
  ]);
  assert.equal(snapshot.nodes.find(node => node.id === 'poc-signer-1')?.stacksTipObservedAt,
    new Date(now - 3_000).toISOString());
  assert.equal(signer?.readings.some(reading => reading.name.endsWith('_bucket')), false,
    'raw histogram buckets must be aggregated rather than exposed as an unbounded table');
});

function sample(name: string, actor: string, role: string, value: number, at: number): PrometheusSample {
  return {
    metric: {
      __name__: name,
      stacks_federation_actor_id: actor,
      stacks_actor_role: role,
    },
    value: [at / 1_000, String(value)] as [number, string],
  };
}

function publicState(key?: string): PublicNetworkState {
  return {
    source: 'http://public-node',
    health: 'healthy',
    observedAt: new Date(now).toISOString(),
    currentEpoch: 'Epoch40',
    burnHeight: 496,
    currentRewardCycle: 24,
    nextRewardCycle: 25,
    rewardCycles: [{id: 24, phase: 'current', status: 'available', totalWeight: key ? 15 : 0, totalStackedMicroStx: key ? '300000000000' : '0', signerKeys: key ? [key] : []}],
    signers: key ? [{publicKey: key, entityName: null, weight: 15, stackedAmountMicroStx: '300000000000', rewardCycles: [24], enrolledActorId: null}] : [],
    error: null,
  };
}
