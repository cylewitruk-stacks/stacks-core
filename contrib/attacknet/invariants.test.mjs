import assert from 'node:assert/strict';
import test from 'node:test';

import {heightCohort, networkCohort, peerConnectivity, progress, telemetryCoverage} from './invariants.mjs';

test('height cohort accepts bounded lag and reports both dimensions', () => {
  const result = heightCohort([
    {actor: 'miner-1', info: {burn_block_height: 250, stacks_tip_height: 10, stacks_tip: 'a'}},
    {actor: 'follower-1', info: {burn_block_height: 249, stacks_tip_height: 9, stacks_tip: 'b'}},
  ], 2);
  assert.equal(result.ok, true);
  assert.equal(result.burnDrift, 1);
  assert.equal(result.stacksDrift, 1);
});

test('height cohort fails rather than hiding excessive drift', () => {
  assert.equal(heightCohort([
    {actor: 'miner-1', info: {burn_block_height: 250, stacks_tip_height: 10}},
    {actor: 'follower-1', info: {burn_block_height: 246, stacks_tip_height: 7}},
  ], 2).ok, false);
});

const progressSample = height => [{actor: 'miner-1', info: {stacks_tip_height: height}}];

test('progress requires configured burn and Stacks deltas', () => {
  assert.equal(progress(
    {burnHeight: 20, cohort: progressSample(5)},
    {burnHeight: 22, cohort: progressSample(7)},
    2,
    2,
  ).ok, true);
  assert.equal(progress(
    {burnHeight: 20, cohort: progressSample(5)},
    {burnHeight: 21, cohort: progressSample(7)},
    2,
    2,
  ).ok, false);
});

test('Bitcoin-only movement cannot pass the chain progress invariant', () => {
  const result = progress(
    {burnHeight: 230, cohort: progressSample(17)},
    {burnHeight: 256, cohort: progressSample(17)},
  );
  assert.equal(result.ok, false);
  assert.equal(result.burn.delta, 26);
  assert.equal(result.stacks.delta, 0);
});

test('height cohort can require actual Stacks progress', () => {
  const samples = [
    {actor: 'a', info: {burn_block_height: 203, stacks_tip_height: 0, stacks_tip: '00'}},
    {actor: 'b', info: {burn_block_height: 203, stacks_tip_height: 0, stacks_tip: '00'}},
  ];
  assert.equal(heightCohort(samples, 2, 0).ok, true);
  const result = heightCohort(samples, 2, 1);
  assert.equal(result.ok, false);
  assert.equal(result.minimumObservedStacksHeight, 0);
});

test('same-height forks fail even when all height gauges agree', () => {
  const result = heightCohort([
    {actor: 'a', info: {burn_block_height: 250, stacks_tip_height: 9, stacks_tip: 'fork-a'}},
    {actor: 'b', info: {burn_block_height: 250, stacks_tip_height: 9, stacks_tip: 'fork-b'}},
  ], 0, 1);
  assert.equal(result.ok, false);
  assert.deepEqual(result.forkedHeights, [{height: 9, tips: ['fork-a', 'fork-b']}]);
});

test('peer health counts only live authenticated conversations', () => {
  const healthy = {actor: 'a', neighbors: {
    bootstrap: [{authenticated: true}], sample: [],
    inbound: [{authenticated: true}], outbound: [],
  }};
  const configuredOnly = {actor: 'b', neighbors: {
    bootstrap: [{authenticated: true}], sample: [{authenticated: true}], inbound: [], outbound: [],
  }};
  assert.equal(peerConnectivity([healthy]).ok, true);
  const result = peerConnectivity([healthy, configuredOnly]);
  assert.equal(result.ok, false);
  assert.equal(result.rows[1].configuredCandidates, 2);
  assert.equal(result.rows[1].authenticated, 0);
});

test('a transient unauthenticated handshake is evidence, not a baseline failure', () => {
  const result = peerConnectivity([{actor: 'a', neighbors: {
    bootstrap: [], sample: [],
    inbound: [{authenticated: true}, {authenticated: false}], outbound: [],
  }}]);
  assert.equal(result.ok, true);
  assert.equal(result.minimumAuthenticatedConnections, 1);
  assert.equal(result.maximumUnauthenticatedConnections, 1);
});

test('network cohort requires height, tip, and live-peer agreement together', () => {
  const sample = actor => ({
    actor,
    info: {burn_block_height: 250, stacks_tip_height: 9, stacks_tip: 'canonical'},
    neighbors: {bootstrap: [], sample: [], inbound: [{authenticated: true}], outbound: []},
  });
  assert.equal(networkCohort([sample('a'), sample('b')], 0, 1).ok, true);
});

const telemetryManifest = {actors: [
  {service: 'miner-1', role: 'miner'},
  {service: 'signer-1', role: 'signer'},
]};
const telemetryResponse = rows => ({status: 'success', data: {resultType: 'vector', result: rows}});
const up = (actor, role, value = '1', timestamp = 100) => ({
  metric: {attacknet_actor: actor, attacknet_role: role}, value: [timestamp, value],
});

test('telemetry coverage requires one fresh healthy series per manifest actor', () => {
  const result = telemetryCoverage(telemetryResponse([
    up('miner-1', 'miner'), up('signer-1', 'signer'),
  ]), telemetryManifest, 110, 15);
  assert.equal(result.ok, true);
  assert.equal(result.expectedActors, 2);
  assert.equal(result.observedUniqueActors, 2);
});

test('telemetry coverage reason-codes missing, down, stale, role, duplicate, and unexpected series', () => {
  const result = telemetryCoverage(telemetryResponse([
    up('miner-1', 'follower', '0', 80), up('miner-1', 'miner', '1', 100),
    up('outsider', 'follower'),
  ]), telemetryManifest, 110, 15);
  assert.equal(result.ok, false);
  assert.deepEqual(result.rows[0].reasons, ['duplicate-series']);
  assert.deepEqual(result.rows[1].reasons, ['missing-series']);
  assert.deepEqual(result.unexpectedActors, ['outsider']);
});

test('telemetry coverage reports each single-series failure without accepting partial health', () => {
  const down = telemetryCoverage(telemetryResponse([
    up('miner-1', 'miner', '0', 100), up('signer-1', 'wrong', '1', 80),
  ]), telemetryManifest, 110, 15);
  assert.deepEqual(down.rows[0].reasons, ['scrape-down']);
  assert.deepEqual(down.rows[1].reasons, ['role-mismatch', 'stale-sample']);
});
