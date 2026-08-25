import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyTerminalAssertion, networkManifest, resolvedNetworkImages,
} from './kubernetes-runtime-contracts.mjs';

const digest = value => `sha256:${value.repeat(64)}`;

test('runtime contracts validate signer ownership and admitted images', () => {
  const network = {
    metadata: {name: 'demo', namespace: 'test', uid: 'network-uid'},
    spec: {actors: [
      {name: 'miner-1', role: 'miner', image: 'stacks:test'},
      {name: 'signer-1', role: 'signer', image: 'signer:test', signerIndex: 1,
        signerWeight: 100, signerPublicKey: `02${'1'.repeat(64)}`},
    ]},
  };
  assert.equal(networkManifest(network).actors[1].signerWeight, 100);
  const pods = {items: network.spec.actors.map((actor, index) => ({
    metadata: {name: `demo-${actor.name}-0`, labels: {
      'testing.stacks.org/network': 'demo', 'testing.stacks.org/actor': actor.name,
    }},
    status: {phase: 'Running', conditions: [{type: 'Ready', status: 'True'}],
      containerStatuses: [{name: 'actor', ready: true, imageID: `containerd://${digest(index ? 'b' : 'a')}`}]},
  }))};
  assert.deepEqual(resolvedNetworkImages(network, pods).map(item => item.scope), ['miner-1', 'signer-1']);
});

test('runtime manifest rejects every partial signer declaration', () => {
  for (const actor of [
    {name: 'signer-1', role: 'signer'},
    {name: 'node-1', role: 'follower', signerWeight: 10},
    {name: 'node-1', role: 'follower', signerPublicKey: `02${'1'.repeat(64)}`},
  ]) {
    assert.throws(() => networkManifest({
      metadata: {name: 'demo', namespace: 'test', uid: 'network-uid'}, spec: {actors: [actor]},
    }), /incomplete authoritative signer identity/);
  }
});

test('terminal classifier is bounded and detects conflicting evidence', () => {
  const run = {metadata: {name: 'attempt', uid: 'run-uid'}, spec: {minimization: {
    enabled: true, attemptId: 'one', candidateScheduleDigest: digest('c'),
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed',
  }}};
  const children = [{metadata: {name: 'b', uid: 'b'}, status: {
    phase: 'Passed', effectResults: [{assertion: 'TargetReady', outcome: 'Failed'}],
  }}, {metadata: {name: 'a', uid: 'a'}, status: {
    phase: 'Passed', recoveryResults: [{assertion: 'TargetReady', outcome: 'Proven'}],
  }}];
  const result = classifyTerminalAssertion(run, children, digest('d'));
  assert.equal(result.outcome, 'Inconclusive');
  assert.equal(result.reason, 'ConflictingExpectedAssertionEvidence');
  assert.equal(result.observationCount, 2);
  assert.match(result.evidenceDigest, /^sha256:[0-9a-f]{64}$/);
});

test('terminal classifier derives observation provenance from owned children', () => {
  const run = {metadata: {name: 'attempt', uid: 'run-uid'}, spec: {minimization: {
    enabled: true, attemptId: 'one', candidateScheduleDigest: digest('c'),
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed',
  }}};
  const children = [{metadata: {name: 'owned-child', uid: 'child-uid'}, status: {
    phase: 'Passed', effectResults: [{
      assertion: 'TargetReady', outcome: 'Failed', child: 'forged-child', source: 'recovery',
    }],
  }}];
  const result = classifyTerminalAssertion(run, children, digest('d'));
  assert.equal(result.outcome, 'FailureReproduced');
  assert.deepEqual(result.observations, [{child: 'owned-child', source: 'effect', outcome: 'Failed'}]);
});
