import assert from 'node:assert/strict';
import test from 'node:test';

import {evaluatePodHealth} from './soak-observation.mjs';

function pod(name, actor, ready = true) {
  return {
    metadata: {name, uid: `uid-${name}`, labels: actor ? {'testing.stacks.org/actor': actor} : {}},
    spec: {nodeName: 'worker-1'},
    status: {
      phase: ready ? 'Running' : 'Pending',
      conditions: [{type: 'Ready', status: ready ? 'True' : 'False'}],
      containerStatuses: [{restartCount: 0}],
    },
  };
}

test('allows only the explicit target of an active campaign to be temporarily unready', () => {
  const result = evaluatePodHealth({items: [pod('target', 'follower-1', false), pod('other', 'miner-1')]}, {
    items: [{metadata: {name: 'fault'}, spec: {target: {actors: ['follower-1']}}, status: {phase: 'Active'}}],
  });
  assert.equal(result.ok, true);
  assert.equal(result.unready[0].expectedDisruption, true);
});

test('fails unexplained actor and infrastructure unready states', () => {
  const result = evaluatePodHealth({items: [
    pod('other', 'miner-1', false), pod('prometheus', null, false),
  ]}, {items: []});
  assert.equal(result.ok, false);
  assert.deepEqual(result.unexplained.map(row => row.pod), ['other', 'prometheus']);
});

test('does not excuse a target after its campaign is terminal', () => {
  const result = evaluatePodHealth({items: [pod('target', 'follower-1', false)]}, {
    items: [{spec: {target: {actors: ['follower-1']}}, status: {phase: 'Passed'}}],
  });
  assert.equal(result.ok, false);
});

test('detects a missing baseline Pod and excuses only an active target', () => {
  const baseline = {items: [pod('target', 'follower-1'), pod('prometheus', null)]};
  const active = {items: [{
    metadata: {name: 'fault'}, spec: {target: {actors: ['follower-1']}}, status: {phase: 'Active'},
  }]};
  const result = evaluatePodHealth({items: []}, active, baseline);
  assert.equal(result.ok, false);
  assert.equal(result.unready.find(row => row.pod === 'target').expectedDisruption, true);
  assert.equal(result.unready.find(row => row.pod === 'prometheus').expectedDisruption, false);
});
