import assert from 'node:assert/strict';
import test from 'node:test';
import {EventEmitter} from 'node:events';

import {
  ProbeClient, baselineUsable, buildProbeRequest, controlTarget, probePhase,
} from './probe-client.mjs';

const network = {
  metadata: {name: 'attacknet', namespace: 'hacknet'},
  spec: {actors: [
    {name: 'miner-1', role: 'miner', ports: [{name: 'p2p', containerPort: 20444}]},
    {name: 'signer-node-1', role: 'companion', ports: [{name: 'p2p', containerPort: 20444}]},
    {name: 'follower-1', role: 'follower', ports: [{name: 'p2p', containerPort: 20444}]},
  ]},
};

const campaign = (type, parameters = {}) => ({
  metadata: {name: 'fault-a'}, spec: {fault: {type, parameters}},
});

test('plans only enrolled named network and DNS peers', () => {
  const target = {actor: 'miner-1'};
  assert.deepEqual(buildProbeRequest({
    kind: 'NetworkChaos', campaign: campaign('network'), compiledEvidence: {}, network, target,
  }), {kind: 'network', peer: 'follower-1', port: 'p2p', attempts: 5, timeoutMs: 2000});
  assert.deepEqual(buildProbeRequest({
    kind: 'NetworkChaos', campaign: campaign('network'),
    compiledEvidence: {peerSelectedActors: ['attacknet-prometheus']}, network, target,
  }), {kind: 'network', peer: 'attacknet-prometheus', port: 'http', attempts: 5, timeoutMs: 2000});
  assert.deepEqual(buildProbeRequest({
    kind: 'DNSChaos', campaign: campaign('dns', {patterns: ['attacknet-signer-node-1.hacknet.svc.cluster.local']}),
    compiledEvidence: {}, network, target,
  }), {kind: 'dns', peer: 'signer-node-1'});
  assert.deepEqual(buildProbeRequest({
    kind: 'TimeChaos', campaign: campaign('time'), compiledEvidence: {}, network,
    target: {actor: 'follower-1'},
  }), {
    kind: 'processClock', peer: 'follower-1', port: 'metrics',
    metric: 'stacks_node_process_wall_clock_seconds', control: false,
  });
  assert.deepEqual(buildProbeRequest({
    kind: 'IOPressurePod', campaign: campaign('io-pressure'), compiledEvidence: {}, network,
    target: {actor: 'follower-1'},
  }), {kind: 'io', operation: 'FSYNC', attempts: 5, bytes: 4096, file: 'fault-a.dat'});
  assert.throws(() => buildProbeRequest({
    kind: 'DNSChaos', campaign: campaign('dns', {patterns: ['outside.example']}),
    compiledEvidence: {}, network, target,
  }), /no enrolled service name matches/);
});

test('chooses an independent ready probe control rather than a selected actor', () => {
  const pod = (actor, role, ready = true) => ({
    metadata: {name: actor, labels: {'testing.stacks.org/actor': actor, 'testing.stacks.org/role': role}},
    status: {phase: 'Running', podIP: `10.0.0.${actor.length}`, conditions: [{type: 'Ready', status: ready ? 'True' : 'False'}],
      containerStatuses: [{name: 'attacknet-probe', ready}]},
  });
  const selected = controlTarget(network, {items: [pod('signer-node-1', 'companion'), pod('follower-1', 'follower')]}, ['signer-node-1']);
  assert.equal(selected.actor, 'follower-1');
});

test('phase evidence remains inconclusive unless its type-specific baseline is usable', () => {
  const response = {observation: {actor: 'miner-1', probe: 'network', status: 'ok', successes: 1}};
  const phase = probePhase({kind: 'NetworkChaos', phase: 'before', responses: [response]});
  assert.equal(baselineUsable('NetworkChaos', phase, ['miner-1']), true);
  phase.observations[0].successes = 0;
  assert.equal(baselineUsable('NetworkChaos', phase, ['miner-1']), false);
  assert.equal(phase.source.trust, 'orchestrator-observed');
});

test('controller-owned I/O-pressure Pod uses the existing trusted active I/O probe contract', () => {
  const response = {observation: {
    actor: 'miner-1', probe: 'io', status: 'ok', successes: 5,
  }};
  const phase = probePhase({kind: 'IOPressurePod', phase: 'before', responses: [response]});
  assert.equal(phase.source.authority, 'active-probe');
  assert.equal(phase.observations[0].probe, 'io');
  assert.equal(baselineUsable('IOPressurePod', phase, ['miner-1']), true);
  assert.equal(phase.injection.source.authority, 'kubernetes-pod-status');
});

test('ProbeClient pins response schema, kind, and actor identity', async () => {
  const request = (_options, callback) => {
    const outgoing = new EventEmitter();
    outgoing.write = () => {};
    outgoing.end = () => {
      const response = new EventEmitter();
      response.statusCode = 200;
      callback(response);
      response.emit('data', Buffer.from(JSON.stringify({
        schemaVersion: 'stacks-attacknet-probe-response/v1', actor: 'miner-1', kind: 'clock',
        observation: {actor: 'miner-1', probe: 'clock', status: 'ok'},
      })));
      response.emit('end');
    };
    outgoing.destroy = error => outgoing.emit('error', error);
    return outgoing;
  };
  const result = await new ProbeClient({request}).probe({actor: 'miner-1', podIP: '10.0.0.1'}, {kind: 'clock'});
  assert.equal(result.actor, 'miner-1');
  await assert.rejects(
    new ProbeClient({request}).probe({actor: 'signer-1', podIP: '10.0.0.2'}, {kind: 'clock'}),
    /mismatched identity/,
  );
});
