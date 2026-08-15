import assert from 'node:assert/strict';
import test from 'node:test';

import {evaluateFaultEffect, FAULT_PROBE_SCHEMA} from './fault-effect-evidence.mjs';

const target = {
  actor: 'signer-node-1', role: 'companion', pod: 'attacknet-signer-node-1-0', podUid: 'uid-1',
  node: 'worker-1', requestedImage: 'stacks:main', resolvedImageId: 'sha256:abc', restartCount: 2,
};

function campaign(kind, action, spec = {}) {
  return {apiVersion: 'chaos-mesh.org/v1alpha1', kind, metadata: {
    name: 'fault-test', namespace: 'hacknet-system', labels: {'testing.stacks.org/network': 'attacknet'},
  }, spec: {
    mode: 'all', duration: '30s', ...(action ? {action} : {}), ...spec,
  }};
}

function targets(items = [target]) {
  return {
    schemaVersion: 1, network: 'attacknet', namespace: 'hacknet-system', resolvedAt: '2026-08-15T00:00:00Z', targets: items,
  };
}

function phase(name, authority, observations = [], allInjectedObserved = false,
  injectionAuthority = 'chaos-mesh-status') {
  return {
    schemaVersion: FAULT_PROBE_SCHEMA, phase: name,
    source: {
      trust: 'orchestrator-observed', authority, collector: 'attacknet-probe/v1',
      ...(authority === 'application-process-metric' ? {contentTrust: 'actor-self-reported'} : {}),
    },
    ...(name === 'during' ? {injection: {
      allInjectedObserved,
      source: {trust: 'orchestrator-observed', authority: injectionAuthority, collector: 'fault-controller'},
    }} : {}),
    observations,
  };
}

function evaluate(compiled, before, during, after, options = {}) {
  const resolved = options.targets ?? targets();
  return evaluateFaultEffect({
    campaign: compiled,
    evidence: options.evidence ?? {selectedActors: resolved.targets.map(item => item.actor)},
    resolvedTargets: resolved,
    before, during, after,
  });
}

function pod(actor, values = {}) {
  return {
    actor, probe: 'pod-state', status: 'ok', targetPodUid: 'uid-1', targetPresent: true,
    currentPodUid: 'uid-1', podPhase: 'Running', containerRestartCount: 2, containerReady: true,
    ...values,
  };
}

test('AllInjected alone is explicitly inconclusive', () => {
  const result = evaluate(
    campaign('PodChaos', 'pod-kill'),
    phase('before', 'kubernetes-api'),
    phase('during', 'kubernetes-api', [], true),
    phase('after', 'kubernetes-api'),
  );
  assert.equal(result.verdict, 'Inconclusive');
  assert.equal(result.injection.allInjectedObserved, true);
  assert.match(result.injection.evidentiaryWeight, /never sufficient/);
});

test('Pod effect requires immutable admitted UID, absence, restart, or readiness evidence', () => {
  const before = phase('before', 'kubernetes-api', [pod(target.actor)]);
  const during = phase('during', 'kubernetes-api', [pod(target.actor, {
    targetPresent: false, currentPodUid: 'uid-2', containerRestartCount: 0, containerReady: false,
  })], true);
  const after = phase('after', 'kubernetes-api', [pod(target.actor, {
    targetPresent: false, currentPodUid: 'uid-2', targetPodUid: 'uid-1', containerRestartCount: 0,
  })]);
  const result = evaluate(campaign('PodChaos', 'pod-kill'), before, during, after);
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Proven');

  const unchanged = evaluate(campaign('PodChaos', 'pod-kill'), before, phase('during', 'kubernetes-api', [pod(target.actor)], true), after);
  assert.equal(unchanged.verdict, 'Failed');

  const restarted = evaluate(
    campaign('PodChaos', 'container-kill'), before,
    phase('during', 'kubernetes-api', [pod(target.actor, {containerRestartCount: 3})], true),
    phase('after', 'kubernetes-api', [pod(target.actor, {containerRestartCount: 3})]),
  );
  assert.equal(restarted.verdict, 'Proven');
});

function network(values = {}) {
  return {
    actor: target.actor, probe: 'network', status: 'ok', probeName: 'peer-rpc', peerActor: 'miner-1',
    attempts: 10, successes: 10, latencyMsP50: 10, latencyMsP95: 20, protocolErrors: 0,
    throughputBytesPerSecond: 1_000_000, ...values,
  };
}

test('Network effect requires a matching named peer probe delta', () => {
  const result = evaluate(
    campaign('NetworkChaos', 'delay', {delay: {latency: '500ms'}}),
    phase('before', 'active-probe', [network()]),
    phase('during', 'active-probe', [network({latencyMsP50: 400, latencyMsP95: 420})], true),
    phase('after', 'active-probe', [network()]),
  );
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Proven');

  const unnamed = evaluate(
    campaign('NetworkChaos', 'delay', {delay: {latency: '500ms'}}),
    phase('before', 'active-probe', [network()]),
    phase('during', 'active-probe', [network({probeName: 'different', latencyMsP95: 800})], true),
    phase('after', 'active-probe', [network()]),
  );
  assert.equal(unnamed.verdict, 'Inconclusive');

  const wrongPeer = evaluateFaultEffect({
    campaign: campaign('NetworkChaos', 'delay', {delay: {latency: '500ms'}}),
    evidence: {selectedActors: [target.actor], peerSelectedActors: ['miner-2']},
    resolvedTargets: targets(),
    before: phase('before', 'active-probe', [network()]),
    during: phase('during', 'active-probe', [network({latencyMsP95: 800})], true),
    after: phase('after', 'active-probe', [network()]),
  });
  assert.equal(wrongPeer.verdict, 'Inconclusive');
});

function dns(values = {}) {
  return {
    actor: target.actor, probe: 'dns', status: 'ok', probeName: 'companion-dns',
    query: 'attacknet-miner-1.hacknet-system.svc.cluster.local', controlQuery: 'kubernetes.default.svc.cluster.local',
    querySucceeded: true, controlSucceeded: true, answers: ['10.0.0.10'], controlAnswers: ['10.0.0.1'], ...values,
  };
}

test('DNS proof isolates selected query failure from a healthy control query', () => {
  const result = evaluate(
    campaign('DNSChaos', 'error', {patterns: ['attacknet-*.hacknet-system.svc.cluster.local']}),
    phase('before', 'active-probe', [dns()]),
    phase('during', 'active-probe', [dns({querySucceeded: false, answers: []})], true),
    phase('after', 'active-probe', [dns()]),
  );
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Proven');

  const controlFailed = evaluate(
    campaign('DNSChaos', 'error', {patterns: ['attacknet-*.hacknet-system.svc.cluster.local']}),
    phase('before', 'active-probe', [dns()]),
    phase('during', 'active-probe', [dns({querySucceeded: false, controlSucceeded: false, answers: [], controlAnswers: []})]),
    phase('after', 'active-probe', [dns()]),
  );
  assert.equal(controlFailed.verdict, 'Inconclusive');
});

function io(values = {}) {
  return {
    actor: target.actor, probe: 'io', status: 'ok', probeName: 'sqlite-read', path: '/data/probe', operation: 'READ',
    attempts: 20, successes: 20, errorCounts: {}, latencyMsP50: 2, latencyMsP95: 4,
    contentDigest: 'sha256:content', attributesDigest: 'sha256:attributes', ...values,
  };
}

function pressureCampaign(contract) {
  const compiled = campaign('IOPressurePod', null, {
    containerNames: ['actor'], workers: 1, bytesMiB: 64, writeSizeKiB: 256,
  });
  compiled.metadata.annotations = {
    'testing.stacks.org/io-pressure-contract': JSON.stringify(contract),
  };
  return compiled;
}

test('I/O proof uses matching operation latency or errno evidence', () => {
  const latency = evaluate(
    campaign('IOChaos', 'latency', {volumePath: '/data', delay: '100ms'}),
    phase('before', 'active-probe', [io()]),
    phase('during', 'active-probe', [io({latencyMsP50: 90, latencyMsP95: 110})], true),
    phase('after', 'active-probe', [io()]),
  );
  assert.equal(latency.verdict, 'Proven');

  const fault = evaluate(
    campaign('IOChaos', 'fault', {volumePath: '/data', errno: 5}),
    phase('before', 'active-probe', [io()]),
    phase('during', 'active-probe', [io({successes: 10, errorCounts: {'5': 10}})], true),
    phase('after', 'active-probe', [io()]),
  );
  assert.equal(fault.verdict, 'Proven');
  assert.equal(fault.recovery.verdict, 'Proven');
});

test('disk I/O pressure requires configured latency multiplier and added-ms evidence and proves recovery distinctly', () => {
  const contract = {
    semantic: 'disk-io-pressure', severity: 'medium', workers: 1, bytesMiB: 64,
    writeSizeKiB: 256, tempPath: '/data', minimumLatencyMultiplier: 2,
    minimumAddedLatencyMs: 5,
  };
  const compiled = pressureCampaign(contract);
  const evidence = {selectedActors: [target.actor], ioPressure: contract};
  const baseline = io({probeName: 'fsync-pressure.dat', operation: 'FSYNC', latencyMsP50: 2, latencyMsP95: 4});
  const affected = io({probeName: 'fsync-pressure.dat', operation: 'FSYNC', latencyMsP50: 8, latencyMsP95: 12});
  const recovered = io({probeName: 'fsync-pressure.dat', operation: 'FSYNC', latencyMsP50: 2, latencyMsP95: 4.5});
  const result = evaluate(
    compiled,
    phase('before', 'active-probe', [baseline]),
    phase('during', 'active-probe', [affected], true, 'kubernetes-pod-status'),
    phase('after', 'active-probe', [recovered]),
    {evidence},
  );
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Proven');
  assert.equal(result.campaign.action, 'disk-pressure');
  assert.equal(result.evaluations[0].metrics.latencyMultiplier, 3);
  assert.equal(result.evaluations[0].metrics.addedLatencyMs, 8);
  assert.match(result.evaluations[0].reason, /both configured/);
  assert.match(result.evaluations[0].recoveryReason, /returned below both/);

  const allInjectedWithoutEffect = evaluate(
    compiled,
    phase('before', 'active-probe', [baseline]),
    phase('during', 'active-probe', [io({
      probeName: 'fsync-pressure.dat', operation: 'FSYNC', latencyMsP95: 4.2,
    })], true, 'kubernetes-pod-status'),
    phase('after', 'active-probe', [recovered]),
    {evidence},
  );
  assert.equal(allInjectedWithoutEffect.verdict, 'Failed');
  assert.equal(allInjectedWithoutEffect.injection.allInjectedObserved, true);
  assert.match(allInjectedWithoutEffect.injection.evidentiaryWeight, /never sufficient/);
});

test('disk I/O pressure recovery fails while either configured threshold remains exceeded', () => {
  const contract = {
    semantic: 'disk-io-pressure', severity: 'low', workers: 1, bytesMiB: 32,
    writeSizeKiB: 128, tempPath: '/data', minimumLatencyMultiplier: 2,
    minimumAddedLatencyMs: 5,
  };
  const evidence = {selectedActors: [target.actor], ioPressure: contract};
  const sample = values => io({probeName: 'fsync-pressure.dat', operation: 'FSYNC', ...values});
  const result = evaluate(
    pressureCampaign(contract),
    phase('before', 'active-probe', [sample({latencyMsP95: 4})]),
    phase('during', 'active-probe', [sample({latencyMsP95: 12})], true, 'kubernetes-pod-status'),
    phase('after', 'active-probe', [sample({latencyMsP95: 9})]),
    {evidence},
  );
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Failed');
  assert.match(result.evaluations[0].recoveryReason, /remained at or above/);
});

test('disk I/O pressure rejects threshold evidence that differs from the compiled resource contract', () => {
  const contract = {
    semantic: 'disk-io-pressure', severity: 'low', workers: 1, bytesMiB: 32,
    writeSizeKiB: 128, tempPath: '/data', minimumLatencyMultiplier: 2,
    minimumAddedLatencyMs: 5,
  };
  assert.throws(() => evaluate(
    pressureCampaign(contract),
    phase('before', 'active-probe'), phase('during', 'active-probe', [], true, 'kubernetes-pod-status'),
    phase('after', 'active-probe'),
    {evidence: {selectedActors: [target.actor], ioPressure: {...contract, minimumAddedLatencyMs: 6}}},
  ), /does not match compiler evidence/);
});

function clock(actor, control, wallEpochSeconds, monotonicSeconds) {
  return {
    actor, probe: 'clock', status: 'ok', control, wallEpochSeconds, monotonicSeconds,
    sampleWindowMs: 20, metric: 'stacks_node_process_wall_clock_seconds',
  };
}

test('Time proof normalizes target wall-clock shift against monotonic and independent control clocks', () => {
  const before = phase('before', 'application-process-metric', [
    clock(target.actor, false, 1000, 100), clock('control-1', true, 2000, 500),
  ]);
  const during = phase('during', 'application-process-metric', [
    clock(target.actor, false, 980, 110), clock('control-1', true, 2010, 510),
  ], true);
  const after = phase('after', 'application-process-metric', [
    clock(target.actor, false, 1020, 120), clock('control-1', true, 2020, 520),
  ]);
  const result = evaluate(campaign('TimeChaos', null, {timeOffset: '-30s'}), before, during, after);
  assert.equal(result.verdict, 'Proven');
  assert.equal(result.recovery.verdict, 'Proven');
  assert.equal(result.evaluations[0].metrics.observedOffsetSeconds, -30);

  const noControl = evaluate(
    campaign('TimeChaos', null, {timeOffset: '-30s'}),
    phase('before', 'application-process-metric', [clock(target.actor, false, 1000, 100)]),
    phase('during', 'application-process-metric', [clock(target.actor, false, 980, 110)], true),
    phase('after', 'application-process-metric', [clock(target.actor, false, 1020, 120)]),
  );
  assert.equal(noControl.verdict, 'Inconclusive');
});

test('rejects actor-supplied authority and malformed/unbounded probe data', () => {
  const actorSource = phase('before', 'active-probe', [network()]);
  actorSource.source.trust = 'actor-self-reported';
  assert.throws(() => evaluate(
    campaign('NetworkChaos', 'delay', {delay: {latency: '10ms'}}), actorSource,
    phase('during', 'active-probe', [network()]), phase('after', 'active-probe', [network()]),
  ), /actor-supplied evidence is not authoritative/);

  const malformed = network({attempts: 1, successes: 2});
  assert.throws(() => evaluate(
    campaign('NetworkChaos', 'delay', {delay: {latency: '10ms'}}),
    phase('before', 'active-probe', [malformed]),
    phase('during', 'active-probe', [network()]), phase('after', 'active-probe', [network()]),
  ), /finite integer/);
});

test('fixed mode requires the requested number of independently proven actors', () => {
  const second = {...target, actor: 'signer-node-2', pod: 'attacknet-signer-node-2-0', podUid: 'uid-2'};
  const resolved = targets([target, second]);
  const before = phase('before', 'kubernetes-api', [pod(target.actor), pod(second.actor, {targetPodUid: 'uid-2', currentPodUid: 'uid-2'})]);
  const during = phase('during', 'kubernetes-api', [
    pod(target.actor, {targetPresent: false, currentPodUid: 'replacement-1', containerReady: false}),
    pod(second.actor, {targetPodUid: 'uid-2', currentPodUid: 'uid-2'}),
  ], true);
  const after = phase('after', 'kubernetes-api', [pod(target.actor), pod(second.actor, {targetPodUid: 'uid-2', currentPodUid: 'uid-2'})]);
  const result = evaluate(campaign('PodChaos', 'pod-kill', {mode: 'fixed', value: '2'}), before, during, after, {targets: resolved});
  assert.equal(result.verdict, 'Failed');
  assert.deepEqual(result.effect.provenActors, [target.actor]);
});
