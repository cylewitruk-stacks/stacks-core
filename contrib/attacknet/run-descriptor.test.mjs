import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

import {
  appendEvent,
  attachInstrumentationCapabilities,
  canonicalJson,
  deriveReplayDescriptor,
  finalizeDescriptor,
  initializeDescriptor,
  resolveRuntimeInputs,
  seededChoice,
  sha256Value,
  validateDescriptor,
} from './run-descriptor.mjs';

const digest = `sha256:${'a'.repeat(64)}`;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-run-'));
  const paths = {
    topology: join(root, 'topology.json'),
    configA: join(root, 'a.toml'),
    configB: join(root, 'b.toml'),
    admitted: join(root, 'admitted.json'),
    metadata: join(root, 'metadata.json'),
    descriptor: join(root, 'run.json'),
  };
  writeFileSync(paths.topology, '{"actors":3}\n');
  writeFileSync(paths.configA, 'mode = "baseline"\n');
  writeFileSync(paths.configB, 'interval = 10\n');
  writeFileSync(paths.admitted, '{"kind":"List","items":[]}\n');
  const metadata = {
    runId: 'run-20260815-001', seed: '18446744073709551615', seedAlgorithm: 'agent-decisions/v1',
    createdAt: '2026-08-15T01:00:00Z', sourceRevision: 'a7e3e76019d9', sourceDirty: false,
    topologyPath: paths.topology, configPaths: [paths.configB, paths.configA], admittedManifestPath: paths.admitted,
    images: [{scope: 'all-stacks-actors', requestedRef: 'stacks:main', resolvedRef: `stacks@${digest}`, resolvedDigest: digest}],
    nondeterminism: {statement: 'Kubernetes placement and wall-clock scheduling remain nondeterministic.', disclosed: [
      {source: 'kubernetes-scheduling', impact: 'Changes actor placement and timing.', capture: 'Admitted resources and pod placement are collected in evidence.', bounded: false},
    ]},
  };
  writeFileSync(paths.metadata, `${JSON.stringify(metadata)}\n`);
  return {root, paths, metadata};
}

function appendTimeline(descriptor) {
  let result = appendEvent(descriptor, {type: 'cadence-transition', occurredAt: '2026-08-15T01:01:00Z', payload: {
    policy: 'burnchain', from: 'pause', to: 'interval:10s', reason: 'network-ready',
  }}, {now: () => '2026-08-15T01:01:01Z'});
  result = appendEvent(result, {type: 'fault-decision', occurredAt: '2026-08-15T01:02:00Z', payload: {
    campaign: 'delay-signer', decision: 'applied', faultKind: 'NetworkChaos', targets: ['signer-2'], parameters: {latency: '500ms'},
  }}, {now: () => '2026-08-15T01:02:01Z'});
  result = appendEvent(result, {type: 'assertion-result', occurredAt: '2026-08-15T01:03:00Z', payload: {
    assertion: 'chain-progress', status: 'fail', details: {burnHeight: 242},
  }}, {now: () => '2026-08-15T01:03:01Z'});
  return result;
}

test('canonical JSON and initialization are deterministic and capture immutable inputs', () => {
  assert.equal(canonicalJson({z: 1, a: {d: 2, c: 3}}), canonicalJson({a: {c: 3, d: 2}, z: 1}));
  const {metadata} = fixture();
  const left = initializeDescriptor(metadata);
  const right = initializeDescriptor({...metadata, images: [...metadata.images]});
  assert.equal(left.integrity.digest, right.integrity.digest);
  assert.deepEqual(left.inputs.configuration.files.map(file => file.path), [...metadata.configPaths].sort());
  assert.equal(left.inputs.images[0].requestedRef, 'stacks:main');
  assert.equal(left.inputs.images[0].resolvedDigest, digest);
  assert.equal(validateDescriptor(left, {verifyFiles: true}), true);
});

test('the ledger assigns an ordered sequence and rejects backwards occurrence time', () => {
  const {metadata} = fixture();
  const descriptor = appendTimeline(initializeDescriptor(metadata));
  assert.deepEqual(descriptor.timeline.map(event => event.sequence), [1, 2, 3]);
  assert.throws(() => appendEvent(descriptor, {type: 'assertion-result', occurredAt: '2026-08-15T01:00:00Z', payload: {
    assertion: 'late-report', status: 'pass',
  }}), /precedes the prior event/);
});

test('pre-apply descriptors resolve admitted state and immutable runtime images in a second phase', () => {
  const {metadata, paths} = fixture();
  delete metadata.admittedManifestPath;
  metadata.requestedManifestPath = paths.topology;
  metadata.images = metadata.images.map(({scope, requestedRef}) => ({scope, requestedRef}));
  const pending = initializeDescriptor(metadata);
  assert.equal(pending.inputs.kubernetes.resolution.complete, false);
  const observedReady = appendEvent(pending, {
    type: 'assertion-result', occurredAt: '2026-08-15T01:01:00Z',
    payload: {assertion: 'ready', status: 'pass'},
  });
  assert.throws(() => finalizeDescriptor(observedReady, 'passed'), /complete admitted.*manifest/);
  const resolved = resolveRuntimeInputs(pending, {
    admittedManifestPath: paths.admitted,
    images: [{
      scope: 'all-stacks-actors', requestedRef: 'stacks:main',
      resolvedRef: `stacks@${digest}`, resolvedDigest: digest,
    }],
  });
  assert.equal(resolved.inputs.kubernetes.resolution.complete, true);
  assert.equal(validateDescriptor(resolved, {verifyFiles: true}), true);
});

test('run descriptor refuses a self-sealed but semantically incomplete instrumentation claim', () => {
  const {metadata, root} = fixture();
  const manifestPath = join(root, 'instrumentation.json');
  const manifest = {
    schema: 'stacks-attacknet-instrumentation-capabilities/v1', manifestId: 'phase-1',
    acceptanceReady: true, profiles: [{id: 'patched-main'}],
  };
  manifest.manifestDigest = sha256Value(manifest);
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => attachInstrumentationCapabilities(initializeDescriptor(metadata), manifestPath), /inventory/);

  manifest.acceptanceReady = false;
  delete manifest.manifestDigest;
  manifest.manifestDigest = sha256Value(manifest);
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => attachInstrumentationCapabilities(initializeDescriptor(metadata), manifestPath), /not acceptance-ready/);
});

test('finalization enforces assertion outcome and detects descriptor or artifact tampering', () => {
  const {metadata, paths} = fixture();
  const failed = finalizeDescriptor(appendTimeline(initializeDescriptor(metadata)), 'failed', {finalizedAt: '2026-08-15T01:04:00Z'});
  assert.equal(failed.summary.faultDecisions, 1);
  assert.equal(failed.summary.assertions.fail, 1);
  assert.equal(validateDescriptor(failed), true);
  const tampered = structuredClone(failed);
  tampered.timeline[2].payload.status = 'pass';
  assert.throws(() => validateDescriptor(tampered), /(summary does not match|integrity mismatch)/);
  writeFileSync(paths.configA, 'mode = "changed"\n');
  assert.throws(() => validateDescriptor(failed, {verifyFiles: true}), /artifact digest mismatch/);
});

test('replay derivation preserves inputs and seed but reduces to the failed action prefix', () => {
  const {metadata} = fixture();
  const source = finalizeDescriptor(appendTimeline(initializeDescriptor(metadata)), 'failed', {finalizedAt: '2026-08-15T01:04:00Z'});
  const replay = deriveReplayDescriptor(source);
  assert.equal(replay.run.status, 'planned');
  assert.equal(replay.randomness.seed, source.randomness.seed);
  assert.equal(replay.inputs.kubernetes.admittedManifest.digest, source.inputs.kubernetes.admittedManifest.digest);
  assert.deepEqual(replay.replayPlan.schedule.map(item => [item.type, item.offsetMs]), [
    ['cadence-transition', 0], ['fault-decision', 60_000],
  ]);
  assert.equal(replay.replayPlan.expectedFailure.assertion, 'chain-progress');
  assert.match(replay.replayPlan.disclosure, /not proof of causal minimality/);
  assert.equal(validateDescriptor(replay), true);
  const invalidSchedule = structuredClone(replay);
  invalidSchedule.replayPlan.schedule[1].offsetMs = -1;
  assert.throws(() => validateDescriptor(invalidSchedule), /nondecreasing non-negative integer/);
});

test('CLI initializes, appends, finalizes, validates, and emits a replay descriptor', () => {
  const {paths} = fixture();
  const cli = new URL('./run-descriptor.mjs', import.meta.url).pathname;
  function run(...args) {
    const result = spawnSync(process.execPath, [cli, ...args], {encoding: 'utf8'});
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  }
  assert.match(run('init', paths.descriptor, `--metadata=${paths.metadata}`), /^sha256:/);
  const eventPath = join(paths.descriptor, '..', 'event.json');
  writeFileSync(eventPath, JSON.stringify({type: 'assertion-result', occurredAt: '2026-08-15T01:01:00Z', recordedAt: '2026-08-15T01:01:01Z', payload: {
    assertion: 'smoke', status: 'fail',
  }}));
  assert.equal(run('append', paths.descriptor, `--event=${eventPath}`), '1');
  assert.match(run('finalize', paths.descriptor, '--status=failed', '--at=2026-08-15T01:02:00Z'), /^sha256:/);
  assert.equal(run('validate', paths.descriptor, '--verify-files'), 'valid');
  const replayPath = join(paths.descriptor, '..', 'replay.json');
  assert.match(run('minimize', paths.descriptor, replayPath), /^sha256:/);
  assert.equal(JSON.parse(readFileSync(replayPath, 'utf8')).run.status, 'planned');
});

test('seeded choices are stable and namespaced within the canonical run contract', () => {
  const first = seededChoice('repeatable-seed', 'campaign-target', 3, ['miner-1', 'miner-2', 'miner-3']);
  assert.deepEqual(first, seededChoice('repeatable-seed', 'campaign-target', 3, ['miner-1', 'miner-2', 'miner-3']));
  assert.notEqual(first.digest, seededChoice('repeatable-seed', 'fault-kind', 3, ['miner-1', 'miner-2', 'miner-3']).digest);
});
