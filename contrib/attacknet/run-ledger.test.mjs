import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  appendRunEvent,
  exportRun,
  initializeRun,
  resolveRun,
  runContext,
} from './run-ledger.mjs';
import {initializeDescriptor, readDescriptor, writeDescriptor} from './run-descriptor.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-ledger-'));
  const topology = join(root, 'manifest.json');
  const requested = join(root, 'stacksnetwork.json');
  const admitted = join(root, 'admitted.json');
  const pods = join(root, 'pods.json');
  const descriptor = join(root, 'run.json');
  writeFileSync(topology, '{"network":"test"}\n');
  writeFileSync(requested, '{"kind":"StacksNetwork"}\n');
  writeFileSync(admitted, '{"kind":"List","resourceVersion":"7"}\n');
  const requestedRef = 'stacks-core:main';
  const digest = `sha256:${'b'.repeat(64)}`;
  writeFileSync(pods, JSON.stringify({items: [{
    metadata: {labels: {'testing.stacks.org/actor': 'miner-1'}},
    spec: {containers: [{name: 'actor', image: requestedRef}]},
    status: {containerStatuses: [{name: 'actor', imageID: `docker-pullable://stacks-core@${digest}`}]},
  }]}));
  const value = initializeDescriptor({
    runId: 'ledger-test', seed: '9', seedAlgorithm: 'test/v1', createdAt: '2026-08-15T00:00:00Z',
    sourceRevision: 'abcdef1', sourceDirty: false, topologyPath: topology,
    configPaths: [requested], requestedManifestPath: requested,
    images: [{scope: 'miner-1', requestedRef}],
    nondeterminism: {statement: 'test disclosure', disclosed: []},
  });
  writeDescriptor(descriptor, value);
  return {root, descriptor, admitted, pods, digest};
}

test('runtime resolution snapshots admitted resources and captures actor image IDs', () => {
  const value = fixture();
  resolveRun(value.descriptor, value.admitted, value.pods);
  const descriptor = readDescriptor(value.descriptor);
  assert.equal(descriptor.inputs.kubernetes.resolution.complete, true);
  assert.equal(descriptor.inputs.images[0].resolvedDigest, value.digest);
  assert.notEqual(descriptor.inputs.kubernetes.admittedManifest.path, value.admitted);
  writeFileSync(value.admitted, '{"kind":"List","resourceVersion":"mutated"}\n');
  assert.doesNotThrow(() => exportRun(value.descriptor, join(value.root, 'post-mutation-bundle')));
  const context = runContext(value.descriptor, 'hacknet-system', 'test');
  assert.equal(context.data['run-id'], 'ledger-test');
  assert.equal(context.data['descriptor-digest'], descriptor.integrity.digest);
});

test('run initialization snapshots mutable rendered inputs before later topology phases', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-generated-'));
  const descriptor = join(root, 'runs', 'snapshot-test', 'run.json');
  const manifest = join(root, 'manifest.json');
  const requested = join(root, 'stacksnetwork.json');
  writeFileSync(manifest, JSON.stringify({network: 'snapshot-net', namespace: 'hacknet-system'}));
  writeFileSync(requested, JSON.stringify({
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    spec: {actors: [{name: 'follower-1', image: 'stacks:test'}]},
  }));
  initializeRun(root, {
    descriptorPath: descriptor,
    runId: 'snapshot-test',
    now: new Date('2026-08-15T00:00:00Z'),
    source: {revision: 'abcdef1', dirty: false},
  });
  const value = readDescriptor(descriptor);
  assert.notEqual(value.inputs.topology.path, manifest);
  assert.notEqual(value.inputs.kubernetes.requestedManifest.path, requested);
  writeFileSync(manifest, JSON.stringify({network: 'changed', namespace: 'hacknet-system'}));
  writeFileSync(requested, JSON.stringify({kind: 'StacksNetwork', spec: {actors: []}}));
  const destination = join(root, 'bundle');
  assert.doesNotThrow(() => exportRun(descriptor, destination));
  const index = JSON.parse(readFileSync(join(destination, 'artifact-index.json'), 'utf8'));
  assert.ok(index.every(item => item.missing === false));
});

test('append is monotonic for a recorder clock that moves backwards', () => {
  const value = fixture();
  appendRunEvent(value.descriptor, 'cadence-transition', {
    policy: 'burnchain', from: 'pause', to: 'run:2s', reason: 'bootstrap',
  }, {now: '2026-08-15T00:01:00Z'});
  appendRunEvent(value.descriptor, 'assertion-result', {
    assertion: 'ready', status: 'pass',
  }, {now: '2026-08-15T00:00:30Z'});
  const timeline = readDescriptor(value.descriptor).timeline;
  assert.equal(timeline[1].occurredAt, timeline[0].occurredAt);
});

test('export verifies and indexes every referenced artifact', () => {
  const value = fixture();
  resolveRun(value.descriptor, value.admitted, value.pods);
  const destination = join(value.root, 'bundle');
  exportRun(value.descriptor, destination);
  const index = JSON.parse(readFileSync(join(destination, 'artifact-index.json'), 'utf8'));
  assert.ok(index.length >= 3);
  assert.ok(index.every(item => item.missing === false));
  assert.ok(readFileSync(join(destination, 'run.json'), 'utf8').includes('ledger-test'));
});

test('resolution refuses missing Pods instead of fabricating an image identity', () => {
  const value = fixture();
  const empty = join(value.root, 'empty-pods.json');
  writeFileSync(empty, '{"items":[]}\n');
  assert.throws(() => resolveRun(value.descriptor, value.admitted, empty), /no admitted Pod/);
});
