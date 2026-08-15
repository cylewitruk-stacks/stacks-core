import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {renderObservability} from './render.mjs';
import {readEvents, renderReport} from './report.mjs';

const manifest = {
  schemaVersion: 1,
  network: 'attacknet-test',
  namespace: 'hacknet-system',
  workloads: [
    {service: 'miner-1', type: 'node', role: 'miner'},
    {service: 'signer-node-1', type: 'node', role: 'companion'},
    {service: 'signer-1', type: 'signer', role: 'signer'},
    {service: 'follower-1', type: 'node', role: 'follower'},
    {service: 'bitcoin', type: 'infrastructure', role: 'burnchain'},
  ],
};

test('render emits actor-labelled scrape targets and restricted credential-free observers', () => {
  const rendered = renderObservability(manifest, {eventToken: 'c'.repeat(64)});
  const resources = new Map(rendered.items.map(item => [`${item.kind}/${item.metadata.name}`, item]));
  const prometheus = resources.get('ConfigMap/attacknet-test-attacknet-prometheus');
  const nodes = JSON.parse(prometheus.data['nodes.json']);
  const signers = JSON.parse(prometheus.data['signers.json']);
  assert.deepEqual(nodes.map(item => item.targets[0]), [
    'attacknet-test-miner-1:20446',
    'attacknet-test-signer-node-1:20446',
    'attacknet-test-follower-1:20446',
  ]);
  assert.equal(nodes[1].labels.attacknet_role, 'companion');
  assert.equal(nodes[1].labels.evidence_source, 'actor_self_reported');
  assert.equal(signers[0].targets[0], 'attacknet-test-signer-1:31000');
  assert.match(prometheus.data['prometheus.yml'], /attacknet-orchestrator-events/);

  for (const name of ['events', 'prometheus', 'grafana']) {
    const deployment = resources.get(`Deployment/attacknet-test-attacknet-${name}`);
    assert.equal(deployment.spec.template.spec.automountServiceAccountToken, false);
    assert.equal(deployment.spec.template.spec.securityContext.runAsNonRoot, true);
    assert.match(deployment.spec.template.metadata.annotations['testing.stacks.org/config-sha256'], /^[0-9a-f]{64}$/);
    for (const container of deployment.spec.template.spec.containers) {
      assert.equal(container.securityContext.allowPrivilegeEscalation, false);
      assert.equal(container.securityContext.readOnlyRootFilesystem, true);
      assert.deepEqual(container.securityContext.capabilities.drop, ['ALL']);
    }
  }
  const secretName = 'attacknet-test-attacknet-event-writer';
  assert.equal(resources.get(`Secret/${secretName}`).stringData.token, 'c'.repeat(64));
  const deployments = rendered.items.filter(item => item.kind === 'Deployment');
  const secretConsumers = deployments.filter(deployment =>
    deployment.spec.template.spec.volumes.some(volume => volume.secret?.secretName === secretName));
  assert.deepEqual(secretConsumers.map(deployment => deployment.metadata.name), ['attacknet-test-attacknet-events']);
});

test('render resolves long logical actor names exactly like bounded Kubernetes children', () => {
  const longManifest = {
    network: 'experiment-with-a-very-long-but-valid-network-name',
    namespace: 'hacknet-system',
    workloads: [{service: 'signer-node-with-an-equally-long-logical-name', type: 'node', role: 'companion'}],
  };
  const rendered = renderObservability(longManifest, {eventToken: 'c'.repeat(64)});
  for (const item of rendered.items) assert.ok(item.metadata.name.length <= 63, item.metadata.name);
  const prometheus = rendered.items.find(item => item.kind === 'ConfigMap' && item.metadata.labels['app.kubernetes.io/name'] === 'attacknet-prometheus');
  const target = JSON.parse(prometheus.data['nodes.json'])[0].targets[0].split(':')[0];
  assert.ok(target.length <= 63);
  assert.match(target, /-[0-9a-f]{8}$/);
});

test('standalone report escapes payloads and includes trust-boundary language', () => {
  const html = renderReport([{
    schemaVersion: 1,
    sequence: 1,
    runId: 'run-1',
    network: 'attacknet-test',
    kind: 'note',
    phase: 'verification',
    occurredAt: '2026-08-15T00:00:00.000Z',
    recordedAt: '2026-08-15T00:00:00.001Z',
    details: {message: '</script><script>alert(1)</script>'},
  }]);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /orchestrator-observed and bearer-authenticated/);
  assert.match(html, /actor-self-reported/);
});

test('report reader accepts multi-line JSONL beginning with an object', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-report-'));
  const path = join(directory, 'events.jsonl');
  writeFileSync(path, '{"sequence":1,"kind":"one"}\n{"sequence":2,"kind":"two"}\n');
  assert.deepEqual(readEvents(path).map(event => event.kind), ['one', 'two']);
});
