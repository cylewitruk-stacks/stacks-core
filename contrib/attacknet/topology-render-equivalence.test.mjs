import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import test from 'node:test';

import {buildTopology, renderTopology} from './topology.mjs';

const LEGACY_REVISION = 'f8a853a0f21c9edebec92398fb56500ae10e1a22';
const LEGACY_CONTROLLER = 'contrib/helm/hacknet/operator/controller.py';
const root = resolve(import.meta.dirname, '../..');
const operatorRoot = join(root, 'contrib/helm/hacknet/operator');

const pythonRenderer = String.raw`
import json
import sys
import types

module = types.ModuleType("legacy_controller")
sys.modules[module.__name__] = module
exec(compile(sys.stdin.read(), "controller.py", "exec"), module.__dict__)
with open(sys.argv[1], encoding="utf-8") as source:
    network = json.load(source)
network["metadata"]["uid"] = "offline-render-check"
network["metadata"]["generation"] = 1
print(json.dumps(module.build_resources(network), sort_keys=True, separators=(",", ":")))
`;

function imagePullPolicy(image) {
  if (image.includes('@')) return 'IfNotPresent';
  const slash = image.lastIndexOf('/');
  const colon = image.lastIndexOf(':');
  return colon <= slash || image.slice(colon + 1) === 'latest' ? 'Always' : 'IfNotPresent';
}

function defaultProbe(probe) {
  if (!probe) return;
  probe.timeoutSeconds ??= 1;
  probe.periodSeconds ??= 10;
  probe.successThreshold ??= 1;
  probe.failureThreshold ??= 3;
  if (probe.httpGet) probe.httpGet.scheme ??= 'HTTP';
}

function normalizeResources(value, {go}) {
  const resources = structuredClone(value);
  const removeInternalManagedLabel = node => {
    if (!node || typeof node !== 'object') return;
    if (node.labels) delete node.labels['testing.stacks.org/managed-by'];
    for (const child of Array.isArray(node) ? node : Object.values(node)) removeInternalManagedLabel(child);
  };
  removeInternalManagedLabel(resources);
  const collections = [
    ['configmaps', 'v1', 'ConfigMap'],
    ['services', 'v1', 'Service'],
    ['statefulsets', 'apps/v1', 'StatefulSet'],
  ];
  for (const [collection, apiVersion, kind] of collections) {
    resources[collection].sort((left, right) => left.metadata.name < right.metadata.name ? -1 : left.metadata.name > right.metadata.name ? 1 : 0);
    for (const object of resources[collection]) {
      object.apiVersion ??= apiVersion;
      object.kind ??= kind;
      delete object.status;
      for (const owner of object.metadata.ownerReferences ?? []) delete owner.blockOwnerDeletion;
      if (kind === 'Service') {
        object.spec.ports ??= [];
        object.spec.publishNotReadyAddresses ??= false;
        object.spec.sessionAffinity ??= 'None';
        object.spec.internalTrafficPolicy ??= 'Cluster';
      }
      if (kind !== 'StatefulSet') continue;
      object.spec.revisionHistoryLimit ??= 10;
      object.spec.volumeClaimTemplates ??= [];
      delete object.spec.template.metadata.annotations['testing.stacks.org/config-hash'];
      const pod = object.spec.template.spec;
      pod.initContainers ??= [];
      pod.securityContext ??= {};
      pod.restartPolicy ??= 'Always';
      pod.dnsPolicy ??= 'ClusterFirst';
      pod.schedulerName ??= 'default-scheduler';
      for (const volume of pod.volumes ?? []) {
        if (volume.configMap) volume.configMap.defaultMode ??= 0o644;
        if (volume.secret) volume.secret.defaultMode ??= 0o644;
      }
      for (const container of [...pod.initContainers, ...pod.containers]) {
        container.ports ??= [];
        container.resources ??= {};
        container.securityContext ??= {};
        container.imagePullPolicy ??= imagePullPolicy(container.image);
        container.terminationMessagePath ??= '/dev/termination-log';
        container.terminationMessagePolicy ??= 'File';
        defaultProbe(container.readinessProbe);
        defaultProbe(container.livenessProbe);
        defaultProbe(container.startupProbe);
        const peers = container.env?.find(variable => variable.name === 'PROBE_PEERS_JSON');
        if (go && peers) {
          const parsed = JSON.parse(peers.value);
          for (const peer of Object.values(parsed)) delete peer.ports.probe;
          peers.value = JSON.stringify(parsed);
        }
        // The Go renderer deliberately hardens dependency init containers.
        if (go && container.name === 'wait-for-dependencies') {
          assert.equal(container.securityContext.readOnlyRootFilesystem, true);
          delete container.securityContext.readOnlyRootFilesystem;
        }
      }
      for (const claim of object.spec.volumeClaimTemplates) delete claim.status;
    }
  }
  return resources;
}

function renderLegacy(input) {
  const source = execFileSync('git', ['show', `${LEGACY_REVISION}:${LEGACY_CONTROLLER}`], {cwd: root, encoding: 'utf8'});
  return JSON.parse(execFileSync('python3', ['-c', pythonRenderer, input], {cwd: root, input: source, encoding: 'utf8'}));
}

function renderGo(input, actors) {
  return JSON.parse(execFileSync('go', [
    'run', './cmd/render-check', '--input', input,
    '--expected-actors', String(actors), '--output', '-',
  ], {
    cwd: operatorRoot,
    encoding: 'utf8',
    env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/private/tmp/attacknet-go-cache'},
  }));
}

test('Go topology renderer preserves the approved A1 workload contract', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-topology-equivalence-'));
  try {
    const topology = buildTopology({minerCount: 1, signerCount: 1, followerCount: 1});
    const {resource} = renderTopology(topology, output, {network: 'equivalence', namespace: 'attacknet-equivalence', probes: true});
    const input = join(output, 'stacksnetwork.json');
    const legacy = renderLegacy(input);
    const go = renderGo(input, resource.spec.actors.length);

    for (const service of go.services) {
      assert.equal(service.metadata.labels['app.kubernetes.io/managed-by'], 'hacknet-operator');
      assert.equal(service.metadata.labels['testing.stacks.org/managed-by'], 'stacks-hacknet-operator');
      assert(service.spec.ports.some(port => port.name === 'probe' && port.port === 18080));
      service.spec.ports = service.spec.ports.filter(port => port.name !== 'probe');
    }
    for (const service of legacy.services) {
      assert(!service.spec.ports?.some(port => port.name === 'probe'));
    }

    assert.deepEqual(
      normalizeResources(go, {go: true}),
      normalizeResources(legacy, {go: false}),
      'Go renderer drifted from the approved A1 resource contract outside documented security and probe-endpoint improvements',
    );
  } finally {
    rmSync(output, {recursive: true, force: true});
  }
});
