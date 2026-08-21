import assert from 'node:assert/strict';
import test from 'node:test';

import {collectDoctorReport, DOCTOR_CONTRACT, runDoctor} from './doctor.mjs';

const json = value => ({status: 0, stdout: JSON.stringify(value), stderr: ''});
const text = value => ({status: 0, stdout: value, stderr: ''});
const missing = command => ({status: null, stdout: '', stderr: '', error: {code: 'ENOENT', message: `${command} missing`}});

function supportedFixture() {
  const crds = DOCTOR_CONTRACT.chaosMesh.requiredCrds.map(name => ({
    metadata: {name}, status: {conditions: [{type: 'Established', status: 'True'}]},
  }));
  const nodes = [
    {metadata: {name: 'kind-control-plane', labels: {'kubernetes.io/arch': 'arm64'}},
      spec: {providerID: 'kind://docker/fixture/kind-control-plane'}, status: {
      nodeInfo: {architecture: 'arm64'}, images: DOCTOR_CONTRACT.images.map(name => ({names: [name]})),
    }},
    {metadata: {name: 'kind-worker', labels: {'kubernetes.io/arch': 'arm64'}},
      spec: {providerID: 'kind://docker/fixture/kind-worker'}, status: {
      nodeInfo: {architecture: 'arm64'}, images: DOCTOR_CONTRACT.images.map(name => ({names: [name]})),
    }},
  ];
  return {
    tools: {
      node: text('v22.18.0\n'),
      python3: text('Python 3.12.11\n'),
      docker: json({Client: {Version: '28.3.2'}, Server: {Version: '28.3.2', Arch: 'arm64'}}),
      kubectl: json({clientVersion: {gitVersion: 'v1.36.3'}, serverVersion: {gitVersion: 'v1.36.1'}}),
      helm: json({version: 'v4.2.4'}),
      kind: text('kind v0.29.0 go1.24.2 darwin/arm64\n'),
    },
    nodes,
    storage: {items: [{metadata: {name: 'standard', annotations: {
      'storageclass.kubernetes.io/is-default-class': 'true',
    }}, provisioner: 'rancher.io/local-path', volumeBindingMode: 'WaitForFirstConsumer'}]},
    crds,
    daemon: {spec: {template: {spec: {containers: [{name: 'chaos-daemon', image: 'chaos-mesh/chaos-daemon:v2.8.3'}]}}},
      status: {desiredNumberScheduled: 2, numberReady: 2}},
    releases: [{name: 'chaos-mesh', chart: 'chaos-mesh-2.8.3', app_version: '2.8.3'}],
    metrics: {groupVersion: 'metrics.k8s.io/v1beta1', resources: []},
    capacities: {'kind-control-plane': 12_000_000_000, 'kind-worker': 13_000_000_000},
    images: Object.fromEntries(DOCTOR_CONTRACT.images.map((name, index) => [name, {Id: `sha256:${index}`}])) ,
    containerImages: Object.fromEntries(nodes.map(node => [
      node.metadata.name,
      DOCTOR_CONTRACT.images.map(name => `docker.io/library/${name}`).join('\n'),
    ])),
  };
}

function fixtureRunner(fixture) {
  return (command, args) => {
    if (args[0] === '--version' || command === 'kind') return fixture.tools[command] ?? missing(command);
    if (command === 'python3') return fixture.tools.python3 ?? missing(command);
    if (command === 'docker' && args[0] === 'version') return fixture.tools.docker ?? missing(command);
    if (command === 'kubectl' && args[0] === 'version') return fixture.tools.kubectl ?? missing(command);
    if (command === 'helm' && args[0] === 'version') return fixture.tools.helm ?? missing(command);
    if (command === 'kubectl' && args[0] === 'get' && args[1] === 'nodes') return json({items: fixture.nodes});
    if (command === 'kubectl' && args[0] === 'get' && args[1] === 'storageclass') return json(fixture.storage);
    if (command === 'kubectl' && args[0] === 'get' && args[1] === 'crd') return json({items: fixture.crds});
    if (command === 'kubectl' && args[0] === '-n') return json(fixture.daemon);
    if (command === 'helm' && args[0] === 'list') return json(fixture.releases);
    if (command === 'kubectl' && args[0] === 'get' && args[1] === '--raw'
      && args[2] === '/apis/metrics.k8s.io/v1beta1') return fixture.metrics === null
        ? {status: 1, stdout: '', stderr: 'NotFound'} : json(fixture.metrics);
    if (command === 'kubectl' && args[0] === 'get' && args[1] === '--raw') {
      const node = args[2].match(/^\/api\/v1\/nodes\/([^/]+)\/proxy\/stats\/summary$/)?.[1];
      const availableBytes = fixture.capacities[node];
      return availableBytes === null ? {status: 1, stdout: '', stderr: 'stats unavailable'}
        : json({node: {nodeName: node, fs: {availableBytes}}});
    }
    if (command === 'docker' && args[0] === 'image' && args[1] === 'inspect') {
      const image = fixture.images[args[2]];
      return image ? json(image) : {status: 1, stdout: '', stderr: 'No such image'};
    }
    if (command === 'docker' && args[0] === 'exec' && args[2] === 'ctr') {
      const output = fixture.containerImages[args[1]];
      return output === undefined ? {status: 1, stdout: '', stderr: 'container unavailable'} : text(`${output}\n`);
    }
    throw new Error(`unexpected fixture command: ${command} ${args.join(' ')}`);
  };
}

const portsAvailable = async ports => ports.map(port => ({...port, available: true, error: null}));
const dependencies = fixture => ({
  runCommand: fixtureRunner(fixture),
  checkPorts: portsAvailable,
  checkManagedPorts: async () => new Set(),
  localArchitecture: 'arm64',
  now: () => '2026-08-18T12:00:00.000Z',
});

function find(report, id) {
  return report.checks.find(item => item.id === id);
}

test('supported fixture reports every declared environment capability without live infrastructure', async () => {
  const report = await collectDoctorReport(dependencies(supportedFixture()));
  assert.equal(report.compatible, true);
  assert.equal(report.observedAt, '2026-08-18T12:00:00.000Z');
  assert.deepEqual(report.summary.requiredFailures, []);
  assert.equal(report.capabilities.podChaos, true);
  assert.equal(report.capabilities.nativeIoChaos.admissionEligible, false);
  assert.equal(report.capabilities.nativeIoChaos.portableAlternative, 'io-pressure');
  assert.equal(report.capabilities.nativeTimeChaos.admissionEligible, false);
  assert.equal(report.capabilities.ioPressure.available, true);
  assert.equal(report.capabilities.applicationClockSkew.available, true);
  assert.equal(report.capabilities.metricsApi, true);
  assert.equal(find(report, 'chaos-mesh.native-io-helper').status, 'warn');
  assert.equal(report.checks.every(item => typeof item.required === 'boolean'), true);
});

test('missing required tool is a named incompatibility', async () => {
  const fixture = supportedFixture();
  fixture.tools.helm = missing('helm');
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(report.compatible, false);
  assert.equal(find(report, 'tool.helm').status, 'fail');
  assert.match(find(report, 'tool.helm').message, /missing|not found/);
});

test('standalone kind CLI is optional for an already-running kind-on-Docker cluster', async () => {
  const fixture = supportedFixture();
  fixture.tools.kind = missing('kind');
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(find(report, 'tool.kind').status, 'warn');
  assert.equal(find(report, 'tool.kind').required, false);
  assert.equal(report.compatible, true);
});

test('kubectl client/server skew beyond one minor fails closed', async () => {
  const fixture = supportedFixture();
  fixture.tools.kubectl = json({clientVersion: {gitVersion: 'v1.34.1'}, serverVersion: {gitVersion: 'v1.36.1'}});
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(find(report, 'kubernetes.client-server-skew').compatible, false);
  assert.equal(find(report, 'kubernetes.client-server-skew').details.skew, 2);
});

test('low or unavailable node storage fails the storage prerequisite', async () => {
  const fixture = supportedFixture();
  fixture.capacities['kind-worker'] = 1024;
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(find(report, 'storage').compatible, false);
  assert.equal(find(report, 'storage').details.nodes.find(item => item.node === 'kind-worker').compatible, false);
});

test('missing Chaos Mesh CRD is reported exactly', async () => {
  const fixture = supportedFixture();
  fixture.crds = fixture.crds.filter(item => item.metadata.name !== 'dnschaos.chaos-mesh.org');
  const report = await collectDoctorReport(dependencies(fixture));
  assert.deepEqual(find(report, 'chaos-mesh.crds').details.missing, ['dnschaos.chaos-mesh.org']);
  assert.equal(report.capabilities.dnsChaos, false);
});

test('unsupported architecture fails while supported arm64 truthfully gates native helpers', async () => {
  const fixture = supportedFixture();
  fixture.nodes[0].status.nodeInfo.architecture = 's390x';
  fixture.nodes[0].metadata.labels['kubernetes.io/arch'] = 's390x';
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(find(report, 'architecture').compatible, false);
  assert.deepEqual(find(report, 'architecture').details.cluster.sort(), ['arm64', 's390x']);
});

test('local port conflict reports the exact owner-facing endpoint', async () => {
  const fixture = supportedFixture();
  const report = await collectDoctorReport({
    ...dependencies(fixture),
    checkPorts: async ports => ports.map(port => ({...port, available: port.port !== 3000,
      error: port.port === 3000 ? 'EADDRINUSE' : null})),
  });
  assert.equal(find(report, 'local-ports').compatible, false);
  assert.match(find(report, 'local-ports').message, /127\.0\.0\.1:3000/);
});

test('persistent dashboard supervisors own their loopback listeners without hiding other conflicts', async () => {
  const fixture = supportedFixture();
  const report = await collectDoctorReport({
    ...dependencies(fixture),
    checkPorts: async ports => ports.map(port => ({...port, available: false, error: 'listener-present'})),
    checkManagedPorts: async () => new Set(['grafana', 'chaos-dashboard']),
  });
  const ports = find(report, 'local-ports');
  assert.equal(ports.compatible, false);
  assert.doesNotMatch(ports.message, /127\.0\.0\.1:(3000|2333)/);
  assert.match(ports.message, /127\.0\.0\.1:8080/);

  const onlyManaged = await collectDoctorReport({
    ...dependencies(fixture),
    checkPorts: async declared => declared.map(port => ({...port,
      available: !['grafana', 'chaos-dashboard'].includes(port.name),
      error: ['grafana', 'chaos-dashboard'].includes(port.name) ? 'listener-present' : null,
    })),
    checkManagedPorts: async () => new Set(['grafana', 'chaos-dashboard']),
  });
  assert.equal(find(onlyManaged, 'local-ports').compatible, true);
});

test('missing image and optional Metrics API are distinguished', async () => {
  const fixture = supportedFixture();
  delete fixture.images['stacks-core-attacknet:main'];
  for (const node of fixture.nodes) node.status.images = node.status.images.filter(image => !image.names.includes('stacks-core-attacknet:main'));
  for (const node of fixture.nodes) fixture.containerImages[node.metadata.name] = fixture.containerImages[node.metadata.name]
    .split('\n').filter(name => !name.endsWith('/stacks-core-attacknet:main')).join('\n');
  fixture.metrics = null;
  const report = await collectDoctorReport(dependencies(fixture));
  assert.equal(find(report, 'images').status, 'fail');
  assert.equal(find(report, 'kubernetes.metrics-api').status, 'warn');
  assert.equal(report.capabilities.metricsApi, false);
});

test('a Docker-only local tag does not prove kind can resolve it', async () => {
  const fixture = supportedFixture();
  fixture.images['local-only:test'] = {Id: 'sha256:local'};
  const report = await collectDoctorReport({...dependencies(fixture), images: ['local-only:test']});
  assert.equal(find(report, 'images').compatible, false);
  assert.equal(find(report, 'images').details.images[0].docker, true);
  assert.equal(find(report, 'images').details.images[0].resolution, 'docker-daemon-only');
});

test('kind image-name normalization and immutable remote references are explicit', async () => {
  const fixture = supportedFixture();
  for (const node of fixture.nodes) node.status.images.push({names: ['docker.io/library/local-loaded:test']});
  const loaded = await collectDoctorReport({...dependencies(fixture), images: ['local-loaded:test']});
  assert.equal(find(loaded, 'images').compatible, true);
  assert.equal(find(loaded, 'images').details.images[0].resolution, 'loaded-on-every-node');

  const digest = `ghcr.io/stacks-network/attacknet@sha256:${'a'.repeat(64)}`;
  const remote = await collectDoctorReport({...dependencies(fixture), images: [digest]});
  assert.equal(find(remote, 'images').compatible, true);
  assert.equal(find(remote, 'images').details.images[0].resolution, 'remote-immutable');
});

test('kind containerd remains authoritative when kubelet truncates its image inventory', async () => {
  const fixture = supportedFixture();
  for (const node of fixture.nodes) node.status.images = [];
  const report = await collectDoctorReport({...dependencies(fixture), images: ['stacks-hacknet-io-pressure:dev']});
  const result = find(report, 'images').details.images[0];
  assert.equal(result.available, true);
  assert.deepEqual(result.loadedOnNodes.sort(), ['kind-control-plane', 'kind-worker']);
  assert.deepEqual(new Set(Object.values(result.nodeInventorySources)), new Set(['kind-containerd-and-kubelet']));
});

test('--json returns the complete report and usage errors exit 2', async () => {
  const result = await runDoctor(['--json'], dependencies(supportedFixture()));
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.schemaVersion, 1);
  assert.deepEqual(parsed.declared.images, DOCTOR_CONTRACT.images);
  assert.equal(parsed.checks.length > 10, true);

  const usage = await runDoctor(['--yaml'], dependencies(supportedFixture()));
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /usage: attacknet doctor \[--json\]/);
});
