#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  mkdirSync, readFileSync, readdirSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {
  A11_ARTIFACTS, validateA11CandidateBuild, validateA11ConfigurationControl,
  validateA11Descriptor, validateA11Import, validateA11LiveQualification,
  validateA11Network, validateA11ProtocolControl, validateA11Run, validateA11SourceDrift,
  validateA11TelemetryControl, validateA11Upgrade, rollbackIdentityRestored,
} from '../evidence.mjs';
import {isMainModule, isMaterializedSource, runMaterializedEntrypoint} from '../qualified-source.mjs';
import {requireA11QualifiedTree} from '../verify.mjs';

const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
const credentialFixture = join(repositoryRoot,
  'contrib/attacknet/test/fixtures/equivalence/v1alpha1/topology/baseline-probes.input.json');
const namespace = 'hacknet-system';
const terminal = new Set(['Passed', 'Failed', 'Inconclusive', 'Paused']);
const cadenceTransitionHeight = 235;
const triggerHeight = 239;
const boundaryHeight = 241;
const boundaryCadence = '15s';
const signerSetReadyHeight = 220;
const protocolControlName = 'a11-protocol-control';
const chaosMeshVersion = '2.8.3';
const profiles = Object.freeze({stable: 'stacks-core-attacknet:a11-stable', candidate: 'stacks-core-attacknet:a11-candidate'});
const scenarios = Object.freeze({
  static: {network: 'a11-static', policy: 'a11-static-policy'},
  primary: {network: 'a11-upgrade', policy: 'a11-policy', template: 'a11-roll-candidate', run: 'a11-upgrade-run'},
  replay: {network: 'a11-replay', policy: 'a11-replay-policy', template: 'a11-replay-roll', run: 'a11-replay-run'},
});

function fail(message) { throw new Error(message); }
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}
function sleep(milliseconds) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds); }

function command(executable, arguments_, {
  cwd = repositoryRoot, env = process.env, input, allowFailure = false, timeout = 180_000,
} = {}) {
  const result = spawnSync(executable, arguments_, {
    cwd, env, input, encoding: 'utf8', timeout, maxBuffer: 128 << 20,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result;
}
function parsed(executable, arguments_, options) {
  const result = command(executable, arguments_, options);
  try { return JSON.parse(result.stdout); }
  catch (error) { fail(`${executable} ${arguments_.join(' ')} returned invalid JSON: ${error.message}\n${result.stdout}`); }
}
function kubectl(arguments_, options) { return command(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, options); }
function kubectlJSON(arguments_) { return JSON.parse(kubectl([...arguments_, '-o', 'json']).stdout); }
function optional(kind, name) {
  const result = kubectl(['-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json']);
  return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
}
function waitFor(label, read, predicate, seconds = 600) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = read();
    if (predicate(last)) return last;
    sleep(1000);
  }
  fail(`${label} did not converge in ${seconds}s: ${JSON.stringify(last?.status ?? last)}`);
}

function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  const localKind = context.startsWith('kind-')
    || context === 'docker-desktop' && nodes.every(node => node.metadata?.name?.startsWith('desktop-'));
  if (!localKind || nodes.length !== 3
    || nodes.some(node => node.status?.nodeInfo?.architecture !== 'arm64'
      || !node.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'))) {
    fail('A11 requires three Ready arm64 kind nodes');
  }
  return {provider: 'kind', context, architecture: 'arm64', nodes: nodes.map(node => node.metadata.name).sort()};
}
function submitPath(attacknet, path) {
  return parsed(attacknet, ['submit', '--file', path, '--namespace', namespace, '--output', 'json']);
}
function submitObject(attacknet, value, directory, label) {
  const path = join(directory, `${label}.json`);
  writeJSON(path, value);
  return submitPath(attacknet, path);
}
function normalizedResource(attacknet, path) {
  return parsed(attacknet, ['validate', '--file', path, '--namespace', namespace, '--output', 'json']);
}
function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', '--timeout', '10m', kind, name],
    {allowFailure: true, timeout: 660_000});
  if (result.status !== 0 && !`${result.stderr}${result.stdout}`.toLowerCase().includes('not found')) {
    fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
  }
}

function networkReady(name) {
  return waitFor(`StacksNetwork ${name}`, () => optional('stacksnetwork.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.inventoryReady === true
      && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.inventoryDigest ?? ''), 1_500);
}
function policyReady(name, minimumHeight = signerSetReadyHeight) {
  return waitFor(`BurnchainPolicy ${name}`, () => optional('burnchainpolicy.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.observedGeneration === value.metadata.generation
      && value.status.observedHeight >= minimumHeight
      && /^sha256:[0-9a-f]{64}$/.test(value.status.appliedPolicyDigest ?? ''), 1_200);
}
function waitRun(name) {
  return waitFor(`AttacknetRun ${name}`, () => optional('attacknetrun.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
      && (value.status.phase !== 'Passed' || value.status.cleanup?.completed === true), 1_800);
}
function waitUpgrade(name) {
  return waitFor(`UpgradeCampaign ${name}`, () => optional('upgradecampaign.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation, 1_500);
}
function childName(run) { return `${run}-execution-roll-candidate`; }
function snapshotResource(attacknet, kind, name, path, tree) {
  mkdirSync(dirname(path), {recursive: true});
  command(attacknet, ['evidence', 'snapshot', '--namespace', namespace, '--output', path, kind, name]);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  writeJSON(path, {qualifiedTree: tree, ...value});
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Prepare an isolated qualification output without adopting prior evidence. */
export function prepareQualificationOutput(outputDirectory) {
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true, mode: 0o700});
  for (const path of [...Object.values(A11_ARTIFACTS), '.execution']) {
    if (['candidate.patch', 'verification.json', 'attacknet-result.json', 'hacknet-result.json'].includes(path)) continue;
    try { statSync(join(output, path)); fail(`refusing to overwrite A11 evidence ${path}`); }
    catch (error) { if (!String(error.message).includes('ENOENT')) throw error; }
  }
}

/** Copy immutable qualification manifests into the private execution root. */
export function stageQualificationManifests(executionDirectory) {
  const directory = join(resolve(executionDirectory), 'manifests');
  mkdirSync(directory, {recursive: true, mode: 0o700});
  for (const name of readdirSync(qualificationDirectory).filter(value => value.endsWith('.yaml'))) {
    writeFileSync(join(directory, name), readFileSync(join(qualificationDirectory, name)), {mode: 0o600});
  }
  return directory;
}

/** Derive ephemeral credentials and one raw config from the sealed fixture. */
export function stageQualificationInputs(executionDirectory) {
  const fixture = JSON.parse(readFileSync(credentialFixture, 'utf8'));
  const actors = new Map((fixture?.spec?.actors ?? []).map(actor => [actor?.name, actor]));
  const file = (actor, key) => actors.get(actor)?.config?.files?.[key];
  const environment = (actor, key) => actors.get(actor)?.env?.find(item => item?.name === key)?.value;
  const epochFour = '\n[[burnchain.epochs]]\nepoch_name = "4.0"\nstart_height = 245\n';
  const moveEpochFour = value => {
    if (typeof value !== 'string' || value.split(epochFour).length !== 2) fail('sealed config does not contain one Epoch 4 stanza');
    return value.replace(epochFour, '\n[[burnchain.epochs]]\nepoch_name = "4.0"\nstart_height = 1000005\n');
  };
  const miner = moveEpochFour(file('miner-1', 'config.toml'));
  const follower = moveEpochFour(file('follower-1', 'config.toml'));
  const signer = file('signer-1', 'signer.toml');
  const privateKeys = environment('stacker', 'STACKING_KEYS');
  const addresses = environment('stacker', 'STACKING_ADDRESSES');
  if (![signer, privateKeys, addresses].every(value => typeof value === 'string' && value.length > 0)) {
    fail('sealed regtest fixture does not contain the A11 credential contract');
  }
  const secret = (name, stringData) => ({apiVersion: 'v1', kind: 'Secret', metadata: {name, namespace}, type: 'Opaque', stringData});
  const resources = {apiVersion: 'v1', kind: 'List', items: [
    secret('a11-miner-config', {'config.toml': miner}),
    secret('a11-signer-config', {'signer.toml': signer}),
    secret('a11-stacker-credentials', {'private-keys': privateKeys, addresses}),
    {apiVersion: 'v1', kind: 'ConfigMap', metadata: {name: 'a11-raw-follower-config', namespace},
      data: {'config.toml': follower}},
    {apiVersion: 'v1', kind: 'ConfigMap', metadata: {name: 'a11-telemetry-dark-config', namespace},
      data: {config: 'intentionally-uninstrumented\n'}},
  ]};
  const resourcePath = join(resolve(executionDirectory), 'inputs.json');
  const configPath = join(resolve(executionDirectory), 'follower-2-candidate.toml');
  writeJSON(resourcePath, resources);
  writeFileSync(configPath, follower, {mode: 0o600});
  return {resourcePath, configPath, configDigest: digestBytes(Buffer.from(follower))};
}

function countImages() {
  return new Set(command('docker', ['image', 'ls', '--quiet']).stdout.split('\n').filter(Boolean)).size;
}
function countNamedResources() {
  const names = new Set(Object.values(scenarios).flatMap(value => Object.values(value)));
  const kinds = ['stacksnetworks.testing.stacks.org', 'burnchainpolicies.testing.stacks.org',
    'attacknetruns.testing.stacks.org', 'upgradecampaigns.testing.stacks.org'];
  return kinds.reduce((total, kind) => {
    const result = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
    return total + (result.status === 0 && result.stdout.trim()
      ? JSON.parse(result.stdout).items.filter(item => names.has(item.metadata.name)).length : 0);
  }, 0);
}
function prebuiltBitcoinReference() {
  command('docker', ['pull', '--platform', 'linux/arm64', 'bitcoin/bitcoin:25.2'], {timeout: 1_200_000});
  const image = JSON.parse(command('docker', ['image', 'inspect', 'bitcoin/bitcoin:25.2']).stdout)[0];
  const reference = image?.RepoDigests?.find(value => value.startsWith('bitcoin/bitcoin@sha256:'));
  if (!reference) fail('Bitcoin prebuilt image has no immutable repository digest');
  return reference;
}
function writePlan(path, {sourceRoot, configPath, configDigest, prebuilt, wrongRevision = false, wrongConfig = false}) {
  const boundaryAssertions = {timeout: '45s', assertions: [{id: 'boundary-chain-progress', chainProgress: {
    actors: ['follower-1'], chain: 'burnchain', minimumDelta: 1, window: '30s',
  }}]};
  const progressAssertions = {timeout: '40s', assertions: [{id: 'chain-progress', chainProgress: {
    actors: ['follower-1'], chain: 'burnchain', minimumDelta: 1, window: '20s',
  }}]};
  const plan = {
    schemaVersion: 'stacks-attacknet-version-plan/v1', matrixId: 'a11-stable-candidate', platform: 'linux/arm64',
    profiles: [
      {name: 'stable', source: {kind: 'remoteGit', repository: 'https://github.com/stacks-network/stacks-core.git',
        ref: '4.0.2', ...(wrongRevision ? {expectedRevision: '0'.repeat(40)} : {})}, image: profiles.stable,
      build: {dockerfile: 'contrib/attacknet/images/cli/Dockerfile', dockerfileScope: 'host', context: '.'},
      expectation: 'compatible'},
      {name: 'candidate', source: {kind: 'localGit', repository: sourceRoot, ref: 'HEAD'}, image: profiles.candidate,
      build: {dockerfile: 'contrib/attacknet/images/cli/Dockerfile', dockerfileScope: 'host', context: '.'},
      capabilities: ['M01', 'M02', 'M03', 'M04', 'M05', 'M06', 'M07', 'M08', 'M09'], expectation: 'compatible'},
      {name: 'prebuilt-control', source: {kind: 'prebuilt'}, image: prebuilt, expectation: 'unknown'},
    ],
    actors: [
      {name: 'miner-1', role: 'miner'}, {name: 'follower-1', role: 'follower'},
      {name: 'follower-2', role: 'follower'}, {name: 'signer-node-1', role: 'signer-node'},
      {name: 'signer-1', role: 'signer'},
    ],
    configurations: [{actor: 'follower-2', profile: 'candidate', configuration: {
      file: configPath, expectedDigest: wrongConfig ? `sha256:${'0'.repeat(64)}` : configDigest,
      allowUnverified: true, source: {configMapRef: {name: 'a11-raw-follower-config', key: 'config.toml', mountPath: '/etc/stacks'}},
    }}],
    assignment: {defaultProfile: 'stable', seed: 'a11-mixed-version-seed-v1',
      overrides: [{actor: 'follower-1', profile: 'candidate'}],
      weighted: [{profile: 'stable', basisPoints: 10000, roles: ['miner', 'follower', 'signer-node', 'signer']}]},
    upgrade: {name: scenarios.primary.template, networkRef: scenarios.primary.network, rollbackOnFailure: true,
      safety: {maxParallelActors: 1, maxSignerWeightPercent: 100, maxMinerPercent: 100}, stages: [
        {name: 'follower-raw-config', stableFor: '3s', deadline: '3m', actors: [{actor: 'follower-2', profile: 'candidate'}], assertions: boundaryAssertions},
        {name: 'signer-node', stableFor: '3s', deadline: '3m', actors: [{actor: 'signer-node-1', profile: 'candidate'}], assertions: progressAssertions},
        {name: 'signer', stableFor: '3s', deadline: '3m', actors: [{actor: 'signer-1', profile: 'candidate'}], assertions: progressAssertions},
        {name: 'miner', stableFor: '3s', deadline: '3m', actors: [{actor: 'miner-1', profile: 'candidate'}], assertions: progressAssertions},
      ]},
  };
  writeJSON(path, plan);
  return plan;
}

function prepareDescriptor(attacknet, plan, workspace, output) {
  const result = command(attacknet, ['version', 'prepare', '--file', plan, '--workspace', workspace,
    '--recipe-root', repositoryRoot, '--output', output], {timeout: 10_800_000});
  const descriptor = JSON.parse(result.stdout);
  requireDistinctRuntimeProfiles(descriptor, ['stable', 'candidate']);
  return descriptor;
}

/** Require a qualification matrix to contain distinct runtime image bytes. */
export function requireDistinctRuntimeProfiles(descriptor, profileNames) {
  const profilesByName = new Map((descriptor?.profiles ?? []).map(profile => [profile.name, profile]));
  const identities = profileNames.map(name => profilesByName.get(name)?.imageID);
  if (identities.some(identity => !/^sha256:[0-9a-f]{64}$/.test(identity ?? ''))
    || new Set(identities).size !== identities.length) {
    fail(`qualification profiles ${profileNames.join(', ')} do not have distinct runtime image identities`);
  }
  return true;
}
function sourceDriftControl(attacknet, options, executionDirectory, tree, output) {
  const path = join(executionDirectory, 'source-drift-plan.json');
  writePlan(path, {...options, wrongRevision: true});
  const beforeResources = countNamedResources();
  const beforeImages = countImages();
  const result = command(attacknet, ['version', 'prepare', '--file', path, '--workspace', join(executionDirectory, 'versions'),
    '--recipe-root', repositoryRoot, '--output', join(executionDirectory, 'source-drift.json')],
  {allowFailure: true, timeout: 1_200_000});
  const message = `${result.stderr}${result.stdout}`;
  const resolved = message.match(/resolved revision ([0-9a-f]{40}) does not match expected ([0-9a-f]{40})/)?.[1];
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-source-drift-control/v1',
    outcome: result.status !== 0 && resolved ? 'Passed' : 'Failed', classification: 'SourceRevisionMismatch',
    clusterMutationsBefore: beforeResources, clusterMutationsAfter: countNamedResources(),
    imageCountBefore: beforeImages, imageCountAfter: countImages(), expectedRevision: '0'.repeat(40),
    resolvedRevision: resolved ?? '', diagnosticDigest: digestBytes(Buffer.from(message)), observedAt: new Date().toISOString()};
  validateA11SourceDrift(value, tree);
  writeJSON(join(output, A11_ARTIFACTS.sourceDrift), value);
}
function configurationControl(attacknet, options, executionDirectory, tree, output) {
  const path = join(executionDirectory, 'configuration-control-plan.json');
  writePlan(path, {...options, wrongConfig: true});
  const before = countNamedResources();
  const result = command(attacknet, ['version', 'prepare', '--file', path, '--workspace', join(executionDirectory, 'versions'),
    '--recipe-root', repositoryRoot, '--output', join(executionDirectory, 'configuration-control.json')],
  {allowFailure: true, timeout: 10_800_000});
  const message = `${result.stderr}${result.stdout}`;
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-configuration-control/v1',
    outcome: result.status !== 0 && message.includes('ConfigurationUnsupported') ? 'Passed' : 'Failed',
    classification: 'ConfigurationUnsupported', protocolIncompatible: false,
    networkMutated: before !== countNamedResources(), expectedConfigDigest: `sha256:${'0'.repeat(64)}`,
    observedConfigDigest: options.configDigest, diagnosticDigest: digestBytes(Buffer.from(message)), observedAt: new Date().toISOString()};
  validateA11ConfigurationControl(value, tree);
  writeJSON(join(output, A11_ARTIFACTS.configurationControl), value);
}

function installChaosMesh() {
  command('helm', ['repo', 'add', 'chaos-mesh', 'https://charts.chaos-mesh.org', '--force-update'], {timeout: 300_000});
  command('helm', ['repo', 'update', 'chaos-mesh'], {timeout: 300_000});
  command('helm', [
    'upgrade', '--install', 'chaos-mesh', 'chaos-mesh/chaos-mesh',
    '--namespace', 'chaos-mesh', '--create-namespace', '--version', chaosMeshVersion,
    '--set', 'chaosDaemon.runtime=containerd',
    '--set', 'chaosDaemon.socketPath=/run/containerd/containerd.sock',
    '--wait', '--timeout', '10m',
  ], {timeout: 660_000});
  const release = parsed('helm', ['status', 'chaos-mesh', '--namespace', 'chaos-mesh', '--output', 'json']);
  const pods = kubectlJSON(['--namespace', 'chaos-mesh', 'get', 'pods']).items.map(pod => ({
    name: pod.metadata.name, uid: pod.metadata.uid, node: pod.spec.nodeName,
    images: (pod.spec.containers ?? []).map(container => container.image).sort(),
    ready: pod.status.phase === 'Running' && (pod.status.containerStatuses ?? []).length > 0
      && pod.status.containerStatuses.every(container => container.ready === true),
  })).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  if (release.info?.status !== 'deployed' || pods.length === 0 || pods.some(pod => !pod.ready)) {
    fail('pinned Chaos Mesh dependency is not completely Ready');
  }
  return {schemaVersion: 'stacks-attacknet-a11-chaos-mesh-install/v1', version: chaosMeshVersion,
    namespace: 'chaos-mesh', release: 'chaos-mesh', status: release.info.status, pods};
}

function buildCandidate(attacknet, descriptor, importReceipt, cluster, tree, output) {
  const dependencies = {chaosMesh: installChaosMesh()};
  const build = parsed(attacknet, ['image', 'build', '--repo-root', repositoryRoot], {timeout: 3_600_000});
  const install = parsed(attacknet, ['install', 'local', '--chart-dir', chartDirectory, '--namespace', namespace,
    '--release', 'hacknet', '--kind-image-load', 'require', '--force-crd-conflicts'], {timeout: 1_200_000});
  const controlPlane = (build.images ?? []).map(image => ({name: image.purpose, image: image.ref, imageID: image.id,
    provenanceDigest: digestBytes(Buffer.from(JSON.stringify({purpose: image.purpose, ref: image.ref, id: image.id}))),
    loadedNodes: cluster.nodes}));
  const profileImages = descriptor.profiles.map(profile => ({name: profile.name, image: profile.image,
    imageID: profile.imageID, provenanceDigest: profile.provenanceDigest, loadedNodes: cluster.nodes}));
  const value = {schemaVersion: 'stacks-attacknet-a11-candidate-build/v1', qualifiedTree: tree,
    capturedAt: new Date().toISOString(), cluster, dependencies,
    controlPlane: {images: controlPlane, build, install},
    profiles: profileImages, importDigest: digestBytes(Buffer.from(JSON.stringify(importReceipt)))};
  validateA11CandidateBuild(value, tree);
  writeJSON(join(output, A11_ARTIFACTS.candidateBuild), value);
  return value;
}

function descriptorEvidence(descriptor, tree, path) {
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-descriptor-evidence/v1', descriptor};
  validateA11Descriptor(value, tree);
  writeJSON(path, value);
  return value;
}
function importEvidence(receipt, descriptor, tree, path) {
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-import-evidence/v1',
    descriptorDigest: descriptor.digest, import: receipt};
  validateA11Import(value, tree, descriptor);
  writeJSON(path, value);
}

function scenarioResources(attacknet, manifestDirectory, descriptor, names, executionDirectory) {
  const network = normalizedResource(attacknet, join(manifestDirectory, 'network.yaml'));
  network.metadata.name = names.network;
  network.spec.burnchain.policyRef.name = names.policy;
  const basePath = join(executionDirectory, `${names.network}-base.json`);
  writeJSON(basePath, network);
  const rendered = parsed(attacknet, ['version', 'render-static', '--descriptor', join(executionDirectory, 'descriptor.json'),
    '--network', basePath, '--output', 'json']);
  const policy = normalizedResource(attacknet, join(manifestDirectory, 'policy.yaml'));
  policy.metadata.name = names.policy;
  policy.spec.networkRef = names.network;
  return {network: rendered, policy};
}
function applyNetwork(attacknet, resources, executionDirectory, label) {
  submitObject(attacknet, resources.policy, executionDirectory, `${label}-policy`);
  submitObject(attacknet, resources.network, executionDirectory, `${label}-network`);
  networkReady(resources.network.metadata.name);
  return policyReady(resources.policy.metadata.name);
}
function telemetryControl(attacknet, manifestDirectory, executionDirectory, tree, output) {
  submitPath(attacknet, join(manifestDirectory, 'telemetry-template.yaml'));
  submitPath(attacknet, join(manifestDirectory, 'telemetry-run.yaml'));
  const run = waitRun('a11-telemetry-control');
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-telemetry-control/v1',
    outcome: run.status.phase === 'Inconclusive' && (run.status.decisions ?? []).length === 0 ? 'Passed' : 'Failed',
    runPhase: run.status.phase, runReason: run.status.reason, classification: 'TelemetryUnavailable',
    protocolIncompatible: false, profile: 'uninstrumented-control', missingFamily: 'metrics-endpoint',
    runUID: run.metadata.uid, mutations: (run.status.decisions ?? []).length, observedAt: new Date().toISOString()};
  validateA11TelemetryControl(value, tree);
  writeJSON(join(output, A11_ARTIFACTS.telemetryControl), value);
  deleteResource(attacknet, 'AttacknetRun', 'a11-telemetry-control');
  deleteResource(attacknet, 'FaultCampaign', 'a11-telemetry-template');
}

function protocolControl(attacknet, descriptorPath, executionDirectory, tree, output) {
  const before = networkReady(scenarios.static.network).status.inventoryDigest;
  const campaign = upgradeTemplate(attacknet, descriptorPath, scenarios.static.network, protocolControlName);
  campaign.metadata.name = protocolControlName;
  campaign.spec.template = false;
  campaign.spec.rollbackOnFailure = true;
  campaign.spec.stages = [campaign.spec.stages[0]];
  campaign.spec.stages[0].stableFor = '0s';
  campaign.spec.stages[0].deadline = '1m';
  campaign.spec.stages[0].assertions = {timeout: '15s', assertions: [{id: 'impossible-progress', chainProgress: {
    actors: ['follower-1'], chain: 'burnchain', minimumDelta: 1_000_000, window: '5s',
  }}]};
  submitObject(attacknet, campaign, executionDirectory, 'protocol-control');
  const observed = waitUpgrade(protocolControlName);
  const after = networkReady(scenarios.static.network).status.inventoryDigest;
  const rollbackRestored = rollbackIdentityRestored(
    observed.status.baselineInventory, observed.status.currentInventory,
  );
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-protocol-control/v1',
    outcome: observed.status.phase === 'Failed' && observed.status.reason === 'ProtocolAssertionViolated'
      && observed.status.rollbackComplete === true && rollbackRestored ? 'Passed' : 'Failed',
    classification: 'ProtocolAssertionViolated', versionCompatibilityConclusion: 'not-established',
    beforeInventoryDigest: before, afterInventoryDigest: after, rollbackRestored, campaign: observed,
    observedAt: new Date().toISOString()};
  validateA11ProtocolControl(value, tree);
  writeJSON(join(output, A11_ARTIFACTS.protocolControl), value);
  deleteResource(attacknet, 'UpgradeCampaign', protocolControlName);
}

function upgradeTemplate(attacknet, descriptorPath, network, name) {
  const campaign = parsed(attacknet, ['version', 'render-upgrade', '--descriptor', descriptorPath,
    '--namespace', namespace, '--template=true', '--output', 'json']);
  campaign.metadata.name = name;
  campaign.spec.networkRef = network;
  return campaign;
}
function runResource(names, policy) {
  return {apiVersion: 'testing.stacks.org/v1beta1', kind: 'AttacknetRun',
    metadata: {name: names.run, namespace}, spec: {networkRef: names.network,
      seed: 'a11-boundary-upgrade-seed-v1', decisionAlgorithm: 'dependency-trigger-scheduler/v1',
      upgradeCatalog: [{name: 'candidate', upgradeRef: names.template}],
      executions: [{id: 'roll-candidate', upgrade: 'candidate', trigger: {burnHeight: triggerHeight}}],
      budgets: {maxCampaigns: 1, maxWallTimeSeconds: 1800, maxCumulativeFaultSeconds: 1,
        maxActiveFaults: 1, maxSignerImpactPercent: 100, maxBurnchainFaults: 0, maxInconclusiveCampaigns: 1},
      stopPolicy: {onCampaignFailure: 'Stop', onInconclusive: 'Stop', onBudgetExhausted: 'Stop', onSuccess: 'Stop'},
      attributionPolicy: {requiredOnFailure: false, requireIncidentBundle: false,
        allowedTerminalStates: ['Triaged', 'Remediated', 'Inconclusive']},
      replay: {enabled: false, requireSameResolvedImages: true, verifyExpectedFailure: true},
      resume: {enabled: false, requireSameSeed: true, requireSameResolvedImages: true},
      minimization: {enabled: false, strategy: 'DeltaDebug', maxAttempts: 0, requireFreshNetwork: true},
    }};
}
function slowPolicyForBoundary(policy) {
  policyReady(policy, cadenceTransitionHeight);
  kubectl(['-n', namespace, 'patch', 'burnchainpolicy.testing.stacks.org', policy, '--type=merge',
    '-p', JSON.stringify({spec: {cadence: boundaryCadence}})]);
  return waitFor(`BurnchainPolicy ${policy} boundary cadence`,
    () => optional('burnchainpolicy.testing.stacks.org', policy), value =>
      value?.spec?.cadence === boundaryCadence && value.status?.phase === 'Ready'
        && value.status.observedGeneration === value.metadata.generation
        && value.status.observedHeight >= cadenceTransitionHeight, 300);
}
/** Extract the durable upgrade result recorded by the run scheduler. */
export function upgradeDecisionEvidence(runSnapshot, tree, network) {
  const decisions = runSnapshot.resource?.status?.decisions ?? [];
  const decision = decisions.find(value => value.executionId === 'roll-candidate');
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-upgrade-decision/v1',
    network, runUID: runSnapshot.resource?.metadata?.uid,
    runResourceDigest: runSnapshot.resourceDigest, decision};
  validateA11Upgrade(value, tree, network, runSnapshot);
  return value;
}
function runUpgrade(attacknet, descriptorPath, names, executionDirectory, tree, output, prefix) {
  const cadence = slowPolicyForBoundary(names.policy);
  const before = cadence.status.observedHeight;
  if (before >= triggerHeight) fail(`${names.policy} reached the trigger before run admission`);
  submitObject(attacknet, upgradeTemplate(attacknet, descriptorPath, names.network, names.template), executionDirectory, `${prefix}-template`);
  submitObject(attacknet, runResource(names, names.policy), executionDirectory, `${prefix}-run`);
  const run = waitRun(names.run);
  const runSnapshot = snapshotResource(attacknet, 'AttacknetRun', names.run,
    join(output, A11_ARTIFACTS[`${prefix}Run`]), tree);
  validateA11Run(runSnapshot, tree, names.network);
  const upgradeSnapshot = upgradeDecisionEvidence(runSnapshot, tree, names.network);
  writeJSON(join(output, A11_ARTIFACTS[`${prefix}Upgrade`]), upgradeSnapshot);
  const executionChild = childName(names.run);
  waitFor(`UpgradeCampaign ${executionChild} rollback cleanup`,
    () => optional('upgradecampaign.testing.stacks.org', executionChild), value => value === undefined, 600);
  networkReady(names.network);
  const atTrigger = Math.max(triggerHeight, ...(run.status.triggerReceipts ?? [])
    .map(receipt => receipt.observedHeight ?? receipt.height ?? 0));
  return {before, atTrigger, after: policyReady(names.policy).status.observedHeight,
    cadenceTransition: {height: cadence.status.observedHeight, cadence: cadence.spec.cadence}, run};
}
function captureIncident(attacknet, network, output) {
  const path = dirname(join(output, A11_ARTIFACTS.forensicManifest));
  command(attacknet, ['evidence', 'incident', '--namespace', namespace, '--output', path, network], {timeout: 600_000});
  const manifest = JSON.parse(readFileSync(join(path, 'manifest.json'), 'utf8'));
  if (manifest.errors?.length || manifest.omissions?.length) fail('A11 incident bundle is incomplete');
}

function count(kind, predicate) {
  const result = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return 0;
  return JSON.parse(result.stdout).items.filter(predicate).length;
}
function scopeResidue() {
  const networkNames = new Set(Object.values(scenarios).map(value => value.network));
  const policyNames = new Set(Object.values(scenarios).map(value => value.policy));
  const runNames = new Set([scenarios.primary.run, scenarios.replay.run, 'a11-telemetry-control']);
  const templateNames = new Set([scenarios.primary.template, scenarios.replay.template, protocolControlName, 'a11-telemetry-template',
    childName(scenarios.primary.run), childName(scenarios.replay.run)]);
  const inputNames = new Set([
    'a11-miner-config', 'a11-signer-config', 'a11-stacker-credentials',
    'a11-raw-follower-config', 'a11-telemetry-dark-config',
  ]);
  const relevant = item => networkNames.has(item.spec?.networkRef)
    || networkNames.has(item.metadata?.labels?.['testing.stacks.org/network']);
  return {
    networks: count('stacksnetworks.testing.stacks.org', item => networkNames.has(item.metadata.name)),
    policies: count('burnchainpolicies.testing.stacks.org', item => policyNames.has(item.metadata.name)),
    runs: count('attacknetruns.testing.stacks.org', item => runNames.has(item.metadata.name)),
    upgrades: count('upgradecampaigns.testing.stacks.org', item => templateNames.has(item.metadata.name) || relevant(item)),
    campaigns: count('faultcampaigns.testing.stacks.org', relevant), pods: count('pods', relevant),
    pvcs: count('persistentvolumeclaims', relevant), statefulsets: count('statefulsets.apps', relevant),
    services: count('services', relevant), configmaps: count('configmaps', item => inputNames.has(item.metadata.name) || relevant(item)),
    secrets: count('secrets', item => inputNames.has(item.metadata.name) || relevant(item)),
  };
}
function clean(counts) { return Object.values(counts).every(value => value === 0); }
function teardown(attacknet, inputPath, tree, output) {
  for (const names of [scenarios.replay, scenarios.primary]) deleteResource(attacknet, 'AttacknetRun', names.run);
  for (const names of [scenarios.replay, scenarios.primary]) deleteResource(attacknet, 'UpgradeCampaign', names.template);
  deleteResource(attacknet, 'AttacknetRun', 'a11-telemetry-control');
  deleteResource(attacknet, 'FaultCampaign', 'a11-telemetry-template');
  deleteResource(attacknet, 'UpgradeCampaign', protocolControlName);
  for (const names of [scenarios.replay, scenarios.primary, scenarios.static]) {
    deleteResource(attacknet, 'BurnchainPolicy', names.policy);
    deleteResource(attacknet, 'StacksNetwork', names.network);
  }
  kubectl(['delete', '-f', inputPath, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  const counts = waitFor('A11 clean teardown', scopeResidue, clean, 600);
  const value = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-clean-teardown/v1',
    outcome: clean(counts) ? 'Passed' : 'Failed', counts, recordedAt: new Date().toISOString()};
  writeJSON(join(output, A11_ARTIFACTS.cleanTeardown), value);
  if (!clean(counts)) fail(`A11 cleanup retained resources: ${JSON.stringify(counts)}`);
}

/** Qualify A11 on a fresh three-node arm64 kind environment. */
export function runQualification({qualifiedTree, outputDirectory}) {
  requireA11QualifiedTree(qualifiedTree);
  prepareQualificationOutput(outputDirectory);
  for (const name of ['verification', 'candidateDiff', 'attacknetCheck', 'hacknetCheck']) {
    if (!statSync(join(outputDirectory, A11_ARTIFACTS[name])).isFile()) fail(`offline artifact ${A11_ARTIFACTS[name]} is required`);
  }
  const cluster = clusterProfile();
  const executionDirectory = join(resolve(outputDirectory), '.execution');
  mkdirSync(executionDirectory, {recursive: true, mode: 0o700});
  const manifestDirectory = stageQualificationManifests(executionDirectory);
  const inputs = stageQualificationInputs(executionDirectory);
  const attacknet = join(executionDirectory, 'attacknet');
  command('go', ['build', '-o', attacknet, './cmd/attacknet'], {cwd: operatorDirectory, timeout: 600_000});
  const prebuilt = prebuiltBitcoinReference();
  const planOptions = {sourceRoot: repositoryRoot, configPath: inputs.configPath,
    configDigest: inputs.configDigest, prebuilt};
  sourceDriftControl(attacknet, planOptions, executionDirectory, qualifiedTree, outputDirectory);
  const planPath = join(executionDirectory, 'plan.json');
  writePlan(planPath, planOptions);
  const descriptorPath = join(executionDirectory, 'descriptor.json');
  const descriptor = prepareDescriptor(attacknet, planPath, join(executionDirectory, 'versions'), descriptorPath);
  configurationControl(attacknet, planOptions, executionDirectory, qualifiedTree, outputDirectory);
  const importReceipt = parsed(attacknet, ['version', 'load', '--descriptor', descriptorPath, '--mode', 'require'], {timeout: 1_800_000});
  buildCandidate(attacknet, descriptor, importReceipt, cluster, qualifiedTree, outputDirectory);
  descriptorEvidence(descriptor, qualifiedTree, join(outputDirectory, A11_ARTIFACTS.staticDescriptor));
  descriptorEvidence(descriptor, qualifiedTree, join(outputDirectory, A11_ARTIFACTS.upgradeDescriptor));
  importEvidence(importReceipt.import, descriptor, qualifiedTree, join(outputDirectory, A11_ARTIFACTS.staticImport));

  try {
    if (!clean(scopeResidue())) fail(`A11 qualification scope is not clean: ${JSON.stringify(scopeResidue())}`);
    kubectl(['apply', '-f', inputs.resourcePath]);
    const staticResources = scenarioResources(attacknet, manifestDirectory, descriptor, scenarios.static, executionDirectory);
    applyNetwork(attacknet, staticResources, executionDirectory, 'static');
    const staticSnapshot = snapshotResource(attacknet, 'StacksNetwork', scenarios.static.network,
      join(outputDirectory, A11_ARTIFACTS.staticNetwork), qualifiedTree);
    validateA11Network(staticSnapshot, qualifiedTree, descriptor, scenarios.static.network);
    telemetryControl(attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory);
    protocolControl(attacknet, descriptorPath, executionDirectory, qualifiedTree, outputDirectory);
    deleteResource(attacknet, 'BurnchainPolicy', scenarios.static.policy);
    deleteResource(attacknet, 'StacksNetwork', scenarios.static.network);

    const primaryResources = scenarioResources(attacknet, manifestDirectory, descriptor, scenarios.primary, executionDirectory);
    applyNetwork(attacknet, primaryResources, executionDirectory, 'primary');
    const primary = runUpgrade(attacknet, descriptorPath, scenarios.primary, executionDirectory, qualifiedTree, outputDirectory, 'primary');
    const primaryNetwork = snapshotResource(attacknet, 'StacksNetwork', scenarios.primary.network,
      join(outputDirectory, A11_ARTIFACTS.primaryNetwork), qualifiedTree);
    validateA11Network(primaryNetwork, qualifiedTree, descriptor, scenarios.primary.network);
    captureIncident(attacknet, scenarios.primary.network, outputDirectory);
    deleteResource(attacknet, 'AttacknetRun', scenarios.primary.run);
    deleteResource(attacknet, 'UpgradeCampaign', scenarios.primary.template);
    deleteResource(attacknet, 'BurnchainPolicy', scenarios.primary.policy);
    deleteResource(attacknet, 'StacksNetwork', scenarios.primary.network);

    const replayResources = scenarioResources(attacknet, manifestDirectory, descriptor, scenarios.replay, executionDirectory);
    applyNetwork(attacknet, replayResources, executionDirectory, 'replay');
    const replay = runUpgrade(attacknet, descriptorPath, scenarios.replay, executionDirectory, qualifiedTree, outputDirectory, 'replay');
    const replayNetwork = snapshotResource(attacknet, 'StacksNetwork', scenarios.replay.network,
      join(outputDirectory, A11_ARTIFACTS.replayNetwork), qualifiedTree);
    validateA11Network(replayNetwork, qualifiedTree, descriptor, scenarios.replay.network);
    if (primaryNetwork.resource.metadata.uid === replayNetwork.resource.metadata.uid) fail('A11 replay reused the primary network identity');
    teardown(attacknet, inputs.resourcePath, qualifiedTree, outputDirectory);

    const digests = {};
    for (const key of ['candidateBuild', 'staticNetwork', 'primaryRun', 'primaryUpgrade', 'replayRun', 'replayUpgrade']) {
      digests[key] = digestFile(join(outputDirectory, A11_ARTIFACTS[key]));
    }
    const live = {qualifiedTree, schemaVersion: 'stacks-attacknet-a11-live-qualification/v1', outcome: 'Passed',
      capturedAt: new Date().toISOString(), architecture: cluster.architecture, kindNodes: cluster.nodes,
      context: cluster.context, boundary: {type: 'reward-cycle', firstHeight: 0, cycleLength: 20,
        bootstrapCadence: '5s', boundaryCadence, cadenceTransitionHeight,
        primaryCadenceTransition: primary.cadenceTransition, replayCadenceTransition: replay.cadenceTransition,
        triggerHeight, boundaryHeight, observedBefore: primary.before, observedAtTrigger: primary.atTrigger,
        observedAfter: primary.after, replayObservedAtTrigger: replay.atTrigger,
        replayObservedAfter: replay.after}, artifactDigests: digests};
    writeJSON(join(outputDirectory, A11_ARTIFACTS.liveQualification), live);
    validateA11LiveQualification(outputDirectory, qualifiedTree);
  } catch (error) {
    try { teardown(attacknet, inputs.resourcePath, qualifiedTree, outputDirectory); }
    catch (cleanupError) { error.message += `\nCleanup also failed: ${cleanupError.message}`; }
    throw error;
  }
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const qualifiedTree = value('--qualified-tree=');
  const outputDirectory = value('--output=');
  if (!qualifiedTree || !outputDirectory) fail('usage: live.mjs --qualified-tree=TREE --output=PATH');
  if (!isMaterializedSource(repositoryRoot)) {
    return runMaterializedEntrypoint({repositoryRoot, qualifiedTree,
      script: 'contrib/attacknet/release/amendments/a11/qualification/live.mjs',
      arguments_: [`--qualified-tree=${qualifiedTree}`, `--output=${resolve(outputDirectory)}`]});
  }
  return runQualification({qualifiedTree, outputDirectory: resolve(outputDirectory)});
}

if (isMainModule(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
