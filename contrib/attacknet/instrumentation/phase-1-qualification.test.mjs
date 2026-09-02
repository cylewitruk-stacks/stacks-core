import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {sha256Value} from './artifact-digest.mjs';
import {
  initializeDescriptor, readDescriptor, validateDescriptor, writeDescriptor,
} from './run-descriptor.mjs';
import {
  finalizeQualification, preflightQualification, qualificationRequired,
} from './phase-1-qualification.mjs';

const sha = letter => `sha256:${letter.repeat(64)}`;
const bytesDigest = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
function json(path, value) { writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`); return path; }
function seal(value, field) { value[field] = sha256Value(value); return value; }

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-phase-1-qualification-'));
  const requestedImage = 'stacks-core-attacknet:content-abc';
  const inventoryBytes = readFileSync(new URL('./inventory-v1.json', import.meta.url));
  const inventory = JSON.parse(inventoryBytes);
  const contextDigest = sha('9');
  const signerConfig = 'node_host = "node"\n';
  const build = seal({
    schema: 'stacks-attacknet-image-build-record/v1', pipelineId: 'release', profileId: 'merged-main',
    source: {kind: 'releasedGitRef', revision: '1'.repeat(40), dirty: false, untrackedFiles: [], sourceStateDigest: sha('d')},
    imageDigest: sha('a'), immutableRef: `stacks-core-attacknet@${sha('a')}`, localRef: requestedImage, stagedContextDigest: contextDigest,
    buildInvocation: {digest: sha('e')},
    imageIdentity: {imageIndexDigest: sha('a'), platformManifestDigest: sha('b'), runtimeConfigDigest: sha('c'), expectedRuntimeImageID: sha('c'), platform: 'linux/amd64'},
    instrumentationSourceAudit: {
      method: 'exact-source-string-audit/v1', inventoryVersion: inventory.inventoryVersion,
      inventoryDigest: bytesDigest(inventoryBytes), sourceContextDigest: contextDigest,
      familiesPresent: inventory.families.map(item => item.id),
    },
  }, 'recordDigest');
  const buildPath = json(join(root, 'build.json'), build);
  const smoke = seal({
    schema: 'stacks-attacknet-config-startup-smoke/v1', result: 'Passed', profileId: 'merged-main',
    requestedImage, actor: 'signer-1', role: 'signer', binary: 'stacks-signer', command: ['docker'],
    config: {sourceDigest: bytesDigest(signerConfig), parserInputDigest: bytesDigest(signerConfig)},
  }, 'evidenceDigest');
  const smokePath = json(join(root, 'smoke.json'), smoke);
  const input = {
    schemaVersion: 1, manifestId: 'phase-1-run', inventoryVersion: 'workstream-m/1', profiles: [{
      id: 'merged-main', requestedImage, actors: [{name: 'signer-1', role: 'signer'}],
      defaultProvenance: 'merged', signals: {}, buildRecordPath: buildPath,
      configSmokeEvidencePaths: [smokePath], admissionEvidencePaths: [], effectiveEventDispatchMode: 'unknown',
    }],
  };
  const inputPath = json(join(root, 'input.json'), input);
  const manifest = {
    schemaVersion: 1, network: 'net', namespace: 'ns', actors: [{
      service: 'signer-1', role: 'signer', requestedImage,
      instrumentation: {profile: 'merged-main', provenance: 'merged'},
    }, {
      service: 'bitcoin', role: 'infrastructure', requestedImage: 'bitcoin:local',
      instrumentation: {profile: 'unmodified', provenance: 'unavailable'},
    }],
  };
  const manifestPath = json(join(root, 'manifest.json'), manifest);
  const network = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    metadata: {name: 'net', uid: 'network-uid', generation: 2},
    spec: {actors: [{name: 'signer-1', image: requestedImage, config: {key: 'signer.toml', files: {'signer.toml': signerConfig}}}]},
    status: {phase: 'Ready', observedGeneration: 2, actors: [{name: 'signer-1', image: requestedImage, ready: true}]},
  };
  const networkPath = json(join(root, 'network.json'), network);
  const pod = {
    metadata: {name: 'net-signer-1-0', uid: 'pod-uid', labels: {'testing.stacks.org/network': 'net', 'testing.stacks.org/actor': 'signer-1'}},
    spec: {nodeName: 'worker-1', containers: [{name: 'actor', image: requestedImage}]},
    status: {phase: 'Running', conditions: [{type: 'Ready', status: 'True'}], containerStatuses: [{name: 'actor', image: `docker.io/library/${requestedImage}`, imageID: sha('c'), ready: true, restartCount: 0}]},
  };
  const podsPath = json(join(root, 'pods.json'), {apiVersion: 'v1', kind: 'List', items: [pod]});
  const metricsDirectory = join(root, 'metrics');
  const required = inventory.families.filter(item => item.roles.includes('signer'));
  const metrics = required.map(item => {
    if (item.type === 'counter') return `${item.family}_total 1`;
    if (item.type === 'histogram') return `${item.family}_bucket{le="1"} 1`;
    return `${item.family} 1`;
  }).join('\n');
  mkdirSync(metricsDirectory);
  writeFileSync(join(metricsDirectory, 'signer-1.prom'), `${metrics}\n`);
  const topologyPath = json(join(root, 'topology.json'), {network: 'net'});
  const configPath = join(root, 'signer.toml'); writeFileSync(configPath, 'node_host = "node"\n');
  const requestedPath = json(join(root, 'requested.json'), network);
  const descriptor = initializeDescriptor({
    runId: 'phase-1-test', seed: 'seed', seedAlgorithm: 'test/v1', createdAt: '2026-08-18T00:00:00Z',
    sourceRevision: '2'.repeat(40), sourceDirty: false, topologyPath, configPaths: [configPath],
    requestedManifestPath: requestedPath, runtimeBackend: 'kubernetes',
    images: [{scope: 'signer-1', requestedRef: requestedImage}],
    nondeterminism: {statement: 'test', disclosed: []},
  });
  const descriptorPath = join(root, 'run.json'); writeDescriptor(descriptorPath, descriptor);
  return {root, input, inputPath, manifest, manifestPath, networkPath, podsPath, descriptorPath, metricsDirectory};
}

test('unavailable manifests do not opt into qualification', () => {
  const data = fixture();
  data.manifest.actors[0].instrumentation = {profile: 'unmodified', provenance: 'unavailable'};
  assert.equal(qualificationRequired(data.manifest), false);
});

test('preflight accepts only sealed build and per-actor smoke gaps awaiting admission', () => {
  const data = fixture();
  const plan = preflightQualification(data.manifestPath, data.inputPath);
  assert.equal(plan.expectedActors[0].name, 'signer-1');
  assert.equal(plan.instrumentationFamilyExpectations[0].actor, 'signer-1');
  assert.equal(plan.instrumentationFamilyExpectations[0].families.length, 18);
  assert.ok(plan.instrumentationFamilyExpectations[0].families.every(item => item.provenance === 'merged'));
  const wrong = structuredClone(data.manifest);
  wrong.actors[0].requestedImage = 'stacks:wrong';
  const wrongPath = json(join(data.root, 'wrong.json'), wrong);
  assert.throws(() => preflightQualification(wrongPath, data.inputPath), /image differs/);
  data.input.profiles[0].configSmokeEvidencePaths = [];
  const incompletePath = json(join(data.root, 'incomplete.json'), data.input);
  assert.throws(() => preflightQualification(data.manifestPath, incompletePath), /configuration-startup smoke/);
});

test('mixed actor provenance summarizes differing applicable family provenance', () => {
  const data = fixture();
  data.input.profiles[0].signals.M01 = 'unavailable';
  json(data.inputPath, data.input);
  data.manifest.actors[0].instrumentation.provenance = 'mixed';
  json(data.manifestPath, data.manifest);
  const plan = preflightQualification(data.manifestPath, data.inputPath);
  assert.equal(plan.expectedActors[0].provenance, 'mixed');
  const familyProvenance = new Map(plan.instrumentationFamilyExpectations[0].families.map(item => [item.id, item.provenance]));
  assert.equal(familyProvenance.get('M01'), 'unavailable');
  assert.equal(familyProvenance.get('M02'), 'merged');

  data.manifest.actors[0].instrumentation.provenance = 'merged';
  json(data.manifestPath, data.manifest);
  assert.throws(() => preflightQualification(data.manifestPath, data.inputPath), /provenance does not match/);
});

test('runtime qualification emits exact admission evidence and attaches an exportable acceptance manifest', () => {
  const data = fixture();
  const planPath = json(join(data.root, 'plan.json'), preflightQualification(data.manifestPath, data.inputPath));
  const outputDirectory = join(data.root, 'evidence');
  const result = finalizeQualification({
    planPath, manifestPath: data.manifestPath, inputPath: data.inputPath,
    networkPath: data.networkPath, podsPath: data.podsPath,
    descriptorPath: data.descriptorPath, outputDirectory, metricsDirectory: data.metricsDirectory,
  });
  assert.equal(result.acceptanceReady, true);
  const capabilities = JSON.parse(readFileSync(result.capabilitiesPath, 'utf8'));
  assert.equal(capabilities.acceptanceReady, true);
  assert.equal(capabilities.profiles[0].admissions[0].podUID, 'pod-uid');
  const descriptor = readDescriptor(data.descriptorPath);
  assert.equal(descriptor.inputs.instrumentation.manifestDigest, capabilities.manifestDigest);
  assert.ok(descriptor.inputs.instrumentation.evidenceArtifacts.length >= 4);
  assert.equal(validateDescriptor(descriptor, {verifyFiles: true}), true);
});

test('runtime qualification rejects changed preflight inputs and duplicate actor Pods', () => {
  const data = fixture();
  const planPath = json(join(data.root, 'plan.json'), preflightQualification(data.manifestPath, data.inputPath));
  writeFileSync(data.inputPath, `${readFileSync(data.inputPath, 'utf8')} `);
  assert.throws(() => finalizeQualification({
    planPath, manifestPath: data.manifestPath, inputPath: data.inputPath,
    networkPath: data.networkPath, podsPath: data.podsPath,
    descriptorPath: data.descriptorPath, outputDirectory: join(data.root, 'changed'), metricsDirectory: data.metricsDirectory,
  }), /changed after qualification preflight/);

  const duplicate = fixture();
  const duplicatePlan = json(join(duplicate.root, 'plan.json'), preflightQualification(duplicate.manifestPath, duplicate.inputPath));
  const podList = JSON.parse(readFileSync(duplicate.podsPath, 'utf8'));
  podList.items.push(structuredClone(podList.items[0]));
  podList.items[1].metadata.name = 'net-signer-1-1';
  podList.items[1].metadata.uid = 'pod-uid-2';
  json(duplicate.podsPath, podList);
  assert.throws(() => finalizeQualification({
    planPath: duplicatePlan, manifestPath: duplicate.manifestPath, inputPath: duplicate.inputPath,
    networkPath: duplicate.networkPath, podsPath: duplicate.podsPath,
    descriptorPath: duplicate.descriptorPath, outputDirectory: join(duplicate.root, 'duplicate'), metricsDirectory: duplicate.metricsDirectory,
  }), /exactly one admitted Pod.*found 2/);
});

test('preflight pins every referenced build, patch, and smoke artifact through finalize', () => {
  const data = fixture();
  const planPath = json(join(data.root, 'plan.json'), preflightQualification(data.manifestPath, data.inputPath));
  writeFileSync(data.input.profiles[0].configSmokeEvidencePaths[0], '{}\n');
  assert.throws(() => finalizeQualification({
    planPath, manifestPath: data.manifestPath, inputPath: data.inputPath,
    networkPath: data.networkPath, podsPath: data.podsPath, descriptorPath: data.descriptorPath,
    outputDirectory: join(data.root, 'changed-reference'), metricsDirectory: data.metricsDirectory,
  }), /config-smoke.*changed after qualification preflight/);
});

test('qualification rejects config and runtime metric claims that do not match the admitted actor', () => {
  const configMismatch = fixture();
  const planPath = json(join(configMismatch.root, 'plan.json'), preflightQualification(configMismatch.manifestPath, configMismatch.inputPath));
  const network = JSON.parse(readFileSync(configMismatch.networkPath, 'utf8'));
  network.spec.actors[0].config.files['signer.toml'] = 'different = true\n';
  json(configMismatch.networkPath, network);
  assert.throws(() => finalizeQualification({
    planPath, manifestPath: configMismatch.manifestPath, inputPath: configMismatch.inputPath,
    networkPath: configMismatch.networkPath, podsPath: configMismatch.podsPath, descriptorPath: configMismatch.descriptorPath,
    outputDirectory: join(configMismatch.root, 'config-mismatch'), metricsDirectory: configMismatch.metricsDirectory,
  }), /smoke does not match admitted config/);

  const missingMetric = fixture();
  const missingPlan = json(join(missingMetric.root, 'plan.json'), preflightQualification(missingMetric.manifestPath, missingMetric.inputPath));
  writeFileSync(join(missingMetric.metricsDirectory, 'signer-1.prom'), 'stacks_signer_runloop_ready 1\n');
  assert.throws(() => finalizeQualification({
    planPath: missingPlan, manifestPath: missingMetric.manifestPath, inputPath: missingMetric.inputPath,
    networkPath: missingMetric.networkPath, podsPath: missingMetric.podsPath, descriptorPath: missingMetric.descriptorPath,
    outputDirectory: join(missingMetric.root, 'missing-metric'), metricsDirectory: missingMetric.metricsDirectory,
  }), /runtime metric evidence.*did not pass/);
});
