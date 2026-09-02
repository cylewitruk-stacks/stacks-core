import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  A11_ARTIFACTS, A11_ASSERTIONS, validateA11ConfigurationControl,
  validateA11CandidateBuild, validateA11Descriptor, validateA11Network, validateA11Run,
  validateA11LiveResult, validateA11ProtocolControl, validateA11SourceDrift, validateA11TelemetryControl,
  validateA11Upgrade,
} from './evidence.mjs';
import {
  prepareQualificationOutput, stageQualificationInputs, stageQualificationManifests,
  requireDistinctRuntimeProfiles, upgradeDecisionEvidence,
} from './qualification/live.mjs';
import {
  A11_ATTESTATION_SCHEMA, A11_CHECK_IDS, A11_PARENT_REVISION,
  A11_VERIFICATION_SCHEMA, validateA11CandidateAttestation, validateA11Verification,
} from './verify.mjs';

const tree = 'a'.repeat(40);
const sha = character => `sha256:${character.repeat(64)}`;
const observedAt = '2026-08-29T00:00:00.000Z';
const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');

function profile(name, imageID, sourceKind = 'localGit') {
  return {
    name, sourceKind, repository: sourceKind === 'prebuilt' ? undefined : 'https://example.test/repo.git',
    requestedRef: 'main', revision: sourceKind === 'prebuilt' ? undefined : imageID[7].repeat(40),
    image: `local/${name}:sealed`, imageID, configDigest: sha('c'), configSmoke: 'passed',
    provenanceDigest: sha(name === 'stable' ? 'd' : 'e'), expectation: 'compatible',
  };
}

function descriptorEvidence() {
  const descriptor = {
    schemaVersion: 'stacks-attacknet-version-descriptor/v1', matrixId: 'matrix', platform: 'linux/arm64',
    planDigest: sha('1'), profiles: [profile('candidate', sha('2')), profile('stable', sha('3'), 'remoteGit')],
    assignments: [
      {actor: 'follower-1', profile: 'candidate'},
      {actor: 'miner-1', profile: 'stable'},
      {actor: 'signer-node-1', profile: 'stable'},
    ],
    assignment: {algorithm: 'sha256-actor-bucket/v1', seed: 'seed', actors: [], overrides: [], weighted: []},
    digest: sha('4'),
  };
  return {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-descriptor-evidence/v1', descriptor};
}

function snapshot(kind, resource) {
  return {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status', resourceDigest: sha('9'),
    resource: {apiVersion: 'testing.stacks.org/v1beta1', kind, ...resource},
  };
}

function networkEvidence(name, descriptor) {
  const profiles = new Map(descriptor.profiles.map(item => [item.name, item]));
  return snapshot('StacksNetwork', {
    metadata: {name, uid: `${name}-uid`, generation: 2,
      annotations: {'testing.stacks.org/version-descriptor-digest': descriptor.digest}},
    status: {
      phase: 'Ready', inventoryReady: true, observedGeneration: 2, inventoryDigest: sha('5'),
      actors: descriptor.assignments.map((assignment, index) => ({
        name: assignment.actor, ready: true, identityReady: true,
        image: profiles.get(assignment.profile).image,
        runtimeImageID: `containerd://${profiles.get(assignment.profile).imageID}`,
        podName: `actor-${index}-0`, podUID: `pod-${index}`, statefulSetUID: `statefulset-${index}`,
        currentRevision: `revision-${index}`, updateRevision: `revision-${index}`,
      })),
    },
  });
}

test('A11 contract binds all live evidence classes', () => {
  const contract = JSON.parse(readFileSync(resolve(amendmentDirectory, 'contract.json'), 'utf8'));
  assert.equal(contract.reviewId, 'release-1-amendment-a11-mixed-version-upgrades');
  assert.equal(contract.tier, 'Full');
  for (const id of [
    'evidence:source-drift-control', 'evidence:configuration-control', 'evidence:telemetry-control',
    'evidence:protocol-control',
    'evidence:static-descriptor', 'evidence:primary-upgrade', 'evidence:replay-upgrade',
    'evidence:archive', 'attestation:signed-candidate',
  ]) assert.ok(contract.requiredInventory.includes(id), `contract omits ${id}`);
  assert.equal(Object.keys(A11_ARTIFACTS).length, 22);
  assert.equal(A11_ASSERTIONS.length, 12);
});

test('live qualification proves primary and replay crossed the sealed reward-cycle boundary', () => {
  const result = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-live-qualification/v1', outcome: 'Passed',
    capturedAt: observedAt, architecture: 'arm64', kindNodes: ['control-plane', 'worker', 'worker2'],
    boundary: {type: 'reward-cycle', firstHeight: 0, cycleLength: 20, triggerHeight: 239,
      boundaryHeight: 241, cadenceTransitionHeight: 235, bootstrapCadence: '5s', boundaryCadence: '15s',
      primaryCadenceTransition: {height: 235, cadence: '15s'},
      replayCadenceTransition: {height: 236, cadence: '15s'},
      observedBefore: 235, observedAtTrigger: 239, observedAfter: 250,
      replayObservedAtTrigger: 239, replayObservedAfter: 251},
    artifactDigests: Object.fromEntries(['build', 'network', 'primary', 'upgrade', 'replay', 'teardown']
      .map((name, index) => [name, sha(String(index + 1))])),
  };
  assert.doesNotThrow(() => validateA11LiveResult(result, tree));
  assert.throws(() => validateA11LiveResult({...result, boundary: {...result.boundary, observedAfter: 240}}, tree), /boundary/);
  assert.throws(() => validateA11LiveResult({...result, boundary: {...result.boundary, replayObservedAfter: 240}}, tree), /boundary/);
});

test('source, configuration, telemetry, and protocol controls fail closed', () => {
  const source = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-source-drift-control/v1',
    outcome: 'Passed', classification: 'SourceRevisionMismatch',
    clusterMutationsBefore: 0, clusterMutationsAfter: 0, imageCountBefore: 2, imageCountAfter: 2,
    expectedRevision: '1'.repeat(40), resolvedRevision: '2'.repeat(40),
  };
  assert.doesNotThrow(() => validateA11SourceDrift(source, tree));
  assert.throws(() => validateA11SourceDrift({...source, clusterMutationsAfter: 1}, tree), /fail-closed/);

  const configuration = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-configuration-control/v1',
    outcome: 'Passed', classification: 'ConfigurationUnsupported', protocolIncompatible: false,
    networkMutated: false, expectedConfigDigest: sha('3'), observedConfigDigest: sha('4'),
  };
  assert.doesNotThrow(() => validateA11ConfigurationControl(configuration, tree));
  assert.throws(() => validateA11ConfigurationControl({...configuration, protocolIncompatible: true}, tree), /distinct/);

  const telemetry = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-telemetry-control/v1',
    outcome: 'Passed', runPhase: 'Inconclusive', classification: 'TelemetryUnavailable',
    protocolIncompatible: false, profile: 'stable', missingFamily: 'M09',
    mutations: 0, runUID: 'run-uid', runReason: 'ProtocolBaselineInconclusive',
  };
  assert.doesNotThrow(() => validateA11TelemetryControl(telemetry, tree));
  assert.throws(() => validateA11TelemetryControl({...telemetry, runPhase: 'Failed'}, tree), /telemetry/);

  const protocol = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-protocol-control/v1', outcome: 'Passed',
    classification: 'ProtocolAssertionViolated', versionCompatibilityConclusion: 'not-established',
    beforeInventoryDigest: sha('a'), afterInventoryDigest: sha('b'), rollbackRestored: true, campaign: {status: {
      phase: 'Failed', reason: 'ProtocolAssertionViolated', rollbackComplete: true,
      stageAssertions: {outcome: 'Violated', results: [{reason: 'RequiredProgressAbsent'}]},
      baselineInventory: rollbackInventory(sha('a'), 'pod-before'),
      currentInventory: rollbackInventory(sha('b'), 'pod-after'),
      identityTransitions: [{campaign: 'rollback', previousDigest: sha('c'), currentDigest: sha('b')}],
    }},
  };
  assert.doesNotThrow(() => validateA11ProtocolControl(protocol, tree));
  assert.throws(() => validateA11ProtocolControl({...protocol, versionCompatibilityConclusion: 'incompatible'}, tree), /protocol control/);
  assert.throws(() => validateA11ProtocolControl({...protocol, rollbackRestored: false}, tree), /protocol control/);
  const wrongImage = structuredClone(protocol);
  wrongImage.campaign.status.currentInventory.actors[0].runtimeImageID = sha('f');
  assert.throws(() => validateA11ProtocolControl(wrongImage, tree), /protocol control/);
});

function rollbackInventory(digest, podUID) {
  return {
    schemaVersion: 'stacks-network-admitted-inventory/v1', observedGeneration: 1, digest,
    burnchainTopology: {digest: sha('d')},
    actors: [{
      controllerRevision: 'network-follower-abc', name: 'follower-1', podName: 'network-follower-1-0',
      podUID, requestedImage: 'stacks:stable', role: 'follower', runtimeImageID: sha('e'),
      serviceName: 'network-follower-1', statefulSetName: 'network-follower-1',
      statefulSetUID: 'statefulset-uid', configDigest: sha('9'),
    }],
  };
}

test('candidate build binds the pinned ready Chaos Mesh dependency', () => {
  const nodes = ['control-plane', 'worker-1', 'worker-2'];
  const image = name => ({name, image: `${name}:sealed`, imageID: sha('1'),
    provenanceDigest: sha('2'), loadedNodes: nodes});
  const build = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-candidate-build/v1',
    cluster: {provider: 'kind', architecture: 'arm64', nodes},
    dependencies: {chaosMesh: {
      schemaVersion: 'stacks-attacknet-a11-chaos-mesh-install/v1', version: '2.8.3',
      namespace: 'chaos-mesh', release: 'chaos-mesh', status: 'deployed',
      pods: [{name: 'chaos-controller', uid: 'pod-uid', ready: true, images: ['chaos-mesh:2.8.3']}],
    }},
    controlPlane: {images: [image('topology'), image('run'), image('clock')]},
    profiles: [image('stable'), image('candidate')],
  };
  assert.doesNotThrow(() => validateA11CandidateBuild(build, tree));
  build.dependencies.chaosMesh.pods[0].ready = false;
  assert.throws(() => validateA11CandidateBuild(build, tree), /three-node arm64 cluster/);
});

test('descriptor and static network prove a true mixed-version cohort', () => {
  const evidence = descriptorEvidence();
  const descriptor = validateA11Descriptor(evidence, tree);
  assert.equal(requireDistinctRuntimeProfiles(descriptor, ['stable', 'candidate']), true);
  const duplicateImage = structuredClone(descriptor);
  duplicateImage.profiles[1].imageID = duplicateImage.profiles[0].imageID;
  assert.throws(() => requireDistinctRuntimeProfiles(duplicateImage, ['stable', 'candidate']), /distinct runtime image/);
  const network = networkEvidence('a11-static', descriptor);
  assert.doesNotThrow(() => validateA11Network(network, tree, descriptor, 'a11-static'));
  network.resource.status.actors[0].runtimeImageID = `containerd://${sha('3')}`;
  assert.throws(() => validateA11Network(network, tree, descriptor, 'a11-static'), /runtime image ID/);

  network.resource.status.actors[0].runtimeImageID = `containerd://${sha('2')}`;
  descriptor.configurations = [{actor: 'follower-1', profile: 'candidate', configDigest: sha('8')}];
  assert.throws(() => validateA11Network(network, tree, descriptor, 'a11-static'), /config digest <absent>/);
  network.resource.status.actors[0].configDigest = sha('8');
  assert.doesNotThrow(() => validateA11Network(network, tree, descriptor, 'a11-static'));
  network.resource.status.actors[0].updateRevision = 'stale-revision';
  assert.throws(() => validateA11Network(network, tree, descriptor, 'a11-static'), /StatefulSet rollout identity/);
});

test('upgrade and run validators require topology-owned completed transitions', () => {
  const stageNames = ['follower-raw-config', 'signer-node', 'signer', 'miner'];
  const actors = ['follower-2', 'signer-node-1', 'signer-1', 'miner-1'];
  const status = {phase: 'Passed', observedGeneration: 1, completedAt: observedAt, currentStage: 3,
    baselineInventory: {digest: sha('3')}, currentInventory: {digest: sha('4')},
    appliedAssignments: actors.map(actor => ({actor, profile: 'candidate'})),
    identityTransitions: stageNames.map((campaign, index) => ({campaign, actors: [actors[index]],
      previousDigest: sha(String(index + 1)), currentDigest: sha(String(index + 2)), observedAt}))};
  const decision = {executionId: 'roll-candidate', child: 'upgrade', childUid: 'upgrade-uid',
    phase: 'Passed', completedAt: observedAt, source: 'template', evidence: {kind: 'UpgradeCampaign', status}};
  const runSource = snapshot('AttacknetRun', {metadata: {name: 'run', uid: 'run-uid'},
    status: {decisions: [decision]}});
  const campaign = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a11-upgrade-decision/v1',
    network: 'a11-upgrade', runUID: 'run-uid', runResourceDigest: runSource.resourceDigest, decision};
  assert.deepEqual(upgradeDecisionEvidence(runSource, tree, 'a11-upgrade'), campaign);
  assert.doesNotThrow(() => validateA11Upgrade(campaign, tree, 'a11-upgrade', runSource));
  const detached = structuredClone(campaign);
  detached.decision.childUid = 'substituted-uid';
  assert.throws(() => validateA11Upgrade(detached, tree, 'a11-upgrade', runSource), /durable run status/);
  campaign.decision.evidence.status.identityTransitions[0].currentDigest = sha('1');
  assert.throws(() => validateA11Upgrade(campaign, tree, 'a11-upgrade', runSource), /invalid identity/);

  const run = snapshot('AttacknetRun', {
    metadata: {name: 'run'}, spec: {networkRef: 'a11-upgrade', seed: 'seed'},
    status: {phase: 'Passed', cleanup: {completed: true},
      decisions: [{executionId: 'upgrade', phase: 'Passed'}],
      resolvedCampaigns: [{name: 'upgrade', kind: 'UpgradeCampaign'}]},
  });
  assert.doesNotThrow(() => validateA11Run(run, tree, 'a11-upgrade'));
});

test('verification and signed-candidate attestation bind the same tree', () => {
  const verification = {
    schema: A11_VERIFICATION_SCHEMA, qualifiedTree: tree, parentRevision: A11_PARENT_REVISION,
    patchDigest: sha('6'), outcome: 'Passed', recordedAt: observedAt,
    checks: A11_CHECK_IDS.map(id => ({id, status: 'passed', command: id, cwd: '.',
      startedAt: observedAt, durationMs: 1, exitCode: 0, outputDigest: sha('7'), stdout: '', stderr: ''})),
  };
  assert.doesNotThrow(() => validateA11Verification(verification, tree));
  verification.checks.pop();
  assert.throws(() => validateA11Verification(verification, tree), /missing/);

  const attestation = {
    schema: A11_ATTESTATION_SCHEMA, candidateRevision: 'b'.repeat(40), candidateTree: tree,
    parentRevision: A11_PARENT_REVISION, patchDigest: sha('6'), evidenceSummaryDigest: sha('8'),
    signatureVerified: true, recordedAt: observedAt,
  };
  assert.doesNotThrow(() => validateA11CandidateAttestation(attestation,
    {qualifiedTree: tree, patchDigest: sha('6')}, sha('8')));
});

test('product docs describe raw config and controller ownership boundaries', () => {
  const concept = readFileSync(resolve(repositoryRoot, 'contrib/attacknet/docs/concepts/mixed-version-images.md'), 'utf8');
  assert.match(concept, /controllers never clone repositories or run builds/i);
  assert.match(concept, /raw ConfigMap or Secret/i);
  assert.match(concept, /topology operator/i);
  assert.match(concept, /ConfigurationUnsupported/);
});

test('maintained qualification inputs use the audited released baseline', () => {
  const plan = readFileSync(resolve(repositoryRoot,
    'contrib/attacknet/examples/matrices/stable-with-candidate.plan.yaml'), 'utf8');
  const liveQualification = readFileSync(resolve(amendmentDirectory, 'qualification/live.mjs'), 'utf8');
  assert.match(plan, /ref: 4\.0\.2/);
  assert.match(liveQualification, /ref: '4\.0\.2'/);
  assert.doesNotMatch(`${plan}\n${liveQualification}`, /4\.0\.3/);
});

test('A11 qualification inputs remain private, complete, and Epoch 4-safe', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-a11-inputs-'));
  try {
    prepareQualificationOutput(join(directory, 'output'));
    const manifests = stageQualificationManifests(directory);
    assert.deepEqual(readdirSync(manifests).sort(), [
      'network.yaml', 'policy.yaml', 'telemetry-run.yaml', 'telemetry-template.yaml',
    ]);
    const inputs = stageQualificationInputs(directory);
    const resources = JSON.parse(readFileSync(inputs.resourcePath, 'utf8'));
    const follower = readFileSync(inputs.configPath, 'utf8');
    assert.equal(resources.items.length, 5);
    assert.equal(resources.items.find(item => item.metadata.name === 'a11-telemetry-dark-config')
      ?.data?.config, 'intentionally-uninstrumented\n');
    assert.match(follower, /epoch_name = "4\.0"\nstart_height = 1000005/);
    assert.doesNotMatch(follower, /epoch_name = "4\.0"\nstart_height = 245/);
    assert.equal(inputs.configDigest, `sha256:${createHash('sha256').update(follower).digest('hex')}`);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});

test('A11 qualification resources pass the production typed CLI decoder', () => {
  const qualification = fileURLToPath(new URL('./qualification/', import.meta.url));
  const files = readdirSync(qualification).filter(name => name.endsWith('.yaml')).sort();
  assert.deepEqual(files, ['network.yaml', 'policy.yaml', 'telemetry-run.yaml', 'telemetry-template.yaml']);
  for (const file of files) {
    execFileSync('go', ['run', './cmd/attacknet', 'validate', '--file', join(qualification, file),
      '--namespace', 'hacknet-system', '--output', 'json'], {
      cwd: join(repositoryRoot, 'contrib/helm/hacknet/operator'),
      env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/tmp/attacknet-a11-go-build'}, stdio: 'pipe',
    });
  }
});
