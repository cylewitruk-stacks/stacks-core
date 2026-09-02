import assert from 'node:assert/strict';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validateControllerLiveArtifact} from './release-1-a2-evidence.mjs';
import {
  A4_ARTIFACTS, assembleReleaseOneA4Evidence, validateA4RuntimeBinding,
  validateA4Verification,
} from './release-1-a4-evidence.mjs';
import {buildReleaseOneA4Packet} from './release-1-a4-packet.mjs';
import {A4_CHECK_IDS} from './release-1-a4-verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./release-1-a4-contract.json', import.meta.url), 'utf8'));
const candidateRevision = 'a'.repeat(40);
const operatorContextTree = 'c'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const result = extra => ({
  schema: 'stacks-attacknet-release-1-a2-result/v1',
  candidateRevision,
  outcome: 'Passed',
  ...extra,
});

function verification() {
  return {
    schema: 'stacks-attacknet-release-1-a4-verification/v1',
    candidateRevision,
    outcome: 'Passed',
    kubernetesVersion: '1.36.2',
    checks: A4_CHECK_IDS.map(id => ({
      id,
      status: 'passed',
      exitCode: 0,
      command: id,
      durationMs: 1,
      startedAt: '2026-08-25T00:00:00.000Z',
      outputDigest: digest('b'),
      stdout: '',
      stderr: '',
    })),
  };
}

function campaignStatus() {
  return {
    phase: 'Passed',
    reason: 'Recovered',
    actualInjection: {kind: 'NetworkChaos'},
    effectResults: [{outcome: 'Proven'}],
    recoveryResults: [{outcome: 'Proven'}],
    cleanup: {absent: true, allRecovered: true},
  };
}

function liveArtifacts() {
  const operatorImage = {index: digest('1'), runtime: digest('2')};
  const runOperatorImage = {index: digest('3'), runtime: digest('4')};
  const probeImage = {index: digest('5'), runtime: digest('6')};
  const nodes = ['control-plane', 'worker', 'worker2'].map(name => ({
    name, operatingSystem: 'linux', architecture: 'arm64',
  }));
  const loadedImages = [operatorImage.index, runOperatorImage.index, probeImage.index]
    .flatMap(hostImageID => nodes.map(node => ({node: node.name, hostImageID, verified: true})));
  return {
    topologyLive: result({
      initial: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('c'), generation: 1, readyActors: 2, desiredActors: 2},
      withdrawn: {phase: 'Reconciling', inventoryReady: false, generation: 2},
      mutated: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('d'), generation: 2, readyActors: 2, desiredActors: 2},
      restored: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('e'), generation: 3, readyActors: 2, desiredActors: 2},
      candidateRuntime: {
        sourceRevision: candidateRevision, worktreeClean: true, operatorContextTree,
        platform: 'linux/arm64',
        images: {operator: operatorImage, runOperator: runOperatorImage, probe: probeImage},
        admittedControllers: [
          {component: 'operator', pod: 'operator-1', podUID: 'operator-uid', node: 'worker',
            declaredImage: 'operator:local', ready: true, runtimeMatched: true,
            indexAnnotationMatched: true, buildAnnotation: operatorImage.index,
            runtimeImageID: operatorImage.runtime, expectedRuntimeImageID: operatorImage.runtime},
          {component: 'run-operator', pod: 'run-1', podUID: 'run-uid', node: 'worker2',
            declaredImage: 'run:local', ready: true, runtimeMatched: true,
            indexAnnotationMatched: true, buildAnnotation: runOperatorImage.index,
            runtimeImageID: runOperatorImage.runtime, expectedRuntimeImageID: runOperatorImage.runtime},
        ],
        admittedProbes: [{actor: 'dependent', pod: 'dependent-0', podUID: 'probe-uid',
          node: 'worker2', declaredImage: 'probe:local', ready: true, runtimeMatched: true,
          runtimeImageID: probeImage.runtime, expectedRuntimeImageID: probeImage.runtime}],
        kindImageLoad: {outcome: 'Loaded', nodes, images: loadedImages},
      },
    }),
    reversibleFaultLive: result({
      preconditionObservation: {phase: 'Pending', reason: 'WaitingForEnvironmentLease', message: 'waiting', mutationCreated: false},
      campaign: campaignStatus(),
      mutationPresentAfterTerminal: false,
    }),
    podKillLive: result({
      campaign: campaignStatus(),
      admittedPodUID: 'old-pod',
      replacementPodUID: 'new-pod',
      replacementRuntimeImageID: digest('f'),
      mutationPresentAfterTerminal: false,
    }),
    restartResumeLive: result({
      controllerUIDBefore: 'old-controller',
      controllerUIDAfter: 'new-controller',
      run: {
        phase: 'Passed', reason: 'SequenceCompleted', decisions: [{execution: 'child'}],
        cleanup: {required: true, completed: true},
      },
      childCampaign: campaignStatus(),
    }),
    cleanTeardown: result({
      remainingCounts: Object.fromEntries([
        'stacksNetworks', 'faultCampaigns', 'attacknetRuns', 'statefulSets', 'pods',
        'pvcs', 'leases', 'chaosResources', 'clockPolicies', 'pressurePods',
      ].map(key => [key, 0])),
    }),
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a4-'));
  const input = join(root, 'raw');
  const live = join(root, 'live');
  mkdirSync(input, {recursive: true});
  const patch = Buffer.from('A4 candidate patch\n');
  writeFileSync(join(input, A4_ARTIFACTS.candidateDiff), patch);
  writeFileSync(join(input, A4_ARTIFACTS.verification), `${JSON.stringify(verification())}\n`);
  writeFileSync(join(input, A4_ARTIFACTS.attacknetCheck), `${JSON.stringify({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: candidateRevision,
    status: 'passed',
  })}\n`);
  writeFileSync(join(input, A4_ARTIFACTS.hacknetCheck), `${JSON.stringify({
    schemaVersion: 'stacks-hacknet-offline-check-result/v1', sourceRevision: candidateRevision,
    status: 'passed', requiredChecks: ['operator'], optionalChecks: [
      {name: 'go', status: 'passed'}, {name: 'envtest', status: 'passed'},
      {name: 'helm', status: 'passed'},
    ],
  })}\n`);
  for (const [key, value] of Object.entries(liveArtifacts())) {
    writeFileSync(join(input, A4_ARTIFACTS[key]), `${JSON.stringify(value)}\n`);
  }
  const summary = assembleReleaseOneA4Evidence({
    candidateRevision,
    inputDirectory: input,
    outputDirectory: live,
    archiveLocation: 'file:///review/release-1-a4-evidence.tar.gz',
    root,
    expectedOperatorContextTree: operatorContextTree,
  });
  const contractTarget = join(root, 'contrib/attacknet/release');
  mkdirSync(contractTarget, {recursive: true});
  cpSync(new URL('./release-1-a4-contract.json', import.meta.url), join(contractTarget, 'release-1-a4-contract.json'));
  return {root, live, summary, patch};
}

function packetInventory() {
  return contract.requiredInventory.map((id, index) => ({
    id,
    kind: id.startsWith('test:') ? 'test'
      : id.startsWith('evidence:') ? 'evidence'
        : id.startsWith('diff:') ? 'diff'
          : id.includes('.md') ? 'document' : 'source',
    path: `review/item-${index}`,
    digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
}

test('A4 verification requires every complete named check', () => {
  const value = verification();
  assert.equal(validateA4Verification(value, candidateRevision), value);
  value.checks.pop();
  assert.throws(() => validateA4Verification(value, candidateRevision), /whole-hacknet-check/);
});

test('shared live validators reject a behaviorally incomplete A4 artifact', () => {
  const value = liveArtifacts().reversibleFaultLive;
  assert.equal(validateControllerLiveArtifact('reversibleFaultLive', value, candidateRevision), value);
  value.campaign.recoveryResults = [];
  assert.throws(
    () => validateControllerLiveArtifact('reversibleFaultLive', value, candidateRevision),
    /recoveries/,
  );
});

test('A4 runtime binding requires candidate images on every admitted kind node', () => {
  const value = liveArtifacts().topologyLive;
  assert.equal(
    validateA4RuntimeBinding(value, candidateRevision, operatorContextTree),
    value,
  );
  value.candidateRuntime.kindImageLoad.images.pop();
  assert.throws(
    () => validateA4RuntimeBinding(value, candidateRevision, operatorContextTree),
    /not verified on every kind node/,
  );
});

test('A4 assembler produces a portable candidate-bound evidence archive', () => {
  const value = fixture();
  assert.equal(value.summary.candidateRevision, candidateRevision);
  assert.deepEqual(Object.keys(value.summary.artifacts).sort(), Object.keys(A4_ARTIFACTS).sort());
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
});

test('A4 packet is Full and binds the exact candidate diff', () => {
  const value = fixture();
  const candidate = {
    sourceRevision: candidateRevision,
    commitPending: false,
    dirtyPatchDigest: digest('0'),
  };
  const packet = buildReleaseOneA4Packet({
    root: value.root,
    candidate,
    liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: []},
    candidateDiff: value.patch,
    expectedOperatorContextTree: operatorContextTree,
  });
  assert.equal(packet.reviewId, 'release-1-amendment-a4-controller-composability');
  assert.equal(packet.tier, 'Full');
  assert.equal(packet.compatibility.runtimeBehaviorChanged, false);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(() => buildReleaseOneA4Packet({
    root: value.root,
    candidate,
    liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: []},
    candidateDiff: Buffer.from('wrong patch\n'),
    expectedOperatorContextTree: operatorContextTree,
  }), /candidate diff artifact/);
});

test('A4 contract makes the composability boundaries and full evidence load-bearing', () => {
  for (const id of [
    'candidate:contrib/helm/hacknet/operator/ARCHITECTURE.md',
    'candidate:contrib/helm/hacknet/operator/internal/fault/mechanism.go',
    'candidate:contrib/helm/hacknet/operator/internal/run/schedule_store.go',
    'diff:candidate-controller-composability',
    'evidence:reversible-fault-live',
    'evidence:restart-resume-live',
    'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});
