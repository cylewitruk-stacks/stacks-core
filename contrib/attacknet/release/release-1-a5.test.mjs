import assert from 'node:assert/strict';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  A5_ARTIFACTS, assembleReleaseOneA5Evidence, validateA5Artifact,
  validateA5Verification,
} from './release-1-a5-evidence.mjs';
import {buildReleaseOneA5Packet} from './release-1-a5-packet.mjs';
import {A5_CHECK_IDS} from './release-1-a5-verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./release-1-a5-contract.json', import.meta.url), 'utf8'));
const candidateRevision = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const networkUID = 'network-uid';
const inventoryDigest = digest('1');
const stacksRuntime = digest('2');

function verification() {
  return {
    schema: 'stacks-attacknet-release-1-a5-verification/v1',
    candidateRevision,
    outcome: 'Passed',
    kubernetesVersion: '1.36.2',
    checks: A5_CHECK_IDS.map(id => ({
      id, status: 'passed', exitCode: 0, command: id, durationMs: 1,
      startedAt: '2026-08-26T00:00:00.000Z', outputDigest: digest('3'), stdout: '', stderr: '',
    })),
  };
}

function snapshot(kind, spec, status, metadata = {}) {
  return {
    schemaVersion: 'stacks-attacknet-resource-snapshot/v1',
    scope: 'single-resource-status',
    resourceDigest: digest('4'),
    resource: {
      apiVersion: 'testing.stacks.org/v1beta1', kind,
      metadata: {name: 'accepted-28', namespace: 'attacknet', uid: networkUID, generation: 1, ...metadata},
      spec, status,
    },
  };
}

function runSnapshot(name) {
  return snapshot('AttacknetRun', {}, {
    phase: 'Passed', reason: 'ScheduleCompleted', cleanup: {completed: true},
  }, {name, uid: `${name}-uid`});
}

function fixtureValues() {
  const nodes = ['control-plane', 'worker', 'worker2'];
  const imageIDs = [stacksRuntime, digest('5'), digest('6')];
  const actors = [
    ...Array.from({length: 3}, (_, index) => ({name: `miner-${index + 1}`, role: 'miner'})),
    ...Array.from({length: 5}, (_, index) => ({name: `follower-${index + 1}`, role: 'follower'})),
    ...Array.from({length: 10}, (_, index) => ({name: `signer-node-${index + 1}`, role: 'companion'})),
  ].map(actor => ({...actor, runtimeImageID: stacksRuntime, ready: true}));
  return {
    verification: verification(),
    attacknetCheck: {
      schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: candidateRevision,
      status: 'passed',
    },
    hacknetCheck: {
      schemaVersion: 'stacks-hacknet-offline-check-result/v1', sourceRevision: candidateRevision,
      status: 'passed', requiredChecks: ['operator'], optionalChecks: [
        {name: 'go', status: 'passed'}, {name: 'envtest', status: 'passed'},
        {name: 'helm', status: 'passed'},
      ],
    },
    localInstall: {
      schemaVersion: 'stacks-attacknet-a5-local-install-evidence/v1', candidateRevision,
      actorImages: {stacksCoreRuntimeImageID: stacksRuntime},
      operatorImages: {topologyRuntimeImageID: digest('5'), runRuntimeImageID: digest('6')},
      kindImageLoad: {
        outcome: 'Loaded', nodes: nodes.map(name => ({name})),
        images: imageIDs.flatMap(runtimeImageID => nodes.map(node => ({node, runtimeImageID, verified: true}))),
      },
    },
    burnchainPolicy: {
      candidateRevision,
      snapshot: snapshot('BurnchainPolicy', {bootstrapHeight: 202}, {
        phase: 'Ready', observedGeneration: 1, observedHeight: 218, admittedNetworkUID: networkUID,
      }),
      assertions: {pauseObserved: true, resumeObserved: true, cadenceObserved: true, exactFlashObserved: true},
    },
    concurrentFault: {
      schemaVersion: 'stacks-attacknet-a5-concurrent-fault-evidence/v1', candidateRevision,
      overlapObserved: true, aggregateSafetyAdmitted: true, controllerRestartObserved: true,
      unsafeUnionRejected: true,
      campaigns: ['network', 'dns'].map(name => snapshot('FaultCampaign', {}, {
        phase: 'Passed', cleanup: {absent: true},
      }, {name, uid: `${name}-uid`})),
    },
    runOverlapRestart: {
      schemaVersion: 'stacks-attacknet-a5-run-overlap-restart-evidence/v1', candidateRevision,
      freshNetworkIdentity: true, cleanupCompleted: true, overlapObserved: true,
      controllerRestartObserved: true, runs: [runSnapshot('source'), runSnapshot('resumed')],
    },
    replayMinimization: {
      schemaVersion: 'stacks-attacknet-a5-replay-minimization-evidence/v1', candidateRevision,
      freshNetworkIdentity: true, cleanupCompleted: true, expectedReplayObserved: true,
      removalOnlyMinimizationObserved: true, runs: [runSnapshot('replay'), runSnapshot('minimize')],
    },
    acceptedNetwork: {
      candidateRevision,
      snapshot: snapshot('StacksNetwork', {}, {
        phase: 'Ready', inventoryReady: true, readyActors: 30, desiredActors: 30,
        observedGeneration: 1, inventoryDigest, actors,
      }),
    },
    acceptedCohort: {
      candidateRevision,
      observation: {
        schemaVersion: 'stacks-attacknet-chain-cohort-observation/v1', network: 'accepted-28',
        actorCount: 18, stacksTipHeight: 12,
        assertions: {allActorsResponded: true, allBurnHeightsEqual: true,
          allStacksTipsNonzero: true, allStacksHeightsEqual: true, allStacksTipHashesEqual: true},
      },
    },
    cleanTeardown: {
      schemaVersion: 'stacks-attacknet-a5-clean-teardown-evidence/v1', candidateRevision,
      cleanupCompleted: true, remainingCounts: {pods: 0, pvcs: 0, campaigns: 0, chaos: 0},
    },
    incident: {
      schemaVersion: 'stacks-attacknet-incident-evidence/v1',
      network: {name: 'accepted-28', uid: networkUID, inventoryReady: true, inventoryDigest},
      artifacts: [{path: 'resources/stacksnetwork.json', digest: digest('7')}],
      errors: [], omissions: [],
    },
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a5-'));
  const input = join(root, 'raw');
  const live = join(root, 'live');
  mkdirSync(input, {recursive: true});
  const values = fixtureValues();
  const patch = Buffer.from('A5 candidate patch\n');
  writeFileSync(join(input, A5_ARTIFACTS.candidateDiff), patch);
  for (const [key, filename] of Object.entries(A5_ARTIFACTS)) {
    if (key !== 'candidateDiff') writeFileSync(join(input, filename), `${JSON.stringify(values[key])}\n`);
  }
  mkdirSync(join(input, 'accepted-incident'), {recursive: true});
  writeFileSync(join(input, 'accepted-incident', 'manifest.json'), `${JSON.stringify(values.incident)}\n`);
  const summary = assembleReleaseOneA5Evidence({
    candidateRevision, inputDirectory: input, outputDirectory: live,
    archiveLocation: 'file:///review/release-1-a5-evidence.tar.gz', root,
  });
  const contractTarget = join(root, 'contrib/attacknet/release');
  mkdirSync(contractTarget, {recursive: true});
  cpSync(new URL('./release-1-a5-contract.json', import.meta.url), join(contractTarget, 'release-1-a5-contract.json'));
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

test('A5 verification requires every complete named check', () => {
  const value = verification();
  assert.equal(validateA5Verification(value, candidateRevision), value);
  value.checks.pop();
  assert.throws(() => validateA5Verification(value, candidateRevision), /whole-hacknet-check/);
});

test('accepted-scale evidence rejects Kubernetes-ready protocol divergence', () => {
  const value = fixtureValues().acceptedCohort;
  assert.equal(validateA5Artifact('acceptedCohort', value, candidateRevision), value);
  value.observation.assertions.allStacksTipHashesEqual = false;
  assert.throws(() => validateA5Artifact('acceptedCohort', value, candidateRevision), /convergence/);
});

test('A5 assembler produces a portable candidate-bound evidence archive', () => {
  const value = fixture();
  assert.equal(value.summary.candidateRevision, candidateRevision);
  assert.deepEqual(
    Object.keys(value.summary.artifacts).sort(),
    [...Object.keys(A5_ARTIFACTS), 'acceptedIncident'].sort(),
  );
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
});

test('A5 packet is Full and binds the exact product diff', () => {
  const value = fixture();
  const candidate = {sourceRevision: candidateRevision, commitPending: false, dirtyPatchDigest: digest('0')};
  const packet = buildReleaseOneA5Packet({
    root: value.root, candidate, liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(), candidateScope: {parent: 'f'.repeat(40), paths: [], deleted: []},
    candidateDiff: value.patch,
  });
  assert.equal(packet.reviewId, 'release-1-amendment-a5-api-productization');
  assert.equal(packet.tier, 'Full');
  assert.equal(packet.compatibility.runtimeBehaviorChanged, true);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(() => buildReleaseOneA5Packet({
    root: value.root, candidate, liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(), candidateScope: {parent: 'f'.repeat(40), paths: [], deleted: []},
    candidateDiff: Buffer.from('wrong patch\n'),
  }), /candidate diff artifact/);
});

test('A5 contract makes every product boundary and live proof load-bearing', () => {
  for (const id of [
    'candidate:contrib/helm/hacknet/operator/api/v1beta1/stacksnetwork_types.go',
    'candidate:contrib/helm/hacknet/operator/internal/burnchainpolicy/reconciler.go',
    'candidate:contrib/attacknet/repository-boundary.test.mjs',
    'diff:candidate-api-productization',
    'evidence:concurrent-fault',
    'evidence:accepted-cohort',
    'evidence:accepted-incident',
    'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});
