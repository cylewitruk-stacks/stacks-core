import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {A2_ARTIFACTS, assembleReleaseOneA2Evidence} from './release-1-a2-evidence.mjs';

const candidate = 'a'.repeat(40);
const digest = letter => `sha256:${letter.repeat(64)}`;

function passed(extra = {}) {
  return {
    schema: 'stacks-attacknet-release-1-a2-result/v1',
    candidateRevision: candidate,
    outcome: 'Passed',
    ...extra,
  };
}

function commandEvidence(ids, extra = {}) {
  return passed({
    checks: ids.map(id => ({
      id, status: 'passed', command: `verify ${id}`, exitCode: 0, durationMs: 1,
      startedAt: '2026-08-25T12:00:00Z', outputDigest: digest('a'), stdout: '', stderr: '',
    })),
    ...extra,
  });
}

function campaign(extra = {}) {
  return {
    phase: 'Passed', reason: 'EffectAndRecoveryProven',
    actualInjection: {allInjectedObserved: true},
    effectResults: [{outcome: 'Proven'}], recoveryResults: [{outcome: 'Proven'}],
    cleanup: {absent: true, allRecovered: true},
    ...extra,
  };
}

function fixtures() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-a2-evidence-'));
  const input = join(root, 'input');
  const output = join(root, 'output');
  mkdirSync(input, {recursive: true});
  const values = {
    equivalenceReport: {schemaVersion: 'stacks-attacknet-controller-equivalence-report/v1', candidateRevision: candidate},
    goVerify: commandEvidence([
      'go-build', 'go-format', 'go-generate-clean', 'go-vet', 'go-unit', 'go-race',
    ]),
    envtest: commandEvidence(['kubernetes-1.36-envtest'], {kubernetesVersion: '1.36.2'}),
    helmRender: commandEvidence([
      'helm-lint', 'helm-render', 'crd-contracts', 'rbac-security-contracts',
    ]),
    topologyLive: passed({
      initial: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('1'), generation: 1, readyActors: 3, desiredActors: 3},
      withdrawn: {phase: 'Progressing', inventoryReady: false, generation: 2, readyActors: 2, desiredActors: 3},
      mutated: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('2'), generation: 2, readyActors: 3, desiredActors: 3},
      restored: {phase: 'Ready', inventoryReady: true, inventoryDigest: digest('3'), generation: 3, readyActors: 3, desiredActors: 3},
    }),
    reversibleFaultLive: passed({
      preconditionObservation: {
        phase: 'Pending', reason: 'WaitingForEnvironmentLease',
        message: 'no active environment lease exists', mutationCreated: false,
      },
      campaign: campaign(), mutationPresentAfterTerminal: false,
    }),
    podKillLive: passed({
      campaign: campaign(), admittedPodUID: 'old', replacementPodUID: 'new',
      replacementRuntimeImageID: digest('4'), mutationPresentAfterTerminal: false,
    }),
    restartResumeLive: passed({
      controllerUIDBefore: 'old-controller', controllerUIDAfter: 'new-controller',
      run: {
        phase: 'Passed', reason: 'SequenceCompleted', decisions: [{}],
        scheduleRef: {digest: digest('5')}, cleanup: {required: true, completed: true},
      },
      childCampaign: campaign(),
    }),
    cleanTeardown: passed({remainingCounts: {
      stacksNetworks: 0, faultCampaigns: 0, attacknetRuns: 0, statefulSets: 0,
      pods: 0, pvcs: 0, leases: 0, chaosResources: 0, clockPolicies: 0, pressurePods: 0,
    }}),
  };
  for (const [key, filename] of Object.entries(A2_ARTIFACTS)) {
    writeFileSync(join(input, filename), key === 'candidateDiff' ? 'diff bytes\n' : `${JSON.stringify(values[key])}\n`);
  }
  writeFileSync(join(input, 'offline-result.json'), '{}\n');
  writeFileSync(join(input, 'hacknet-result.json'), '{}\n');
  return {root, input, output, values};
}

test('A2 evidence assembler creates one candidate-bound portable archive', () => {
  const value = fixtures();
  const summary = assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  });
  assert.equal(summary.candidateRevision, candidate);
  assert.equal(summary.assertions.length, 9);
  assert.equal(summary.artifacts.topologyLive.archiveEntry, 'artifacts/topology-live.json');
  const members = readFileSync(join(value.output, 'archive-index.json'), 'utf8');
  assert.match(members, /artifacts\/restart-resume-live\.json/);
});

test('A2 evidence assembler rejects a false topology-withdrawal claim', () => {
  const value = fixtures();
  value.values.topologyLive.withdrawn.inventoryReady = true;
  value.values.topologyLive.withdrawn.inventoryDigest = digest('9');
  writeFileSync(join(value.input, A2_ARTIFACTS.topologyLive), `${JSON.stringify(value.values.topologyLive)}\n`);
  assert.throws(() => assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  }), /retained a supposedly authoritative inventory digest/);
});

test('A2 evidence assembler requires the fail-closed environment-lease wait', () => {
  const value = fixtures();
  value.values.reversibleFaultLive.preconditionObservation.mutationCreated = true;
  writeFileSync(
    join(value.input, A2_ARTIFACTS.reversibleFaultLive),
    `${JSON.stringify(value.values.reversibleFaultLive)}\n`,
  );
  assert.throws(() => assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  }), /did not prove a fail-closed environment-lease wait/);
});

test('A2 evidence assembler rejects a terminal run without completed cleanup', () => {
  const value = fixtures();
  value.values.restartResumeLive.run.cleanup.completed = false;
  writeFileSync(
    join(value.input, A2_ARTIFACTS.restartResumeLive),
    `${JSON.stringify(value.values.restartResumeLive)}\n`,
  );
  assert.throws(() => assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  }), /does not prove terminal child cleanup/);
});

test('A2 evidence assembler rejects a restart claim without a replaced controller', () => {
  const value = fixtures();
  value.values.restartResumeLive.controllerUIDAfter = value.values.restartResumeLive.controllerUIDBefore;
  writeFileSync(
    join(value.input, A2_ARTIFACTS.restartResumeLive),
    `${JSON.stringify(value.values.restartResumeLive)}\n`,
  );
  assert.throws(() => assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  }), /did not replace the run controller Pod/);
});

test('A2 evidence assembler rejects an asserted command result missing a required check', () => {
  const value = fixtures();
  value.values.goVerify.checks = value.values.goVerify.checks.filter(check => check.id !== 'go-race');
  writeFileSync(join(value.input, A2_ARTIFACTS.goVerify), `${JSON.stringify(value.values.goVerify)}\n`);
  assert.throws(() => assembleReleaseOneA2Evidence({
    candidateRevision: candidate, inputDirectory: value.input, outputDirectory: value.output,
    archiveLocation: 'attacknet-evidence://test/a2', root: value.root,
  }), /missing required check go-race/);
});
