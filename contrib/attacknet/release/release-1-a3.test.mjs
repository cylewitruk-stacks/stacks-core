import assert from 'node:assert/strict';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validateClockPolicyProof} from './release-1-a3-clock-live.mjs';
import {
  A3_ARTIFACTS, assembleReleaseOneA3Evidence, validateA3Verification,
} from './release-1-a3-evidence.mjs';
import {buildReleaseOneA3Packet} from './release-1-a3-packet.mjs';
import {A3_CHECK_IDS} from './release-1-a3-verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./release-1-a3-contract.json', import.meta.url), 'utf8'));
const candidateRevision = 'a'.repeat(40);
const imageID = `sha256:${'b'.repeat(64)}`;
const imageIndex = `sha256:${'c'.repeat(64)}`;

function clockProof() {
  return {
    schema: 'stacks-attacknet-release-1-a3-clock-policy/v1',
    candidateRevision,
    outcome: 'Passed',
    cluster: {
      context: 'kind-attacknet-a3',
      nodes: ['control-plane', 'worker', 'worker2'].map(name => ({
        name, providerID: `kind://docker/attacknet-a3/${name}`,
        operatingSystem: 'linux', architecture: 'arm64',
      })),
    },
    network: {phase: 'Ready', inventoryReady: true, inventoryDigest: `sha256:${'d'.repeat(64)}`},
    candidateRuntime: {
      runtimeImageID: imageID, expectedRuntimeImageID: imageID,
      buildAnnotation: imageIndex, expectedImageIndex: imageIndex,
      operatorContextTree: 'e'.repeat(40),
    },
    campaign: {
      phase: 'Failed', reason: 'FaultCapabilityUnavailable',
      message: 'follower-1: application clock policy is not globally at zero offset',
      capabilityEvidence: [{supported: false, reason: 'application clock policy is not globally at zero offset'}],
    },
    observedDuringFailure: {target: '+0s\n', control: '+1s\n'},
    cleanup: {campaignAbsent: true, mutationLeaseAbsent: true, policyRestored: true},
  };
}

function verification() {
  return {
    schema: 'stacks-attacknet-release-1-a3-verification/v1',
    candidateRevision,
    outcome: 'Passed',
    kubernetesVersion: '1.36.2',
    checks: A3_CHECK_IDS.map(id => ({
      id, status: 'passed', exitCode: 0, command: id, durationMs: 1,
    })),
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a3-'));
  const input = join(root, 'raw');
  const live = join(root, 'live');
  mkdirSync(input, {recursive: true});
  const patch = Buffer.from('A3 candidate patch\n');
  writeFileSync(join(input, A3_ARTIFACTS.candidateDiff), patch);
  writeFileSync(join(input, A3_ARTIFACTS.verification), `${JSON.stringify(verification())}\n`);
  writeFileSync(join(input, A3_ARTIFACTS.attacknetCheck), `${JSON.stringify({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', sourceRevision: candidateRevision,
    status: 'passed',
  })}\n`);
  writeFileSync(join(input, A3_ARTIFACTS.hacknetCheck), `${JSON.stringify({
    schemaVersion: 'stacks-hacknet-offline-check-result/v1', sourceRevision: candidateRevision,
    status: 'passed', requiredChecks: ['operator'], optionalChecks: [
      {name: 'go', status: 'passed'}, {name: 'envtest', status: 'passed'},
      {name: 'helm', status: 'passed'},
    ],
  })}\n`);
  writeFileSync(join(input, A3_ARTIFACTS.clockPolicyLive), `${JSON.stringify(clockProof())}\n`);
  const summary = assembleReleaseOneA3Evidence({
    candidateRevision, inputDirectory: input, outputDirectory: live,
    archiveLocation: 'file:///review/release-1-a3-evidence.tar.gz', root,
  });
  const contractTarget = join(root, 'contrib/attacknet/release');
  mkdirSync(contractTarget, {recursive: true});
  cpSync(new URL('./release-1-a3-contract.json', import.meta.url), join(contractTarget, 'release-1-a3-contract.json'));
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

test('A3 clock-policy proof requires fail-closed admission and no mutation', () => {
  const value = clockProof();
  assert.equal(validateClockPolicyProof(value), value);
  value.observedDuringFailure.target = '-30s\n';
  assert.throws(() => validateClockPolicyProof(value), /mutated the policy/);
});

test('A3 verification requires every named offline check', () => {
  const value = verification();
  assert.equal(validateA3Verification(value, candidateRevision), value);
  value.checks.pop();
  assert.throws(() => validateA3Verification(value, candidateRevision), /whole-hacknet-check/);
});

test('A3 assembler produces a portable candidate-bound evidence archive', () => {
  const value = fixture();
  assert.equal(value.summary.candidateRevision, candidateRevision);
  assert.deepEqual(Object.keys(value.summary.artifacts).sort(), Object.keys(A3_ARTIFACTS).sort());
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
});

test('A3 packet is Full and binds the exact candidate diff', () => {
  const value = fixture();
  const candidate = {
    sourceRevision: candidateRevision, commitPending: false,
    dirtyPatchDigest: `sha256:${'0'.repeat(64)}`,
  };
  const packet = buildReleaseOneA3Packet({
    root: value.root,
    candidate,
    liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: []},
    candidateDiff: value.patch,
    candidateContextTree: 'e'.repeat(40),
  });
  assert.equal(packet.reviewId, 'release-1-amendment-a3-controller-hardening');
  assert.equal(packet.tier, 'Full');
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(() => buildReleaseOneA3Packet({
    root: value.root,
    candidate,
    liveSummaryPath: join(value.live, 'live-summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: []},
    candidateDiff: Buffer.from('wrong patch\n'),
    candidateContextTree: 'e'.repeat(40),
  }), /candidate diff artifact/);
});

test('A3 contract makes all three follow-up findings and portable evidence load-bearing', () => {
  for (const id of [
    'candidate:contrib/helm/hacknet/operator/internal/fault/capability.go',
    'candidate:contrib/helm/hacknet/operator/internal/rbac/validate.go',
    'candidate:contrib/attacknet/topology-render-equivalence.test.mjs',
    'diff:candidate-controller-hardening',
    'evidence:clock-policy-live',
    'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});
