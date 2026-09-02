import assert from 'node:assert/strict';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  A6_ARTIFACTS, assembleA6Evidence, validateA6AttacknetResult,
  validateA6HacknetResult,
} from './evidence.mjs';
import {buildA6Packet, isA6CandidatePath} from './packet.mjs';
import {A6_CHECK_IDS, A6_VERIFICATION_SCHEMA, validateA6Verification} from './verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
const candidateRevision = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;

function verification() {
  return {
    schema: A6_VERIFICATION_SCHEMA,
    candidateRevision,
    outcome: 'Passed',
    recordedAt: '2026-08-26T00:00:00.000Z',
    checks: A6_CHECK_IDS.map(id => ({
      id,
      status: 'passed',
      command: id,
      cwd: '.',
      startedAt: '2026-08-26T00:00:00.000Z',
      durationMs: 1,
      exitCode: 0,
      outputDigest: digest('b'),
      stdout: '',
      stderr: '',
    })),
  };
}

function attacknetResult() {
  return {
    schemaVersion: 'stacks-attacknet-offline-check-result/v1',
    sourceRevision: candidateRevision,
    status: 'passed',
    suites: [{name: 'all', tests: 1, passed: 1, failed: 0}],
  };
}

function hacknetResult() {
  return {
    schemaVersion: 'stacks-hacknet-offline-check-result/v1',
    sourceRevision: candidateRevision,
    status: 'passed',
    requiredChecks: ['operator', 'chart'],
    optionalChecks: [
      {name: 'go', status: 'passed'},
      {name: 'helm', status: 'passed'},
      {name: 'envtest', status: 'skipped-unavailable', reason: 'Reduced tier does not require envtest'},
    ],
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a6-'));
  const input = join(root, 'raw');
  const evidence = join(root, 'evidence');
  mkdirSync(input, {recursive: true});
  const patch = Buffer.from('A6 candidate patch\n');
  writeFileSync(join(input, A6_ARTIFACTS.candidateDiff), patch);
  writeFileSync(join(input, A6_ARTIFACTS.verification), `${JSON.stringify(verification())}\n`);
  writeFileSync(join(input, A6_ARTIFACTS.attacknetCheck), `${JSON.stringify(attacknetResult())}\n`);
  writeFileSync(join(input, A6_ARTIFACTS.hacknetCheck), `${JSON.stringify(hacknetResult())}\n`);
  const summary = assembleA6Evidence({
    candidateRevision,
    inputDirectory: input,
    outputDirectory: evidence,
    archiveLocation: 'file:///review/release-1-a6-evidence.tar.gz',
    root,
  });
  const contractDirectory = join(root, 'contrib/attacknet/release/amendments/a6');
  mkdirSync(contractDirectory, {recursive: true});
  cpSync(new URL('./contract.json', import.meta.url), join(contractDirectory, 'contract.json'));
  return {root, evidence, patch, summary};
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

test('A6 verification requires every complete named check', () => {
  const value = verification();
  assert.equal(validateA6Verification(value, candidateRevision), value);
  value.checks.pop();
  assert.throws(() => validateA6Verification(value, candidateRevision), /missing/);
});

test('A6 whole-product results reject incomplete verification', () => {
  const attacknet = attacknetResult();
  assert.equal(validateA6AttacknetResult(attacknet, candidateRevision), attacknet);
  attacknet.suites[0].passed = 0;
  assert.throws(() => validateA6AttacknetResult(attacknet, candidateRevision), /incomplete/);
  const hacknet = hacknetResult();
  assert.equal(validateA6HacknetResult(hacknet, candidateRevision), hacknet);
  hacknet.optionalChecks.find(check => check.name === 'helm').status = 'skipped-unavailable';
  hacknet.optionalChecks.find(check => check.name === 'helm').reason = 'missing';
  assert.throws(() => validateA6HacknetResult(hacknet, candidateRevision), /passed Hacknet helm/);
});

test('A6 assembler produces a portable candidate-bound archive', () => {
  const value = fixture();
  assert.equal(value.summary.candidateRevision, candidateRevision);
  assert.deepEqual(Object.keys(value.summary.artifacts).sort(), Object.keys(A6_ARTIFACTS).sort());
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
  assert.ok(value.summary.archive.path.startsWith('evidence/archive/'));
  assert.ok(!JSON.stringify(value.summary).includes(value.root));
});

test('A6 packet is Reduced and binds the exact candidate diff', () => {
  const value = fixture();
  const candidate = {sourceRevision: candidateRevision, commitPending: false, dirtyPatchDigest: digest('0')};
  const options = {
    root: value.root,
    candidate,
    summaryPath: join(value.evidence, 'summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: [], deleted: []},
    candidateDiff: value.patch,
  };
  const packet = buildA6Packet(options);
  assert.equal(packet.reviewId, 'release-1-amendment-a6-repository-hygiene');
  assert.equal(packet.tier, 'Reduced');
  assert.equal(packet.compatibility.runtimeBehaviorChanged, false);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(
    () => buildA6Packet({...options, candidateDiff: Buffer.from('wrong patch\n')}),
    /candidate diff artifact/,
  );
});

test('A6 contract makes the new boundary and portable evidence load-bearing', () => {
  for (const id of [
    'candidate:contrib/attacknet/test/contracts/repository-boundary.test.mjs',
    'candidate:contrib/attacknet/legacy/v1alpha1/manifest.v1.json',
    'candidate:contrib/helm/hacknet/operator/internal/attacknetcli/examples_test.go',
    'candidate:contrib/helm/hacknet/operator/internal/attacknetcli/local_images.go',
    'diff:candidate-repository-hygiene',
    'test:attacknet-check',
    'test:hacknet-check',
    'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});

test('A6 scope includes every Hacknet locator changed by the reorganization', () => {
  for (const path of [
    'contrib/helm/hacknet/operator/internal/attacknetcli/examples_test.go',
    'contrib/helm/hacknet/operator/internal/attacknetcli/local_images.go',
    'contrib/helm/hacknet/operator/internal/attacknetcli/local_ops_test.go',
    'contrib/helm/hacknet/scripts/build-local.sh',
    'contrib/helm/hacknet/scripts/check.sh',
  ]) assert.equal(isA6CandidatePath(path), true, `A6 scope omitted ${path}`);
  assert.equal(isA6CandidatePath('stacks-node/src/main.rs'), false);
});
