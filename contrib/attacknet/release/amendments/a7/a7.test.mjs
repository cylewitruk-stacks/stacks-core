import assert from 'node:assert/strict';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  A7_ARTIFACTS, assembleA7Evidence, validateA7AttacknetResult,
  validateA7HacknetResult,
} from './evidence.mjs';
import {buildA7Packet, isA7CandidatePath} from './packet.mjs';
import {
  A7_CHECK_IDS, A7_DELETED_PATHS_SCHEMA, A7_VERIFICATION_SCHEMA,
  validateA7DeletedPaths, validateA7Verification,
} from './verify.mjs';

const contract = JSON.parse(readFileSync(new URL('./contract.json', import.meta.url), 'utf8'));
const candidateRevision = 'a'.repeat(40);
const digest = character => `sha256:${character.repeat(64)}`;
const deleted = ['contrib/attacknet/legacy/README.md'];

function deletedPaths() {
  return {
    schema: A7_DELETED_PATHS_SCHEMA,
    candidateRevision,
    parentRevision: '52e0d2812c514cad29d9fd2603eb2b8b3d93b0c3',
    paths: deleted,
  };
}

function verification() {
  return {
    schema: A7_VERIFICATION_SCHEMA,
    candidateRevision,
    outcome: 'Passed',
    recordedAt: '2026-08-26T00:00:00.000Z',
    checks: A7_CHECK_IDS.map(id => ({
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
  const root = mkdtempSync(join(tmpdir(), 'release-one-a7-'));
  const input = join(root, 'raw');
  const evidence = join(root, 'evidence');
  mkdirSync(input, {recursive: true});
  const patch = Buffer.from('A7 candidate patch\n');
  writeFileSync(join(input, A7_ARTIFACTS.candidateDiff), patch);
  writeFileSync(join(input, A7_ARTIFACTS.deletedPaths), `${JSON.stringify(deletedPaths())}\n`);
  writeFileSync(join(input, A7_ARTIFACTS.verification), `${JSON.stringify(verification())}\n`);
  writeFileSync(join(input, A7_ARTIFACTS.attacknetCheck), `${JSON.stringify(attacknetResult())}\n`);
  writeFileSync(join(input, A7_ARTIFACTS.hacknetCheck), `${JSON.stringify(hacknetResult())}\n`);
  const summary = assembleA7Evidence({
    candidateRevision,
    inputDirectory: input,
    outputDirectory: evidence,
    archiveLocation: 'file:///review/release-1-a7-evidence.tar.gz',
    root,
  });
  const contractDirectory = join(root, 'contrib/attacknet/release/amendments/a7');
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

test('A7 verification requires every complete named check', () => {
  const value = verification();
  assert.equal(validateA7Verification(value, candidateRevision), value);
  value.checks.pop();
  assert.throws(() => validateA7Verification(value, candidateRevision), /missing/);
});

test('A7 deletion inventory is exact and candidate-bound', () => {
  const value = deletedPaths();
  assert.equal(validateA7DeletedPaths(value, candidateRevision, deleted), value);
  assert.throws(() => validateA7DeletedPaths(value, candidateRevision, [...deleted, 'contrib/attacknet/legacy/extra']), /exact candidate diff/);
});

test('A7 whole-product results reject incomplete verification', () => {
  const attacknet = attacknetResult();
  assert.equal(validateA7AttacknetResult(attacknet, candidateRevision), attacknet);
  attacknet.suites[0].passed = 0;
  assert.throws(() => validateA7AttacknetResult(attacknet, candidateRevision), /incomplete/);
  const hacknet = hacknetResult();
  assert.equal(validateA7HacknetResult(hacknet, candidateRevision), hacknet);
  hacknet.optionalChecks.find(check => check.name === 'helm').status = 'skipped-unavailable';
  hacknet.optionalChecks.find(check => check.name === 'helm').reason = 'missing';
  assert.throws(() => validateA7HacknetResult(hacknet, candidateRevision), /passed Hacknet helm/);
});

test('A7 assembler produces a portable candidate-bound archive', () => {
  const value = fixture();
  assert.equal(value.summary.candidateRevision, candidateRevision);
  assert.deepEqual(Object.keys(value.summary.artifacts).sort(), Object.keys(A7_ARTIFACTS).sort());
  assert.ok(value.summary.assertions.every(assertion => assertion.status === 'passed'));
  assert.ok(value.summary.archive.path.startsWith('evidence/archive/'));
  assert.ok(!JSON.stringify(value.summary).includes(value.root));
});

test('A7 packet is Reduced and binds the exact candidate diff', () => {
  const value = fixture();
  const candidate = {sourceRevision: candidateRevision, commitPending: false, dirtyPatchDigest: digest('0')};
  const options = {
    root: value.root,
    candidate,
    summaryPath: join(value.evidence, 'summary.json'),
    inventory: packetInventory(),
    candidateScope: {parent: 'f'.repeat(40), paths: [], deleted},
    candidateDiff: value.patch,
  };
  const packet = buildA7Packet(options);
  assert.equal(packet.reviewId, 'release-1-amendment-a7-legacy-retirement');
  assert.equal(packet.tier, 'Reduced');
  assert.equal(packet.compatibility.runtimeBehaviorChanged, false);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
  assert.throws(
    () => buildA7Packet({...options, candidateDiff: Buffer.from('wrong patch\n')}),
    /candidate diff artifact/,
  );
});

test('A7 contract makes the new boundary and portable evidence load-bearing', () => {
  for (const id of [
    'candidate:contrib/attacknet/test/contracts/repository-boundary.test.mjs',
    'candidate:contrib/attacknet/test/fixtures/equivalence/v1alpha1/manifest.json',
    'candidate:contrib/attacknet/instrumentation/artifact-digest.mjs',
    'candidate:contrib/attacknet/instrumentation/run-descriptor.mjs',
    'diff:candidate-legacy-retirement',
    'evidence:deleted-paths',
    'test:attacknet-check',
    'test:hacknet-check',
    'evidence:archive',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});

test('A7 scope is confined to the Attacknet product tree', () => {
  for (const path of [
    'contrib/attacknet/instrumentation/run-descriptor.mjs',
    'contrib/attacknet/test/fixtures/equivalence/v1alpha1/manifest.json',
  ]) assert.equal(isA7CandidatePath(path), true, `A7 scope omitted ${path}`);
  assert.equal(isA7CandidatePath('contrib/helm/hacknet/operator/main.go'), false);
  assert.equal(isA7CandidatePath('stacks-node/src/main.rs'), false);
});
