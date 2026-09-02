import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {REVIEW_CONTRACT_SCHEMA, REVIEW_PACKET_SCHEMA} from './phase-review.mjs';
import {
  buildReleaseOneA2Packet,
  committedBinaryDiff,
  validateReleaseOneA2LiveSummary,
} from './release-1-a2-packet.mjs';

const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const contract = JSON.parse(readFileSync(new URL('./release-1-a2-contract.json', import.meta.url), 'utf8'));
const matrix = JSON.parse(readFileSync(new URL('./controller-equivalence-v1.json', import.meta.url), 'utf8'));
const matrixDigest = digest(readFileSync(new URL('./controller-equivalence-v1.json', import.meta.url)));

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a2-packet-'));
  const liveRoot = join(root, 'live');
  mkdirSync(liveRoot);
  const artifact = (name, bytes = Buffer.from(`${name}\n`)) => {
    const path = join(liveRoot, name);
    writeFileSync(path, bytes);
    return {path, digest: digest(bytes), archiveEntry: name};
  };
  const candidate = {
    sourceRevision: 'a'.repeat(40),
    commitPending: false,
    dirtyPatchDigest: `sha256:${'0'.repeat(64)}`,
  };
  const patch = Buffer.from('controller migration patch\n');
  const equivalence = Buffer.from(`${JSON.stringify({
    schemaVersion: 'stacks-attacknet-controller-equivalence-report/v1',
    candidateRevision: candidate.sourceRevision,
    matrixDigest,
    entries: matrix.entries.map(entry => ({id: entry.id, status: 'verified', evidence: ['direct-read']})),
  }, null, 2)}\n`);
  const artifacts = {
    candidateDiff: artifact('candidate.patch', patch),
    equivalenceReport: artifact('equivalence-report.json', equivalence),
    ...Object.fromEntries([
      'goVerify', 'envtest', 'helmRender', 'topologyLive', 'reversibleFaultLive',
      'podKillLive', 'restartResumeLive', 'cleanTeardown',
    ].map(name => [name, artifact(`${name}.json`)])),
  };
  const indexPath = join(liveRoot, 'evidence-index.json');
  const indexBytes = Buffer.from(`${JSON.stringify({
    schema: 'stacks-attacknet-evidence-archive-index/v1',
    candidateRevision: candidate.sourceRevision,
    entries: Object.values(artifacts).map(value => ({
      path: value.archiveEntry,
      digest: value.digest,
      size: readFileSync(value.path).length,
    })),
  }, null, 2)}\n`);
  writeFileSync(indexPath, indexBytes);
  const archiveDirectory = join(liveRoot, 'archive');
  mkdirSync(archiveDirectory);
  const archivePath = join(archiveDirectory, 'evidence.tar');
  execFileSync('tar', ['-cf', archivePath, '-C', liveRoot, 'evidence-index.json', ...Object.values(artifacts).map(value => value.archiveEntry)], {env: {...process.env, COPYFILE_DISABLE: '1'}});
  const summary = {
    schema: 'stacks-attacknet-release-1-a2-live-evidence/v1',
    candidateRevision: candidate.sourceRevision,
    archive: {
      path: archivePath,
      digest: digest(readFileSync(archivePath)),
      indexPath,
      indexDigest: digest(indexBytes),
      indexEntry: 'evidence-index.json',
      location: 'file:///portable-review-archive/release-1-a2-evidence.tar',
    },
    artifacts,
    assertions: [
      'go-build-vet-unit-race',
      'envtest-api-server-contracts',
      'crd-rbac-helm-security-contracts',
      'whole-attacknet-and-hacknet-offline-verification',
      'topology-admitted-inventory-and-mutable-reconcile',
      'reversible-fault-injection-effect-recovery-cleanup',
      'one-shot-pod-replacement-identity-bounds',
      'controller-restart-idempotent-resume',
      'clean-teardown',
    ].map(id => ({id, status: 'passed'})),
  };
  const liveSummaryPath = join(liveRoot, 'live-summary.json');
  writeFileSync(liveSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  const offlineResultPath = join(liveRoot, 'offline-result.json');
  writeFileSync(offlineResultPath, `${JSON.stringify({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1',
    sourceRevision: candidate.sourceRevision,
    status: 'passed',
  })}\n`);
  const hacknetResultPath = join(liveRoot, 'hacknet-result.json');
  writeFileSync(hacknetResultPath, `${JSON.stringify({
    schemaVersion: 'stacks-hacknet-offline-check-result/v1',
    sourceRevision: candidate.sourceRevision,
    status: 'passed',
    requiredChecks: ['topology-operator', 'run-operator', 'crd-contracts'],
    optionalChecks: [
      {name: 'go', status: 'passed'},
      {name: 'envtest', status: 'passed'},
      {name: 'helm', status: 'passed'},
    ],
  })}\n`);
  return {root, candidate, patch, summary, liveSummaryPath, offlineResultPath, hacknetResultPath};
}

function inventory() {
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

test('A2 live evidence binds every controller-runtime qualification assertion', () => {
  const value = fixture();
  assert.equal(validateReleaseOneA2LiveSummary(value.summary, value.candidate, value.root), value.summary);
  value.summary.assertions.find(assertion => assertion.id === 'controller-restart-idempotent-resume').status = 'failed';
  assert.throws(() => validateReleaseOneA2LiveSummary(value.summary, value.candidate, value.root), /controller-restart-idempotent-resume/);
});

test('A2 candidate diff recomputation has an explicit large bounded buffer', () => {
  let invocation;
  const expected = Buffer.from('large candidate diff');
  const actual = committedBinaryDiff('/review/root', 'a'.repeat(40), 'b'.repeat(40),
    (command, args, options) => {
      invocation = {command, args, options};
      return expected;
    });
  assert.equal(actual, expected);
  assert.equal(invocation.command, 'git');
  assert.deepEqual(invocation.args, ['diff', '--binary', 'a'.repeat(40), 'b'.repeat(40)]);
  assert.equal(invocation.options.cwd, '/review/root');
  assert.ok(invocation.options.maxBuffer >= 64 * 1024 * 1024);
});

test('A2 packet is Full and binds the exact migration diff and equivalence report', () => {
  const value = fixture();
  const packet = buildReleaseOneA2Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: value.offlineResultPath,
    hacknetResultPath: value.hacknetResultPath,
    inventory: inventory(),
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: value.patch,
  });
  assert.equal(contract.schemaVersion, REVIEW_CONTRACT_SCHEMA);
  assert.equal(packet.schemaVersion, REVIEW_PACKET_SCHEMA);
  assert.equal(packet.reviewId, 'release-1-amendment-a2-controller-runtime-migration');
  assert.equal(packet.tier, 'Full');
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));

  assert.throws(() => buildReleaseOneA2Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: value.offlineResultPath,
    hacknetResultPath: value.hacknetResultPath,
    inventory: inventory(),
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: Buffer.from('wrong diff\n'),
  }), /candidate diff artifact/);
});

test('A2 requires Go, envtest, and Helm rather than recording an unavailable skip', () => {
  const value = fixture();
  const hacknet = JSON.parse(readFileSync(value.hacknetResultPath, 'utf8'));
  hacknet.optionalChecks.find(check => check.name === 'envtest').status = 'skipped-unavailable';
  hacknet.optionalChecks.find(check => check.name === 'envtest').reason = 'missing assets';
  writeFileSync(value.hacknetResultPath, `${JSON.stringify(hacknet)}\n`);
  assert.throws(() => buildReleaseOneA2Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: value.offlineResultPath,
    hacknetResultPath: value.hacknetResultPath,
    inventory: inventory(),
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: value.patch,
  }), /requires a passed Hacknet envtest/);
});

test('A2 contract makes parity, security, live mutation, and teardown evidence load-bearing', () => {
  for (const id of [
    'candidate:contrib/attacknet/release/controller-equivalence-v1.json',
    'candidate:contrib/attacknet/release/release-1-a2-evidence.mjs',
    'candidate:contrib/helm/hacknet/operator/internal/topology/reconciler.go',
    'candidate:contrib/helm/hacknet/operator/internal/fault/reconciler.go',
    'candidate:contrib/attacknet/fault-compiler-equivalence.test.mjs',
    'candidate:contrib/helm/hacknet/operator/internal/orchestratormetrics/collector.go',
    'candidate:contrib/helm/hacknet/operator/internal/run/reconciler.go',
    'candidate:contrib/helm/hacknet/templates/run-rbac.yaml',
    'candidate:contrib/helm/hacknet/scripts/load-kind-images.sh',
    'candidate:contrib/attacknet/lifecycle.sh',
    'diff:candidate-controller-runtime-migration',
    'evidence:pod-kill-live',
    'evidence:restart-resume-live',
    'evidence:clean-teardown',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});
