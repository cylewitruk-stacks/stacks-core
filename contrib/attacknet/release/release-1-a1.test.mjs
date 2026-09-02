import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {REVIEW_CONTRACT_SCHEMA, REVIEW_PACKET_SCHEMA} from './phase-review.mjs';
import {
  buildReleaseOneA1Packet,
  validateReleaseOneA1LiveSummary,
} from './release-1-a1-packet.mjs';

const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'release-one-a1-packet-'));
  const liveRoot = join(root, 'live');
  mkdirSync(liveRoot);
  const artifact = (name, bytes = Buffer.from(`${name}\n`)) => {
    const path = join(liveRoot, name);
    writeFileSync(path, bytes);
    return {path, digest: digest(bytes), archiveEntry: name};
  };
  const patch = Buffer.from('candidate patch\n');
  const artifacts = {
    candidateDiff: artifact('candidate.patch', patch),
    ...Object.fromEntries([
      'doctor', 'lifecycleApply', 'verification', 'faultRun',
      'evidenceCapture', 'cleanTeardown',
    ].map(name => [name, artifact(`${name}.json`)])),
  };
  const candidate = {
    sourceRevision: 'a'.repeat(40),
    commitPending: false,
    dirtyPatchDigest: `sha256:${'0'.repeat(64)}`,
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
  execFileSync('tar', [
    '-cf', archivePath, '-C', liveRoot,
    'evidence-index.json', ...Object.values(artifacts).map(value => value.archiveEntry),
  ], {env: {...process.env, COPYFILE_DISABLE: '1'}});
  const summary = {
    schema: 'stacks-attacknet-release-1-a1-live-evidence/v1',
    candidateRevision: candidate.sourceRevision,
    archive: {
      path: archivePath,
      digest: digest(readFileSync(archivePath)),
      indexPath,
      indexDigest: digest(indexBytes),
      indexEntry: 'evidence-index.json',
      location: 'file:///portable-review-archive/release-1-a1-evidence.tar',
    },
    artifacts,
    assertions: [
      'supported-environment-doctor',
      'kubernetes-apply-complete',
      'kubernetes-verification-passed',
      'bounded-fault-effect-and-recovery',
      'evidence-capture-complete',
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
    requiredChecks: ['controllers', 'chart'],
    optionalChecks: [{name: 'go', status: 'skipped-unavailable', reason: 'not installed'}],
  })}\n`);
  return {
    root,
    patch,
    candidate,
    summary,
    liveSummaryPath,
    offlineResultPath,
    hacknetResultPath,
  };
}

test('A1 live evidence binds the signed candidate and complete Kubernetes lifecycle', () => {
  const value = fixture();
  assert.equal(
    validateReleaseOneA1LiveSummary(value.summary, value.candidate, value.root),
    value.summary,
  );
  value.summary.assertions.find(assertion => assertion.id === 'clean-teardown').status = 'failed';
  assert.throws(
    () => validateReleaseOneA1LiveSummary(value.summary, value.candidate, value.root),
    /clean-teardown/,
  );
});

test('A1 packet is Full, review-identified, and binds the exact retirement diff', () => {
  const value = fixture();
  const contract = JSON.parse(readFileSync(new URL('./release-1-a1-contract.json', import.meta.url), 'utf8'));
  const inventory = contract.requiredInventory.map((id, index) => ({
    id,
    kind: id.startsWith('test:') ? 'test'
      : id.startsWith('evidence:') ? 'evidence'
        : id.startsWith('diff:') ? 'diff'
          : id.includes('.md') ? 'document' : 'source',
    path: `review/item-${index}`,
    digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
  const packet = buildReleaseOneA1Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: value.offlineResultPath,
    hacknetResultPath: value.hacknetResultPath,
    inventory,
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: value.patch,
  });
  assert.equal(contract.schemaVersion, REVIEW_CONTRACT_SCHEMA);
  assert.equal(packet.schemaVersion, REVIEW_PACKET_SCHEMA);
  assert.equal(packet.reviewId, 'release-1-amendment-a1-compose-retirement');
  assert.equal(packet.tier, 'Full');
  assert.equal(packet.compatibility.runtimeBehaviorChanged, true);
  assert.equal(packet.compatibility.evidenceInterpretationChanged, true);
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));

  assert.throws(() => buildReleaseOneA1Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: value.offlineResultPath,
    hacknetResultPath: value.hacknetResultPath,
    inventory,
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: Buffer.from('different patch\n'),
  }), /candidate diff artifact/);
});

test('A1 packet evidence resolves through one packet-relative live root', () => {
  const value = fixture();
  const misplaced = join(value.root, 'offline-result.json');
  writeFileSync(misplaced, readFileSync(value.offlineResultPath));
  assert.throws(() => buildReleaseOneA1Packet({
    candidate: value.candidate,
    liveSummaryPath: value.liveSummaryPath,
    offlineResultPath: misplaced,
    hacknetResultPath: value.hacknetResultPath,
    inventory: [],
    candidateScope: {parent: 'b'.repeat(40), paths: []},
    committedPatch: value.patch,
  }), /Attacknet offline result must resolve/);
});

test('A1 contract makes the baseline amendment, deletions, and live proof load-bearing', () => {
  const contract = JSON.parse(readFileSync(new URL('./release-1-a1-contract.json', import.meta.url), 'utf8'));
  for (const id of [
    'candidate:contrib/attacknet/release/baseline-v1.json',
    'diff:candidate-compose-retirement',
    'evidence:lifecycle-apply',
    'evidence:fault-run',
    'evidence:clean-teardown',
    'test:offline-check',
    'test:hacknet-check',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});

test('Hacknet offline results distinguish required success from unavailable optional tools', () => {
  const value = {
    schemaVersion: 'stacks-hacknet-offline-check-result/v1',
    sourceRevision: 'a'.repeat(40),
    status: 'passed',
    requiredChecks: ['controllers'],
    optionalChecks: [{name: 'go', status: 'skipped-unavailable', reason: 'not installed'}],
  };
  assert.equal(validateHacknetOfflineResult(value), value);
  assert.throws(
    () => validateHacknetOfflineResult({...value, optionalChecks: [{name: 'go', status: 'skipped-unavailable'}]}),
    /incomplete/,
  );
});
