import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {buildPhaseTwoPacket, validatePhaseTwoLiveSummary} from './phase-two-packet.mjs';
import {resolveEvidenceInventoryPath} from './phase-review.mjs';

const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'phase-two-packet-'));
  const bundle = join(root, 'bundle');
  mkdirSync(bundle);
  const artifact = name => {
    const path = join(bundle, name);
    const bytes = Buffer.from(`${name}\n`);
    writeFileSync(path, bytes);
    return {path, digest: digest(bytes), archiveEntry: name};
  };
  const artifacts = Object.fromEntries([
    'doctor', 'humanWorkflow', 'agentWorkflow', 'cleanTeardown',
  ].map(name => [name, artifact(`${name}.json`)]));
  const indexPath = join(bundle, 'evidence-index.json');
  const indexBytes = Buffer.from(`${JSON.stringify({
    schema: 'stacks-attacknet-evidence-archive-index/v1',
    candidateRevision: 'a'.repeat(40),
    entries: Object.values(artifacts).map(value => ({
      path: value.archiveEntry, digest: value.digest, size: readFileSync(value.path).length,
    })),
  }, null, 2)}\n`);
  writeFileSync(indexPath, indexBytes);
  const archivePath = join(root, 'evidence.tar');
  execFileSync('tar', ['-cf', archivePath, '-C', bundle, '.']);
  return {
    root,
    candidate: {sourceRevision: 'a'.repeat(40), commitPending: false, dirtyPatchDigest: `sha256:${'0'.repeat(64)}`},
    summary: {
      schema: 'stacks-attacknet-phase-2-live-evidence/v1',
      candidateRevision: 'a'.repeat(40),
      archive: {
        path: archivePath, digest: digest(readFileSync(archivePath)),
        indexPath, indexDigest: digest(indexBytes), indexEntry: 'evidence-index.json',
        location: 'file:///portable-review-archive/phase-2-evidence.tar',
      },
      artifacts,
      assertions: [
        'supported-environment-doctor', 'human-workflow-complete',
        'agent-workflow-complete', 'fault-through-facade',
        'evidence-captured', 'clean-teardown',
      ].map(id => ({id, status: 'passed'})),
    },
  };
}

test('Phase 2 live summary binds the candidate, portable archive, personas, and teardown', () => {
  const value = fixture();
  assert.equal(validatePhaseTwoLiveSummary(value.summary, value.candidate, value.root), value.summary);
  assert.throws(() => validatePhaseTwoLiveSummary(value.summary, {...value.candidate, commitPending: true}, value.root), /clean committed candidate/);
  assert.throws(() => validatePhaseTwoLiveSummary({...value.summary, candidateRevision: 'b'.repeat(40)}, value.candidate, value.root), /does not pin/);
});

test('Phase 2 live summary fails closed on incomplete personas and archive drift', () => {
  const missing = fixture();
  missing.summary.assertions.find(item => item.id === 'agent-workflow-complete').status = 'failed';
  assert.throws(() => validatePhaseTwoLiveSummary(missing.summary, missing.candidate, missing.root), /agent-workflow-complete/);

  const drifted = fixture();
  writeFileSync(drifted.summary.artifacts.doctor.path, 'tampered\n');
  assert.throws(() => validatePhaseTwoLiveSummary(drifted.summary, drifted.candidate, drifted.root), /doctor digest mismatch/);
});

test('Phase 2 contract names every load-bearing source and evidence artifact', () => {
  const contract = JSON.parse(readFileSync(new URL('./phase-2-contract.json', import.meta.url), 'utf8'));
  for (const id of [
    'candidate:contrib/attacknet/attacknet',
    'candidate:contrib/attacknet/release/phase-review.mjs',
    'candidate:contrib/attacknet/campaign-runner.sh',
    'evidence:doctor', 'evidence:human-workflow', 'evidence:agent-workflow',
    'evidence:clean-teardown',
  ]) assert.ok(contract.requiredInventory.includes(id), `missing ${id}`);
});

test('Phase 2 packet generation upgrades the review tier and remains clean-clone testable', () => {
  const value = fixture();
  const contract = JSON.parse(readFileSync(new URL('./phase-2-contract.json', import.meta.url), 'utf8'));
  const liveSummaryPath = join(value.root, 'live-summary.json');
  writeFileSync(liveSummaryPath, `${JSON.stringify(value.summary, null, 2)}\n`);
  const offlineResultPath = join(value.root, 'offline-result.json');
  writeFileSync(offlineResultPath, `${JSON.stringify({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', status: 'passed',
  })}\n`);
  const inventory = contract.requiredInventory.map((id, index) => ({
    id,
    kind: id.startsWith('test:') ? 'test' : id.startsWith('evidence:') ? 'evidence' : 'source',
    path: `review/item-${index}`,
    digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
  const packet = buildPhaseTwoPacket({
    candidate: value.candidate,
    liveSummaryPath,
    offlineResultPath,
    inventory,
  });
  assert.equal(packet.tier, 'Full');
  assert.equal(packet.evidenceRoot, 'live');
  assert.equal(packet.compatibility.evidenceInterpretationChanged, true);
  assert.ok(packet.inventory.every(item => !item.path.startsWith('/')));
  assert.ok(packet.matrix.every(row => row.status === 'satisfied' && row.evidence.length > 0));
});

test('Phase 2 evidence inventory resolves from one explicit packet-relative root', () => {
  const value = fixture();
  const packetDir = join(value.root, 'review');
  const evidenceDir = join(packetDir, 'live');
  mkdirSync(join(evidenceDir, 'archive'), {recursive: true});
  const contract = JSON.parse(readFileSync(new URL('./phase-2-contract.json', import.meta.url), 'utf8'));
  const inventory = contract.requiredInventory.map((id, index) => {
    const kind = id.startsWith('test:') ? 'test' : id.startsWith('evidence:') ? 'evidence' : 'source';
    const path = kind === 'source' ? `candidate-${index}` : `artifact-${index}.json`;
    if (kind !== 'source') writeFileSync(join(evidenceDir, path), `${id}\n`);
    return {id, kind, path, digest: `sha256:${String(index + 1).padStart(64, '0')}`};
  });
  const liveSummaryPath = join(value.root, 'live-summary.json');
  writeFileSync(liveSummaryPath, `${JSON.stringify(value.summary, null, 2)}\n`);
  const offlineResultPath = join(value.root, 'offline-result.json');
  writeFileSync(offlineResultPath, `${JSON.stringify({
    schemaVersion: 'stacks-attacknet-offline-check-result/v1', status: 'passed',
  })}\n`);
  const packet = buildPhaseTwoPacket({candidate: value.candidate, liveSummaryPath, offlineResultPath, inventory});
  const packetPath = join(packetDir, 'packet.json');
  for (const item of packet.inventory.filter(({kind}) => kind === 'evidence' || kind === 'test')) {
    assert.equal(existsSync(resolveEvidenceInventoryPath(packetPath, packet, item)), true, item.id);
  }
  assert.throws(
    () => buildPhaseTwoPacket({candidate: value.candidate, liveSummaryPath, offlineResultPath, inventory, evidenceRoot: '../elsewhere'}),
    /portable relative locator/,
  );
});
