import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validatePhaseOneLiveSummary} from './phase-one-packet.mjs';

const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'phase-one-packet-'));
  const bundle = join(root, 'bundle');
  mkdirSync(bundle);
  const artifact = name => {
    const path = join(bundle, name);
    const bytes = Buffer.from(`${name}\n`);
    writeFileSync(path, bytes);
    return {path, digest: digest(bytes)};
  };
  const artifacts = Object.fromEntries([
    'imageBuild', 'baselineCapability', 'baselineRun', 'alertActive',
    'alertRecovered', 'blockingCapability', 'blockingRun',
  ].map(name => {
    const value = artifact(`${name}.json`);
    return [name, {...value, archiveEntry: `${name}.json`}];
  }));
  const indexPath = join(bundle, 'evidence-index.json');
  const indexBytes = Buffer.from(`${JSON.stringify({
    schema: 'stacks-attacknet-evidence-archive-index/v1',
    candidateRevision: 'a'.repeat(40),
    entries: Object.values(artifacts).map(value => ({
      path: value.archiveEntry,
      digest: value.digest,
      size: readFileSize(value.path),
    })),
  }, null, 2)}\n`);
  writeFileSync(indexPath, indexBytes);
  const archivePath = join(root, 'evidence.tar');
  execFileSync('tar', ['-cf', archivePath, '-C', bundle, '.']);
  return {
    root,
    candidate: {sourceRevision: 'a'.repeat(40), commitPending: false, dirtyPatchDigest: `sha256:${'0'.repeat(64)}`},
    summary: {
      schema: 'stacks-attacknet-phase-1-live-evidence/v1',
      candidateRevision: 'a'.repeat(40),
      archive: {
        path: archivePath,
        digest: digest(readFileBytes(archivePath)),
        indexPath,
        indexDigest: digest(indexBytes),
        indexEntry: 'evidence-index.json',
        location: archivePath,
      },
      artifacts,
      assertions: [
        'runtime-family-presence', 'admitted-image-and-config-identity',
        'clean-attributed-baseline', 'alert-fired-for-selected-actor',
        'alert-cleared-after-recovery', 'post-fault-chain-progress',
        'blocking-dispatch-admitted',
      ].map(id => ({id, status: 'passed'})),
    },
  };
}

function readFileBytes(path) {
  return readFileSync(path);
}

function readFileSize(path) {
  return readFileBytes(path).length;
}

test('Phase 1 live summary binds the clean candidate, archive, artifacts, and every assertion', () => {
  const value = fixture();
  assert.equal(validatePhaseOneLiveSummary(value.summary, value.candidate, value.root), value.summary);
  assert.throws(() => validatePhaseOneLiveSummary(value.summary, {...value.candidate, commitPending: true}, value.root), /clean committed candidate/);
  assert.throws(() => validatePhaseOneLiveSummary({...value.summary, candidateRevision: 'b'.repeat(40)}, value.candidate, value.root), /does not pin/);
});

test('Phase 1 live summary fails closed on missing assertions and artifact drift', () => {
  const value = fixture();
  value.summary.assertions.find(item => item.id === 'alert-cleared-after-recovery').status = 'failed';
  assert.throws(() => validatePhaseOneLiveSummary(value.summary, value.candidate, value.root), /alert-cleared-after-recovery/);
  const fresh = fixture();
  writeFileSync(fresh.summary.artifacts.alertActive.path, 'tampered\n');
  assert.throws(() => validatePhaseOneLiveSummary(fresh.summary, fresh.candidate, fresh.root), /alertActive digest mismatch/);
});
