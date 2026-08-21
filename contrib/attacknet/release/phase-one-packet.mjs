#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from './phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from './phase-review.mjs';

const releaseDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(releaseDir, '../../..');
const LIVE_SCHEMA = 'stacks-attacknet-phase-1-live-evidence/v1';
const ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
const PHASE_ZERO_REVISION = '307393762da99c8fce0d5bc97bc5f684ee68ff7f';
const REQUIRED_ASSERTIONS = Object.freeze([
  'runtime-family-presence',
  'admitted-image-and-config-identity',
  'clean-attributed-baseline',
  'alert-fired-for-selected-actor',
  'alert-cleared-after-recovery',
  'post-fault-chain-progress',
  'blocking-dispatch-admitted',
]);

function absolute(path, root = repoRoot) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function load(path, root = repoRoot) {
  return JSON.parse(readFileSync(absolute(path, root), 'utf8'));
}

function digestFile(path, root = repoRoot) {
  return `sha256:${createHash('sha256').update(readFileSync(absolute(path, root))).digest('hex')}`;
}

function item(id, kind, path, root = repoRoot, sourcePath = path) {
  return {id, kind, path, digest: digestFile(sourcePath, root)};
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function candidateId(path) {
  return `candidate:${path}`;
}

function candidateKind(path) {
  if (path.endsWith('.md')) return 'document';
  if (path.endsWith('.patch')) return 'diff';
  return 'source';
}

function archiveMembers(path, root = repoRoot) {
  return new Set(execFileSync('tar', ['-tf', absolute(path, root)], {encoding: 'utf8'})
    .split('\n').filter(Boolean).map(member => member.replace(/^\.\//, '').replace(/\/$/, '')));
}

export function phaseOneCandidateInventorySpec(root = repoRoot, candidateRevision = 'HEAD') {
  const parent = execFileSync('git', ['rev-parse', `${candidateRevision}^`], {cwd: root, encoding: 'utf8'}).trim();
  if (parent !== PHASE_ZERO_REVISION) throw new Error(`Phase 1 candidate must be based directly on approved Phase 0 ${PHASE_ZERO_REVISION}`);
  const paths = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRT', PHASE_ZERO_REVISION, candidateRevision], {
    cwd: root,
    encoding: 'utf8',
  }).split('\n').filter(Boolean).sort();
  if (paths.length === 0) throw new Error('Phase 1 candidate scope is empty');
  return paths.map(path => [candidateId(path), candidateKind(path), path]);
}

export function validatePhaseOneLiveSummary(summary, candidate, root = repoRoot) {
  assertObject(summary, 'live summary');
  if (summary.schema !== LIVE_SCHEMA) throw new Error('live summary uses an unsupported schema');
  if (summary.candidateRevision !== candidate.sourceRevision) throw new Error('live evidence does not pin the candidate revision');
  if (candidate.commitPending) throw new Error('Phase 1 packet requires a clean committed candidate');
  const archive = assertObject(summary.archive, 'live summary archive');
  for (const key of ['path', 'digest', 'indexPath', 'indexDigest', 'indexEntry', 'location']) {
    if (typeof archive[key] !== 'string' || archive[key].length === 0) throw new Error(`live summary archive.${key} is required`);
  }
  if (digestFile(archive.path, root) !== archive.digest) throw new Error('live evidence archive digest mismatch');
  if (digestFile(archive.indexPath, root) !== archive.indexDigest) throw new Error('live evidence archive index digest mismatch');
  const index = load(archive.indexPath, root);
  if (index.schema !== ARCHIVE_INDEX_SCHEMA) throw new Error('live evidence archive index uses an unsupported schema');
  if (index.candidateRevision !== candidate.sourceRevision) throw new Error('live evidence archive index does not pin the candidate revision');
  if (!Array.isArray(index.entries) || index.entries.length === 0) throw new Error('live evidence archive index entries are required');
  const indexed = new Map();
  for (const [position, entry] of index.entries.entries()) {
    assertObject(entry, `live evidence archive index entry ${position}`);
    if (typeof entry.path !== 'string' || entry.path.length === 0 || entry.path.startsWith('/') || entry.path.split('/').includes('..')) {
      throw new Error(`live evidence archive index entry ${position} has an unsafe path`);
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(entry.digest) || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new Error(`live evidence archive index entry ${position} is incomplete`);
    }
    if (indexed.has(entry.path)) throw new Error(`live evidence archive index duplicates ${entry.path}`);
    indexed.set(entry.path, entry);
  }
  const members = archiveMembers(archive.path, root);
  if (!members.has(archive.indexEntry)) throw new Error('live evidence archive omits its index');
  const artifacts = assertObject(summary.artifacts, 'live summary artifacts');
  for (const key of ['imageBuild', 'baselineCapability', 'baselineRun', 'alertActive', 'alertRecovered', 'blockingCapability', 'blockingRun']) {
    const artifact = assertObject(artifacts[key], `live summary artifacts.${key}`);
    if (typeof artifact.path !== 'string' || typeof artifact.digest !== 'string' || typeof artifact.archiveEntry !== 'string') {
      throw new Error(`live summary artifact ${key} is incomplete`);
    }
    if (digestFile(artifact.path, root) !== artifact.digest) throw new Error(`live summary artifact ${key} digest mismatch`);
    if (indexed.get(artifact.archiveEntry)?.digest !== artifact.digest) throw new Error(`live evidence archive index does not bind artifact ${key}`);
    if (!members.has(artifact.archiveEntry)) throw new Error(`live evidence archive omits artifact ${key}`);
  }
  const assertions = Array.isArray(summary.assertions) ? summary.assertions : [];
  const byId = new Map(assertions.map(assertion => [assertion?.id, assertion]));
  if (byId.size !== assertions.length) throw new Error('live summary contains duplicate assertion IDs');
  for (const id of REQUIRED_ASSERTIONS) {
    if (byId.get(id)?.status !== 'passed') throw new Error(`live summary assertion ${id} is not passed`);
  }
  return summary;
}

export function buildPhaseOnePacket({
  root = repoRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  offlineResultPath,
} = {}) {
  if (!liveSummaryPath) throw new Error('liveSummaryPath is required');
  if (!offlineResultPath) throw new Error('offlineResultPath is required');
  const contract = load('contrib/attacknet/release/phase-1-contract.json', root);
  const live = validatePhaseOneLiveSummary(load(liveSummaryPath, root), candidate, root);
  const offline = load(offlineResultPath, root);
  if (offline.schemaVersion !== 'stacks-attacknet-offline-check-result/v1' || offline.status !== 'passed') {
    throw new Error('offline check result is not a passed canonical result');
  }
  const artifacts = live.artifacts;
  const inventory = [
    ...phaseOneCandidateInventorySpec(root, candidate.sourceRevision).map(parts => item(...parts, root)),
    item('test:offline-check', 'test', 'review/offline-result.json', root, offlineResultPath),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'review/live-summary.json', root, liveSummaryPath),
    item('evidence:image-build', 'evidence', artifacts.imageBuild.archiveEntry, root, artifacts.imageBuild.path),
    item('evidence:baseline-capability', 'evidence', artifacts.baselineCapability.archiveEntry, root, artifacts.baselineCapability.path),
    item('evidence:baseline-run', 'evidence', artifacts.baselineRun.archiveEntry, root, artifacts.baselineRun.path),
    item('evidence:alert-active', 'evidence', artifacts.alertActive.archiveEntry, root, artifacts.alertActive.path),
    item('evidence:alert-recovered', 'evidence', artifacts.alertRecovered.archiveEntry, root, artifacts.alertRecovered.path),
    item('evidence:blocking-capability', 'evidence', artifacts.blockingCapability.archiveEntry, root, artifacts.blockingCapability.path),
    item('evidence:blocking-run', 'evidence', artifacts.blockingRun.archiveEntry, root, artifacts.blockingRun.path),
  ];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA,
    phase: 1,
    tier: 'Full',
    candidate,
    requirements: [...contract.requirements],
    inventory,
    matrix: [
      {requirement: 'bounded-portable-instrumentation', status: 'satisfied', evidence: [candidateId('contrib/attacknet/instrumentation/inventory-v1.json'), candidateId('contrib/attacknet/instrumentation/workstream-m.patch'), candidateId('contrib/attacknet/instrumentation/workstream-m.patch.json'), 'test:offline-check']},
      {requirement: 'legacy-response-milestones', status: 'satisfied', evidence: [candidateId('contrib/attacknet/instrumentation/workstream-m.patch'), candidateId('contrib/attacknet/INSTRUMENTATION.md'), 'evidence:baseline-capability']},
      {requirement: 'runtime-provenance-and-presence', status: 'satisfied', evidence: [candidateId('contrib/attacknet/instrumentation/capability-manifest.mjs'), candidateId('contrib/attacknet/instrumentation/phase-1-qualification.mjs'), 'evidence:image-build', 'evidence:baseline-capability']},
      {requirement: 'configuration-and-compatibility-guards', status: 'satisfied', evidence: [candidateId('contrib/attacknet/topology.mjs'), candidateId('contrib/attacknet/lifecycle.sh'), 'evidence:baseline-run', 'evidence:blocking-run']},
      {requirement: 'clean-attributed-baseline', status: 'satisfied', evidence: ['evidence:baseline-run', 'evidence:baseline-capability', 'evidence:archive-index']},
      {requirement: 'attributed-alert-negative-control', status: 'satisfied', evidence: ['evidence:alert-active', 'evidence:alert-recovered', 'evidence:baseline-run']},
      {requirement: 'blocking-dispatch-negative-control', status: 'satisfied', evidence: ['evidence:blocking-capability', 'evidence:blocking-run']},
      {requirement: 'clean-offline-verification', status: 'satisfied', evidence: ['test:offline-check']},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'Node/signer changes are metrics-only. Attacknet admission, qualification, observability, and evidence interpretation changed and were exercised on local arm64 kind.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Release 1 live qualification covers the supported local arm64 kind profile; external clusters and x86 remain future qualification work.'},
      {id: 'instrumented-build', disposition: 'Workstream M is carried as a digest-bound patch until equivalent metrics merge upstream.'},
      {id: 'archive-location', disposition: `Live evidence is externally archived at ${live.archive.path} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      `sha256sum ${live.archive.path}`,
      `sha256sum ${live.archive.indexPath}`,
      'node --test contrib/attacknet/instrumentation/*.test.mjs contrib/attacknet/observability/*.test.mjs contrib/attacknet/release/phase-one.test.mjs',
      'contrib/attacknet/check.sh',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const known = ['--output=', '--live-summary=', '--offline-result='];
  const unknown = args.find(arg => !known.some(prefix => arg.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const value = prefix => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const packet = buildPhaseOnePacket({
    liveSummaryPath: value('--live-summary='),
    offlineResultPath: value('--offline-result='),
  });
  const serialized = `${JSON.stringify(packet, null, 2)}\n`;
  if (output) writeFileSync(absolute(output), serialized);
  else process.stdout.write(serialized);
}
