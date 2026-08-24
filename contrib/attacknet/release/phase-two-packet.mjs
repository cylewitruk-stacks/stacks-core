#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from './phase-zero-packet.mjs';
import {validatePortableLiveSummary} from './portable-live-evidence.mjs';
import {REVIEW_PACKET_SCHEMA_V1, sealReviewPacket} from './phase-review.mjs';

const releaseDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(releaseDir, '../../..');
const PHASE_ONE_REVISION = 'e61c589a66f04d436f6777622176e43d06ae9266';
const LIVE_SCHEMA = 'stacks-attacknet-phase-2-live-evidence/v1';
const REQUIRED_ARTIFACTS = Object.freeze([
  'doctor', 'humanWorkflow', 'agentWorkflow', 'cleanTeardown',
]);
const REQUIRED_ASSERTIONS = Object.freeze([
  'supported-environment-doctor',
  'human-workflow-complete',
  'agent-workflow-complete',
  'fault-through-facade',
  'evidence-captured',
  'clean-teardown',
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

function candidateId(path) {
  return `candidate:${path}`;
}

function candidateKind(path) {
  if (path.endsWith('.md')) return 'document';
  return 'source';
}

export function phaseTwoCandidateInventorySpec(root = repoRoot, candidateRevision = 'HEAD') {
  const parent = execFileSync('git', ['rev-parse', `${candidateRevision}^`], {cwd: root, encoding: 'utf8'}).trim();
  if (parent !== PHASE_ONE_REVISION) {
    throw new Error(`Phase 2 candidate must be based directly on approved Phase 1 ${PHASE_ONE_REVISION}`);
  }
  const paths = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRT', PHASE_ONE_REVISION, candidateRevision], {
    cwd: root, encoding: 'utf8',
  }).split('\n').filter(Boolean).sort();
  if (paths.length === 0) throw new Error('Phase 2 candidate scope is empty');
  return paths.map(path => [candidateId(path), candidateKind(path), path]);
}

export function validatePhaseTwoLiveSummary(summary, candidate, root = repoRoot) {
  return validatePortableLiveSummary(summary, candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Phase 2',
    requiredArtifacts: REQUIRED_ARTIFACTS,
    requiredAssertions: REQUIRED_ASSERTIONS,
  });
}

export function buildPhaseTwoPacket({
  root = repoRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  offlineResultPath,
  evidenceRoot = 'live',
  inventory = undefined,
} = {}) {
  if (!liveSummaryPath) throw new Error('liveSummaryPath is required');
  if (!offlineResultPath) throw new Error('offlineResultPath is required');
  const contract = load('contrib/attacknet/release/phase-2-contract.json', root);
  const live = validatePhaseTwoLiveSummary(load(liveSummaryPath, root), candidate, root);
  const offline = load(offlineResultPath, root);
  if (offline.schemaVersion !== 'stacks-attacknet-offline-check-result/v1' || offline.status !== 'passed') {
    throw new Error('offline check result is not a passed canonical result');
  }
  const artifacts = live.artifacts;
  const resolvedInventory = inventory ?? [
    ...phaseTwoCandidateInventorySpec(root, candidate.sourceRevision).map(parts => item(...parts, root)),
    item('test:offline-check', 'test', 'offline-result.json', root, offlineResultPath),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'live-summary.json', root, liveSummaryPath),
    ...REQUIRED_ARTIFACTS.map(key => item(
      `evidence:${key.replace(/[A-Z]/g, match => `-${match.toLowerCase()}`)}`,
      'evidence', artifacts[key].archiveEntry, root, artifacts[key].path,
    )),
  ];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA_V1,
    phase: 2,
    tier: 'Full',
    candidate,
    evidenceRoot,
    requirements: [...contract.requirements],
    inventory: resolvedInventory,
    matrix: [
      {requirement: 'versioned-command-registry', status: 'satisfied', evidence: [candidateId('contrib/attacknet/command-registry.v1.json'), candidateId('contrib/attacknet/command-contract.cjs')]},
      {requirement: 'consistent-command-facade', status: 'satisfied', evidence: [candidateId('contrib/attacknet/attacknet'), candidateId('contrib/attacknet/command-surface.test.mjs')]},
      {requirement: 'truthful-environment-doctor', status: 'satisfied', evidence: [candidateId('contrib/attacknet/doctor.mjs'), candidateId('contrib/attacknet/doctor.test.mjs'), 'evidence:doctor']},
      {requirement: 'hermetic-offline-verification', status: 'satisfied', evidence: ['test:offline-check', candidateId('contrib/attacknet/command-surface.test.mjs')]},
      {requirement: 'human-live-usability', status: 'satisfied', evidence: ['evidence:human-workflow', 'evidence:clean-teardown']},
      {requirement: 'agent-live-usability', status: 'satisfied', evidence: ['evidence:agent-workflow', 'evidence:clean-teardown']},
      {requirement: 'cadence-aware-recovery-proof', status: 'satisfied', evidence: [candidateId('contrib/attacknet/campaign-runner.sh'), candidateId('contrib/attacknet/progress-window.test.mjs'), 'evidence:human-workflow']},
      {requirement: 'portable-self-identifying-review-evidence', status: 'satisfied', evidence: [candidateId('contrib/attacknet/release/phase-review.mjs'), candidateId('contrib/attacknet/release/phase-zero.test.mjs'), 'evidence:archive-index']},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: true,
      notes: 'The facade delegates existing actor behavior, while review-tool identity, portable evidence locators, and the cadence-aware post-chaos progress assertion change evidence interpretation.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Release 1 live usability covers the supported local arm64 kind profile; external clusters and x86 remain future qualification work.'},
      {id: 'archive-location', disposition: `Live evidence is externally archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'node --test contrib/attacknet/command-surface.test.mjs contrib/attacknet/doctor.test.mjs contrib/attacknet/release/phase-two.test.mjs',
      'contrib/attacknet/check.sh',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const known = ['--output=', '--live-summary=', '--offline-result=', '--evidence-root='];
  const unknown = args.find(arg => !known.some(prefix => arg.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const value = prefix => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const packet = buildPhaseTwoPacket({
    liveSummaryPath: value('--live-summary='),
    offlineResultPath: value('--offline-result='),
    evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  const serialized = `${JSON.stringify(packet, null, 2)}\n`;
  if (output) writeFileSync(absolute(output), serialized);
  else process.stdout.write(serialized);
}
