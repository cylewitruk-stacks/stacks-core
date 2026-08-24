#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {deriveGitCandidate} from './phase-zero-packet.mjs';
import {validatePortableLiveSummary} from './portable-live-evidence.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from './phase-review.mjs';

const releaseDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(releaseDir, '../../..');
const APPROVED_PHASE_TWO_REVISION = '7d4a734077bb7216a813b9e8de0ade65fa7b5ec6';
const REVIEW_ID = 'release-1-amendment-a1-compose-retirement';
const LIVE_SCHEMA = 'stacks-attacknet-release-1-a1-live-evidence/v1';
const RETIRED_PATHS = Object.freeze([
  'contrib/attacknet/compose-lifecycle.sh',
  'contrib/attacknet/compose-negative-controls.sh',
]);
const REQUIRED_ARTIFACTS = Object.freeze([
  'candidateDiff', 'doctor', 'lifecycleApply', 'verification',
  'faultRun', 'evidenceCapture', 'cleanTeardown',
]);
const REQUIRED_ASSERTIONS = Object.freeze([
  'supported-environment-doctor',
  'kubernetes-apply-complete',
  'kubernetes-verification-passed',
  'bounded-fault-effect-and-recovery',
  'evidence-capture-complete',
  'clean-teardown',
]);

function absolute(path, root = repoRoot) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function load(path, root = repoRoot) {
  return JSON.parse(readFileSync(absolute(path, root), 'utf8'));
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function digestFile(path, root = repoRoot) {
  return digestBytes(readFileSync(absolute(path, root)));
}

function item(id, kind, path, root = repoRoot, sourcePath = path) {
  return {id, kind, path, digest: digestFile(sourcePath, root)};
}

function candidateId(path) {
  return `candidate:${path}`;
}

function candidateKind(path) {
  return path.endsWith('.md') ? 'document' : 'source';
}

function gitLines(root, args) {
  return execFileSync('git', args, {cwd: root, encoding: 'utf8'}).split('\n').filter(Boolean);
}

/** Derive the exact one-commit amendment scope and require both intended deletions. */
export function releaseOneA1CandidateScope(root = repoRoot, candidateRevision = 'HEAD') {
  try {
    execFileSync('git', ['merge-base', '--is-ancestor', APPROVED_PHASE_TWO_REVISION, candidateRevision], {
      cwd: root,
      stdio: 'ignore',
    });
  } catch {
    throw new Error(`Release 1 amendment A1 must descend from approved Phase 2 ${APPROVED_PHASE_TWO_REVISION}`);
  }
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision]);
  const parentValues = parents[0]?.split(' ').filter(Boolean) ?? [];
  if (parentValues.length !== 1) throw new Error('Release 1 amendment A1 must be one non-merge commit');
  const [parent] = parentValues;
  const paths = gitLines(root, [
    'diff', '--name-only', '--diff-filter=ACMRT', parent, candidateRevision,
  ]).sort();
  if (paths.length === 0) throw new Error('Release 1 amendment A1 candidate scope is empty');
  const deleted = gitLines(root, [
    'diff', '--name-only', '--diff-filter=D', parent, candidateRevision,
  ]).sort();
  if (JSON.stringify(deleted) !== JSON.stringify([...RETIRED_PATHS].sort())) {
    throw new Error(`Release 1 amendment A1 must delete exactly: ${RETIRED_PATHS.join(', ')}`);
  }
  return {parent, paths};
}

function candidatePatch(root, candidateRevision, parent) {
  return execFileSync('git', ['diff', '--binary', parent, candidateRevision], {cwd: root});
}

function requireFileAt(path, expected, label, root) {
  if (absolute(path, root) !== expected) {
    throw new Error(`${label} must resolve to ${expected}`);
  }
}

function validateEvidenceLayout(live, {
  root,
  liveSummaryPath,
  offlineResultPath,
  hacknetResultPath,
}) {
  const liveRoot = dirname(absolute(liveSummaryPath, root));
  requireFileAt(offlineResultPath, resolve(liveRoot, 'offline-result.json'), 'Attacknet offline result', root);
  requireFileAt(hacknetResultPath, resolve(liveRoot, 'hacknet-result.json'), 'Hacknet offline result', root);
  requireFileAt(live.archive.indexPath, resolve(liveRoot, live.archive.indexEntry), 'archive index', root);
  requireFileAt(
    live.archive.path,
    resolve(liveRoot, 'archive', basename(live.archive.path)),
    'evidence archive',
    root,
  );
  for (const key of REQUIRED_ARTIFACTS) {
    const artifact = live.artifacts[key];
    requireFileAt(artifact.path, resolve(liveRoot, artifact.archiveEntry), `artifact ${key}`, root);
  }
}

export function validateReleaseOneA1LiveSummary(summary, candidate, root = repoRoot) {
  return validatePortableLiveSummary(summary, candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Release 1 amendment A1',
    requiredArtifacts: REQUIRED_ARTIFACTS,
    requiredAssertions: REQUIRED_ASSERTIONS,
  });
}

/** Build the Full review packet for the Kubernetes-only Release 1 amendment. */
export function buildReleaseOneA1Packet({
  root = repoRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  offlineResultPath,
  hacknetResultPath,
  evidenceRoot = 'live',
  inventory = undefined,
  candidateScope = undefined,
  committedPatch = undefined,
} = {}) {
  if (!liveSummaryPath || !offlineResultPath || !hacknetResultPath) {
    throw new Error('liveSummaryPath, offlineResultPath, and hacknetResultPath are required');
  }
  const contract = load('contrib/attacknet/release/release-1-a1-contract.json', root);
  const live = validateReleaseOneA1LiveSummary(load(liveSummaryPath, root), candidate, root);
  if (evidenceRoot !== 'live') throw new Error('Release 1 amendment A1 evidenceRoot must be live');
  validateEvidenceLayout(live, {
    root,
    liveSummaryPath,
    offlineResultPath,
    hacknetResultPath,
  });
  const offline = load(offlineResultPath, root);
  if (offline.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || offline.status !== 'passed' || offline.sourceRevision !== candidate.sourceRevision) {
    throw new Error('Attacknet offline check result is not a passed result for the candidate');
  }
  const hacknet = validateHacknetOfflineResult(load(hacknetResultPath, root));
  if (hacknet.sourceRevision !== candidate.sourceRevision) {
    throw new Error('Hacknet offline check result does not pin the candidate');
  }
  const scope = candidateScope ?? releaseOneA1CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(committedPatch
    ?? candidatePatch(root, candidate.sourceRevision, scope.parent));
  if (live.artifacts.candidateDiff.digest !== patchDigest) {
    throw new Error('candidate diff artifact does not match the committed amendment');
  }

  const artifacts = live.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {
      id: 'diff:candidate-compose-retirement',
      kind: 'diff',
      path: artifacts.candidateDiff.archiveEntry,
      digest: artifacts.candidateDiff.digest,
    },
    item('test:offline-check', 'test', 'offline-result.json', root, offlineResultPath),
    item('test:hacknet-check', 'test', 'hacknet-result.json', root, hacknetResultPath),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'live-summary.json', root, liveSummaryPath),
    ...REQUIRED_ARTIFACTS.filter(key => key !== 'candidateDiff').map(key => item(
      `evidence:${key.replace(/[A-Z]/g, match => `-${match.toLowerCase()}`)}`,
      'evidence', artifacts[key].archiveEntry, root, artifacts[key].path,
    )),
  ];

  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA,
    reviewId: REVIEW_ID,
    phase: 2,
    tier: 'Full',
    candidate,
    evidenceRoot,
    requirements: [...contract.requirements],
    inventory: resolvedInventory,
    matrix: [
      {
        requirement: 'kubernetes-only-command-and-runtime-surface', status: 'satisfied',
        evidence: [candidateId('contrib/attacknet/attacknet'), candidateId('contrib/attacknet/command-registry.v1.json'), candidateId('contrib/attacknet/runtime-backend.sh'), 'evidence:lifecycle-apply', 'evidence:verification'],
      },
      {
        requirement: 'compose-implementation-and-artifact-retirement', status: 'satisfied',
        evidence: ['diff:candidate-compose-retirement', candidateId('contrib/attacknet/command-surface.test.mjs'), candidateId('contrib/attacknet/topology.test.mjs')],
      },
      {
        requirement: 'narrowed-release-baseline-without-dangling-claims', status: 'satisfied',
        evidence: [candidateId('contrib/attacknet/release/baseline-v1.json'), candidateId('contrib/attacknet/release/phase-zero.test.mjs')],
      },
      {
        requirement: 'truthful-operator-and-developer-documentation', status: 'satisfied',
        evidence: [candidateId('contrib/attacknet/README.md'), candidateId('contrib/attacknet/OPERATIONS.md'), candidateId('contrib/attacknet/DEVELOPMENT.md'), candidateId('contrib/helm/hacknet/README.md')],
      },
      {
        requirement: 'kubernetes-lifecycle-fault-evidence-and-clean-teardown', status: 'satisfied',
        evidence: ['evidence:doctor', 'evidence:lifecycle-apply', 'evidence:verification', 'evidence:fault-run', 'evidence:evidence-capture', 'evidence:clean-teardown'],
      },
      {
        requirement: 'portable-self-identifying-review-evidence', status: 'satisfied',
        evidence: [candidateId('contrib/attacknet/release/phase-review.mjs'), candidateId('contrib/attacknet/release/portable-live-evidence.mjs'), 'evidence:archive-index', 'evidence:archive'],
      },
      {
        requirement: 'clean-offline-verification', status: 'satisfied',
        evidence: ['test:offline-check', 'test:hacknet-check'],
      },
    ],
    compatibility: {
      runtimeBehaviorChanged: true,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: true,
      notes: 'The unreleased Compose runtime is removed, Kubernetes remains the sole runtime, and the Release 1 capability baseline is narrowed accordingly.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Live amendment evidence covers the supported local three-node arm64 kind profile.'},
      {id: 'historical-compose-evidence', disposition: 'Historical local Compose bundles may remain in external archives but are not Release 1 product evidence or capability claims.'},
      {id: 'archive-location', disposition: `Live evidence is externally archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'contrib/attacknet/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/release-1-a1.test.mjs',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const known = [
    '--output=', '--live-summary=', '--offline-result=', '--hacknet-result=', '--evidence-root=',
  ];
  const unknown = args.find(arg => !known.some(prefix => arg.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const value = prefix => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const liveSummaryPath = value('--live-summary=');
  if (!output || !liveSummaryPath) {
    throw new Error('--output and --live-summary are required');
  }
  if (dirname(absolute(liveSummaryPath)) !== resolve(dirname(absolute(output)), 'live')) {
    throw new Error('live summary must be under the packet-relative live evidence root');
  }
  const packet = buildReleaseOneA1Packet({
    liveSummaryPath,
    offlineResultPath: value('--offline-result='),
    hacknetResultPath: value('--hacknet-result='),
    evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  const serialized = `${JSON.stringify(packet, null, 2)}\n`;
  if (output) writeFileSync(absolute(output), serialized);
  else process.stdout.write(serialized);
}
