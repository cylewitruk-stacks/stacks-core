#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {
  A6_ARTIFACTS, A6_ASSERTIONS, A6_SUMMARY_SCHEMA, validateA6AttacknetResult,
  validateA6HacknetResult,
} from './evidence.mjs';
import {validateA6Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const APPROVED_A5_REVISION = '7b16b53c520778a143767751f0b95275f0d7a0d9';
const REVIEW_ID = 'release-1-amendment-a6-repository-hygiene';
const ALLOWED_HACKNET_PATHS = new Set([
  'contrib/helm/hacknet/operator/internal/attacknetcli/examples_test.go',
  'contrib/helm/hacknet/operator/internal/attacknetcli/local_images.go',
  'contrib/helm/hacknet/operator/internal/attacknetcli/local_ops_test.go',
  'contrib/helm/hacknet/scripts/build-local.sh',
  'contrib/helm/hacknet/scripts/check.sh',
]);

/** Return whether a changed path belongs to the A6 repository-hygiene scope. */
export function isA6CandidatePath(path) {
  return path.startsWith('contrib/attacknet/') || ALLOWED_HACKNET_PATHS.has(path);
}

function absolute(path, root = repositoryRoot) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function load(path, root = repositoryRoot) {
  return JSON.parse(readFileSync(absolute(path, root), 'utf8'));
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestFile(path, root = repositoryRoot) {
  return digestBytes(readFileSync(absolute(path, root)));
}

function item(id, kind, path, root = repositoryRoot, sourcePath = path) {
  return {id, kind, path, digest: digestFile(sourcePath, root)};
}

function candidateId(path) {
  return `candidate:${path}`;
}

function candidateKind(path) {
  return path.endsWith('.md') ? 'document' : 'source';
}

function gitLines(root, arguments_) {
  return execFileSync('git', arguments_, {cwd: root, encoding: 'utf8'})
    .split('\n').filter(Boolean);
}

/** Derive and constrain the exact one-commit repository-hygiene scope. */
export function a6CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A5_REVISION) {
    throw new Error(`A6 must be one non-merge commit directly on approved A5 ${APPROVED_A5_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A5_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', APPROVED_A5_REVISION, candidateRevision]).sort();
  if (paths.length === 0 || deleted.length === 0) {
    throw new Error('A6 must contain both the organized surface and retired public legacy paths');
  }
  const unexpected = [...paths, ...deleted].filter(path => !isA6CandidatePath(path));
  if (unexpected.length > 0) throw new Error(`A6 contains out-of-scope paths: ${unexpected.join(', ')}`);
  if (deleted.some(path => !path.startsWith('contrib/attacknet/'))) {
    throw new Error('A6 must not delete Hacknet or node sources');
  }
  return {parent: APPROVED_A5_REVISION, paths, deleted};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A5_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
}

function validateSummary(value, candidateRevision) {
  if (value?.schema !== A6_SUMMARY_SCHEMA || value.candidateRevision !== candidateRevision) {
    throw new Error('A6 evidence summary does not pin the candidate');
  }
  const assertions = new Map((value.assertions ?? []).map(entry => [entry?.id, entry?.status]));
  if (assertions.size !== A6_ASSERTIONS.length
    || A6_ASSERTIONS.some(id => assertions.get(id) !== 'passed')) {
    throw new Error('A6 evidence summary does not contain every passed assertion');
  }
  for (const key of Object.keys(A6_ARTIFACTS)) {
    const artifact = value.artifacts?.[key];
    if (!artifact || !/^sha256:[0-9a-f]{64}$/.test(artifact.digest ?? '')) {
      throw new Error(`A6 evidence summary omits ${key}`);
    }
  }
  return value;
}

function validateArtifactLayout(summary, summaryPath, root) {
  const evidenceRoot = dirname(absolute(summaryPath, root));
  const expected = (entry, path, label) => {
    if (absolute(path, root) !== resolve(evidenceRoot, entry)) {
      throw new Error(`${label} does not resolve under evidenceRoot`);
    }
  };
  expected(summary.archive.indexEntry, summary.archive.indexPath, 'archive index');
  expected(`archive/${basename(summary.archive.path)}`, summary.archive.path, 'archive');
  for (const [key, artifact] of Object.entries(summary.artifacts)) {
    expected(artifact.archiveEntry, artifact.path, key);
  }
}

/** Build the Reduced-tier review packet for Amendment A6. */
export function buildA6Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  summaryPath,
  evidenceRoot = 'evidence',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
} = {}) {
  if (!summaryPath) throw new Error('summaryPath is required');
  const contract = load('contrib/attacknet/release/amendments/a6/contract.json', root);
  const summary = validateSummary(load(summaryPath, root), candidate.sourceRevision);
  if (evidenceRoot !== 'evidence') throw new Error('A6 evidenceRoot must be evidence');
  validateArtifactLayout(summary, summaryPath, root);
  const artifacts = summary.artifacts;
  validateA6Verification(load(artifacts.verification.path, root), candidate.sourceRevision);
  validateA6AttacknetResult(load(artifacts.attacknetCheck.path, root), candidate.sourceRevision);
  validateA6HacknetResult(load(artifacts.hacknetCheck.path, root), candidate.sourceRevision);
  const scope = candidateScope ?? a6CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) {
    throw new Error('candidate diff artifact does not match committed A6');
  }

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-repository-hygiene', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('evidence:archive-index', 'evidence', summary.archive.indexEntry, root, summary.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(summary.archive.path)}`, root, summary.archive.path),
    item('evidence:summary', 'evidence', 'summary.json', root, summaryPath),
  ];

  const candidateEvidence = path => [candidateId(path)];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA,
    reviewId: REVIEW_ID,
    phase: 2,
    tier: 'Reduced',
    candidate,
    evidenceRoot,
    requirements: [...contract.requirements],
    inventory: resolvedInventory,
    matrix: [
      {requirement: contract.requirements[0], status: 'satisfied', evidence: ['diff:candidate-repository-hygiene', 'evidence:verification']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/README.md'), ...candidateEvidence('contrib/attacknet/test/contracts/repository-boundary.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/legacy/v1alpha1/manifest.v1.json'), ...candidateEvidence('contrib/attacknet/test/contracts/repository-boundary.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/scripts/build-local.sh'), ...candidateEvidence('contrib/helm/hacknet/operator/internal/attacknetcli/local_images.go'), 'test:hacknet-check']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/docs/README.md'), ...candidateEvidence('contrib/attacknet/images/README.md'), 'test:attacknet-check']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/test/contracts/repository-boundary.test.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/fault-compiler-equivalence.test.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/topology-render-equivalence.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:archive-index', 'evidence:archive', 'evidence:summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: false,
      notes: 'A6 changes repository ownership and locators only. The Go CLI and controller-runtime operators remain authoritative; the frozen v1alpha1 implementation remains solely as an equivalence oracle.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'offline-reduced-tier', disposition: 'A6 changes no Kubernetes API, controller state machine, fault semantics, or evidence interpretation; verification is intentionally offline.'},
      {id: 'historical-review-layout', disposition: 'Approved A1 through A5 review sources remain at their historical paths because their exact revisions and packets bind those locators.'},
      {id: 'archive-location', disposition: `A6 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a6/a6.test.mjs',
    ],
  });
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--output=', '--summary=', '--evidence-root='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const output = value('--output=');
  const summaryPath = value('--summary=');
  if (!output || !summaryPath) throw new Error('usage: packet.mjs --output=PATH --summary=PATH');
  if (dirname(absolute(summaryPath)) !== resolve(dirname(absolute(output)), 'evidence')) {
    throw new Error('A6 summary must be under the packet-relative evidence root');
  }
  const packet = buildA6Packet({
    summaryPath,
    evidenceRoot: value('--evidence-root=') ?? 'evidence',
  });
  writeFileSync(absolute(output), `${JSON.stringify(packet, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
