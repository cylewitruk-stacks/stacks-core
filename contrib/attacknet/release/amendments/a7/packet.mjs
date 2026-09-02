#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {
  A7_ARTIFACTS, A7_ASSERTIONS, A7_SUMMARY_SCHEMA, validateA7AttacknetResult,
  validateA7HacknetResult,
} from './evidence.mjs';
import {validateA7DeletedPaths, validateA7Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const APPROVED_A6_REVISION = '52e0d2812c514cad29d9fd2603eb2b8b3d93b0c3';
const REVIEW_ID = 'release-1-amendment-a7-legacy-retirement';
/** Return whether a changed path belongs to the A7 legacy-retirement scope. */
export function isA7CandidatePath(path) {
  return path.startsWith('contrib/attacknet/');
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

/** Derive and constrain the exact one-commit legacy-retirement scope. */
export function a7CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A6_REVISION) {
    throw new Error(`A7 must be one non-merge commit directly on approved A6 ${APPROVED_A6_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--no-renames', '--name-only', '--diff-filter=ACMRT', APPROVED_A6_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--no-renames', '--name-only', '--diff-filter=D', APPROVED_A6_REVISION, candidateRevision]).sort();
  if (paths.length === 0 || deleted.length === 0) {
    throw new Error('A7 must contain both current replacements and retired paths');
  }
  const unexpected = [...paths, ...deleted].filter(path => !isA7CandidatePath(path));
  if (unexpected.length > 0) throw new Error(`A7 contains out-of-scope paths: ${unexpected.join(', ')}`);
  const requiredDeletions = gitLines(root, [
    'ls-tree', '-r', '--name-only', APPROVED_A6_REVISION, '--',
    'contrib/attacknet/legacy', 'contrib/attacknet/testdata/legacy-v1alpha1',
  ]).sort();
  const missing = requiredDeletions.filter(path => !deleted.includes(path));
  if (requiredDeletions.length === 0 || missing.length > 0) {
    throw new Error(`A7 does not retire every legacy path: ${missing.join(', ') || 'approved A6 inventory is empty'}`);
  }
  const retained = gitLines(root, [
    'ls-tree', '-r', '--name-only', candidateRevision, '--',
    'contrib/attacknet/legacy', 'contrib/attacknet/testdata/legacy-v1alpha1',
  ]);
  if (retained.length > 0) {
    throw new Error(`A7 candidate retains legacy paths: ${retained.join(', ')}`);
  }
  return {parent: APPROVED_A6_REVISION, paths, deleted, requiredDeletions};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A6_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
}

function validateSummary(value, candidateRevision) {
  if (value?.schema !== A7_SUMMARY_SCHEMA || value.candidateRevision !== candidateRevision) {
    throw new Error('A7 evidence summary does not pin the candidate');
  }
  const assertions = new Map((value.assertions ?? []).map(entry => [entry?.id, entry?.status]));
  if (assertions.size !== A7_ASSERTIONS.length
    || A7_ASSERTIONS.some(id => assertions.get(id) !== 'passed')) {
    throw new Error('A7 evidence summary does not contain every passed assertion');
  }
  for (const key of Object.keys(A7_ARTIFACTS)) {
    const artifact = value.artifacts?.[key];
    if (!artifact || !/^sha256:[0-9a-f]{64}$/.test(artifact.digest ?? '')) {
      throw new Error(`A7 evidence summary omits ${key}`);
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

/** Build the Reduced-tier review packet for Amendment A7. */
export function buildA7Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  summaryPath,
  evidenceRoot = 'evidence',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
} = {}) {
  if (!summaryPath) throw new Error('summaryPath is required');
  const contract = load('contrib/attacknet/release/amendments/a7/contract.json', root);
  const summary = validateSummary(load(summaryPath, root), candidate.sourceRevision);
  if (evidenceRoot !== 'evidence') throw new Error('A7 evidenceRoot must be evidence');
  validateArtifactLayout(summary, summaryPath, root);
  const artifacts = summary.artifacts;
  validateA7Verification(load(artifacts.verification.path, root), candidate.sourceRevision);
  validateA7AttacknetResult(load(artifacts.attacknetCheck.path, root), candidate.sourceRevision);
  validateA7HacknetResult(load(artifacts.hacknetCheck.path, root), candidate.sourceRevision);
  const scope = candidateScope ?? a7CandidateScope(root, candidate.sourceRevision);
  validateA7DeletedPaths(
    load(artifacts.deletedPaths.path, root), candidate.sourceRevision, scope.deleted,
  );
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) {
    throw new Error('candidate diff artifact does not match committed A7');
  }

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-legacy-retirement', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:deleted-paths', 'evidence', artifacts.deletedPaths.archiveEntry, root, artifacts.deletedPaths.path),
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
      {requirement: contract.requirements[0], status: 'satisfied', evidence: ['diff:candidate-legacy-retirement', 'evidence:deleted-paths', 'evidence:verification']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: ['evidence:deleted-paths', ...candidateEvidence('contrib/attacknet/test/contracts/repository-boundary.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/instrumentation/artifact-digest.mjs'), ...candidateEvidence('contrib/attacknet/instrumentation/run-descriptor.mjs'), ...candidateEvidence('contrib/attacknet/instrumentation/image-admission-evidence.mjs'), ...candidateEvidence('contrib/attacknet/observability/render.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/test/fixtures/equivalence/v1alpha1/manifest.json'), ...candidateEvidence('contrib/attacknet/test/support/equivalence-fixtures.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/fault-compiler-equivalence.test.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/topology-render-equivalence.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/README.md'), ...candidateEvidence('contrib/attacknet/docs/development/README.md'), 'diff:candidate-legacy-retirement']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/test/contracts/repository-boundary.test.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/fault-compiler-equivalence.test.mjs'), ...candidateEvidence('contrib/attacknet/test/equivalence/topology-render-equivalence.test.mjs'), 'test:attacknet-check']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:archive-index', 'evidence:archive', 'evidence:summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: false,
      notes: 'A7 removes unsupported executable qualification code, moves byte-identical active modules, and replaces test-time oracles with sealed vectors. It changes no Kubernetes resource, Go controller, fault, or evidence semantics.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'offline-reduced-tier', disposition: 'A7 changes no Kubernetes API, controller state machine, fault semantics, or evidence interpretation; verification is intentionally offline.'},
      {id: 'historical-review-layout', disposition: 'Approved A1 through A6 packets remain bound to their original revisions; current fixture provenance names historical paths without requiring them in the candidate tree.'},
      {id: 'archive-location', disposition: `A7 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a7/a7.test.mjs',
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
    throw new Error('A7 summary must be under the packet-relative evidence root');
  }
  const packet = buildA7Packet({
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
