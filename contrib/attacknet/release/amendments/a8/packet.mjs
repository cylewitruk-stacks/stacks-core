#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {
  A8_ARTIFACTS, A8_ASSERTIONS, A8_SUMMARY_SCHEMA, validateA8LiveQualification,
} from './evidence.mjs';
import {validateA8CandidateAttestation, validateA8Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const APPROVED_A7_ROADMAP_REVISION = 'c428fcbb42bb8884cc1fe47055576130ba061346';
const REVIEW_ID = 'release-1-amendment-a8-trusted-observations';

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

function candidateKind(path) {
  return path.endsWith('.md') ? 'document' : 'source';
}

function gitLines(root, arguments_) {
  return execFileSync('git', arguments_, {cwd: root, encoding: 'utf8'})
    .split('\n').filter(Boolean);
}

/** Derive and constrain the exact one-commit A8 product scope. */
export function a8CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A7_ROADMAP_REVISION) {
    throw new Error(`A8 must be one commit directly on ${APPROVED_A7_ROADMAP_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A7_ROADMAP_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', APPROVED_A7_ROADMAP_REVISION, candidateRevision]);
  if (paths.length === 0 || deleted.length > 0) throw new Error('A8 requires non-empty additive changes and permits no deletions');
  const unexpected = paths.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A8 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: APPROVED_A7_ROADMAP_REVISION, paths};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A7_ROADMAP_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
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
  for (const [key, artifact] of Object.entries(summary.artifacts)) expected(artifact.archiveEntry, artifact.path, key);
}

/** Build the Full-tier review packet for Amendment A8. */
export function buildA8Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  summaryPath,
  evidenceRoot = 'evidence',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
  signedCandidateBinding = undefined,
  attestationPath = undefined,
  qualifiedCandidateTree = undefined,
} = {}) {
  if (!summaryPath) throw new Error('summaryPath is required');
  if (evidenceRoot !== 'evidence') throw new Error('A8 evidenceRoot must be evidence');
  const contract = load('contrib/attacknet/release/amendments/a8/contract.json', root);
  const candidateTree = qualifiedCandidateTree
    ?? gitLines(root, ['show', '-s', '--format=%T', candidate.sourceRevision])[0];
  const summary = validatePortableLiveSummary(load(summaryPath, root), candidate, {
    root, schema: A8_SUMMARY_SCHEMA, checkpoint: 'A8',
    requiredArtifacts: Object.keys(A8_ARTIFACTS), requiredAssertions: A8_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: candidateTree, description: 'qualified tree'},
  });
  validateArtifactLayout(summary, summaryPath, root);
  const artifacts = summary.artifacts;
  const verification = validateA8Verification(load(artifacts.verification.path, root), summary.qualifiedTree);
  const summaryDigest = digestFile(summaryPath, root);
  const binding = validateA8CandidateAttestation(
    signedCandidateBinding ?? load(attestationPath, root), verification, summaryDigest,
  );
  if (binding.candidateRevision !== candidate.sourceRevision
    || binding.candidateTree !== summary.qualifiedTree
    || binding.patchDigest !== verification.patchDigest) {
    throw new Error('signed A8 candidate does not match the qualified tree and diff');
  }
  validateA8LiveQualification(
    load(artifacts.liveQualification.path, root), summary.qualifiedTree,
    dirname(absolute(artifacts.liveQualification.path, root)),
  );
  const scope = candidateScope ?? a8CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) throw new Error('candidate diff artifact does not match committed A8');
  if (verification.patchDigest !== patchDigest) throw new Error('qualified diff digest does not match committed A8');

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-trusted-observations', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:live-qualification', 'evidence', artifacts.liveQualification.archiveEntry, root, artifacts.liveQualification.path),
    item('evidence:archive-index', 'evidence', summary.archive.indexEntry, root, summary.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(summary.archive.path)}`, root, summary.archive.path),
    item('evidence:summary', 'evidence', 'summary.json', root, summaryPath),
    item('attestation:signed-candidate', 'evidence', 'candidate-attestation.json', root, attestationPath),
  ];
  const candidateEvidence = path => [`candidate:${path}`];
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
      {requirement: contract.requirements[0], status: 'satisfied', evidence: ['diff:candidate-trusted-observations', 'evidence:verification', 'attestation:signed-candidate', ...candidateEvidence('contrib/attacknet/release/amendments/a8/qualification/candidate-build.mjs'), 'evidence:live-qualification', 'evidence:summary']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/operator/internal/protocolobservation/reader.go'), 'test:hacknet-check', 'evidence:live-qualification']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/operator/api/v1beta1/protocolassertion_types.go'), ...candidateEvidence('contrib/helm/hacknet/operator/internal/protocolassertion/evaluator.go'), ...candidateEvidence('contrib/helm/hacknet/operator/internal/run/v1beta1_schedule.go'), 'test:hacknet-check']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/operator/internal/run/v1beta1_reconciler.go'), 'test:hacknet-check', 'evidence:live-qualification']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/operator/internal/fault/v1beta1_observations.go'), 'evidence:live-qualification']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: [...candidateEvidence('contrib/helm/hacknet/operator/internal/attacknetcli/loki_evidence.go'), ...candidateEvidence('contrib/helm/hacknet/operator/internal/attacknetcli/teardown.go'), 'evidence:live-qualification']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/observability/render.mjs'), ...candidateEvidence('contrib/attacknet/observability/dashboards/attacknet-overview.json'), 'test:attacknet-check']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: [...candidateEvidence('contrib/attacknet/release/amendments/a8/qualification/live.mjs'), 'evidence:live-qualification']},
      {requirement: contract.requirements[9], status: 'satisfied', evidence: ['evidence:archive-index', 'evidence:archive', 'evidence:summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true,
      kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'A8 adds typed API fields, controller terminal gates, direct actor observation reads, a destructive-operation evidence barrier, and new evidence semantics; Full-tier qualification is mandatory.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'finite-a8-vocabulary', disposition: 'A8 qualifies height/progress, cohort, signer registration/freshness, proposal visibility, and telemetry completeness. Hash, chainwork, balance, supply, and transaction assertions remain roadmap work.'},
      {id: 'actor-self-reported-values', disposition: 'The bridge authenticates endpoint identity and freshness; actor metric values remain actor-self-reported and are labelled as such.'},
      {id: 'prometheus-range-export', disposition: 'The teardown barrier exports complete retained Loki logs and bounded incident state. Prometheus range export remains a separate operator action.'},
      {id: 'archive-location', disposition: `A8 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      'go test -race ./...',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a8/a8.test.mjs',
    ],
  });
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--output=', '--summary=', '--attestation=', '--evidence-root='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const output = value('--output=');
  const summaryPath = value('--summary=');
  const attestationPath = value('--attestation=');
  if (!output || !summaryPath || !attestationPath) {
    throw new Error('usage: packet.mjs --output=PATH --summary=PATH --attestation=PATH');
  }
  if (dirname(absolute(summaryPath)) !== resolve(dirname(absolute(output)), 'evidence')) {
    throw new Error('A8 summary must be under the packet-relative evidence root');
  }
  writeFileSync(absolute(output), `${JSON.stringify(buildA8Packet({
    summaryPath, attestationPath, evidenceRoot: value('--evidence-root=') ?? 'evidence',
  }), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
