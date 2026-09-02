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
  A9_ARTIFACTS, A9_ASSERTIONS, A9_SUMMARY_SCHEMA, validateA9LiveQualification,
} from './evidence.mjs';
import {
  A9_PARENT_REVISION, validateA9CandidateAttestation, validateA9Verification,
} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const REVIEW_ID = 'release-1-amendment-a9-bitcoin-reorganizations';

function absolute(path, root = repositoryRoot) { return isAbsolute(path) ? path : resolve(root, path); }
function load(path, root = repositoryRoot) { return JSON.parse(readFileSync(absolute(path, root), 'utf8')); }
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path, root = repositoryRoot) { return digestBytes(readFileSync(absolute(path, root))); }
function item(id, kind, path, root = repositoryRoot, sourcePath = path) {
  return {id, kind, path, digest: digestFile(sourcePath, root)};
}
function candidateKind(path) { return path.endsWith('.md') ? 'document' : 'source'; }
function gitLines(root, arguments_) {
  return execFileSync('git', arguments_, {cwd: root, encoding: 'utf8'}).split('\n').filter(Boolean);
}

/** Derive and constrain the exact one-commit A9 product scope. */
export function a9CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== A9_PARENT_REVISION) {
    throw new Error(`A9 must be one signed non-merge child of ${A9_PARENT_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', A9_PARENT_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', A9_PARENT_REVISION, candidateRevision]);
  if (paths.length === 0 || deleted.length > 0) throw new Error('A9 requires non-empty additive changes and permits no deletions');
  const unexpected = paths.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A9 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: A9_PARENT_REVISION, paths};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', A9_PARENT_REVISION, candidateRevision], {cwd: root, maxBuffer: 128 << 20});
}

function validateSummary(summary, candidate, summaryPath, root) {
  validatePortableLiveSummary(summary, candidate, {
    root, schema: A9_SUMMARY_SCHEMA, checkpoint: 'A9',
    requiredArtifacts: Object.keys(A9_ARTIFACTS), requiredAssertions: A9_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: summary.qualifiedTree, description: 'qualified Git tree'},
  });
  const evidenceRoot = dirname(absolute(summaryPath, root));
  const expected = (entry, path, label) => {
    const want = resolve(evidenceRoot, entry);
    if (absolute(path, root) !== want) throw new Error(`${label} does not resolve under the packet evidence root`);
  };
  expected(summary.archive.indexEntry, summary.archive.indexPath, 'archive index');
  expected(`archive/${basename(summary.archive.path)}`, summary.archive.path, 'archive');
  for (const [key, artifact] of Object.entries(summary.artifacts)) expected(artifact.archiveEntry, artifact.path, key);
  validateA9LiveQualification(evidenceRoot, summary.qualifiedTree);
  return summary;
}

/** Build the Full-tier review packet for Amendment A9. */
export function buildA9Packet({
  root = repositoryRoot, candidate = deriveGitCandidate(root), summaryPath,
  attestationPath, evidenceRoot = 'evidence', inventory = undefined,
} = {}) {
  if (!summaryPath || !attestationPath) throw new Error('summaryPath and attestationPath are required');
  if (evidenceRoot !== 'evidence') throw new Error('A9 packet evidenceRoot must be evidence');
  const contract = load('contrib/attacknet/release/amendments/a9/contract.json', root);
  const summary = validateSummary(load(summaryPath, root), candidate, summaryPath, root);
  const verification = load(summary.artifacts.verification.path, root);
  validateA9Verification(verification, summary.qualifiedTree);
  const attestation = validateA9CandidateAttestation(
    load(attestationPath, root),
    {qualifiedTree: summary.qualifiedTree, patchDigest: verification.patchDigest},
    digestFile(summaryPath, root),
  );
  if (attestation.candidateRevision !== candidate.sourceRevision) throw new Error('A9 attestation does not bind the candidate revision');
  const scope = a9CandidateScope(root, candidate.sourceRevision);
  if (summary.artifacts.candidateDiff.digest !== digestBytes(committedPatch(root, candidate.sourceRevision))) {
    throw new Error('A9 candidate diff does not match the committed revision');
  }
  const artifacts = summary.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-bitcoin-reorganization', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:storage-preflight', 'evidence', artifacts.storagePreflight.archiveEntry, root, artifacts.storagePreflight.path),
    item('evidence:live-qualification', 'evidence', artifacts.liveQualification.archiveEntry, root, artifacts.liveQualification.path),
    item('evidence:negative-control', 'evidence', artifacts.negativeControl.archiveEntry, root, artifacts.negativeControl.path),
    item('evidence:primary-run', 'evidence', artifacts.primaryRun.archiveEntry, root, artifacts.primaryRun.path),
    item('evidence:primary-campaign', 'evidence', artifacts.primaryCampaign.archiveEntry, root, artifacts.primaryCampaign.path),
    item('evidence:primary-views', 'evidence', artifacts.primaryViews.archiveEntry, root, artifacts.primaryViews.path),
    item('evidence:flash-receipt', 'evidence', artifacts.flashReceipt.archiveEntry, root, artifacts.flashReceipt.path),
    item('evidence:replay-run', 'evidence', artifacts.replayRun.archiveEntry, root, artifacts.replayRun.path),
    item('evidence:replay-campaign', 'evidence', artifacts.replayCampaign.archiveEntry, root, artifacts.replayCampaign.path),
    item('evidence:replay-views', 'evidence', artifacts.replayViews.archiveEntry, root, artifacts.replayViews.path),
    item('evidence:forensic-bundle', 'evidence', artifacts.forensicManifest.archiveEntry, root, artifacts.forensicManifest.path),
    item('evidence:clean-teardown', 'evidence', artifacts.cleanTeardown.archiveEntry, root, artifacts.cleanTeardown.path),
    item('evidence:archive-index', 'evidence', summary.archive.indexEntry, root, summary.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(summary.archive.path)}`, root, summary.archive.path),
    item('evidence:summary', 'evidence', 'live-summary.json', root, summaryPath),
    item('attestation:signed-candidate', 'evidence', 'candidate-attestation.json', root, attestationPath),
  ];
  const source = path => [`candidate:${path}`];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA, reviewId: REVIEW_ID, phase: 2, tier: 'Full',
    candidate, evidenceRoot, requirements: [...contract.requirements], inventory: resolvedInventory,
    matrix: [
      {requirement: contract.requirements[0], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/api/v1beta1/faultcampaign_types.go'), ...source('contrib/helm/hacknet/operator/internal/fault/v1beta1_validation.go'), 'test:hacknet-check']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/burnchain/reorg.go'), ...source('contrib/helm/hacknet/operator/internal/burnchainworker/worker.go'), 'evidence:primary-campaign']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: ['evidence:negative-control', ...source('contrib/helm/hacknet/operator/internal/burnchain/reorg_test.go')]},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/fault/reorg_mutation.go'), ...source('contrib/helm/hacknet/operator/internal/burnchain/boundary.go'), 'evidence:primary-campaign', 'evidence:flash-receipt']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/fault/reorg_mutation_test.go'), 'evidence:forensic-bundle']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: ['evidence:primary-run', 'evidence:primary-views', 'evidence:replay-run', 'evidence:replay-views']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: ['evidence:primary-campaign', 'evidence:flash-receipt', ...source('contrib/attacknet/docs/concepts/bitcoin-reorganizations.md')]},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:primary-run', 'evidence:primary-campaign', 'evidence:replay-run', 'evidence:replay-campaign']},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[9], status: 'satisfied', evidence: ['evidence:storage-preflight']},
      {requirement: contract.requirements[10], status: 'satisfied', evidence: ['evidence:live-qualification', 'evidence:forensic-bundle', 'evidence:archive-index', 'evidence:archive', 'evidence:summary', 'attestation:signed-candidate']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true, kubernetesResourcesChanged: true, evidenceInterpretationChanged: true,
      notes: 'A9 adds a typed semantic Bitcoin regtest reorganization, policy-bound worker lifecycle, trusted branch evidence, and review validators.',
    },
    limitations: [
      {id: 'single-bitcoin-view', disposition: 'A9 proves one canonical regtest branch replacement. Multi-Bitcoin-node partitions and simultaneous honest split views remain A11.'},
      {id: 'regtest-only', disposition: 'The worker independently rejects every Bitcoin chain other than regtest and exposes no arbitrary RPC method.'},
      {id: 'actor-observation-boundary', disposition: 'Stacks node chain views are actor-self-reported and identity-bound; Bitcoin branch mutation receipts and Kubernetes identity are controller-observed.'},
      {id: 'review-evidence-archive', disposition: `Portable A9 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
      {id: 'human-review-custody', disposition: 'The mechanical gate cannot attest reviewer identity or comprehension.'},
    ],
    reproduction: [
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a9/a9.test.mjs',
      'node contrib/attacknet/release/phase-review.mjs verify-packet --contract=contrib/attacknet/release/amendments/a9/contract.json --packet=contrib/attacknet/evidence-packets/release-1-a9/review-packet.json',
    ],
  });
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output='); const summary = value('--summary='); const attestation = value('--attestation=');
  if (!output || !summary || !attestation) throw new Error('usage: packet.mjs --output=PATH --summary=PATH --attestation=PATH');
  if (dirname(absolute(summary)) !== resolve(dirname(absolute(output)), 'evidence')) {
    throw new Error('A9 summary must be under the packet-relative evidence root');
  }
  writeFileSync(absolute(output), `${JSON.stringify(buildA9Packet({summaryPath: summary, attestationPath: attestation}), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
