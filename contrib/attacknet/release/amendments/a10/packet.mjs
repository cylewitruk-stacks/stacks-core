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
  A10_ARTIFACTS, A10_ASSERTIONS, A10_SUMMARY_SCHEMA, validateA10LiveQualification,
} from './evidence.mjs';
import {
  A10_PARENT_REVISION, validateA10CandidateAttestation, validateA10Verification,
} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const reviewID = 'release-1-amendment-a10-multi-bitcoin-split-views';

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

/** Derive and constrain the exact one-commit A10 product scope. */
export function a10CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== A10_PARENT_REVISION) throw new Error(`A10 must be one signed non-merge child of ${A10_PARENT_REVISION}`);
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', A10_PARENT_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', A10_PARENT_REVISION, candidateRevision]);
  if (paths.length === 0 || deleted.length > 0) throw new Error('A10 requires non-empty additive changes and permits no deletions');
  const unexpected = paths.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A10 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: A10_PARENT_REVISION, paths};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', A10_PARENT_REVISION, candidateRevision], {cwd: root, maxBuffer: 128 << 20});
}

function validateSummary(summary, candidate, summaryPath, root) {
  validatePortableLiveSummary(summary, candidate, {
    root, schema: A10_SUMMARY_SCHEMA, checkpoint: 'A10',
    requiredArtifacts: Object.keys(A10_ARTIFACTS), requiredAssertions: A10_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: summary.qualifiedTree, description: 'qualified Git tree'},
  });
  const evidenceRoot = dirname(absolute(summaryPath, root));
  const expected = (entry, path, label) => {
    if (absolute(path, root) !== resolve(evidenceRoot, entry)) throw new Error(`${label} does not resolve under the packet evidence root`);
  };
  expected(summary.archive.indexEntry, summary.archive.indexPath, 'archive index');
  expected(`archive/${basename(summary.archive.path)}`, summary.archive.path, 'archive');
  for (const [key, artifact] of Object.entries(summary.artifacts)) expected(artifact.archiveEntry, artifact.path, key);
  validateA10LiveQualification(evidenceRoot, summary.qualifiedTree);
  return summary;
}

/** Build the Full-tier review packet for Amendment A10. */
export function buildA10Packet({
  root = repositoryRoot, candidate = deriveGitCandidate(root), summaryPath,
  attestationPath, evidenceRoot = 'evidence', inventory = undefined,
} = {}) {
  if (!summaryPath || !attestationPath) throw new Error('summaryPath and attestationPath are required');
  if (evidenceRoot !== 'evidence') throw new Error('A10 packet evidenceRoot must be evidence');
  const contract = load('contrib/attacknet/release/amendments/a10/contract.json', root);
  const summary = validateSummary(load(summaryPath, root), candidate, summaryPath, root);
  const verification = load(summary.artifacts.verification.path, root);
  validateA10Verification(verification, summary.qualifiedTree);
  const attestation = validateA10CandidateAttestation(load(attestationPath, root), {
    qualifiedTree: summary.qualifiedTree, patchDigest: verification.patchDigest,
  }, digestFile(summaryPath, root));
  if (attestation.candidateRevision !== candidate.sourceRevision) throw new Error('A10 attestation does not bind the candidate revision');
  const scope = a10CandidateScope(root, candidate.sourceRevision);
  if (summary.artifacts.candidateDiff.digest !== digestBytes(committedPatch(root, candidate.sourceRevision))) throw new Error('A10 candidate diff does not match the committed revision');
  const artifacts = summary.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-multi-bitcoin-split-views', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:candidate-build', 'evidence', artifacts.candidateBuild.archiveEntry, root, artifacts.candidateBuild.path),
    item('evidence:storage-preflight', 'evidence', artifacts.storagePreflight.archiveEntry, root, artifacts.storagePreflight.path),
    item('evidence:topology-drift-negative-control', 'evidence', artifacts.negativeControl.archiveEntry, root, artifacts.negativeControl.path),
    item('evidence:primary-network', 'evidence', artifacts.primaryNetwork.archiveEntry, root, artifacts.primaryNetwork.path),
    item('evidence:primary-policy-a', 'evidence', artifacts.primaryPolicyA.archiveEntry, root, artifacts.primaryPolicyA.path),
    item('evidence:primary-policy-b', 'evidence', artifacts.primaryPolicyB.archiveEntry, root, artifacts.primaryPolicyB.path),
    item('evidence:primary-run', 'evidence', artifacts.primaryRun.archiveEntry, root, artifacts.primaryRun.path),
    item('evidence:primary-campaign', 'evidence', artifacts.primaryCampaign.archiveEntry, root, artifacts.primaryCampaign.path),
    item('evidence:primary-views', 'evidence', artifacts.primaryViews.archiveEntry, root, artifacts.primaryViews.path),
    item('evidence:replay-network', 'evidence', artifacts.replayNetwork.archiveEntry, root, artifacts.replayNetwork.path),
    item('evidence:replay-run', 'evidence', artifacts.replayRun.archiveEntry, root, artifacts.replayRun.path),
    item('evidence:replay-campaign', 'evidence', artifacts.replayCampaign.archiveEntry, root, artifacts.replayCampaign.path),
    item('evidence:replay-views', 'evidence', artifacts.replayViews.archiveEntry, root, artifacts.replayViews.path),
    item('evidence:forensic-bundle', 'evidence', artifacts.forensicManifest.archiveEntry, root, artifacts.forensicManifest.path),
    item('evidence:clean-teardown', 'evidence', artifacts.cleanTeardown.archiveEntry, root, artifacts.cleanTeardown.path),
    item('evidence:live-qualification', 'evidence', artifacts.liveQualification.archiveEntry, root, artifacts.liveQualification.path),
    item('evidence:archive-index', 'evidence', summary.archive.indexEntry, root, summary.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(summary.archive.path)}`, root, summary.archive.path),
    item('evidence:summary', 'evidence', 'live-summary.json', root, summaryPath),
    item('attestation:signed-candidate', 'evidence', 'candidate-attestation.json', root, attestationPath),
  ];
  const source = path => [`candidate:${path}`];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA, reviewId: reviewID, phase: 2, tier: 'Full',
    candidate, evidenceRoot, requirements: [...contract.requirements], inventory: resolvedInventory,
    matrix: [
      {requirement: contract.requirements[0], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/burnchaintopology/topology.go'), ...source('contrib/helm/hacknet/operator/internal/topology/v1beta1_reconciler.go'), 'evidence:primary-network', 'evidence:primary-policy-a', 'evidence:primary-policy-b']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...source('contrib/attacknet/examples/campaigns/bitcoin-competing-branches.yaml'), ...source('contrib/helm/hacknet/operator/internal/fault/reorg_mutation.go'), 'evidence:primary-campaign']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/protocolobservation/reader.go'), 'evidence:primary-run', 'evidence:primary-views']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/protocolassertion/evaluator.go'), 'evidence:primary-run', 'evidence:replay-run']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: ['evidence:topology-drift-negative-control', 'test:hacknet-check']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: ['evidence:primary-network', 'evidence:primary-run', 'evidence:replay-network', 'evidence:replay-run', 'evidence:replay-campaign']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/orchestratormetrics/collector.go'), ...source('contrib/attacknet/observability/dashboards/attacknet-overview.json'), 'evidence:forensic-bundle']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: ['evidence:candidate-build', 'evidence:storage-preflight', 'evidence:live-qualification', 'evidence:clean-teardown', 'evidence:archive-index', 'evidence:archive', 'evidence:summary', 'attestation:signed-candidate']},
    ],
    compatibility: {runtimeBehaviorChanged: true, kubernetesResourcesChanged: true, evidenceInterpretationChanged: true,
      notes: 'A10 adds admitted multi-Bitcoin topology, bound Stacks views, split-view assertions, bounded metrics, and live qualification evidence.'},
    limitations: [
      {id: 'regtest-only', disposition: 'Competing branch mutation remains A9 typed regtest-only behavior with no arbitrary Bitcoin RPC surface.'},
      {id: 'two-node-qualification', disposition: 'The public API is bounded for larger graphs; Release 1 live qualification proves a deterministic two-node graph.'},
      {id: 'actor-observation-boundary', disposition: 'Bitcoin and Stacks protocol values are actor-self-reported through identity-bracketed reads; Kubernetes identity and admitted graph data are orchestrator-observed.'},
      {id: 'review-evidence-archive', disposition: `Portable A10 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
      {id: 'human-review-custody', disposition: 'The mechanical gate cannot attest reviewer identity or comprehension.'},
    ],
    reproduction: [
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a10/a10.test.mjs',
      'node contrib/attacknet/release/phase-review.mjs verify-packet --contract=contrib/attacknet/release/amendments/a10/contract.json --packet=contrib/attacknet/evidence-packets/release-1-a10/review-packet.json',
    ],
  });
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output='); const summary = value('--summary='); const attestation = value('--attestation=');
  if (!output || !summary || !attestation) throw new Error('usage: packet.mjs --output=PATH --summary=PATH --attestation=PATH');
  if (dirname(absolute(summary)) !== resolve(dirname(absolute(output)), 'evidence')) throw new Error('A10 summary must be under the packet-relative evidence root');
  writeFileSync(absolute(output), `${JSON.stringify(buildA10Packet({summaryPath: summary, attestationPath: attestation}), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
