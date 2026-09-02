#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {A12_ARTIFACTS, validateA12Summary} from './evidence.mjs';
import {
  A12_PARENT_REVISION, validateA12CandidateAttestation, validateA12Verification,
} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const reviewID = 'release-1-amendment-a12-deterministic-adversarial-actors';

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

/** Report whether one changed path belongs to the A12 amendment boundary. */
export function isA12PathPermitted(path) {
  return path === '.gitattributes'
    || path.startsWith('contrib/attacknet/') || path.startsWith('contrib/helm/hacknet/');
}

/** Derive and constrain the exact one-commit A12 product scope. */
export function a12CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== A12_PARENT_REVISION) {
    throw new Error(`A12 must be one signed non-merge child of ${A12_PARENT_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', A12_PARENT_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', A12_PARENT_REVISION, candidateRevision]).sort();
  const permittedDeletions = new Set([
    'contrib/attacknet/test/fixtures/adversaries/rejecting-signer.patch',
  ]);
  const unexpectedDeletions = deleted.filter(path => !permittedDeletions.has(path));
  if (paths.length === 0 || unexpectedDeletions.length > 0) {
    throw new Error(`A12 has no changes or unexpected deletions: ${unexpectedDeletions.join(', ')}`);
  }
  const unexpected = [...paths, ...deleted]
    .filter(path => !isA12PathPermitted(path));
  if (unexpected.length > 0) throw new Error(`A12 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: A12_PARENT_REVISION, paths, deleted};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', A12_PARENT_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
}

/** Build the Full-tier review packet for Amendment A12. */
export function buildA12Packet({
  root = repositoryRoot, candidate = deriveGitCandidate(root), summaryPath,
  attestationPath, evidenceRoot = 'evidence', inventory = undefined,
} = {}) {
  if (!summaryPath || !attestationPath) throw new Error('summaryPath and attestationPath are required');
  if (evidenceRoot !== 'evidence') throw new Error('A12 packet evidenceRoot must be evidence');
  const contract = load('contrib/attacknet/release/amendments/a12/contract.json', root);
  const summary = validateA12Summary(load(summaryPath, root), candidate, summaryPath, root);
  const verification = load(summary.artifacts.verification.path, root);
  validateA12Verification(verification, summary.qualifiedTree);
  const attestation = validateA12CandidateAttestation(load(attestationPath, root), {
    qualifiedTree: summary.qualifiedTree, patchDigest: verification.patchDigest,
  }, digestFile(summaryPath, root));
  if (attestation.candidateRevision !== candidate.sourceRevision) {
    throw new Error('A12 attestation does not bind the candidate revision');
  }
  const scope = a12CandidateScope(root, candidate.sourceRevision);
  if (summary.artifacts.candidateDiff.digest !== digestBytes(committedPatch(root, candidate.sourceRevision))) {
    throw new Error('A12 candidate diff does not match the committed revision');
  }
  const artifacts = summary.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-adversarial-actors', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:candidate-build', 'evidence', artifacts.candidateBuild.archiveEntry, root, artifacts.candidateBuild.path),
    item('evidence:normal-image-control', 'evidence', artifacts.normalImageControl.archiveEntry, root, artifacts.normalImageControl.path),
    item('evidence:policy-drift-control', 'evidence', artifacts.policyDriftControl.archiveEntry, root, artifacts.policyDriftControl.path),
    item('evidence:egress-control', 'evidence', artifacts.egressControl.archiveEntry, root, artifacts.egressControl.path),
    item('evidence:forgery-control', 'evidence', artifacts.forgeryControl.archiveEntry, root, artifacts.forgeryControl.path),
    item('evidence:observer-replacement-control', 'evidence', artifacts.observerReplacementControl.archiveEntry, root, artifacts.observerReplacementControl.path),
    item('evidence:below-quorum-network', 'evidence', artifacts.belowNetwork.archiveEntry, root, artifacts.belowNetwork.path),
    item('evidence:below-quorum-run', 'evidence', artifacts.belowRun.archiveEntry, root, artifacts.belowRun.path),
    item('evidence:below-quorum-campaign', 'evidence', artifacts.belowCampaign.archiveEntry, root, artifacts.belowCampaign.path),
    item('evidence:quorum-loss-network', 'evidence', artifacts.quorumNetwork.archiveEntry, root, artifacts.quorumNetwork.path),
    item('evidence:quorum-loss-run', 'evidence', artifacts.quorumRun.archiveEntry, root, artifacts.quorumRun.path),
    item('evidence:quorum-loss-campaign', 'evidence', artifacts.quorumCampaign.archiveEntry, root, artifacts.quorumCampaign.path),
    item('evidence:replay-network', 'evidence', artifacts.replayNetwork.archiveEntry, root, artifacts.replayNetwork.path),
    item('evidence:replay-run', 'evidence', artifacts.replayRun.archiveEntry, root, artifacts.replayRun.path),
    item('evidence:replay-campaign', 'evidence', artifacts.replayCampaign.archiveEntry, root, artifacts.replayCampaign.path),
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
      {requirement: contract.requirements[0], status: 'satisfied', evidence: [...source('contrib/attacknet/test/fixtures/adversaries/deterministic-signer.patch'), 'evidence:candidate-build', 'evidence:normal-image-control']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/adversarial/policy.go'), 'test:hacknet-check']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/inventory/inventory.go'), ...source('contrib/helm/hacknet/operator/internal/topology/networkpolicy.go'), 'evidence:below-quorum-network']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/fault/v1beta1_compiler.go'), 'evidence:below-quorum-campaign', 'evidence:quorum-loss-campaign']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/probeattribution/verify.go'), ...source('contrib/helm/hacknet/operator/internal/fault/signer_behavior.go'), 'evidence:below-quorum-campaign']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/topology/networkpolicy.go'), 'evidence:egress-control']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: ['evidence:normal-image-control', 'evidence:policy-drift-control', 'evidence:forgery-control', 'evidence:observer-replacement-control']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:below-quorum-run', 'evidence:quorum-loss-run', 'evidence:below-quorum-campaign', 'evidence:quorum-loss-campaign']},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: ['evidence:below-quorum-network', 'evidence:below-quorum-run', 'evidence:replay-network', 'evidence:replay-run', 'evidence:replay-campaign']},
      {requirement: contract.requirements[9], status: 'satisfied', evidence: [...source('contrib/attacknet/observability/dashboards/attacknet-overview.json'), 'evidence:forensic-bundle']},
      {requirement: contract.requirements[10], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[11], status: 'satisfied', evidence: ['evidence:candidate-build', 'evidence:live-qualification', 'evidence:clean-teardown', 'evidence:archive-index', 'evidence:archive', 'evidence:summary', 'attestation:signed-candidate']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true, kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'A12 adds testing-only deterministic signer behaviors, restricted egress, signed attribution, quorum-aware campaigns, and fail-closed live qualification evidence.',
    },
    limitations: [
      {id: 'testing-only-signer', disposition: 'Adversarial behavior is compiled only into a locally built signer with the Rust testing feature; production signer images remain outside this behavior surface.'},
      {id: 'actor-self-report-content', disposition: 'The external observer signs transport and identity facts, but signer counters remain actor-self-reported and are corroborated against protocol outcomes.'},
      {id: 'preconfigured-policy-window', disposition: 'The immutable behavior policy is admitted at topology creation; a FaultCampaign authorizes and attributes a matching observation window rather than hot-patching the signer process.'},
      {id: 'unseeded-node-relay-randomness', disposition: 'The A12 seed controls its bounded testing policy and orchestration inputs, not node-internal P2P or relay randomness, OS scheduling, transport ordering, block hashes, or timings; replay proves the same bounded match count and outcome class rather than a byte-identical trace.'},
      {id: 'local-kind-r1', disposition: 'Release 1 qualifies linux/arm64 images on a local three-node kind cluster; registry and multi-architecture publication remain future work.'},
      {id: 'review-evidence-archive', disposition: `Portable A12 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
      {id: 'human-review-custody', disposition: 'The mechanical gate cannot attest reviewer identity or comprehension.'},
    ],
    reproduction: [
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a12/a12.test.mjs',
      'node contrib/attacknet/release/phase-review.mjs verify-packet --contract=contrib/attacknet/release/amendments/a12/contract.json --packet=contrib/attacknet/evidence-packets/release-1-a12/review-packet.json',
    ],
  });
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const summary = value('--summary=');
  const attestation = value('--attestation=');
  if (!output || !summary || !attestation) {
    throw new Error('usage: packet.mjs --output=PATH --summary=PATH --attestation=PATH');
  }
  if (dirname(absolute(summary)) !== resolve(dirname(absolute(output)), 'evidence')) {
    throw new Error('A12 summary must be under the packet-relative evidence root');
  }
  writeFileSync(absolute(output), `${JSON.stringify(buildA12Packet({summaryPath: summary, attestationPath: attestation}), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
