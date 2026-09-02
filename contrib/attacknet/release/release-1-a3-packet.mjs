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
import {A3_ARTIFACTS, A3_ASSERTIONS, validateA3Verification} from './release-1-a3-evidence.mjs';
import {validateClockPolicyProof} from './release-1-a3-clock-live.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const APPROVED_A2_REVISION = '7765c308a761acb9e73bfc7893761904ede0caf1';
const REVIEW_ID = 'release-1-amendment-a3-controller-hardening';
const LIVE_SCHEMA = 'stacks-attacknet-release-1-a3-live-evidence/v1';

function absolute(path, root = repositoryRoot) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function load(path, root = repositoryRoot) {
  return JSON.parse(readFileSync(absolute(path, root), 'utf8'));
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
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
  return execFileSync('git', arguments_, {cwd: root, encoding: 'utf8'}).split('\n').filter(Boolean);
}

/** Derive the exact one-commit A3 scope directly above approved A2. */
export function releaseOneA3CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A2_REVISION) {
    throw new Error(`A3 must be one non-merge commit directly on approved A2 ${APPROVED_A2_REVISION}`);
  }
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', APPROVED_A2_REVISION, candidateRevision]);
  if (deleted.length > 0) throw new Error(`A3 must not delete files: ${deleted.join(', ')}`);
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A2_REVISION, candidateRevision]).sort();
  if (paths.length === 0) throw new Error('A3 candidate scope is empty');
  const unexpected = paths.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A3 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: APPROVED_A2_REVISION, paths};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A2_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 64 << 20,
  });
}

function validateArtifactLayout(live, liveSummaryPath, root) {
  const liveRoot = dirname(absolute(liveSummaryPath, root));
  const expected = (path, value, label) => {
    if (absolute(value, root) !== resolve(liveRoot, path)) throw new Error(`${label} does not resolve under evidenceRoot`);
  };
  expected(live.archive.indexEntry, live.archive.indexPath, 'archive index');
  expected(`archive/${basename(live.archive.path)}`, live.archive.path, 'archive');
  for (const key of Object.keys(A3_ARTIFACTS)) {
    expected(live.artifacts[key].archiveEntry, live.artifacts[key].path, key);
  }
}

function validateAttacknetResult(result, candidateRevision) {
  if (result.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || result.sourceRevision !== candidateRevision || result.status !== 'passed') {
    throw new Error('Attacknet offline result is not a passed candidate result');
  }
}

/** Build the Full review packet for Amendment A3. */
export function buildReleaseOneA3Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  evidenceRoot = 'live',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
  candidateContextTree = undefined,
} = {}) {
  if (!liveSummaryPath) throw new Error('liveSummaryPath is required');
  const contract = load('contrib/attacknet/release/release-1-a3-contract.json', root);
  const live = validatePortableLiveSummary(load(liveSummaryPath, root), candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Release 1 amendment A3',
    requiredArtifacts: Object.keys(A3_ARTIFACTS),
    requiredAssertions: A3_ASSERTIONS,
  });
  if (evidenceRoot !== 'live') throw new Error('A3 evidenceRoot must be live');
  validateArtifactLayout(live, liveSummaryPath, root);
  const artifacts = live.artifacts;
  validateA3Verification(load(artifacts.verification.path, root), candidate.sourceRevision);
  validateAttacknetResult(load(artifacts.attacknetCheck.path, root), candidate.sourceRevision);
  const hacknet = validateHacknetOfflineResult(load(artifacts.hacknetCheck.path, root));
  if (hacknet.sourceRevision !== candidate.sourceRevision) throw new Error('Hacknet result does not pin the candidate');
  for (const required of ['go', 'envtest', 'helm']) {
    if (hacknet.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      throw new Error(`A3 requires a passed Hacknet ${required} check`);
    }
  }
  const clockPolicy = validateClockPolicyProof(load(artifacts.clockPolicyLive.path, root));
  if (clockPolicy.candidateRevision !== candidate.sourceRevision) {
    throw new Error('clock-policy proof does not pin the candidate');
  }
  const contextTree = candidateContextTree ?? gitLines(root, [
    'rev-parse', `${candidate.sourceRevision}:contrib/helm/hacknet/operator`,
  ])[0];
  if (clockPolicy.candidateRuntime.operatorContextTree !== contextTree) {
    throw new Error('clock-policy proof does not bind the candidate operator context tree');
  }
  const scope = candidateScope ?? releaseOneA3CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) throw new Error('candidate diff artifact does not match committed A3');

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-controller-hardening', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'live-summary.json', root, liveSummaryPath),
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('evidence:clock-policy-live', 'evidence', artifacts.clockPolicyLive.archiveEntry, root, artifacts.clockPolicyLive.path),
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
      {requirement: 'single-signed-commit-directly-on-approved-a2-with-exact-diff', status: 'satisfied', evidence: ['diff:candidate-controller-hardening', 'evidence:verification']},
      {requirement: 'clock-skew-capability-admission-preserves-the-approved-legacy-safety-contract', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/fault/capability.go'), candidateId('contrib/helm/hacknet/operator/internal/fault/capability_test.go'), 'evidence:clock-policy-live']},
      {requirement: 'rendered-operator-rbac-matches-a-structural-exact-least-privilege-contract', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/rbac/validate.go'), candidateId('contrib/helm/hacknet/operator/internal/rbac/validate_test.go'), candidateId('contrib/helm/hacknet/operator/cmd/rbac-check/main.go'), 'evidence:verification']},
      {requirement: 'topology-render-equivalence-covers-multi-actor-probe-disabled-and-storage-disabled-profiles', status: 'satisfied', evidence: [candidateId('contrib/attacknet/topology-render-equivalence.test.mjs'), 'evidence:verification']},
      {requirement: 'clean-go-race-envtest-helm-whole-product-and-live-kind-verification', status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check', 'evidence:clock-policy-live']},
      {requirement: 'portable-self-identifying-review-evidence', status: 'satisfied', evidence: [candidateId('contrib/attacknet/evidence-packets/release-1-a3/README.md'), 'evidence:archive-index', 'evidence:archive', 'evidence:live-summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: true,
      notes: 'Clock-skew admission again requires the complete approved shared-policy and mount contract; RBAC and topology-equivalence evidence become structural and broader without changing the CRD API.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Live evidence covers the supported local three-node arm64 kind profile.'},
      {id: 'archive-location', disposition: `A3 evidence is archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/release-1-a3.test.mjs',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arguments_ = process.argv.slice(2);
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--output=', '--live-summary=', '--evidence-root='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const output = value('--output=');
  const liveSummaryPath = value('--live-summary=');
  if (!output || !liveSummaryPath) throw new Error('--output and --live-summary are required');
  if (dirname(absolute(liveSummaryPath)) !== resolve(dirname(absolute(output)), 'live')) {
    throw new Error('live summary must be under the packet-relative live evidence root');
  }
  const packet = buildReleaseOneA3Packet({
    liveSummaryPath,
    evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  writeFileSync(absolute(output), `${JSON.stringify(packet, null, 2)}\n`);
}
