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
import {validateControllerLiveArtifact} from './release-1-a2-evidence.mjs';
import {
  A4_ARTIFACTS, A4_ASSERTIONS, validateA4RuntimeBinding, validateA4Verification,
} from './release-1-a4-evidence.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const APPROVED_A3_REVISION = '5b6d3018374d24946c12ec46406ee6abed10ca56';
const REVIEW_ID = 'release-1-amendment-a4-controller-composability';
const LIVE_SCHEMA = 'stacks-attacknet-release-1-a4-live-evidence/v1';

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

/** Derive the exact one-commit A4 scope directly above approved A3. */
export function releaseOneA4CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A3_REVISION) {
    throw new Error(`A4 must be one non-merge commit directly on approved A3 ${APPROVED_A3_REVISION}`);
  }
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', APPROVED_A3_REVISION, candidateRevision]);
  if (deleted.length > 0) throw new Error(`A4 must not delete files: ${deleted.join(', ')}`);
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A3_REVISION, candidateRevision]).sort();
  if (paths.length === 0) throw new Error('A4 candidate scope is empty');
  const unexpected = paths.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A4 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: APPROVED_A3_REVISION, paths};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A3_REVISION, candidateRevision], {
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
  for (const key of Object.keys(A4_ARTIFACTS)) expected(live.artifacts[key].archiveEntry, live.artifacts[key].path, key);
}

function validateAttacknetResult(result, candidateRevision) {
  if (result.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || result.sourceRevision !== candidateRevision || result.status !== 'passed') {
    throw new Error('Attacknet offline result is not a passed candidate result');
  }
}

/** Build the Full review packet for Amendment A4. */
export function buildReleaseOneA4Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  evidenceRoot = 'live',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
  expectedOperatorContextTree = undefined,
} = {}) {
  if (!liveSummaryPath) throw new Error('liveSummaryPath is required');
  const contract = load('contrib/attacknet/release/release-1-a4-contract.json', root);
  const live = validatePortableLiveSummary(load(liveSummaryPath, root), candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Release 1 amendment A4',
    requiredArtifacts: Object.keys(A4_ARTIFACTS),
    requiredAssertions: A4_ASSERTIONS,
  });
  if (evidenceRoot !== 'live') throw new Error('A4 evidenceRoot must be live');
  validateArtifactLayout(live, liveSummaryPath, root);
  const artifacts = live.artifacts;
  validateA4Verification(load(artifacts.verification.path, root), candidate.sourceRevision);
  validateAttacknetResult(load(artifacts.attacknetCheck.path, root), candidate.sourceRevision);
  const hacknet = validateHacknetOfflineResult(load(artifacts.hacknetCheck.path, root));
  if (hacknet.sourceRevision !== candidate.sourceRevision) throw new Error('Hacknet result does not pin the candidate');
  for (const required of ['go', 'envtest', 'helm']) {
    if (hacknet.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      throw new Error(`A4 requires a passed Hacknet ${required} check`);
    }
  }
  for (const key of ['topologyLive', 'reversibleFaultLive', 'podKillLive', 'restartResumeLive', 'cleanTeardown']) {
    const value = load(artifacts[key].path, root);
    validateControllerLiveArtifact(key, value, candidate.sourceRevision);
    if (key === 'topologyLive') {
      const operatorContextTree = expectedOperatorContextTree ?? execFileSync(
        'git', ['rev-parse', `${candidate.sourceRevision}:contrib/helm/hacknet/operator`],
        {cwd: root, encoding: 'utf8'},
      ).trim();
      validateA4RuntimeBinding(value, candidate.sourceRevision, operatorContextTree);
    }
  }
  const scope = candidateScope ?? releaseOneA4CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) throw new Error('candidate diff artifact does not match committed A4');

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-controller-composability', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'live-summary.json', root, liveSummaryPath),
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    ...['topologyLive', 'reversibleFaultLive', 'podKillLive', 'restartResumeLive', 'cleanTeardown'].map(key => item(
      `evidence:${key.replaceAll(/[A-Z]/g, match => `-${match.toLowerCase()}`)}`,
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
      {requirement: 'single-signed-commit-directly-on-approved-a3-with-exact-diff', status: 'satisfied', evidence: ['diff:candidate-controller-composability', 'evidence:verification']},
      {requirement: 'one-closed-complete-fault-mechanism-registry-governs-all-seven-fault-types', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/fault/mechanism.go'), candidateId('contrib/helm/hacknet/operator/internal/fault/mechanism_test.go'), 'evidence:verification']},
      {requirement: 'fault-and-topology-decomposition-preserves-one-authoritative-reconciler-per-crd', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/fault/reconciler.go'), candidateId('contrib/helm/hacknet/operator/internal/topology/render.go'), 'evidence:topology-live', 'evidence:reversible-fault-live']},
      {requirement: 'immutable-schedule-persistence-is-a-focused-direct-read-collaborator', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/run/schedule_store.go'), 'evidence:restart-resume-live', 'evidence:verification']},
      {requirement: 'a3-render-compile-lifecycle-safety-identity-and-evidence-behavior-remains-equivalent', status: 'satisfied', evidence: ['evidence:topology-live', 'evidence:reversible-fault-live', 'evidence:pod-kill-live', 'evidence:restart-resume-live', 'evidence:verification']},
      {requirement: 'controller-extension-boundaries-state-machines-and-invariants-are-documented', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/ARCHITECTURE.md')]},
      {requirement: 'clean-go-race-envtest-helm-whole-product-and-live-kind-verification', status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check', 'evidence:clean-teardown']},
      {requirement: 'portable-self-identifying-review-evidence', status: 'satisfied', evidence: [candidateId('contrib/attacknet/evidence-packets/release-1-a4/README.md'), 'evidence:archive-index', 'evidence:archive', 'evidence:live-summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: false,
      notes: 'A4 is a behavior-preserving internal decomposition. It retains the A3 CRDs, resource rendering, admission and safety policy, identity barriers, mutation semantics, status transitions, and evidence interpretation.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Live evidence covers the supported local three-node arm64 kind profile.'},
      {id: 'closed-built-in-registry', disposition: 'Fault mechanisms are compile-time registrations; A4 intentionally does not provide dynamically loaded plugins.'},
      {id: 'archive-location', disposition: `A4 evidence is archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      '(cd contrib/helm/hacknet/operator && GOCACHE=/tmp/attacknet-a4-go-cache go test -race ./...)',
      'contrib/attacknet/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/release-1-a4.test.mjs',
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
  const packet = buildReleaseOneA4Packet({
    liveSummaryPath,
    evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  writeFileSync(absolute(output), `${JSON.stringify(packet, null, 2)}\n`);
}
