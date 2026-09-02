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
import {
  A5_ARTIFACTS, A5_ASSERTIONS, validateA5Artifact, validateA5ArtifactSet,
  validateA5Incident,
} from './release-1-a5-evidence.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const APPROVED_A4_REVISION = '42f92191286d7e4542ac95d85ee75621d166ed58';
const REVIEW_ID = 'release-1-amendment-a5-api-productization';
const LIVE_SCHEMA = 'stacks-attacknet-release-1-a5-live-evidence/v1';

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

/** Derive the exact one-commit A5 product scope directly above approved A4. */
export function releaseOneA5CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== APPROVED_A4_REVISION) {
    throw new Error(`A5 must be one non-merge commit directly on approved A4 ${APPROVED_A4_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A4_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', APPROVED_A4_REVISION, candidateRevision]).sort();
  if (paths.length === 0) throw new Error('A5 candidate scope is empty');
  const all = [...paths, ...deleted];
  const unexpected = all.filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) {
    throw new Error(`A5 contains out-of-scope paths; node fixes require a separate commit: ${unexpected.join(', ')}`);
  }
  return {parent: APPROVED_A4_REVISION, paths, deleted};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', APPROVED_A4_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 64 << 20,
  });
}

function validateArtifactLayout(live, liveSummaryPath, root) {
  const liveRoot = dirname(absolute(liveSummaryPath, root));
  const expected = (path, value, label) => {
    if (absolute(value, root) !== resolve(liveRoot, path)) {
      throw new Error(`${label} does not resolve under evidenceRoot`);
    }
  };
  expected(live.archive.indexEntry, live.archive.indexPath, 'archive index');
  expected(`archive/${basename(live.archive.path)}`, live.archive.path, 'archive');
  for (const key of Object.keys(A5_ARTIFACTS)) {
    expected(live.artifacts[key].archiveEntry, live.artifacts[key].path, key);
  }
  expected(live.artifacts.acceptedIncident.archiveEntry, live.artifacts.acceptedIncident.path, 'acceptedIncident');
}

/** Build the Full review packet for Amendment A5. */
export function buildReleaseOneA5Packet({
  root = repositoryRoot,
  candidate = deriveGitCandidate(root),
  liveSummaryPath,
  evidenceRoot = 'live',
  inventory = undefined,
  candidateScope = undefined,
  candidateDiff = undefined,
} = {}) {
  if (!liveSummaryPath) throw new Error('liveSummaryPath is required');
  const contract = load('contrib/attacknet/release/release-1-a5-contract.json', root);
  const live = validatePortableLiveSummary(load(liveSummaryPath, root), candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Release 1 amendment A5',
    requiredArtifacts: [...Object.keys(A5_ARTIFACTS), 'acceptedIncident'],
    requiredAssertions: A5_ASSERTIONS,
  });
  if (evidenceRoot !== 'live') throw new Error('A5 evidenceRoot must be live');
  validateArtifactLayout(live, liveSummaryPath, root);
  const artifacts = live.artifacts;
  const values = {};
  for (const key of Object.keys(A5_ARTIFACTS).filter(key => key !== 'candidateDiff')) {
    values[key] = load(artifacts[key].path, root);
    validateA5Artifact(key, values[key], candidate.sourceRevision);
  }
  const incident = validateA5Incident(load(artifacts.acceptedIncident.path, root), candidate.sourceRevision);
  validateA5ArtifactSet(values, incident);
  const hacknet = validateHacknetOfflineResult(load(artifacts.hacknetCheck.path, root));
  if (hacknet.sourceRevision !== candidate.sourceRevision) throw new Error('Hacknet result does not pin candidate');

  const scope = candidateScope ?? releaseOneA5CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(candidateDiff ?? committedPatch(root, candidate.sourceRevision));
  if (artifacts.candidateDiff.digest !== patchDigest) throw new Error('candidate diff artifact does not match committed A5');

  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-api-productization', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:archive-index', 'evidence', live.archive.indexEntry, root, live.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(live.archive.path)}`, root, live.archive.path),
    item('evidence:live-summary', 'evidence', 'live-summary.json', root, liveSummaryPath),
    ...[
      ['verification', 'verification'], ['local-install', 'localInstall'],
      ['burnchain-policy', 'burnchainPolicy'], ['concurrent-fault', 'concurrentFault'],
      ['run-overlap-restart', 'runOverlapRestart'], ['replay-minimization', 'replayMinimization'],
      ['accepted-network', 'acceptedNetwork'], ['accepted-cohort', 'acceptedCohort'],
      ['accepted-incident', 'acceptedIncident'], ['clean-teardown', 'cleanTeardown'],
    ].map(([id, key]) => item(`evidence:${id}`, 'evidence', artifacts[key].archiveEntry, root, artifacts[key].path)),
  ];

  const evidence = (...ids) => ids;
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
      {requirement: contract.requirements[0], status: 'satisfied', evidence: evidence('diff:candidate-api-productization', 'evidence:verification')},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/api/v1beta1/stacksnetwork_types.go'), 'evidence:verification')},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/internal/topology/v1beta1_compile.go'), 'evidence:accepted-network', 'evidence:accepted-cohort')},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/internal/burnchainpolicy/reconciler.go'), 'evidence:burnchain-policy')},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/internal/fault/v1beta1_reconciler.go'), 'evidence:concurrent-fault')},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/internal/run/v1beta1_reconciler.go'), 'evidence:run-overlap-restart', 'evidence:replay-minimization')},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: evidence(candidateId('contrib/helm/hacknet/operator/internal/attacknetcli/app.go'), 'evidence:local-install', 'test:attacknet-check')},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: evidence(candidateId('contrib/attacknet/repository-boundary.test.mjs'), 'test:attacknet-check')},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: evidence('evidence:verification', 'test:attacknet-check', 'test:hacknet-check')},
      {requirement: contract.requirements[9], status: 'satisfied', evidence: evidence('evidence:accepted-network', 'evidence:accepted-cohort', 'evidence:accepted-incident')},
      {requirement: contract.requirements[10], status: 'satisfied', evidence: evidence('evidence:archive-index', 'evidence:archive', 'evidence:live-summary')},
    ],
    compatibility: {
      runtimeBehaviorChanged: true,
      kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'A5 replaces the prototype v1alpha1 authoring and host workflow surface with typed v1beta1 aggregate APIs, controller-owned durable workflows, and a typed Go CLI. It is a clean-install API transition for an unreleased product.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Live evidence covers the supported local three-node arm64 kind profile.'},
      {id: 'clean-install-v1beta1', disposition: 'A5 intentionally does not promise in-cluster v1alpha1 conversion or skew compatibility.'},
      {id: 'opaque-complete-configs', disposition: 'Secret and ConfigMap complete configs remain operator-opaque and must match the declared network genesis contract.'},
      {id: 'archive-location', disposition: `A5 evidence is archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'make -C contrib/helm/hacknet/operator verify',
      '(cd contrib/helm/hacknet/operator && go test -race ./...)',
      'contrib/attacknet/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/release-1-a5.test.mjs',
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
  const packet = buildReleaseOneA5Packet({
    liveSummaryPath, evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  writeFileSync(absolute(output), `${JSON.stringify(packet, null, 2)}\n`);
}
