#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateControllerEquivalence} from './controller-equivalence.mjs';
import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {deriveGitCandidate} from './phase-zero-packet.mjs';
import {validatePortableLiveSummary} from './portable-live-evidence.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from './phase-review.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const APPROVED_A1_REVISION = 'f8a853a0f21c9edebec92398fb56500ae10e1a22';
const REVIEW_ID = 'release-1-amendment-a2-controller-runtime-migration';
const LIVE_SCHEMA = 'stacks-attacknet-release-1-a2-live-evidence/v1';
const CANDIDATE_DIFF_MAX_BYTES = 64 << 20;
const RETIRED_PATHS = Object.freeze([
  'contrib/helm/hacknet/operator/controller.py',
  'contrib/helm/hacknet/operator/test_controller.py',
  'contrib/helm/hacknet/run-operator/Dockerfile',
  'contrib/helm/hacknet/run-operator/controller.mjs',
  'contrib/helm/hacknet/run-operator/controller.test.mjs',
  'contrib/helm/hacknet/run-operator/image-context.test.mjs',
  'contrib/helm/hacknet/run-operator/probe-client.mjs',
  'contrib/helm/hacknet/run-operator/probe-client.test.mjs',
  'contrib/helm/hacknet/templates/development-source-configmap.yaml',
]);
const REQUIRED_ARTIFACTS = Object.freeze([
  'candidateDiff', 'equivalenceReport', 'goVerify', 'envtest', 'helmRender',
  'topologyLive', 'reversibleFaultLive', 'podKillLive', 'restartResumeLive',
  'cleanTeardown',
]);
const REQUIRED_ASSERTIONS = Object.freeze([
  'go-build-vet-unit-race',
  'envtest-api-server-contracts',
  'crd-rbac-helm-security-contracts',
  'whole-attacknet-and-hacknet-offline-verification',
  'topology-admitted-inventory-and-mutable-reconcile',
  'reversible-fault-injection-effect-recovery-cleanup',
  'one-shot-pod-replacement-identity-bounds',
  'controller-restart-idempotent-resume',
  'clean-teardown',
]);

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

function gitLines(root, args) {
  return execFileSync('git', args, {cwd: root, encoding: 'utf8'}).split('\n').filter(Boolean);
}

/** Derive the exact one-commit Go migration and require all legacy runtime deletions. */
export function releaseOneA2CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision]);
  const parentValues = parents[0]?.split(' ').filter(Boolean) ?? [];
  if (parentValues.length !== 1 || parentValues[0] !== APPROVED_A1_REVISION) {
    throw new Error(`Release 1 amendment A2 must be one non-merge commit directly on approved A1 ${APPROVED_A1_REVISION}`);
  }
  const paths = gitLines(root, [
    'diff', '--name-only', '--diff-filter=ACMRT', APPROVED_A1_REVISION, candidateRevision,
  ]).sort();
  if (paths.length === 0) throw new Error('Release 1 amendment A2 candidate scope is empty');
  const deleted = gitLines(root, [
    'diff', '--name-only', '--diff-filter=D', APPROVED_A1_REVISION, candidateRevision,
  ]).sort();
  if (JSON.stringify(deleted) !== JSON.stringify([...RETIRED_PATHS].sort())) {
    throw new Error(`Release 1 amendment A2 must delete exactly: ${RETIRED_PATHS.join(', ')}`);
  }
  return {parent: APPROVED_A1_REVISION, paths};
}

/** Read a candidate's complete binary diff with an explicit bounded buffer. */
export function committedBinaryDiff(root, parentRevision, candidateRevision, execute = execFileSync) {
  return execute('git', ['diff', '--binary', parentRevision, candidateRevision], {
    cwd: root,
    maxBuffer: CANDIDATE_DIFF_MAX_BYTES,
  });
}

function candidatePatch(root, candidateRevision) {
  return committedBinaryDiff(root, APPROVED_A1_REVISION, candidateRevision);
}

function requireFileAt(path, expected, label, root) {
  if (absolute(path, root) !== expected) throw new Error(`${label} must resolve to ${expected}`);
}

function validateEvidenceLayout(live, {root, liveSummaryPath, offlineResultPath, hacknetResultPath}) {
  const liveRoot = dirname(absolute(liveSummaryPath, root));
  requireFileAt(offlineResultPath, resolve(liveRoot, 'offline-result.json'), 'Attacknet offline result', root);
  requireFileAt(hacknetResultPath, resolve(liveRoot, 'hacknet-result.json'), 'Hacknet offline result', root);
  requireFileAt(live.archive.indexPath, resolve(liveRoot, live.archive.indexEntry), 'archive index', root);
  requireFileAt(live.archive.path, resolve(liveRoot, 'archive', basename(live.archive.path)), 'evidence archive', root);
  for (const key of REQUIRED_ARTIFACTS) {
    requireFileAt(live.artifacts[key].path, resolve(liveRoot, live.artifacts[key].archiveEntry), `artifact ${key}`, root);
  }
}

function validateEquivalenceReport(report, candidate, matrix, matrixDigest) {
  if (report?.schemaVersion !== 'stacks-attacknet-controller-equivalence-report/v1'
    || report.candidateRevision !== candidate.sourceRevision
    || report.matrixDigest !== matrixDigest) {
    throw new Error('controller equivalence report does not bind the candidate and matrix');
  }
  if (!Array.isArray(report.entries) || report.entries.length !== matrix.entries.length) {
    throw new Error('controller equivalence report does not cover every matrix entry');
  }
  const byId = new Map(report.entries.map(entry => [entry?.id, entry]));
  if (byId.size !== report.entries.length) throw new Error('controller equivalence report duplicates entry IDs');
  for (const entry of matrix.entries) {
    const result = byId.get(entry.id);
    if (result?.status !== 'verified' || !Array.isArray(result.evidence) || result.evidence.length === 0) {
      throw new Error(`controller equivalence report has not verified ${entry.id}`);
    }
  }
  return report;
}

export function validateReleaseOneA2LiveSummary(summary, candidate, root = repositoryRoot) {
  return validatePortableLiveSummary(summary, candidate, {
    root,
    schema: LIVE_SCHEMA,
    checkpoint: 'Release 1 amendment A2',
    requiredArtifacts: REQUIRED_ARTIFACTS,
    requiredAssertions: REQUIRED_ASSERTIONS,
  });
}

/** Build the Full review packet for the controller-runtime migration. */
export function buildReleaseOneA2Packet({
  root = repositoryRoot,
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
  const contract = load('contrib/attacknet/release/release-1-a2-contract.json', root);
  const matrixPath = 'contrib/attacknet/release/controller-equivalence-v1.json';
  const matrix = validateControllerEquivalence(load(matrixPath, root), root);
  const matrixDigest = digestFile(matrixPath, root);
  const live = validateReleaseOneA2LiveSummary(load(liveSummaryPath, root), candidate, root);
  if (evidenceRoot !== 'live') throw new Error('Release 1 amendment A2 evidenceRoot must be live');
  validateEvidenceLayout(live, {root, liveSummaryPath, offlineResultPath, hacknetResultPath});
  const offline = load(offlineResultPath, root);
  if (offline.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || offline.status !== 'passed' || offline.sourceRevision !== candidate.sourceRevision) {
    throw new Error('Attacknet offline check result is not a passed result for the candidate');
  }
  const hacknet = validateHacknetOfflineResult(load(hacknetResultPath, root));
  if (hacknet.sourceRevision !== candidate.sourceRevision) {
    throw new Error('Hacknet offline check result does not pin the candidate');
  }
  for (const required of ['go', 'envtest', 'helm']) {
    if (hacknet.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      throw new Error(`Release 1 amendment A2 requires a passed Hacknet ${required} check`);
    }
  }
  validateEquivalenceReport(load(live.artifacts.equivalenceReport.path, root), candidate, matrix, matrixDigest);
  const scope = candidateScope ?? releaseOneA2CandidateScope(root, candidate.sourceRevision);
  const patchDigest = digestBytes(committedPatch ?? candidatePatch(root, candidate.sourceRevision));
  if (live.artifacts.candidateDiff.digest !== patchDigest) {
    throw new Error('candidate diff artifact does not match the committed controller migration');
  }

  const artifacts = live.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(candidateId(path), candidateKind(path), path, root)),
    {id: 'diff:candidate-controller-runtime-migration', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('test:attacknet-check', 'test', 'offline-result.json', root, offlineResultPath),
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
      {requirement: 'single-commit-a1-descendant-and-complete-legacy-runtime-retirement', status: 'satisfied', evidence: ['diff:candidate-controller-runtime-migration', candidateId('contrib/attacknet/release/controller-equivalence-v1.json')]},
      {requirement: 'typed-api-topology-rendering-reconciliation-and-status-equivalence', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/topology/render.go'), candidateId('contrib/helm/hacknet/operator/internal/topology/reconciler.go'), 'evidence:equivalence-report', 'evidence:topology-live']},
      {requirement: 'fault-compilation-safety-injection-effect-recovery-and-cleanup-equivalence', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/fault/compiler.go'), candidateId('contrib/helm/hacknet/operator/internal/fault/reconciler.go'), candidateId('contrib/attacknet/fault-compiler-equivalence.test.mjs'), candidateId('contrib/attacknet/probe/probe.mjs'), 'evidence:reversible-fault-live', 'evidence:pod-kill-live']},
      {requirement: 'run-scheduling-replay-minimization-resume-and-classification-equivalence', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/run/schedule.go'), candidateId('contrib/helm/hacknet/operator/internal/run/reconciler.go'), 'evidence:go-verify', 'evidence:envtest', 'evidence:restart-resume-live']},
      {requirement: 'canonical-admitted-identity-and-uncached-pre-mutation-barriers', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/operator/internal/canonical/canonical.go'), candidateId('contrib/helm/hacknet/operator/internal/inventory/inventory.go'), candidateId('contrib/helm/hacknet/operator/internal/inventory/reader.go'), candidateId('contrib/helm/hacknet/operator/internal/fault/reconciler_contract_test.go'), 'evidence:go-verify', 'evidence:envtest', 'evidence:pod-kill-live']},
      {requirement: 'crd-rbac-helm-image-and-security-contract-integrity', status: 'satisfied', evidence: [candidateId('contrib/helm/hacknet/crds/testing.stacks.org_stacksnetworks.yaml'), candidateId('contrib/helm/hacknet/templates/run-rbac.yaml'), 'evidence:helm-render']},
      {requirement: 'clean-go-unit-race-envtest-and-whole-product-verification', status: 'satisfied', evidence: ['evidence:go-verify', 'evidence:envtest', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: 'signed-candidate-live-topology-fault-pod-replacement-restart-and-teardown-proof', status: 'satisfied', evidence: ['evidence:topology-live', 'evidence:reversible-fault-live', 'evidence:pod-kill-live', 'evidence:restart-resume-live', 'evidence:clean-teardown']},
      {requirement: 'portable-self-identifying-review-evidence-and-truthful-documentation', status: 'satisfied', evidence: [candidateId('contrib/attacknet/evidence-packets/release-1-a2/README.md'), 'evidence:archive-index', 'evidence:archive', 'evidence:live-summary']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true,
      kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'Both controller runtimes, workload rendering, admitted identity, status behavior, packaging, and controller evidence move to typed controller-runtime implementations while the v1alpha1 CRD API remains stable.',
    },
    limitations: [
      {id: 'human-review-custody', disposition: 'The gate cannot attest reviewer identity or comprehension.'},
      {id: 'local-arm64-kind', disposition: 'Live amendment evidence covers the supported local three-node arm64 kind profile.'},
      {id: 'v1alpha1-api', disposition: 'The CRDs remain unreleased v1alpha1 APIs without external-controller skew compatibility.'},
      {id: 'archive-location', disposition: `Live evidence is externally archived at ${live.archive.location} with digest ${live.archive.digest}.`},
    ],
    reproduction: [
      'node contrib/attacknet/release/phase-review.mjs tooling-digest',
      'node contrib/attacknet/release/controller-equivalence.mjs',
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/release-1-a2.test.mjs',
    ],
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const known = ['--output=', '--live-summary=', '--offline-result=', '--hacknet-result=', '--evidence-root='];
  const unknown = args.find(arg => !known.some(prefix => arg.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const value = prefix => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const liveSummaryPath = value('--live-summary=');
  if (!output || !liveSummaryPath) throw new Error('--output and --live-summary are required');
  if (dirname(absolute(liveSummaryPath)) !== resolve(dirname(absolute(output)), 'live')) {
    throw new Error('live summary must be under the packet-relative live evidence root');
  }
  const packet = buildReleaseOneA2Packet({
    liveSummaryPath,
    offlineResultPath: value('--offline-result='),
    hacknetResultPath: value('--hacknet-result='),
    evidenceRoot: value('--evidence-root=') ?? 'live',
  });
  writeFileSync(absolute(output), `${JSON.stringify(packet, null, 2)}\n`);
}
