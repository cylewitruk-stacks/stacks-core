#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {A11_ARTIFACTS, validateA11Summary} from './evidence.mjs';
import {
  A11_PARENT_REVISION, validateA11CandidateAttestation, validateA11Verification,
} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const reviewID = 'release-1-amendment-a11-mixed-version-upgrades';

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

/** Derive and constrain the exact one-commit A11 product scope. */
export function a11CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== A11_PARENT_REVISION) {
    throw new Error(`A11 must be one signed non-merge child of ${A11_PARENT_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', A11_PARENT_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', A11_PARENT_REVISION, candidateRevision]).sort();
  const permittedDeletions = new Set([
    'contrib/attacknet/examples/matrices/mixed-version-images.plan.json',
    'contrib/attacknet/examples/matrices/version-matrix.plan.json',
  ]);
  const unexpectedDeletions = deleted.filter(path => !permittedDeletions.has(path));
  if (paths.length === 0 || unexpectedDeletions.length > 0) {
    throw new Error(`A11 has no changes or unexpected deletions: ${unexpectedDeletions.join(', ')}`);
  }
  const unexpected = [...paths, ...deleted]
    .filter(path => !path.startsWith('contrib/attacknet/') && !path.startsWith('contrib/helm/hacknet/'));
  if (unexpected.length > 0) throw new Error(`A11 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: A11_PARENT_REVISION, paths, deleted};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', A11_PARENT_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
}

/** Build the Full-tier review packet for Amendment A11. */
export function buildA11Packet({
  root = repositoryRoot, candidate = deriveGitCandidate(root), summaryPath,
  attestationPath, evidenceRoot = 'evidence', inventory = undefined,
} = {}) {
  if (!summaryPath || !attestationPath) throw new Error('summaryPath and attestationPath are required');
  if (evidenceRoot !== 'evidence') throw new Error('A11 packet evidenceRoot must be evidence');
  const contract = load('contrib/attacknet/release/amendments/a11/contract.json', root);
  const summary = validateA11Summary(load(summaryPath, root), candidate, summaryPath, root);
  const verification = load(summary.artifacts.verification.path, root);
  validateA11Verification(verification, summary.qualifiedTree);
  const attestation = validateA11CandidateAttestation(load(attestationPath, root), {
    qualifiedTree: summary.qualifiedTree, patchDigest: verification.patchDigest,
  }, digestFile(summaryPath, root));
  if (attestation.candidateRevision !== candidate.sourceRevision) {
    throw new Error('A11 attestation does not bind the candidate revision');
  }
  const scope = a11CandidateScope(root, candidate.sourceRevision);
  if (summary.artifacts.candidateDiff.digest !== digestBytes(committedPatch(root, candidate.sourceRevision))) {
    throw new Error('A11 candidate diff does not match the committed revision');
  }
  const artifacts = summary.artifacts;
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-mixed-version-upgrades', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    item('evidence:verification', 'evidence', artifacts.verification.archiveEntry, root, artifacts.verification.path),
    item('test:attacknet-check', 'test', artifacts.attacknetCheck.archiveEntry, root, artifacts.attacknetCheck.path),
    item('test:hacknet-check', 'test', artifacts.hacknetCheck.archiveEntry, root, artifacts.hacknetCheck.path),
    item('evidence:candidate-build', 'evidence', artifacts.candidateBuild.archiveEntry, root, artifacts.candidateBuild.path),
    item('evidence:source-drift-control', 'evidence', artifacts.sourceDrift.archiveEntry, root, artifacts.sourceDrift.path),
    item('evidence:configuration-control', 'evidence', artifacts.configurationControl.archiveEntry, root, artifacts.configurationControl.path),
    item('evidence:telemetry-control', 'evidence', artifacts.telemetryControl.archiveEntry, root, artifacts.telemetryControl.path),
    item('evidence:protocol-control', 'evidence', artifacts.protocolControl.archiveEntry, root, artifacts.protocolControl.path),
    item('evidence:static-descriptor', 'evidence', artifacts.staticDescriptor.archiveEntry, root, artifacts.staticDescriptor.path),
    item('evidence:static-import', 'evidence', artifacts.staticImport.archiveEntry, root, artifacts.staticImport.path),
    item('evidence:static-network', 'evidence', artifacts.staticNetwork.archiveEntry, root, artifacts.staticNetwork.path),
    item('evidence:upgrade-descriptor', 'evidence', artifacts.upgradeDescriptor.archiveEntry, root, artifacts.upgradeDescriptor.path),
    item('evidence:primary-network', 'evidence', artifacts.primaryNetwork.archiveEntry, root, artifacts.primaryNetwork.path),
    item('evidence:primary-run', 'evidence', artifacts.primaryRun.archiveEntry, root, artifacts.primaryRun.path),
    item('evidence:primary-upgrade', 'evidence', artifacts.primaryUpgrade.archiveEntry, root, artifacts.primaryUpgrade.path),
    item('evidence:replay-network', 'evidence', artifacts.replayNetwork.archiveEntry, root, artifacts.replayNetwork.path),
    item('evidence:replay-run', 'evidence', artifacts.replayRun.archiveEntry, root, artifacts.replayRun.path),
    item('evidence:replay-upgrade', 'evidence', artifacts.replayUpgrade.archiveEntry, root, artifacts.replayUpgrade.path),
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
      {requirement: contract.requirements[0], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/versionmatrix/prepare.go'), 'evidence:source-drift-control', 'evidence:static-descriptor', 'evidence:candidate-build']},
      {requirement: contract.requirements[1], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/versionmatrix/assignment.go'), 'evidence:static-descriptor', 'evidence:upgrade-descriptor']},
      {requirement: contract.requirements[2], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/inventory/inventory.go'), ...source('contrib/helm/hacknet/operator/internal/topology/statefulset.go'), 'evidence:configuration-control', 'evidence:static-network']},
      {requirement: contract.requirements[3], status: 'satisfied', evidence: ['evidence:static-import', 'evidence:static-network']},
      {requirement: contract.requirements[4], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/topology/upgrade_overlay.go'), ...source('contrib/helm/hacknet/operator/internal/run/v1beta1_reconciler.go'), 'evidence:primary-run', 'evidence:primary-upgrade']},
      {requirement: contract.requirements[5], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/upgrade/reconciler.go'), 'evidence:primary-network', 'evidence:primary-upgrade']},
      {requirement: contract.requirements[6], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/versionmatrix/types.go'), 'evidence:configuration-control', 'evidence:telemetry-control', 'evidence:protocol-control']},
      {requirement: contract.requirements[7], status: 'satisfied', evidence: ['evidence:primary-network', 'evidence:primary-run', 'evidence:primary-upgrade', 'evidence:replay-network', 'evidence:replay-run', 'evidence:replay-upgrade']},
      {requirement: contract.requirements[8], status: 'satisfied', evidence: [...source('contrib/helm/hacknet/operator/internal/orchestratormetrics/collector.go'), ...source('contrib/attacknet/observability/dashboards/attacknet-overview.json'), 'evidence:forensic-bundle']},
      {requirement: contract.requirements[9], status: 'satisfied', evidence: ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check']},
      {requirement: contract.requirements[10], status: 'satisfied', evidence: ['evidence:candidate-build', 'evidence:live-qualification', 'evidence:clean-teardown', 'evidence:archive-index', 'evidence:archive', 'evidence:summary', 'attestation:signed-candidate']},
    ],
    compatibility: {
      runtimeBehaviorChanged: true, kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'A11 adds immutable mixed-version preparation, exact configuration identity, topology-owned upgrade orchestration, run integration, bounded observability, and live qualification evidence.',
    },
    limitations: [
      {id: 'operator-authorized-builds', disposition: 'Source preparation executes explicitly selected repository build logic on the operator workstation; it is outside the Kubernetes controller trust boundary.'},
      {id: 'host-scoped-recipe', disposition: 'Historical revisions may use a trusted current Attacknet Dockerfile whose root, scope, and digest are sealed separately from the selected source.'},
      {id: 'local-builder-provenance', disposition: 'R1 seals canonical build inputs, the platform runtime config identity, and verified per-node imports; builder toolchain, OCI index/manifest, and base-layer inventory are not independently portable until registry-backed publication.'},
      {id: 'configuration-smoke-strength', disposition: 'A target parser is preferred; bounded non-networked startup smoke or explicit unverified raw configuration is retained as weaker evidence when old binaries lack one.'},
      {id: 'local-kind-r1', disposition: 'Release 1 qualifies linux/arm64 images on a local three-node kind cluster; registry and multi-architecture publication remain future work.'},
      {id: 'review-evidence-archive', disposition: `Portable A11 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
      {id: 'human-review-custody', disposition: 'The mechanical gate cannot attest reviewer identity or comprehension.'},
    ],
    reproduction: [
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a11/a11.test.mjs',
      'node contrib/attacknet/release/phase-review.mjs verify-packet --contract=contrib/attacknet/release/amendments/a11/contract.json --packet=contrib/attacknet/evidence-packets/release-1-a11/review-packet.json',
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
    throw new Error('A11 summary must be under the packet-relative evidence root');
  }
  writeFileSync(absolute(output), `${JSON.stringify(buildA11Packet({summaryPath: summary, attestationPath: attestation}), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
