#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync} from 'node:fs';
import {basename, dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {deriveGitCandidate} from '../../phase-zero-packet.mjs';
import {REVIEW_PACKET_SCHEMA, sealReviewPacket} from '../../phase-review.mjs';
import {A13_ARTIFACTS, validateA13Summary} from './evidence.mjs';
import {
  A13_PARENT_REVISION, validateA13CandidateAttestation, validateA13Verification,
} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const reviewID = 'release-1-amendment-a13-seeded-fuzzing-corpus-reduction';

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

/** Report whether one changed path belongs to the A13 product boundary. */
export function isA13PathPermitted(path) {
  return path.startsWith('contrib/attacknet/') || path.startsWith('contrib/helm/hacknet/');
}

/** Derive and constrain the exact one-commit A13 scope. */
export function a13CandidateScope(root = repositoryRoot, candidateRevision = 'HEAD') {
  const parents = gitLines(root, ['show', '-s', '--format=%P', candidateRevision])[0]?.split(' ').filter(Boolean) ?? [];
  if (parents.length !== 1 || parents[0] !== A13_PARENT_REVISION) {
    throw new Error(`A13 must be one signed non-merge child of ${A13_PARENT_REVISION}`);
  }
  const paths = gitLines(root, ['diff', '--name-only', '--diff-filter=ACMRT', A13_PARENT_REVISION, candidateRevision]).sort();
  const deleted = gitLines(root, ['diff', '--name-only', '--diff-filter=D', A13_PARENT_REVISION, candidateRevision]).sort();
  if (paths.length === 0 || deleted.length > 0) throw new Error(`A13 has no changes or unexpected deletions: ${deleted.join(', ')}`);
  const unexpected = paths.filter(path => !isA13PathPermitted(path));
  if (unexpected.length > 0) throw new Error(`A13 contains out-of-scope paths: ${unexpected.join(', ')}`);
  return {parent: A13_PARENT_REVISION, paths, deleted};
}

function committedPatch(root, candidateRevision) {
  return execFileSync('git', ['diff', '--binary', A13_PARENT_REVISION, candidateRevision], {
    cwd: root, maxBuffer: 128 << 20,
  });
}

/** Build the Full-tier review packet for Amendment A13. */
export function buildA13Packet({
  root = repositoryRoot, candidate = deriveGitCandidate(root), summaryPath,
  attestationPath, evidenceRoot = 'evidence', inventory = undefined,
} = {}) {
  if (!summaryPath || !attestationPath) throw new Error('summaryPath and attestationPath are required');
  if (evidenceRoot !== 'evidence') throw new Error('A13 packet evidenceRoot must be evidence');
  if (dirname(absolute(attestationPath)) !== dirname(absolute(summaryPath))
    || basename(attestationPath) !== 'candidate-attestation.json') {
    throw new Error('A13 candidate attestation must be evidence/candidate-attestation.json beside the summary');
  }
  const contract = load('contrib/attacknet/release/amendments/a13/contract.json', root);
  const summary = validateA13Summary(load(summaryPath, root), candidate, summaryPath, root);
  const verification = load(summary.artifacts.verification.path, root);
  validateA13Verification(verification, summary.qualifiedTree);
  const attestation = validateA13CandidateAttestation(load(attestationPath, root), {
    qualifiedTree: summary.qualifiedTree, patchDigest: verification.patchDigest,
  }, digestFile(summaryPath, root));
  if (attestation.candidateRevision !== candidate.sourceRevision) throw new Error('A13 attestation does not bind candidate');
  execFileSync('git', ['verify-commit', candidate.sourceRevision], {cwd: root, stdio: 'pipe'});
  const candidateTree = gitLines(root, ['show', '-s', '--format=%T', candidate.sourceRevision])[0];
  if (candidateTree !== summary.qualifiedTree || attestation.candidateTree !== candidateTree
    || verification.patchDigest !== summary.artifacts.candidateDiff.digest) {
    throw new Error('A13 evidence or attestation does not bind the signed candidate tree and diff');
  }
  const scope = a13CandidateScope(root, candidate.sourceRevision);
  if (summary.artifacts.candidateDiff.digest !== digestBytes(committedPatch(root, candidate.sourceRevision))) {
    throw new Error('A13 candidate diff does not match the committed revision');
  }
  const artifacts = summary.artifacts;
  const evidence = (id, key, kind = 'evidence') => item(id, kind,
    artifacts[key].archiveEntry, root, artifacts[key].path);
  const resolvedInventory = inventory ?? [
    ...scope.paths.map(path => item(`candidate:${path}`, candidateKind(path), path, root)),
    {id: 'diff:candidate-seeded-fuzzing', kind: 'diff', path: artifacts.candidateDiff.archiveEntry, digest: artifacts.candidateDiff.digest},
    evidence('evidence:verification', 'verification'),
    evidence('test:attacknet-check', 'attacknetCheck', 'test'),
    evidence('test:hacknet-check', 'hacknetCheck', 'test'),
    evidence('evidence:planning-controls', 'planningControls'),
    evidence('evidence:capacity-control', 'capacityControl'),
    evidence('evidence:advisory-controls', 'advisoryControls'),
    evidence('evidence:resume-controls', 'resumeControls'),
    evidence('evidence:finite-session', 'finiteSession'),
    evidence('evidence:failure-confirmation', 'failureConfirmation'),
    evidence('evidence:non-reproduction', 'nonReproduction'),
    evidence('evidence:evidence-loss-control', 'evidenceLossControl'),
    evidence('evidence:reduction', 'reduction'),
    evidence('evidence:corpus-verification', 'corpusVerification'),
    evidence('evidence:corpus-archive', 'corpusArchive'),
    evidence('evidence:clean-teardown', 'cleanTeardown'),
    evidence('evidence:live-qualification', 'liveQualification'),
    item('evidence:archive-index', 'evidence', summary.archive.indexEntry, root, summary.archive.indexPath),
    item('evidence:archive', 'evidence', `archive/${basename(summary.archive.path)}`, root, summary.archive.path),
    item('evidence:summary', 'evidence', 'live-summary.json', root, summaryPath),
    item('attestation:signed-candidate', 'evidence', 'candidate-attestation.json', root, attestationPath),
  ];
  const source = path => [`candidate:${path}`];
  const requirementEvidence = [
    [...source('contrib/helm/hacknet/operator/internal/fuzzplan/planner.go'), 'evidence:planning-controls', 'evidence:advisory-controls'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzplan/validate.go'), 'evidence:planning-controls', 'evidence:capacity-control'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzcorpus/journal.go'), ...source('contrib/helm/hacknet/operator/internal/fuzzsession/engine.go'), 'evidence:resume-controls'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzplan/materialize.go'), 'evidence:finite-session'],
    [...source('contrib/helm/hacknet/operator/internal/attacknetcli/fuzz_evidence_plane.go'), 'evidence:evidence-loss-control', 'evidence:finite-session'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzsession/classify.go'), 'evidence:failure-confirmation', 'evidence:non-reproduction'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzcorpus/store.go'), 'evidence:advisory-controls', 'evidence:corpus-verification', 'evidence:corpus-archive'],
    [...source('contrib/helm/hacknet/operator/internal/fuzzreduce/reducer.go'), 'evidence:reduction'],
    [...source('contrib/attacknet/observability/dashboards/attacknet-fuzz.json'), ...source('contrib/attacknet/docs/operations/fuzzing.md'), 'evidence:live-qualification'],
    ['evidence:finite-session', 'evidence:failure-confirmation'],
    ['evidence:verification', 'test:attacknet-check', 'test:hacknet-check'],
    ['evidence:live-qualification', 'evidence:clean-teardown', 'evidence:archive-index', 'evidence:archive', 'evidence:summary', 'attestation:signed-candidate'],
  ];
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA, reviewId: reviewID, phase: 2, tier: 'Full',
    candidate, evidenceRoot, requirements: [...contract.requirements], inventory: resolvedInventory,
    matrix: contract.requirements.map((requirement, index) => ({
      requirement, status: 'satisfied', evidence: requirementEvidence[index],
    })),
    compatibility: {
      runtimeBehaviorChanged: true, kubernetesResourcesChanged: true,
      evidenceInterpretationChanged: true,
      notes: 'A13 adds finite seeded planning, capacity admission, resumable sessions, content-addressed corpus replay, fresh confirmation, and removal-only reduction.',
    },
    limitations: [
      {id: 'bounded-input-not-node-determinism', disposition: 'The seed determines orchestration choices, not Stacks P2P randomness, scheduling, message order, block hashes, or timings.'},
      {id: 'reduced-not-causal-minimal', disposition: 'Distributed failures may be non-monotone; reduction claims only a smaller confirmed reproducer and never causal minimality.'},
      {id: 'automatic-parameter-reduction-deferred', disposition: 'R1 automatic reduction covers execution, stage, action, and explicit-actor removal. The pre-existing manual RemovedParameters API remains available, while mechanism-registered monotone parameter reducers are future work.'},
      {id: 'nested-reduction-live-coverage', disposition: 'Live qualification exercises execution-level removal. Material stage, action, and actor candidates are qualified by production reducer tests and are not claimed as live coverage.'},
      {id: 'local-corpus', disposition: 'R1 uses a caller-selected local content-addressed corpus root; shared service storage remains future work.'},
      {id: 'local-kind-r1', disposition: 'Release 1 qualifies linux/arm64 images on a local three-node kind cluster; registry and multi-architecture publication remain future work.'},
      {id: 'review-evidence-archive', disposition: `Portable A13 evidence is archived at ${summary.archive.location} with digest ${summary.archive.digest}.`},
      {id: 'human-review-custody', disposition: 'The mechanical gate cannot attest reviewer identity or comprehension.'},
    ],
    reproduction: [
      'make -C contrib/helm/hacknet/operator verify',
      'contrib/attacknet/test/check.sh',
      'contrib/helm/hacknet/scripts/check.sh',
      'node --test contrib/attacknet/release/amendments/a13/a13.test.mjs',
      'node contrib/attacknet/release/phase-review.mjs verify-packet --contract=contrib/attacknet/release/amendments/a13/contract.json --packet=contrib/attacknet/evidence-packets/release-1-a13/review-packet.json',
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
    throw new Error('A13 summary must be under the packet-relative evidence root');
  }
  writeFileSync(absolute(output), `${JSON.stringify(buildA13Packet({summaryPath: summary, attestationPath: attestation}), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
