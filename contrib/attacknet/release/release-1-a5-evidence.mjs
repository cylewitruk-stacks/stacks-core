#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {A5_CHECK_IDS} from './release-1-a5-verify.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a5-live-evidence/v1';
const INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';

export const A5_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'offline-result.json',
  hacknetCheck: 'hacknet-result.json',
  localInstall: 'local-install.json',
  burnchainPolicy: 'burnchain-policy.json',
  concurrentFault: 'concurrent-fault.json',
  runOverlapRestart: 'run-overlap-restart.json',
  replayMinimization: 'replay-minimization.json',
  acceptedNetwork: 'accepted-network.json',
  acceptedCohort: 'accepted-cohort.json',
  cleanTeardown: 'clean-teardown.json',
});

export const A5_ASSERTIONS = Object.freeze([
  'signed-a4-child-and-exact-candidate-diff',
  'go-format-generation-vet-unit-race-envtest',
  'yaml-v1beta1-conversion-and-closed-schema',
  'immutable-three-node-local-install',
  'burnchain-bootstrap-cadence-pause-resume-flash',
  'aggregate-safe-concurrent-fault-effect-recovery-cleanup',
  'deterministic-run-overlap-restart-resume',
  'fresh-network-replay-and-removal-only-minimization',
  'accepted-scale-thirty-actor-readiness-and-eighteen-node-convergence',
  'bounded-incident-capture-and-clean-teardown',
]);

function fail(message) {
  throw new Error(message);
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function digestFile(path) {
  return digestBytes(readFileSync(path));
}

function load(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`${label} is not readable JSON: ${error.message}`);
  }
}

function portablePath(root, path) {
  const value = relative(root, path);
  if (!value || value.startsWith('..') || isAbsolute(value) || value.includes('\\')) {
    fail(`evidence path is not portable from the repository root: ${path}`);
  }
  return value;
}

function requireCandidate(value, candidate, label) {
  if (!value || typeof value !== 'object' || value.candidateRevision !== candidate) {
    fail(`${label} does not pin the candidate revision`);
  }
  return value;
}

function requiredDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
}

/** Validate the complete candidate-bound A5 offline verification result. */
export function validateA5Verification(value, candidate) {
  requireCandidate(value, candidate, 'A5 verification');
  if (value.schema !== 'stacks-attacknet-release-1-a5-verification/v1' || value.outcome !== 'Passed') {
    fail('A5 verification is not passed');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== value.checks?.length) fail('A5 verification duplicates check IDs');
  for (const id of A5_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0
      || !Number.isSafeInteger(check.durationMs) || typeof check.command !== 'string') {
      fail(`A5 verification check ${id} is not a complete pass`);
    }
    requiredDigest(check.outputDigest, `A5 verification ${id}.outputDigest`);
  }
  if (checks.size !== A5_CHECK_IDS.length) fail('A5 verification contains unexpected checks');
  return value;
}

function validateAttacknetResult(value, candidate) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== candidate || value.status !== 'passed') {
    fail('Attacknet check is not a passed candidate result');
  }
}

function validateHacknetResult(value, candidate) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== candidate) fail('Hacknet result does not pin the candidate');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A5 requires a passed Hacknet ${required} check`);
    }
  }
}

function validateLocalInstall(value, candidate) {
  requireCandidate(value, candidate, 'local install evidence');
  if (value.schemaVersion !== 'stacks-attacknet-a5-local-install-evidence/v1'
    || value.kindImageLoad?.outcome !== 'Loaded' || value.kindImageLoad.nodes?.length !== 3) {
    fail('local install evidence does not prove a three-node immutable load');
  }
  const nodes = new Set(value.kindImageLoad.nodes.map(node => node.name));
  if (nodes.size !== 3 || value.kindImageLoad.images?.some(image => !image.verified || !nodes.has(image.node))) {
    fail('local install evidence contains an unverified image or duplicate node');
  }
  requiredDigest(value.actorImages?.stacksCoreRuntimeImageID, 'local install actorImages.stacksCoreRuntimeImageID');
  requiredDigest(value.operatorImages?.topologyRuntimeImageID, 'local install operatorImages.topologyRuntimeImageID');
  requiredDigest(value.operatorImages?.runRuntimeImageID, 'local install operatorImages.runRuntimeImageID');
  for (const imageID of [
    value.actorImages.stacksCoreRuntimeImageID,
    value.operatorImages.topologyRuntimeImageID,
    value.operatorImages.runRuntimeImageID,
  ]) {
    const loaded = new Set(value.kindImageLoad.images
      .filter(image => image.verified === true && image.runtimeImageID === imageID)
      .map(image => image.node));
    if (loaded.size !== nodes.size || [...nodes].some(node => !loaded.has(node))) {
      fail(`qualified image ${imageID} was not verified on every kind node`);
    }
  }
}

function snapshotResource(value, kind, label) {
  if (value?.schemaVersion !== 'stacks-attacknet-resource-snapshot/v1'
    || value.resource?.kind !== kind || value.scope !== 'single-resource-status') {
    fail(`${label} is not a typed resource snapshot`);
  }
  requiredDigest(value.resourceDigest, `${label}.resourceDigest`);
  return value.resource;
}

function validateBurnchainPolicy(value, candidate) {
  requireCandidate(value, candidate, 'burnchain policy evidence');
  const resource = snapshotResource(value.snapshot, 'BurnchainPolicy', 'burnchain policy snapshot');
  if (resource.status?.phase !== 'Ready' || resource.status.observedGeneration !== resource.metadata?.generation
    || resource.status.observedHeight < resource.spec?.bootstrapHeight) {
    fail('burnchain policy is not freshly Ready beyond bootstrap');
  }
  for (const claim of ['pauseObserved', 'resumeObserved', 'cadenceObserved', 'exactFlashObserved']) {
    if (value.assertions?.[claim] !== true) fail(`burnchain policy omits ${claim}`);
  }
}

function validateConcurrentFault(value, candidate) {
  requireCandidate(value, candidate, 'concurrent fault evidence');
  if (value.schemaVersion !== 'stacks-attacknet-a5-concurrent-fault-evidence/v1'
    || value.overlapObserved !== true || value.aggregateSafetyAdmitted !== true
    || value.controllerRestartObserved !== true || value.unsafeUnionRejected !== true
    || !Array.isArray(value.campaigns) || value.campaigns.length < 2) {
    fail('concurrent fault evidence is incomplete');
  }
  for (const campaign of value.campaigns) {
    const resource = snapshotResource(campaign, 'FaultCampaign', 'concurrent campaign');
    if (resource.status?.phase !== 'Passed' || resource.status.cleanup?.absent !== true) {
      fail('concurrent campaign did not pass with absent mutation');
    }
  }
}

function validateRunEvidence(value, candidate, mode) {
  requireCandidate(value, candidate, `${mode} evidence`);
  if (value.schemaVersion !== `stacks-attacknet-a5-${mode}-evidence/v1`
    || value.freshNetworkIdentity !== true || value.cleanupCompleted !== true) {
    fail(`${mode} evidence is incomplete`);
  }
  for (const snapshot of value.runs ?? []) {
    const resource = snapshotResource(snapshot, 'AttacknetRun', `${mode} run`);
    if (resource.status?.phase !== 'Passed' || resource.status.cleanup?.completed !== true) {
      fail(`${mode} run did not pass with controller-owned cleanup`);
    }
  }
  if ((value.runs ?? []).length < 2) fail(`${mode} evidence requires at least two bound runs`);
  if (mode === 'run-overlap-restart' && (value.overlapObserved !== true || value.controllerRestartObserved !== true)) {
    fail('run overlap/restart evidence lacks overlap or restart');
  }
  if (mode === 'replay-minimization'
    && (value.expectedReplayObserved !== true || value.removalOnlyMinimizationObserved !== true)) {
    fail('replay/minimization evidence lacks expected replay or removal-only minimization');
  }
}

function validateAcceptedNetwork(value, candidate) {
  requireCandidate(value, candidate, 'accepted network evidence');
  const resource = snapshotResource(value.snapshot, 'StacksNetwork', 'accepted network snapshot');
  if (resource.status?.phase !== 'Ready' || resource.status.inventoryReady !== true
    || resource.status.readyActors !== 30 || resource.status.desiredActors !== 30
    || resource.status.observedGeneration !== resource.metadata?.generation) {
    fail('accepted topology is not freshly 30/30 Ready with admitted inventory');
  }
}

function validateCohort(value, candidate) {
  requireCandidate(value, candidate, 'accepted cohort evidence');
  const cohort = value.observation;
  if (cohort?.schemaVersion !== 'stacks-attacknet-chain-cohort-observation/v1'
    || cohort.actorCount !== 18 || cohort.stacksTipHeight <= 0
    || Object.values(cohort.assertions ?? {}).some(assertion => assertion !== true)) {
    fail('accepted cohort does not prove eighteen-node nonzero convergence');
  }
}

function validateIncident(value, candidate) {
  requireCandidate(value, candidate, 'accepted incident evidence');
  const manifest = value.manifest;
  if (manifest?.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || manifest.network?.inventoryReady !== true || !Array.isArray(manifest.artifacts)
    || manifest.artifacts.length === 0 || (manifest.errors ?? []).length !== 0
    || (manifest.omissions ?? []).length !== 0) {
    fail('accepted incident evidence is incomplete or contains errors/omissions');
  }
}

function validateTeardown(value, candidate) {
  requireCandidate(value, candidate, 'clean teardown evidence');
  if (value.schemaVersion !== 'stacks-attacknet-a5-clean-teardown-evidence/v1'
    || value.cleanupCompleted !== true
    || Object.values(value.remainingCounts ?? {}).some(count => count !== 0)) {
    fail('clean teardown evidence retains managed resources');
  }
}

const validators = Object.freeze({
  verification: validateA5Verification,
  attacknetCheck: validateAttacknetResult,
  hacknetCheck: validateHacknetResult,
  localInstall: validateLocalInstall,
  burnchainPolicy: validateBurnchainPolicy,
  concurrentFault: validateConcurrentFault,
  runOverlapRestart: (value, candidate) => validateRunEvidence(value, candidate, 'run-overlap-restart'),
  replayMinimization: (value, candidate) => validateRunEvidence(value, candidate, 'replay-minimization'),
  acceptedNetwork: validateAcceptedNetwork,
  acceptedCohort: validateCohort,
  cleanTeardown: validateTeardown,
});

/** Validate one named A5 JSON artifact against the signed candidate. */
export function validateA5Artifact(key, value, candidate) {
  const validator = validators[key];
  if (!validator) fail(`unknown A5 artifact ${key}`);
  validator(value, candidate);
  return value;
}

/** Validate the accepted-scale incident manifest against the signed candidate wrapper. */
export function validateA5Incident(manifest, candidate) {
  validateIncident({candidateRevision: candidate, manifest}, candidate);
  return manifest;
}

/** Validate the immutable identity joins across the accepted-scale artifacts. */
export function validateA5ArtifactSet(values, incidentManifest) {
  const network = values.acceptedNetwork.snapshot.resource;
  const policy = values.burnchainPolicy.snapshot.resource;
  const stacksRuntime = values.localInstall.actorImages.stacksCoreRuntimeImageID;
  const stacksActors = network.status.actors.filter(actor => ['miner', 'follower', 'companion'].includes(actor.role));
  if (stacksActors.length !== 18 || stacksActors.some(actor => actor.runtimeImageID !== stacksRuntime)) {
    fail('accepted network does not bind all eighteen Stacks nodes to the qualified runtime image');
  }
  if (policy.status.admittedNetworkUID !== network.metadata.uid
    || incidentManifest.network.uid !== network.metadata.uid
    || incidentManifest.network.inventoryDigest !== network.status.inventoryDigest
    || values.acceptedCohort.observation.network !== network.metadata.name) {
    fail('accepted topology, burnchain policy, cohort, and incident identities do not join');
  }
  return values;
}

function archiveIndex(candidate, root) {
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const archivePath = relative(root, path);
      if (archivePath === 'archive-index.json' || archivePath === 'archive') continue;
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) entries.push({path: archivePath, digest: digestFile(path), size: statSync(path).size});
      else fail(`unsupported archive entry ${archivePath}`);
    }
  };
  visit(root);
  return {schema: INDEX_SCHEMA, candidateRevision: candidate, entries};
}

/** Validate and archive all A5 command and live evidence under one portable root. */
export function assembleReleaseOneA5Evidence({
  candidateRevision, inputDirectory, outputDirectory, archiveLocation, root = repositoryRoot,
}) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) fail('candidateRevision must be a full Git SHA');
  if (typeof archiveLocation !== 'string' || archiveLocation.length === 0) fail('archiveLocation is required');
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  if (output === root || !portablePath(root, output)) fail('outputDirectory must be inside the repository');
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'artifacts'), {recursive: true});
  mkdirSync(join(output, 'archive'), {recursive: true});

  const artifacts = {};
  const values = {};
  for (const [key, filename] of Object.entries(A5_ARTIFACTS)) {
    const source = join(input, filename);
    const archiveEntry = `artifacts/${filename}`;
    const target = join(output, archiveEntry);
    copyFileSync(source, target);
    if (key === 'candidateDiff') {
      if (statSync(target).size === 0) fail('candidate diff is empty');
    } else {
      values[key] = load(target, key);
      validators[key](values[key], candidateRevision);
    }
    artifacts[key] = {path: portablePath(root, target), archiveEntry, digest: digestFile(target)};
  }

  const incidentSource = join(input, 'accepted-incident');
  const incidentTarget = join(output, 'artifacts', 'accepted-incident');
  cpSync(incidentSource, incidentTarget, {recursive: true, errorOnExist: true});
  const incidentManifest = load(join(incidentTarget, 'manifest.json'), 'accepted incident manifest');
  validateIncident({candidateRevision, manifest: incidentManifest}, candidateRevision);
  artifacts.acceptedIncident = {
    path: portablePath(root, join(incidentTarget, 'manifest.json')),
    archiveEntry: 'artifacts/accepted-incident/manifest.json',
    digest: digestFile(join(incidentTarget, 'manifest.json')),
  };

  validateA5ArtifactSet(values, incidentManifest);

  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(candidateRevision, output), null, 2)}\n`);
  const archiveName = `release-1-a5-evidence-${candidateRevision.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts'], {env: {...process.env, COPYFILE_DISABLE: '1'}});
  const summary = {
    schema: SUMMARY_SCHEMA,
    candidateRevision,
    archive: {
      path: portablePath(root, archivePath), digest: digestFile(archivePath),
      indexPath: portablePath(root, indexPath), indexDigest: digestFile(indexPath),
      indexEntry: 'archive-index.json', location: archiveLocation,
    },
    artifacts,
    assertions: A5_ASSERTIONS.map(id => ({id, status: 'passed'})),
  };
  writeFileSync(join(output, 'live-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--input=', '--output=', '--archive-location='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  const options = {
    candidateRevision: value('--candidate='), inputDirectory: value('--input='),
    outputDirectory: value('--output='), archiveLocation: value('--archive-location='),
  };
  for (const [name, option] of Object.entries(options)) if (!option) fail(`${name} is required`);
  const summary = assembleReleaseOneA5Evidence(options);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
