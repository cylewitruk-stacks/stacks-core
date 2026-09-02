#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a2-live-evidence/v1';
const INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
const RESULT_SCHEMA = 'stacks-attacknet-release-1-a2-result/v1';

export const REQUIRED_COMMAND_CHECKS = Object.freeze({
  goVerify: Object.freeze([
    'go-build', 'go-format', 'go-generate-clean', 'go-vet', 'go-unit', 'go-race',
  ]),
  envtest: Object.freeze(['kubernetes-1.36-envtest']),
  helmRender: Object.freeze([
    'helm-lint', 'helm-render', 'crd-contracts', 'rbac-security-contracts',
  ]),
});

export const A2_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  equivalenceReport: 'equivalence-report.json',
  goVerify: 'go-verify.json',
  envtest: 'envtest.json',
  helmRender: 'helm-render.json',
  topologyLive: 'topology-live.json',
  reversibleFaultLive: 'reversible-fault-live.json',
  podKillLive: 'pod-kill-live.json',
  restartResumeLive: 'restart-resume-live.json',
  cleanTeardown: 'clean-teardown.json',
});

export const A2_ASSERTIONS = Object.freeze([
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

function fail(message) {
  throw new Error(message);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function string(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function digest(value, label) {
  const result = string(value, label);
  if (!/^sha256:[0-9a-f]{64}$/.test(result)) fail(`${label} must be a SHA-256 digest`);
  return result;
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

function requireCandidate(value, candidate, label) {
  object(value, label);
  if (value.candidateRevision !== candidate) fail(`${label} does not pin the candidate revision`);
  return value;
}

function requirePassed(value, candidate, label) {
  requireCandidate(value, candidate, label);
  if (value.schema !== RESULT_SCHEMA || value.outcome !== 'Passed') {
    fail(`${label} is not a passed A2 result`);
  }
  return value;
}

function requireCommandChecks(value, candidate, label, required) {
  requirePassed(value, candidate, label);
  if (!Array.isArray(value.checks) || value.checks.length === 0) {
    fail(`${label}.checks must contain observed command results`);
  }
  const checks = new Map();
  for (const [index, check] of value.checks.entries()) {
    object(check, `${label}.checks[${index}]`);
    const id = string(check.id, `${label}.checks[${index}].id`);
    if (checks.has(id)) fail(`${label}.checks contains duplicate ${id}`);
    if (check.status !== 'passed') fail(`${label}.${id} is not passed`);
    string(check.command, `${label}.${id}.command`);
    if (check.exitCode !== 0 || !Number.isSafeInteger(check.durationMs) || check.durationMs < 0
      || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')
      || typeof check.stdout !== 'string' || typeof check.stderr !== 'string') {
      fail(`${label}.${id} does not contain a complete observed command result`);
    }
    checks.set(id, check);
  }
  for (const id of required) {
    if (!checks.has(id)) fail(`${label} is missing required check ${id}`);
  }
  if (checks.size !== required.length || [...checks.keys()].some(id => !required.includes(id))) {
    fail(`${label}.checks must contain exactly the required command checks`);
  }
  return value;
}

function terminalCampaign(value, label, expected = 'Passed') {
  object(value, label);
  if (value.phase !== expected) fail(`${label}.phase must be ${expected}`);
  string(value.reason, `${label}.reason`);
  return value;
}

function cleanupAbsent(value, label) {
  object(value, label);
  if (value.absent !== true || value.allRecovered !== true) fail(`${label} does not prove cleanup and recovery`);
}

function proveResults(values, label) {
  if (!Array.isArray(values) || values.length === 0 || values.some(value => value?.outcome !== 'Proven')) {
    fail(`${label} must contain only proven results`);
  }
}

function validateTopology(value, candidate) {
  requirePassed(value, candidate, 'topology evidence');
  const initial = object(value.initial, 'topology.initial');
  const withdrawn = object(value.withdrawn, 'topology.withdrawn');
  const mutated = object(value.mutated, 'topology.mutated');
  const restored = object(value.restored, 'topology.restored');
  for (const [label, snapshot] of [['initial', initial], ['mutated', mutated], ['restored', restored]]) {
    if (snapshot.phase !== 'Ready' || snapshot.inventoryReady !== true
      || !/^sha256:[0-9a-f]{64}$/.test(snapshot.inventoryDigest)
      || snapshot.readyActors !== snapshot.desiredActors || snapshot.readyActors < 1) {
      fail(`topology.${label} is not a complete admitted inventory`);
    }
  }
  if (withdrawn.inventoryReady === true || withdrawn.inventoryDigest) {
    fail('topology.withdrawn retained a supposedly authoritative inventory digest');
  }
  if (!(initial.generation < withdrawn.generation && withdrawn.generation <= mutated.generation
    && mutated.generation < restored.generation)) {
    fail('topology evidence does not prove both mutable reconcile generations');
  }
  if (new Set([initial.inventoryDigest, mutated.inventoryDigest, restored.inventoryDigest]).size !== 3) {
    fail('topology admitted-inventory digests did not change with immutable Pod identity');
  }
}

function validateReversibleFault(value, candidate) {
  requirePassed(value, candidate, 'reversible fault evidence');
  const precondition = object(
    value.preconditionObservation,
    'reversible fault environment-lease precondition',
  );
  if (precondition.phase !== 'Pending'
    || precondition.reason !== 'WaitingForEnvironmentLease'
    || typeof precondition.message !== 'string' || precondition.message.length === 0
    || precondition.mutationCreated !== false) {
    fail('reversible fault did not prove a fail-closed environment-lease wait');
  }
  terminalCampaign(value.campaign, 'reversible fault campaign');
  object(value.campaign.actualInjection, 'reversible fault actual injection');
  proveResults(value.campaign.effectResults, 'reversible fault effects');
  proveResults(value.campaign.recoveryResults, 'reversible fault recoveries');
  cleanupAbsent(value.campaign.cleanup, 'reversible fault cleanup');
  if (value.mutationPresentAfterTerminal !== false) fail('reversible fault mutation remains after terminal status');
}

function validatePodKill(value, candidate) {
  requirePassed(value, candidate, 'Pod-kill evidence');
  terminalCampaign(value.campaign, 'Pod-kill campaign');
  const admitted = string(value.admittedPodUID, 'Pod-kill admittedPodUID');
  const replacement = string(value.replacementPodUID, 'Pod-kill replacementPodUID');
  if (admitted === replacement) fail('Pod-kill did not replace the admitted Pod identity');
  if (!/^sha256:[0-9a-f]{64}$/.test(value.replacementRuntimeImageID ?? '')) {
    fail('Pod-kill replacement image identity is not immutable');
  }
  proveResults(value.campaign.effectResults, 'Pod-kill effects');
  proveResults(value.campaign.recoveryResults, 'Pod-kill recoveries');
  cleanupAbsent(value.campaign.cleanup, 'Pod-kill cleanup');
  if (value.mutationPresentAfterTerminal !== false) fail('Pod-kill mutation remains after terminal status');
}

function validateRestartResume(value, candidate) {
  requirePassed(value, candidate, 'restart/resume evidence');
  const run = terminalCampaign(value.run, 'restart run');
  if (run.reason !== 'SequenceCompleted' || !Array.isArray(run.decisions) || run.decisions.length < 1) {
    fail('restart run does not prove a durable completed decision');
  }
  if (run.cleanup?.required !== true || run.cleanup?.completed !== true) {
    fail('restart run does not prove terminal child cleanup');
  }
  if (string(value.controllerUIDBefore, 'controllerUIDBefore')
    === string(value.controllerUIDAfter, 'controllerUIDAfter')) {
    fail('restart evidence did not replace the run controller Pod');
  }
  terminalCampaign(value.childCampaign, 'restart child campaign');
  cleanupAbsent(value.childCampaign.cleanup, 'restart child cleanup');
}

function validateTeardown(value, candidate) {
  requirePassed(value, candidate, 'teardown evidence');
  const counts = object(value.remainingCounts, 'teardown remainingCounts');
  const required = [
    'stacksNetworks', 'faultCampaigns', 'attacknetRuns', 'statefulSets', 'pods',
    'pvcs', 'leases', 'chaosResources', 'clockPolicies', 'pressurePods',
  ];
  for (const key of required) {
    if (counts[key] !== 0) fail(`teardown did not remove ${key}`);
  }
}

const VALIDATORS = Object.freeze({
  goVerify: (value, candidate) => requireCommandChecks(
    value, candidate, 'Go verification evidence', REQUIRED_COMMAND_CHECKS.goVerify,
  ),
  envtest: (value, candidate) => {
    requireCommandChecks(
      value, candidate, 'envtest evidence', REQUIRED_COMMAND_CHECKS.envtest,
    );
    if (!/^1\.36\.[0-9]+$/.test(value.kubernetesVersion ?? '')) {
      fail('envtest evidence must identify the Kubernetes 1.36 patch release');
    }
    return value;
  },
  helmRender: (value, candidate) => requireCommandChecks(
    value, candidate, 'Helm/render evidence', REQUIRED_COMMAND_CHECKS.helmRender,
  ),
  topologyLive: validateTopology,
  reversibleFaultLive: validateReversibleFault,
  podKillLive: validatePodKill,
  restartResumeLive: validateRestartResume,
  cleanTeardown: validateTeardown,
});

/**
 * Validate one controller live-qualification artifact using the compatibility
 * schema established by A2. Later behavior-preserving amendments reuse these
 * semantics instead of maintaining independent copies of the same validators.
 */
export function validateControllerLiveArtifact(kind, value, candidate) {
  const validator = VALIDATORS[kind];
  if (!validator || !['topologyLive', 'reversibleFaultLive', 'podKillLive', 'restartResumeLive', 'cleanTeardown'].includes(kind)) {
    fail(`unsupported controller live artifact ${kind}`);
  }
  validator(value, candidate);
  return value;
}

function portablePath(root, path) {
  const value = relative(root, path);
  if (!value || value.startsWith('..') || isAbsolute(value) || value.includes('\\')) {
    fail(`evidence path is not portable from the repository root: ${path}`);
  }
  return value;
}

function archiveIndex(candidate, root) {
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const archivePath = relative(root, path);
      if (archivePath === 'archive-index.json' || archivePath === 'archive') continue;
      if (entry.isDirectory()) {
        visit(path);
        continue;
      }
      if (!entry.isFile()) fail(`evidence archive contains unsupported entry ${archivePath}`);
      entries.push({path: archivePath, digest: digestFile(path), size: statSync(path).size});
    }
  };
  visit(root);
  return {schema: INDEX_SCHEMA, candidateRevision: candidate, entries};
}

/** Validate raw A2 qualification artifacts and assemble one portable review archive. */
export function assembleReleaseOneA2Evidence({
  candidateRevision,
  inputDirectory,
  outputDirectory,
  archiveLocation,
  root = repositoryRoot,
}) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) fail('candidateRevision must be a full Git SHA');
  string(archiveLocation, 'archiveLocation');
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  if (output === root || !portablePath(root, output)) fail('outputDirectory must be inside the repository');
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'artifacts'), {recursive: true});
  mkdirSync(join(output, 'archive'), {recursive: true});

  const artifacts = {};
  for (const [key, filename] of Object.entries(A2_ARTIFACTS)) {
    const source = join(input, filename);
    const archiveEntry = `artifacts/${filename}`;
    const target = join(output, archiveEntry);
    copyFileSync(source, target);
    if (key === 'candidateDiff') {
      if (statSync(target).size === 0) fail('candidate diff is empty');
    } else if (key === 'equivalenceReport') {
      requireCandidate(load(target, 'equivalence report'), candidateRevision, 'equivalence report');
    } else {
      VALIDATORS[key](load(target, key), candidateRevision, key);
    }
    artifacts[key] = {
      path: portablePath(root, target), archiveEntry, digest: digestFile(target),
    };
  }

  for (const filename of ['offline-result.json', 'hacknet-result.json']) {
    copyFileSync(join(input, filename), join(output, filename));
  }
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(candidateRevision, output), null, 2)}\n`);
  const archiveName = `release-1-a2-live-evidence-${candidateRevision.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts', 'offline-result.json', 'hacknet-result.json'], {env: {...process.env, COPYFILE_DISABLE: '1'}});

  const summary = {
    schema: SUMMARY_SCHEMA,
    candidateRevision,
    archive: {
      path: portablePath(root, archivePath),
      digest: digestFile(archivePath),
      indexPath: portablePath(root, indexPath),
      indexDigest: digestFile(indexPath),
      indexEntry: 'archive-index.json',
      location: archiveLocation,
    },
    artifacts,
    assertions: A2_ASSERTIONS.map(id => ({id, status: 'passed'})),
  };
  writeFileSync(join(output, 'live-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = prefix => args.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--input=', '--output=', '--archive-location='];
  const unknown = args.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  const summary = assembleReleaseOneA2Evidence({
    candidateRevision: value('--candidate='),
    inputDirectory: value('--input='),
    outputDirectory: value('--output='),
    archiveLocation: value('--archive-location='),
  });
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}
