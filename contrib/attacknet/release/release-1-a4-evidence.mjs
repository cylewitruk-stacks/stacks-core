#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateControllerLiveArtifact} from './release-1-a2-evidence.mjs';
import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {A4_CHECK_IDS} from './release-1-a4-verify.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a4-live-evidence/v1';
const INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';

export const A4_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'offline-result.json',
  hacknetCheck: 'hacknet-result.json',
  topologyLive: 'topology-live.json',
  reversibleFaultLive: 'reversible-fault-live.json',
  podKillLive: 'pod-kill-live.json',
  restartResumeLive: 'restart-resume-live.json',
  cleanTeardown: 'clean-teardown.json',
});

export const A4_ASSERTIONS = Object.freeze([
  'signed-a3-child-and-exact-candidate-diff',
  'go-format-build-generation-vet-unit-race',
  'envtest-api-server-contracts',
  'fault-registry-and-seven-type-compiler-equivalence',
  'four-profile-topology-render-equivalence',
  'immutable-schedule-direct-read-restart-and-resume',
  'reversible-and-one-shot-fault-lifecycle-equivalence',
  'whole-product-verification',
  'clean-teardown',
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

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function requiredDigest(value, label) {
  const result = requiredString(value, label);
  if (!/^sha256:[0-9a-f]{64}$/.test(result)) fail(`${label} must be an immutable SHA-256 digest`);
  return result;
}

/** Validate that live controller evidence ran the exact A4 candidate images. */
export function validateA4RuntimeBinding(value, candidate, expectedOperatorContextTree) {
  const runtime = value?.candidateRuntime;
  if (!runtime || typeof runtime !== 'object' || runtime.sourceRevision !== candidate
    || runtime.worktreeClean !== true || runtime.platform !== 'linux/arm64') {
    fail('A4 topology evidence does not bind a clean linux/arm64 candidate runtime');
  }
  if (!/^[0-9a-f]{40}$/.test(runtime.operatorContextTree ?? '')
    || runtime.operatorContextTree !== expectedOperatorContextTree) {
    fail('A4 topology evidence does not bind the candidate operator source tree');
  }
  const images = runtime.images;
  if (!images || typeof images !== 'object') fail('A4 topology evidence omits candidate images');
  for (const component of ['operator', 'runOperator', 'probe']) {
    requiredDigest(images[component]?.index, `candidateRuntime.images.${component}.index`);
    requiredDigest(images[component]?.runtime, `candidateRuntime.images.${component}.runtime`);
  }

  const expectedControllers = new Map([
    ['operator', images.operator], ['run-operator', images.runOperator],
  ]);
  const controllers = runtime.admittedControllers;
  if (!Array.isArray(controllers) || controllers.length !== expectedControllers.size) {
    fail('A4 topology evidence must admit both candidate controllers');
  }
  const seenControllers = new Set();
  for (const controller of controllers) {
    const expected = expectedControllers.get(controller?.component);
    if (!expected || seenControllers.has(controller.component) || controller.ready !== true
      || controller.runtimeMatched !== true || controller.indexAnnotationMatched !== true
      || controller.buildAnnotation !== expected.index
      || controller.runtimeImageID !== expected.runtime
      || controller.expectedRuntimeImageID !== expected.runtime) {
      fail('A4 topology evidence contains an unbound admitted controller');
    }
    for (const field of ['pod', 'podUID', 'node', 'declaredImage']) {
      requiredString(controller[field], `candidateRuntime controller ${controller.component}.${field}`);
    }
    seenControllers.add(controller.component);
  }

  if (!Array.isArray(runtime.admittedProbes) || runtime.admittedProbes.length === 0) {
    fail('A4 topology evidence omits admitted candidate probes');
  }
  for (const probe of runtime.admittedProbes) {
    if (probe?.ready !== true || probe.runtimeMatched !== true
      || probe.runtimeImageID !== images.probe.runtime
      || probe.expectedRuntimeImageID !== images.probe.runtime) {
      fail('A4 topology evidence contains an unbound admitted probe');
    }
    for (const field of ['actor', 'pod', 'podUID', 'node', 'declaredImage']) {
      requiredString(probe[field], `candidateRuntime probe.${field}`);
    }
  }

  const receipt = runtime.kindImageLoad;
  if (receipt?.outcome !== 'Loaded' || !Array.isArray(receipt.nodes)
    || receipt.nodes.length !== 3 || !Array.isArray(receipt.images)) {
    fail('A4 topology evidence does not contain the three-node kind load receipt');
  }
  const nodes = new Set();
  for (const node of receipt.nodes) {
    requiredString(node?.name, 'candidateRuntime kind node name');
    if (node.operatingSystem !== 'linux' || node.architecture !== 'arm64'
      || nodes.has(node.name)) {
      fail('A4 topology evidence kind nodes are not unique linux/arm64 nodes');
    }
    nodes.add(node.name);
  }
  for (const loaded of receipt.images) {
    if (!nodes.has(loaded?.node) || loaded.verified !== true) {
      fail('A4 topology evidence contains an unverified kind image load');
    }
  }
  for (const image of [images.operator.index, images.runOperator.index, images.probe.index]) {
    const loadedNodes = new Set(receipt.images
      .filter(entry => entry.hostImageID === image && entry.verified === true)
      .map(entry => entry.node));
    if (loadedNodes.size !== nodes.size || [...nodes].some(node => !loadedNodes.has(node))) {
      fail(`A4 candidate image ${image} was not verified on every kind node`);
    }
  }
  return value;
}

/** Validate one complete A4 offline verification result. */
export function validateA4Verification(value, candidate) {
  requireCandidate(value, candidate, 'A4 verification');
  if (value.schema !== 'stacks-attacknet-release-1-a4-verification/v1' || value.outcome !== 'Passed') {
    fail('A4 verification is not passed');
  }
  if (!/^1\.36\.[0-9]+$/.test(value.kubernetesVersion ?? '')) {
    fail('A4 verification omits the exact Kubernetes 1.36 envtest version');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== value.checks?.length) fail('A4 verification duplicates check IDs');
  for (const id of A4_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0
      || typeof check.command !== 'string' || !Number.isSafeInteger(check.durationMs)
      || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')
      || typeof check.stdout !== 'string' || typeof check.stderr !== 'string') {
      fail(`A4 verification check ${id} is not a complete pass`);
    }
  }
  if (checks.size !== A4_CHECK_IDS.length) fail('A4 verification contains unexpected checks');
  return value;
}

function validateAttacknetResult(value, candidate) {
  if (!value || typeof value !== 'object' || value.sourceRevision !== candidate
    || value.schemaVersion !== 'stacks-attacknet-offline-check-result/v1' || value.status !== 'passed') {
    fail('Attacknet check is not passed');
  }
}

function validateHacknetResult(value, candidate) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== candidate) fail('Hacknet check does not pin the candidate');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A4 requires a passed Hacknet ${required} check`);
    }
  }
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

/** Validate and archive all A4 command and live evidence under one portable root. */
export function assembleReleaseOneA4Evidence({
  candidateRevision,
  inputDirectory,
  outputDirectory,
  archiveLocation,
  root = repositoryRoot,
  expectedOperatorContextTree = undefined,
}) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) fail('candidateRevision must be a full Git SHA');
  if (typeof archiveLocation !== 'string' || archiveLocation.length === 0) fail('archiveLocation is required');
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  if (output === root || !portablePath(root, output)) fail('outputDirectory must be inside the repository');
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'artifacts'), {recursive: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const operatorContextTree = expectedOperatorContextTree ?? execFileSync(
    'git', ['rev-parse', `${candidateRevision}:contrib/helm/hacknet/operator`],
    {cwd: root, encoding: 'utf8'},
  ).trim();

  const artifacts = {};
  for (const [key, filename] of Object.entries(A4_ARTIFACTS)) {
    const source = join(input, filename);
    const archiveEntry = `artifacts/${filename}`;
    const target = join(output, archiveEntry);
    copyFileSync(source, target);
    if (key === 'candidateDiff') {
      if (statSync(target).size === 0) fail('candidate diff is empty');
    } else {
      const value = load(target, key);
      if (key === 'verification') validateA4Verification(value, candidateRevision);
      else if (key === 'attacknetCheck') validateAttacknetResult(value, candidateRevision);
      else if (key === 'hacknetCheck') validateHacknetResult(value, candidateRevision);
      else {
        validateControllerLiveArtifact(key, value, candidateRevision);
        if (key === 'topologyLive') {
          validateA4RuntimeBinding(value, candidateRevision, operatorContextTree);
        }
      }
    }
    artifacts[key] = {path: portablePath(root, target), archiveEntry, digest: digestFile(target)};
  }

  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(candidateRevision, output), null, 2)}\n`);
  const archiveName = `release-1-a4-evidence-${candidateRevision.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts'], {env: {...process.env, COPYFILE_DISABLE: '1'}});
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
    assertions: A4_ASSERTIONS.map(id => ({id, status: 'passed'})),
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
    candidateRevision: value('--candidate='),
    inputDirectory: value('--input='),
    outputDirectory: value('--output='),
    archiveLocation: value('--archive-location='),
  };
  for (const [name, option] of Object.entries(options)) if (!option) fail(`${name} is required`);
  const summary = assembleReleaseOneA4Evidence(options);
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
