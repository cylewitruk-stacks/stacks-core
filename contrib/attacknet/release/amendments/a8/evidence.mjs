#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {
  candidateRuntimeImageIDs, validateCandidateBuildReceipt,
} from './qualification/candidate-build.mjs';
import {A8_CHECK_IDS, validateA8Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');

export const A8_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a8-live-evidence/v1';
export const A8_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A8_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
  candidateBuild: 'candidate-build.json',
  liveQualification: 'live-qualification.json',
  baselineRun: 'baseline-run.json',
  violationRun: 'violation-run.json',
  sourceLossRun: 'source-loss-run.json',
  stacksTriggerRun: 'stacks-trigger-run.json',
  teardownManifest: 'teardown-success/teardown.json',
  lokiMetadata: 'teardown-success/loki/export.json',
  lokiSource: 'teardown-success/loki/kubernetes-source.json',
  lokiLogs: 'teardown-success/loki/logs.jsonl.gz',
  teardownInventory: 'teardown-success/inventory.json',
  teardownFailure: 'teardown-failure.json',
  cleanTeardown: 'clean-teardown.json',
});
export const A8_ASSERTIONS = Object.freeze([
  'qualified-tree-and-exact-candidate-diff',
  'qualified-tree-bound-image-build-and-kind-admission',
  'offline-race-envtest-helm-and-whole-product-checks-pass',
  'clean-protocol-baseline-and-recovery-proven',
  'protocol-violation-fails-with-identity-bound-evidence',
  'observation-source-loss-is-inconclusive',
  'stacks-height-trigger-has-a-trusted-source-bound-receipt',
  'loki-ingress-allows-trusted-collectors-and-denies-untrusted-pods',
  'complete-loki-export-precedes-network-deletion',
  'failed-loki-export-preserves-the-same-network-identity',
  'clean-final-teardown',
]);

function fail(message) {
  throw new Error(message);
}

function load(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`${label} is not readable JSON: ${error.message}`);
  }
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestFile(path) {
  return digestBytes(readFileSync(path));
}

function requiredDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
}

function safeRelative(path, label) {
  if (typeof path !== 'string' || path.length === 0 || isAbsolute(path)
    || path.includes('\\') || path.split('/').includes('..')) {
    fail(`${label} must be a portable relative path`);
  }
  return path;
}

function portablePath(root, path) {
  const value = relative(root, path);
  if (!value || value.startsWith('..') || isAbsolute(value) || value.includes('\\')) {
    fail(`evidence path is not portable from the repository root: ${path}`);
  }
  return value;
}

function qualifiedTreeBound(value, qualifiedTree, label) {
  if (!value || typeof value !== 'object' || value.qualifiedTree !== qualifiedTree) {
    fail(`${label} does not pin the qualified tree`);
  }
  return value;
}

function resourceSnapshot(value, qualifiedTree, label) {
  qualifiedTreeBound(value, qualifiedTree, label);
  if (value.schemaVersion !== 'stacks-attacknet-resource-snapshot/v1'
    || value.scope !== 'single-resource-status'
    || value.resource?.kind !== 'AttacknetRun') {
    fail(`${label} is not an AttacknetRun status snapshot`);
  }
  requiredDigest(value.resourceDigest, `${label}.resourceDigest`);
  return value.resource;
}

function assertionResults(resource) {
  const protocol = resource.status?.protocolAssertions ?? {};
  return Object.values(protocol).flatMap(set => set?.results ?? []);
}

function evidenceIdentity(result, label) {
  const raw = result?.evidence;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || typeof raw.networkUID !== 'string' || raw.networkUID.length === 0
    || !/^sha256:[0-9a-f]{64}$/.test(raw.inventoryDigest ?? '')
    || !Number.isFinite(Date.parse(raw.observedAt ?? ''))
    || !Array.isArray(raw.sources) || raw.sources.length === 0) {
    fail(`${label} lacks identity-bound assertion evidence`);
  }
  for (const source of raw.sources) {
    if (source.evidenceClass !== 'actor_self_reported' || !source.actor || !source.podUID
      || !source.runtimeImageID || !Number.isFinite(Date.parse(source.observedAt ?? ''))) {
      fail(`${label} contains an incomplete actor source`);
    }
  }
}

/** Validate the clean baseline and recovery run. */
export function validateA8BaselineRun(value, qualifiedTree) {
  const resource = resourceSnapshot(value, qualifiedTree, 'baseline run');
  if (resource.status?.phase !== 'Passed'
    || resource.status?.protocolAssertions?.baseline?.outcome !== 'Proven'
    || resource.status?.protocolAssertions?.recovery?.outcome !== 'Proven') {
    fail('baseline run did not pass proven baseline and recovery gates');
  }
  for (const result of assertionResults(resource)) {
    if (result.outcome === 'Proven') evidenceIdentity(result, `baseline assertion ${result.id}`);
  }
  return value;
}

/** Validate one observed protocol violation that terminates Failed. */
export function validateA8ViolationRun(value, qualifiedTree) {
  const resource = resourceSnapshot(value, qualifiedTree, 'violation run');
  const violated = assertionResults(resource).filter(result => result.outcome === 'Violated');
  if (resource.status?.phase !== 'Failed' || resource.status?.attribution !== 'ProtocolAssertion'
    || violated.length === 0) {
    fail('violation run lacks a failed protocol assertion outcome');
  }
  for (const result of violated) evidenceIdentity(result, `violated assertion ${result.id}`);
  return value;
}

/** Validate that required source loss terminates Inconclusive, never Passed. */
export function validateA8SourceLossRun(value, qualifiedTree) {
  const resource = resourceSnapshot(value, qualifiedTree, 'source-loss run');
  const inconclusive = assertionResults(resource).filter(result => result.outcome === 'Inconclusive');
  if (resource.status?.phase !== 'Inconclusive' || inconclusive.length === 0) {
    fail('source-loss run did not terminate Inconclusive');
  }
  return value;
}

/** Validate the independently controlled metrics-Service withdrawal. */
export function validateA8SourceLossControl(value, run) {
  const matchingResult = assertionResults(run).find(result => (
    result.outcome === 'Inconclusive'
    && result.evidence?.networkUID === value?.network?.before?.uid
    && result.evidence?.inventoryDigest === value?.network?.before?.inventoryDigest
  ));
  const timeFields = [
    value?.faultOracle?.activeObservedAt, value?.topology?.pausedAt,
    value?.topology?.restoredAt, value?.service?.deletedAt,
    value?.service?.restoredAt, value?.runCompletedAt,
  ];
  if (value?.schemaVersion !== 'stacks-attacknet-a8-source-loss-control/v1'
    || value.control !== 'topology-paused-service-withdrawal'
    || value.actor !== 'follower-1'
    || value.faultOracle?.phase !== 'Running' || !value.faultOracle?.childCampaign
    || !value.faultOracle?.childUID || !value.topology?.deployment
    || !value.topology?.deploymentUID || value.topology?.originalReplicas !== 1
    || value.topology?.restoredReplicas !== 1
    || !value.service?.name || !value.service?.beforeUID || !value.service?.restoredUID
    || value.service.beforeUID === value.service.restoredUID
    || !value.network?.before?.uid || value.network.before.uid !== value.network?.after?.uid
    || value.network.before.inventoryDigest !== value.network.after.inventoryDigest
    || value.run?.name !== run?.metadata?.name || value.run?.uid !== run?.metadata?.uid
    || value.run?.generation !== run?.metadata?.generation
    || value.run?.resourceVersion !== run?.metadata?.resourceVersion
    || run?.status?.phase !== 'Inconclusive' || !matchingResult
    || value.runPhase !== 'Inconclusive'
    || timeFields.some(timestamp => !Number.isFinite(Date.parse(timestamp ?? '')))) {
    fail('A8 source-loss control does not prove bounded Service withdrawal and exact restoration');
  }
  return value;
}

/** Validate that only the explicitly allowed collector identity can reach Loki. */
export function validateA8LokiIngressControl(value) {
  const outcomes = new Map((value?.outcomes ?? []).map(outcome => [outcome?.name, outcome]));
  if (value?.schemaVersion !== 'stacks-attacknet-a8-loki-ingress-control/v1'
    || !value.service || !value.networkPolicy || !Number.isFinite(Date.parse(value.observedAt ?? ''))
    || value.outcomes?.length !== 2 || outcomes.size !== 2) {
    fail('A8 Loki ingress control is incomplete');
  }
  for (const [name, expectedReachable] of [
    ['a8-loki-policy-allowed', true], ['a8-loki-policy-denied', false],
  ]) {
    const outcome = outcomes.get(name);
    if (!outcome?.podUID || outcome.expectedReachable !== expectedReachable
      || outcome.phase !== 'Succeeded' || outcome.exitCode !== 0) {
      fail(`A8 Loki ingress control did not prove ${name}`);
    }
  }
  return value;
}

/** Validate one trusted Stacks-height trigger receipt. */
export function validateA8StacksTriggerRun(value, qualifiedTree) {
  const resource = resourceSnapshot(value, qualifiedTree, 'Stacks-trigger run');
  const receipts = (resource.status?.triggerReceipts ?? []).map(receipt =>
    typeof receipt === 'string' ? JSON.parse(receipt) : receipt);
  const receipt = receipts.find(entry => (entry?.evidence ?? []).some(evidence => evidence.kind === 'StacksHeight'));
  const evidence = receipt?.evidence?.find(entry => entry.kind === 'StacksHeight');
  const source = evidence?.source;
  if (!receipt || receipt.schemaVersion !== 'stacks-attacknet-trigger-receipt/v1'
    || source?.kind !== 'ProtocolObservation' || source?.trusted !== true
    || !/^sha256:[0-9a-f]{64}$/.test(source.uid ?? '')
    || !Number.isSafeInteger(evidence.observedHeight)
    || evidence.observedHeight < evidence.targetHeight) {
    fail('Stacks-trigger run lacks a trusted inventory-bound height receipt');
  }
  return value;
}

function teardownFiles(root) {
  const files = new Map();
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const relativePath = relative(root, path);
      if (relativePath === 'inventory.json') continue;
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) files.set(relativePath, path);
      else fail(`teardown evidence contains unsupported entry ${relativePath}`);
    }
  };
  visit(root);
  return files;
}

function validateTeardownInventory(root) {
  const inventory = load(join(root, 'inventory.json'), 'teardown inventory');
  if (inventory?.schemaVersion !== 'stacks-attacknet-a8-teardown-inventory/v1'
    || !Array.isArray(inventory.entries) || inventory.entries.length === 0) {
    fail('teardown inventory is incomplete');
  }
  const actual = teardownFiles(root);
  const declared = new Map();
  for (const entry of inventory.entries) {
    const path = safeRelative(entry?.path, 'teardown inventory path');
    if (declared.has(path) || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      fail(`teardown inventory contains an incomplete or duplicate entry ${path}`);
    }
    requiredDigest(entry.digest, `teardown inventory ${path}`);
    declared.set(path, entry);
  }
  if (declared.size !== actual.size) fail('teardown inventory does not cover the exact evidence tree');
  for (const [path, file] of actual) {
    const entry = declared.get(path);
    if (!entry || entry.digest !== digestFile(file) || entry.size !== statSync(file).size) {
      fail(`teardown inventory does not bind ${path}`);
    }
  }
  return {inventory, actual};
}

function validateLokiCorpus(loki, logsPath, network) {
  let raw;
  try {
    raw = gunzipSync(readFileSync(logsPath));
  } catch (error) {
    fail(`retained Loki corpus is not valid gzip: ${error.message}`);
  }
  if (loki.compressedBytes !== statSync(logsPath).size || loki.uncompressedBytes !== raw.length) {
    fail('Loki byte counts do not match the retained corpus');
  }
  const lines = raw.toString('utf8').split('\n');
  if (lines.at(-1) !== '') fail('retained Loki corpus is not newline-terminated JSONL');
  lines.pop();
  if (lines.length !== loki.entryCount) fail('Loki entry count does not match the retained corpus');
  if (!/^[0-9]+$/.test(loki.startNs ?? '') || !/^[0-9]+$/.test(loki.endNs ?? '')) {
    fail('Loki export range is invalid');
  }
  let prior = BigInt(loki.startNs);
  const end = BigInt(loki.endNs);
  if (prior > end) fail('Loki export range is reversed');
  for (const [index, line] of lines.entries()) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch (error) {
      fail(`retained Loki entry ${index} is not JSON: ${error.message}`);
    }
    if (!/^[0-9]+$/.test(entry?.timestampNs ?? '') || !entry.labels
      || typeof entry.labels !== 'object' || Array.isArray(entry.labels)
      || Object.values(entry.labels).some(value => typeof value !== 'string')
      || entry.labels.attacknet_network !== network || typeof entry.line !== 'string') {
      fail(`retained Loki entry ${index} has an invalid shape`);
    }
    const timestamp = BigInt(entry.timestampNs);
    if (timestamp < prior || timestamp > end) fail('retained Loki corpus is outside its ordered export range');
    prior = timestamp;
  }
}

function validateLokiPagination(loki) {
  if (!Number.isSafeInteger(loki.pageCount) || loki.pageCount < 1
    || !Number.isSafeInteger(loki.pageLimit) || loki.pageLimit < 1
    || !Array.isArray(loki.pages) || loki.pages.length !== loki.pageCount) {
    fail('Loki pagination evidence is incomplete');
  }
  let fresh = 0;
  for (const [index, page] of loki.pages.entries()) {
    if (page.page !== index + 1 || !Number.isSafeInteger(page.rawEntries) || page.rawEntries < 0
      || !Number.isSafeInteger(page.newEntries) || page.newEntries < 0 || page.newEntries > page.rawEntries) {
      fail('Loki pagination evidence contains an invalid page');
    }
    const expectedStart = index === 0 ? loki.startNs : loki.pages[index - 1].maximumTimestampNs;
    const hasMaximum = /^[0-9]+$/.test(page.maximumTimestampNs ?? '');
    if (page.startNs !== expectedStart || (page.rawEntries > 0) !== hasMaximum) {
      fail('Loki pagination cursor chain is inconsistent');
    }
    if (hasMaximum && (BigInt(page.maximumTimestampNs) < BigInt(page.startNs)
      || BigInt(page.maximumTimestampNs) > BigInt(loki.endNs))) {
      fail('Loki pagination cursor is outside the export range');
    }
    if (index < loki.pages.length - 1 ? page.rawEntries !== loki.pageLimit : page.rawEntries >= loki.pageLimit) {
      fail('Loki pagination termination is not proven');
    }
    fresh += page.newEntries;
  }
  if (fresh !== loki.entryCount) fail('Loki pagination pages do not account for every retained entry');
}

/** Validate the successful teardown barrier and complete Loki result. */
export function validateA8Teardown(manifest, loki, teardownRoot, qualifiedTree) {
  qualifiedTreeBound(manifest, qualifiedTree, 'teardown manifest wrapper');
  const value = manifest.manifest;
  if (value?.schemaVersion !== 'stacks-attacknet-teardown-evidence/v1'
    || value.deletionComplete !== true || !value.run || !value.network || !value.networkUID
    || !/^sha256:[0-9a-f]{64}$/.test(value.inventoryDigest ?? '')
    || !Number.isFinite(Date.parse(value.start ?? ''))
    || !Number.isFinite(Date.parse(value.end ?? ''))) {
    fail('successful teardown manifest is incomplete');
  }
  if (loki?.schemaVersion !== 'stacks-attacknet-loki-export/v1' || loki.complete !== true
    || loki.direction !== 'forward' || loki.entryCount < 1 || !loki.logArtifact
    || loki.selector !== `{attacknet_network="${value.network}"}` || loki.partialLogArtifact) {
    fail('successful teardown does not contain a complete non-empty Loki export');
  }
  const {actual} = validateTeardownInventory(teardownRoot);
  const artifactPaths = {
    incident: 'incident/manifest.json', attacknetRun: 'attacknet-run.json',
    lokiSource: 'loki/kubernetes-source.json', lokiMetadata: 'loki/export.json',
    lokiLogs: 'loki/logs.jsonl.gz',
  };
  for (const [key, path] of Object.entries(artifactPaths)) {
    if (!actual.has(path) || value.artifacts?.[key] !== digestFile(actual.get(path))) {
      fail(`teardown manifest does not bind ${key}`);
    }
  }
  const logsPath = actual.get(artifactPaths.lokiLogs);
  const sourcePath = actual.get(artifactPaths.lokiSource);
  validateLokiPagination(loki);
  validateLokiCorpus(loki, logsPath, value.network);
  if (digestFile(actual.get(artifactPaths.lokiMetadata)) !== value.artifacts.lokiMetadata) {
    fail('teardown manifest does not bind the Loki export metadata');
  }
  const source = load(sourcePath, 'Loki Kubernetes source');
  if (!source?.service?.metadata?.uid || !source?.service?.metadata?.name
    || !source?.pod?.metadata?.uid || !source?.pod?.metadata?.name) {
    fail('Loki Kubernetes source identity is incomplete');
  }
  const incident = load(actual.get(artifactPaths.incident), 'incident manifest');
  if (incident?.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || !Array.isArray(incident.artifacts) || incident.errors?.length || incident.omissions?.length) {
    fail('teardown incident evidence is incomplete');
  }
  for (const artifact of incident.artifacts) {
    const path = safeRelative(artifact?.path, 'incident artifact path');
    const file = actual.get(`incident/${path}`);
    if (!file || artifact.sha256 !== digestFile(file)
      || artifact.bytes !== statSync(file).size) {
      fail(`incident manifest does not bind ${path}`);
    }
  }
  return manifest;
}

/** Validate that a failed Loki export preserves the exact network identity. */
export function validateA8TeardownFailure(value, qualifiedTree) {
  qualifiedTreeBound(value, qualifiedTree, 'teardown failure');
  if (value.schemaVersion !== 'stacks-attacknet-a8-teardown-failure/v1'
    || value.commandFailed !== true || value.networkPreserved !== true
    || value.before?.uid !== value.after?.uid || !value.before?.uid
    || value.before?.inventoryDigest !== value.after?.inventoryDigest
    || value.partialExport?.complete !== false || !value.partialExport?.failure) {
    fail('failed Loki export did not preserve the exact network identity');
  }
  return value;
}

/** Validate that all A8-managed resources were removed after final teardown. */
export function validateA8CleanTeardown(value, qualifiedTree) {
  qualifiedTreeBound(value, qualifiedTree, 'clean teardown');
  if (value.schemaVersion !== 'stacks-attacknet-a8-clean-teardown/v1'
    || value.completed !== true
    || Object.values(value.remainingCounts ?? {}).some(count => count !== 0)) {
    fail('A8 final teardown retains managed resources');
  }
  return value;
}

/** Validate the qualified-tree-bound live qualification inventory. */
export function validateA8LiveQualification(value, qualifiedTree, inputDirectory) {
  qualifiedTreeBound(value, qualifiedTree, 'live qualification');
  if (value.schemaVersion !== 'stacks-attacknet-a8-live-qualification/v1'
    || value.outcome !== 'Passed' || value.cluster?.nodes !== 3
    || value.cluster?.architecture !== 'arm64' || value.cluster?.provider !== 'kind') {
    fail('A8 live qualification does not prove the supported three-node profile');
  }
  const runtime = value.candidateRuntime;
  const inventory = value.artifacts ?? {};
  const buildArtifact = inventory.candidateBuild;
  if (!buildArtifact || safeRelative(buildArtifact.path, 'candidateBuild.path') !== A8_ARTIFACTS.candidateBuild
    || digestFile(resolve(inputDirectory, buildArtifact.path)) !== buildArtifact.digest) {
    fail('A8 live qualification does not bind the candidate build receipt');
  }
  const buildReceipt = load(resolve(inputDirectory, buildArtifact.path), 'candidate build receipt');
  validateCandidateBuildReceipt(buildReceipt, qualifiedTree);
  validateCandidateRuntime(runtime, buildReceipt);
  validateA8LokiIngressControl(value.lokiIngressControl);
  for (const [key, path] of Object.entries(A8_ARTIFACTS)) {
    if (key === 'candidateDiff' || key === 'verification' || key === 'attacknetCheck'
      || key === 'hacknetCheck' || key === 'liveQualification') continue;
    const artifact = inventory[key];
    if (!artifact || safeRelative(artifact.path, `${key}.path`) !== path
      || digestFile(resolve(inputDirectory, artifact.path)) !== artifact.digest) {
      fail(`A8 live qualification does not bind ${key}`);
    }
  }
  const baseline = load(resolve(inputDirectory, inventory.baselineRun.path), 'baseline run');
  const violation = load(resolve(inputDirectory, inventory.violationRun.path), 'violation run');
  const sourceLoss = load(resolve(inputDirectory, inventory.sourceLossRun.path), 'source-loss run');
  const stacksTrigger = load(resolve(inputDirectory, inventory.stacksTriggerRun.path), 'Stacks-trigger run');
  const teardown = load(resolve(inputDirectory, inventory.teardownManifest.path), 'teardown manifest');
  const loki = load(resolve(inputDirectory, inventory.lokiMetadata.path), 'Loki metadata');
  const teardownFailure = load(resolve(inputDirectory, inventory.teardownFailure.path), 'teardown failure');
  const cleanTeardown = load(resolve(inputDirectory, inventory.cleanTeardown.path), 'clean teardown');
  const sourceLossResource = resourceSnapshot(sourceLoss, qualifiedTree, 'source-loss run');
  validateA8SourceLossControl(value.sourceLossControl, sourceLossResource);
  validateA8BaselineRun(baseline, qualifiedTree);
  validateA8ViolationRun(violation, qualifiedTree);
  validateA8SourceLossRun(sourceLoss, qualifiedTree);
  validateA8StacksTriggerRun(stacksTrigger, qualifiedTree);
  validateA8Teardown(teardown, loki, resolve(inputDirectory, 'teardown-success'), qualifiedTree);
  validateA8TeardownFailure(teardownFailure, qualifiedTree);
  validateA8CleanTeardown(cleanTeardown, qualifiedTree);
  return value;
}

function validateCandidateRuntime(runtime, buildReceipt) {
  if (runtime?.schemaVersion !== 'stacks-attacknet-a8-candidate-runtime/v1'
    || !Number.isFinite(Date.parse(runtime.capturedAt ?? ''))
    || JSON.stringify(runtime.builtButNotRunning) !== JSON.stringify(['io-pressure'])) {
    fail('A8 live qualification has an invalid candidate runtime inventory');
  }
  const expectedBuilds = new Map(buildReceipt.build.images.map(image => [image.purpose, image.id]));
  const expectedRuntime = candidateRuntimeImageIDs(buildReceipt, buildReceipt.qualifiedTree);
  const expectedCounts = new Map([
    ['topology-operator', 1], ['run-operator', 1], ['burnchain-clock', 1],
    ['probe', 3], ['stacks-core', 2],
  ]);
  const counts = new Map();
  const identities = new Set();
  const probePods = new Set();
  const stacksPods = new Set();
  for (const container of runtime.containers ?? []) {
    const expected = expectedRuntime.get(container.purpose);
    const identity = `${container.podUID}\0${container.container}`;
    if (!expectedCounts.has(container.purpose) || identities.has(identity)
      || !container.pod || !container.podUID || !container.requestedImage
      || container.runtimeImageID !== expected || container.expectedRuntimeImageID !== expected) {
      fail('A8 live qualification contains an unknown, duplicate, or mismatched candidate runtime');
    }
    if ((container.purpose === 'topology-operator' || container.purpose === 'run-operator')
      && container.buildIndex !== expectedBuilds.get(container.purpose)) {
      fail('A8 live qualification controller build annotation is inconsistent');
    }
    identities.add(identity);
    counts.set(container.purpose, (counts.get(container.purpose) ?? 0) + 1);
    if (container.purpose === 'probe') probePods.add(container.podUID);
    if (container.purpose === 'stacks-core') stacksPods.add(container.podUID);
  }
  for (const [purpose, count] of expectedCounts) {
    if (counts.get(purpose) !== count) fail(`A8 live qualification does not prove every ${purpose} runtime`);
  }
  if ([...stacksPods].some(podUID => !probePods.has(podUID))) {
    fail('A8 live qualification does not bind Stacks actors to their probe sidecars');
  }
}

function archiveIndex(qualifiedTree, root) {
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
  return {schema: A8_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
}

function copyEvidenceTree(source, target) {
  mkdirSync(target, {recursive: true});
  for (const entry of readdirSync(source, {withFileTypes: true})) {
    const from = join(source, entry.name);
    const to = join(target, entry.name);
    if (entry.isDirectory()) copyEvidenceTree(from, to);
    else if (entry.isFile()) copyFileSync(from, to);
    else fail(`unsupported evidence entry ${from}`);
  }
}

function validateAttacknetResult(value, qualifiedTree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== qualifiedTree || value.status !== 'passed') {
    fail('Attacknet check is not a passed qualified-tree result');
  }
}

function validateHacknetResult(value, qualifiedTree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== qualifiedTree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A8 requires a passed Hacknet ${required} check`);
    }
  }
}

/** Assemble the portable A8 archive after offline and live qualification. */
export function assembleA8Evidence({qualifiedTree, inputDirectory, outputDirectory, archiveLocation, root = repositoryRoot}) {
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree ?? '')) fail('qualifiedTree must be a full Git tree SHA');
  if (!archiveLocation) fail('archiveLocation is required');
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  if (output === root || !portablePath(root, output)) fail('outputDirectory must be inside the repository');
  const values = {
    verification: load(join(input, A8_ARTIFACTS.verification), 'verification'),
    attacknetCheck: load(join(input, A8_ARTIFACTS.attacknetCheck), 'Attacknet check'),
    hacknetCheck: load(join(input, A8_ARTIFACTS.hacknetCheck), 'Hacknet check'),
    liveQualification: load(join(input, A8_ARTIFACTS.liveQualification), 'live qualification'),
  };
  validateA8Verification(values.verification, qualifiedTree);
  if (values.verification.checks.length !== A8_CHECK_IDS.length) fail('A8 verification check count changed');
  validateAttacknetResult(values.attacknetCheck, qualifiedTree);
  validateHacknetResult(values.hacknetCheck, qualifiedTree);
  validateA8LiveQualification(values.liveQualification, qualifiedTree, input);

  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'artifacts'), {recursive: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  copyEvidenceTree(
    join(input, 'teardown-success'),
    join(output, 'artifacts', 'teardown-success'),
  );
  const artifacts = {};
  for (const [key, path] of Object.entries(A8_ARTIFACTS)) {
    const source = join(input, path);
    const archiveEntry = `artifacts/${path}`;
    const target = join(output, archiveEntry);
    mkdirSync(dirname(target), {recursive: true});
    copyFileSync(source, target);
    artifacts[key] = {path: portablePath(root, target), archiveEntry, digest: digestFile(target)};
  }
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(qualifiedTree, output), null, 2)}\n`);
  const archiveName = `release-1-a8-evidence-${qualifiedTree.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts'], {
    env: {...process.env, COPYFILE_DISABLE: '1'},
  });
  const summary = {
    schema: A8_SUMMARY_SCHEMA,
    qualifiedTree,
    archive: {
      path: portablePath(root, archivePath), digest: digestFile(archivePath),
      indexPath: portablePath(root, indexPath), indexDigest: digestFile(indexPath),
      indexEntry: 'archive-index.json', location: archiveLocation,
    },
    artifacts,
    assertions: A8_ASSERTIONS.map(id => ({id, status: 'passed'})),
  };
  writeFileSync(join(output, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--qualified-tree=', '--input=', '--output=', '--archive-location='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  const options = {
    qualifiedTree: value('--qualified-tree='), inputDirectory: value('--input='),
    outputDirectory: value('--output='), archiveLocation: value('--archive-location='),
  };
  for (const [name, option] of Object.entries(options)) if (!option) fail(`${name} is required`);
  process.stdout.write(`${JSON.stringify(assembleA8Evidence(options), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
