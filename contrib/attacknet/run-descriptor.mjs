#!/usr/bin/env node

import {createHash, createHmac} from 'node:crypto';
import {readFileSync, renameSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';

export const RUN_DESCRIPTOR_SCHEMA = 'stacks-attacknet-run/v1';

const RUN_STATUSES = new Set(['planned', 'running', 'passed', 'failed', 'aborted']);
const EVENT_TYPES = new Set(['fault-decision', 'cadence-transition', 'assertion-result']);
const FAULT_DECISIONS = new Set(['selected', 'applied', 'reverted', 'skipped', 'rejected']);
const ASSERTION_STATUSES = new Set(['pass', 'fail', 'error', 'skipped']);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, field) {
  if (!isObject(value)) throw new Error(`${field} must be an object`);
  return value;
}

function requireString(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function requireArray(value, field) {
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  return value;
}

function requireEnum(value, allowed, field) {
  if (!allowed.has(value)) throw new Error(`${field} must be one of ${[...allowed].join(', ')}`);
  return value;
}

function normalizedTimestamp(value, field) {
  requireString(value, field);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(`${field} must be an RFC 3339 timestamp`);
  return new Date(timestamp).toISOString();
}

function deepCopy(value) {
  return JSON.parse(JSON.stringify(value));
}

// JSON object keys are sorted recursively. Array order remains significant: it is
// used for the event ledger and replay schedule.
export function canonicalJson(value) {
  const seen = new Set();
  function visit(item) {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new Error('canonical JSON cannot encode a non-finite number');
      return item;
    }
    if (Array.isArray(item)) return item.map(visit);
    if (!isObject(item)) throw new Error(`canonical JSON cannot encode ${typeof item}`);
    if (seen.has(item)) throw new Error('canonical JSON cannot encode a cyclic object');
    seen.add(item);
    const result = {};
    for (const key of Object.keys(item).sort()) {
      if (item[key] === undefined) throw new Error(`canonical JSON cannot encode undefined at ${key}`);
      result[key] = visit(item[key]);
    }
    seen.delete(item);
    return result;
  }
  return JSON.stringify(visit(value));
}

export function sha256Value(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function sha256File(path, readFile = readFileSync) {
  return `sha256:${createHash('sha256').update(readFile(path)).digest('hex')}`;
}

// Stable, namespaced experiment choices.  The ordered choice list and the
// namespace/index are part of the instruction; changing any of them is a new
// experiment even when the run seed is unchanged.
export function seededChoice(seed, namespace, index, choices) {
  requireString(String(seed), 'seed');
  requireString(namespace, 'namespace');
  if (!Number.isSafeInteger(index) || index < 0) throw new Error('index must be a non-negative integer');
  if (!Array.isArray(choices) || choices.length === 0) throw new Error('choices must be a non-empty array');
  choices.forEach((choice, choiceIndex) => requireString(choice, `choices[${choiceIndex}]`));
  const digest = createHmac('sha256', String(seed))
    .update(`stacks-attacknet-choice/v1\0${namespace}\0${index}`)
    .digest();
  const choiceIndex = Number(digest.readBigUInt64BE(0) % BigInt(choices.length));
  return {choice: choices[choiceIndex], choiceIndex, digest: digest.toString('hex')};
}

function descriptorDigest(descriptor) {
  const unsigned = deepCopy(descriptor);
  delete unsigned.integrity;
  return sha256Value(unsigned);
}

function seal(descriptor) {
  const result = deepCopy(descriptor);
  result.integrity = {algorithm: 'sha256', digest: descriptorDigest(result)};
  return result;
}

function artifact(path, readFile) {
  return {path: requireString(path, 'artifact path'), digest: sha256File(path, readFile)};
}

function normalizeImages(images, {allowUnresolved = false} = {}) {
  const normalized = requireArray(images, 'images').map((image, index) => {
    requireObject(image, `images[${index}]`);
    const scope = requireString(image.scope, `images[${index}].scope`);
    const requestedRef = requireString(image.requestedRef, `images[${index}].requestedRef`);
    const resolvedRef = image.resolvedRef;
    const resolvedDigest = image.resolvedDigest;
    if (allowUnresolved && resolvedRef === undefined && resolvedDigest === undefined) {
      return {scope, requestedRef};
    }
    requireString(resolvedRef, `images[${index}].resolvedRef`);
    requireString(resolvedDigest, `images[${index}].resolvedDigest`);
    if (!/^sha256:[0-9a-f]{64}$/.test(resolvedDigest)) {
      throw new Error(`images[${index}].resolvedDigest must be a lowercase sha256 digest`);
    }
    if (!resolvedRef.includes(resolvedDigest)) {
      throw new Error(`images[${index}].resolvedRef must contain its resolvedDigest`);
    }
    return {scope, requestedRef, resolvedRef, resolvedDigest};
  }).sort((left, right) => left.scope.localeCompare(right.scope));
  const scopes = new Set();
  for (const image of normalized) {
    if (scopes.has(image.scope)) throw new Error(`duplicate image scope ${image.scope}`);
    scopes.add(image.scope);
  }
  if (normalized.length === 0) throw new Error('images must contain at least one image');
  return normalized;
}

function normalizeNondeterminism(value) {
  requireObject(value, 'nondeterminism');
  const statement = requireString(value.statement, 'nondeterminism.statement');
  const disclosed = requireArray(value.disclosed, 'nondeterminism.disclosed').map((item, index) => {
    requireObject(item, `nondeterminism.disclosed[${index}]`);
    return {
      source: requireString(item.source, `nondeterminism.disclosed[${index}].source`),
      impact: requireString(item.impact, `nondeterminism.disclosed[${index}].impact`),
      capture: requireString(item.capture, `nondeterminism.disclosed[${index}].capture`),
      bounded: item.bounded === true,
    };
  }).sort((left, right) => left.source.localeCompare(right.source));
  return {statement, disclosed};
}

function normalizeSource(metadata, readFile) {
  const revision = requireString(metadata.sourceRevision, 'sourceRevision');
  if (!/^[0-9a-f]{7,64}$/i.test(revision)) throw new Error('sourceRevision must be a commit hash');
  const dirty = metadata.sourceDirty === true;
  const source = {revision: revision.toLowerCase(), dirty};
  if (dirty) {
    if (!metadata.sourceDiffPath) throw new Error('sourceDiffPath is required when sourceDirty=true');
    source.diff = artifact(metadata.sourceDiffPath, readFile);
  } else if (metadata.sourceDiffPath) {
    throw new Error('sourceDiffPath is only valid when sourceDirty=true');
  }
  return source;
}

export function initializeDescriptor(metadata, options = {}) {
  requireObject(metadata, 'metadata');
  const readFile = options.readFile ?? readFileSync;
  const now = options.now ?? (() => new Date().toISOString());
  const runId = requireString(metadata.runId, 'runId');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(runId)) throw new Error('runId contains unsupported characters');
  const seed = requireString(String(metadata.seed ?? ''), 'seed');
  const seedAlgorithm = requireString(metadata.seedAlgorithm, 'seedAlgorithm');
  const topology = artifact(metadata.topologyPath, readFile);
  const configFiles = requireArray(metadata.configPaths, 'configPaths')
    .map(path => artifact(path, readFile))
    .sort((left, right) => left.path.localeCompare(right.path));
  if (configFiles.length === 0) throw new Error('configPaths must contain at least one rendered configuration');
  const requestedManifestPath = metadata.requestedManifestPath ?? metadata.admittedManifestPath;
  const requestedManifest = artifact(requestedManifestPath, readFile);
  const createdAt = normalizedTimestamp(metadata.createdAt ?? now(), 'createdAt');
  const descriptor = {
    schemaVersion: RUN_DESCRIPTOR_SCHEMA,
    run: {id: runId, status: 'running', createdAt},
    randomness: {seed, algorithm: seedAlgorithm},
    source: normalizeSource(metadata, readFile),
    inputs: {
      topology,
      configuration: {files: configFiles, digest: sha256Value(configFiles)},
      images: normalizeImages(metadata.images, {allowUnresolved: true}),
      kubernetes: {
        requestedManifest,
        ...(metadata.admittedManifestPath
          ? {
              admittedManifest: artifact(metadata.admittedManifestPath, readFile),
              resolution: {complete: true, missingImageScopes: []},
            }
          : {
              resolution: {complete: false, missingImageScopes: metadata.images.map(image => image.scope)},
            }),
      },
    },
    timeline: [],
    nondeterminism: normalizeNondeterminism(metadata.nondeterminism),
  };
  return seal(descriptor);
}

export function resolveRuntimeInputs(descriptor, resolution, options = {}) {
  validateDescriptor(descriptor);
  if (descriptor.run.status !== 'running') throw new Error(`cannot resolve inputs for a ${descriptor.run.status} run`);
  requireObject(resolution, 'resolution');
  const readFile = options.readFile ?? readFileSync;
  const resolvedByScope = new Map(normalizeImages(resolution.images ?? []).map(image => [image.scope, image]));
  const images = descriptor.inputs.images.map(image => {
    const resolved = resolvedByScope.get(image.scope);
    if (!resolved) return deepCopy(image);
    if (resolved.requestedRef !== image.requestedRef) {
      throw new Error(`resolved requestedRef changed for image scope ${image.scope}`);
    }
    return resolved;
  });
  for (const scope of resolvedByScope.keys()) {
    if (!descriptor.inputs.images.some(image => image.scope === scope)) {
      throw new Error(`resolution contains unknown image scope ${scope}`);
    }
  }
  const missingImageScopes = images.filter(image => !image.resolvedDigest).map(image => image.scope);
  const result = deepCopy(descriptor);
  result.inputs.images = images;
  result.inputs.kubernetes.admittedManifest = artifact(resolution.admittedManifestPath, readFile);
  result.inputs.kubernetes.resolution = {complete: missingImageScopes.length === 0, missingImageScopes};
  return seal(result);
}

function normalizeEvent(event, sequence, recordedAt) {
  requireObject(event, 'event');
  const type = requireEnum(event.type, EVENT_TYPES, 'event.type');
  const occurredAt = normalizedTimestamp(event.occurredAt, 'event.occurredAt');
  const payload = deepCopy(requireObject(event.payload, 'event.payload'));
  if (type === 'fault-decision') {
    requireString(payload.campaign, 'event.payload.campaign');
    requireEnum(payload.decision, FAULT_DECISIONS, 'event.payload.decision');
    requireString(payload.faultKind, 'event.payload.faultKind');
    requireArray(payload.targets, 'event.payload.targets');
    payload.targets.forEach((target, index) => requireString(target, `event.payload.targets[${index}]`));
  } else if (type === 'cadence-transition') {
    requireString(payload.policy, 'event.payload.policy');
    requireString(payload.from, 'event.payload.from');
    requireString(payload.to, 'event.payload.to');
    requireString(payload.reason, 'event.payload.reason');
  } else {
    requireString(payload.assertion, 'event.payload.assertion');
    requireEnum(payload.status, ASSERTION_STATUSES, 'event.payload.status');
  }
  return {sequence, type, occurredAt, recordedAt: normalizedTimestamp(recordedAt, 'event.recordedAt'), payload};
}

export function appendEvent(descriptor, event, options = {}) {
  validateDescriptor(descriptor);
  if (descriptor.run.status !== 'running') throw new Error(`cannot append to a ${descriptor.run.status} run`);
  const now = options.now ?? (() => new Date().toISOString());
  const result = deepCopy(descriptor);
  const normalized = normalizeEvent(event, result.timeline.length + 1, event.recordedAt ?? now());
  const previous = result.timeline.at(-1);
  if (previous && Date.parse(normalized.occurredAt) < Date.parse(previous.occurredAt)) {
    throw new Error('event.occurredAt precedes the prior event; append a causally ordered ledger');
  }
  result.timeline.push(normalized);
  return seal(result);
}

function eventCounts(timeline) {
  const counts = {faultDecisions: 0, cadenceTransitions: 0, assertions: {pass: 0, fail: 0, error: 0, skipped: 0}};
  for (const event of timeline) {
    if (event.type === 'fault-decision') counts.faultDecisions += 1;
    if (event.type === 'cadence-transition') counts.cadenceTransitions += 1;
    if (event.type === 'assertion-result') counts.assertions[event.payload.status] += 1;
  }
  return counts;
}

export function finalizeDescriptor(descriptor, status, options = {}) {
  validateDescriptor(descriptor);
  if (descriptor.run.status !== 'running') throw new Error(`cannot finalize a ${descriptor.run.status} run`);
  if (!new Set(['passed', 'failed', 'aborted']).has(status)) throw new Error('final status must be passed, failed, or aborted');
  if (status === 'passed' && descriptor.inputs.kubernetes.resolution.complete !== true) {
    throw new Error('a passed run requires complete admitted-manifest and image resolution');
  }
  const counts = eventCounts(descriptor.timeline);
  const failed = counts.assertions.fail + counts.assertions.error;
  const evaluated = counts.assertions.pass + failed;
  if (status === 'passed' && evaluated === 0) throw new Error('a passed run requires at least one evaluated assertion');
  if (status === 'passed' && failed > 0) throw new Error('a run with failed assertions cannot be finalized as passed');
  if (status === 'failed' && failed === 0) throw new Error('a failed run requires a failed or errored assertion');
  const now = options.now ?? (() => new Date().toISOString());
  const result = deepCopy(descriptor);
  result.run.status = status;
  result.run.finalizedAt = normalizedTimestamp(options.finalizedAt ?? now(), 'finalizedAt');
  result.summary = counts;
  return seal(result);
}

function validateArtifact(value, field) {
  requireObject(value, field);
  requireString(value.path, `${field}.path`);
  if (!/^sha256:[0-9a-f]{64}$/.test(value.digest ?? '')) throw new Error(`${field}.digest must be a sha256 digest`);
}

export function validateDescriptor(descriptor, options = {}) {
  requireObject(descriptor, 'descriptor');
  if (descriptor.schemaVersion !== RUN_DESCRIPTOR_SCHEMA) throw new Error(`unsupported schemaVersion ${descriptor.schemaVersion}`);
  requireObject(descriptor.run, 'run');
  requireString(descriptor.run.id, 'run.id');
  requireEnum(descriptor.run.status, RUN_STATUSES, 'run.status');
  normalizedTimestamp(descriptor.run.createdAt, 'run.createdAt');
  requireObject(descriptor.randomness, 'randomness');
  requireString(descriptor.randomness.seed, 'randomness.seed');
  requireString(descriptor.randomness.algorithm, 'randomness.algorithm');
  requireObject(descriptor.source, 'source');
  requireString(descriptor.source.revision, 'source.revision');
  if (!/^[0-9a-f]{7,64}$/i.test(descriptor.source.revision)) throw new Error('source.revision must be a commit hash');
  if (typeof descriptor.source.dirty !== 'boolean') throw new Error('source.dirty must be boolean');
  if (descriptor.source.dirty) validateArtifact(descriptor.source.diff, 'source.diff');
  if (!descriptor.source.dirty && descriptor.source.diff !== undefined) throw new Error('source.diff requires source.dirty=true');
  requireObject(descriptor.inputs, 'inputs');
  validateArtifact(descriptor.inputs.topology, 'inputs.topology');
  requireObject(descriptor.inputs.configuration, 'inputs.configuration');
  const configFiles = requireArray(descriptor.inputs.configuration.files, 'inputs.configuration.files');
  if (configFiles.length === 0) throw new Error('inputs.configuration.files cannot be empty');
  configFiles.forEach((value, index) => validateArtifact(value, `inputs.configuration.files[${index}]`));
  if (descriptor.inputs.configuration.digest !== sha256Value(configFiles)) throw new Error('configuration aggregate digest mismatch');
  normalizeImages(descriptor.inputs.images, {
    allowUnresolved: descriptor.run.status !== 'passed' && descriptor.run.status !== 'planned',
  });
  requireObject(descriptor.inputs.kubernetes, 'inputs.kubernetes');
  validateArtifact(descriptor.inputs.kubernetes.requestedManifest, 'inputs.kubernetes.requestedManifest');
  requireObject(descriptor.inputs.kubernetes.resolution, 'inputs.kubernetes.resolution');
  if (typeof descriptor.inputs.kubernetes.resolution.complete !== 'boolean') {
    throw new Error('inputs.kubernetes.resolution.complete must be boolean');
  }
  requireArray(
    descriptor.inputs.kubernetes.resolution.missingImageScopes,
    'inputs.kubernetes.resolution.missingImageScopes',
  );
  if (descriptor.inputs.kubernetes.admittedManifest) {
    validateArtifact(descriptor.inputs.kubernetes.admittedManifest, 'inputs.kubernetes.admittedManifest');
  } else if (descriptor.inputs.kubernetes.resolution.complete) {
    throw new Error('complete Kubernetes resolution requires an admitted manifest');
  }
  normalizeNondeterminism(descriptor.nondeterminism);
  const timeline = requireArray(descriptor.timeline, 'timeline');
  let previousTimestamp = -Infinity;
  timeline.forEach((event, index) => {
    if (event.sequence !== index + 1) throw new Error(`timeline sequence must be contiguous at index ${index}`);
    const normalized = normalizeEvent(event, event.sequence, event.recordedAt);
    const timestamp = Date.parse(normalized.occurredAt);
    if (timestamp < previousTimestamp) throw new Error('timeline occurredAt values must be nondecreasing');
    previousTimestamp = timestamp;
  });
  if (descriptor.run.status === 'planned') {
    if (descriptor.inputs.kubernetes.resolution.complete !== true) {
      throw new Error('a replay plan requires completely resolved runtime inputs');
    }
    requireObject(descriptor.replayPlan, 'replayPlan');
    if (descriptor.timeline.length !== 0) throw new Error('a planned replay cannot contain observed timeline events');
    if (descriptor.replayPlan.strategy !== 'failure-prefix/v1') throw new Error('unsupported replayPlan.strategy');
    requireObject(descriptor.replayPlan.derivedFrom, 'replayPlan.derivedFrom');
    requireString(descriptor.replayPlan.derivedFrom.runId, 'replayPlan.derivedFrom.runId');
    if (!/^sha256:[0-9a-f]{64}$/.test(descriptor.replayPlan.derivedFrom.descriptorDigest ?? '')) {
      throw new Error('replayPlan.derivedFrom.descriptorDigest must be a sha256 digest');
    }
    let priorOffset = -1;
    requireArray(descriptor.replayPlan.schedule, 'replayPlan.schedule').forEach((action, index) => {
      requireObject(action, `replayPlan.schedule[${index}]`);
      if (!Number.isInteger(action.order) || action.order < 1) throw new Error(`replayPlan.schedule[${index}].order must be a positive integer`);
      if (!Number.isInteger(action.offsetMs) || action.offsetMs < 0 || action.offsetMs < priorOffset) {
        throw new Error(`replayPlan.schedule[${index}].offsetMs must be a nondecreasing non-negative integer`);
      }
      priorOffset = action.offsetMs;
      if (!new Set(['fault-decision', 'cadence-transition']).has(action.type)) {
        throw new Error(`replayPlan.schedule[${index}].type is not replayable`);
      }
      normalizeEvent({type: action.type, occurredAt: action.originalOccurredAt, payload: action.payload}, action.order, action.originalOccurredAt);
    });
    requireObject(descriptor.replayPlan.expectedFailure, 'replayPlan.expectedFailure');
    requireString(descriptor.replayPlan.expectedFailure.assertion, 'replayPlan.expectedFailure.assertion');
    if (!new Set(['fail', 'error']).has(descriptor.replayPlan.expectedFailure.status)) {
      throw new Error('replayPlan.expectedFailure.status must be fail or error');
    }
    if (!Number.isInteger(descriptor.replayPlan.expectedFailure.originalSequence)
      || descriptor.replayPlan.expectedFailure.originalSequence < 1) {
      throw new Error('replayPlan.expectedFailure.originalSequence must be a positive integer');
    }
    requireString(descriptor.replayPlan.disclosure, 'replayPlan.disclosure');
  }
  if (new Set(['passed', 'failed', 'aborted']).has(descriptor.run.status)) {
    normalizedTimestamp(descriptor.run.finalizedAt, 'run.finalizedAt');
    const counts = eventCounts(timeline);
    if (canonicalJson(descriptor.summary) !== canonicalJson(counts)) throw new Error('summary does not match timeline');
    const failed = counts.assertions.fail + counts.assertions.error;
    const evaluated = counts.assertions.pass + failed;
    if (descriptor.run.status === 'passed' && (failed > 0 || evaluated === 0)) {
      throw new Error('passed run status contradicts assertion results');
    }
    if (descriptor.run.status === 'failed' && failed === 0) throw new Error('failed run status requires a failed assertion');
  }
  requireObject(descriptor.integrity, 'integrity');
  if (descriptor.integrity.algorithm !== 'sha256') throw new Error('unsupported integrity algorithm');
  if (descriptor.integrity.digest !== descriptorDigest(descriptor)) throw new Error('descriptor integrity mismatch');
  if (options.verifyFiles === true) {
    const readFile = options.readFile ?? readFileSync;
    const artifacts = [descriptor.inputs.topology, ...configFiles, descriptor.inputs.kubernetes.requestedManifest];
    if (descriptor.inputs.kubernetes.admittedManifest) {
      artifacts.push(descriptor.inputs.kubernetes.admittedManifest);
    }
    if (descriptor.source.diff) artifacts.push(descriptor.source.diff);
    for (const item of artifacts) {
      if (sha256File(item.path, readFile) !== item.digest) throw new Error(`artifact digest mismatch: ${item.path}`);
    }
  }
  return true;
}

export function deriveReplayDescriptor(descriptor, options = {}) {
  validateDescriptor(descriptor);
  const failedAssertions = descriptor.timeline.filter(event =>
    event.type === 'assertion-result' && new Set(['fail', 'error']).has(event.payload.status));
  const target = options.assertion
    ? failedAssertions.find(event => event.payload.assertion === options.assertion)
    : failedAssertions[0];
  if (!target) throw new Error(options.assertion ? `failed assertion not found: ${options.assertion}` : 'no failed assertion to minimize');
  const actions = descriptor.timeline.filter(event =>
    event.sequence < target.sequence && new Set(['fault-decision', 'cadence-transition']).has(event.type));
  const origin = actions.length ? Date.parse(actions[0].occurredAt) : Date.parse(descriptor.run.createdAt);
  const schedule = actions.map(event => ({
    order: event.sequence,
    offsetMs: Date.parse(event.occurredAt) - origin,
    type: event.type,
    payload: deepCopy(event.payload),
    originalOccurredAt: event.occurredAt,
  }));
  const replay = {
    schemaVersion: RUN_DESCRIPTOR_SCHEMA,
    run: {id: `${descriptor.run.id}-replay-${target.sequence}`, status: 'planned', createdAt: descriptor.run.createdAt},
    randomness: deepCopy(descriptor.randomness),
    source: deepCopy(descriptor.source),
    inputs: deepCopy(descriptor.inputs),
    timeline: [],
    nondeterminism: deepCopy(descriptor.nondeterminism),
    replayPlan: {
      strategy: 'failure-prefix/v1',
      derivedFrom: {runId: descriptor.run.id, descriptorDigest: descriptor.integrity.digest},
      schedule,
      expectedFailure: {assertion: target.payload.assertion, status: target.payload.status, originalSequence: target.sequence},
      disclosure: 'This is a deterministic action-prefix reduction, not proof of causal minimality. Delta-debug subsequent successful reproductions before claiming a minimal cause.',
    },
  };
  return seal(replay);
}

export function readDescriptor(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function writeDescriptor(path, descriptor) {
  validateDescriptor(descriptor);
  const temporary = join(dirname(path), `.${path.split('/').at(-1)}.${process.pid}.tmp`);
  writeFileSync(temporary, `${JSON.stringify(descriptor, null, 2)}\n`, {mode: 0o600});
  renameSync(temporary, path);
}

function option(args, name) {
  const prefix = `--${name}=`;
  return args.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
}

export function runCli(argv) {
  const [command, ...args] = argv;
  if (command === 'init') {
    const [output] = args;
    const metadataPath = option(args, 'metadata');
    if (!output || !metadataPath) throw new Error('usage: run-descriptor.mjs init OUTPUT --metadata=METADATA.json');
    const descriptor = initializeDescriptor(JSON.parse(readFileSync(metadataPath, 'utf8')));
    writeDescriptor(output, descriptor);
    process.stdout.write(`${descriptor.integrity.digest}\n`);
    return;
  }
  if (command === 'append') {
    const [path] = args;
    const eventPath = option(args, 'event');
    if (!path || !eventPath) throw new Error('usage: run-descriptor.mjs append DESCRIPTOR --event=EVENT.json');
    const descriptor = appendEvent(readDescriptor(path), JSON.parse(readFileSync(eventPath, 'utf8')));
    writeDescriptor(path, descriptor);
    process.stdout.write(`${descriptor.timeline.at(-1).sequence}\n`);
    return;
  }
  if (command === 'resolve') {
    const [path] = args;
    const resolutionPath = option(args, 'resolution');
    if (!path || !resolutionPath) {
      throw new Error('usage: run-descriptor.mjs resolve DESCRIPTOR --resolution=RESOLUTION.json');
    }
    const descriptor = resolveRuntimeInputs(
      readDescriptor(path),
      JSON.parse(readFileSync(resolutionPath, 'utf8')),
    );
    writeDescriptor(path, descriptor);
    process.stdout.write(`${descriptor.integrity.digest}\n`);
    return;
  }
  if (command === 'finalize') {
    const [path] = args;
    const status = option(args, 'status');
    const finalizedAt = option(args, 'at');
    if (!path || !status) throw new Error('usage: run-descriptor.mjs finalize DESCRIPTOR --status=passed|failed|aborted [--at=TIMESTAMP]');
    const descriptor = finalizeDescriptor(readDescriptor(path), status, {finalizedAt});
    writeDescriptor(path, descriptor);
    process.stdout.write(`${descriptor.integrity.digest}\n`);
    return;
  }
  if (command === 'validate') {
    const [path] = args;
    if (!path) throw new Error('usage: run-descriptor.mjs validate DESCRIPTOR [--verify-files]');
    validateDescriptor(readDescriptor(path), {verifyFiles: args.includes('--verify-files')});
    process.stdout.write('valid\n');
    return;
  }
  if (command === 'minimize') {
    const [path, output] = args;
    if (!path || !output) throw new Error('usage: run-descriptor.mjs minimize DESCRIPTOR OUTPUT [--assertion=ID]');
    const replay = deriveReplayDescriptor(readDescriptor(path), {assertion: option(args, 'assertion')});
    writeDescriptor(output, replay);
    process.stdout.write(`${replay.integrity.digest}\n`);
    return;
  }
  if (command === 'choose') {
    const [path, namespace, indexText, ...choices] = args;
    if (!path || !namespace || indexText === undefined || choices.length === 0) {
      throw new Error('usage: run-descriptor.mjs choose DESCRIPTOR NAMESPACE INDEX CHOICE...');
    }
    const descriptor = readDescriptor(path);
    validateDescriptor(descriptor);
    process.stdout.write(`${JSON.stringify(seededChoice(descriptor.randomness.seed, namespace, Number(indexText), choices))}\n`);
    return;
  }
  throw new Error('commands: init, resolve, append, finalize, validate, minimize, choose');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`run descriptor: ${error.message}\n`);
    process.exitCode = 1;
  }
}
