#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, isAbsolute, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const INVENTORY_PATH = resolve(ROOT, 'inventory-v1.json');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REVISION = /^[0-9a-f]{40}$/;
const ID = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const ACTOR = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PROVENANCE = new Set(['merged', 'attacknet-patch', 'unavailable']);
const ROLE = new Set(['miner', 'companion', 'follower', 'signer']);

function fail(message) { throw new Error(message); }
function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${path} must be an object`);
  return value;
}
function string(value, path) {
  if (typeof value !== 'string' || value.length === 0) fail(`${path} must be a non-empty string`);
  return value;
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestValue(value) { return digestBytes(JSON.stringify(canonical(value))); }
function patchSourceStateDigest(revision, bytes) {
  const hash = createHash('sha256');
  hash.update('stacks-attacknet-source-state-v1\0');
  hash.update(revision);
  hash.update('\0patch\0');
  hash.update(bytes);
  return `sha256:${hash.digest('hex')}`;
}
function artifact(path) {
  const absolute = resolve(path);
  return {path: absolute, digest: digestBytes(readFileSync(absolute))};
}
function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`${label} is not valid JSON: ${error.message}`); }
}
function resolveInputPath(path, baseDirectory) {
  return isAbsolute(path) ? path : resolve(baseDirectory, path);
}
function verifySeal(value, digestField, label) {
  const claimed = value?.[digestField];
  if (!DIGEST.test(claimed ?? '')) fail(`${label}.${digestField} is missing or invalid`);
  const unsigned = {...value};
  delete unsigned[digestField];
  if (digestValue(unsigned) !== claimed) fail(`${label}.${digestField} does not verify`);
}

export function loadInventory(path = INVENTORY_PATH) {
  const inventory = readJson(path, 'inventory');
  if (inventory.schema !== 'stacks-attacknet-instrumentation-inventory/v1') fail('unsupported inventory schema');
  if (!Array.isArray(inventory.families) || inventory.families.length !== 22) fail('inventory must contain exactly 22 families');
  const ids = new Set();
  const names = new Set();
  for (const [index, family] of inventory.families.entries()) {
    object(family, `families[${index}]`);
    if (!/^M(?:0[1-9]|1[0-9]|2[0-2])$/.test(family.id ?? '')) fail(`families[${index}].id is invalid`);
    if (ids.has(family.id)) fail(`duplicate family id ${family.id}`);
    ids.add(family.id);
    if (!/^stacks_(?:node|signer)_[a-z0-9_]+$/.test(family.family ?? '')) fail(`families[${index}].family is invalid`);
    if (names.has(family.family)) fail(`duplicate family ${family.family}`);
    names.add(family.family);
    if (!['counter', 'gauge', 'histogram'].includes(family.type)) fail(`${family.id}.type is invalid`);
    if (!Array.isArray(family.roles) || family.roles.length === 0 || family.roles.some(role => !ROLE.has(role))) fail(`${family.id}.roles is invalid`);
    if (!Number.isInteger(family.maxSeriesPerProcess) || family.maxSeriesPerProcess < 1 || family.maxSeriesPerProcess > 512) fail(`${family.id}.maxSeriesPerProcess is invalid`);
    for (const forbidden of inventory.forbiddenLabels ?? []) {
      if (Object.keys(family.labels ?? {}).includes(forbidden)) fail(`${family.id} uses forbidden label ${forbidden}`);
    }
  }
  return inventory;
}

function normalizeActors(value, path) {
  if (!Array.isArray(value) || value.length === 0) fail(`${path} must be a non-empty array`);
  const actors = value.map((item, index) => {
    object(item, `${path}[${index}]`);
    if (!ACTOR.test(item.name ?? '')) fail(`${path}[${index}].name is invalid`);
    if (!ROLE.has(item.role)) fail(`${path}[${index}].role is invalid`);
    return {name: item.name, role: item.role};
  });
  if (new Set(actors.map(actor => actor.name)).size !== actors.length) fail(`${path} contains duplicate actors`);
  return actors.sort((left, right) => left.name.localeCompare(right.name));
}

function normalizeSignalProvenance(profile, inventory, path) {
  const defaultProvenance = profile.defaultProvenance;
  if (defaultProvenance !== undefined && !PROVENANCE.has(defaultProvenance)) fail(`${path}.defaultProvenance is invalid`);
  const supplied = object(profile.signals ?? {}, `${path}.signals`);
  for (const id of Object.keys(supplied)) {
    if (!inventory.families.some(family => family.id === id)) fail(`${path}.signals contains unknown family ${id}`);
    if (!PROVENANCE.has(supplied[id])) fail(`${path}.signals.${id} is invalid`);
  }
  const signals = inventory.families.map(family => {
    let provenance = supplied[family.id] ?? defaultProvenance;
    if (family.requiredProvenance && provenance === 'attacknet-patch') provenance = family.requiredProvenance;
    if (!PROVENANCE.has(provenance)) fail(`${path}.signals.${family.id} is required`);
    if (family.requiredProvenance && !['unavailable', family.requiredProvenance].includes(provenance)) {
      fail(`${path}.signals.${family.id} must use ${family.requiredProvenance} or unavailable provenance`);
    }
    return {id: family.id, family: family.family, roles: family.roles, provenance};
  });
  return signals;
}

function normalizeBuild(path, baseDirectory) {
  const absolute = resolveInputPath(path, baseDirectory);
  const record = readJson(absolute, 'build record');
  if (record.schema !== 'stacks-attacknet-image-build-record/v1') fail('unsupported build record schema');
  verifySeal(record, 'recordDigest', 'build record');
  if (!REVISION.test(record.source?.revision ?? '')) fail('build record source revision is invalid');
  if (!DIGEST.test(record.source?.sourceStateDigest ?? '')) fail('build record sourceStateDigest is invalid');
  if (!Array.isArray(record.source?.untrackedFiles ?? [])) fail('build record source.untrackedFiles is invalid');
  if (!DIGEST.test(record.imageDigest ?? '') || record.imageIdentity?.imageIndexDigest !== record.imageDigest) fail('build record image index identity is inconsistent');
  if (!DIGEST.test(record.imageIdentity?.expectedRuntimeImageID ?? '') || record.imageIdentity.expectedRuntimeImageID !== record.imageIdentity.runtimeConfigDigest) fail('build record runtime identity is inconsistent');
  return {
    artifact: artifact(absolute),
    recordDigest: record.recordDigest,
    profileId: record.profileId,
    sourceRevision: record.source.revision,
    sourceStateDigest: record.source.sourceStateDigest,
    sourceKind: record.source.kind,
    sourceDirty: record.source.dirty,
    untrackedFiles: record.source.untrackedFiles ?? [],
    buildInvocationDigest: record.buildInvocation?.digest,
    stagedContextDigest: record.stagedContextDigest,
    imageIndexDigest: record.imageDigest,
    platformManifestDigest: record.imageIdentity.platformManifestDigest,
    runtimeConfigDigest: record.imageIdentity.runtimeConfigDigest,
    expectedRuntimeImageID: record.imageIdentity.expectedRuntimeImageID,
    immutableRef: record.immutableRef,
    localRef: record.localRef,
    instrumentationSourceAudit: record.instrumentationSourceAudit ?? null,
  };
}

function normalizeAdmission(path, baseDirectory, build) {
  const absolute = resolveInputPath(path, baseDirectory);
  const evidence = readJson(absolute, 'admission evidence');
  if (evidence.schema !== 'stacks-attacknet-image-admission-evidence/v1' || evidence.result !== 'Passed') fail('admission evidence is not a passing v1 record');
  verifySeal(evidence, 'evidenceDigest', 'admission evidence');
  if (evidence.build?.recordDigest !== build.recordDigest) fail('admission evidence does not reference the profile build record');
  if (evidence.build?.runtimeConfigDigest !== build.expectedRuntimeImageID) fail('admission build runtime identity mismatch');
  if (!string(evidence.admission?.podUID, 'admission.podUID')) fail('admission pod UID missing');
  if (evidence.admission?.runtimeDigest !== build.expectedRuntimeImageID) fail('admission runtime image ID does not match build identity');
  return {
    artifact: artifact(absolute), actor: evidence.admission.actor, network: evidence.admission.network,
    networkUID: evidence.admission.networkUID, pod: evidence.admission.pod, podUID: evidence.admission.podUID,
    runtimeImageID: evidence.admission.runtimeDigest,
  };
}

function normalizeSmoke(path, baseDirectory, profileId, requestedImage) {
  const absolute = resolveInputPath(path, baseDirectory);
  const smoke = readJson(absolute, 'configuration smoke');
  if (smoke.schema !== 'stacks-attacknet-config-startup-smoke/v1') fail('unsupported configuration smoke schema');
  verifySeal(smoke, 'evidenceDigest', 'configuration smoke');
  if (smoke.result !== 'Passed') fail(`configuration smoke ${absolute} did not pass`);
  if (smoke.profileId !== profileId || smoke.requestedImage !== requestedImage) fail('configuration smoke profile/image mismatch');
  if (!ACTOR.test(smoke.actor ?? '')) fail('configuration smoke actor is invalid');
  if (!ROLE.has(smoke.role)) fail('configuration smoke role is invalid');
  if (!DIGEST.test(smoke.config?.sourceDigest ?? '') || !DIGEST.test(smoke.config?.parserInputDigest ?? '')) fail('configuration smoke config digests are invalid');
  return {
    artifact: artifact(absolute), actor: smoke.actor, role: smoke.role, binary: smoke.binary, command: smoke.command,
    sourceConfigDigest: smoke.config.sourceDigest, parserInputDigest: smoke.config.parserInputDigest,
  };
}

function normalizeRuntimeMetrics(path, baseDirectory, profileId, requestedImage, inventoryDigest) {
  const absolute = resolveInputPath(path, baseDirectory);
  const evidence = readJson(absolute, 'runtime metric evidence');
  if (evidence.schema !== 'stacks-attacknet-runtime-metric-presence/v1') fail('unsupported runtime metric evidence schema');
  verifySeal(evidence, 'evidenceDigest', 'runtime metric evidence');
  if (evidence.result !== 'Passed') fail(`runtime metric evidence ${absolute} did not pass`);
  if (evidence.profileId !== profileId || evidence.requestedImage !== requestedImage) fail('runtime metric evidence profile/image mismatch');
  if (evidence.inventoryDigest !== inventoryDigest) fail('runtime metric evidence inventory mismatch');
  const rawMetricsPath = resolveInputPath(evidence.metricsArtifact?.path ?? '', baseDirectory);
  if (evidence.metricsArtifact?.digest !== evidence.metricsDigest || artifact(rawMetricsPath).digest !== evidence.metricsDigest) {
    fail('runtime metric evidence raw artifact digest mismatch');
  }
  if (!Array.isArray(evidence.requiredFamilies) || !Array.isArray(evidence.presentFamilies) || evidence.missingFamilies?.length !== 0) {
    fail('runtime metric evidence is incomplete');
  }
  for (const family of evidence.requiredFamilies) if (!evidence.presentFamilies.includes(family)) fail(`runtime metric evidence omits ${family}`);
  return {
    artifact: artifact(absolute), actor: evidence.actor, role: evidence.role, podUID: evidence.podUID,
    runtimeImageID: evidence.runtimeImageID, metricsDigest: evidence.metricsDigest,
    metricsArtifact: {path: rawMetricsPath, digest: evidence.metricsDigest},
    requiredFamilies: evidence.requiredFamilies, presentFamilies: evidence.presentFamilies,
  };
}

export function compileCapabilityManifest(input, {baseDirectory = process.cwd(), acceptance = false, inventoryPath = INVENTORY_PATH} = {}) {
  object(input, 'manifest');
  if (input.schemaVersion !== 1) fail('schemaVersion must be 1');
  if (!ID.test(input.manifestId ?? '')) fail('manifestId is invalid');
  const inventory = loadInventory(inventoryPath);
  const inventoryDigest = artifact(inventoryPath).digest;
  if (input.inventoryVersion !== inventory.inventoryVersion) fail(`inventoryVersion must be ${inventory.inventoryVersion}`);
  if (!Array.isArray(input.profiles) || input.profiles.length === 0 || input.profiles.length > 32) fail('profiles must contain 1 through 32 entries');
  const unresolved = [];
  const profiles = input.profiles.map((profile, index) => {
    const path = `profiles[${index}]`;
    object(profile, path);
    if (!ID.test(profile.id ?? '')) fail(`${path}.id is invalid`);
    const requestedImage = string(profile.requestedImage, `${path}.requestedImage`);
    const actors = normalizeActors(profile.actors, `${path}.actors`);
    const signals = normalizeSignalProvenance(profile, inventory, path);
    const available = signals.filter(signal => signal.provenance !== 'unavailable');
    const patched = signals.filter(signal => signal.provenance === 'attacknet-patch');
    let patch = null;
    if (patched.length > 0) {
      if (!profile.patch?.path) fail(`${path}.patch.path is required for attacknet-patch signals`);
      const patchPath = resolveInputPath(profile.patch.path, baseDirectory);
      const bytes = readFileSync(patchPath);
      patch = {...artifact(patchPath), upstreamBaseRevision: string(profile.patch.upstreamBaseRevision, `${path}.patch.upstreamBaseRevision`)};
      if (!REVISION.test(patch.upstreamBaseRevision)) fail(`${path}.patch.upstreamBaseRevision must be a 40-character commit`);
      patch.expectedSourceStateDigest = patchSourceStateDigest(patch.upstreamBaseRevision, bytes);
    } else if (profile.patch !== undefined) fail(`${path}.patch is only valid with attacknet-patch signals`);
    const build = profile.buildRecordPath ? normalizeBuild(profile.buildRecordPath, baseDirectory) : null;
    if (available.length > 0 && !build) unresolved.push(`${profile.id}: no sealed image build record for available instrumentation`);
    if (build && ![build.localRef, build.immutableRef].includes(requestedImage)) fail(`${path}.requestedImage is not sealed by the build record`);
    const merged = signals.filter(signal => signal.provenance === 'merged');
    if (merged.length > 0 && build) {
      const audit = build.instrumentationSourceAudit;
      if (audit?.inventoryDigest !== inventoryDigest || audit?.method !== 'exact-source-string-audit/v1'
        || audit?.sourceContextDigest !== build.stagedContextDigest) {
        fail(`${path} merged provenance requires a build-time instrumentation source audit for this inventory`);
      }
      for (const signal of merged) {
        if (!audit.familiesPresent?.includes(signal.id)) fail(`${path} build source audit does not contain merged family ${signal.id}`);
      }
    }
    if (patch && build && build.sourceRevision !== patch.upstreamBaseRevision) fail(`${path} patch base does not match build source revision`);
    if (patch && build && build.sourceStateDigest !== patch.expectedSourceStateDigest) fail(`${path} patch bytes do not match the build source-state digest`);
    if (patch && build && (build.sourceKind !== 'localModified' || build.sourceDirty !== true || build.untrackedFiles.length !== 0)) {
      fail(`${path} carried patch build must be an exact localModified source with no untracked files`);
    }
    if (!build && (profile.admissionEvidencePaths ?? []).length > 0) fail(`${path} admission evidence requires a build record`);
    const admissions = (profile.admissionEvidencePaths ?? []).map(item => normalizeAdmission(item, baseDirectory, build));
    const admittedActors = new Set(admissions.map(item => item.actor));
    for (const actor of actors) if (build && !admittedActors.has(actor.name)) unresolved.push(`${profile.id}: no admitted Pod/runtime identity for ${actor.name}`);
    const smokes = (profile.configSmokeEvidencePaths ?? []).map(item => normalizeSmoke(item, baseDirectory, profile.id, requestedImage));
    const roles = new Set(actors.map(actor => actor.role));
    const actorRoles = new Map(actors.map(actor => [actor.name, actor.role]));
    const smokeActors = new Set();
    for (const smoke of smokes) {
      if (!actorRoles.has(smoke.actor)) fail(`${path} configuration smoke references undeclared actor ${smoke.actor}`);
      if (actorRoles.get(smoke.actor) !== smoke.role) fail(`${path} configuration smoke role mismatch for ${smoke.actor}`);
      if (smokeActors.has(smoke.actor)) fail(`${path} contains duplicate configuration smokes for ${smoke.actor}`);
      smokeActors.add(smoke.actor);
    }
    for (const actor of actors) if (!smokeActors.has(actor.name)) unresolved.push(`${profile.id}: no passing configuration-startup smoke for actor ${actor.name} (${actor.role})`);
    const runtimeMetrics = (profile.runtimeMetricEvidencePaths ?? []).map(item =>
      normalizeRuntimeMetrics(item, baseDirectory, profile.id, requestedImage, inventoryDigest));
    const runtimeActors = new Set();
    for (const evidence of runtimeMetrics) {
      if (actorRoles.get(evidence.actor) !== evidence.role) fail(`${path} runtime metric evidence actor/role mismatch for ${evidence.actor}`);
      const admission = admissions.find(item => item.actor === evidence.actor);
      if (!admission || admission.podUID !== evidence.podUID || admission.runtimeImageID !== evidence.runtimeImageID) {
        fail(`${path} runtime metric evidence is not bound to the admitted Pod for ${evidence.actor}`);
      }
      if (runtimeActors.has(evidence.actor)) fail(`${path} contains duplicate runtime metric evidence for ${evidence.actor}`);
      runtimeActors.add(evidence.actor);
    }
    for (const actor of actors) {
      const required = signals.filter(signal => signal.provenance !== 'unavailable' && signal.roles.includes(actor.role));
      if (required.length > 0 && !runtimeActors.has(actor.name)) unresolved.push(`${profile.id}: no runtime metric-presence evidence for ${actor.name}`);
    }
    const applicableAvailable = signals.filter(signal => signal.provenance !== 'unavailable' && signal.roles.some(role => roles.has(role)));
    const result = {
      id: profile.id, requestedImage, actors, signals, patch, build, admissions,
      configStartupSmokes: smokes, runtimeMetricPresence: runtimeMetrics,
      capability: {
        status: applicableAvailable.length === 0 ? 'unavailable' : applicableAvailable.length === inventory.families.filter(f => f.roles.some(role => roles.has(role))).length ? 'complete' : 'partial',
        availableSignalCount: applicableAvailable.length,
        unavailableSignalCount: signals.filter(signal => signal.provenance === 'unavailable' && signal.roles.some(role => roles.has(role))).length,
      },
      effectiveEventDispatchMode: profile.effectiveEventDispatchMode ?? 'unknown',
    };
    if (!['blocking', 'queued', 'mixed', 'unknown'].includes(result.effectiveEventDispatchMode)) fail(`${path}.effectiveEventDispatchMode is invalid`);
    return result;
  });
  if (new Set(profiles.map(profile => profile.id)).size !== profiles.length) fail('profile IDs must be unique');
  const manifest = {
    schema: 'stacks-attacknet-instrumentation-capabilities/v1', manifestId: input.manifestId,
    inventory: {...artifact(inventoryPath), schema: inventory.schema, version: inventory.inventoryVersion, familyCount: 22},
    acceptanceRequested: acceptance, acceptanceReady: unresolved.length === 0, unresolvedReasons: [...new Set(unresolved)].sort(),
    profiles,
    interpretation: {
      missingSeries: 'No data. Consult this manifest: the signal may be unavailable, not applicable to the actor role, or unexpectedly absent.',
      trust: 'Metric values are actor-self-reported; build, admission, Pod UID, and runtime image identity are orchestrator-observed evidence.',
      sourceAudit: 'familiesPresent is an integrity-bound producer assertion, not independently derived by this compiler; per-actor runtime metric-presence evidence is mandatory and authoritative for acceptance.',
      percentileWarning: 'Aggregate histogram percentiles cannot be subtracted to derive a percentile distribution of per-proposal differences.',
    },
  };
  if (acceptance && !manifest.acceptanceReady) fail(`manifest is not acceptance-ready: ${manifest.unresolvedReasons[0]}`);
  manifest.manifestDigest = digestValue(manifest);
  return manifest;
}

function main() {
  const args = process.argv.slice(2);
  const inputPath = args.find(arg => !arg.startsWith('--'));
  if (!inputPath) fail('usage: capability-manifest.mjs INPUT.json [--acceptance] [--output=FILE]');
  const absolute = resolve(inputPath);
  const manifest = compileCapabilityManifest(readJson(absolute, 'input'), {baseDirectory: dirname(absolute), acceptance: args.includes('--acceptance')});
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  const output = args.find(arg => arg.startsWith('--output='))?.slice('--output='.length);
  if (output) writeFileSync(resolve(output), serialized); else process.stdout.write(serialized);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(`instrumentation capability manifest: ${error.message}`); process.exitCode = 1; }
}
