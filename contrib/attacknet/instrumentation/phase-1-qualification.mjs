#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {
  copyFileSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, isAbsolute, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {joinImageAdmissionEvidence} from './image-admission-evidence.mjs';
import {canonicalJson, sha256File, sha256Value} from './artifact-digest.mjs';
import {
  attachInstrumentationCapabilities, readDescriptor, writeDescriptor,
} from './run-descriptor.mjs';
import {compileCapabilityManifest, loadInventory} from './capability-manifest.mjs';
import {buildRuntimeMetricEvidence} from './runtime-metric-evidence.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const INVENTORY = join(ROOT, 'inventory-v1.json');
// `mixed` is an actor-level summary only. Exact family provenance in the
// capability manifest remains merged|attacknet-patch|unavailable.
const PROVENANCE = new Set(['merged', 'attacknet-patch', 'mixed', 'unavailable']);
const ROLES = new Set(['miner', 'companion', 'follower', 'signer']);

function fail(message) { throw new Error(message); }
function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`${label} is not valid JSON: ${error.message}`); }
}
function writeAtomic(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
  renameSync(temporary, path);
}
function absoluteInput(path, base) { return isAbsolute(path) ? path : resolve(base, path); }
function artifact(path) { return {path: resolve(path), digest: sha256File(resolve(path))}; }
function bytesDigest(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }

function referencedArtifacts(input, inputPath) {
  const base = dirname(resolve(inputPath));
  return input.profiles.flatMap(profile => [
    profile.patch?.path ? {profile: profile.id, kind: 'patch', ...artifact(absoluteInput(profile.patch.path, base))} : null,
    profile.buildRecordPath ? {profile: profile.id, kind: 'build', ...artifact(absoluteInput(profile.buildRecordPath, base))} : null,
    ...(profile.configSmokeEvidencePaths ?? []).map(path => ({profile: profile.id, kind: 'config-smoke', ...artifact(absoluteInput(path, base))})),
    ...(profile.admissionEvidencePaths ?? []).map(path => ({profile: profile.id, kind: 'admission', ...artifact(absoluteInput(path, base))})),
    ...(profile.runtimeMetricEvidencePaths ?? []).map(path => ({profile: profile.id, kind: 'runtime-metrics', ...artifact(absoluteInput(path, base))})),
  ].filter(Boolean)).sort((left, right) => `${left.profile}:${left.kind}:${left.path}`.localeCompare(`${right.profile}:${right.kind}:${right.path}`));
}

function declarations(manifest) {
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.actors)) {
    fail('rendered manifest must be a v1 Attacknet manifest');
  }
  const result = manifest.actors.map((actor, index) => {
    const name = actor?.service;
    const role = actor?.role;
    const profile = actor?.instrumentation?.profile;
    const provenance = actor?.instrumentation?.provenance;
    if (typeof name !== 'string' || !name) fail(`manifest actor ${index} has no service`);
    if (!PROVENANCE.has(provenance)) fail(`manifest actor ${name} has invalid instrumentation provenance`);
    if (typeof profile !== 'string' || !profile) fail(`manifest actor ${name} has no instrumentation profile`);
    if (typeof actor.requestedImage !== 'string' || !actor.requestedImage) fail(`manifest actor ${name} has no requested image`);
    if (provenance !== 'unavailable' && !ROLES.has(role)) {
      fail(`non-protocol actor ${name} cannot declare ${provenance} instrumentation`);
    }
    return {name, role, profile, provenance, requestedImage: actor.requestedImage};
  });
  if (new Set(result.map(actor => actor.name)).size !== result.length) fail('rendered manifest contains duplicate actors');
  return result;
}

export function qualificationRequired(manifest) {
  return declarations(manifest).some(actor => actor.provenance !== 'unavailable');
}

function assertProfileMatches(manifestActors, compiled) {
  const expected = manifestActors.filter(actor => actor.provenance !== 'unavailable')
    .sort((left, right) => left.name.localeCompare(right.name));
  const observed = [];
  for (const profile of compiled.profiles) {
    for (const actor of profile.actors) {
      const declaration = expected.find(item => item.name === actor.name);
      if (!declaration) fail(`qualification profile ${profile.id} contains undeclared instrumented actor ${actor.name}`);
      if (declaration.profile !== profile.id) fail(`actor ${actor.name} declares profile ${declaration.profile}, not ${profile.id}`);
      if (declaration.role !== actor.role) fail(`actor ${actor.name} role differs between manifest and qualification profile`);
      if (declaration.requestedImage !== profile.requestedImage) fail(`actor ${actor.name} image differs between manifest and qualification profile`);
      const applicable = profile.signals.filter(signal => signal.roles.includes(actor.role));
      const familyProvenances = new Set(applicable.map(signal => signal.provenance));
      const summarizedProvenance = familyProvenances.size === 1 ? [...familyProvenances][0] : 'mixed';
      if (applicable.length === 0 || summarizedProvenance !== declaration.provenance) {
        fail(`actor ${actor.name} declared provenance does not match its applicable profile signals`);
      }
      observed.push(actor.name);
    }
  }
  observed.sort();
  if (canonicalJson(observed) !== canonicalJson(expected.map(actor => actor.name))) {
    const missing = expected.map(actor => actor.name).filter(name => !observed.includes(name));
    fail(`qualification input does not cover declared instrumented actor(s): ${missing.join(', ')}`);
  }
  if (new Set(observed).size !== observed.length) fail('qualification input assigns an actor to multiple profiles');
  return expected;
}

function instrumentationFamilyExpectations(compiled) {
  return compiled.profiles.flatMap(profile => profile.actors.map(actor => ({
    actor: actor.name,
    role: actor.role,
    families: profile.signals
      .filter(signal => signal.roles.includes(actor.role))
      .map(signal => ({id: signal.id, provenance: signal.provenance})),
  }))).sort((left, right) => left.actor.localeCompare(right.actor));
}

export function preflightQualification(manifestPath, inputPath) {
  const absoluteManifest = resolve(manifestPath);
  const absoluteInput = resolve(inputPath);
  const manifest = readJson(absoluteManifest, 'rendered manifest');
  if (!qualificationRequired(manifest)) fail('rendered manifest does not require Phase-1 qualification');
  const input = readJson(absoluteInput, 'instrumentation profile input');
  const compiled = compileCapabilityManifest(input, {baseDirectory: dirname(absoluteInput)});
  const expected = assertProfileMatches(declarations(manifest), compiled);
  const expectedRuntimeGaps = compiled.profiles.flatMap(profile => profile.actors.flatMap(actor => {
    const hasSignals = profile.signals.some(signal => signal.provenance !== 'unavailable' && signal.roles.includes(actor.role));
    return [
      `${profile.id}: no admitted Pod/runtime identity for ${actor.name}`,
      ...(hasSignals ? [`${profile.id}: no runtime metric-presence evidence for ${actor.name}`] : []),
    ];
  })).sort();
  if (canonicalJson(compiled.unresolvedReasons) !== canonicalJson(expectedRuntimeGaps)) {
    fail(`qualification preflight is incomplete: ${compiled.unresolvedReasons.join('; ') || 'unexpected acceptance state'}`);
  }
  const plan = {
    schema: 'stacks-attacknet-phase-1-qualification-plan/v1',
    renderedManifest: artifact(absoluteManifest),
    profileInput: artifact(absoluteInput),
    preliminaryManifestDigest: compiled.manifestDigest,
    referencedArtifacts: referencedArtifacts(input, absoluteInput),
    expectedActors: expected,
    instrumentationFamilyExpectations: instrumentationFamilyExpectations(compiled),
  };
  plan.planDigest = sha256Value(plan);
  return plan;
}

function verifyPlan(plan, manifestPath, inputPath) {
  if (plan?.schema !== 'stacks-attacknet-phase-1-qualification-plan/v1') fail('unsupported qualification plan');
  const unsigned = {...plan}; delete unsigned.planDigest;
  if (plan.planDigest !== sha256Value(unsigned)) fail('qualification plan digest mismatch');
  for (const [label, supplied, expected] of [
    ['rendered manifest', resolve(manifestPath), plan.renderedManifest],
    ['profile input', resolve(inputPath), plan.profileInput],
  ]) {
    if (resolve(expected?.path ?? '') !== supplied || sha256File(supplied) !== expected?.digest) {
      fail(`${label} changed after qualification preflight`);
    }
  }
  for (const item of plan.referencedArtifacts ?? []) {
    if (sha256File(item.path) !== item.digest) fail(`${item.kind} for ${item.profile} changed after qualification preflight`);
  }
}

function copyArtifact(source, target) {
  mkdirSync(dirname(target), {recursive: true});
  copyFileSync(source, target);
  if (sha256File(source) !== sha256File(target)) fail(`qualification artifact copy changed bytes: ${source}`);
  return target;
}

function snapshotInput(input, inputPath, outputDirectory) {
  const base = dirname(resolve(inputPath));
  const snapshot = JSON.parse(JSON.stringify(input));
  for (const profile of snapshot.profiles) {
    const profileDirectory = join(outputDirectory, 'profiles', profile.id);
    if (profile.patch?.path) {
      profile.patch.path = copyArtifact(absoluteInput(profile.patch.path, base), join(profileDirectory, 'instrumentation.patch'));
    }
    if (profile.buildRecordPath) {
      profile.buildRecordPath = copyArtifact(absoluteInput(profile.buildRecordPath, base), join(profileDirectory, 'build-record.json'));
    }
    profile.configSmokeEvidencePaths = (profile.configSmokeEvidencePaths ?? []).map(path => {
      const absolute = absoluteInput(path, base);
      const smoke = readJson(absolute, 'configuration smoke');
      return copyArtifact(absolute, join(profileDirectory, `${smoke.actor}.config-startup-smoke.json`));
    });
    profile.admissionEvidencePaths = [];
    profile.runtimeMetricEvidencePaths = [];
  }
  return snapshot;
}

export function finalizeQualification({planPath, manifestPath, inputPath, networkPath, podsPath, descriptorPath, outputDirectory, metricsDirectory}) {
  const plan = readJson(resolve(planPath), 'qualification plan');
  verifyPlan(plan, manifestPath, inputPath);
  const manifest = readJson(resolve(manifestPath), 'rendered manifest');
  const input = readJson(resolve(inputPath), 'instrumentation profile input');
  const preliminary = compileCapabilityManifest(input, {baseDirectory: dirname(resolve(inputPath))});
  if (preliminary.manifestDigest !== plan.preliminaryManifestDigest) fail('preliminary capability manifest changed after qualification preflight');
  assertProfileMatches(declarations(manifest), preliminary);
  const network = readJson(resolve(networkPath), 'admitted StacksNetwork');
  const pods = readJson(resolve(podsPath), 'admitted Pods').items;
  if (!Array.isArray(pods)) fail('admitted Pods input must be a Kubernetes List');
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  copyArtifact(resolve(planPath), join(output, 'qualification-plan.json'));
  copyArtifact(resolve(inputPath), join(output, `qualification-input-${basename(inputPath)}`));
  const inventoryPath = copyArtifact(INVENTORY, join(output, 'inventory-v1.json'));
  const inventory = loadInventory(inventoryPath);
  const qualifiedInput = snapshotInput(input, inputPath, output);
  for (const profile of qualifiedInput.profiles) {
    const buildRecord = readJson(profile.buildRecordPath, 'build record');
    for (const actor of profile.actors) {
      const candidates = pods.filter(pod =>
        pod.metadata?.labels?.['testing.stacks.org/network'] === network.metadata?.name
        && pod.metadata?.labels?.['testing.stacks.org/actor'] === actor.name
        && pod.metadata?.deletionTimestamp === undefined);
      if (candidates.length !== 1) fail(`expected exactly one admitted Pod for ${actor.name}, found ${candidates.length}`);
      const evidence = joinImageAdmissionEvidence({buildRecord, network, pod: candidates[0], actor: actor.name});
      const evidencePath = join(output, 'profiles', profile.id, `${actor.name}.image-admission.json`);
      writeAtomic(evidencePath, evidence);
      profile.admissionEvidencePaths.push(evidencePath);
      const declaredActor = manifest.actors.find(item => item.service === actor.name);
      const admittedActor = network.spec?.actors?.find(item => item.name === actor.name);
      const configKey = admittedActor?.config?.key;
      const admittedConfig = admittedActor?.config?.files?.[configKey];
      const originalProfile = input.profiles.find(item => item.id === profile.id);
      const smokePath = originalProfile.configSmokeEvidencePaths.find(path => {
        const smoke = readJson(absoluteInput(path, dirname(resolve(inputPath))), 'configuration smoke');
        return smoke.actor === actor.name;
      });
      const smoke = readJson(absoluteInput(smokePath, dirname(resolve(inputPath))), 'configuration smoke');
      if (typeof admittedConfig !== 'string' || bytesDigest(admittedConfig) !== smoke.config?.sourceDigest) {
        fail(`configuration smoke does not match admitted config for ${actor.name}`);
      }
      if (declaredActor?.requestedImage !== profile.requestedImage) fail(`rendered image changed for ${actor.name}`);
      if (!metricsDirectory) fail('metricsDirectory is required for acceptance qualification');
      const metricsPath = join(resolve(metricsDirectory), `${actor.name}.prom`);
      const metrics = readFileSync(metricsPath, 'utf8');
      const preliminaryProfile = preliminary.profiles.find(item => item.id === profile.id);
      const requiredFamilies = preliminaryProfile.signals
        .filter(signal => signal.provenance !== 'unavailable' && signal.roles.includes(actor.role))
        .map(signal => signal.family);
      if (requiredFamilies.length > 0) {
        const retainedMetricsPath = copyArtifact(metricsPath, join(output, 'profiles', profile.id, `${actor.name}.metrics.prom`));
        const runtimeEvidence = buildRuntimeMetricEvidence({
          profileId: profile.id, requestedImage: profile.requestedImage, actor: actor.name, role: actor.role,
          podUID: evidence.admission.podUID, runtimeImageID: evidence.admission.runtimeDigest,
          inventory, inventoryDigest: sha256File(inventoryPath), requiredFamilies, metrics,
          metricsArtifact: artifact(retainedMetricsPath),
        });
        const runtimePath = join(output, 'profiles', profile.id, `${actor.name}.runtime-metrics.json`);
        writeAtomic(runtimePath, runtimeEvidence);
        profile.runtimeMetricEvidencePaths.push(runtimePath);
      }
    }
  }
  const qualifiedInputPath = join(output, 'qualified-capability-input.json');
  writeAtomic(qualifiedInputPath, qualifiedInput);
  const capabilities = compileCapabilityManifest(qualifiedInput, {
    baseDirectory: output, acceptance: true, inventoryPath,
  });
  assertProfileMatches(declarations(manifest), capabilities);
  const capabilitiesPath = join(output, 'instrumentation-capabilities.json');
  writeAtomic(capabilitiesPath, capabilities);
  const descriptor = attachInstrumentationCapabilities(readDescriptor(resolve(descriptorPath)), capabilitiesPath);
  writeDescriptor(resolve(descriptorPath), descriptor);
  return {capabilitiesPath, manifestDigest: capabilities.manifestDigest, acceptanceReady: true};
}

function option(args, name) { return args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3); }
function main(args) {
  const [command, ...rest] = args;
  if (command === 'required') {
    if (!rest[0]) fail('usage: phase-1-qualification.mjs required MANIFEST');
    process.stdout.write(`${qualificationRequired(readJson(resolve(rest[0]), 'rendered manifest')) ? 'required' : 'unavailable'}\n`);
    return;
  }
  if (command === 'preflight') {
    const [manifestPath, inputPath] = rest.filter(arg => !arg.startsWith('--'));
    const output = option(rest, 'output');
    if (!manifestPath || !inputPath || !output) fail('usage: phase-1-qualification.mjs preflight MANIFEST INPUT --output=PLAN');
    writeAtomic(resolve(output), preflightQualification(manifestPath, inputPath));
    return;
  }
  if (command === 'finalize') {
    const paths = rest.filter(arg => !arg.startsWith('--'));
    const outputDirectory = option(rest, 'output-directory');
    const metricsDirectory = option(rest, 'metrics-directory');
    if (paths.length !== 6 || !outputDirectory || !metricsDirectory) fail('usage: phase-1-qualification.mjs finalize PLAN MANIFEST INPUT NETWORK PODS DESCRIPTOR --output-directory=DIR --metrics-directory=DIR');
    process.stdout.write(`${JSON.stringify(finalizeQualification({
      planPath: paths[0], manifestPath: paths[1], inputPath: paths[2], networkPath: paths[3],
      podsPath: paths[4], descriptorPath: paths[5], outputDirectory, metricsDirectory,
    }))}\n`);
    return;
  }
  fail('commands: required, preflight, finalize');
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) {
    console.error(`Phase-1 instrumentation qualification: ${error.message}`);
    process.exitCode = 1;
  }
}
