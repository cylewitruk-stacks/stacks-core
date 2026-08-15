#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {lstatSync, readFileSync, readlinkSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const DIGEST_REF = /@sha256:([0-9a-f]{64})$/;
const REVISION = /^[0-9a-f]{40}$/;
const ACTOR = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ID = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const PLATFORMS = new Set(['linux/amd64', 'linux/arm64']);
const SOURCE_KINDS = new Set(['current', 'releasedGitRef', 'localModified']);
const PHASE_KINDS = new Set(['baseline', 'rolling-upgrade', 'missed-upgrade', 'modified-actor']);
const EXPECTED_OUTCOMES = new Set(['compatible', 'intentional-failure', 'observe']);
const COMPATIBILITY = new Set(['compatible', 'intentionally-incompatible', 'unknown']);

function fail(message) { throw new Error(message); }
function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${path} must be an object`);
  return value;
}
function string(value, path) {
  if (typeof value !== 'string' || value.length === 0) fail(`${path} must be a non-empty string`);
  return value;
}
function integer(value, path, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) fail(`${path} must be an integer from ${min} through ${max}`);
  return value;
}
function array(value, path) {
  if (!Array.isArray(value)) fail(`${path} must be an array`);
  return value;
}
function exactKeys(value, allowed, path) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${path}.${key} is not supported`);
}
function unique(values, path) {
  if (new Set(values).size !== values.length) fail(`${path} must not contain duplicates`);
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function artifactDigest(value) { return digestBytes(JSON.stringify(canonical(value))); }

function commandGit(repository, args) {
  try {
    return execFileSync('git', ['-C', repository, ...args], {encoding: null, stdio: ['ignore', 'pipe', 'pipe']});
  } catch (error) {
    const detail = error.stderr?.toString().trim();
    fail(`git ${args.join(' ')} failed in ${repository}${detail ? `: ${detail}` : ''}`);
  }
}

function gitText(repository, args) { return commandGit(repository, args).toString('utf8').trim(); }

function repositoryPath(input, baseDirectory) {
  const candidate = isAbsolute(input) ? input : resolve(baseDirectory, input);
  try { return realpathSync(candidate); } catch { fail(`source repository does not exist: ${candidate}`); }
}

function safeRepositoryFile(repository, filename) {
  const candidate = resolve(repository, filename);
  if (candidate !== repository && !candidate.startsWith(`${repository}${sep}`)) fail(`build file escapes repository: ${filename}`);
  return candidate;
}

function gitBlob(repository, revision, filename) {
  const normalized = relative(repository, safeRepositoryFile(repository, filename)).split(sep).join('/');
  return commandGit(repository, ['show', `${revision}:${normalized}`]);
}

function workspaceState(repository, revision) {
  const patch = commandGit(repository, ['diff', '--binary', revision, '--']);
  const staged = commandGit(repository, ['diff', '--binary', '--cached', revision, '--']);
  const untrackedRaw = commandGit(repository, ['ls-files', '--others', '--exclude-standard', '-z']);
  const untracked = untrackedRaw.toString('utf8').split('\0').filter(Boolean).sort();
  const hash = createHash('sha256');
  hash.update('stacks-attacknet-worktree-v1\0');
  hash.update(revision);
  hash.update('\0unstaged-and-head\0');
  hash.update(patch);
  hash.update('\0index-and-head\0');
  hash.update(staged);
  const files = [];
  for (const filename of untracked) {
    const path = safeRepositoryFile(repository, filename);
    const stat = lstatSync(path);
    const contents = stat.isSymbolicLink() ? Buffer.from(readlinkSync(path)) : readFileSync(path);
    const fileDigest = digestBytes(contents);
    files.push({path: filename, mode: stat.mode & 0o777, digest: fileDigest, symlink: stat.isSymbolicLink()});
    hash.update('\0untracked\0');
    hash.update(filename);
    hash.update('\0');
    hash.update(String(stat.mode & 0o777));
    hash.update('\0');
    hash.update(contents);
  }
  const status = commandGit(repository, ['status', '--porcelain=v1', '-z']);
  return {dirty: status.length > 0, digest: `sha256:${hash.digest('hex')}`, untracked: files};
}

function resolveSource(source, baseDirectory) {
  object(source, 'source');
  if (!SOURCE_KINDS.has(source.kind)) fail(`unsupported source.kind ${source.kind}`);
  if (source.kind === 'current') exactKeys(source, ['kind', 'repository'], 'source');
  if (source.kind === 'releasedGitRef') exactKeys(source, ['kind', 'repository', 'gitRef', 'expectedRevision'], 'source');
  if (source.kind === 'localModified') exactKeys(source, ['kind', 'repository', 'baseRef', 'changeId'], 'source');
  const requestedRepository = string(source.repository, 'source.repository');
  const repository = repositoryPath(requestedRepository, baseDirectory);
  let ref = 'HEAD';
  if (source.kind === 'releasedGitRef') ref = string(source.gitRef, 'source.gitRef');
  else if (source.kind === 'localModified') ref = source.baseRef === undefined ? 'HEAD' : string(source.baseRef, 'source.baseRef');
  const revision = gitText(repository, ['rev-parse', '--verify', `${ref}^{commit}`]);
  if (!REVISION.test(revision)) fail(`git resolved ${ref} to an invalid commit ${revision}`);
  if (source.expectedRevision && !REVISION.test(source.expectedRevision)) fail('source.expectedRevision must be a 40-character lowercase commit ID');
  if (source.expectedRevision && source.expectedRevision !== revision) {
    fail(`source.expectedRevision ${source.expectedRevision} does not match ${ref} (${revision})`);
  }
  const resolved = {kind: source.kind, repository: requestedRepository, requestedRef: ref, revision};
  Object.defineProperty(resolved, 'repositoryPath', {value: repository, enumerable: false});
  if (source.kind === 'localModified' || source.kind === 'current') {
    const state = workspaceState(repository, revision);
    resolved.dirty = state.dirty;
    resolved.sourceStateDigest = state.digest;
    resolved.untrackedFiles = state.untracked;
  } else {
    resolved.dirty = false;
    resolved.sourceStateDigest = digestBytes(`git-commit\0${revision}`);
  }
  if (source.kind === 'localModified') resolved.changeId = string(source.changeId, 'source.changeId');
  return resolved;
}

function validateImage(image, targetPlatform, acceptance, unresolved, path) {
  object(image, path);
  exactKeys(image, ['requestedRef', 'origin', 'platforms', 'execution', 'executionPlatform', 'attestationRef', 'attestationDigest'], path);
  const requestedRef = string(image.requestedRef, `${path}.requestedRef`);
  if (!['prebuilt', 'localBuild'].includes(image.origin)) fail(`${path}.origin must be prebuilt or localBuild`);
  const platforms = array(image.platforms, `${path}.platforms`).map((item, index) => {
    if (!PLATFORMS.has(item)) fail(`${path}.platforms[${index}] is unsupported`);
    return item;
  });
  unique(platforms, `${path}.platforms`);
  const execution = image.execution ?? 'native';
  if (!['native', 'emulated'].includes(execution)) fail(`${path}.execution must be native or emulated`);
  const executionPlatform = image.executionPlatform ?? targetPlatform;
  if (!PLATFORMS.has(executionPlatform)) fail(`${path}.executionPlatform is unsupported`);
  if (!platforms.includes(executionPlatform)) fail(`${path} does not provide execution platform ${executionPlatform}`);
  if (execution === 'native' && executionPlatform !== targetPlatform) {
    fail(`${path} native executionPlatform must equal targetPlatform ${targetPlatform}`);
  }
  if (execution === 'emulated' && executionPlatform === targetPlatform) {
    fail(`${path} emulated execution must name a non-target executionPlatform`);
  }
  const match = requestedRef.match(DIGEST_REF);
  if (!match) unresolved.push(`${path}.requestedRef is mutable or unresolved: ${requestedRef}`);
  const resolvedDigest = match ? `sha256:${match[1]}` : null;
  const attestationRef = image.attestationRef ?? null;
  const attestationDigest = image.attestationDigest ?? null;
  if (image.origin === 'prebuilt') {
    if (!attestationRef) unresolved.push(`${path}.attestationRef is unresolved`);
    if (!DIGEST.test(attestationDigest ?? '')) unresolved.push(`${path}.attestationDigest is unresolved`);
  } else if (attestationRef || attestationDigest) {
    fail(`${path} localBuild provenance belongs in the build object`);
  }
  if (acceptance && !resolvedDigest) fail(unresolved.at(-1));
  if (acceptance && image.origin === 'prebuilt' && (!attestationRef || !DIGEST.test(attestationDigest ?? ''))) fail(unresolved.at(-1));
  return {requestedRef, resolvedRef: resolvedDigest ? requestedRef : null, resolvedDigest, origin: image.origin, platforms, execution, executionPlatform, attestationRef, attestationDigest};
}

function validateBuild(build, profilePath, source, acceptance, unresolved) {
  object(build, `${profilePath}.build`);
  exactKeys(build, ['dockerfile', 'cargoProfile', 'cargoChef', 'cargoIncremental', 'builderImage', 'runtimeImage', 'recipeDigest', 'buildInvocationDigest', 'attestationRef', 'attestationDigest'], `${profilePath}.build`);
  if (build.cargoChef !== true) fail(`${profilePath}.build.cargoChef must be true`);
  if (build.cargoIncremental !== false) fail(`${profilePath}.build.cargoIncremental must be false`);
  const dockerfile = string(build.dockerfile, `${profilePath}.build.dockerfile`);
  const dockerfileBytes = source.kind === 'releasedGitRef'
    ? gitBlob(source.repositoryPath, source.revision, dockerfile)
    : readFileSync(safeRepositoryFile(source.repositoryPath, dockerfile));
  const result = {
    dockerfile,
    dockerfileDigest: digestBytes(dockerfileBytes),
    cargoProfile: string(build.cargoProfile, `${profilePath}.build.cargoProfile`),
    cargoChef: true,
    cargoIncremental: false,
    builderImage: string(build.builderImage, `${profilePath}.build.builderImage`),
    runtimeImage: string(build.runtimeImage, `${profilePath}.build.runtimeImage`),
    recipeDigest: build.recipeDigest ?? null,
    buildInvocationDigest: build.buildInvocationDigest ?? null,
    attestationRef: build.attestationRef ?? null,
    attestationDigest: build.attestationDigest ?? null,
  };
  for (const field of ['builderImage', 'runtimeImage']) {
    if (!DIGEST_REF.test(result[field])) unresolved.push(`${profilePath}.build.${field} is not digest-pinned`);
  }
  for (const field of ['recipeDigest', 'buildInvocationDigest', 'attestationDigest']) {
    if (!DIGEST.test(result[field] ?? '')) unresolved.push(`${profilePath}.build.${field} is unresolved`);
  }
  if (!result.attestationRef) unresolved.push(`${profilePath}.build.attestationRef is unresolved`);
  if (acceptance && unresolved.length) fail(unresolved[0]);
  return result;
}

function validateCompatibility(value, path) {
  object(value, path);
  exactKeys(value, ['expectation', 'basis', 'protocolVersions', 'epochs', 'limitations'], path);
  if (!COMPATIBILITY.has(value.expectation)) fail(`${path}.expectation is invalid`);
  const result = {expectation: value.expectation, basis: string(value.basis, `${path}.basis`)};
  if (value.protocolVersions !== undefined) {
    result.protocolVersions = array(value.protocolVersions, `${path}.protocolVersions`);
    unique(result.protocolVersions, `${path}.protocolVersions`);
    result.protocolVersions.forEach((item, index) => integer(item, `${path}.protocolVersions[${index}]`, 0, 65535));
  }
  if (value.epochs !== undefined) {
    result.epochs = array(value.epochs, `${path}.epochs`).map((item, index) => string(item, `${path}.epochs[${index}]`));
    unique(result.epochs, `${path}.epochs`);
  }
  if (value.limitations !== undefined) result.limitations = array(value.limitations, `${path}.limitations`).map((item, index) => string(item, `${path}.limitations[${index}]`));
  return result;
}

export function compileVersionMatrix(input, {baseDirectory = process.cwd(), acceptance = false} = {}) {
  object(input, 'matrix');
  exactKeys(input, ['schemaVersion', 'matrixId', 'targetPlatform', 'bounds', 'actors', 'defaultProfile', 'profiles', 'phases'], 'matrix');
  if (input.schemaVersion !== 1) fail('schemaVersion must be 1');
  if (!ID.test(string(input.matrixId, 'matrixId'))) fail('matrixId is invalid');
  if (!PLATFORMS.has(input.targetPlatform)) fail('targetPlatform must be linux/amd64 or linux/arm64');
  object(input.bounds, 'bounds');
  exactKeys(input.bounds, ['maxProfiles', 'maxActors', 'maxPhases'], 'bounds');
  const bounds = {
    maxProfiles: integer(input.bounds.maxProfiles, 'bounds.maxProfiles', 1, 32),
    maxActors: integer(input.bounds.maxActors, 'bounds.maxActors', 1, 128),
    maxPhases: integer(input.bounds.maxPhases, 'bounds.maxPhases', 1, 32),
  };
  const actors = array(input.actors, 'actors').map((actor, index) => {
    if (!ACTOR.test(actor)) fail(`actors[${index}] is invalid`);
    return actor;
  });
  unique(actors, 'actors');
  if (actors.length === 0 || actors.length > bounds.maxActors) fail(`actors must contain 1 through ${bounds.maxActors} entries`);
  const actorSet = new Set(actors);
  const profilesInput = object(input.profiles, 'profiles');
  const profileEntries = Object.entries(profilesInput);
  if (profileEntries.length === 0 || profileEntries.length > bounds.maxProfiles) fail(`profiles must contain 1 through ${bounds.maxProfiles} entries`);
  const defaultProfile = string(input.defaultProfile, 'defaultProfile');
  if (!profilesInput[defaultProfile]) fail(`defaultProfile ${defaultProfile} does not exist`);
  const profiles = {};
  const unresolvedReasons = [];
  for (const [name, value] of profileEntries) {
    if (!ID.test(name)) fail(`profile name ${name} is invalid`);
    object(value, `profiles.${name}`);
    exactKeys(value, ['source', 'image', 'build', 'compatibility'], `profiles.${name}`);
    const source = resolveSource(value.source, baseDirectory);
    const profileUnresolved = [];
    const image = validateImage(value.image, input.targetPlatform, acceptance, profileUnresolved, `profiles.${name}.image`);
    if (image.origin === 'localBuild' && !value.build) fail(`profiles.${name}.build is required for a localBuild image`);
    if (image.origin === 'prebuilt' && value.build) fail(`profiles.${name}.build is only valid for a localBuild image`);
    const build = value.build ? validateBuild(value.build, `profiles.${name}`, source, acceptance, profileUnresolved) : null;
    unresolvedReasons.push(...profileUnresolved);
    profiles[name] = {source, image, build, compatibility: validateCompatibility(value.compatibility, `profiles.${name}.compatibility`)};
  }
  const phasesInput = array(input.phases, 'phases');
  if (phasesInput.length === 0 || phasesInput.length > bounds.maxPhases) fail(`phases must contain 1 through ${bounds.maxPhases} entries`);
  const phases = [];
  const byId = new Map();
  for (let index = 0; index < phasesInput.length; index += 1) {
    const value = object(phasesInput[index], `phases[${index}]`);
    exactKeys(value, ['id', 'kind', 'inherits', 'assignments', 'expectedOutcome', 'hypothesis'], `phases[${index}]`);
    if (!ID.test(value.id)) fail(`phases[${index}].id is invalid`);
    if (byId.has(value.id)) fail(`duplicate phase ${value.id}`);
    if (!PHASE_KINDS.has(value.kind)) fail(`phases[${index}].kind is invalid`);
    if (!EXPECTED_OUTCOMES.has(value.expectedOutcome)) fail(`phases[${index}].expectedOutcome is invalid`);
    let actorProfiles = Object.fromEntries(actors.map(actor => [actor, defaultProfile]));
    if (value.inherits !== undefined) {
      const inherited = byId.get(value.inherits);
      if (!inherited) fail(`phase ${value.id} inherits unknown or later phase ${value.inherits}`);
      actorProfiles = {...inherited.actorProfiles};
    }
    const assigned = new Set();
    for (const [assignmentIndex, assignment] of array(value.assignments, `phases[${index}].assignments`).entries()) {
      object(assignment, `phases[${index}].assignments[${assignmentIndex}]`);
      exactKeys(assignment, ['profile', 'actors'], `phases[${index}].assignments[${assignmentIndex}]`);
      if (!profiles[assignment.profile]) fail(`phase ${value.id} references unknown profile ${assignment.profile}`);
      for (const actor of array(assignment.actors, `phases[${index}].assignments[${assignmentIndex}].actors`)) {
        if (!actorSet.has(actor)) fail(`phase ${value.id} references unknown actor ${actor}`);
        if (assigned.has(actor)) fail(`phase ${value.id} assigns actor ${actor} more than once`);
        assigned.add(actor);
        actorProfiles[actor] = assignment.profile;
      }
    }
    const actorImages = Object.fromEntries(actors.map(actor => [actor, profiles[actorProfiles[actor]].image.requestedRef]));
    const phase = {
      id: value.id,
      kind: value.kind,
      inherits: value.inherits ?? null,
      expectedOutcome: value.expectedOutcome,
      hypothesis: value.hypothesis ?? null,
      actorProfiles,
      actorImages,
      topologyArguments: actors.map(actor => `--actor-image=${actor}=${actorImages[actor]}`),
    };
    phases.push(phase);
    byId.set(value.id, phase);
  }
  const output = {
    schema: 'stacks-attacknet-version-matrix/v1',
    matrixId: input.matrixId,
    targetPlatform: input.targetPlatform,
    acceptanceRequested: acceptance,
    acceptanceReady: unresolvedReasons.length === 0,
    unresolvedReasons: [...new Set(unresolvedReasons)].sort(),
    bounds,
    actors,
    defaultProfile,
    profiles,
    phases,
    caveats: [
      'Resolution is offline: no container registry was contacted and no image was built.',
      'Compatibility declarations are hypotheses until exercised by an admitted attacknet run.',
      'Acceptance still requires runtime image-ID and admitted-Pod evidence in the run descriptor.',
    ],
  };
  output.matrixDigest = artifactDigest(output);
  return output;
}

function parseArgs(argv) {
  const args = {acceptance: false, output: null};
  for (const arg of argv) {
    if (arg === '--acceptance') args.acceptance = true;
    else if (arg.startsWith('--output=')) args.output = arg.slice('--output='.length);
    else if (!args.input) args.input = arg;
    else fail(`unknown argument ${arg}`);
  }
  if (!args.input) fail('usage: version-matrix.mjs MATRIX.json [--acceptance] [--output=FILE]');
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = resolve(args.input);
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  const output = compileVersionMatrix(input, {baseDirectory: dirname(inputPath), acceptance: args.acceptance});
  const serialized = `${JSON.stringify(output, null, 2)}\n`;
  if (args.output) writeFileSync(resolve(args.output), serialized);
  else process.stdout.write(serialized);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(`version-matrix: ${error.message}`); process.exitCode = 1; }
}
