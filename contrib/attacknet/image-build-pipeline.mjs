#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const DIGEST_REFERENCE = /@sha256:[0-9a-f]{64}$/;
const REVISION = /^[0-9a-f]{40}$/;
const ID = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const IMAGE_REPOSITORY = /^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?\/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const SOURCE_KINDS = new Set(['current', 'releasedGitRef', 'localModified']);
const PLATFORMS = new Set(['linux/amd64', 'linux/arm64']);
const CARGO_FEATURE = /^[a-zA-Z0-9_-]{1,64}$/;
const DEFAULT_CARGO_FEATURES = Object.freeze(['monitoring_prom', 'slog_json']);

function fail(message) { throw new Error(message); }
function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${path} must be an object`);
  return value;
}
function string(value, path) {
  if (typeof value !== 'string' || value.length === 0) fail(`${path} must be a non-empty string`);
  return value;
}
function exactKeys(value, allowed, path) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${path}.${key} is not supported`);
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
function sha256(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function artifactDigest(value) { return sha256(JSON.stringify(canonical(value))); }
function tagFragment(digest) { return digest.slice('sha256:'.length, 'sha256:'.length + 24); }

function defaultRunner(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    input: options.input,
    encoding: options.encoding === undefined ? 'utf8' : options.encoding,
    maxBuffer: 1024 * 1024 * 1024,
    stdio: options.stdio ?? [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ''}`.trim();
    fail(`${command} ${args.join(' ')} exited ${result.status}${detail ? `: ${detail}` : ''}`);
  }
  return result;
}

function git(repository, args, encoding = 'utf8') {
  const result = defaultRunner('git', ['-C', repository, ...args], {encoding});
  return encoding === null ? result.stdout : result.stdout.trim();
}

function repositoryPath(value, baseDirectory) {
  const candidate = isAbsolute(value) ? value : resolve(baseDirectory, value);
  try { return realpathSync(candidate); } catch { fail(`repository does not exist: ${candidate}`); }
}

function safePath(root, filename) {
  const candidate = resolve(root, filename);
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) fail(`path escapes ${root}: ${filename}`);
  return candidate;
}

function workspaceState(repository, revision) {
  const patch = git(repository, ['diff', '--binary', revision, '--'], null);
  const status = git(repository, ['status', '--porcelain=v1', '-z'], null);
  const untracked = git(repository, ['ls-files', '--others', '--exclude-standard', '-z'], null)
    .toString('utf8').split('\0').filter(Boolean).sort();
  const hash = createHash('sha256');
  hash.update('stacks-attacknet-source-state-v1\0');
  hash.update(revision);
  hash.update('\0patch\0');
  hash.update(patch);
  const untrackedFiles = [];
  for (const filename of untracked) {
    const path = safePath(repository, filename);
    const stat = lstatSync(path);
    const contents = stat.isSymbolicLink() ? Buffer.from(readlinkSync(path)) : readFileSync(path);
    const digest = sha256(contents);
    untrackedFiles.push({path: filename, digest, mode: stat.mode & 0o777, symlink: stat.isSymbolicLink()});
    hash.update('\0untracked\0');
    hash.update(filename);
    hash.update('\0');
    hash.update(String(stat.mode & 0o777));
    hash.update('\0');
    hash.update(contents);
  }
  return {dirty: status.length > 0, sourceStateDigest: `sha256:${hash.digest('hex')}`, untrackedFiles};
}

function resolveSource(source, defaultRepository, baseDirectory) {
  object(source, 'source');
  exactKeys(source, ['kind', 'repository', 'gitRef', 'expectedRevision', 'baseRef', 'changeId'], 'source');
  if (!SOURCE_KINDS.has(source.kind)) fail(`unsupported source kind ${source.kind}`);
  const repository = repositoryPath(source.repository ?? defaultRepository, baseDirectory);
  let requestedRef = 'HEAD';
  if (source.kind === 'releasedGitRef') {
    requestedRef = string(source.gitRef, 'source.gitRef');
    if (!REVISION.test(source.expectedRevision ?? '')) {
      fail('releasedGitRef source.expectedRevision must pin the intended 40-character commit');
    }
  } else if (source.kind === 'localModified') {
    requestedRef = source.baseRef ?? 'HEAD';
    string(source.changeId, 'source.changeId');
  }
  const revision = git(repository, ['rev-parse', '--verify', `${requestedRef}^{commit}`]);
  if (!REVISION.test(revision)) fail(`${requestedRef} resolved to invalid revision ${revision}`);
  if (source.expectedRevision && revision !== source.expectedRevision) {
    fail(`${requestedRef} resolved to ${revision}, expected ${source.expectedRevision}`);
  }
  const state = source.kind === 'releasedGitRef'
    ? {dirty: false, sourceStateDigest: sha256(`git-commit\0${revision}`), untrackedFiles: []}
    : workspaceState(repository, revision);
  return {
    kind: source.kind,
    repository,
    requestedRef,
    revision,
    changeId: source.changeId ?? null,
    ...state,
  };
}

function validateDockerfile(contents, path) {
  const checks = [
    [/cargo\s+chef\s+prepare\b/, 'cargo chef prepare'],
    [/cargo\s+chef\s+cook\b/, 'cargo chef cook'],
    [/FROM\s+scratch\s+AS\s+cargo-chef-recipe\b/i, 'exportable cargo-chef-recipe target'],
    [/COPY\s+--from=planner\s+\/src\/recipe\.json\s+\/recipe\.json/, 'exact Cargo Chef recipe export'],
    [/CARGO_INCREMENTAL=0/, 'CARGO_INCREMENTAL=0'],
    [/ARG\s+CARGO_CHEF_IMAGE=/, 'CARGO_CHEF_IMAGE build argument'],
    [/FROM\s+\$\{CARGO_CHEF_IMAGE\}/, 'digest-pinnable cargo-chef base'],
    [/ARG\s+RUNTIME_IMAGE=/, 'RUNTIME_IMAGE build argument'],
    [/FROM\s+\$\{RUNTIME_IMAGE\}/, 'digest-pinnable runtime base'],
    [/ARG\s+ATTACKNET_CARGO_FEATURES=/, 'ATTACKNET_CARGO_FEATURES build argument'],
    [/cargo\s+chef\s+cook[\s\S]*?--features\s+"?\$\{ATTACKNET_CARGO_FEATURES\}"?/, 'Cargo Chef feature-keyed dependency build'],
    [/cargo\s+build[\s\S]*?--features\s+"?\$\{ATTACKNET_CARGO_FEATURES\}"?/, 'feature-keyed runtime build'],
  ];
  for (const [pattern, description] of checks) {
    if (!pattern.test(contents)) fail(`${path} does not provide ${description}`);
  }
}

export function planImageBuildPipeline(input, {baseDirectory = process.cwd()} = {}) {
  object(input, 'pipeline');
  exactKeys(input, [
    'schemaVersion', 'pipelineId', 'repository', 'dockerfile', 'imageRepository',
    'targetPlatform', 'baseImages', 'profiles',
  ], 'pipeline');
  if (input.schemaVersion !== 1) fail('schemaVersion must be 1');
  if (!ID.test(input.pipelineId ?? '')) fail('pipelineId is invalid');
  const defaultRepository = string(input.repository, 'repository');
  const targetPlatform = string(input.targetPlatform, 'targetPlatform');
  if (!PLATFORMS.has(targetPlatform)) fail(`unsupported targetPlatform ${targetPlatform}`);
  const imageRepository = string(input.imageRepository, 'imageRepository');
  if (!IMAGE_REPOSITORY.test(imageRepository) || imageRepository.includes('@')) fail('imageRepository is invalid');
  object(input.baseImages, 'baseImages');
  exactKeys(input.baseImages, ['cargoChef', 'runtime'], 'baseImages');
  const baseImages = {
    cargoChef: string(input.baseImages.cargoChef, 'baseImages.cargoChef'),
    runtime: string(input.baseImages.runtime, 'baseImages.runtime'),
  };
  for (const [name, value] of Object.entries(baseImages)) {
    if (!DIGEST_REFERENCE.test(value)) fail(`baseImages.${name} must be digest-pinned`);
  }
  const dockerfile = isAbsolute(input.dockerfile)
    ? input.dockerfile
    : resolve(baseDirectory, string(input.dockerfile, 'dockerfile'));
  const dockerfileBytes = readFileSync(dockerfile);
  validateDockerfile(dockerfileBytes.toString('utf8'), dockerfile);
  const dockerfileDigest = sha256(dockerfileBytes);
  if (!Array.isArray(input.profiles) || input.profiles.length === 0 || input.profiles.length > 32) {
    fail('profiles must contain 1 through 32 entries');
  }
  const ids = new Set();
  const profiles = input.profiles.map((profile, index) => {
    object(profile, `profiles[${index}]`);
    exactKeys(profile, ['id', 'source', 'cargoFeatures'], `profiles[${index}]`);
    if (!ID.test(profile.id ?? '')) fail(`profiles[${index}].id is invalid`);
    if (ids.has(profile.id)) fail(`duplicate profile ${profile.id}`);
    ids.add(profile.id);
    const source = resolveSource(profile.source, defaultRepository, baseDirectory);
    const cargoFeatures = profile.cargoFeatures ?? DEFAULT_CARGO_FEATURES;
    if (!Array.isArray(cargoFeatures) || cargoFeatures.length < 1 || cargoFeatures.length > 16
        || cargoFeatures.some(feature => typeof feature !== 'string' || !CARGO_FEATURE.test(feature))) {
      fail(`profiles[${index}].cargoFeatures must contain 1 through 16 bounded Cargo features`);
    }
    if (new Set(cargoFeatures).size !== cargoFeatures.length) fail(`profiles[${index}].cargoFeatures contains duplicates`);
    for (const required of DEFAULT_CARGO_FEATURES) {
      if (!cargoFeatures.includes(required)) fail(`profiles[${index}].cargoFeatures must include ${required}`);
    }
    const normalizedCargoFeatures = [...cargoFeatures].sort();
    const buildKey = {
      schema: 'stacks-attacknet-image-build-key/v1',
      source: {
        kind: source.kind,
        revision: source.revision,
        sourceStateDigest: source.sourceStateDigest,
        changeId: source.changeId,
      },
      dockerfileDigest,
      baseImages,
      targetPlatform,
      cargoProfile: 'release-lite',
      cargoIncremental: false,
      features: normalizedCargoFeatures,
      binaries: ['stacks-node', 'stacks-signer', 'stacks-inspect'],
    };
    const buildKeyDigest = artifactDigest(buildKey);
    return {
      id: profile.id,
      source,
      cargoFeatures: normalizedCargoFeatures,
      buildKey,
      buildKeyDigest,
      plannedLocalRef: `${imageRepository}:src-${tagFragment(buildKeyDigest)}`,
      executionRequiredForContentTag: true,
    };
  });
  const plan = {
    schema: 'stacks-attacknet-image-build-plan/v1',
    pipelineId: input.pipelineId,
    targetPlatform,
    imageRepository,
    dockerfile,
    dockerfileDigest,
    baseImages,
    profiles,
    execution: {
      defaultMode: 'plan-only',
      dockerMutationRequires: '--execute',
      kindMutationRequires: '--execute plus --load-kind=CLUSTER',
      kubernetesApiMutation: false,
    },
    acceptanceReady: false,
    acceptanceBlockers: [
      'Images have not been built and resolved to immutable image digests.',
      'No admitted Pod UID and runtime imageID have been captured.',
    ],
  };
  // Host paths are operational evidence, not build identity. Keep them in the
  // human-readable plan while deriving the reproducibility ID only from exact
  // source/build content and semantic profile names.
  plan.planDigest = artifactDigest({
    schema: plan.schema,
    pipelineId: plan.pipelineId,
    targetPlatform,
    imageRepository,
    dockerfileDigest,
    baseImages,
    profiles: profiles.map(profile => ({id: profile.id, buildKeyDigest: profile.buildKeyDigest})),
  });
  return plan;
}

function sourceFileList(repository) {
  return git(repository, ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], null)
    .toString('utf8').split('\0').filter(Boolean).sort();
}

function copyWorkspaceSnapshot(repository, destination) {
  for (const filename of sourceFileList(repository)) {
    const source = safePath(repository, filename);
    const target = safePath(destination, filename);
    const stat = lstatSync(source);
    mkdirSync(dirname(target), {recursive: true});
    if (stat.isSymbolicLink()) symlinkSync(readlinkSync(source), target);
    else {
      copyFileSync(source, target);
      chmodSync(target, stat.mode & 0o777);
    }
  }
}

export function stageResolvedSource(profile, destination) {
  mkdirSync(destination, {recursive: true});
  if (profile.source.kind === 'releasedGitRef' || !profile.source.dirty) {
    const archive = git(profile.source.repository, ['archive', '--format=tar', profile.source.revision], null);
    defaultRunner('tar', ['-xf', '-', '-C', destination], {input: archive, encoding: null});
  } else {
    copyWorkspaceSnapshot(profile.source.repository, destination);
  }
}

function treeEntries(root, current = '') {
  const directory = safePath(root, current);
  const result = [];
  for (const name of readdirSync(directory).sort()) {
    const relativePath = current ? `${current}/${name}` : name;
    const path = safePath(root, relativePath);
    const stat = lstatSync(path);
    if (stat.isDirectory()) result.push(...treeEntries(root, relativePath));
    else {
      const contents = stat.isSymbolicLink() ? Buffer.from(readlinkSync(path)) : readFileSync(path);
      result.push({path: relativePath, mode: stat.mode & 0o777, symlink: stat.isSymbolicLink(), digest: sha256(contents)});
    }
  }
  return result;
}

export function stagedContextDigest(directory) {
  return artifactDigest({schema: 'stacks-attacknet-staged-context/v1', files: treeEntries(directory)});
}

function assertSourceUnchanged(profile) {
  const fresh = profile.source.kind === 'releasedGitRef'
    ? {revision: git(profile.source.repository, ['rev-parse', '--verify', `${profile.source.revision}^{commit}`]), sourceStateDigest: profile.source.sourceStateDigest}
    : {
        revision: git(profile.source.repository, ['rev-parse', '--verify', `${profile.source.requestedRef}^{commit}`]),
        ...workspaceState(profile.source.repository, profile.source.revision),
      };
  if (fresh.revision !== profile.source.revision || fresh.sourceStateDigest !== profile.source.sourceStateDigest) {
    fail(`source for profile ${profile.id} changed after planning; create a new plan`);
  }
}

function imageDigestFromMetadata(metadata, profileId) {
  const digest = metadata['containerimage.digest'] ?? metadata['containerimage.descriptor']?.digest;
  if (!DIGEST.test(digest ?? '')) fail(`BuildKit metadata for ${profileId} has no immutable image digest`);
  if (!metadata['buildx.build.provenance'] || typeof metadata['buildx.build.provenance'] !== 'object') {
    fail(`BuildKit metadata for ${profileId} has no provenance object`);
  }
  return digest;
}

function parseJsonBytes(bytes, path) {
  try { return JSON.parse(Buffer.from(bytes).toString('utf8')); }
  catch (error) { fail(`${path} is not valid JSON: ${error.message}`); }
}

function verifiedBlob(readBlob, digest, path) {
  if (!DIGEST.test(digest ?? '')) fail(`${path} has an invalid digest`);
  const bytes = Buffer.from(readBlob(digest));
  if (sha256(bytes) !== digest) fail(`${path} contents do not match ${digest}`);
  return bytes;
}

/**
 * Resolve the identity Kubernetes CRI reports for a single-platform image.
 *
 * BuildKit emits an OCI index digest when provenance attestations are enabled,
 * while containerd reports the selected platform manifest's config digest in
 * Pod.status.containerStatuses[].imageID.  They are intentionally different
 * hashes.  This function verifies the complete index -> manifest -> config
 * chain rather than weakening admission evidence to a mutable tag.
 */
export function resolveOciRuntimeIdentity({
  archiveIndexBytes,
  readBlob,
  expectedImageDigest,
  targetPlatform,
}) {
  const [os, architecture] = string(targetPlatform, 'targetPlatform').split('/');
  if (!os || !architecture) fail(`targetPlatform is invalid: ${targetPlatform}`);
  const archiveIndex = parseJsonBytes(archiveIndexBytes, 'OCI archive index.json');
  const roots = Array.isArray(archiveIndex.manifests) ? archiveIndex.manifests : [];
  const root = roots.find(item => item?.digest === expectedImageDigest);
  if (!root) fail(`OCI archive does not contain BuildKit image digest ${expectedImageDigest}`);
  const imageIndexBytes = verifiedBlob(readBlob, root.digest, 'OCI image index');
  const imageIndex = parseJsonBytes(imageIndexBytes, 'OCI image index');
  const matches = (Array.isArray(imageIndex.manifests) ? imageIndex.manifests : [])
    .filter(item => item?.platform?.os === os && item?.platform?.architecture === architecture);
  if (matches.length !== 1) {
    fail(`OCI image index must contain exactly one ${targetPlatform} manifest; found ${matches.length}`);
  }
  const platformDescriptor = matches[0];
  const platformManifestBytes = verifiedBlob(readBlob, platformDescriptor.digest, 'OCI platform manifest');
  const platformManifest = parseJsonBytes(platformManifestBytes, 'OCI platform manifest');
  const runtimeConfigDigest = platformManifest?.config?.digest;
  const configBytes = verifiedBlob(readBlob, runtimeConfigDigest, 'OCI runtime config');
  const config = parseJsonBytes(configBytes, 'OCI runtime config');
  if (config.os !== os || config.architecture !== architecture) {
    fail(`OCI runtime config platform ${config.os}/${config.architecture} does not match ${targetPlatform}`);
  }
  return {
    imageIndexDigest: expectedImageDigest,
    platformManifestDigest: platformDescriptor.digest,
    runtimeConfigDigest,
    expectedRuntimeImageID: runtimeConfigDigest,
    platform: targetPlatform,
  };
}

function inspectRuntimeImageIdentity({localRef, imageDigest, targetPlatform, profileId, scratch, runner}) {
  const archive = join(scratch, `${profileId}.runtime-image.oci.tar`);
  try {
    runner('docker', ['image', 'save', '--output', archive, localRef]);
    const member = name => runner('tar', ['-xOf', archive, name], {encoding: null}).stdout;
    return resolveOciRuntimeIdentity({
      archiveIndexBytes: member('index.json'),
      readBlob: digest => member(`blobs/sha256/${digest.slice('sha256:'.length)}`),
      expectedImageDigest: imageDigest,
      targetPlatform,
    });
  } finally {
    rmSync(archive, {force: true});
  }
}

export function executeImageBuildPipeline(plan, {
  outputDirectory,
  loadKindCluster = null,
  runner = defaultRunner,
  stager = stageResolvedSource,
  identityResolver = inspectRuntimeImageIdentity,
  temporaryRoot = null,
} = {}) {
  if (plan?.schema !== 'stacks-attacknet-image-build-plan/v1') fail('invalid image build plan');
  if (!outputDirectory) fail('outputDirectory is required for execution evidence');
  const resolvedOutput = resolve(outputDirectory);
  for (const profile of plan.profiles) {
    if (resolvedOutput === profile.source.repository || resolvedOutput.startsWith(`${profile.source.repository}${sep}`)) {
      fail('outputDirectory must be outside every source repository so evidence cannot alter the source snapshot');
    }
  }
  mkdirSync(resolvedOutput, {recursive: true});
  const scratch = temporaryRoot ?? mkdtempSync(join(tmpdir(), 'stacks-attacknet-images-'));
  mkdirSync(scratch, {recursive: true});
  const liveDockerfileBytes = readFileSync(plan.dockerfile);
  if (sha256(liveDockerfileBytes) !== plan.dockerfileDigest) {
    fail('Dockerfile changed after planning; create a new plan');
  }
  const toolingDirectory = join(scratch, '.attacknet-build-tooling');
  const stagedDockerfile = join(toolingDirectory, 'Dockerfile');
  mkdirSync(toolingDirectory, {recursive: true});
  writeFileSync(stagedDockerfile, liveDockerfileBytes);
  if (sha256(readFileSync(stagedDockerfile)) !== plan.dockerfileDigest) fail('staged Dockerfile digest mismatch');
  const records = [];
  for (const profile of plan.profiles) {
    assertSourceUnchanged(profile);
    const context = join(scratch, profile.id);
    stager(profile, context);
    assertSourceUnchanged(profile);
    const contextDigest = stagedContextDigest(context);
    const contentDigest = artifactDigest({buildKeyDigest: profile.buildKeyDigest, contextDigest});
    const localRef = `${plan.imageRepository}:content-${tagFragment(contentDigest)}`;
    const recipeOutput = join(scratch, `${profile.id}-cargo-chef-recipe`);
    const recipeEvidencePath = join(
      resolvedOutput, `${profile.id}.${tagFragment(contentDigest)}.cargo-chef-recipe.json`);
    const recipeArgs = [
      'buildx', 'build',
      '--file', stagedDockerfile,
      '--platform', plan.targetPlatform,
      '--target', 'cargo-chef-recipe',
      '--output', `type=local,dest=${recipeOutput}`,
      '--build-arg', `CARGO_CHEF_IMAGE=${plan.baseImages.cargoChef}`,
      '--build-arg', `RUNTIME_IMAGE=${plan.baseImages.runtime}`,
      '--build-arg', `ATTACKNET_CARGO_FEATURES=${profile.cargoFeatures.join(',')}`,
      context,
    ];
    runner('docker', recipeArgs, {
      env: {...process.env, DOCKER_BUILDKIT: '1', CARGO_INCREMENTAL: '0'},
    });
    const recipeBytes = readFileSync(join(recipeOutput, 'recipe.json'));
    writeFileSync(recipeEvidencePath, recipeBytes);
    const recipeDigest = sha256(recipeBytes);
    const metadataPath = join(resolvedOutput, `${profile.id}.${tagFragment(contentDigest)}.buildkit-metadata.json`);
    // An empty sentinel prevents a successful-but-broken executor from reusing
    // metadata left by an earlier invocation in the same evidence directory.
    writeFileSync(metadataPath, '');
    const args = [
      'buildx', 'build',
      '--file', stagedDockerfile,
      '--platform', plan.targetPlatform,
      '--tag', localRef,
      '--metadata-file', metadataPath,
      '--provenance=mode=max',
      '--sbom=true',
      '--load',
      '--build-arg', `CARGO_CHEF_IMAGE=${plan.baseImages.cargoChef}`,
      '--build-arg', `RUNTIME_IMAGE=${plan.baseImages.runtime}`,
      '--build-arg', `ATTACKNET_CARGO_FEATURES=${profile.cargoFeatures.join(',')}`,
      '--build-arg', 'CARGO_INCREMENTAL=0',
      '--build-arg', `STACKS_NODE_VERSION=attacknet-${profile.id}-${profile.source.revision.slice(0, 12)}`,
      '--build-arg', `GIT_BRANCH=${profile.source.requestedRef}`,
      '--build-arg', `GIT_COMMIT=${profile.source.revision}`,
      '--label', `org.opencontainers.image.revision=${profile.source.revision}`,
      '--label', `org.stacks.attacknet.source-state=${profile.source.sourceStateDigest}`,
      context,
    ];
    const buildInvocation = {
      schema: 'stacks-attacknet-image-build-invocation/v1',
      buildKeyDigest: profile.buildKeyDigest,
      stagedContextDigest: contextDigest,
      dockerfileDigest: plan.dockerfileDigest,
      targetPlatform: plan.targetPlatform,
      target: 'runtime',
      localRef,
      baseImages: plan.baseImages,
      cargoIncremental: false,
      cargoFeatures: profile.cargoFeatures,
      provenanceMode: 'max',
      sbomRequested: true,
      labels: {
        revision: profile.source.revision,
        sourceState: profile.source.sourceStateDigest,
      },
    };
    const buildInvocationDigest = artifactDigest(buildInvocation);
    runner('docker', args, {
      env: {...process.env, DOCKER_BUILDKIT: '1', BUILDX_METADATA_PROVENANCE: 'max', CARGO_INCREMENTAL: '0'},
    });
    const metadataBytes = readFileSync(metadataPath);
    const metadata = JSON.parse(metadataBytes.toString('utf8'));
    const imageDigest = imageDigestFromMetadata(metadata, profile.id);
    const immutableRef = `${plan.imageRepository}@${imageDigest}`;
    const imageIdentity = identityResolver({
      localRef,
      imageDigest,
      targetPlatform: plan.targetPlatform,
      profileId: profile.id,
      scratch,
      runner,
    });
    if (imageIdentity?.imageIndexDigest !== imageDigest
      || imageIdentity?.platform !== plan.targetPlatform
      || !DIGEST.test(imageIdentity?.platformManifestDigest ?? '')
      || !DIGEST.test(imageIdentity?.runtimeConfigDigest ?? '')
      || imageIdentity?.expectedRuntimeImageID !== imageIdentity.runtimeConfigDigest) {
      fail(`runtime image identity for ${profile.id} is incomplete or inconsistent`);
    }
    let kindLoaded = false;
    if (loadKindCluster) {
      runner('kind', ['load', 'docker-image', localRef, '--name', loadKindCluster]);
      kindLoaded = true;
    }
    const record = {
      schema: 'stacks-attacknet-image-build-record/v1',
      pipelineId: plan.pipelineId,
      profileId: profile.id,
      source: profile.source,
      buildKeyDigest: profile.buildKeyDigest,
      stagedContextDigest: contextDigest,
      contentDigest,
      localRef,
      imageDigest,
      immutableRef,
      imageIdentity,
      cargoChefRecipe: {
        path: basename(recipeEvidencePath),
        digest: recipeDigest,
      },
      buildInvocation: {
        ...buildInvocation,
        digest: buildInvocationDigest,
      },
      buildkitMetadata: {
        path: basename(metadataPath),
        digest: sha256(metadataBytes),
        provenancePresent: true,
        sbomRequested: true,
      },
      kindLoad: kindLoaded ? {cluster: loadKindCluster, localRef} : null,
      acceptanceReady: false,
      acceptanceImageRef: kindLoaded ? localRef : immutableRef,
      acceptanceBlockers: [
        kindLoaded
          ? 'The admitted declaration must match this locally loaded content tag; local kind cannot pull the registry-style digest reference.'
          : 'A Kubernetes admission record must match this immutable image index digest.',
        'The exact admitted Pod UID and runtime imageID must match imageIdentity.expectedRuntimeImageID.',
      ],
    };
    record.recordDigest = artifactDigest(record);
    writeFileSync(join(resolvedOutput, `${profile.id}.build-record.json`), `${JSON.stringify(record, null, 2)}\n`);
    records.push(record);
  }
  const result = {
    schema: 'stacks-attacknet-image-build-result/v1',
    pipelineId: plan.pipelineId,
    planDigest: plan.planDigest,
    profiles: records,
    kindMutationPerformed: Boolean(loadKindCluster),
    kubernetesApiMutationPerformed: false,
    acceptanceReady: false,
    acceptanceBlockers: ['Runtime admission evidence has not yet been joined to these build records.'],
  };
  result.resultDigest = artifactDigest(result);
  writeFileSync(join(resolvedOutput, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  return result;
}

export function runImageBuildPipeline(input, options = {}) {
  const plan = planImageBuildPipeline(input, options);
  if (!options.execute) return {plan, result: null};
  return {
    plan,
    result: executeImageBuildPipeline(plan, {
      outputDirectory: options.outputDirectory,
      loadKindCluster: options.loadKindCluster,
      runner: options.runner,
      stager: options.stager,
      identityResolver: options.identityResolver,
      temporaryRoot: options.temporaryRoot,
    }),
  };
}

function parseArgs(argv) {
  const options = {execute: false, outputDirectory: null, loadKindCluster: null};
  for (const argument of argv) {
    if (argument === '--execute') options.execute = true;
    else if (argument.startsWith('--output-dir=')) options.outputDirectory = argument.slice('--output-dir='.length);
    else if (argument.startsWith('--load-kind=')) options.loadKindCluster = argument.slice('--load-kind='.length);
    else if (!options.input) options.input = argument;
    else fail(`unknown argument ${argument}`);
  }
  if (!options.input) {
    fail('usage: image-build-pipeline.mjs PIPELINE.json [--execute --output-dir=DIR [--load-kind=CLUSTER]]');
  }
  if (options.loadKindCluster && !options.execute) fail('--load-kind requires --execute');
  if (options.execute && !options.outputDirectory) fail('--execute requires --output-dir');
  return options;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = resolve(args.input);
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  const {plan, result} = runImageBuildPipeline(input, {
    baseDirectory: dirname(inputPath),
    execute: args.execute,
    outputDirectory: args.outputDirectory,
    loadKindCluster: args.loadKindCluster,
  });
  process.stdout.write(`${JSON.stringify(result ?? plan, null, 2)}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`image-build-pipeline: ${error.message}`);
    process.exitCode = 1;
  }
}
