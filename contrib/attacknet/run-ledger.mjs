#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import {basename, dirname, join, resolve} from 'node:path';
import {tmpdir} from 'node:os';

import {
  RUN_DESCRIPTOR_SCHEMA,
  appendEvent,
  finalizeDescriptor,
  initializeDescriptor,
  readDescriptor,
  resolveRuntimeInputs,
  sha256File,
  validateDescriptor,
  writeDescriptor,
} from './run-descriptor.mjs';

function requireString(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function writeAtomic(path, contents) {
  mkdirSync(dirname(path), {recursive: true});
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, contents, {mode: 0o600});
  renameSync(temporary, path);
}

function timestampId(date = new Date()) {
  return date.toISOString().replaceAll(/[-:.]/g, '').replace('Z', 'Z');
}

function registryPath(namespace, network) {
  return join(tmpdir(), 'stacks-attacknet-runs', `${namespace}--${network}.path`);
}

function listFiles(root, relative = '') {
  const result = [];
  for (const entry of readdirSync(join(root, relative), {withFileTypes: true})) {
    const child = join(relative, entry.name);
    if (entry.isDirectory()) {
      if (!new Set(['run-artifacts', 'runs']).has(entry.name)) result.push(...listFiles(root, child));
    } else if (entry.isFile()
      && entry.name !== 'active-run-descriptor'
      && !/^run-.*\.json$/.test(entry.name)) {
      result.push(join(root, child));
    }
  }
  return result.sort();
}

function renderedConfigurationFiles(root) {
  const topLevel = new Set([
    'stacksnetwork.json', 'stacksnetwork.bootstrap.json',
    'burnchain-policy.configmap.json', 'policy.env',
    'compose.yaml', 'compose.bootstrap.yaml', 'compose.observability.yaml',
    'prometheus.compose.yml',
  ]);
  return listFiles(root).filter(path => {
    const relative = path.slice(root.length + 1);
    return topLevel.has(relative)
      || relative.startsWith('configs/')
      || relative.startsWith('configs-bootstrap/');
  });
}

function snapshotArtifact(path, artifactsDirectory, category) {
  const absolute = resolve(path);
  const digest = sha256File(absolute);
  const snapshotDirectory = join(artifactsDirectory, category);
  const target = join(snapshotDirectory, `${digest.slice(7, 23)}-${basename(absolute)}`);
  mkdirSync(snapshotDirectory, {recursive: true});
  if (!existsSync(target)) copyFileSync(absolute, target);
  if (sha256File(target) !== digest) {
    throw new Error(`immutable run artifact snapshot digest mismatch: ${absolute}`);
  }
  return target;
}

function repositoryRoot(attacknetDirectory) {
  return execFileSync('git', ['-C', attacknetDirectory, 'rev-parse', '--show-toplevel'], {encoding: 'utf8'}).trim();
}

function gitOutput(root, args) {
  return execFileSync('git', ['-C', root, ...args], {encoding: 'utf8', maxBuffer: 128 * 1024 * 1024});
}

function sourceState(root, outputPath) {
  const revision = gitOutput(root, ['rev-parse', 'HEAD']).trim();
  const status = gitOutput(root, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (!status.trim()) return {revision, dirty: false};
  let patch = gitOutput(root, ['diff', '--binary', 'HEAD', '--', '.']);
  const untracked = gitOutput(root, ['ls-files', '--others', '--exclude-standard'])
    .trim().split('\n').filter(Boolean)
    .filter(path => !/(^|\/)(generated|evidence|target)(\/|$)/.test(path));
  for (const path of untracked) {
    try {
      execFileSync('git', ['-C', root, 'diff', '--no-index', '--binary', '--', '/dev/null', path], {
        encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
      });
    } catch (error) {
      if (error.status !== 1 || typeof error.stdout !== 'string') throw error;
      patch += error.stdout;
    }
  }
  writeAtomic(outputPath, patch);
  return {revision, dirty: true, diffPath: outputPath};
}

function nondeterminismDisclosure() {
  return {
    statement: 'Resolved choices are replayable; scheduling, packet timing, proof-of-work, and actor execution remain observationally bounded rather than deterministic.',
    disclosed: [
      {
        source: 'kubernetes-scheduling',
        impact: 'Pod placement and competing resource pressure alter event timing.',
        capture: 'The admitted workload and Pod state, including node placement and image IDs, are retained.',
        bounded: false,
      },
      {
        source: 'network-and-process-scheduling',
        impact: 'Packet delivery, process wakeups, and consensus-message interleavings can differ on replay.',
        capture: 'Ordered orchestrator decisions, trusted events, actor logs, and metrics delimit the observed execution.',
        bounded: false,
      },
      {
        source: 'bitcoin-proof-of-work',
        impact: 'Regtest block hashes and dependent consensus hashes differ even under the same cadence.',
        capture: 'Cadence transitions and admitted chain evidence are retained; assertions compare behavior, not literal hashes.',
        bounded: false,
      },
    ],
  };
}

export function initializeRun(generated, options = {}) {
  const absoluteGenerated = resolve(generated);
  const manifestPath = join(absoluteGenerated, 'manifest.json');
  const requestedManifestPath = join(absoluteGenerated, 'stacksnetwork.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const now = options.now ?? new Date();
  const runId = options.runId ?? process.env.ATTACKNET_RUN_ID
    ?? `${manifest.network}-${timestampId(now)}-${randomBytes(4).toString('hex')}`;
  const descriptorPath = resolve(options.descriptorPath ?? process.env.ATTACKNET_RUN_DESCRIPTOR
    ?? join(absoluteGenerated, 'runs', runId, 'run.json'));
  const artifacts = join(dirname(descriptorPath), 'run-artifacts');
  mkdirSync(artifacts, {recursive: true});
  const root = repositoryRoot(dirname(new URL(import.meta.url).pathname));
  const source = options.source ?? sourceState(root, join(artifacts, 'source.patch'));
  const topologySnapshot = snapshotArtifact(manifestPath, artifacts, 'initial-inputs');
  const requestedManifestSnapshot = snapshotArtifact(
    requestedManifestPath, artifacts, 'initial-inputs');
  const configurationSnapshots = renderedConfigurationFiles(absoluteGenerated)
    .map(path => snapshotArtifact(path, artifacts, 'initial-inputs'));
  const metadata = {
    runId,
    seed: String(options.seed ?? process.env.ATTACKNET_RUN_SEED ?? runId),
    seedAlgorithm: options.seedAlgorithm ?? process.env.ATTACKNET_SEED_ALGORITHM ?? 'hmac-sha256-decisions/v1',
    createdAt: now.toISOString(),
    sourceRevision: source.revision,
    sourceDirty: source.dirty,
    ...(source.diffPath ? {sourceDiffPath: source.diffPath} : {}),
    topologyPath: topologySnapshot,
    // Deliberately exclude observability credentials and run artifacts. They
    // belong in protected evidence, not in the replayable SUT configuration.
    configPaths: configurationSnapshots,
    requestedManifestPath: requestedManifestSnapshot,
    runtimeBackend: options.runtimeBackend ?? process.env.ATTACKNET_BACKEND ?? 'kubernetes',
    images: JSON.parse(readFileSync(requestedManifestPath, 'utf8')).spec.actors.map(actor => ({
      scope: actor.name,
      requestedRef: actor.image,
    })),
    nondeterminism: nondeterminismDisclosure(),
  };
  const metadataPath = join(artifacts, 'initialization.json');
  writeAtomic(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
  const descriptor = initializeDescriptor(metadata);
  writeDescriptor(descriptorPath, descriptor);
  writeAtomic(join(absoluteGenerated, 'active-run-descriptor'), `${descriptorPath}\n`);
  writeAtomic(registryPath(manifest.namespace, manifest.network), `${descriptorPath}\n`);
  return descriptorPath;
}

function digestFromImageId(imageId, scope) {
  const match = /sha256:[0-9a-f]{64}/.exec(imageId ?? '');
  if (!match) throw new Error(`actor ${scope} has no immutable image digest in imageID ${imageId ?? '<missing>'}`);
  return match[0];
}

export function resolveRun(descriptorPath, admittedManifestPath, podsPath) {
  const descriptor = readDescriptor(descriptorPath);
  const pods = JSON.parse(readFileSync(podsPath, 'utf8')).items ?? [];
  const byActor = new Map(pods.map(pod => [pod.metadata?.labels?.['testing.stacks.org/actor'], pod]));
  const images = descriptor.inputs.images.map(image => {
    const pod = byActor.get(image.scope);
    if (!pod) throw new Error(`no admitted Pod found for image scope ${image.scope}`);
    const spec = pod.spec?.containers?.find(container => container.name === 'actor');
    const status = pod.status?.containerStatuses?.find(container => container.name === 'actor');
    if (!spec || !status) throw new Error(`actor container status is incomplete for ${image.scope}`);
    const resolvedDigest = digestFromImageId(status.imageID, image.scope);
    return {
      scope: image.scope,
      requestedRef: image.requestedRef,
      resolvedRef: status.imageID,
      resolvedDigest,
      admittedRef: spec.image,
    };
  });
  // admittedRef is valuable evidence but is not part of the v1 cryptographic
  // identity tuple; retain it adjacent to the resolution input.
  const artifacts = join(dirname(descriptorPath), 'run-artifacts');
  const admittedManifestSnapshot = snapshotArtifact(
    admittedManifestPath, artifacts, 'runtime-inputs');
  const resolutionPath = join(artifacts, 'runtime-resolution.json');
  writeAtomic(resolutionPath, `${JSON.stringify({
    observedAdmittedManifestPath: resolve(admittedManifestPath),
    admittedManifestSnapshot,
    images,
  }, null, 2)}\n`);
  const normalizedImages = images.map(({admittedRef: _admittedRef, ...image}) => image);
  writeDescriptor(descriptorPath, resolveRuntimeInputs(descriptor, {
    backend: 'kubernetes', admittedManifestPath: admittedManifestSnapshot,
    images: normalizedImages,
  }));
  return descriptorPath;
}

export function resolveComposeRun(descriptorPath, admittedManifestPath, containersPath) {
  const descriptor = readDescriptor(descriptorPath);
  const containers = JSON.parse(readFileSync(containersPath, 'utf8'));
  if (!Array.isArray(containers)) throw new Error('Compose container inspection must be an array');
  const byService = new Map(containers.map(container => [
    container.Config?.Labels?.['com.docker.compose.service'], container,
  ]).filter(([service]) => typeof service === 'string' && service.length > 0));
  const images = descriptor.inputs.images.map(image => {
    const container = byService.get(image.scope);
    if (!container) throw new Error(`no admitted Compose container found for image scope ${image.scope}`);
    if (container.State?.Running !== true) {
      throw new Error(`Compose actor ${image.scope} was not Running at runtime resolution`);
    }
    const admittedRef = container.Config?.Image;
    if (admittedRef !== image.requestedRef) {
      throw new Error(`Compose actor ${image.scope} admitted image ${admittedRef ?? '<missing>'} instead of ${image.requestedRef}`);
    }
    const resolvedDigest = container.Image;
    if (!/^sha256:[0-9a-f]{64}$/.test(resolvedDigest ?? '')) {
      throw new Error(`Compose actor ${image.scope} has no immutable Docker image ID`);
    }
    return {
      scope: image.scope,
      requestedRef: image.requestedRef,
      resolvedRef: `docker-image://${resolvedDigest}`,
      resolvedDigest,
    };
  });
  const artifacts = join(dirname(descriptorPath), 'run-artifacts');
  const admittedManifestSnapshot = snapshotArtifact(
    admittedManifestPath, artifacts, 'runtime-inputs');
  const containersSnapshot = snapshotArtifact(containersPath, artifacts, 'runtime-inputs');
  const resolutionPath = join(artifacts, 'compose-runtime-resolution.json');
  writeAtomic(resolutionPath, `${JSON.stringify({
    backend: 'compose', observedAdmittedManifestPath: resolve(admittedManifestPath),
    admittedManifestSnapshot, containersSnapshot, images,
  }, null, 2)}\n`);
  writeDescriptor(descriptorPath, resolveRuntimeInputs(descriptor, {
    backend: 'compose', admittedManifestPath: admittedManifestSnapshot, images,
  }));
  return descriptorPath;
}

export function appendRunEvent(descriptorPath, type, payload, options = {}) {
  const descriptor = readDescriptor(descriptorPath);
  if (descriptor.run.status !== 'running') return descriptor;
  const now = options.now ?? new Date().toISOString();
  const prior = descriptor.timeline.at(-1)?.occurredAt;
  const occurredAt = options.occurredAt ?? (prior && Date.parse(now) < Date.parse(prior) ? prior : now);
  const updated = appendEvent(descriptor, {type, occurredAt, payload}, {now: () => now});
  writeDescriptor(descriptorPath, updated);
  return updated;
}

export function finalizeRun(descriptorPath, status, options = {}) {
  const descriptor = readDescriptor(descriptorPath);
  if (descriptor.run.status !== 'running') return descriptor;
  const updated = finalizeDescriptor(descriptor, status, options);
  writeDescriptor(descriptorPath, updated);
  return updated;
}

function descriptorArtifacts(descriptor) {
  const artifacts = [
    descriptor.inputs.topology,
    ...descriptor.inputs.configuration.files,
    descriptor.inputs.kubernetes.requestedManifest,
  ];
  if (descriptor.inputs.kubernetes.admittedManifest) artifacts.push(descriptor.inputs.kubernetes.admittedManifest);
  if (descriptor.source.diff) artifacts.push(descriptor.source.diff);
  return artifacts;
}

export function exportRun(descriptorPath, destination) {
  const descriptor = readDescriptor(descriptorPath);
  validateDescriptor(descriptor);
  const root = resolve(destination);
  const artifactsDirectory = join(root, 'artifacts');
  mkdirSync(artifactsDirectory, {recursive: true});
  copyFileSync(descriptorPath, join(root, 'run.json'));
  const index = [];
  for (const artifact of descriptorArtifacts(descriptor)) {
    if (!existsSync(artifact.path)) {
      index.push({...artifact, exportedPath: null, missing: true});
      continue;
    }
    const exportedPath = join('artifacts', `${artifact.digest.slice(7, 23)}-${basename(artifact.path)}`);
    const target = join(root, exportedPath);
    if (!existsSync(target)) copyFileSync(artifact.path, target);
    if (sha256File(target) !== artifact.digest) throw new Error(`exported artifact digest mismatch: ${artifact.path}`);
    index.push({...artifact, exportedPath, missing: false});
  }
  writeAtomic(join(root, 'artifact-index.json'), `${JSON.stringify(index, null, 2)}\n`);
  return root;
}

export function runContext(descriptorPath, namespace, network) {
  const descriptor = readDescriptor(descriptorPath);
  validateDescriptor(descriptor);
  return {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {
      name: `${network}-run-context`, namespace,
      labels: {
        'testing.stacks.org/network': network,
        'app.kubernetes.io/part-of': 'stacks-attacknet',
      },
    },
    data: {
      'run-id': descriptor.run.id,
      'schema-version': descriptor.schemaVersion,
      seed: descriptor.randomness.seed,
      'seed-algorithm': descriptor.randomness.algorithm,
      'started-at': descriptor.run.createdAt,
      'descriptor-digest': descriptor.integrity.digest,
    },
  };
}

export function locateRun(target, namespace, network) {
  if (process.env.ATTACKNET_RUN_DESCRIPTOR) return resolve(process.env.ATTACKNET_RUN_DESCRIPTOR);
  if (target) {
    const directory = statSync(target).isDirectory() ? target : dirname(target);
    const pointer = join(directory, 'active-run-descriptor');
    if (existsSync(pointer)) return readFileSync(pointer, 'utf8').trim();
  }
  const registry = registryPath(requireString(namespace, 'namespace'), requireString(network, 'network'));
  if (!existsSync(registry)) throw new Error(`no active run registry for ${namespace}/${network}`);
  return readFileSync(registry, 'utf8').trim();
}

function option(args, name) {
  const prefix = `--${name}=`;
  return args.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
}

export function runCli(argv) {
  const [command, ...args] = argv;
  if (command === 'init') {
    const [generated] = args;
    if (!generated) throw new Error('usage: run-ledger.mjs init GENERATED [--descriptor=PATH]');
    process.stdout.write(`${initializeRun(generated, {descriptorPath: option(args, 'descriptor')})}\n`);
    return;
  }
  if (command === 'resolve') {
    const [descriptor, admitted, pods] = args;
    if (!descriptor || !admitted || !pods) throw new Error('usage: run-ledger.mjs resolve DESCRIPTOR ADMITTED_MANIFEST PODS_JSON');
    process.stdout.write(`${resolveRun(descriptor, admitted, pods)}\n`);
    return;
  }
  if (command === 'resolve-compose') {
    const [descriptor, admitted, containers] = args;
    if (!descriptor || !admitted || !containers) {
      throw new Error('usage: run-ledger.mjs resolve-compose DESCRIPTOR ADMITTED_COMPOSE CONTAINERS_INSPECTED');
    }
    process.stdout.write(`${resolveComposeRun(descriptor, admitted, containers)}\n`);
    return;
  }
  if (command === 'append') {
    const [descriptor, type, payloadJson] = args;
    if (!descriptor || !type || !payloadJson) throw new Error('usage: run-ledger.mjs append DESCRIPTOR TYPE PAYLOAD_JSON [--at=TIMESTAMP]');
    process.stdout.write(`${appendRunEvent(descriptor, type, JSON.parse(payloadJson), {occurredAt: option(args, 'at')}).timeline.length}\n`);
    return;
  }
  if (command === 'finalize') {
    const [descriptor, status] = args;
    if (!descriptor || !status) throw new Error('usage: run-ledger.mjs finalize DESCRIPTOR passed|failed|aborted');
    process.stdout.write(`${finalizeRun(descriptor, status).integrity.digest}\n`);
    return;
  }
  if (command === 'export') {
    const [descriptor, destination] = args;
    if (!descriptor || !destination) throw new Error('usage: run-ledger.mjs export DESCRIPTOR DESTINATION');
    process.stdout.write(`${exportRun(descriptor, destination)}\n`);
    return;
  }
  if (command === 'context') {
    const [descriptor, namespace, network] = args;
    if (!descriptor || !namespace || !network) throw new Error('usage: run-ledger.mjs context DESCRIPTOR NAMESPACE NETWORK');
    process.stdout.write(`${JSON.stringify(runContext(descriptor, namespace, network), null, 2)}\n`);
    return;
  }
  if (command === 'locate') {
    process.stdout.write(`${locateRun(option(args, 'target'), option(args, 'namespace'), option(args, 'network'))}\n`);
    return;
  }
  throw new Error('commands: init, resolve, append, finalize, export, context, locate');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`run ledger: ${error.message}\n`);
    process.exitCode = 1;
  }
}
