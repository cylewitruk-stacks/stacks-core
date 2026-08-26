#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {renderObservability} from '../../../../observability/render.mjs';
import {A8_ARTIFACTS, validateA8LiveQualification} from '../evidence.mjs';
import {isMainModule, isMaterializedSource, runMaterializedEntrypoint} from '../qualified-source.mjs';
import {requireA8QualifiedTree} from '../verify.mjs';
import {candidateRuntimeImageIDs, validateCandidateBuildReceipt} from './candidate-build.mjs';

const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
const networkName = 'a8-qualification';
const namespace = 'hacknet-system';
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
const candidateBuildAnnotation = 'attacknet-build';
const sourceLossActor = 'follower-1';
const sourceLossChild = 'a8-source-loss-execution-source-loss';
const terminalPhases = new Set(['Passed', 'Failed', 'Inconclusive']);
const runCases = Object.freeze([
  {name: 'a8-protocol-violation', file: 'violation-run.yaml', artifact: A8_ARTIFACTS.violationRun},
  {name: 'a8-source-loss', file: 'source-loss-run.yaml', artifact: A8_ARTIFACTS.sourceLossRun, sourceLoss: true},
  {name: 'a8-stacks-trigger', file: 'stacks-trigger-run.yaml', artifact: A8_ARTIFACTS.stacksTriggerRun},
  {name: 'a8-baseline', file: 'baseline-run.yaml', artifact: A8_ARTIFACTS.baselineRun, retain: true},
]);
const templateFiles = Object.freeze(['benign-template.yaml', 'source-loss-template.yaml']);
const chaosKinds = Object.freeze(['networkchaos', 'podchaos', 'dnschaos', 'iochaos', 'timechaos', 'stresschaos']);

function fail(message) {
  throw new Error(message);
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestFile(path) {
  return digestBytes(readFileSync(path));
}

function sealTeardownInventory(root) {
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const archivePath = relative(root, path);
      if (archivePath === 'inventory.json') continue;
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) entries.push({
        path: archivePath, digest: digestFile(path), size: statSync(path).size,
      });
      else fail(`unsupported teardown evidence entry ${archivePath}`);
    }
  };
  visit(root);
  if (entries.length === 0) fail('teardown evidence tree is empty');
  writeJSON(join(root, 'inventory.json'), {
    schemaVersion: 'stacks-attacknet-a8-teardown-inventory/v1', entries,
  });
}

function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function command(executable, arguments_, {
  input, allowFailure = false, timeout = 120_000, cwd = repositoryRoot,
} = {}) {
  const result = spawnSync(executable, arguments_, {
    cwd, encoding: 'utf8', input, timeout, maxBuffer: 64 << 20,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result;
}

function parsedCommand(executable, arguments_, options) {
  const result = command(executable, arguments_, options);
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    fail(`${executable} ${arguments_.join(' ')} did not return JSON: ${error.message}`);
  }
}

function kubectl(arguments_, options) {
  return command(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, options);
}

function kubectlJSON(arguments_) {
  const result = kubectl([...arguments_, '-o', 'json']);
  return JSON.parse(result.stdout);
}

function optionalJSON(kind, name) {
  const result = kubectl(['-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json']);
  return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
}

function waitFor(label, read, predicate, timeoutSeconds = 300) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = read();
    if (predicate(last)) return last;
    sleep(1000);
  }
  fail(`${label} did not converge within ${timeoutSeconds}s: ${JSON.stringify(last?.status ?? last)}`);
}

/** Require the source-loss campaign to remain inside its intervention window. */
export function observesActiveFaultCampaign(campaign) {
  const phase = campaign?.status?.phase;
  if (terminalPhases.has(phase)) {
    fail(`source-loss campaign became ${phase} before Service withdrawal`);
  }
  return phase === 'Running';
}

function requireImmutableDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable sha256 digest`);
  return value;
}

function normalizeImageID(value, label) {
  return requireImmutableDigest(String(value ?? '').replace(/^.*@(?=sha256:)/, ''), label);
}

function assertCleanQualificationScope() {
  const resources = [
    ['stacksnetwork.testing.stacks.org', networkName],
    ['burnchainpolicy.testing.stacks.org', networkName],
    ['faultcampaign.testing.stacks.org', 'a8-benign-delay'],
    ['faultcampaign.testing.stacks.org', 'a8-observation-source-loss'],
    ...runCases.map(value => ['attacknetrun.testing.stacks.org', value.name]),
  ];
  const existing = resources.filter(([kind, name]) => optionalJSON(kind, name));
  if (existing.length > 0) fail(`qualification scope is not clean: ${existing.map(value => value.join('/')).join(', ')}`);
}

function submit(attacknet, file) {
  command(attacknet, ['submit', '--file', join(qualificationDirectory, file), '--namespace', namespace, '--output', 'json']);
}

function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', kind, name], {allowFailure: true, timeout: 180_000});
  if (result.status !== 0 && !String(result.stderr).includes('not found')) {
    fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
  }
}

function waitForNetwork() {
  return waitFor('A8 StacksNetwork', () => optionalJSON('stacksnetwork.testing.stacks.org', networkName), value =>
    value?.status?.phase === 'Ready'
      && value.status.inventoryReady === true
      && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.inventoryDigest ?? ''), 600);
}

function applyObservability(network, runOperatorTarget) {
  const resources = renderObservability(network, {runOperatorTarget});
  kubectl(['apply', '-f', '-'], {input: JSON.stringify(resources), timeout: 180_000});
  for (const item of resources.items.filter(item => ['Deployment', 'StatefulSet', 'DaemonSet'].includes(item.kind))) {
    kubectl(['-n', namespace, 'rollout', 'status', `${item.kind.toLowerCase()}/${item.metadata.name}`, '--timeout=300s'], {timeout: 330_000});
  }
  return resources;
}

function policyProbePod(name, image, nodeName, labels, host, expectReachable) {
  const script = expectReachable
    ? 'import socket; socket.create_connection(("' + host + '",3100),3).close()'
    : 'import socket,sys\ntry: socket.create_connection(("' + host + '",3100),3).close()\nexcept OSError: sys.exit(0)\nsys.exit(9)';
  return {
    apiVersion: 'v1', kind: 'Pod', metadata: {name, namespace, labels},
    spec: {
      restartPolicy: 'Never', automountServiceAccountToken: false, nodeName,
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: 'RuntimeDefault'}},
      containers: [{
        name: 'probe', image, imagePullPolicy: 'IfNotPresent', command: ['python3', '-c', script],
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ['ALL']}},
        resources: {requests: {cpu: '5m', memory: '16Mi'}, limits: {cpu: '100m', memory: '64Mi'}},
      }],
    },
  };
}

function proveLokiIngressIsolation(resources) {
  const byName = (kind, component) => resources.items.find(item => item.kind === kind
    && item.metadata?.labels?.['app.kubernetes.io/name'] === `attacknet-${component}`);
  const service = byName('Service', 'loki');
  const events = kubectlJSON(['-n', namespace, 'get', 'pods', '-l', `app.kubernetes.io/name=attacknet-events,testing.stacks.org/network=${networkName}`]).items;
  if (!service || events.length !== 1 || !events[0].spec?.nodeName) fail('Loki policy control cannot resolve its trusted source resources');
  const image = events[0].spec.containers?.find(container => container.name === 'events')?.image;
  if (!image) fail('Loki policy control cannot reuse the admitted Python image');
  const common = {'app.kubernetes.io/part-of': 'stacks-attacknet', 'testing.stacks.org/network': networkName};
  const cases = [
    {name: 'a8-loki-policy-allowed', labels: {...common, 'testing.stacks.org/loki-writer': 'true'}, reachable: true},
    {name: 'a8-loki-policy-denied', labels: {...common, 'app.kubernetes.io/name': 'attacknet-adversary'}, reachable: false},
  ];
  const outcomes = [];
  try {
    for (const value of cases) {
      kubectl(['apply', '-f', '-'], {input: JSON.stringify(policyProbePod(
        value.name, image, events[0].spec.nodeName, value.labels, service.metadata.name, value.reachable,
      ))});
      const pod = waitFor(`Loki ${value.name} control`, () => optionalJSON('pod', value.name), current =>
        ['Succeeded', 'Failed'].includes(current?.status?.phase), 90);
      const terminated = pod.status?.containerStatuses?.find(status => status.name === 'probe')?.state?.terminated;
      if (pod.status.phase !== 'Succeeded' || terminated?.exitCode !== 0) {
        fail(`Loki ${value.reachable ? 'allowed' : 'denied'} ingress control failed: ${JSON.stringify(pod.status)}`);
      }
      outcomes.push({name: value.name, podUID: pod.metadata.uid, expectedReachable: value.reachable, phase: pod.status.phase, exitCode: terminated.exitCode});
    }
  } finally {
    for (const value of cases) kubectl(['-n', namespace, 'delete', 'pod', value.name, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  }
  return {
    schemaVersion: 'stacks-attacknet-a8-loki-ingress-control/v1',
    service: service.metadata.name, networkPolicy: byName('NetworkPolicy', 'loki')?.metadata?.name,
    observedAt: new Date().toISOString(), outcomes,
  };
}

/** Bind one Ready candidate container to its exact locally built image. */
export function candidateContainerIdentity(
  pod, containerName, purpose, expectedRuntimeImageID, expectedBuildIndex = undefined,
) {
  const status = pod.status?.containerStatuses?.find(value => value.name === containerName);
  if (!status?.ready) fail(`the ${containerName} container must be Ready`);
  const runtimeImageID = normalizeImageID(status.imageID, `${containerName} runtime image ID`);
  const buildIndex = pod.metadata?.annotations?.[candidateBuildAnnotation];
  if (runtimeImageID !== expectedRuntimeImageID
    || (expectedBuildIndex && buildIndex !== expectedBuildIndex)) {
    fail(`the live ${containerName} does not match the expected candidate image`);
  }
  return {
    purpose, pod: pod.metadata.name, podUID: pod.metadata.uid, container: containerName,
    requestedImage: pod.spec?.containers?.find(value => value.name === containerName)?.image,
    runtimeImageID, expectedRuntimeImageID,
    ...(expectedBuildIndex ? {buildIndex} : {}),
  };
}

function oneCandidateContainer(
  selector, container, purpose, expectedRuntimeImageID, expectedBuildIndex = undefined,
) {
  const pods = kubectlJSON(['-n', namespace, 'get', 'pods', '-l', selector]).items;
  const ready = pods.filter(pod => pod.status?.containerStatuses?.some(
    status => status.name === container && status.ready,
  ));
  if (ready.length !== 1) fail(`exactly one Ready ${container} Pod is required`);
  return candidateContainerIdentity(ready[0], container, purpose, expectedRuntimeImageID, expectedBuildIndex);
}

function indexedImages(images, label) {
  if (!Array.isArray(images)) fail(`${label} does not contain images`);
  const result = new Map();
  for (const image of images) {
    if (!image?.purpose || result.has(image.purpose)) {
      fail(`${label} contains an unknown or duplicate image purpose`);
    }
    const id = image.id ?? image.immutableID;
    result.set(image.purpose, requireImmutableDigest(id, `${label} ${image.purpose} image ID`));
  }
  return result;
}

function buildAndInstallCandidate(qualifiedTree, outputDirectory) {
  requireA8QualifiedTree(qualifiedTree);
  const temporary = mkdtempSync(join(tmpdir(), 'attacknet-a8-candidate-'));
  const attacknet = join(temporary, 'attacknet');
  try {
    command('go', ['build', '-o', attacknet, './cmd/attacknet'], {
      cwd: operatorDirectory, timeout: 300_000,
    });
    const build = parsedCommand(attacknet, [
      'image', 'build', '--repo-root', repositoryRoot, '--stacks', '--skip-stacker',
    ], {
      timeout: 1_800_000,
    });
    const install = parsedCommand(attacknet, [
      'install', 'local', '--chart-dir', chartDirectory, '--namespace', namespace,
      '--release', 'hacknet', '--kind-image-load', 'require',
    ], {timeout: 900_000});
    const built = indexedImages(build.images, 'candidate build');
    const actorImage = build.images.find(image => image.purpose === 'stacks-core');
    const actorImageLoad = parsedCommand(attacknet, [
      'image', 'load', '--mode', 'require', actorImage.ref,
    ], {timeout: 900_000});
    requireA8QualifiedTree(qualifiedTree);
    const receipt = {
      schemaVersion: 'stacks-attacknet-a8-candidate-build/v1', qualifiedTree,
      capturedAt: new Date().toISOString(), build, install, actorImageLoad,
      actorImage: {
        purpose: actorImage.purpose, ref: actorImage.ref, immutableID: built.get('stacks-core'),
      },
      runOperatorImageID: built.get('run-operator'),
    };
    validateCandidateBuildReceipt(receipt, qualifiedTree);
    writeJSON(join(outputDirectory, A8_ARTIFACTS.candidateBuild), receipt);
    return {attacknet, receipt, cleanup: () => rmSync(temporary, {recursive: true, force: true})};
  } catch (error) {
    rmSync(temporary, {recursive: true, force: true});
    throw error;
  }
}

function candidateRuntimeIdentities(buildReceipt) {
  const build = indexedImages(buildReceipt.build.images, 'candidate build');
  const runtime = candidateRuntimeImageIDs(buildReceipt, buildReceipt.qualifiedTree);
  const containers = [
    oneCandidateContainer(
      'app.kubernetes.io/component=operator', 'operator', 'topology-operator',
      runtime.get('topology-operator'), build.get('topology-operator'),
    ),
    oneCandidateContainer(
      'app.kubernetes.io/component=run-operator', 'run-operator', 'run-operator',
      runtime.get('run-operator'), build.get('run-operator'),
    ),
    oneCandidateContainer(
      `app.kubernetes.io/component=burnchain-clock,testing.stacks.org/network=${networkName}`,
      'clock', 'burnchain-clock', runtime.get('burnchain-clock'),
    ),
  ];
  const actorPods = kubectlJSON([
    '-n', namespace, 'get', 'pods', '-l', `testing.stacks.org/network=${networkName}`,
  ]).items.filter(pod => pod.metadata?.labels?.['testing.stacks.org/actor']);
  if (actorPods.length !== 3) fail('candidate runtime requires exactly three admitted actor Pods');
  for (const pod of actorPods) {
    containers.push(candidateContainerIdentity(pod, 'attacknet-probe', 'probe', runtime.get('probe')));
    if (pod.metadata.labels['testing.stacks.org/role'] === 'follower') {
      containers.push(candidateContainerIdentity(pod, 'actor', 'stacks-core', runtime.get('stacks-core')));
    }
  }
  return {
    schemaVersion: 'stacks-attacknet-a8-candidate-runtime/v1',
    capturedAt: new Date().toISOString(), containers,
    builtButNotRunning: ['io-pressure'],
  };
}

function captureRun(attacknet, value, qualifiedTree, outputDirectory) {
  submit(attacknet, value.file);
  const terminal = waitForRun(value.name);
  snapshotRun(attacknet, value, qualifiedTree, outputDirectory);
  if (!value.retain) deleteResource(attacknet, 'AttacknetRun', value.name);
  return terminal;
}

function waitForRun(name, timeoutSeconds = 360) {
  return waitFor(`AttacknetRun ${name}`, () => optionalJSON('attacknetrun.testing.stacks.org', name), run =>
    terminalPhases.has(run?.status?.phase) && run.status.observedGeneration === run.metadata.generation, timeoutSeconds);
}

function snapshotRun(attacknet, value, qualifiedTree, outputDirectory) {
  const output = join(outputDirectory, value.artifact);
  mkdirSync(dirname(output), {recursive: true});
  command(attacknet, ['evidence', 'snapshot', '--namespace', namespace, '--output', output, 'AttacknetRun', value.name]);
  const snapshot = JSON.parse(readFileSync(output, 'utf8'));
  writeJSON(output, {qualifiedTree, ...snapshot});
}

function topologyDeployment() {
  const deployments = kubectlJSON([
    '-n', namespace, 'get', 'deployments',
    '-l', 'app.kubernetes.io/component=operator',
  ]).items;
  if (deployments.length !== 1 || deployments[0].spec?.replicas !== 1
    || deployments[0].status?.readyReplicas !== 1) {
    fail('source-loss control requires exactly one Ready single-replica topology operator');
  }
  return deployments[0];
}

function scaleTopology(name, replicas) {
  kubectl(['-n', namespace, 'scale', `deployment/${name}`, `--replicas=${replicas}`]);
  return waitFor(`topology deployment ${name} replicas=${replicas}`,
    () => optionalJSON('deployment', name), value => value?.spec?.replicas === replicas
      && (value.status?.replicas ?? 0) === replicas
      && (replicas === 0 || value.status?.readyReplicas === replicas), 180);
}

function ownedMetricsService(actor, networkUID) {
  const name = `${networkName}-${actor}`;
  const service = optionalJSON('service', name);
  if (!service || !service.metadata?.ownerReferences?.some(owner => owner.uid === networkUID)
    || !service.spec?.ports?.some(port => port.port === 20446)) {
    fail(`source-loss control requires the topology-owned metrics Service ${name}`);
  }
  return service;
}

function captureSourceLossRun(attacknet, value, qualifiedTree, outputDirectory) {
  submit(attacknet, value.file);
  const child = waitFor(`FaultCampaign ${sourceLossChild}`,
    () => optionalJSON('faultcampaign.testing.stacks.org', sourceLossChild),
    observesActiveFaultCampaign, 120);
  const beforeNetwork = networkIdentity();
  const deployment = topologyDeployment();
  const beforeService = ownedMetricsService(sourceLossActor, beforeNetwork.uid);
  const control = {
    schemaVersion: 'stacks-attacknet-a8-source-loss-control/v1',
    control: 'topology-paused-service-withdrawal', actor: sourceLossActor,
    faultOracle: {
      childCampaign: child.metadata.name, childUID: child.metadata.uid,
      phase: child.status.phase, activeObservedAt: new Date().toISOString(),
    },
    topology: {
      deployment: deployment.metadata.name, deploymentUID: deployment.metadata.uid,
      originalReplicas: deployment.spec.replicas,
    },
    service: {name: beforeService.metadata.name, beforeUID: beforeService.metadata.uid},
    network: {before: beforeNetwork},
  };
  let terminal;
  let operationError;
  try {
    scaleTopology(deployment.metadata.name, 0);
    control.topology.pausedAt = new Date().toISOString();
    kubectl(['-n', namespace, 'delete', 'service', beforeService.metadata.name, '--wait=true', '--timeout=60s']);
    waitFor(`metrics Service ${beforeService.metadata.name} withdrawal`,
      () => optionalJSON('service', beforeService.metadata.name), service => service === undefined, 60);
    control.service.deletedAt = new Date().toISOString();
    terminal = waitForRun(value.name, 90);
    control.run = {
      name: terminal.metadata.name,
      uid: terminal.metadata.uid,
      generation: terminal.metadata.generation,
      resourceVersion: terminal.metadata.resourceVersion,
    };
    control.runPhase = terminal.status.phase;
    control.runCompletedAt = terminal.status.completedAt ?? terminal.status.finishedAt;
    snapshotRun(attacknet, value, qualifiedTree, outputDirectory);
  } catch (error) {
    operationError = error;
  }
  let restorationError;
  try {
    scaleTopology(deployment.metadata.name, deployment.spec.replicas);
    const restoredService = waitFor(`metrics Service ${beforeService.metadata.name} restoration`,
      () => optionalJSON('service', beforeService.metadata.name), service => service !== undefined, 180);
    const afterNetwork = networkIdentity();
    control.topology.restoredReplicas = deployment.spec.replicas;
    control.topology.restoredAt = new Date().toISOString();
    control.service.restoredUID = restoredService.metadata.uid;
    control.service.restoredAt = new Date().toISOString();
    control.network.after = afterNetwork;
  } catch (error) {
    restorationError = error;
  }
  if (operationError || restorationError) {
    const messages = [operationError, restorationError].filter(Boolean).map(error => error.message);
    fail(`source-loss control failed: ${messages.join('; ')}`);
  }
  deleteResource(attacknet, 'AttacknetRun', value.name);
  return {terminal, control};
}

function networkIdentity() {
  const network = optionalJSON('stacksnetwork.testing.stacks.org', networkName);
  if (!network) fail('the A8 network is absent');
  return {uid: network.metadata.uid, inventoryDigest: network.status?.inventoryDigest};
}

function lokiWorkload(resources) {
  const loki = resources.items.find(item => item.kind === 'StatefulSet'
    && item.metadata.labels?.['app.kubernetes.io/name'] === 'attacknet-loki');
  if (!loki) fail('the rendered observability stack has no Loki StatefulSet');
  return loki.metadata.name;
}

function proveFailedTeardown(attacknet, qualifiedTree, outputDirectory, resources) {
  const name = lokiWorkload(resources);
  kubectl(['-n', namespace, 'scale', `statefulset/${name}`, '--replicas=0']);
  waitFor('Loki scale-down', () => kubectlJSON(['-n', namespace, 'get', 'pods', '-l', 'app.kubernetes.io/name=attacknet-loki']), value => value.items.length === 0, 180);
  const before = networkIdentity();
  const partialDirectory = join(outputDirectory, 'teardown-failure-partial');
  const result = command(attacknet, [
    'teardown', '--namespace', namespace, '--output', partialDirectory,
    '--run', 'a8-baseline', networkName,
  ], {allowFailure: true, timeout: 180_000});
  if (result.status === 0) fail('teardown unexpectedly succeeded while Loki was unavailable');
  const after = networkIdentity();
  const partialMetadata = join(partialDirectory, 'loki', 'export.json');
  let partialExport = {complete: false, failure: String(result.stderr || result.stdout).trim()};
  try {
    partialExport = JSON.parse(readFileSync(partialMetadata, 'utf8'));
  } catch {
    // Source discovery can fail before the exporter has a metadata path. The
    // command failure and preserved network identity remain the proof.
  }
  writeJSON(join(outputDirectory, A8_ARTIFACTS.teardownFailure), {
    schemaVersion: 'stacks-attacknet-a8-teardown-failure/v1', qualifiedTree,
    commandFailed: true, networkPreserved: true, before, after, partialExport,
    stderrDigest: digestBytes(result.stderr || result.stdout),
  });
  kubectl(['-n', namespace, 'scale', `statefulset/${name}`, '--replicas=1']);
  kubectl(['-n', namespace, 'rollout', 'status', `statefulset/${name}`, '--timeout=300s'], {timeout: 330_000});
}

function successfulTeardown(attacknet, qualifiedTree, outputDirectory) {
  const output = join(outputDirectory, 'teardown-success');
  command(attacknet, [
    'teardown', '--namespace', namespace, '--output', output,
    '--run', 'a8-baseline', networkName,
  ], {timeout: 300_000});
  const manifestPath = join(outputDirectory, A8_ARTIFACTS.teardownManifest);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  writeJSON(manifestPath, {qualifiedTree, manifest});
  sealTeardownInventory(output);
}

function deleteObservability(resources) {
  kubectl(['delete', '--ignore-not-found', '-f', '-'], {input: JSON.stringify(resources), timeout: 180_000});
}

function filteredCount(kind, predicate) {
  const value = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (value.status !== 0 || !value.stdout.trim()) return 0;
  return JSON.parse(value.stdout).items.filter(predicate).length;
}

function cleanup(attacknet, resources, qualifiedTree, outputDirectory) {
  deleteResource(attacknet, 'AttacknetRun', 'a8-baseline');
  for (const name of ['a8-benign-delay', 'a8-observation-source-loss']) deleteResource(attacknet, 'FaultCampaign', name);
  deleteResource(attacknet, 'BurnchainPolicy', networkName);
  deleteObservability(resources);
  const byNetwork = item => item.metadata?.labels?.['testing.stacks.org/network'] === networkName
    || item.spec?.networkRef === networkName;
  const remainingCounts = {
    networks: optionalJSON('stacksnetwork.testing.stacks.org', networkName) ? 1 : 0,
    runs: filteredCount('attacknetruns.testing.stacks.org', byNetwork),
    campaigns: filteredCount('faultcampaigns.testing.stacks.org', byNetwork),
    chaos: chaosKinds.reduce((sum, kind) => sum + filteredCount(kind, byNetwork), 0),
    pods: filteredCount('pods', byNetwork),
    pvcs: filteredCount('persistentvolumeclaims', byNetwork),
  };
  writeJSON(join(outputDirectory, A8_ARTIFACTS.cleanTeardown), {
    schemaVersion: 'stacks-attacknet-a8-clean-teardown/v1', qualifiedTree,
    completed: Object.values(remainingCounts).every(value => value === 0), remainingCounts,
    observedAt: new Date().toISOString(),
  });
}

function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  if (!context.startsWith('kind-') || nodes.length !== 3
    || nodes.some(node => node.status?.nodeInfo?.architecture !== 'arm64')) {
    fail('A8 requires the supported three-node arm64 kind profile');
  }
  return {provider: 'kind', architecture: 'arm64', nodes: 3, context};
}

function qualificationArtifacts(outputDirectory) {
  const result = {};
  for (const [key, path] of Object.entries(A8_ARTIFACTS)) {
    if (['candidateDiff', 'verification', 'attacknetCheck', 'hacknetCheck', 'liveQualification'].includes(key)) continue;
    const absolute = join(outputDirectory, path);
    if (!statSync(absolute).isFile()) fail(`qualification artifact ${path} is absent`);
    result[key] = {path, digest: digestFile(absolute)};
  }
  return result;
}

/** Run A8 live qualification once against an image built from the qualified tree. */
export function runQualification({
  qualifiedTree, outputDirectory, runOperatorTarget = 'hacknet-run:8080',
}) {
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree ?? '')) fail('qualified tree must be a full Git tree SHA');
  if (!outputDirectory) fail('outputDirectory is required');
  prepareQualificationOutput(outputDirectory);

  let candidate;
  let observability;
  try {
    const cluster = clusterProfile();
    candidate = buildAndInstallCandidate(qualifiedTree, outputDirectory);
    const {attacknet} = candidate;
    assertCleanQualificationScope();
    submit(attacknet, 'burnchain-policy.yaml');
    submit(attacknet, 'network.yaml');
    const network = waitForNetwork();
    const runtime = candidateRuntimeIdentities(candidate.receipt);
    observability = applyObservability(network, runOperatorTarget);
    const lokiIngressControl = proveLokiIngressIsolation(observability);
    for (const file of templateFiles) submit(attacknet, file);
    let sourceLossControl;
    for (const value of runCases) {
      if (value.sourceLoss) {
        sourceLossControl = captureSourceLossRun(attacknet, value, qualifiedTree, outputDirectory).control;
      } else {
        captureRun(attacknet, value, qualifiedTree, outputDirectory);
      }
    }
    proveFailedTeardown(attacknet, qualifiedTree, outputDirectory, observability);
    successfulTeardown(attacknet, qualifiedTree, outputDirectory);
    cleanup(attacknet, observability, qualifiedTree, outputDirectory);
    const result = {
      schemaVersion: 'stacks-attacknet-a8-live-qualification/v1', qualifiedTree,
      outcome: 'Passed', capturedAt: new Date().toISOString(), cluster,
      candidateRuntime: runtime, sourceLossControl, lokiIngressControl,
      artifacts: qualificationArtifacts(outputDirectory),
    };
    writeJSON(join(outputDirectory, A8_ARTIFACTS.liveQualification), result);
    validateA8LiveQualification(result, qualifiedTree, outputDirectory);
    return result;
  } catch (error) {
    writeJSON(join(outputDirectory, 'qualification-failure.json'), {
      schemaVersion: 'stacks-attacknet-a8-qualification-failure/v1', qualifiedTree,
      failedAt: new Date().toISOString(), message: error.message,
    });
    throw error;
  } finally {
    candidate?.cleanup();
  }
}

function statExists(path) {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

/** Preserve offline verification while refusing to overwrite live evidence. */
export function prepareQualificationOutput(outputDirectory) {
  if (statExists(outputDirectory) && !statSync(outputDirectory).isDirectory()) {
    fail('A8 qualification output must be a directory');
  }
  mkdirSync(outputDirectory, {recursive: true, mode: 0o700});
  const livePaths = [
    ...Object.entries(A8_ARTIFACTS)
      .filter(([key]) => !['candidateDiff', 'verification', 'attacknetCheck', 'hacknetCheck'].includes(key))
      .map(([, path]) => path),
    'qualification-failure.json',
    'teardown-failure-partial',
  ];
  const existing = livePaths.filter(path => statExists(join(outputDirectory, path)));
  if (existing.length > 0) {
    fail(`refusing to overwrite existing A8 live evidence: ${existing.join(', ')}`);
  }
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = [
    '--qualified-tree=', '--output=', '--run-operator-target=',
  ];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  for (const required of ['--qualified-tree=', '--output=']) {
    if (!value(required)) fail(`${required.slice(2, -1)} is required`);
  }
  if (!isMaterializedSource(repositoryRoot)) {
    const qualifiedTree = value('--qualified-tree=');
    const forwarded = [
      `--qualified-tree=${qualifiedTree}`,
      `--output=${resolve(value('--output='))}`,
    ];
    const target = value('--run-operator-target=');
    if (target) forwarded.push(`--run-operator-target=${target}`);
    runMaterializedEntrypoint({
      repositoryRoot,
      qualifiedTree,
      script: 'contrib/attacknet/release/amendments/a8/qualification/live.mjs',
      arguments_: forwarded,
    });
    return;
  }
  runQualification({
    qualifiedTree: value('--qualified-tree='),
    outputDirectory: resolve(value('--output=')),
    runOperatorTarget: value('--run-operator-target=') ?? 'hacknet-run:8080',
  });
}

if (isMainModule(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
