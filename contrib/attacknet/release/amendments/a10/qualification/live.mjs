#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {
  A10_ARTIFACTS, A10_STORAGE_MINIMUM_AVAILABLE_BYTES, validateA10Campaign,
  validateA10NegativeControl, validateA10Network, validateA10Policy, validateA10Run,
  validateA10StoragePreflight, validateA10Views,
} from '../evidence.mjs';
import {isMainModule, isMaterializedSource, runMaterializedEntrypoint} from '../qualified-source.mjs';
import {requireA10QualifiedTree} from '../verify.mjs';
import {validateA10CandidateBuild} from './candidate-build.mjs';

const qualificationDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(qualificationDirectory, '../../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const chartDirectory = join(repositoryRoot, 'contrib/helm/hacknet');
const storagePreflightProgram = join(repositoryRoot, 'contrib/attacknet/observability/storage-preflight.sh');
const credentialFixture = join(repositoryRoot,
  'contrib/attacknet/test/fixtures/equivalence/v1alpha1/topology/baseline-probes.input.json');
const namespace = 'hacknet-system';
/** First reward-cycle boundary after the qualification profile enables PoX-4. */
export const A10_SIGNER_SET_READY_HEIGHT = 220;
const terminal = new Set(['Passed', 'Failed', 'Inconclusive', 'Paused']);
const primary = Object.freeze({network: 'a10-qualification', policyA: 'a10-bitcoin-a', policyB: 'a10-bitcoin-b',
  template: 'a10-split-template', run: 'a10-split-view'});
const replay = Object.freeze({network: 'a10-replay', policyA: 'a10-replay-bitcoin-a', policyB: 'a10-replay-bitcoin-b',
  template: primary.template, run: 'a10-split-view-replay'});

function fail(message) { throw new Error(message); }
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
}
function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function command(executable, arguments_, {
  cwd = repositoryRoot, env = process.env, input, allowFailure = false, timeout = 180_000,
} = {}) {
  const result = spawnSync(executable, arguments_, {cwd, env, input, encoding: 'utf8', timeout, maxBuffer: 128 << 20});
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) fail(`${executable} ${arguments_.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  return result;
}
function parsed(executable, arguments_, options) {
  const result = command(executable, arguments_, options);
  try { return JSON.parse(result.stdout); }
  catch (error) { fail(`${executable} ${arguments_.join(' ')} returned invalid JSON: ${error.message}\n${result.stdout}`); }
}
function kubectl(arguments_, options) { return command(process.env.ATTACKNET_KUBECTL ?? 'kubectl', arguments_, options); }
function kubectlJSON(arguments_) { return JSON.parse(kubectl([...arguments_, '-o', 'json']).stdout); }
function optional(kind, name) {
  const result = kubectl(['-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json']);
  return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
}
function waitFor(label, read, predicate, seconds = 600) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    last = read();
    if (predicate(last)) return last;
    sleep(1000);
  }
  fail(`${label} did not converge in ${seconds}s: ${JSON.stringify(last?.status ?? last)}`);
}

function clusterProfile() {
  const context = kubectl(['config', 'current-context']).stdout.trim();
  const nodes = kubectlJSON(['get', 'nodes']).items;
  if (!context.startsWith('kind-') || nodes.length !== 3
    || nodes.some(node => node.status?.nodeInfo?.architecture !== 'arm64'
      || !node.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'))) {
    fail('A10 requires three Ready arm64 kind nodes');
  }
  return {provider: 'kind', context, architecture: 'arm64', nodes: 3};
}

function submitPath(attacknet, path) {
  return parsed(attacknet, ['submit', '--file', path, '--namespace', namespace, '--output', 'json']);
}
function submitObject(attacknet, value, executionDirectory, label) {
  const path = join(executionDirectory, `${label}.json`);
  writeJSON(path, value);
  return submitPath(attacknet, path);
}
function normalizedResource(attacknet, manifestDirectory, filename) {
  return parsed(attacknet, ['validate', '--file', join(manifestDirectory, filename), '--namespace', namespace, '--output', 'json']);
}
function deleteResource(attacknet, kind, name) {
  const result = command(attacknet, ['delete', '--namespace', namespace, '--wait', '--timeout', '10m', kind, name], {allowFailure: true, timeout: 660_000});
  if (result.status !== 0 && !`${result.stderr}${result.stdout}`.toLowerCase().includes('not found')) fail(`delete ${kind}/${name} failed: ${result.stderr || result.stdout}`);
}

function networkReady(name, expectedDigest = undefined) {
  return waitFor(`StacksNetwork ${name}`, () => optional('stacksnetwork.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.inventoryReady === true
      && value.status.observedGeneration === value.metadata.generation
      && /^sha256:[0-9a-f]{64}$/.test(value.status.inventoryDigest ?? '')
      && /^sha256:[0-9a-f]{64}$/.test(value.status.burnchainTopology?.digest ?? '')
      && (!expectedDigest || value.status.burnchainTopology.digest === expectedDigest), 1_200);
}
function policyReady(name, node) {
  return waitFor(`BurnchainPolicy ${name}`, () => optional('burnchainpolicy.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.observedGeneration === value.metadata.generation
      && value.spec?.bitcoinNodeRef === node && value.status.observedHeight >= A10_SIGNER_SET_READY_HEIGHT
      && /^sha256:[0-9a-f]{64}$/.test(value.status.appliedPolicyDigest ?? ''), 900);
}
function patchPolicy(name, patch) {
  kubectl(['-n', namespace, 'patch', 'burnchainpolicy.testing.stacks.org', name,
    '--type=merge', '-p', JSON.stringify({spec: patch})]);
}
function waitPolicyPaused(name) {
  return waitFor(`BurnchainPolicy ${name} paused`, () => optional('burnchainpolicy.testing.stacks.org', name), value =>
    value?.status?.phase === 'Ready' && value.status.observedGeneration === value.metadata.generation
      && value.spec?.paused === true, 300);
}
function pauseCadencePolicies(descriptor) {
  for (const name of [descriptor.policyA, descriptor.policyB]) patchPolicy(name, {paused: true});
  for (const name of [descriptor.policyA, descriptor.policyB]) waitPolicyPaused(name);
}
function indexed(images) { return new Map(images.map(image => [image.purpose, image])); }

function storageCapacityCheck(phase, executionDirectory) {
  const path = join(executionDirectory, `storage-${phase}.json`);
  const result = command(storagePreflightProgram, [path], {allowFailure: true,
    env: {...process.env, ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES: String(A10_STORAGE_MINIMUM_AVAILABLE_BYTES)}});
  let report;
  try { report = JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { report = {ok: false, error: `storage preflight emitted no readable report: ${error.message}`}; }
  return {phase, exitCode: result.status ?? -1, ...report};
}
function recordStoragePreflight(tree, output, checks) {
  const value = {schemaVersion: 'stacks-attacknet-a10-storage-preflight/v1', qualifiedTree: tree,
    minimumAvailableBytes: A10_STORAGE_MINIMUM_AVAILABLE_BYTES, recordedAt: new Date().toISOString(), checks};
  writeJSON(join(output, A10_ARTIFACTS.storagePreflight), value);
  return value;
}
function requireStorageCapacity(phase, tree, output, executionDirectory, checks) {
  checks.push(storageCapacityCheck(phase, executionDirectory));
  const value = recordStoragePreflight(tree, output, checks);
  if (checks.at(-1).exitCode !== 0 || checks.at(-1).ok !== true) fail(`A10 ${phase} storage preflight failed`);
  if (checks.length === 2) validateA10StoragePreflight(value, tree);
}

function buildCandidate(tree, output, executionDirectory) {
  requireA10QualifiedTree(tree);
  const attacknet = join(executionDirectory, 'attacknet');
  command('go', ['build', '-o', attacknet, './cmd/attacknet'], {cwd: operatorDirectory, timeout: 600_000});
  const build = parsed(attacknet, ['image', 'build', '--repo-root', repositoryRoot, '--stacks'], {timeout: 7_200_000});
  const install = parsed(attacknet, ['install', 'local', '--chart-dir', chartDirectory,
    '--namespace', namespace, '--release', 'hacknet', '--kind-image-load', 'require',
    '--force-crd-conflicts'], {timeout: 1_200_000});
  const byPurpose = indexed(build.images);
  const actorImages = ['stacks-core', 'stacker'].map(purpose => ({purpose,
    ref: byPurpose.get(purpose).ref, immutableID: byPurpose.get(purpose).id}));
  const actorImageLoad = parsed(attacknet, ['image', 'load', '--mode', 'require',
    ...actorImages.map(image => image.ref)], {timeout: 1_200_000});
  const receipt = {schemaVersion: 'stacks-attacknet-a10-candidate-build/v1', qualifiedTree: tree,
    capturedAt: new Date().toISOString(), build, install, actorImages, actorImageLoad,
    runOperatorImageID: byPurpose.get('run-operator').id};
  validateA10CandidateBuild(receipt, tree);
  writeJSON(join(output, A10_ARTIFACTS.candidateBuild), receipt);
  return {attacknet, receipt};
}

function waitRun(name) {
  return waitFor(`AttacknetRun ${name}`, () => optional('attacknetrun.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
      && (value.status.phase !== 'Passed' || value.status.cleanup?.completed === true), 1_500);
}
function childName(runName) { return `${runName}-execution-partition-and-reorg`; }
function waitCampaign(name) {
  return waitFor(`FaultCampaign ${name}`, () => optional('faultcampaign.testing.stacks.org', name), value =>
    terminal.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation
      && value.status.cleanup?.allRecovered === true, 900);
}
function snapshotResource(attacknet, kind, name, path, tree) {
  mkdirSync(dirname(path), {recursive: true});
  command(attacknet, ['evidence', 'snapshot', '--namespace', namespace, '--output', path, kind, name]);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  writeJSON(path, {qualifiedTree: tree, ...value});
  return JSON.parse(readFileSync(path, 'utf8'));
}

function actorStatus(network, actor) {
  const current = optional('stacksnetwork.testing.stacks.org', network);
  const status = current?.status?.actors?.find(item => item.name === actor);
  if (!status?.podName || !status.podUID || !status.runtimeImageID) fail(`${network}/${actor} has no admitted identity`);
  return {network: current, status};
}
function normalizedImageID(value) {
  const match = String(value ?? '').match(/sha256:[0-9a-f]{64}$/);
  return match?.[0] ?? '';
}
function actorIdentity(network, actor) {
  const admitted = actorStatus(network, actor);
  const generation = admitted.network.metadata?.generation;
  if (!Number.isSafeInteger(generation) || generation < 1
    || admitted.network.status?.phase !== 'Ready'
    || admitted.network.status?.inventoryReady !== true
    || admitted.network.status?.observedGeneration !== generation
    || admitted.network.status?.burnchainTopology?.observedGeneration !== generation) {
    fail(`${network}/${actor} network generation is not fully observed`);
  }
  const pod = optional('pod', admitted.status.podName);
  const container = pod?.status?.containerStatuses?.find(item => item.name === 'actor');
  const runtimeImageID = normalizedImageID(admitted.status.runtimeImageID);
  if (pod?.metadata?.uid !== admitted.status.podUID || normalizedImageID(container?.imageID) !== runtimeImageID) {
    fail(`${network}/${actor} live Pod identity differs from admitted status`);
  }
  return {networkUID: admitted.network.metadata.uid,
    networkGeneration: generation,
    inventoryDigest: admitted.network.status.inventoryDigest,
    topologyDigest: admitted.network.status.burnchainTopology?.digest,
    podName: admitted.status.podName, podUID: admitted.status.podUID, runtimeImageID};
}
function sameActorIdentity(before, after) {
  return ['networkUID', 'networkGeneration', 'inventoryDigest', 'topologyDigest', 'podName', 'podUID', 'runtimeImageID']
    .every(field => before[field] === after[field]);
}
function bitcoinCLI(podName, arguments_) {
  return parsed(process.env.ATTACKNET_KUBECTL ?? 'kubectl', ['-n', namespace, 'exec', podName, '-c', 'actor', '--',
    'bitcoin-cli', '-regtest', '-rpcuser=devnet', '-rpcpassword=devnet', ...arguments_]);
}
function bitcoinInfo(network, actor) {
  const before = actorIdentity(network, actor);
  const info = bitcoinCLI(before.podName, ['getblockchaininfo']);
  const tips = bitcoinCLI(before.podName, ['getchaintips']);
  const peers = bitcoinCLI(before.podName, ['getpeerinfo']);
  const after = actorIdentity(network, actor);
  if (!sameActorIdentity(before, after)) fail(`${network}/${actor} identity changed during Bitcoin observation`);
  return {actor, ...before, chain: info.chain, blocks: info.blocks, headers: info.headers,
    bestblockhash: info.bestblockhash, chainwork: info.chainwork,
    tips: tips.map(tip => ({height: tip.height, hash: tip.hash, branchlen: tip.branchlen, status: tip.status})),
    peers: peers.map(peer => ({id: peer.id, addr: peer.addr, inbound: peer.inbound,
      connection_type: peer.connection_type, last_block: peer.last_block, last_transaction: peer.last_transaction})),
    evidenceClass: 'actor_self_reported'};
}
function stacksInfo(network, actor, bitcoinNodeRef) {
  const before = actorIdentity(network, actor);
  const result = kubectl(['get', '--raw', `/api/v1/namespaces/${namespace}/pods/${before.podName}:20443/proxy/v2/info`]);
  const info = JSON.parse(result.stdout);
  const after = actorIdentity(network, actor);
  if (!sameActorIdentity(before, after)) fail(`${network}/${actor} identity changed during Stacks observation`);
  return {actor, bitcoinNodeRef, ...before,
    burnBlockHeight: info.burn_block_height, burnConsensusHash: info.pox_consensus,
    stacksTipHeight: info.stacks_tip_height, evidenceClass: 'actor_self_reported'};
}
function captureViews(network, tree) {
  const value = waitFor(`${network} exact Bitcoin and Stacks convergence`, () => {
    const resource = optional('stacksnetwork.testing.stacks.org', network);
    const bitcoin = ['bitcoin-a', 'bitcoin-b'].map(actor => bitcoinInfo(network, actor));
    const stacks = [stacksInfo(network, 'follower-1', 'bitcoin-a'), stacksInfo(network, 'follower-b', 'bitcoin-b')];
    return {resource, bitcoin, stacks};
  }, current => current.bitcoin[0].bestblockhash === current.bitcoin[1].bestblockhash
      && current.stacks.every(item => item.burnBlockHeight === current.bitcoin.find(bitcoin => bitcoin.actor === item.bitcoinNodeRef)?.blocks)
      && current.stacks[0].burnConsensusHash === current.stacks[1].burnConsensusHash, 600);
  const result = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a10-node-views/v1',
    observedAt: new Date().toISOString(), network: {name: network, uid: value.resource.metadata.uid,
      observedGeneration: value.resource.status.observedGeneration,
      inventoryDigest: value.resource.status.inventoryDigest,
      topologyDigest: value.resource.status.burnchainTopology.digest},
    bitcoin: value.bitcoin, stacks: value.stacks};
  validateA10Views(result, tree, network);
  return result;
}

function chaosMutationCount(campaignName) {
  const kinds = ['networkchaos', 'podchaos', 'dnschaos', 'iochaos', 'timechaos', 'stresschaos'];
  return kinds.reduce((total, kind) => {
    const result = kubectl(['-n', namespace, 'get', kind, '-l', `testing.stacks.org/campaign=${campaignName}`, '-o', 'json'], {allowFailure: true});
    return total + (result.status === 0 ? JSON.parse(result.stdout).items.length : 0);
  }, 0);
}

function negativeControl(attacknet, manifestDirectory, executionDirectory, tree, output) {
  const current = networkReady(primary.network);
  const originalDigest = current.status.burnchainTopology.digest;
  const campaign = {apiVersion: 'testing.stacks.org/v1beta1', kind: 'FaultCampaign',
    metadata: {name: 'a10-topology-drift', namespace}, spec: {networkRef: primary.network,
      safety: {maxUnavailableSignerBasisPoints: 0, maxUnavailableMinerBasisPoints: 0,
        maxConcurrentFaults: 1, allowUnenrolledNetworkTargets: false, allowBurnchain: true}, stages: [{id: 'delayed-partition',
        trigger: {afterCampaignStart: '30s'}, faults: [{id: 'must-not-run',
          target: {actors: ['bitcoin-b'], mode: 'all'}, fault: {type: 'network', action: 'partition',
            mode: 'all', duration: '10s', parameters: {direction: 'both', peerTarget: {actors: ['bitcoin-a'], mode: 'all'}}}}]}]}};
  submitObject(attacknet, campaign, executionDirectory, 'negative-control-campaign');
  waitFor('negative control admission', () => optional('faultcampaign.testing.stacks.org', campaign.metadata.name), value =>
    value?.status?.phase === 'Admitted' && value.status.admission?.networkInventory?.burnchainTopology?.digest === originalDigest, 180);
  const before = chaosMutationCount(campaign.metadata.name);
  kubectl(['-n', namespace, 'patch', 'stacksnetwork.testing.stacks.org', primary.network, '--type=json',
    '-p', JSON.stringify([{op: 'replace', path: '/spec/burnchain/nodes/1/peerRefs', value: []}])]);
  const changed = waitFor('changed admitted topology', () => networkReady(primary.network), value =>
    value.status.burnchainTopology.digest !== originalDigest, 900);
  const terminalCampaign = waitFor('topology drift rejection', () => optional('faultcampaign.testing.stacks.org', campaign.metadata.name), value =>
    ((value?.status?.phase === 'Failed' && value.status.reason === 'AdmissionInputChanged')
      || (value?.status?.phase === 'Inconclusive' && value.status.reason === 'TargetIdentityDiverged'))
      && value.status.cleanup?.absent === true && value.status.cleanup?.allRecovered === true, 180);
  const after = chaosMutationCount(campaign.metadata.name);
  submitPath(attacknet, join(manifestDirectory, 'network.yaml'));
  const restored = networkReady(primary.network, originalDigest);
  const result = {qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a10-topology-drift-control/v1',
    outcome: 'Passed', observedAt: new Date().toISOString(), campaignUID: terminalCampaign.metadata.uid,
    campaignPhase: terminalCampaign.status.phase, campaignReason: terminalCampaign.status.reason,
    cleanupAbsent: terminalCampaign.status.cleanup.absent,
    cleanupAllRecovered: terminalCampaign.status.cleanup.allRecovered,
    mutationsBefore: before, mutationsAfter: after, admittedTopologyDigest: originalDigest,
    changedTopologyDigest: changed.status.burnchainTopology.digest,
    restoredTopologyDigest: restored.status.burnchainTopology.digest};
  validateA10NegativeControl(result, tree);
  writeJSON(join(output, A10_ARTIFACTS.negativeControl), result);
  deleteResource(attacknet, 'FaultCampaign', campaign.metadata.name);
}

function replayResources(attacknet, manifestDirectory, executionDirectory, sourceRun) {
  const policyA = normalizedResource(attacknet, manifestDirectory, 'policy-a.yaml');
  policyA.metadata.name = replay.policyA; policyA.spec.networkRef = replay.network;
  const policyB = normalizedResource(attacknet, manifestDirectory, 'policy-b.yaml');
  policyB.metadata.name = replay.policyB; policyB.spec.networkRef = replay.network;
  const network = normalizedResource(attacknet, manifestDirectory, 'network.yaml');
  network.metadata.name = replay.network; network.spec.burnchain.policyRef.name = replay.policyA;
  network.spec.burnchain.nodes.find(node => node.name === 'bitcoin-b').policyRef.name = replay.policyB;
  const run = normalizedResource(attacknet, manifestDirectory, 'run.yaml');
  run.metadata.name = replay.run; run.spec.networkRef = replay.network;
  run.spec.replay = {enabled: true, sourceRunRef: sourceRun.metadata.name,
    descriptorURI: `k8s://attacknetruns/${sourceRun.metadata.name}/resolved-schedule`,
    descriptorDigest: sourceRun.status.scheduleRef.digest,
    attemptId: 'a10-fresh-network-replay',
    requireSameResolvedImages: true, verifyExpectedFailure: false};
  submitObject(attacknet, policyA, executionDirectory, 'replay-policy-a');
  submitObject(attacknet, policyB, executionDirectory, 'replay-policy-b');
  submitObject(attacknet, network, executionDirectory, 'replay-network');
  return {run};
}

function runScenario(attacknet, manifestDirectory, executionDirectory, descriptor, runObject, tree, output) {
  // A quiescent shared tip makes the convergence window independent of normal
  // one-block propagation lag. The reorg worker mines its own replacement
  // branch and restores each policy to this pre-fault paused state.
  pauseCadencePolicies(descriptor);
  if (runObject) submitObject(attacknet, runObject, executionDirectory, `${descriptor.run}-resource`);
  else submitPath(attacknet, join(manifestDirectory, 'run.yaml'));
  const run = waitRun(descriptor.run);
  if (run.status.phase !== 'Passed') fail(`${descriptor.run} terminated ${run.status.phase}: ${run.status.reason} ${run.status.message ?? ''}`);
  const campaign = waitCampaign(childName(descriptor.run));
  const prefix = descriptor === primary ? 'primary' : 'replay';
  const runSnapshot = snapshotResource(attacknet, 'AttacknetRun', descriptor.run,
    join(output, A10_ARTIFACTS[`${prefix}Run`]), tree);
  const campaignSnapshot = snapshotResource(attacknet, 'FaultCampaign', childName(descriptor.run),
    join(output, A10_ARTIFACTS[`${prefix}Campaign`]), tree);
  validateA10Run(runSnapshot, tree, descriptor.network);
  validateA10Campaign(campaignSnapshot, tree, descriptor.network);
  for (const name of [descriptor.policyA, descriptor.policyB]) waitPolicyPaused(name);
  const views = captureViews(descriptor.network, tree);
  writeJSON(join(output, A10_ARTIFACTS[`${prefix}Views`]), views);
  return {run, campaign, runSnapshot, campaignSnapshot, views};
}

function captureIncident(attacknet, network, output) {
  const path = dirname(join(output, A10_ARTIFACTS.forensicManifest));
  command(attacknet, ['evidence', 'incident', '--namespace', namespace, '--output', path, network], {timeout: 600_000});
  const manifest = JSON.parse(readFileSync(join(path, 'manifest.json'), 'utf8'));
  if (manifest.errors?.length || manifest.omissions?.length) fail('A10 incident bundle is incomplete');
}
function count(kind, predicate) {
  const result = kubectl(['-n', namespace, 'get', kind, '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return 0;
  return JSON.parse(result.stdout).items.filter(predicate).length;
}
function scopeResidue() {
  const networkNames = new Set([primary.network, replay.network]);
  const policyNames = new Set([primary.policyA, primary.policyB, replay.policyA, replay.policyB]);
  const runNames = new Set([primary.run, replay.run]);
  const campaignNames = new Set([primary.template, 'a10-topology-drift', childName(primary.run), childName(replay.run)]);
  const credentialNames = new Set(['a10-miner-config', 'a10-signer-config', 'a10-stacker-credentials']);
  const relevant = item => networkNames.has(item.spec?.networkRef)
    || networkNames.has(item.metadata?.labels?.['testing.stacks.org/network']);
  return {
    networks: count('stacksnetworks.testing.stacks.org', item => networkNames.has(item.metadata?.name)),
    policies: count('burnchainpolicies.testing.stacks.org', item => policyNames.has(item.metadata?.name)),
    runs: count('attacknetruns.testing.stacks.org', item => runNames.has(item.metadata?.name)),
    campaigns: count('faultcampaigns.testing.stacks.org', item => campaignNames.has(item.metadata?.name) || relevant(item)),
    pods: count('pods', relevant), pvcs: count('persistentvolumeclaims', relevant),
    statefulsets: count('statefulsets.apps', relevant), services: count('services', relevant),
    configmaps: count('configmaps', relevant), deployments: count('deployments.apps', relevant),
    jobs: count('jobs.batch', relevant), secrets: count('secrets', item => credentialNames.has(item.metadata?.name) || relevant(item)),
    networkChaos: count('networkchaos.chaos-mesh.org', relevant),
  };
}
function scopeIsClean(counts) { return Object.values(counts).every(value => value === 0); }
function cleanTeardown(attacknet, credentialPath, tree, output) {
  for (const descriptor of [replay, primary]) deleteResource(attacknet, 'AttacknetRun', descriptor.run);
  deleteResource(attacknet, 'FaultCampaign', primary.template);
  deleteResource(attacknet, 'FaultCampaign', 'a10-topology-drift');
  for (const descriptor of [replay, primary]) {
    deleteResource(attacknet, 'BurnchainPolicy', descriptor.policyB);
    deleteResource(attacknet, 'BurnchainPolicy', descriptor.policyA);
    deleteResource(attacknet, 'StacksNetwork', descriptor.network);
  }
  kubectl(['-n', namespace, 'delete', '-f', credentialPath, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  const remainingCounts = waitFor('A10 owned-resource teardown', scopeResidue, scopeIsClean, 300);
  const value = {schemaVersion: 'stacks-attacknet-a10-clean-teardown/v1', qualifiedTree: tree,
    completed: scopeIsClean(remainingCounts), remainingCounts,
    observedAt: new Date().toISOString()};
  writeJSON(join(output, A10_ARTIFACTS.cleanTeardown), value);
  if (!value.completed) fail(`A10 cleanup retained resources: ${JSON.stringify(remainingCounts)}`);
}

function assertCleanScope() {
  const remainingCounts = scopeResidue();
  if (!scopeIsClean(remainingCounts)) fail(`A10 qualification scope is not clean: ${JSON.stringify(remainingCounts)}`);
}
/** Prepare an isolated qualification output without adopting prior private state. */
export function prepareQualificationOutput(output) {
  mkdirSync(output, {recursive: true, mode: 0o700});
  for (const path of [...Object.values(A10_ARTIFACTS), '.execution']) {
    if (['candidate.patch', 'verification.json', 'attacknet-result.json', 'hacknet-result.json'].includes(path)) continue;
    try { statSync(join(output, path)); fail(`refusing to overwrite A10 evidence ${path}`); }
    catch (error) { if (!String(error.message).includes('ENOENT')) throw error; }
  }
}

/** Copy immutable A10 qualification manifests into one execution root. */
export function stageQualificationManifests(executionDirectory) {
  const directory = join(resolve(executionDirectory), 'manifests');
  mkdirSync(directory, {mode: 0o700});
  for (const name of readdirSync(qualificationDirectory).filter(value => value.endsWith('.yaml'))) {
    writeFileSync(join(directory, name), readFileSync(join(qualificationDirectory, name)), {mode: 0o600});
  }
  return directory;
}

/** Derive ephemeral Secrets from the sealed regtest fixture. */
export function stageQualificationCredentials(executionDirectory) {
  const fixture = JSON.parse(readFileSync(credentialFixture, 'utf8'));
  const actors = new Map((fixture?.spec?.actors ?? []).map(actor => [actor?.name, actor]));
  const file = (actor, key) => actors.get(actor)?.config?.files?.[key];
  const environment = (actor, key) => actors.get(actor)?.env?.find(item => item?.name === key)?.value;
  const epochFour = '\n[[burnchain.epochs]]\nepoch_name = "4.0"\nstart_height = 245\n';
  const rawMiner = file('miner-1', 'config.toml');
  if (typeof rawMiner !== 'string' || rawMiner.split(epochFour).length !== 2) {
    fail('sealed regtest miner config does not contain exactly one unsupported Epoch 4 stanza');
  }
  const miner = rawMiner.replace(epochFour,
    '\n[[burnchain.epochs]]\nepoch_name = "4.0"\nstart_height = 1000005\n')
    .replaceAll('${SERVICE:bitcoin}', '${SERVICE:bitcoin-a}');
  const signer = file('signer-1', 'signer.toml');
  const privateKeys = environment('stacker', 'STACKING_KEYS');
  const addresses = environment('stacker', 'STACKING_ADDRESSES');
  if (![miner, signer, privateKeys, addresses].every(value => typeof value === 'string' && value.length > 0)
    || miner.includes('${SERVICE:bitcoin}')) fail('sealed regtest fixture does not contain the A10 credential contract');
  const secret = (name, stringData) => ({apiVersion: 'v1', kind: 'Secret', metadata: {name, namespace}, type: 'Opaque', stringData});
  const value = {apiVersion: 'v1', kind: 'List', items: [
    secret('a10-miner-config', {'config.toml': miner}), secret('a10-signer-config', {'signer.toml': signer}),
    secret('a10-stacker-credentials', {'private-keys': privateKeys, addresses}),
  ]};
  const path = join(resolve(executionDirectory), 'credentials.json');
  writeJSON(path, value);
  return path;
}

/** Qualify A10 on a fresh three-node arm64 kind environment. */
export function runQualification({qualifiedTree, outputDirectory}) {
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree ?? '')) fail('qualified tree must be a full Git tree SHA');
  prepareQualificationOutput(outputDirectory);
  for (const name of ['verification', 'candidateDiff', 'attacknetCheck', 'hacknetCheck']) {
    if (!statSync(join(outputDirectory, A10_ARTIFACTS[name])).isFile()) fail(`offline artifact ${A10_ARTIFACTS[name]} is required`);
  }
  const cluster = clusterProfile();
  const executionDirectory = join(resolve(outputDirectory), '.execution');
  mkdirSync(executionDirectory, {mode: 0o700});
  const manifestDirectory = stageQualificationManifests(executionDirectory);
  const credentialPath = stageQualificationCredentials(executionDirectory);
  const capacityChecks = [];
  try {
    requireStorageCapacity('before-build', qualifiedTree, outputDirectory, executionDirectory, capacityChecks);
    const candidate = buildCandidate(qualifiedTree, outputDirectory, executionDirectory);
    requireStorageCapacity('before-network', qualifiedTree, outputDirectory, executionDirectory, capacityChecks);
    assertCleanScope();
    kubectl(['apply', '-f', credentialPath]);
    submitPath(candidate.attacknet, join(manifestDirectory, 'policy-a.yaml'));
    submitPath(candidate.attacknet, join(manifestDirectory, 'policy-b.yaml'));
    submitPath(candidate.attacknet, join(manifestDirectory, 'network.yaml'));
    const primaryNetwork = networkReady(primary.network);
    policyReady(primary.policyA, 'bitcoin-a'); policyReady(primary.policyB, 'bitcoin-b');
    negativeControl(candidate.attacknet, manifestDirectory, executionDirectory, qualifiedTree, outputDirectory);
    submitPath(candidate.attacknet, join(manifestDirectory, 'campaign.yaml'));
    const primaryResult = runScenario(candidate.attacknet, manifestDirectory, executionDirectory, primary, undefined, qualifiedTree, outputDirectory);
    snapshotResource(candidate.attacknet, 'StacksNetwork', primary.network, join(outputDirectory, A10_ARTIFACTS.primaryNetwork), qualifiedTree);
    snapshotResource(candidate.attacknet, 'BurnchainPolicy', primary.policyA, join(outputDirectory, A10_ARTIFACTS.primaryPolicyA), qualifiedTree);
    snapshotResource(candidate.attacknet, 'BurnchainPolicy', primary.policyB, join(outputDirectory, A10_ARTIFACTS.primaryPolicyB), qualifiedTree);
    captureIncident(candidate.attacknet, primary.network, outputDirectory);
    deleteResource(candidate.attacknet, 'BurnchainPolicy', primary.policyB);
    deleteResource(candidate.attacknet, 'BurnchainPolicy', primary.policyA);
    deleteResource(candidate.attacknet, 'StacksNetwork', primary.network);
    const resources = replayResources(candidate.attacknet, manifestDirectory, executionDirectory, primaryResult.run);
    networkReady(replay.network); policyReady(replay.policyA, 'bitcoin-a'); policyReady(replay.policyB, 'bitcoin-b');
    const replayResult = runScenario(candidate.attacknet, manifestDirectory, executionDirectory, replay, resources.run, qualifiedTree, outputDirectory);
    if (replayResult.run.status.scheduleSummary?.replay !== true) fail('fresh A10 run was not admitted through replay mode');
    snapshotResource(candidate.attacknet, 'StacksNetwork', replay.network, join(outputDirectory, A10_ARTIFACTS.replayNetwork), qualifiedTree);
    if (primaryNetwork.metadata.uid === replayResult.views.network.uid) fail('A10 replay did not use a fresh network identity');
    cleanTeardown(candidate.attacknet, credentialPath, qualifiedTree, outputDirectory);
    const value = {schemaVersion: 'stacks-attacknet-a10-live-qualification/v1', qualifiedTree,
      outcome: 'Passed', capturedAt: new Date().toISOString(), architecture: cluster.architecture,
      kindNodes: cluster.nodes, context: cluster.context,
      negativeControlDigest: digestFile(join(outputDirectory, A10_ARTIFACTS.negativeControl)),
      primaryRunDigest: digestFile(join(outputDirectory, A10_ARTIFACTS.primaryRun)),
      replayRunDigest: digestFile(join(outputDirectory, A10_ARTIFACTS.replayRun)),
      candidateBuildDigest: digestFile(join(outputDirectory, A10_ARTIFACTS.candidateBuild))};
    writeJSON(join(outputDirectory, A10_ARTIFACTS.liveQualification), value);
    return value;
  } catch (error) {
    writeJSON(join(outputDirectory, 'qualification-failure.json'), {schemaVersion: 'stacks-attacknet-a10-qualification-failure/v1',
      qualifiedTree, failedAt: new Date().toISOString(), message: error.message});
    throw error;
  } finally {
    rmSync(executionDirectory, {recursive: true, force: true});
  }
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const tree = value('--qualified-tree='); const output = value('--output=');
  if (!tree || !output) fail('usage: live.mjs --qualified-tree=TREE --output=DIR');
  if (!isMaterializedSource(repositoryRoot)) {
    runMaterializedEntrypoint({repositoryRoot, qualifiedTree: tree,
      script: 'contrib/attacknet/release/amendments/a10/qualification/live.mjs',
      arguments_: [`--qualified-tree=${tree}`, `--output=${resolve(output)}`]});
    return;
  }
  runQualification({qualifiedTree: tree, outputDirectory: resolve(output)});
}

if (isMainModule(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
