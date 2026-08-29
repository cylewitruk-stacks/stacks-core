#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, join, parse, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {validateA10CandidateBuild} from './qualification/candidate-build.mjs';
import {validateA10Verification} from './verify.mjs';
import {A10_STORAGE_MINIMUM_AVAILABLE_BYTES} from './limits.mjs';

export {A10_STORAGE_MINIMUM_AVAILABLE_BYTES} from './limits.mjs';

export const A10_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a10-live-evidence/v1';
export const A10_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A10_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
  candidateBuild: 'candidate-build.json',
  storagePreflight: 'storage-preflight.json',
  negativeControl: 'negative-control.json',
  primaryNetwork: 'primary/network.json',
  primaryPolicyA: 'primary/policy-a.json',
  primaryPolicyB: 'primary/policy-b.json',
  primaryRun: 'primary/run.json',
  primaryCampaign: 'primary/campaign.json',
  primaryViews: 'primary/views.json',
  replayNetwork: 'replay/network.json',
  replayRun: 'replay/run.json',
  replayCampaign: 'replay/campaign.json',
  replayViews: 'replay/views.json',
  forensicManifest: 'primary/incident/manifest.json',
  cleanTeardown: 'clean-teardown.json',
  liveQualification: 'live-qualification.json',
});
export const A10_ASSERTIONS = Object.freeze([
  'qualified-tree-and-candidate-images',
  'offline-race-envtest-helm-rbac-and-product-checks-pass',
  'two-node-bitcoin-graph-and-stacks-bindings-are-admitted',
  'topology-drift-after-admission-mutates-no-chaos-resource',
  'partition-and-higher-work-branch-produce-two-distinct-bitcoin-views',
  'bound-stacks-followers-produce-two-distinct-burnchain-views',
  'bitcoin-and-stacks-cohorts-recover-for-stable-windows',
  'fresh-network-replay-preserves-graph-schedule-and-outcome-class',
  'complete-identity-bound-forensic-bundle',
  'clean-final-teardown',
]);

function fail(message) { throw new Error(message); }
function load(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`${label} is not readable JSON: ${error.message}`); }
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function containsPath(parent, child) { return child === parent || child.startsWith(`${parent}${sep}`); }

/** Refuse destructive evidence output locations that overlap source or repository data. */
export function validateA10EvidenceOutput(inputDirectory, outputDirectory) {
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..');
  if (output === parse(output).root
    || containsPath(output, repository)
    || containsPath(input, output)
    || containsPath(output, input)) {
    fail(`A10 evidence output must be isolated from the repository and input bundle: ${output}`);
  }
  return output;
}
function immutable(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
  return value;
}
function qualified(value, tree, label) {
  if (!value || value.qualifiedTree !== tree) fail(`${label} does not pin the qualified tree`);
  return value;
}
function snapshot(value, tree, kind, label) {
  qualified(value, tree, label);
  if (value.schemaVersion !== 'stacks-attacknet-resource-snapshot/v1'
    || value.scope !== 'single-resource-status' || value.resource?.kind !== kind) {
    fail(`${label} is not a ${kind} status snapshot`);
  }
  immutable(value.resourceDigest, `${label}.resourceDigest`);
  return value.resource;
}

/** Validate the exact-tree whole-product Attacknet result required by A10. */
export function validateA10AttacknetCheck(value, tree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== tree || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0
    || value.suites.some(suite => typeof suite?.name !== 'string' || suite.name.length === 0
      || !Number.isSafeInteger(suite.tests) || suite.tests < 1
      || suite.passed !== suite.tests || suite.failed !== 0)) {
    fail('Attacknet check is not a complete qualified-tree pass');
  }
  return value;
}

/** Validate the exact-tree, fully equipped Hacknet result required by A10. */
export function validateA10HacknetCheck(value, tree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== tree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A10 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

/** Validate capacity evidence before both expensive deployment boundaries. */
export function validateA10StoragePreflight(value, tree) {
  qualified(value, tree, 'storage preflight');
  if (value.schemaVersion !== 'stacks-attacknet-a10-storage-preflight/v1'
    || value.minimumAvailableBytes !== A10_STORAGE_MINIMUM_AVAILABLE_BYTES
    || !Number.isFinite(Date.parse(value.recordedAt ?? ''))
    || !Array.isArray(value.checks) || value.checks.length !== 2) {
    fail('A10 storage preflight is incomplete');
  }
  for (const [index, phase] of ['before-build', 'before-network'].entries()) {
    const check = value.checks[index];
    if (check?.phase !== phase || check.exitCode !== 0 || check.ok !== true
      || check.schemaVersion !== 1 || check.source !== 'kubelet-stats-summary'
      || check.minimumAvailableBytes !== A10_STORAGE_MINIMUM_AVAILABLE_BYTES
      || !Array.isArray(check.nodes) || check.nodes.length !== 3
      || check.nodes.some(node => node.ok !== true
        || node.rootFilesystem?.availableBytes < A10_STORAGE_MINIMUM_AVAILABLE_BYTES
        || node.imageFilesystem?.availableBytes < A10_STORAGE_MINIMUM_AVAILABLE_BYTES)) {
      fail(`A10 ${phase} storage preflight did not prove sufficient capacity`);
    }
  }
  return value;
}

function topologyShape(topology) {
  return {
    nodes: [...(topology.nodes ?? [])].map(node => ({name: node.name, rpcPort: node.rpcPort, p2pPort: node.p2pPort,
      peerRefs: [...(node.peerRefs ?? [])].sort()}))
      .sort((a, b) => a.name.localeCompare(b.name)),
    bindings: [...(topology.bindings ?? [])].map(binding => ({actor: binding.actor, bitcoinNodeRef: binding.bitcoinNodeRef}))
      .sort((a, b) => a.actor.localeCompare(b.actor)),
  };
}

/** Validate one fully admitted two-Bitcoin graph and Stacks binding set. */
export function validateA10Network(value, tree, expectedName) {
  const network = snapshot(value, tree, 'StacksNetwork', `${expectedName} network`);
  const topology = network.status?.burnchainTopology;
  const nodes = new Map((topology?.nodes ?? []).map(node => [node.name, node]));
  const bindings = new Map((topology?.bindings ?? []).map(binding => [binding.actor, binding.bitcoinNodeRef]));
  if (network.metadata?.name !== expectedName || network.status?.phase !== 'Ready'
    || network.status.inventoryReady !== true || network.status.observedGeneration !== network.metadata.generation
    || !network.metadata.uid || !/^sha256:[0-9a-f]{64}$/.test(network.status.inventoryDigest ?? '')
    || topology?.schemaVersion !== 'stacks-network-admitted-burnchain-topology/v1'
    || topology.observedGeneration !== network.metadata.generation
    || !/^sha256:[0-9a-f]{64}$/.test(topology.digest ?? '') || nodes.size !== 2
    || nodes.get('bitcoin-a')?.peerRefs?.join(',') !== 'bitcoin-b'
    || nodes.get('bitcoin-b')?.peerRefs?.join(',') !== 'bitcoin-a'
    || nodes.get('bitcoin-a')?.policyUID === nodes.get('bitcoin-b')?.policyUID
    || [...nodes.values()].some(node => !node.policyUID || !node.policyServiceName)
    || bindings.get('miner-1') !== 'bitcoin-a' || bindings.get('follower-1') !== 'bitcoin-a'
    || bindings.get('follower-b') !== 'bitcoin-b' || bindings.get('signer-node-1') !== 'bitcoin-a') {
    fail(`${expectedName} does not prove the admitted two-Bitcoin topology`);
  }
  return network;
}

/** Validate one policy's immutable binding to its intended Bitcoin node. */
export function validateA10Policy(value, tree, expectedNetwork, expectedNode, admittedNode) {
  const policy = snapshot(value, tree, 'BurnchainPolicy', `${expectedNetwork}/${expectedNode} policy`);
  if (policy.spec?.networkRef !== expectedNetwork || policy.spec?.bitcoinNodeRef !== expectedNode
    || (admittedNode && (policy.metadata?.name !== admittedNode.policyRef || policy.metadata?.uid !== admittedNode.policyUID))
    || policy.status?.phase !== 'Ready' || policy.status.observedGeneration !== policy.metadata.generation
    || !policy.metadata?.uid || policy.status?.observedHeight < 202
    || !/^sha256:[0-9a-f]{64}$/.test(policy.status?.appliedPolicyDigest ?? '')) {
    fail(`${expectedNetwork}/${expectedNode} policy is not fully observed`);
  }
  return policy;
}

function resultEvidence(set, id) {
  const result = set?.results?.find(candidate => candidate.id === id);
  if (result?.outcome !== 'Proven' || !result.evidence) fail(`protocol assertion ${id} was not proven with evidence`);
  return result.evidence;
}

function distinct(values) { return new Set(Object.values(values ?? {})).size; }

/** Validate end-to-end divergence and stable recovery on both protocol layers. */
export function validateA10Run(value, tree, expectedNetwork) {
  const run = snapshot(value, tree, 'AttacknetRun', `${expectedNetwork} run`);
  const sets = run.status?.protocolAssertions ?? {};
  if (run.spec?.networkRef !== expectedNetwork || run.status?.phase !== 'Passed'
    || run.status.cleanup?.completed !== true || run.status.budgetUsage?.burnchainFaults !== 2
    || !['baseline', 'during', 'recovery'].every(name => sets[name]?.outcome === 'Proven')) {
    fail(`${expectedNetwork} run did not independently prove all protocol gates`);
  }
  const baselineBitcoin = resultEvidence(sets.baseline, 'bitcoin-baseline');
  const baselineStacks = resultEvidence(sets.baseline, 'stacks-baseline');
  const duringBitcoin = resultEvidence(sets.during, 'bitcoin-diverged');
  const duringStacks = resultEvidence(sets.during, 'stacks-diverged');
  const recoveryBitcoin = resultEvidence(sets.recovery, 'bitcoin-converged');
  const recoveryStacks = resultEvidence(sets.recovery, 'stacks-converged');
  if (distinct(baselineBitcoin.current) !== 1 || distinct(baselineStacks.current) !== 1
    || distinct(duringBitcoin.current) < 2 || distinct(duringStacks.current) < 2
    || distinct(recoveryBitcoin.current) !== 1 || distinct(recoveryStacks.current) !== 1
    || !recoveryBitcoin.stableSince || !recoveryStacks.stableSince
    || Object.keys(duringBitcoin.bitcoinObservations ?? {}).length !== 2
    || Object.keys(duringStacks.stacksObservations ?? {}).length !== 2
    || duringStacks.bindings?.['follower-1'] !== 'bitcoin-a'
    || duringStacks.bindings?.['follower-b'] !== 'bitcoin-b') {
    fail(`${expectedNetwork} protocol evidence does not prove split and stable recovery`);
  }
  return run;
}

/** Validate a completed partition plus higher-work branch campaign. */
export function validateA10Campaign(value, tree, expectedNetwork) {
  const campaign = snapshot(value, tree, 'FaultCampaign', `${expectedNetwork} campaign`);
  const actions = (campaign.status?.stages ?? []).flatMap(stage => stage.actions ?? []);
  const partition = actions.find(action => action.id === 'partition-bitcoin-edge');
  const reorg = actions.find(action => action.id === 'reorg-bitcoin-b');
  const branch = reorg?.effectResults?.find(result => result.assertion === 'BurnchainReorgProven')?.evidence;
  if (campaign.spec?.networkRef !== expectedNetwork || campaign.status?.phase !== 'Passed'
    || campaign.status.cleanup?.allRecovered !== true || actions.length !== 2
    || partition?.mutation?.kind !== 'NetworkChaos' || partition.phase !== 'Completed'
    || reorg?.mutation?.kind !== 'BurnchainReorgWorker' || reorg.phase !== 'Completed'
    || branch?.schemaVersion !== 'attacknet-burnchain-reorg-result/v1'
    || branch.canonicalProven !== true || branch.originalBranch?.length !== 2
    || branch.replacementBranch?.length !== 3
    || branch.final?.bestblockhash !== branch.replacementBranch[2]?.hash
    || !reorg.recoveryResults?.some(result => result.assertion === 'BurnchainPolicyRestored' && result.outcome === 'Proven')) {
    fail(`${expectedNetwork} campaign does not prove partitioned competing-branch execution and cleanup`);
  }
  return campaign;
}

/** Validate direct full-hash views after stable convergence. */
export function validateA10Views(value, tree, expectedNetwork) {
  qualified(value, tree, `${expectedNetwork} views`);
  const bitcoins = new Map((value.bitcoin ?? []).map(item => [item.actor, item]));
  const stacks = new Map((value.stacks ?? []).map(item => [item.actor, item]));
  if (value.schemaVersion !== 'stacks-attacknet-a10-node-views/v1'
    || !Number.isFinite(Date.parse(value.observedAt ?? ''))
    || value.network?.name !== expectedNetwork || !value.network.uid
    || !Number.isSafeInteger(value.network.observedGeneration) || value.network.observedGeneration < 1
    || !/^sha256:[0-9a-f]{64}$/.test(value.network.inventoryDigest ?? '')
    || !/^sha256:[0-9a-f]{64}$/.test(value.network.topologyDigest ?? '')
    || bitcoins.size !== 2 || stacks.size !== 2
    || [...bitcoins.values()].some(item => item.chain !== 'regtest' || item.blocks < 202 || item.headers < item.blocks
      || item.evidenceClass !== 'actor_self_reported' || item.networkUID !== value.network.uid
      || item.networkGeneration !== value.network.observedGeneration
      || item.inventoryDigest !== value.network.inventoryDigest || item.topologyDigest !== value.network.topologyDigest
      || !item.podName || !item.podUID || !/^sha256:[0-9a-f]{64}$/.test(item.runtimeImageID ?? '')
      || !/^[0-9a-f]{64}$/.test(item.bestblockhash ?? '') || !/^[0-9a-f]{64}$/.test(item.chainwork ?? '')
      || !(item.peers ?? []).every(peer => Number.isSafeInteger(peer.last_block) && peer.last_block >= 0
        && Number.isSafeInteger(peer.last_transaction) && peer.last_transaction >= 0))
    || bitcoins.get('bitcoin-a').bestblockhash !== bitcoins.get('bitcoin-b').bestblockhash
    || [...stacks.values()].some(item => item.burnBlockHeight !== bitcoins.get(item.bitcoinNodeRef)?.blocks
      || item.evidenceClass !== 'actor_self_reported' || item.networkUID !== value.network.uid
      || item.networkGeneration !== value.network.observedGeneration
      || item.inventoryDigest !== value.network.inventoryDigest || item.topologyDigest !== value.network.topologyDigest
      || !/^[0-9a-f]{40}$/.test(item.burnConsensusHash ?? '')
      || !item.podName || !item.podUID || !/^sha256:[0-9a-f]{64}$/.test(item.runtimeImageID ?? ''))
    || stacks.get('follower-1')?.burnConsensusHash !== stacks.get('follower-b')?.burnConsensusHash
    || stacks.get('follower-1')?.bitcoinNodeRef !== 'bitcoin-a'
    || stacks.get('follower-b')?.bitcoinNodeRef !== 'bitcoin-b') {
    fail(`${expectedNetwork} full-hash recovery views are incomplete or divergent`);
  }
  return value;
}

/** Validate fail-closed topology drift before any Chaos Mesh mutation. */
export function validateA10NegativeControl(value, tree) {
  qualified(value, tree, 'topology drift negative control');
  const rejectedAdmission = value.campaignPhase === 'Failed'
    && value.campaignReason === 'AdmissionInputChanged';
  const rejectedLiveIdentity = value.campaignPhase === 'Inconclusive'
    && value.campaignReason === 'TargetIdentityDiverged';
  if (value.schemaVersion !== 'stacks-attacknet-a10-topology-drift-control/v1'
    || value.outcome !== 'Passed' || (!rejectedAdmission && !rejectedLiveIdentity)
    || value.cleanupAbsent !== true || value.cleanupAllRecovered !== true
    || value.mutationsBefore !== 0 || value.mutationsAfter !== 0
    || value.admittedTopologyDigest === value.changedTopologyDigest
    || value.restoredTopologyDigest !== value.admittedTopologyDigest
    || ![value.admittedTopologyDigest, value.changedTopologyDigest, value.restoredTopologyDigest]
      .every(item => /^sha256:[0-9a-f]{64}$/.test(item ?? ''))) {
    fail('topology drift negative control does not prove admission rejection, zero mutation, complete cleanup, and exact restoration');
  }
  return value;
}

/** Validate a complete incident manifest and every retained artifact. */
export function validateA10Incident(path) {
  const manifest = load(path, 'incident manifest');
  if (manifest.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || manifest.errors?.length || manifest.omissions?.length || !manifest.artifacts?.length) {
    fail('A10 incident bundle is incomplete');
  }
  const root = dirname(path);
  for (const entry of manifest.artifacts) {
    const candidate = resolve(root, entry.path);
    if (candidate === root || !containsPath(root, candidate) || digestFile(candidate) !== entry.sha256
      || statSync(candidate).size !== entry.bytes) fail(`incident artifact ${entry.path} is invalid`);
  }
  return manifest;
}

function topologyEquivalent(primary, replay) {
  return JSON.stringify(topologyShape(primary.status.burnchainTopology))
    === JSON.stringify(topologyShape(replay.status.burnchainTopology));
}

function walkFiles(root) {
  const result = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) result.push(...walkFiles(path)); else result.push(path);
  }
  return result;
}
function artifact(path, archiveEntry) {
  return {path, archiveEntry, digest: digestFile(path), size: statSync(path).size};
}

/** Suppress macOS AppleDouble members that are not part of evidence. */
export function portableArchiveEnvironment(environment = process.env) {
  return {...environment, COPYFILE_DISABLE: '1'};
}

/** Validate every A10 live artifact before sealing. */
export function validateA10LiveQualification(root, tree) {
  const at = name => join(root, A10_ARTIFACTS[name]);
  validateA10Verification(load(at('verification'), 'verification'), tree);
  validateA10HacknetCheck(load(at('hacknetCheck'), 'Hacknet check'), tree);
  validateA10AttacknetCheck(load(at('attacknetCheck'), 'Attacknet check'), tree);
  validateA10CandidateBuild(load(at('candidateBuild'), 'candidate build'), tree);
  validateA10StoragePreflight(load(at('storagePreflight'), 'storage preflight'), tree);
  validateA10NegativeControl(load(at('negativeControl'), 'negative control'), tree);
  const primaryNetwork = validateA10Network(load(at('primaryNetwork'), 'primary network'), tree, 'a10-qualification');
  const primaryNodes = new Map(primaryNetwork.status.burnchainTopology.nodes.map(node => [node.name, node]));
  validateA10Policy(load(at('primaryPolicyA'), 'primary policy A'), tree, 'a10-qualification', 'bitcoin-a', primaryNodes.get('bitcoin-a'));
  validateA10Policy(load(at('primaryPolicyB'), 'primary policy B'), tree, 'a10-qualification', 'bitcoin-b', primaryNodes.get('bitcoin-b'));
  const primaryRun = validateA10Run(load(at('primaryRun'), 'primary run'), tree, 'a10-qualification');
  const primaryCampaign = validateA10Campaign(load(at('primaryCampaign'), 'primary campaign'), tree, 'a10-qualification');
  validateA10Views(load(at('primaryViews'), 'primary views'), tree, 'a10-qualification');
  const replayNetwork = validateA10Network(load(at('replayNetwork'), 'replay network'), tree, 'a10-replay');
  const replayRun = validateA10Run(load(at('replayRun'), 'replay run'), tree, 'a10-replay');
  const replayCampaign = validateA10Campaign(load(at('replayCampaign'), 'replay campaign'), tree, 'a10-replay');
  validateA10Views(load(at('replayViews'), 'replay views'), tree, 'a10-replay');
  if (!topologyEquivalent(primaryNetwork, replayNetwork)
    || primaryNetwork.metadata.uid === replayNetwork.metadata.uid
    || primaryRun.spec.seed !== replayRun.spec.seed
    || replayRun.spec.replay?.sourceRunRef !== primaryRun.metadata.name
    || replayRun.spec.replay?.descriptorDigest !== primaryRun.status.scheduleRef?.digest
    || replayRun.status.scheduleSummary?.replay !== true
    || primaryCampaign.status.phase !== replayCampaign.status.phase) {
    fail('fresh-network replay does not preserve topology, schedule, and outcome class');
  }
  validateA10Incident(at('forensicManifest'));
  const teardown = qualified(load(at('cleanTeardown'), 'clean teardown'), tree, 'clean teardown');
  if (teardown.completed !== true || Object.values(teardown.remainingCounts ?? {}).some(count => count !== 0)) fail('A10 final teardown is incomplete');
  const qualification = qualified(load(at('liveQualification'), 'live qualification'), tree, 'live qualification');
  if (qualification.schemaVersion !== 'stacks-attacknet-a10-live-qualification/v1'
    || qualification.outcome !== 'Passed' || qualification.architecture !== 'arm64'
    || qualification.kindNodes !== 3
    || qualification.negativeControlDigest !== digestFile(at('negativeControl'))
    || qualification.primaryRunDigest !== digestFile(at('primaryRun'))
    || qualification.replayRunDigest !== digestFile(at('replayRun'))) {
    fail('A10 live qualification receipt is incomplete');
  }
  return {primaryNetwork, primaryRun, primaryCampaign, replayNetwork, replayRun, replayCampaign, qualification};
}

/** Assemble a portable, content-addressed A10 evidence archive and summary. */
export function assembleA10Evidence({inputDirectory, outputDirectory, qualifiedTree}) {
  const input = resolve(inputDirectory);
  validateA10LiveQualification(input, qualifiedTree);
  const output = validateA10EvidenceOutput(input, outputDirectory);
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const staging = join(output, '.staging');
  mkdirSync(staging, {recursive: true});
  const artifactEntries = {};
  for (const [key, path] of Object.entries(A10_ARTIFACTS)) {
    const destination = join(staging, path);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, path), destination);
    artifactEntries[key] = artifact(destination, path);
  }
  const incidentSource = dirname(join(input, A10_ARTIFACTS.forensicManifest));
  for (const source of walkFiles(incidentSource)) {
    const entry = join('primary/incident', relative(incidentSource, source));
    if (entry === A10_ARTIFACTS.forensicManifest) continue;
    const destination = join(staging, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const entries = walkFiles(staging).map(path => ({
    path: relative(staging, path), digest: digestFile(path), size: statSync(path).size,
  }));
  const index = {schema: A10_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
  copyFileSync(indexPath, join(staging, 'archive-index.json'));
  const archivePath = join(output, `archive/phase-2-live-evidence-${qualifiedTree.slice(0, 12)}.tar.gz`);
  execFileSync('tar', ['-czf', archivePath, '-C', staging, '.'], {env: portableArchiveEnvironment()});
  rmSync(staging, {recursive: true, force: true});
  const artifacts = {};
  for (const [key, value] of Object.entries(artifactEntries)) {
    const finalPath = join(output, value.archiveEntry);
    mkdirSync(dirname(finalPath), {recursive: true});
    copyFileSync(join(input, value.archiveEntry), finalPath);
    artifacts[key] = artifact(finalPath, value.archiveEntry);
  }
  const incidentOutput = dirname(join(output, A10_ARTIFACTS.forensicManifest));
  rmSync(incidentOutput, {recursive: true, force: true});
  for (const source of walkFiles(incidentSource)) {
    const destination = join(incidentOutput, relative(incidentSource, source));
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const summary = {
    schema: A10_SUMMARY_SCHEMA, qualifiedTree, generatedAt: new Date().toISOString(),
    assertions: A10_ASSERTIONS.map(id => ({id, status: 'passed'})), artifacts,
    archive: {path: archivePath, digest: digestFile(archivePath), location: 'local-review-bundle',
      indexPath, indexDigest: digestFile(indexPath), indexEntry: 'archive-index.json'},
  };
  const summaryPath = join(output, 'live-summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  validatePortableLiveSummary(summary, {commitPending: false}, {
    root: resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..'),
    schema: A10_SUMMARY_SCHEMA, checkpoint: 'A10 evidence assembly',
    requiredArtifacts: Object.keys(A10_ARTIFACTS), requiredAssertions: A10_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: qualifiedTree, description: 'qualified Git tree'},
  });
  return {summary, summaryPath};
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const input = value('--input='); const output = value('--output='); const tree = value('--qualified-tree=');
  if (!input || !output || !tree) fail('usage: evidence.mjs --input=DIR --output=DIR --qualified-tree=TREE');
  const result = assembleA10Evidence({inputDirectory: input, outputDirectory: output, qualifiedTree: tree});
  process.stdout.write(`${JSON.stringify({summary: result.summaryPath, archive: result.summary.archive.path})}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
