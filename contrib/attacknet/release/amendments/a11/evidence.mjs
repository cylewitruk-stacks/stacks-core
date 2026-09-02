#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {basename, dirname, join, parse, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {validatePortableLiveSummary} from '../../portable-live-evidence.mjs';
import {validateA11Verification} from './verify.mjs';

export const A11_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a11-live-evidence/v1';
export const A11_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A11_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
  candidateBuild: 'candidate-build.json',
  sourceDrift: 'controls/source-drift.json',
  configurationControl: 'controls/configuration.json',
  telemetryControl: 'controls/telemetry.json',
  protocolControl: 'controls/protocol-assertion.json',
  staticDescriptor: 'static/descriptor.json',
  staticImport: 'static/import.json',
  staticNetwork: 'static/network.json',
  upgradeDescriptor: 'upgrade/descriptor.json',
  primaryNetwork: 'upgrade/network.json',
  primaryRun: 'upgrade/run.json',
  primaryUpgrade: 'upgrade/decision.json',
  replayNetwork: 'replay/network.json',
  replayRun: 'replay/run.json',
  replayUpgrade: 'replay/decision.json',
  forensicManifest: 'upgrade/incident/manifest.json',
  cleanTeardown: 'clean-teardown.json',
  liveQualification: 'live-qualification.json',
});
export const A11_ASSERTIONS = Object.freeze([
  'qualified-tree-and-control-plane-images',
  'offline-race-envtest-helm-rbac-and-product-checks-pass',
  'remote-local-prebuilt-and-expected-revision-controls-are-sealed',
  'deterministic-assignment-and-static-mixed-version-cohort-are-admitted',
  'raw-config-digest-is-verified-and-joined-to-admitted-identity',
  'topology-owned-upgrade-runs-through-the-typed-run-scheduler',
  'staged-upgrade-crosses-the-sealed-boundary-with-bounded-impact',
  'configuration-and-telemetry-controls-retain-distinct-outcome-classes',
  'protocol-assertion-negative-control-rolls-back-and-does-not-claim-version-incompatibility',
  'rollback-and-fresh-network-replay-preserve-sealed-identity-and-outcome-class',
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
function immutable(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
  return value;
}
function qualified(value, tree, label) {
  if (!value || value.qualifiedTree !== tree) fail(`${label} does not pin the qualified tree`);
  return value;
}
function containsPath(parent, child) { return child === parent || child.startsWith(`${parent}${sep}`); }

/** Refuse destructive evidence output locations that overlap source data. */
export function validateA11EvidenceOutput(inputDirectory, outputDirectory) {
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..');
  if (output === parse(output).root || containsPath(output, repository)
    || containsPath(input, output) || containsPath(output, input)) {
    fail(`A11 evidence output must be isolated from repository and input data: ${output}`);
  }
  return output;
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

/** Validate one exact-tree whole-product Attacknet result. */
export function validateA11AttacknetCheck(value, tree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== tree || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0
    || value.suites.some(suite => !Number.isSafeInteger(suite?.tests) || suite.tests < 1
      || suite.passed !== suite.tests || suite.failed !== 0)) {
    fail('Attacknet check is not a complete qualified-tree pass');
  }
  return value;
}

/** Validate one exact-tree fully equipped Hacknet result. */
export function validateA11HacknetCheck(value, tree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== tree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A11 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

/** Validate control-plane and version images loaded on all three arm64 nodes. */
export function validateA11CandidateBuild(value, tree) {
  qualified(value, tree, 'candidate build');
  const nodes = value.cluster?.nodes ?? [];
  const control = value.controlPlane?.images ?? [];
  const profiles = value.profiles ?? [];
  const chaos = value.dependencies?.chaosMesh;
  if (value.schemaVersion !== 'stacks-attacknet-a11-candidate-build/v1'
    || value.cluster?.provider !== 'kind' || value.cluster.architecture !== 'arm64'
    || nodes.length !== 3 || new Set(nodes).size !== 3
    || control.length < 3 || profiles.length < 2
    || chaos?.schemaVersion !== 'stacks-attacknet-a11-chaos-mesh-install/v1'
    || chaos.version !== '2.8.3' || chaos.namespace !== 'chaos-mesh'
    || chaos.release !== 'chaos-mesh' || chaos.status !== 'deployed'
    || !Array.isArray(chaos.pods) || chaos.pods.length === 0
    || chaos.pods.some(pod => !pod.name || !pod.uid || pod.ready !== true
      || !Array.isArray(pod.images) || pod.images.length === 0)) {
    fail('A11 candidate build does not cover the three-node arm64 cluster');
  }
  for (const image of [...control, ...profiles]) {
    immutable(image.imageID, `${image.name}.imageID`);
    immutable(image.provenanceDigest, `${image.name}.provenanceDigest`);
    if (!image.image || new Set(image.loadedNodes ?? []).size !== 3
      || nodes.some(node => !image.loadedNodes.includes(node))) {
      fail(`A11 image ${image.name} is not loaded on every node`);
    }
  }
  return value;
}

/** Validate immutable source drift rejection before any build or cluster write. */
export function validateA11SourceDrift(value, tree) {
  qualified(value, tree, 'source drift control');
  if (value.schemaVersion !== 'stacks-attacknet-a11-source-drift-control/v1'
    || value.outcome !== 'Passed' || value.classification !== 'SourceRevisionMismatch'
    || value.clusterMutationsBefore !== value.clusterMutationsAfter
    || value.imageCountBefore !== value.imageCountAfter
    || !/^[0-9a-f]{40}$/.test(value.expectedRevision ?? '')
    || !/^[0-9a-f]{40}$/.test(value.resolvedRevision ?? '')
    || value.expectedRevision === value.resolvedRevision) {
    fail('A11 source drift control does not prove fail-closed immutability');
  }
  return value;
}

/** Validate distinct configuration failure classification and zero protocol claim. */
export function validateA11ConfigurationControl(value, tree) {
  qualified(value, tree, 'configuration control');
  if (value.schemaVersion !== 'stacks-attacknet-a11-configuration-control/v1'
    || value.outcome !== 'Passed'
    || !['ConfigurationUnsupported', 'StartupIncompatible'].includes(value.classification)
    || value.protocolIncompatible === true || value.networkMutated !== false
    || !immutable(value.expectedConfigDigest, 'configuration expected digest')
    || !immutable(value.observedConfigDigest, 'configuration observed digest')
    || value.expectedConfigDigest === value.observedConfigDigest) {
    fail('A11 configuration control does not preserve its distinct failure class');
  }
  return value;
}

/** Validate missing declared instrumentation remains inconclusive. */
export function validateA11TelemetryControl(value, tree) {
  qualified(value, tree, 'telemetry control');
  if (value.schemaVersion !== 'stacks-attacknet-a11-telemetry-control/v1'
    || value.outcome !== 'Passed' || value.runPhase !== 'Inconclusive'
    || value.classification !== 'TelemetryUnavailable'
    || value.protocolIncompatible === true || !value.profile || !value.missingFamily
    || value.mutations !== 0 || !value.runUID || !value.runReason) {
    fail('A11 telemetry control does not preserve an inconclusive telemetry outcome');
  }
  return value;
}

/** Validate the independent protocol-gate negative control. */
export function validateA11ProtocolControl(value, tree) {
  qualified(value, tree, 'protocol control');
  const status = value?.campaign?.status;
  const rollback = (status?.identityTransitions ?? []).find(transition => transition.campaign === 'rollback');
  if (value.schemaVersion !== 'stacks-attacknet-a11-protocol-control/v1'
    || value.outcome !== 'Passed' || value.classification !== 'ProtocolAssertionViolated'
    || value.rollbackRestored !== true
    || value.versionCompatibilityConclusion !== 'not-established'
    || status?.phase !== 'Failed' || status.reason !== 'ProtocolAssertionViolated'
    || status.rollbackComplete !== true || status.stageAssertions?.outcome !== 'Violated'
    || !(status.stageAssertions.results ?? []).some(result => result.reason === 'RequiredProgressAbsent')
    || !immutable(value.beforeInventoryDigest, 'protocolControl.beforeInventoryDigest')
    || !immutable(value.afterInventoryDigest, 'protocolControl.afterInventoryDigest')
    || status.baselineInventory?.digest !== value.beforeInventoryDigest
    || status.currentInventory?.digest !== value.afterInventoryDigest
    || !immutable(rollback?.previousDigest, 'protocolControl.rollback.previousDigest')
    || rollback.previousDigest === rollback.currentDigest
    || rollback?.currentDigest !== value.afterInventoryDigest
    || !rollbackIdentityRestored(status.baselineInventory, status.currentInventory)) {
    fail('protocol control did not prove a violated gate, exact rollback, and non-conclusion');
  }
  return value;
}

const rollbackActorFields = Object.freeze([
  'controllerRevision', 'name', 'podName', 'requestedImage', 'role', 'runtimeImageID',
  'serviceName', 'statefulSetName', 'statefulSetUID', 'configDigest',
]);

/** Compare durable admitted workload identity while allowing a replaced Pod UID. */
export function rollbackIdentityRestored(baseline, current) {
  if (!baseline || !current || baseline.schemaVersion !== current.schemaVersion
    || baseline.observedGeneration !== current.observedGeneration
    || baseline.burnchainTopology?.digest !== current.burnchainTopology?.digest
    || !Array.isArray(baseline.actors) || !Array.isArray(current.actors)
    || baseline.actors.length !== current.actors.length) return false;
  const observed = new Map(current.actors.map(actor => [actor.name, actor]));
  return baseline.actors.every(expected => {
    const actual = observed.get(expected.name);
    return actual && rollbackActorFields.every(field => (expected[field] ?? '') === (actual[field] ?? ''));
  });
}

function validateProfile(profile, label) {
  if (!profile?.name || !['remoteGit', 'localGit', 'prebuilt'].includes(profile.sourceKind)
    || !profile.image || !immutable(profile.imageID, `${label}.imageID`)
    || !immutable(profile.configDigest, `${label}.configDigest`)
    || !immutable(profile.provenanceDigest, `${label}.provenanceDigest`)
    || profile.sourceKind !== 'prebuilt' && !/^[0-9a-f]{40}$/.test(profile.revision ?? '')) {
    fail(`${label} is not an immutable version profile`);
  }
}

/** Validate one canonical descriptor and its deterministic assignment receipt. */
export function validateA11Descriptor(value, tree, label = 'descriptor') {
  qualified(value, tree, label);
  const descriptor = value.descriptor;
  if (value.schemaVersion !== 'stacks-attacknet-a11-descriptor-evidence/v1'
    || descriptor?.schemaVersion !== 'stacks-attacknet-version-descriptor/v1'
    || !immutable(descriptor.digest, `${label}.digest`)
    || !immutable(descriptor.planDigest, `${label}.planDigest`)
    || descriptor.assignment?.algorithm !== 'sha256-actor-bucket/v1'
    || !descriptor.assignment.seed || descriptor.profiles?.length < 2
    || descriptor.assignments?.length < 3) {
    fail(`${label} is not a complete deterministic version descriptor`);
  }
  descriptor.profiles.forEach((profile, index) => validateProfile(profile, `${label}.profiles[${index}]`));
  const names = new Set(descriptor.profiles.map(profile => profile.name));
  const actors = new Set();
  for (const assignment of descriptor.assignments) {
    if (!assignment.actor || !names.has(assignment.profile) || actors.has(assignment.actor)) {
      fail(`${label} has an invalid actor assignment`);
    }
    actors.add(assignment.actor);
  }
  return descriptor;
}

/** Validate all descriptor images were imported to every target node. */
export function validateA11Import(value, tree, descriptor) {
  qualified(value, tree, 'static import');
  const receipt = value.import;
  const nodes = receipt?.nodes?.map(node => node.name) ?? [];
  if (value.schemaVersion !== 'stacks-attacknet-a11-import-evidence/v1'
    || value.descriptorDigest !== descriptor.digest || receipt?.outcome !== 'Loaded'
    || nodes.length !== 3 || receipt.images?.length !== nodes.length * descriptor.profiles.length) {
    fail('A11 import receipt is incomplete');
  }
  for (const profile of descriptor.profiles) {
    const imported = receipt.images.filter(image => image.requestedRef === profile.image);
    if (imported.length !== nodes.length || imported.some(image => image.verified !== true
      || image.runtimeImageID !== profile.imageID)) {
      fail(`A11 import identity for ${profile.name} is incomplete`);
    }
  }
  return value;
}

function networkActors(network) { return new Map((network.status?.actors ?? []).map(actor => [actor.name, actor])); }

/** Validate a Ready mixed-version network against its sealed descriptor. */
export function validateA11Network(value, tree, descriptor, expectedName, finalUpgrade = false) {
  const network = snapshot(value, tree, 'StacksNetwork', `${expectedName} network`);
  const actors = networkActors(network);
  const profiles = new Map(descriptor.profiles.map(profile => [profile.name, profile]));
  const expected = new Map(descriptor.assignments.map(assignment => [assignment.actor, assignment.profile]));
  if (finalUpgrade) {
    for (const stage of descriptor.upgrade?.stages ?? []) {
      for (const assignment of stage.actors ?? []) expected.set(assignment.actor, assignment.profile);
    }
  }
  const configByActorProfile = new Map((descriptor.configurations ?? [])
    .map(configuration => [`${configuration.actor}\0${configuration.profile}`, configuration.configDigest]));
  if (network.metadata?.name !== expectedName || network.status?.phase !== 'Ready'
    || network.status.inventoryReady !== true
    || network.status.observedGeneration !== network.metadata.generation
    || !immutable(network.status.inventoryDigest, `${expectedName}.inventoryDigest`)
    || network.metadata.annotations?.['testing.stacks.org/version-descriptor-digest'] !== descriptor.digest) {
    fail(`${expectedName} is not a fully admitted mixed-version network`);
  }
  const runtimeIDs = new Set();
  for (const [actorName, profileName] of expected) {
    const actor = actors.get(actorName);
    const profile = profiles.get(profileName);
    const label = `${expectedName}/${actorName}`;
    if (!profile) fail(`${label} references unknown profile ${profileName}`);
    const configDigest = configByActorProfile.get(`${actorName}\0${profileName}`)
      ?? (profile.configSource ? profile.configDigest : undefined);
    if (!actor) fail(`${label} is absent from admitted actor status`);
    if (!actor.ready || !actor.identityReady) fail(`${label} is not identity-ready`);
    if (actor.image !== profile.image) {
      fail(`${label} requested image ${actor.image ?? '<absent>'}, expected ${profile.image}`);
    }
    if (!String(actor.runtimeImageID ?? '').endsWith(profile.imageID)) {
      fail(`${label} runtime image ID ${actor.runtimeImageID ?? '<absent>'} does not match ${profile.imageID}`);
    }
    if (actor.configDigest) immutable(actor.configDigest, `${label}.configDigest`);
    if (configDigest !== undefined && actor.configDigest !== configDigest) {
      fail(`${label} config digest ${actor.configDigest || '<absent>'} does not match ${configDigest}`);
    }
    if (!actor.podName || !actor.podUID || !actor.statefulSetUID || !actor.currentRevision
      || actor.currentRevision !== actor.updateRevision) {
      fail(`${label} lacks a current admitted Pod or StatefulSet rollout identity`);
    }
    runtimeIDs.add(profile.imageID);
  }
  if (!finalUpgrade && runtimeIDs.size < 2) fail(`${expectedName} does not contain a mixed-version cohort`);
  return network;
}

const stagedUpgradeActors = ['follower-2', 'miner-1', 'signer-1', 'signer-node-1'];
const stagedUpgradeCampaigns = ['follower-raw-config', 'signer-node', 'signer', 'miner'];

/** Validate a durable run decision for a completed staged upgrade. */
export function validateA11Upgrade(value, tree, expectedNetwork, runSnapshot) {
  qualified(value, tree, `${expectedNetwork} upgrade decision`);
  const decision = value.decision ?? {};
  const status = decision.evidence?.status ?? {};
  const transitions = status.identityTransitions ?? [];
  const actors = (status.appliedAssignments ?? []).map(assignment => assignment.actor).sort();
  if (value.schemaVersion !== 'stacks-attacknet-a11-upgrade-decision/v1'
    || value.network !== expectedNetwork || !value.runUID
    || !immutable(value.runResourceDigest, 'upgrade decision runResourceDigest')
    || decision.executionId !== 'roll-candidate' || decision.phase !== 'Passed'
    || !decision.child || !decision.childUid || !decision.source
    || decision.evidence?.kind !== 'UpgradeCampaign'
    || status.phase !== 'Passed' || status.observedGeneration < 1
    || status.rollbackComplete === true || !status.completedAt
    || decision.completedAt !== status.completedAt
    || status.currentStage !== stagedUpgradeCampaigns.length - 1
    || transitions.length !== stagedUpgradeCampaigns.length
    || actors.join(',') !== stagedUpgradeActors.join(',')
    || !immutable(status.baselineInventory?.digest, 'upgrade baseline inventory')
    || !immutable(status.currentInventory?.digest, 'upgrade current inventory')
    || status.baselineInventory.digest === status.currentInventory.digest) {
    fail(`${expectedNetwork} upgrade did not prove staged identity transitions`);
  }
  if (transitions.map(transition => transition.campaign).join(',') !== stagedUpgradeCampaigns.join(',')) {
    fail(`${expectedNetwork} upgrade stages do not match the sealed rollout order`);
  }
  for (const transition of transitions) {
    if (!transition.campaign || !transition.actors?.length
      || !immutable(transition.previousDigest, 'transition.previousDigest')
      || !immutable(transition.currentDigest, 'transition.currentDigest')
      || transition.previousDigest === transition.currentDigest
      || !Number.isFinite(Date.parse(transition.observedAt ?? ''))) {
      fail(`${expectedNetwork} contains an invalid identity transition`);
    }
  }
  if (runSnapshot) {
    const run = snapshot(runSnapshot, tree, 'AttacknetRun', `${expectedNetwork} run decision source`);
    const recorded = (run.status?.decisions ?? []).find(item => item.executionId === decision.executionId);
    if (runSnapshot.resourceDigest !== value.runResourceDigest || run.metadata?.uid !== value.runUID
      || JSON.stringify(recorded) !== JSON.stringify(decision)) {
      fail(`${expectedNetwork} upgrade decision is not bound to the durable run status`);
    }
  }
  return {decision, status};
}

/** Validate the scheduler owned and completed one upgrade child. */
export function validateA11Run(value, tree, expectedNetwork) {
  const run = snapshot(value, tree, 'AttacknetRun', `${expectedNetwork} run`);
  const decisions = run.status?.decisions ?? [];
  if (run.spec?.networkRef !== expectedNetwork || run.status?.phase !== 'Passed'
    || run.status.cleanup?.completed !== true || decisions.length !== 1
    || decisions[0].phase !== 'Passed'
    || run.status?.resolvedCampaigns?.length !== 1
    || run.status.resolvedCampaigns[0].kind !== 'UpgradeCampaign') {
    fail(`${expectedNetwork} run did not schedule and complete one upgrade campaign`);
  }
  return run;
}

/** Validate the boundary-aware qualification result and its artifact bindings. */
export function validateA11LiveResult(value, tree) {
  qualified(value, tree, 'live qualification');
  const boundary = value.boundary ?? {};
  if (value.schemaVersion !== 'stacks-attacknet-a11-live-qualification/v1'
    || value.outcome !== 'Passed' || value.architecture !== 'arm64'
    || value.kindNodes?.length !== 3 || new Set(value.kindNodes).size !== 3
    || boundary.type !== 'reward-cycle' || boundary.triggerHeight !== 239
    || boundary.boundaryHeight !== 241 || boundary.cadenceTransitionHeight !== 235
    || boundary.bootstrapCadence !== '5s' || boundary.boundaryCadence !== '15s'
    || boundary.primaryCadenceTransition?.cadence !== '15s'
    || boundary.replayCadenceTransition?.cadence !== '15s'
    || boundary.primaryCadenceTransition?.height < boundary.cadenceTransitionHeight
    || boundary.primaryCadenceTransition?.height >= boundary.triggerHeight
    || boundary.replayCadenceTransition?.height < boundary.cadenceTransitionHeight
    || boundary.replayCadenceTransition?.height >= boundary.triggerHeight
    || boundary.cycleLength !== 20 || boundary.firstHeight !== 0
    || boundary.triggerHeight >= boundary.boundaryHeight
    || boundary.observedBefore >= boundary.triggerHeight
    || boundary.observedAtTrigger < boundary.triggerHeight
    || boundary.observedAfter < boundary.boundaryHeight
    || boundary.replayObservedAtTrigger < boundary.triggerHeight
    || boundary.replayObservedAfter < boundary.boundaryHeight
    || !Number.isFinite(Date.parse(value.capturedAt ?? ''))) {
    fail('A11 live qualification does not prove the sealed boundary transition');
  }
  for (const [name, digest] of Object.entries(value.artifactDigests ?? {})) {
    if (!name || !immutable(digest, `liveQualification.artifactDigests.${name}`)) {
      fail('A11 live qualification contains an invalid artifact binding');
    }
  }
  if (Object.keys(value.artifactDigests ?? {}).length < 6) {
    fail('A11 live qualification does not bind its principal evidence');
  }
  return value;
}

/** Validate a complete incident manifest and every retained artifact. */
export function validateA11Incident(path) {
  const manifest = load(path, 'incident manifest');
  if (manifest.schemaVersion !== 'stacks-attacknet-incident-evidence/v1'
    || manifest.errors?.length || manifest.omissions?.length || !manifest.artifacts?.length) {
    fail('A11 incident bundle is incomplete');
  }
  const root = dirname(path);
  for (const entry of manifest.artifacts) {
    const candidate = resolve(root, entry.path);
    if (candidate === root || !containsPath(root, candidate)
      || digestFile(candidate) !== entry.sha256 || statSync(candidate).size !== entry.bytes) {
      fail(`incident artifact ${entry.path} is invalid`);
    }
  }
  return manifest;
}

/** Validate all A11-scoped Kubernetes resources were removed. */
export function validateA11Teardown(value, tree) {
  qualified(value, tree, 'clean teardown');
  if (value.schemaVersion !== 'stacks-attacknet-a11-clean-teardown/v1'
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))
    || !value.counts || Object.values(value.counts).some(count => count !== 0)) {
    fail('A11 teardown is not clean');
  }
  return value;
}

/** Validate all live A11 claims directly from one evidence directory. */
export function validateA11LiveQualification(directory, tree) {
  const artifact = key => load(join(directory, A11_ARTIFACTS[key]), key);
  validateA11Verification(artifact('verification'), tree);
  validateA11AttacknetCheck(artifact('attacknetCheck'), tree);
  validateA11HacknetCheck(artifact('hacknetCheck'), tree);
  validateA11CandidateBuild(artifact('candidateBuild'), tree);
  validateA11SourceDrift(artifact('sourceDrift'), tree);
  validateA11ConfigurationControl(artifact('configurationControl'), tree);
  validateA11TelemetryControl(artifact('telemetryControl'), tree);
  validateA11ProtocolControl(artifact('protocolControl'), tree);
  const staticDescriptor = validateA11Descriptor(artifact('staticDescriptor'), tree, 'static descriptor');
  validateA11Import(artifact('staticImport'), tree, staticDescriptor);
  validateA11Network(artifact('staticNetwork'), tree, staticDescriptor, 'a11-static');
  const upgradeDescriptor = validateA11Descriptor(artifact('upgradeDescriptor'), tree, 'upgrade descriptor');
  const primaryNetwork = validateA11Network(artifact('primaryNetwork'), tree, upgradeDescriptor, 'a11-upgrade');
  const primaryRunArtifact = artifact('primaryRun');
  const primaryRun = validateA11Run(primaryRunArtifact, tree, 'a11-upgrade');
  const primaryUpgrade = validateA11Upgrade(artifact('primaryUpgrade'), tree, 'a11-upgrade', primaryRunArtifact);
  const replayNetwork = validateA11Network(artifact('replayNetwork'), tree, upgradeDescriptor, 'a11-replay');
  const replayRunArtifact = artifact('replayRun');
  const replayRun = validateA11Run(replayRunArtifact, tree, 'a11-replay');
  const replayUpgrade = validateA11Upgrade(artifact('replayUpgrade'), tree, 'a11-replay', replayRunArtifact);
  const transitionShape = upgrade => upgrade.status.identityTransitions
    .map(transition => ({campaign: transition.campaign, actors: transition.actors}));
  if (primaryNetwork.metadata.uid === replayNetwork.metadata.uid
    || primaryRun.spec.seed !== replayRun.spec.seed
    || JSON.stringify(transitionShape(primaryUpgrade)) !== JSON.stringify(transitionShape(replayUpgrade))) {
    fail('A11 fresh-network replay does not preserve the sealed plan and outcome class');
  }
  validateA11Incident(join(directory, A11_ARTIFACTS.forensicManifest));
  validateA11Teardown(artifact('cleanTeardown'), tree);
  validateA11LiveResult(artifact('liveQualification'), tree);
  return true;
}

function walkFiles(current) {
  const result = [];
  for (const entry of readdirSync(current, {withFileTypes: true})) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) result.push(...walkFiles(path));
    else if (entry.isFile()) result.push(path);
  }
  return result.sort();
}

function artifact(path, archiveEntry) {
  return {path, archiveEntry, digest: digestFile(path)};
}

function portableArchiveEnvironment() {
  return {...process.env, COPYFILE_DISABLE: '1', GZIP: '-n'};
}

/** Copy, index, archive, and summarize a complete A11 qualification bundle. */
export function assembleA11Evidence({inputDirectory, outputDirectory, qualifiedTree}) {
  const input = resolve(inputDirectory);
  validateA11LiveQualification(input, qualifiedTree);
  const output = validateA11EvidenceOutput(input, outputDirectory);
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const staging = join(output, '.staging');
  mkdirSync(staging, {recursive: true});
  const artifactEntries = {};
  for (const [key, path] of Object.entries(A11_ARTIFACTS)) {
    const destination = join(staging, path);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, path), destination);
    artifactEntries[key] = artifact(destination, path);
  }
  const incidentSource = dirname(join(input, A11_ARTIFACTS.forensicManifest));
  for (const source of walkFiles(incidentSource)) {
    const entry = join('upgrade/incident', relative(incidentSource, source)).split(sep).join('/');
    if (entry === A11_ARTIFACTS.forensicManifest) continue;
    const destination = join(staging, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const entries = walkFiles(staging).map(path => ({
    path: relative(staging, path).split(sep).join('/'),
    digest: digestFile(path), size: statSync(path).size,
  }));
  const index = {schema: A11_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
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
  const incidentOutput = dirname(join(output, A11_ARTIFACTS.forensicManifest));
  rmSync(incidentOutput, {recursive: true, force: true});
  for (const source of walkFiles(incidentSource)) {
    const destination = join(incidentOutput, relative(incidentSource, source));
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(source, destination);
  }
  const summary = {
    schema: A11_SUMMARY_SCHEMA, qualifiedTree, generatedAt: new Date().toISOString(),
    assertions: A11_ASSERTIONS.map(id => ({id, status: 'passed'})), artifacts,
    archive: {
      path: archivePath, digest: digestFile(archivePath), location: 'local-review-bundle',
      indexPath, indexDigest: digestFile(indexPath), indexEntry: 'archive-index.json',
    },
  };
  const summaryPath = join(output, 'live-summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  return {summary, summaryPath};
}

/** Validate one portable A11 summary against a candidate. */
export function validateA11Summary(summary, candidate, summaryPath, root) {
  validatePortableLiveSummary(summary, candidate, {
    root, schema: A11_SUMMARY_SCHEMA, checkpoint: 'A11',
    requiredArtifacts: Object.keys(A11_ARTIFACTS), requiredAssertions: A11_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: summary.qualifiedTree, description: 'qualified Git tree'},
  });
  const evidenceRoot = dirname(resolve(root, summaryPath));
  if (resolve(root, summary.archive.indexPath) !== resolve(evidenceRoot, summary.archive.indexEntry)
    || resolve(root, summary.archive.path) !== resolve(evidenceRoot, 'archive', basename(summary.archive.path))) {
    fail('A11 archive paths do not resolve from the packet evidence root');
  }
  for (const [key, artifact] of Object.entries(summary.artifacts)) {
    if (resolve(root, artifact.path) !== resolve(evidenceRoot, artifact.archiveEntry)) {
      fail(`${key} does not resolve under the packet evidence root`);
    }
  }
  validateA11LiveQualification(evidenceRoot, summary.qualifiedTree);
  return summary;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const inputDirectory = value('--input=');
  const outputDirectory = value('--output=');
  const qualifiedTree = value('--qualified-tree=');
  if (!inputDirectory || !outputDirectory || !qualifiedTree) {
    fail('usage: evidence.mjs --input=PATH --output=PATH --qualified-tree=TREE');
  }
  const result = assembleA11Evidence({inputDirectory, outputDirectory, qualifiedTree});
  process.stdout.write(`${JSON.stringify(result.summary, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
