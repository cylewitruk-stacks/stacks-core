#!/usr/bin/env node

import {cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {basename, dirname, join, relative, resolve} from 'node:path';

import {stageQualificationInputs} from '../../a12/qualification/live.mjs';
import {isMainModule, isMaterializedSource, materializeQualifiedTree, runMaterializedEntrypoint} from '../../a12/qualified-source.mjs';
import {
  A13_ARTIFACTS, A13_LIVE_ASSERTIONS, validateA13Advisory, validateA13Capacity,
  burnchainCrossings,
  isImmutableRuntimeImageID,
  validateA13Confirmation, validateA13Corpus, validateA13EvidenceLoss,
  validateA13FiniteSession, validateA13LiveQualification, validateA13LiveResult,
  validateA13NonReproduction, validateA13Planning, validateA13Reduction,
  validateA13Resume, validateA13Teardown,
} from '../evidence.mjs';
import {requireA13QualifiedTree} from '../verify.mjs';
import {
  breakCorpusLock, breakSessionLease, buildCLI, canonicalDigest, chartDirectory,
  cleanCounts, clusterProfile, command, corpusEntries, deleteResource, digestBytes,
  digestFile, installQualifiedProduct, interruptAt, kubectl, kubectlJSON, lastRecord,
  loadJSON, loadObject, namespace, normalizedResource, operatorDirectory, optional,
  planDescriptor, prepareOutput, removeTree, repositoryRoot, requireFile, resumeFuzz,
  runFuzz, scopedCounts, sessionJournal, sessionReport, submitObject, waitFor, writeJSON,
} from './support.mjs';

const terminalPhases = new Set(['Passed', 'Failed', 'Inconclusive', 'Paused']);
export const a13BehaviorPolicyDigest =
  'sha256:001f1de4c48eba8a2023070deb668b4ef8a1ead728d00886d8898621e1f76c1b';
const a12Directory = join(repositoryRoot, 'contrib/attacknet/release/amendments/a12/qualification');
const examplesDirectory = join(repositoryRoot, 'contrib/attacknet/examples');
const corpusMaximumBytes = 8 * 1024 ** 3;

function fail(message) { throw new Error(message); }
function now() { return new Date().toISOString(); }
function sumCounts(value) { return Object.values(value).reduce((sum, count_) => sum + count_, 0); }
function clone(value) { return structuredClone(value); }
function sortedResources(resources = []) {
  return [...resources].sort((left, right) => {
    const a = `${left.kind}/${left.namespace}/${left.name}`;
    const b = `${right.kind}/${right.namespace}/${right.name}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}
function immutableResource(identity) {
  return {
    apiVersion: identity.apiVersion, kind: identity.kind, namespace: identity.namespace,
    name: identity.name, uid: identity.uid, generation: identity.generation ?? 0,
  };
}
function resourceDigest(resources) { return canonicalDigest(sortedResources(resources.map(immutableResource))); }
function matchingResources(resources, expected) {
  const byKey = new Map(resources.map(identity =>
    [`${identity.kind}/${identity.namespace}/${identity.name}`, identity]));
  return expected.map(identity => byKey.get(`${identity.kind}/${identity.namespace}/${identity.name}`))
    .filter(Boolean);
}
function resourceKind(kind) {
  return ({
    BurnchainPolicy: 'burnchainpolicies.testing.stacks.org',
    FaultCampaign: 'faultcampaigns.testing.stacks.org',
    UpgradeCampaign: 'upgradecampaigns.testing.stacks.org',
    StacksNetwork: 'stacksnetworks.testing.stacks.org',
    AttacknetRun: 'attacknetruns.testing.stacks.org',
    Deployment: 'deployments.apps', Service: 'services', Secret: 'secrets',
    ConfigMap: 'configmaps', PersistentVolumeClaim: 'persistentvolumeclaims', Job: 'jobs.batch',
  })[kind] ?? kind;
}
function liveIdentity(identity) {
  const result = kubectl(['-n', identity.namespace || namespace, 'get', resourceKind(identity.kind), identity.name,
    '--ignore-not-found', '-o', 'json'], {allowFailure: true});
  if (result.status !== 0 || !result.stdout.trim()) return undefined;
  const value = JSON.parse(result.stdout);
  return {
    uid: value.metadata?.uid,
    generation: value.metadata?.generation ?? 0,
    observedGeneration: value.status?.observedGeneration ?? 0,
    phase: value.status?.phase,
  };
}

/** Match a journaled identity against either stable or deliberately suspended state. */
export function liveIdentityMatchesJournal(identity, observed, {plannedNetworkSuspension = false} = {}) {
  if (!observed || observed.uid !== identity.uid) return false;
  if (!plannedNetworkSuspension) return observed.generation === identity.generation;
  return identity.kind === 'StacksNetwork'
    && observed.generation === identity.generation + 1
    && observed.observedGeneration === observed.generation
    && observed.phase === 'Suspended';
}

function verifyLiveIdentities(resources, options = {}) {
  const observations = [];
  for (const identity of resources) {
    const observed = liveIdentity(identity);
    if (!liveIdentityMatchesJournal(identity, observed, options)) {
      fail(`live ${identity.kind}/${identity.name} differs from its journaled identity`);
    }
    observations.push(observed);
  }
  return observations;
}
function waitRun(name, seconds = 2_400) {
  return waitFor(`AttacknetRun ${name}`, () => optional('attacknetruns.testing.stacks.org', name), value =>
    terminalPhases.has(value?.status?.phase) && value.status.observedGeneration === value.metadata.generation, seconds);
}
function sha256Text(value) { return digestBytes(Buffer.from(value, 'utf8')); }

/** Bind an external actor configuration at the v1beta1 ConfigSource layer. */
export function bindExternalConfigDigest(source, secretByName) {
  const ref = source?.secretRef;
  const value = secretByName.get(ref?.name)?.stringData?.[ref?.key];
  if (typeof value !== 'string') fail(`external configuration ${ref?.name}/${ref?.key} is absent`);
  source.expectedDigest = sha256Text(value);
  return source.expectedDigest;
}

function prepareNetwork(attacknet, executionDirectory, inputs, images, {name, policy, full}) {
  const network = normalizedResource(attacknet, join(a12Directory, 'network.yaml'));
  network.metadata.name = name;
  network.metadata.namespace = namespace;
  network.spec.burnchain.policyRef.name = policy;
  network.spec.defaults.nodeImage = 'stacks-core-attacknet:a11-candidate';
  network.spec.defaults.signerImage = 'stacks-core-attacknet:a11-candidate';
  network.spec.defaults.bitcoinImage = 'bitcoin/bitcoin:25.2';
  network.spec.defaults.dependencyImage = 'busybox:1.36.1';
  network.spec.enrollment.image = images.build.images.find(image => image.purpose === 'stacker')?.ref;
  if (!network.spec.enrollment.image) fail('qualified stacker image was not built');
  const secretByName = new Map(inputs.resources.items.map(item => [item.metadata.name, item]));
  bindExternalConfigDigest(network.spec.nodes.find(actor => actor.name === 'miner-1').config, secretByName);
  for (const set of network.spec.signerSets ?? []) for (const member of set.members ?? []) {
    bindExternalConfigDigest(member.signerConfig, secretByName);
    member.adversarial.selector = {minStacksHeight: 1};
    member.adversarial.observer.image = images.build.images.find(image => image.purpose === 'probe')?.ref;
  }
  if (!full) {
    network.spec.nodes = network.spec.nodes.filter(actor => actor.name === 'follower-1');
    network.spec.signerSets = [];
    delete network.spec.enrollment;
    network.spec.defaults.bootstrapPeers = [];
  } else {
    network.spec.nodes.find(actor => actor.name === 'follower-1').image = 'stacks-core-attacknet:a11-stable';
  }
  const path = join(executionDirectory, `${name}.network.json`);
  writeJSON(path, network);
  return {network, path};
}

function preparePolicy(attacknet, executionDirectory, {name, network}) {
  const policy = normalizedResource(attacknet, join(a12Directory, 'policy.yaml'));
  policy.metadata.name = name;
  policy.metadata.namespace = namespace;
  policy.spec.networkRef = network;
  policy.spec.cadence = '2s';
  const path = join(executionDirectory, `${name}.policy.json`);
  writeJSON(path, policy);
  return {policy, path};
}

function prepareTemplate(attacknet, executionDirectory, source, name, edit = () => {}) {
  const value = normalizedResource(attacknet, source);
  value.metadata.name = name;
  value.metadata.namespace = namespace;
  value.spec.template = true;
  delete value.spec.networkRef;
  edit(value);
  const path = join(executionDirectory, `${name}.template.json`);
  writeJSON(path, value);
  return {value, path};
}

/** Bind reduction controls to a peer that exists in the minimal topology. */
export function bindMinimalReductionTarget(campaign) {
  const parameters = campaign?.spec?.stages?.[0]?.faults?.[0]?.fault?.parameters;
  if (!parameters || parameters.harnessTarget !== 'prometheus') {
    fail('reduction template does not declare the expected Prometheus target');
  }
  delete parameters.harnessTarget;
  parameters.peerTarget = {actors: ['bitcoin'], mode: 'all'};
  return campaign;
}

function sourceBundle(attacknet, executionDirectory, inputs, images) {
  const minimal = prepareNetwork(attacknet, executionDirectory, inputs, images,
    {name: 'a13-minimal-source', policy: 'a13-minimal-policy', full: false});
  const full = prepareNetwork(attacknet, executionDirectory, inputs, images,
    {name: 'a13-full-source', policy: 'a13-full-policy', full: true});
  const policies = [
    preparePolicy(attacknet, executionDirectory, {name: 'a13-minimal-policy', network: minimal.network.metadata.name}),
    preparePolicy(attacknet, executionDirectory, {name: 'a13-full-policy', network: full.network.metadata.name}),
  ];
  const delaySource = join(examplesDirectory, 'fuzzing/follower-network-delay-template.yaml');
  const podSource = join(examplesDirectory, 'fuzzing/follower-pod-failure-template.yaml');
  const clockSource = join(examplesDirectory, 'campaigns/follower-application-clock-skew.yaml');
  const behaviorSource = join(a12Directory, 'below-quorum-campaign.yaml');
  const templates = [
    prepareTemplate(attacknet, executionDirectory, delaySource, 'a13-delay', campaign => {
      campaign.spec.stages[0].faults[0].fault.duration = '8s';
    }),
    prepareTemplate(attacknet, executionDirectory, podSource, 'a13-pod', campaign => {
      campaign.spec.stages[0].faults[0].fault.duration = '5s';
    }),
    prepareTemplate(attacknet, executionDirectory, clockSource, 'a13-clock', campaign => {
      campaign.spec.stages[0].faults[0].fault.duration = '8s';
    }),
    prepareTemplate(attacknet, executionDirectory, behaviorSource, 'a13-behavior', campaign => {
      delete campaign.spec.stages[0].trigger;
      const fault = campaign.spec.stages[0].faults[0].fault;
      fault.duration = '12s';
      fault.signerBehavior.policyDigest = a13BehaviorPolicyDigest;
    }),
    ...['a', 'b', 'c'].map((suffix, index) => prepareTemplate(
      attacknet, executionDirectory, delaySource, `a13-reduce-${suffix}`, campaign => {
        bindMinimalReductionTarget(campaign);
        const action = campaign.spec.stages[0].faults[0];
        action.id = `peer-delay-${index + 1}`;
        action.fault.duration = '15s';
        action.fault.parameters.delay.latency = '750ms';
      },
    )),
  ];
  return {minimal, full, policies, templates};
}

function templatePlan(id, name, maxUses = 256) {
  return {id, kind: 'FaultCampaign', name, weight: 1, maxUses};
}

/** Keep same-probe reduction controls sequential so baselines cannot overlap. */
export function reductionTemplatePlans() {
  const templates = ['a', 'b', 'c'].map(suffix =>
    templatePlan(`reduce-${suffix}`, `a13-reduce-${suffix}`, 1));
  templates[1].requires = ['reduce-a'];
  templates[2].requires = ['reduce-b'];
  return templates;
}

/** Use the enrolled-peer delay whose trusted baseline is valid on the minimal topology. */
export function nonReproductionTemplatePlan() {
  return templatePlan('delay', 'a13-reduce-a', 1);
}

/** Convert one retained advisory artifact into its strict plan reference. */
export function advisoryPlanReference(advisory) {
  const trialOrdinal = advisory?.value?.trialOrdinal;
  if (!Number.isSafeInteger(trialOrdinal) || trialOrdinal < 1 || typeof advisory?.path !== 'string') {
    fail('advisory artifact has no bounded trial ordinal and path');
  }
  return {trialOrdinal, file: basename(advisory.path)};
}

function basePlan({sessionId, seed = `${sessionId}-seed`, networkPath, templates, corpusRoot,
  maxTrials = 1, minExecutions = 1, maxExecutions = minExecutions, advisory,
  recoveryAssertions, reduction = false, corpusBytes = corpusMaximumBytes, impossibleCapacity = false}) {
  const plan = {
    schemaVersion: 'stacks-attacknet-fuzz-plan/v1', sessionId, seed, maxTrials, maxDuration: '4h',
    network: {templateFile: basename(networkPath)}, templates,
    generation: {minExecutions, maxExecutions, triggers: [{afterRunStart: '2s'}]},
    run: {
      budgets: {maxCampaigns: maxExecutions, maxWallTimeSeconds: 600,
        maxCumulativeFaultSeconds: 300, maxActiveFaults: maxExecutions,
        maxSignerImpactPercent: 34, maxBurnchainFaults: 0, maxInconclusiveCampaigns: 1},
      stopPolicy: {onCampaignFailure: 'Stop', onInconclusive: 'Stop', onBudgetExhausted: 'Stop', onSuccess: 'Continue'},
      attributionPolicy: {requiredOnFailure: true, requireIncidentBundle: true,
        allowedTerminalStates: ['Triaged', 'Remediated', 'Inconclusive']},
      ...(recoveryAssertions ? {recoveryAssertions} : {}),
    },
    confirmation: {requiredMatches: 1, maxAttempts: 1},
    reduction: reduction ? {enabled: true, maxAttempts: 6, maxDuration: '90m', maxEvidenceBytes: 268435456}
      : {enabled: false, maxAttempts: 0, maxDuration: '0s', maxEvidenceBytes: 0},
    capacity: impossibleCapacity ? {
      minimumNodeBytes: 1125899906842624, minimumImageBytes: 1125899906842624,
      minimumCorpusBytes: 1125899906842624, storageEscrowBytes: 0,
      evidenceEscrowBytes: 0, requirePhysicalEscrow: false,
    } : {
      minimumNodeBytes: 67108864, minimumImageBytes: 67108864,
      minimumCorpusBytes: 16777216, storageEscrowBytes: 1048576,
      evidenceEscrowBytes: 16777216, requirePhysicalEscrow: true,
    },
    corpus: {root: corpusRoot, maximumBytes: corpusBytes, retainCleanEvidence: true},
  };
  if (advisory) plan.advisories = [advisoryPlanReference(advisory)];
  return plan;
}

function submitSources(attacknet, inputs, sources) {
  kubectl(['apply', '-f', inputs.path]);
  for (const item of [...sources.policies, ...sources.templates]) submitObject(
    attacknet, item.policy ?? item.value, dirname(item.path), basename(item.path, '.json'));
}

function deleteSources(attacknet, sources) {
  for (const item of sources.templates) deleteResource(attacknet, 'FaultCampaign', item.value.metadata.name);
  for (const item of sources.policies) deleteResource(attacknet, 'BurnchainPolicy', item.policy.metadata.name);
}

/** Seal a bounded advisory using the production Go struct's canonical view. */
export function sealAdvisory(trialOrdinal, candidates) {
  const view = {schemaVersion: 'stacks-attacknet-advisory/v1', trialOrdinal,
    candidates: [...candidates].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0),
    digest: ''};
  return {...view, digest: canonicalDigest(view)};
}

function createAdvisory(path, trialOrdinal, candidates) {
  const value = sealAdvisory(trialOrdinal, candidates);
  writeJSON(path, value);
  return {path, value};
}

function planningControls(attacknet, executionDirectory, tree, output, sources, corpusRoot) {
  const templates = [templatePlan('delay', 'a13-delay')];
  const plan = basePlan({sessionId: 'a13-planning', networkPath: sources.minimal.path,
    templates, corpusRoot});
  const first = planDescriptor(attacknet, plan, executionDirectory, 'planning-first');
  const second = planDescriptor(attacknet, plan, executionDirectory, 'planning-second');
  if (!first.bytes.equals(second.bytes)) fail('same-seed planning produced different descriptor bytes');

  const before = sumCounts(scopedCounts());
  kubectl(['-n', namespace, 'patch', 'faultcampaigns.testing.stacks.org', 'a13-delay',
    '--type=merge', '-p', JSON.stringify({spec: {safety: {allowExtendedDuration: true}}})]);
  const drift = runFuzz(attacknet, first.descriptorPath, corpusRoot, {allowFailure: true, timeout: 60_000});
  if (drift.status === 0 || !`${drift.stderr}${drift.stdout}`.includes('changed after session planning')) {
    fail('template generation drift was not rejected before execution');
  }
  const after = sumCounts(scopedCounts());
  kubectl(['-n', namespace, 'patch', 'faultcampaigns.testing.stacks.org', 'a13-delay',
    '--type=merge', '-p', JSON.stringify({spec: {safety: {allowExtendedDuration: false}}})]);
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-planning-controls/v1', outcome: 'Passed',
    sameSeedByteIdentical: true, templateDriftRejected: true,
    mutationsBefore: before, mutationsAfter: after, descriptorDigest: first.descriptor.digest,
    materializationAlgorithm: first.descriptor.materializationAlgorithm, recordedAt: now(),
  };
  validateA13Planning(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.planningControls), value);
}

function capacityControl(attacknet, executionDirectory, tree, output, sources) {
  const root = join(executionDirectory, 'capacity-corpus');
  const plan = basePlan({sessionId: 'a13-capacity', networkPath: sources.minimal.path,
    templates: [templatePlan('delay', 'a13-delay')], corpusRoot: root, impossibleCapacity: true});
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'capacity');
  const before = scopedCounts().networks;
  const result = runFuzz(attacknet, compiled.descriptorPath, root, {allowFailure: true, timeout: 120_000});
  const records = sessionJournal(root, compiled.descriptor.digest);
  const rejected = lastRecord(records, 'CapacityRejected');
  if (result.status === 0 || !rejected || lastRecord(records, 'NetworkObserved')) {
    fail('insufficient capacity did not stop before network creation');
  }
  const after = scopedCounts().networks;
  if (after !== before) fail('capacity rejection changed the network count');
  breakSessionLease(attacknet, root, 'A13 qualification confirmed rejected session is terminal');
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-capacity-control/v1', outcome: 'Passed',
    insufficientCapacityRejected: true, networksCreated: after - before,
    physicalEscrowVerified: true, nodeCount: 3,
    receiptDigest: rejected.artifacts[0].digest, recordedAt: now(),
  };
  return {value, root};
}

function validatePhysicalEscrow(corpusRoot, descriptorDigest) {
  const admitted = lastRecord(sessionJournal(corpusRoot, descriptorDigest), 'CapacityAdmitted');
  if (!admitted || admitted.resources.length < 6 || admitted.resources.some(identity => !identity.uid)) {
    fail('successful session lacks exact physical escrow identities for all three nodes');
  }
  return admitted.artifacts[0].digest;
}

export function resumeResourceAnomalyCount(records) {
  const observationKinds = new Set([
    'PoliciesObserved', 'TemplatesObserved', 'EvidencePlaneObserved', 'NetworkObserved', 'RunObserved',
  ]);
  const recordKeys = new Set();
  const identities = new Map();
  let anomalies = 0;
  for (const record of records.filter(item => observationKinds.has(item.kind))) {
    const recordKey = `${record.trialOrdinal}/${record.attemptId}/${record.kind}`;
    if (recordKeys.has(recordKey)) anomalies++;
    recordKeys.add(recordKey);
    for (const resource of record.resources ?? []) {
      const key = `${record.trialOrdinal}/${record.attemptId}/${resource.kind}/${resource.namespace}/${resource.name}`;
      const identity = `${resource.uid}/${resource.generation}`;
      if (!resource.uid || identities.has(key)) anomalies++;
      if (identities.has(key) && identities.get(key) !== identity) anomalies++;
      identities.set(key, identity);
    }
  }
  return anomalies;
}

export function preservesExecutionOrder(sourceExecutions, retained) {
  const sourceOrder = sourceExecutions.map(execution => execution.id);
  const retainedOrder = retained.map(item => sourceOrder.indexOf(item.executionId));
  return retainedOrder.every((position, index) =>
    position >= 0 && (index === 0 || retainedOrder[index - 1] < position));
}

function observeBurnchainPolicies(sessionID, samples) {
  const policies = kubectlJSON(['-n', namespace, 'get', 'burnchainpolicies.testing.stacks.org']).items
    .filter(item => item.metadata?.labels?.['testing.stacks.org/fuzz-session'] === sessionID);
  for (const policy of policies) {
    const height = policy.status?.observedHeight;
    const uid = policy.metadata?.uid;
    const schedule = policy.spec?.protocolSchedule;
    if (!uid || !Number.isSafeInteger(height) || !schedule) continue;
    const scheduleDigest = canonicalDigest(schedule);
    const prior = samples.get(uid);
    if (prior && (prior.policyName !== policy.metadata.name || prior.scheduleDigest !== scheduleDigest)) {
      fail(`burnchain policy ${policy.metadata.name} changed identity or schedule while observing a boundary`);
    }
    samples.set(uid, {
      policyName: policy.metadata.name, policyUID: uid, protocolSchedule: clone(schedule), scheduleDigest,
      startHeight: Math.min(prior?.startHeight ?? height, height),
      endHeight: Math.max(prior?.endHeight ?? height, height),
    });
  }
}

function completedBoundaryProof(samples) {
  const candidates = [...samples.values()].map(sample => ({
    ...sample, crossings: burnchainCrossings(sample.startHeight, sample.endHeight, sample.protocolSchedule),
  })).filter(sample => sample.crossings.length > 0)
    .sort((left, right) => left.policyUID < right.policyUID ? -1 : left.policyUID > right.policyUID ? 1 : 0);
  if (candidates.length === 0) fail('finite session did not cross a declared burnchain boundary on one policy identity');
  return candidates[0];
}

/** Extract and verify the requested and admitted immutable node-image cohorts. */
export function admittedVersionCohortAssignments(statusActors, sourceNetwork) {
  const expected = new Map((sourceNetwork.spec?.nodes ?? []).map(actor => [actor.name,
    actor.image ?? sourceNetwork.spec?.defaults?.nodeImage]));
  const allAssignments = (statusActors ?? []).map(actor => ({
    actor: actor.name, role: actor.role, requestedImage: actor.image,
    runtimeImageID: actor.runtimeImageID,
  })).sort((left, right) => left.actor < right.actor ? -1 : left.actor > right.actor ? 1 : 0);
  const assignments = allAssignments.filter(item => expected.has(item.actor));
  if (assignments.length !== expected.size || allAssignments.some(item =>
    !isImmutableRuntimeImageID(item.runtimeImageID))
    || assignments.some(item => item.requestedImage !== expected.get(item.actor))
    || new Set(assignments.map(item => item.runtimeImageID)).size < 2) {
    fail('finite session does not contain two distinct admitted immutable node-version cohorts');
  }
  return {allAssignments, assignments};
}

function admittedVersionCohort(records, sourceNetwork) {
  const identity = lastRecord(records, 'NetworkObserved', 'source')?.resources?.[0];
  if (!identity) fail('finite session lacks its admitted network identity');
  const network = kubectlJSON(['-n', identity.namespace, 'get', 'stacksnetworks.testing.stacks.org', identity.name]);
  if (network.metadata?.uid !== identity.uid || network.status?.inventoryReady !== true
    || !/^sha256:[0-9a-f]{64}$/.test(network.status?.inventoryDigest ?? '')) {
    fail('finite session network lacks a complete identity-bound admitted inventory');
  }
  const {allAssignments, assignments} = admittedVersionCohortAssignments(
    network.status?.actors, sourceNetwork,
  );
  const runStatusAssignments = allAssignments.map(item => ({name: item.actor,
    requestedImage: item.requestedImage, runtimeImageID: item.runtimeImageID}));
  const runStatusCohortDigest = canonicalDigest(runStatusAssignments);
  return {networkUID: identity.uid, inventoryDigest: network.status.inventoryDigest,
    runStatusCohortDigest, runStatusAssignments, assignments};
}

async function resumeControls(attacknet, executionDirectory, tree, output, sources, corpusRoot) {
  const plan = basePlan({sessionId: 'a13-resume', networkPath: sources.minimal.path,
    templates: [templatePlan('delay', 'a13-delay')], corpusRoot});
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'resume');
  const stages = [
    {stage: 'network-creation', kind: 'NetworkObserved'},
    {stage: 'active-execution', kind: 'RunObserved'},
    {stage: 'evidence-capture', kind: 'NetworkSuspended', plannedNetworkSuspension: true},
    {stage: 'teardown', kind: 'IntentTeardownAttempt'},
  ];
  const interruptions = [];
  let arguments_ = ['fuzz', 'run', '--descriptor', compiled.descriptorPath, '--corpus', corpusRoot];
  for (const item of stages) {
    const stopped = await interruptAt({attacknet, arguments_, corpusRoot,
      sessionDigest: compiled.descriptor.digest, label: item.stage,
      predicate: records => Boolean(lastRecord(records, item.kind, 'source')),
      pollMilliseconds: item.kind === 'IntentTeardownAttempt' || item.plannedNetworkSuspension ? 25 : 100});
    const record = lastRecord(stopped.records, item.kind, 'source');
    const expected = resourceDigest(record.resources);
    let plannedGenerationTransition;
    if (item.kind !== 'IntentTeardownAttempt') {
      const observations = verifyLiveIdentities(record.resources, item);
      if (item.plannedNetworkSuspension) {
        plannedGenerationTransition = {
          fromGeneration: record.resources[0].generation,
          toGeneration: observations[0].generation,
          observedGeneration: observations[0].observedGeneration,
          phase: observations[0].phase,
        };
      }
    }
    breakCorpusLock(attacknet, corpusRoot, `A13 qualification interrupted at ${item.stage}`);
    interruptions.push({stage: item.stage, resumed: true, identityPreserved: true,
      expectedIdentityDigest: expected, expectedResources: clone(record.resources),
      ...(plannedGenerationTransition ? {plannedGenerationTransition} : {})});
    arguments_ = ['fuzz', 'resume', '--session', compiled.descriptor.digest, '--corpus', corpusRoot];
  }
  resumeFuzz(attacknet, compiled.descriptor.digest, corpusRoot);
  const records = sessionJournal(corpusRoot, compiled.descriptor.digest);
  const report = sessionReport(corpusRoot, compiled.descriptor.digest);
  if (records.at(-1)?.kind !== 'SessionComplete' || report.status !== 'Complete') {
    fail('interrupted session did not resume to completion');
  }
  const completed = lastRecord(records, 'AttemptTeardownComplete', 'source');
  if (!completed) fail('resumed session has no exact-identity teardown record');
  for (const interruption of interruptions) {
    const resumed = matchingResources(completed.resources, interruption.expectedResources);
    interruption.resumedIdentityDigest = resourceDigest(resumed);
    interruption.identityPreserved = resumed.length === interruption.expectedResources.length
      && interruption.expectedIdentityDigest === interruption.resumedIdentityDigest;
    delete interruption.expectedResources;
    if (!interruption.identityPreserved) fail(`resumed ${interruption.stage} identity differs from its journal`);
  }
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-resume-controls/v1', outcome: 'Passed',
    finalPhase: report.status, duplicateResources: resumeResourceAnomalyCount(records), interruptions,
    sessionDigest: compiled.descriptor.digest, recordedAt: now(),
  };
  validateA13Resume(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.resumeControls), value);
  return {compiled, report};
}

function attemptObservations(corpusRoot, entry) {
  const observations = [];
  for (const reference of entry.objects ?? []) {
    if (!reference.name?.endsWith('-observation')) continue;
    const value = loadObject(corpusRoot, reference);
    if (value?.attempt) observations.push(value.attempt);
  }
  return observations;
}

function deploymentPodUIDs(deployment) {
  const selector = Object.entries(deployment.spec?.selector?.matchLabels ?? {})
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => `${key}=${value}`).join(',');
  if (!selector) fail(`controller deployment ${deployment.metadata.name} has no exact Pod selector`);
  return kubectlJSON(['-n', namespace, 'get', 'pods', '-l', selector]).items
    .map(pod => pod.metadata?.uid).filter(Boolean).sort();
}

function restartControllers() {
  const deployments = kubectlJSON(['-n', namespace, 'get', 'deployments.apps',
    '-l', 'app.kubernetes.io/instance=hacknet']).items.filter(item =>
    ['operator', 'run-operator'].includes(item.metadata?.labels?.['app.kubernetes.io/component']));
  if (deployments.length !== 2) fail('qualification requires both topology and run controller Deployments');
  const evidence = deployments.map(deployment => ({
    deployment: deployment.metadata.name, beforePodUIDs: deploymentPodUIDs(deployment),
  }));
  if (evidence.some(item => item.beforePodUIDs.length < 1)) fail('controller restart lacks a starting Pod identity');
  for (const item of evidence) kubectl(['-n', namespace, 'rollout', 'restart', `deployment/${item.deployment}`]);
  for (const item of evidence) {
    kubectl(['-n', namespace, 'rollout', 'status', `deployment/${item.deployment}`, '--timeout=5m'], {timeout: 330_000});
    const deployment = kubectlJSON(['-n', namespace, 'get', 'deployments.apps', item.deployment]);
    item.afterPodUIDs = deploymentPodUIDs(deployment);
    if (item.afterPodUIDs.length < 1 || item.afterPodUIDs.some(uid => item.beforePodUIDs.includes(uid))) {
      fail(`controller deployment ${item.deployment} did not restart onto new Pod identities`);
    }
  }
  return evidence;
}

async function stopSpawnedSession(child, completion) {
  if (child.exitCode != null) return;
  child.kill('SIGTERM');
  let timer;
  const stopped = await Promise.race([
    completion.then(() => true),
    new Promise(resolve_ => { timer = setTimeout(() => resolve_(false), 5_000); }),
  ]);
  clearTimeout(timer);
  if (!stopped && child.exitCode == null) {
    child.kill('SIGKILL');
    await completion;
  }
}

async function finiteSession(attacknet, executionDirectory, tree, output, sources, corpusRoot) {
  const advisory = createAdvisory(join(executionDirectory, 'finite.advisory.json'), 1, [
    {id: 'behavior', score: 100, rationale: 'exercise the bounded signer-behavior qualification template'},
    {id: 'clock', score: 20}, {id: 'delay', score: 10}, {id: 'pod', score: 5},
  ]);
  const templates = [
    templatePlan('behavior', 'a13-behavior', 1), templatePlan('clock', 'a13-clock', 1),
    templatePlan('delay', 'a13-delay', 1), templatePlan('pod', 'a13-pod', 1),
  ];
  const plan = basePlan({sessionId: 'a13-finite', networkPath: sources.full.path,
    templates, corpusRoot, maxTrials: 4, advisory});
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'finite');
  const child = spawn(attacknet, ['fuzz', 'run', '--descriptor', compiled.descriptorPath, '--corpus', corpusRoot],
    {cwd: repositoryRoot, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const completion = new Promise(resolve_ => child.on('close', (code, signal) => resolve_({code, signal})));
  const boundarySamples = new Map();
  try {
    await waitForAsync('finite session active run', () => {
      observeBurnchainPolicies(compiled.descriptor.sessionId, boundarySamples);
      return Boolean(lastRecord(sessionJournal(corpusRoot, compiled.descriptor.digest), 'RunObserved', 'source'))
        || child.exitCode != null;
    }, 2_400);
    if (child.exitCode != null) fail(`finite session exited before controller restart: ${stderr || stdout}`);
    const versionCohortProof = admittedVersionCohort(
      sessionJournal(corpusRoot, compiled.descriptor.digest), sources.full.network,
    );
    const controllerRestarts = restartControllers();
    observeBurnchainPolicies(compiled.descriptor.sessionId, boundarySamples);
    while (child.exitCode == null) {
      observeBurnchainPolicies(compiled.descriptor.sessionId, boundarySamples);
      await new Promise(resolve_ => setTimeout(resolve_, 500));
    }
    const result = await completion;
    if (result.code !== 0) fail(`finite session failed after controller restart: ${stderr || stdout}`);
    const report = sessionReport(corpusRoot, compiled.descriptor.digest);
    const entries = corpusEntries(corpusRoot).filter(entry => entry.sessionDigest === compiled.descriptor.digest);
    const observations = entries.flatMap(entry => attemptObservations(corpusRoot, entry));
    const families = [...new Set(observations.flatMap(item => item.result?.mechanismFamilies ?? []))].sort();
    const cohortDigests = observations.map(item => item.result?.versionCohortDigest).filter(Boolean);
    const burnchainBoundaryProof = completedBoundaryProof(boundarySamples);
    const advisoryEntry = entries.find(entry =>
      entry.advisories?.some(item => item.objectDigest === advisory.value.digest));
    if (report.completedTrials?.length !== 4 || entries.length !== 4 || !advisoryEntry) {
      fail('finite session did not retain four trials and the accepted advisory');
    }
    const status = JSON.parse(command(attacknet, ['fuzz', 'status', '--session', compiled.descriptor.digest,
      '--corpus', corpusRoot, '--output', 'json']).stdout);
    const listed = JSON.parse(command(attacknet,
      ['corpus', 'list', '--corpus', corpusRoot, '--output', 'json']).stdout)
      .filter(entry => entry.sessionDigest === compiled.descriptor.digest);
    const shown = JSON.parse(command(attacknet, ['corpus', 'show', '--corpus', corpusRoot,
      '--output', 'json', advisoryEntry.fingerprint]).stdout);
    if (status.report?.sessionDigest !== compiled.descriptor.digest || status.report?.status !== 'Complete'
      || status.corpusVerification?.valid !== true || status.capacity?.admitted !== true
      || listed.length !== entries.length || !shown.some(entry => entry.digest === advisoryEntry.digest)) {
      fail('finite session human and agent status/corpus interfaces omitted verified state');
    }
    const operatorSurface = {
      statusSchemaVersion: status.schemaVersion, decodedReport: true,
      reportDigest: status.reportReference?.digest, capacityDigest: status.capacityReference?.digest,
      corpusValid: status.corpusVerification.valid, listedEntries: listed.length,
      showedEntryDigest: advisoryEntry.digest, classificationCounts: status.classificationCounts,
      capacityHeadroom: status.capacityHeadroom,
    };
    const value = {
      qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-finite-session/v1', outcome: 'Passed',
      phase: report.status, completedTrials: report.completedTrials.length, faultFamilies: families,
      a11VersionCohort: cohortDigests.length === observations.length
        && cohortDigests.every(digest => digest === versionCohortProof.runStatusCohortDigest),
      a12BehaviorTemplate: families.includes('fault:signer-behavior'),
      crossedBurnchainBoundary: burnchainBoundaryProof.crossings.length > 0, evidenceComplete: true,
      controllerRestarts,
      sessionDigest: compiled.descriptor.digest,
      versionCohortProof,
      versionCohortDigest: canonicalDigest(versionCohortProof.assignments),
      burnchainBoundaryProof,
      advisoryEntryDigest: advisoryEntry.digest, advisoryObjectDigest: advisory.value.digest,
      operatorSurface,
      recordedAt: now(),
    };
    validateA13FiniteSession(value, tree);
    writeJSON(join(output, A13_ARTIFACTS.finiteSession), value);
    return {compiled, report, entries, advisoryEntry, advisory};
  } finally {
    await stopSpawnedSession(child, completion);
  }
}

async function waitForAsync(label, predicate, seconds) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve_ => setTimeout(resolve_, 250));
  }
  fail(`${label} did not converge in ${seconds}s`);
}

function impossibleProgressAssertions() {
  return {timeout: '15s', assertions: [{id: 'qualification-required-progress', chainProgress: {
    chain: 'stacks', actors: ['follower-1'], window: '10s', minimumDelta: 2147483647,
  }}]};
}

function reductionSource(descriptor, trial) {
  const templates = new Map(descriptor.templates.map(template => [template.id, template]));
  return trial.executions.map(execution => {
    const template = templates.get(execution.template);
    if (execution.kind !== 'FaultCampaign' || !template?.faultSpec) {
      fail(`reduction execution ${execution.id} is not backed by a retained fault template`);
    }
    return {id: execution.id, stages: template.faultSpec.stages.map(stage => ({
      id: stage.id, actions: stage.faults.map(action => ({
        id: action.id, ...(action.target?.actors?.length ? {actors: [...action.target.actors].sort()} : {}),
      })),
    }))};
  });
}

function confirmationAndReduction(attacknet, executionDirectory, tree, output, sources, corpusRoot) {
  const templates = reductionTemplatePlans();
  const plan = basePlan({sessionId: 'a13-confirm', networkPath: sources.minimal.path,
    templates, corpusRoot, minExecutions: 3, maxExecutions: 3,
    recoveryAssertions: impossibleProgressAssertions(), reduction: true});
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'confirmation');
  runFuzz(attacknet, compiled.descriptorPath, corpusRoot);
  const entry = corpusEntries(corpusRoot).find(item =>
    item.sessionDigest === compiled.descriptor.digest && item.classification === 'ConfirmedNetworkFailure');
  if (!entry) fail('deliberate assertion control did not produce one confirmed corpus entry');
  const source = entry.attempts.find(attempt => attempt.kind === 'Source');
  const confirmation = entry.attempts.find(attempt => attempt.kind === 'Confirmation');
  if (!source || !confirmation || source.networkUid === confirmation.networkUid) {
    fail('confirmation did not execute on a distinct fresh network');
  }
  const confirmationValue = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-confirmation/v1', outcome: 'Passed',
    classification: entry.classification, sourceNetworkUID: source.networkUid,
    confirmationNetworkUID: confirmation.networkUid,
    sourceFingerprint: entry.fingerprint, confirmationFingerprint: entry.fingerprint,
    entryDigest: entry.digest, recordedAt: now(),
  };
  validateA13Confirmation(confirmationValue, tree);
  writeJSON(join(output, A13_ARTIFACTS.failureConfirmation), confirmationValue);

  const graphDigest = entry.reduction?.[0];
  const graphReference = entry.objects.find(reference => reference.digest === graphDigest);
  if (!graphReference) fail('confirmed entry does not retain its reduction graph');
  const graph = loadObject(corpusRoot, graphReference);
  const sourceStructure = reductionSource(compiled.descriptor, compiled.descriptor.trials[0]);
  const reducedExecutionCount = graph.retained?.length ?? 0;
  const reductionUIDs = entry.attempts.filter(attempt => attempt.kind === 'Reduction').map(attempt => attempt.networkUid);
  const attemptUIDs = [source.networkUid, confirmation.networkUid, ...reductionUIDs];
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-reduction/v1', outcome: 'Passed',
    classification: entry.classification, sourceExecutionCount: sourceStructure.length, reducedExecutionCount,
    sourceOrderPreserved: preservesExecutionOrder(compiled.descriptor.trials[0].executions, graph.retained),
    removalOnly: true, causalMinimalityClaimed: graph.causalMinimalityClaimed,
    freshNetworkUIDs: attemptUIDs.every(Boolean) && new Set(attemptUIDs).size === attemptUIDs.length,
    graphDigest, algorithm: graph.algorithm, source: sourceStructure, sourceDigest: graph.sourceDigest,
    retained: graph.retained, retainedDigest: canonicalDigest(graph.retained), attempts: graph.attempts,
    sourceBudgets: compiled.descriptor.run.budgets, reducedBudgets: clone(compiled.descriptor.run.budgets),
    attemptCount: graph.attempts?.length ?? 0, recordedAt: now(),
  };
  validateA13Reduction(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.reduction), value);
  return {compiled, entry};
}

/** Require the controller to seal its recovery baseline before a source-only control. */
export function nonReproductionControlReady(run) {
  return run?.status?.phase === 'Running'
    && run.status.reason === 'ProtocolRecoveryPending'
    && typeof run.status.protocolAssertions?.recovery?.startedAt === 'string';
}

/** Keep the clean replay feasible while requiring more progress than pause acknowledgement can race. */
export function nonReproductionAssertions() {
  return {timeout: '70s', assertions: [{id: 'bounded-progress', chainProgress: {
    chain: 'burnchain', actors: ['follower-1'], window: '60s', minimumDelta: 15,
  }}]};
}

function setBurnchainPolicyPaused(identity, paused, {allowMissing = false} = {}) {
  const current = optional('burnchainpolicies.testing.stacks.org', identity.name);
  if (!current && allowMissing) return false;
  if (!current || current.metadata?.uid !== identity.uid) {
    fail(`qualification burnchain policy ${identity.name} no longer has its journaled identity`);
  }
  kubectl(['-n', namespace, 'patch', 'burnchainpolicies.testing.stacks.org', identity.name,
    '--type=merge', '-p', JSON.stringify({spec: {paused}})]);
  waitFor(`BurnchainPolicy ${identity.name} paused=${paused}`, () =>
    optional('burnchainpolicies.testing.stacks.org', identity.name), value =>
    value?.metadata?.uid === identity.uid && value.spec?.paused === paused
      && value.status?.observedGeneration === value.metadata?.generation
      && value.status?.phase === 'Ready', 120);
  if (!paused) return {policyUID: identity.uid};

  let stableHeight;
  let stableSince;
  const stableForSeconds = 5;
  const stable = waitFor(`paused BurnchainPolicy ${identity.name} stable Bitcoin height`, () =>
    optional('burnchainpolicies.testing.stacks.org', identity.name), value => {
    const height = value?.status?.observedHeight;
    if (value?.metadata?.uid !== identity.uid || value.spec?.paused !== true
      || value.status?.observedGeneration !== value.metadata?.generation
      || value.status?.phase !== 'Ready' || !Number.isSafeInteger(height) || height < 0) {
      stableHeight = undefined;
      stableSince = undefined;
      return false;
    }
    if (height !== stableHeight) {
      stableHeight = height;
      stableSince = Date.now();
      return false;
    }
    return Date.now() - stableSince >= stableForSeconds * 1000;
  }, 30);
  return {
    policyUID: identity.uid,
    policyGeneration: stable.metadata.generation,
    observedHeight: stable.status.observedHeight,
    stableForSeconds,
  };
}

async function nonReproductionControl(attacknet, executionDirectory, tree, output, sources, corpusRoot) {
  const assertions = nonReproductionAssertions();
  const plan = basePlan({sessionId: 'a13-nonrep', networkPath: sources.minimal.path,
    templates: [nonReproductionTemplatePlan()], corpusRoot, recoveryAssertions: assertions});
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'non-reproduction');
  const child = spawn(attacknet,
    ['fuzz', 'run', '--descriptor', compiled.descriptorPath, '--corpus', corpusRoot],
    {cwd: repositoryRoot, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const completion = new Promise(resolve_ => child.on('close', (code, signal) => resolve_({code, signal})));
  let policyIdentity;
  let policyPaused = false;
  let pauseProof;
  const deadline = Date.now() + 2_460_000;
  try {
    while (Date.now() < deadline && child.exitCode == null) {
      const records = sessionJournal(corpusRoot, compiled.descriptor.digest);
      const policyRecord = lastRecord(records, 'PoliciesObserved', 'source');
      const runRecord = lastRecord(records, 'RunObserved', 'source');
      const runName = runRecord?.resources?.[0]?.name;
      const run = runName ? optional('attacknetruns.testing.stacks.org', runName) : undefined;
      if (!policyPaused && policyRecord?.resources?.length === 1
        && nonReproductionControlReady(run)) {
        policyIdentity = policyRecord.resources[0];
        pauseProof = {
          ...setBurnchainPolicyPaused(policyIdentity, true),
          recoveryStartedAt: run.status.protocolAssertions.recovery.startedAt,
        };
        policyPaused = true;
      }
      if (policyPaused && terminalPhases.has(run?.status?.phase)) {
        break;
      }
      await new Promise(resolve_ => setTimeout(resolve_, 500));
    }
  } finally {
    if (policyPaused) setBurnchainPolicyPaused(policyIdentity, false, {allowMissing: true});
  }
  const result = await completion;
  if (result.code !== 0) fail(`non-reproduction session failed as a harness run: ${stderr || stdout}`);
  if (!policyPaused || !pauseProof) {
    fail('non-reproduction source never reached the sealed recovery baseline and stable policy pause');
  }
  const entry = corpusEntries(corpusRoot).find(item =>
    item.sessionDigest === compiled.descriptor.digest && item.classification === 'NotReproduced');
  if (!entry) fail('qualification-only transient condition was not retained as NotReproduced');
  const source = entry.attempts.find(attempt => attempt.kind === 'Source');
  const replay = entry.attempts.find(attempt => attempt.kind === 'Confirmation');
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-non-reproduction/v1', outcome: 'Passed',
    classification: entry.classification, retained: true, reductionAttempted: false,
    sourceNetworkUID: source?.networkUid, replayNetworkUID: replay?.networkUid,
    qualificationControl: 'bounded-recovery-window-burnchain-policy-pause', pauseProof, recordedAt: now(),
  };
  validateA13NonReproduction(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.nonReproduction), value);
  return {compiled, entry};
}

export function observedAttemptResources(records, attemptID = 'source') {
  const resources = [];
  for (const kind of ['PoliciesObserved', 'TemplatesObserved', 'EvidencePlaneObserved', 'NetworkObserved', 'RunObserved']) {
    const observed = lastRecord(records, kind, attemptID);
    if (observed) resources.push(...observed.resources);
  }
  const unique = new Map(resources.map(identity =>
    [`${identity.kind}/${identity.namespace}/${identity.name}`, identity]));
  return sortedResources([...unique.values()]);
}

function deleteAttemptResources(attacknet, records) {
  const resources = observedAttemptResources(records);
  for (const kind of ['AttacknetRun', 'UpgradeCampaign', 'FaultCampaign', 'BurnchainPolicy', 'StacksNetwork']) {
    for (const identity of resources.filter(item => item.kind === kind)) {
      const observed = liveIdentity(identity);
      if (observed && observed.uid !== identity.uid) {
        fail(`refusing cleanup of replaced ${identity.kind}/${identity.name}`);
      }
      deleteResource(attacknet, kind, identity.name);
    }
  }
}

function cleanupFailedSession(attacknet, corpusRoot, descriptorDigest) {
  const records = sessionJournal(corpusRoot, descriptorDigest);
  deleteAttemptResources(attacknet, records);
  const capacity = lastRecord(records, 'CapacityAdmitted');
  for (const identity of capacity?.resources ?? []) {
    kubectl(['-n', identity.namespace || namespace, 'delete', resourceKind(identity.kind), identity.name,
      '--ignore-not-found', '--wait=true'], {allowFailure: true});
  }
  const lease = optional('leases.coordination.k8s.io', 'attacknet-fuzz-session');
  if (lease) breakSessionLease(attacknet, corpusRoot, 'A13 qualification recorded terminal preserved-session evidence');
  return records;
}

/** Return the most recent explicit harness-failure journal record. */
export function lastHarnessFailure(records) {
  return [...records].reverse().find(record => record.phase === 'HarnessFailed');
}

function evidenceLossControl(attacknet, executionDirectory, tree, output, sources) {
  const root = join(executionDirectory, 'evidence-loss-corpus');
  const plan = basePlan({sessionId: 'a13-evidence-loss', networkPath: sources.minimal.path,
    templates: [templatePlan('delay', 'a13-delay')], corpusRoot: root, corpusBytes: 262_144});
  // Exercise the bounded capture path rather than failing capacity admission:
  // a small logical corpus limits evidence, while physical headroom remains a
  // separately verified concern covered by the capacity controls.
  plan.capacity = {
    minimumNodeBytes: 67_108_864, minimumImageBytes: 67_108_864,
    minimumCorpusBytes: 16_777_216, storageEscrowBytes: 0,
    evidenceEscrowBytes: 0, requirePhysicalEscrow: false,
  };
  const compiled = planDescriptor(attacknet, plan, executionDirectory, 'evidence-loss');
  const result = runFuzz(attacknet, compiled.descriptorPath, root, {allowFailure: true});
  const records = sessionJournal(root, compiled.descriptor.digest);
  const network = lastRecord(records, 'NetworkObserved', 'source')?.resources?.[0];
  const failure = lastHarnessFailure(records);
  if (result.status === 0 || !network || !liveIdentity(network) || !failure) {
    fail('bounded evidence exhaustion did not preserve a live network and explicit harness failure');
  }
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-evidence-loss-control/v1', outcome: 'Passed',
    classification: 'HarnessFailed', terminalPassPossible: false, networkPreserved: true,
    networkUID: network.uid, journalFailureDigest: failure.digest, recordedAt: now(),
  };
  validateA13EvidenceLoss(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.evidenceLossControl), value);
  cleanupFailedSession(attacknet, root, compiled.descriptor.digest);
  return {compiled, root};
}

function objectPath(corpusRoot, digest) {
  const hex = digest.slice(7);
  return join(corpusRoot, 'objects', 'sha256', hex.slice(0, 2), hex);
}

function advisoryControls(attacknet, executionDirectory, tree, output, sources, finite, corpusRoot) {
  const invalid = createAdvisory(join(executionDirectory, 'invalid.advisory.json'), 1,
    [{id: 'outside-declared-universe', score: 100, rationale: 'negative control'}]);
  const invalidPlan = basePlan({sessionId: 'a13-invalid-advisory', networkPath: sources.minimal.path,
    templates: [templatePlan('delay', 'a13-delay')], corpusRoot,
    advisory: invalid});
  const invalidPath = join(executionDirectory, 'invalid-advisory.plan.json');
  writeJSON(invalidPath, invalidPlan);
  const before = sumCounts(scopedCounts());
  const rejected = command(attacknet, ['fuzz', 'plan', '--file', invalidPath,
    '--output', join(executionDirectory, 'invalid-advisory.descriptor.json'), '--namespace', namespace],
    {allowFailure: true});
  const after = sumCounts(scopedCounts());
  if (rejected.status === 0 || !`${rejected.stderr}${rejected.stdout}`.includes('invalid candidate') || before !== after) {
    fail('out-of-universe advisory was not rejected without mutation');
  }

  for (const item of sources.templates) deleteResource(attacknet, 'FaultCampaign', item.value.metadata.name);
  for (const item of sources.policies) deleteResource(attacknet, 'BurnchainPolicy', item.policy.metadata.name);
  const replay = command(attacknet, ['corpus', 'replay', '--corpus', corpusRoot,
    '--entry', finite.advisoryEntry.digest, '--attempt-id', 'a13-corpus-only-replay', finite.advisoryEntry.fingerprint],
    {timeout: 14_400_000});
  const replayValue = JSON.parse(replay.stdout);

  const missingRoot = join(executionDirectory, 'corpus-missing-object');
  const changedRoot = join(executionDirectory, 'corpus-substituted-object');
  cpSync(corpusRoot, missingRoot, {recursive: true});
  cpSync(corpusRoot, changedRoot, {recursive: true});
  const missingPath = objectPath(missingRoot, finite.advisory.value.digest);
  const changedPath = objectPath(changedRoot, finite.advisory.value.digest);
  rmSync(missingPath, {force: true});
  writeFileSync(changedPath, '{"substituted":true}\n', {mode: 0o600});
  const missing = command(attacknet, ['corpus', 'verify', '--corpus', missingRoot], {allowFailure: true});
  const changed = command(attacknet, ['corpus', 'verify', '--corpus', changedRoot], {allowFailure: true});
  if (missing.status === 0 || changed.status === 0) fail('missing or substituted advisory object passed verification');
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-advisory-controls/v1', outcome: 'Passed',
    outOfUniverseRejected: true, mutationsBefore: before, mutationsAfter: after,
    acceptedRetained: finite.advisoryEntry.advisories.some(item => item.objectDigest === finite.advisory.value.digest),
    corpusOnlyReplay: replayValue.classification === finite.advisoryEntry.classification,
    missingObjectRejected: true, substitutedObjectRejected: true,
    advisoryObjectDigest: finite.advisory.value.digest, replayRequestDigest: replayValue.requestDigest,
    recordedAt: now(),
  };
  validateA13Advisory(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.advisoryControls), value);
}

function walkFiles(root, current = root) {
  const result = [];
  for (const name of readdirSync(current).sort()) {
    const path = join(current, name);
    const info = statSync(path);
    if (info.isDirectory()) result.push(...walkFiles(root, path));
    else if (info.isFile()) result.push({path: relative(root, path).split('\\').join('/'),
      digest: digestFile(path), size: info.size});
    else fail(`corpus contains unsupported filesystem entry ${path}`);
  }
  return result;
}

function portableCorpus(attacknet, executionDirectory, tree, output, corpusRoot) {
  const verified = JSON.parse(command(attacknet, ['corpus', 'verify', '--corpus', corpusRoot]).stdout);
  const entries = corpusEntries(corpusRoot);
  const indexEntries = walkFiles(corpusRoot);
  const index = {schemaVersion: 'stacks-attacknet-a13-corpus-index/v1', entries: indexEntries};
  const indexPath = join(executionDirectory, 'corpus-index.json');
  writeJSON(indexPath, index);
  const archivePath = join(output, A13_ARTIFACTS.corpusArchive);
  mkdirSync(dirname(archivePath), {recursive: true, mode: 0o700});
  command('tar', ['-czf', archivePath, '-C', dirname(corpusRoot), basename(corpusRoot)], {
    env: {...process.env, COPYFILE_DISABLE: '1', GZIP: '-n'}, timeout: 900_000,
  });

  const extracted = join(executionDirectory, 'portable-corpus');
  mkdirSync(extracted, {recursive: true, mode: 0o700});
  command('tar', ['-xzf', archivePath, '-C', extracted]);
  const materialized = materializeQualifiedTree(repositoryRoot, tree);
  let cleanVerification;
  try {
    const cleanCLI = join(executionDirectory, 'attacknet-clean-tree');
    command('go', ['build', '-o', cleanCLI, './cmd/attacknet'], {
      cwd: join(materialized.sourceRoot, 'contrib/helm/hacknet/operator'),
      env: materialized.environment, timeout: 900_000,
    });
    cleanVerification = JSON.parse(command(cleanCLI, ['corpus', 'verify',
      '--corpus', join(extracted, basename(corpusRoot))]).stdout);
  } finally { materialized.cleanup(); }
  if (verified.valid !== true || cleanVerification.valid !== true || verified.entries !== entries.length) {
    fail('corpus did not verify identically from the qualified clean tree');
  }
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-corpus-verification/v1', outcome: 'Passed',
    valid: true, cleanCheckoutVerified: true, entries: verified.entries,
    objects: verified.objects,
    advisoryObjects: new Set(entries.flatMap(entry => (entry.advisories ?? []).map(item => item.objectDigest))).size,
    archiveEntries: indexEntries.length, indexDigest: digestFile(indexPath),
    archiveDigest: digestFile(archivePath), corpusBytes: verified.bytes, recordedAt: now(),
  };
  validateA13Corpus(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.corpusVerification), value);
  return value;
}

function teardown(attacknet, inputs, tree, output) {
  const retainedNetworkNames = kubectlJSON([
    '-n', namespace, 'get', 'stacksnetworks.testing.stacks.org',
  ]).items.filter(a13Resource => String(a13Resource.metadata?.name ?? '').startsWith('a13-'))
    .map(a13Resource => a13Resource.metadata.name);
  for (const kind of ['attacknetruns.testing.stacks.org', 'faultcampaigns.testing.stacks.org',
    'upgradecampaigns.testing.stacks.org', 'burnchainpolicies.testing.stacks.org',
    'stacksnetworks.testing.stacks.org']) {
    const list = kubectlJSON(['-n', namespace, 'get', kind]);
    for (const item of list.items.filter(value => String(value.metadata?.name ?? '').startsWith('a13-'))) {
      deleteResource(attacknet, item.kind, item.metadata.name);
    }
  }
  kubectl(['delete', '-f', inputs.path, '--ignore-not-found', '--wait=true'], {allowFailure: true});
  const counts = waitFor('A13 clean teardown', () => scopedCounts(retainedNetworkNames), cleanCounts, 900);
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-clean-teardown/v1', outcome: 'Passed',
    counts, recordedAt: now(),
  };
  validateA13Teardown(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.cleanTeardown), value);
  return value;
}

function liveSummary(tree, output, cluster, details) {
  const assertions = A13_LIVE_ASSERTIONS.map(id => ({id, status: 'passed'}));
  const value = {
    qualifiedTree: tree, schemaVersion: 'stacks-attacknet-a13-live-qualification/v1', outcome: 'Passed',
    architecture: cluster.architecture, kindNodes: cluster.nodes, context: cluster.context,
    assertions, details, capturedAt: now(),
  };
  validateA13LiveResult(value, tree);
  writeJSON(join(output, A13_ARTIFACTS.liveQualification), value);
  return value;
}

/** Qualify finite, reproducible A13 reliability sessions on local regtest. */
export async function runQualification({qualifiedTree, outputDirectory}) {
  requireA13QualifiedTree(qualifiedTree);
  const output = prepareOutput(outputDirectory, A13_ARTIFACTS);
  for (const key of ['candidateDiff', 'verification', 'attacknetCheck', 'hacknetCheck']) {
    requireFile(join(output, A13_ARTIFACTS[key]));
  }
  const cluster = clusterProfile();
  const executionDirectory = join(output, '.execution');
  mkdirSync(executionDirectory, {recursive: true, mode: 0o700});
  if (!cleanCounts(scopedCounts())) fail(`A13 qualification scope is not clean: ${JSON.stringify(scopedCounts())}`);
  const attacknet = buildCLI(executionDirectory);
  const product = installQualifiedProduct(attacknet, qualifiedTree, cluster);
  const staged = stageQualificationInputs(executionDirectory);
  const inputs = {...staged, resources: loadJSON(staged.path)};
  const sources = sourceBundle(attacknet, executionDirectory, inputs, product);
  submitSources(attacknet, inputs, sources);
  const corpusRoot = join(executionDirectory, 'corpus');
  const details = {};
  try {
    planningControls(attacknet, executionDirectory, qualifiedTree, output, sources, corpusRoot);
    const capacity = capacityControl(attacknet, executionDirectory, qualifiedTree, output, sources);
    const resume = await resumeControls(attacknet, executionDirectory, qualifiedTree, output, sources, corpusRoot);
    capacity.value.receiptDigest = validatePhysicalEscrow(corpusRoot, resume.compiled.descriptor.digest);
    validateA13Capacity(capacity.value, qualifiedTree);
    writeJSON(join(output, A13_ARTIFACTS.capacityControl), capacity.value);
    const finite = await finiteSession(attacknet, executionDirectory, qualifiedTree, output, sources, corpusRoot);
    const confirmation = confirmationAndReduction(attacknet, executionDirectory, qualifiedTree, output, sources, corpusRoot);
    const nonReproduction = await nonReproductionControl(
      attacknet, executionDirectory, qualifiedTree, output, sources, corpusRoot);
    evidenceLossControl(attacknet, executionDirectory, qualifiedTree, output, sources);
    advisoryControls(attacknet, executionDirectory, qualifiedTree, output, sources, finite, corpusRoot);
    const corpus = portableCorpus(attacknet, executionDirectory, qualifiedTree, output, corpusRoot);
    teardown(attacknet, inputs, qualifiedTree, output);
    details.sessions = {resume: resume.compiled.descriptor.digest, finite: finite.compiled.descriptor.digest,
      confirmation: confirmation.compiled.descriptor.digest,
      nonReproduction: nonReproduction.compiled.descriptor.digest};
    details.corpus = {entries: corpus.entries, objects: corpus.objects, archiveDigest: corpus.archiveDigest};
    liveSummary(qualifiedTree, output, cluster, details);
    validateA13LiveQualification(output, qualifiedTree);
  } catch (error) {
    let counts;
    try { counts = scopedCounts(); }
    catch (countError) { counts = {unavailable: countError.message}; }
    writeJSON(join(executionDirectory, 'qualification-failure.json'), {
      schemaVersion: 'stacks-attacknet-a13-qualification-failure/v1', qualifiedTree,
      failedAt: now(), message: error.message, counts,
      disposition: 'preserved for forensic inspection; not release evidence',
    });
    throw error;
  }
}

async function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const qualifiedTree = value('--qualified-tree=');
  const outputDirectory = value('--output=');
  if (!qualifiedTree || !outputDirectory) fail('usage: live.mjs --qualified-tree=TREE --output=PATH');
  if (!isMaterializedSource(repositoryRoot)) {
    return runMaterializedEntrypoint({repositoryRoot, qualifiedTree,
      script: 'contrib/attacknet/release/amendments/a13/qualification/live.mjs',
      arguments_: [`--qualified-tree=${qualifiedTree}`, `--output=${resolve(outputDirectory)}`]});
  }
  return runQualification({qualifiedTree, outputDirectory: resolve(outputDirectory)});
}

if (isMainModule(import.meta.url)) {
  try { await main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
