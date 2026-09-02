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
import {validateA13Verification} from './verify.mjs';

export const A13_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a13-live-evidence/v1';
export const A13_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A13_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch', verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json', hacknetCheck: 'hacknet-result.json',
  planningControls: 'controls/planning.json', capacityControl: 'controls/capacity.json',
  advisoryControls: 'controls/advisory.json', resumeControls: 'controls/resume.json',
  finiteSession: 'sessions/finite.json', failureConfirmation: 'sessions/confirmation.json',
  nonReproduction: 'sessions/non-reproduction.json', evidenceLossControl: 'controls/evidence-loss.json',
  reduction: 'sessions/reduction.json', corpusVerification: 'corpus-verification.json',
  corpusArchive: 'corpus/corpus.tar.gz',
  cleanTeardown: 'clean-teardown.json', liveQualification: 'live-qualification.json',
});
export const A13_ASSERTIONS = Object.freeze([
  'qualified-tree-and-offline-verification',
  'same-seed-planning-and-template-drift-control',
  'fail-closed-capacity-and-physical-escrow',
  'advisory-containment-retention-and-corpus-only-replay',
  'four-crash-point-exact-identity-resume',
  'finite-four-family-a11-a12-session',
  'fresh-network-confirmation-and-non-reproduction',
  'evidence-loss-never-passes-and-preserves-network',
  'smaller-removal-only-reproducer-without-causal-claim',
  'portable-content-addressed-corpus',
  'clean-final-teardown',
]);
export const A13_LIVE_ASSERTIONS = Object.freeze(A13_ASSERTIONS.slice(1));
const A13_TEARDOWN_KEYS = Object.freeze([
  'networks', 'runs', 'faultCampaigns', 'upgradeCampaigns', 'policies',
  'persistentVolumeClaims', 'leases', 'reservationJobs', 'reservationPVCs',
]);

function fail(message) { throw new Error(message); }
function load(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`${label} is not readable JSON: ${error.message}`); }
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestFile(path) { return digestBytes(readFileSync(path)); }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
function canonicalDigest(value) {
  const encoded = JSON.stringify(canonical(value));
  return encoded == null ? '' : digestBytes(encoded);
}
function immutable(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) fail(`${label} must be an immutable digest`);
  return value;
}

/** Accept a runtime image identity containing exactly one unambiguous SHA-256 digest. */
export function isImmutableRuntimeImageID(value) {
  return typeof value === 'string' && value.match(/sha256:[0-9a-f]{64}/g)?.length === 1;
}
function qualified(value, tree, label) {
  if (value?.qualifiedTree !== tree || value.outcome !== 'Passed') fail(`${label} is not a qualified pass`);
  return value;
}
function containsPath(parent, child) { return child === parent || child.startsWith(`${parent}${sep}`); }

/** Refuse evidence output overlapping source or mutable qualification input. */
export function validateA13EvidenceOutput(inputDirectory, outputDirectory) {
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../..');
  if (output === parse(output).root || containsPath(repository, output)
    || containsPath(output, repository)
    || containsPath(input, output) || containsPath(output, input)) {
    fail(`A13 evidence output must be isolated from repository and input data: ${output}`);
  }
  return output;
}

export function validateA13AttacknetCheck(value, tree) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== tree || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0
    || value.suites.some(suite => !Number.isSafeInteger(suite.tests) || suite.tests < 1
      || !Number.isSafeInteger(suite.passed) || !Number.isSafeInteger(suite.failed)
      || suite.passed !== suite.tests || suite.failed !== 0)) {
    fail('Attacknet check is not a complete qualified-tree pass');
  }
  return value;
}

export function validateA13HacknetCheck(value, tree) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== tree) fail('Hacknet check does not pin the qualified tree');
  for (const required of ['go', 'envtest', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A13 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

export function validateA13Planning(value, tree) {
  qualified(value, tree, 'planning controls');
  if (value.schemaVersion !== 'stacks-attacknet-a13-planning-controls/v1'
    || value.sameSeedByteIdentical !== true || value.templateDriftRejected !== true
    || !Number.isSafeInteger(value.mutationsBefore) || value.mutationsBefore < 0
    || !Number.isSafeInteger(value.mutationsAfter) || value.mutationsAfter < 0
    || value.mutationsBefore !== value.mutationsAfter
    || value.materializationAlgorithm !== 'attacknet-resource-materializer/v1') {
    fail('A13 planning controls do not prove deterministic fail-closed compilation');
  }
  immutable(value.descriptorDigest, 'planning.descriptorDigest');
  return value;
}

export function validateA13Capacity(value, tree) {
  qualified(value, tree, 'capacity control');
  if (value.schemaVersion !== 'stacks-attacknet-a13-capacity-control/v1'
    || value.insufficientCapacityRejected !== true || value.networksCreated !== 0
    || value.physicalEscrowVerified !== true || value.nodeCount !== 3
    || !Number.isSafeInteger(value.networksCreated)) {
    fail('A13 capacity control does not prove fail-closed admission and escrow');
  }
  immutable(value.receiptDigest, 'capacity.receiptDigest');
  return value;
}

export function validateA13Advisory(value, tree) {
  qualified(value, tree, 'advisory controls');
  if (value.schemaVersion !== 'stacks-attacknet-a13-advisory-controls/v1'
    || value.outOfUniverseRejected !== true || value.mutationsBefore !== value.mutationsAfter
    || !Number.isSafeInteger(value.mutationsBefore) || value.mutationsBefore < 0
    || !Number.isSafeInteger(value.mutationsAfter) || value.mutationsAfter < 0
    || value.acceptedRetained !== true || value.corpusOnlyReplay !== true
    || value.missingObjectRejected !== true || value.substitutedObjectRejected !== true) {
    fail('A13 advisory controls do not prove bounded retained-input replay');
  }
  immutable(value.advisoryObjectDigest, 'advisory.objectDigest');
  return value;
}

export function validateA13Resume(value, tree) {
  qualified(value, tree, 'resume controls');
  const expected = ['network-creation', 'active-execution', 'evidence-capture', 'teardown'];
  const suspension = value.interruptions?.[2]?.plannedGenerationTransition;
  if (value.schemaVersion !== 'stacks-attacknet-a13-resume-controls/v1'
    || value.finalPhase !== 'Complete' || value.duplicateResources !== 0
    || !Number.isSafeInteger(value.duplicateResources)
    || !Array.isArray(value.interruptions) || value.interruptions.length !== expected.length
    || value.interruptions.some((item, index) => item.stage !== expected[index]
      || item.resumed !== true || item.identityPreserved !== true
      || !/^sha256:[0-9a-f]{64}$/.test(item.expectedIdentityDigest ?? '')
      || item.expectedIdentityDigest !== item.resumedIdentityDigest)
    || !Number.isSafeInteger(suspension?.fromGeneration)
    || suspension.fromGeneration < 1
    || suspension.toGeneration !== suspension.fromGeneration + 1
    || suspension.observedGeneration !== suspension.toGeneration
    || suspension.phase !== 'Suspended') {
    fail('A13 resume controls do not cover every crash point with exact identity');
  }
  return value;
}

export function validateA13FiniteSession(value, tree) {
  qualified(value, tree, 'finite session');
  const restarts = Array.isArray(value.controllerRestarts) ? value.controllerRestarts : [];
  const classificationNames = ['Clean', 'NetworkFailureCandidate', 'ConfirmedNetworkFailure',
    'NotReproduced', 'Inconclusive', 'HarnessFailed'];
  if (value.schemaVersion !== 'stacks-attacknet-a13-finite-session/v1'
    || value.phase !== 'Complete' || !Number.isSafeInteger(value.completedTrials)
    || value.completedTrials < 4 || !Array.isArray(value.faultFamilies)
    || value.faultFamilies.some(item => typeof item !== 'string' || item === '')
    || new Set(value.faultFamilies).size < 4
    || value.a11VersionCohort !== true || value.a12BehaviorTemplate !== true
    || value.crossedBurnchainBoundary !== true || value.evidenceComplete !== true
    || restarts.length !== 2 || new Set(restarts.map(item => item?.deployment)).size !== 2
    || restarts.some(item => typeof item?.deployment !== 'string' || item.deployment === ''
      || !Array.isArray(item.beforePodUIDs) || item.beforePodUIDs.length < 1
      || !Array.isArray(item.afterPodUIDs) || item.afterPodUIDs.length < 1
      || item.beforePodUIDs.some(uid => typeof uid !== 'string' || uid === '')
      || item.afterPodUIDs.some(uid => typeof uid !== 'string' || uid === ''
        || item.beforePodUIDs.includes(uid)))) {
    fail('A13 finite session does not prove the required A9-A12 composition');
  }
  immutable(value.sessionDigest, 'finite.sessionDigest');
  immutable(value.versionCohortDigest, 'finite.versionCohortDigest');
  validateVersionCohortProof(value.versionCohortProof, value.versionCohortDigest);
  validateBurnchainBoundaryProof(value.burnchainBoundaryProof);
  if (value.operatorSurface?.statusSchemaVersion !== 'stacks-attacknet-fuzz-status/v1'
    || value.operatorSurface?.decodedReport !== true || value.operatorSurface?.corpusValid !== true
    || !Number.isSafeInteger(value.operatorSurface?.listedEntries) || value.operatorSurface.listedEntries < 4
    || value.operatorSurface?.showedEntryDigest !== value.advisoryEntryDigest
    || value.operatorSurface?.classificationCounts == null
    || classificationNames.some(name => !Object.hasOwn(value.operatorSurface.classificationCounts, name))
    || Object.keys(value.operatorSurface.classificationCounts).some(name => !classificationNames.includes(name))
    || Object.values(value.operatorSurface.classificationCounts).some(count => !Number.isSafeInteger(count) || count < 0)
    || Object.values(value.operatorSurface.classificationCounts).reduce((sum, count) => sum + count, 0)
      !== value.operatorSurface.listedEntries
    || !Array.isArray(value.operatorSurface?.capacityHeadroom?.nodes)
    || value.operatorSurface.capacityHeadroom.nodes.length !== 3
    || value.operatorSurface.capacityHeadroom.nodes.some(node => !Number.isSafeInteger(node?.rootBytes)
      || node.rootBytes < 0 || !Number.isSafeInteger(node?.imageBytes) || node.imageBytes < 0)
    || !Number.isSafeInteger(value.operatorSurface.capacityHeadroom.corpusBytes)
    || value.operatorSurface.capacityHeadroom.corpusBytes < 0
    || !/^sha256:[0-9a-f]{64}$/.test(value.operatorSurface?.reportDigest ?? '')
    || !/^sha256:[0-9a-f]{64}$/.test(value.operatorSurface?.capacityDigest ?? '')) {
    fail('A13 finite session does not qualify its human and agent status/corpus interface');
  }
  return value;
}

function validateVersionCohortProof(proof, expectedDigest) {
  const assignments = Array.isArray(proof?.assignments) ? proof.assignments : [];
  const runStatusAssignments = Array.isArray(proof?.runStatusAssignments) ? proof.runStatusAssignments : [];
  const runStatusByName = new Map(runStatusAssignments.map(item => [item?.name, item]));
  if (typeof proof?.networkUID !== 'string' || proof.networkUID === ''
    || !/^sha256:[0-9a-f]{64}$/.test(proof.inventoryDigest ?? '')
    || assignments.length < 2 || assignments.some(item =>
      typeof item?.actor !== 'string' || item.actor === '' || typeof item?.role !== 'string' || item.role === ''
      || typeof item?.requestedImage !== 'string' || item.requestedImage === ''
      || !isImmutableRuntimeImageID(item?.runtimeImageID))
    || new Set(assignments.map(item => item.actor)).size !== assignments.length
    || assignments.some((item, index) => index > 0 && assignments[index - 1].actor >= item.actor)
    || new Set(assignments.map(item => item.runtimeImageID)).size < 2
    || runStatusAssignments.length < assignments.length
    || assignments.some(item => {
      const observed = runStatusByName.get(item.actor);
      return observed?.requestedImage !== item.requestedImage || observed?.runtimeImageID !== item.runtimeImageID;
    })
    || runStatusAssignments.some((item, index) => typeof item?.name !== 'string' || item.name === ''
      || !isImmutableRuntimeImageID(item?.runtimeImageID)
      || index > 0 && runStatusAssignments[index - 1].name >= item.name)
    || canonicalDigest(runStatusAssignments) !== proof.runStatusCohortDigest
    || canonicalDigest(assignments) !== expectedDigest) {
    fail('A13 finite session does not bind distinct admitted immutable version cohorts');
  }
}

/** Return every declared epoch or reward-cycle boundary in the observed interval. */
export function burnchainCrossings(startHeight, endHeight, schedule) {
  if (!Number.isSafeInteger(startHeight) || !Number.isSafeInteger(endHeight) || endHeight <= startHeight
    || !Array.isArray(schedule?.epochs) || !schedule?.rewardCycle
    || !Number.isSafeInteger(schedule.rewardCycle.firstHeight)
    || !Number.isSafeInteger(schedule.rewardCycle.cycleLength) || schedule.rewardCycle.cycleLength < 1) return [];
  const result = schedule.epochs.filter(epoch => Number.isSafeInteger(epoch?.startHeight)
      && typeof epoch?.name === 'string' && epoch.name !== ''
      && epoch.startHeight > startHeight && epoch.startHeight <= endHeight)
    .map(epoch => ({kind: 'epoch', name: epoch.name, height: epoch.startHeight}));
  const {firstHeight, cycleLength} = schedule.rewardCycle;
  const firstOrdinal = Math.max(0, Math.floor((startHeight - firstHeight) / cycleLength) + 1);
  const lastOrdinal = Math.floor((endHeight - firstHeight) / cycleLength);
  for (let ordinal = firstOrdinal; ordinal <= lastOrdinal && ordinal - firstOrdinal <= 10_000; ordinal++) {
    const height = firstHeight + ordinal * cycleLength;
    if (height > startHeight && height <= endHeight) {
      result.push({kind: 'reward-cycle', name: `reward-cycle-${ordinal}`, height});
    }
  }
  return result.sort((left, right) => left.height - right.height
    || (left.kind < right.kind ? -1 : left.kind > right.kind ? 1 : 0));
}

function validateBurnchainBoundaryProof(proof) {
  const crossings = burnchainCrossings(proof?.startHeight, proof?.endHeight, proof?.protocolSchedule);
  if (typeof proof?.policyName !== 'string' || proof.policyName === ''
    || typeof proof?.policyUID !== 'string' || proof.policyUID === ''
    || canonicalDigest(proof.protocolSchedule) !== proof.scheduleDigest
    || crossings.length < 1 || JSON.stringify(crossings) !== JSON.stringify(proof.crossings)) {
    fail('A13 finite session does not prove an actual declared burnchain-boundary crossing');
  }
}

export function validateA13Confirmation(value, tree) {
  qualified(value, tree, 'failure confirmation');
  if (value.schemaVersion !== 'stacks-attacknet-a13-confirmation/v1'
    || value.classification !== 'ConfirmedNetworkFailure'
    || typeof value.sourceNetworkUID !== 'string' || value.sourceNetworkUID === ''
    || typeof value.confirmationNetworkUID !== 'string' || value.confirmationNetworkUID === ''
    || value.sourceNetworkUID === value.confirmationNetworkUID
    || value.sourceFingerprint !== value.confirmationFingerprint) {
    fail('A13 confirmation did not use a fresh network with the same semantic outcome');
  }
  immutable(value.sourceFingerprint, 'confirmation.fingerprint');
  return value;
}

export function validateA13NonReproduction(value, tree) {
  qualified(value, tree, 'non-reproduction control');
  if (value.schemaVersion !== 'stacks-attacknet-a13-non-reproduction/v1'
    || value.classification !== 'NotReproduced' || value.retained !== true
    || value.reductionAttempted !== false
    || value.qualificationControl !== 'bounded-recovery-window-burnchain-policy-pause'
    || typeof value.pauseProof?.policyUID !== 'string' || value.pauseProof.policyUID === ''
    || !Number.isSafeInteger(value.pauseProof?.policyGeneration) || value.pauseProof.policyGeneration < 1
    || !Number.isSafeInteger(value.pauseProof?.observedHeight) || value.pauseProof.observedHeight < 0
    || value.pauseProof?.stableForSeconds < 5
    || typeof value.pauseProof?.recoveryStartedAt !== 'string' || value.pauseProof.recoveryStartedAt === ''
    || typeof value.sourceNetworkUID !== 'string' || value.sourceNetworkUID === ''
    || typeof value.replayNetworkUID !== 'string' || value.replayNetworkUID === ''
    || value.sourceNetworkUID === value.replayNetworkUID) {
    fail('A13 non-reproduction control was not retained and excluded from reduction');
  }
  return value;
}

export function validateA13EvidenceLoss(value, tree) {
  qualified(value, tree, 'evidence-loss control');
  if (value.schemaVersion !== 'stacks-attacknet-a13-evidence-loss-control/v1'
    || !['HarnessFailed', 'Inconclusive'].includes(value.classification)
    || value.terminalPassPossible !== false || value.networkPreserved !== true) {
    fail('A13 evidence-loss control could produce a false pass or destructive cleanup');
  }
  return value;
}

export function validateA13Reduction(value, tree) {
  qualified(value, tree, 'reduction');
  if (value.schemaVersion !== 'stacks-attacknet-a13-reduction/v1'
    || value.classification !== 'ConfirmedNetworkFailure'
    || !Number.isSafeInteger(value.sourceExecutionCount) || value.sourceExecutionCount < 2
    || !Number.isSafeInteger(value.reducedExecutionCount) || value.reducedExecutionCount < 1
    || value.reducedExecutionCount >= value.sourceExecutionCount
    || value.sourceOrderPreserved !== true || value.removalOnly !== true
    || value.causalMinimalityClaimed !== false || value.freshNetworkUIDs !== true) {
    fail('A13 reduction is not a smaller removal-only confirmed reproducer');
  }
  immutable(value.graphDigest, 'reduction.graphDigest');
  const source = Array.isArray(value.source) ? value.source : [];
  const retained = Array.isArray(value.retained) ? value.retained : [];
  const attempts = Array.isArray(value.attempts) ? value.attempts : [];
  assertNoAutomaticParameterReduction(source, retained, attempts);
  if (value.algorithm !== 'deterministic-hierarchical-ddmin/v1'
    || canonicalDigest(source) !== value.sourceDigest || canonicalDigest(retained) !== value.retainedDigest
    || !validateRemovalOnlyRelation(source, retained)
    || attempts.length < 1 || attempts.some((attempt, index) => {
      const candidate = attempt?.candidate;
      return candidate?.algorithm !== value.algorithm || candidate?.attempt !== index + 1
        || !['execution', 'stage', 'action', 'actor'].includes(candidate?.level)
        || canonicalDigest(candidate?.retained) !== candidate?.digest
        || !validateRemovalOnlyRelation(source, candidate?.retained)
        || !['Reproduced', 'NotReproduced', 'Inconclusive'].includes(attempt?.outcome);
    })
    || !attempts.some(attempt => attempt.outcome === 'Reproduced'
      && canonicalDigest(attempt.candidate.retained) === value.retainedDigest)
    || canonicalDigest(value.sourceBudgets) !== canonicalDigest(value.reducedBudgets)) {
    fail('A13 reduction proof does not derive a removal-only, budget-preserving candidate');
  }
  return value;
}

function assertNoAutomaticParameterReduction(source, retained, attempts) {
  const declaresParameters = source.some(execution => (execution?.stages ?? []).some(stage =>
    (stage?.actions ?? []).some(action => Object.hasOwn(action ?? {}, 'monotoneParameters'))));
  const candidates = [retained, ...attempts.map(attempt => attempt?.candidate?.retained)];
  const removesParameters = candidates.some(candidate => (candidate ?? []).some(rule =>
    Object.hasOwn(rule ?? {}, 'removedParameters')));
  if (declaresParameters || removesParameters) {
    fail('A13 automatic parameter reduction is deferred; source and candidates must omit parameter reducers');
  }
}

/** Validate a reducer candidate as a source-ordered removal-only relation. */
export function validateRemovalOnlyRelation(source, retained) {
  if (!Array.isArray(source) || source.length < 1 || !Array.isArray(retained) || retained.length < 1) return false;
  const sourceByID = new Map(source.map(execution => [execution.id, execution]));
  if (sourceByID.size !== source.length) return false;
  let previous = -1;
  let removed = retained.length < source.length;
  const seenExecutions = new Set();
  for (const rule of retained) {
    const execution = sourceByID.get(rule?.executionId);
    const position = source.findIndex(item => item.id === rule?.executionId);
    if (!execution || seenExecutions.has(rule.executionId) || position <= previous) return false;
    previous = position;
    seenExecutions.add(rule.executionId);
    const stages = new Map((execution.stages ?? []).map(stage => [stage.id, stage]));
    const valid = {
      removedStages: new Set(stages.keys()), removedActions: new Set(), removedTargets: new Set(),
    };
    for (const stage of stages.values()) for (const action of stage.actions ?? []) {
      const prefix = `${stage.id}/${action.id}`;
      valid.removedActions.add(prefix);
      for (const actor of action.actors ?? []) valid.removedTargets.add(`${prefix}/${actor}`);
    }
    for (const field of Object.keys(valid)) {
      const values = rule[field] ?? [];
      if (!Array.isArray(values) || new Set(values).size !== values.length
        || values.some(item => typeof item !== 'string' || !valid[field].has(item))) return false;
      removed = removed || values.length > 0;
    }
  }
  return removed;
}

export function validateA13Corpus(value, tree) {
  qualified(value, tree, 'corpus verification');
  if (value.schemaVersion !== 'stacks-attacknet-a13-corpus-verification/v1'
    || value.valid !== true || value.cleanCheckoutVerified !== true
    || !Number.isSafeInteger(value.entries) || value.entries < 1
    || !Number.isSafeInteger(value.objects) || value.objects < 1
    || !Number.isSafeInteger(value.advisoryObjects) || value.advisoryObjects < 1
    || !Number.isSafeInteger(value.archiveEntries) || value.archiveEntries < 1) {
    fail('A13 corpus is not complete and portable');
  }
  immutable(value.indexDigest, 'corpus.indexDigest');
  immutable(value.archiveDigest, 'corpus.archiveDigest');
  return value;
}

export function validateA13Teardown(value, tree) {
  qualified(value, tree, 'clean teardown');
  if (value.schemaVersion !== 'stacks-attacknet-a13-clean-teardown/v1'
    || value.counts == null || typeof value.counts !== 'object' || Array.isArray(value.counts)
    || A13_TEARDOWN_KEYS.some(key => !Number.isSafeInteger(value.counts[key]) || value.counts[key] !== 0)
    || Object.values(value.counts).some(count => !Number.isSafeInteger(count) || count !== 0)) {
    fail('A13 final teardown left scoped resources');
  }
  return value;
}

export function validateA13LiveResult(value, tree) {
  qualified(value, tree, 'live qualification');
  const assertions = Array.isArray(value.assertions) ? value.assertions : [];
  const ids = new Set(assertions.map(item => item?.id));
  if (value.schemaVersion !== 'stacks-attacknet-a13-live-qualification/v1'
    || value.architecture !== 'arm64' || value.kindNodes?.length !== 3
    || value.kindNodes.some(item => typeof item !== 'string' || item === '')
    || new Set(value.kindNodes).size !== 3 || assertions.length !== A13_LIVE_ASSERTIONS.length
    || ids.size !== assertions.length || A13_LIVE_ASSERTIONS.some(id => !ids.has(id))
    || assertions.some(item => item?.status !== 'passed')) {
    fail('A13 live qualification is incomplete');
  }
  return value;
}

/** Validate every A13 input artifact before it can enter a review archive. */
export function validateA13LiveQualification(directory, tree) {
  const artifact = key => load(join(directory, A13_ARTIFACTS[key]), key);
  validateA13Verification(artifact('verification'), tree);
  validateA13AttacknetCheck(artifact('attacknetCheck'), tree);
  validateA13HacknetCheck(artifact('hacknetCheck'), tree);
  validateA13Planning(artifact('planningControls'), tree);
  validateA13Capacity(artifact('capacityControl'), tree);
  validateA13Advisory(artifact('advisoryControls'), tree);
  validateA13Resume(artifact('resumeControls'), tree);
  validateA13FiniteSession(artifact('finiteSession'), tree);
  validateA13Confirmation(artifact('failureConfirmation'), tree);
  validateA13NonReproduction(artifact('nonReproduction'), tree);
  validateA13EvidenceLoss(artifact('evidenceLossControl'), tree);
  validateA13Reduction(artifact('reduction'), tree);
  const corpus = validateA13Corpus(artifact('corpusVerification'), tree);
  if (digestFile(join(directory, A13_ARTIFACTS.corpusArchive)) !== corpus.archiveDigest) {
    fail('A13 corpus archive differs from its verified portability record');
  }
  validateA13Teardown(artifact('cleanTeardown'), tree);
  validateA13LiveResult(artifact('liveQualification'), tree);
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
function artifact(path, archiveEntry) { return {path, archiveEntry, digest: digestFile(path)}; }

/** Copy, index, archive, and summarize a complete A13 qualification bundle. */
export function assembleA13Evidence({inputDirectory, outputDirectory, qualifiedTree}) {
  const input = resolve(inputDirectory);
  validateA13LiveQualification(input, qualifiedTree);
  const output = validateA13EvidenceOutput(input, outputDirectory);
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'archive'), {recursive: true});
  const staging = join(output, '.staging');
  mkdirSync(staging, {recursive: true});
  const artifacts = {};
  for (const [key, entry] of Object.entries(A13_ARTIFACTS)) {
    const destination = join(staging, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, entry), destination);
    artifacts[key] = artifact(destination, entry);
  }
  const entries = walkFiles(staging).map(path => ({
    path: relative(staging, path).split(sep).join('/'), digest: digestFile(path), size: statSync(path).size,
  }));
  const index = {schema: A13_ARCHIVE_INDEX_SCHEMA, qualifiedTree, entries};
  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
  copyFileSync(indexPath, join(staging, 'archive-index.json'));
  const archivePath = join(output, `archive/phase-2-live-evidence-${qualifiedTree.slice(0, 12)}.tar.gz`);
  execFileSync('tar', ['-czf', archivePath, '-C', staging, '.'], {
    env: {...process.env, COPYFILE_DISABLE: '1', GZIP: '-n'},
  });
  rmSync(staging, {recursive: true, force: true});
  for (const [key, entry] of Object.entries(A13_ARTIFACTS)) {
    const destination = join(output, entry);
    mkdirSync(dirname(destination), {recursive: true});
    copyFileSync(join(input, entry), destination);
    artifacts[key] = artifact(destination, entry);
  }
  const summary = {
    schema: A13_SUMMARY_SCHEMA, qualifiedTree, generatedAt: new Date().toISOString(),
    assertions: A13_ASSERTIONS.map(id => ({id, status: 'passed'})), artifacts,
    archive: {
      path: archivePath, digest: digestFile(archivePath), location: 'local-review-bundle',
      indexPath, indexDigest: digestFile(indexPath), indexEntry: 'archive-index.json',
    },
  };
  const summaryPath = join(output, 'live-summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  return {summary, summaryPath};
}

/** Validate one portable A13 summary against its signed candidate. */
export function validateA13Summary(summary, candidate, summaryPath, root) {
  validatePortableLiveSummary(summary, candidate, {
    root, schema: A13_SUMMARY_SCHEMA, checkpoint: 'A13',
    requiredArtifacts: Object.keys(A13_ARTIFACTS), requiredAssertions: A13_ASSERTIONS,
    binding: {field: 'qualifiedTree', value: summary.qualifiedTree, description: 'qualified Git tree'},
  });
  const evidenceRoot = dirname(resolve(root, summaryPath));
  if (resolve(root, summary.archive.indexPath) !== resolve(evidenceRoot, summary.archive.indexEntry)
    || resolve(root, summary.archive.path) !== resolve(evidenceRoot, 'archive', basename(summary.archive.path))) {
    fail('A13 archive paths do not resolve from the packet evidence root');
  }
  for (const [key, value] of Object.entries(summary.artifacts)) {
    if (resolve(root, value.path) !== resolve(evidenceRoot, value.archiveEntry)) {
      fail(`${key} does not resolve under the packet evidence root`);
    }
  }
  validateA13LiveQualification(evidenceRoot, summary.qualifiedTree);
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
  const result = assembleA13Evidence({inputDirectory, outputDirectory, qualifiedTree});
  process.stdout.write(`${JSON.stringify(result.summary, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
