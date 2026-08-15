import {createHash} from 'node:crypto';
import {mkdirSync, renameSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';

import {
  createDdminPlan,
  issueDdminAttempt,
  recordDdminOutcome,
  validateResolvedSchedule,
} from './attacknet-run-schedule.mjs';
import {canonicalJson, sha256Value} from './run-descriptor.mjs';

export const DDMIN_EXECUTION_SCHEMA = 'stacks-attacknet-ddmin-execution/v1';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TERMINAL = new Set(['Complete', 'Inconclusive', 'BudgetExhausted']);

function object(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function string(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function integer(value, field, {minimum = 0, maximum = Number.MAX_SAFE_INTEGER} = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${field} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function digest(value, field) {
  if (!DIGEST.test(value ?? '')) throw new Error(`${field} must be a lowercase sha256 digest`);
  return value;
}

function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  const temporary = join(dirname(path), `.${path.split('/').at(-1)}.${process.pid}.tmp`);
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
  renameSync(temporary, path);
}

function sourceTemplatesDigest(schedule) {
  const sources = schedule.actions
    .filter(action => action.kind === 'fault-campaign')
    .map(action => ({
      name: action.source.name,
      uid: action.source.uid,
      generation: action.source.generation,
      specDigest: action.source.specDigest,
    }))
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return sha256Value(sources);
}

export function admittedInputContract(schedule) {
  validateResolvedSchedule(schedule);
  return {
    logicalNetworkName: schedule.network.name,
    sourceNetworkUID: schedule.network.uid,
    manifestDigest: schedule.network.manifestDigest,
    imagesDigest: sha256Value(schedule.imageConstraints),
    sourceTemplatesDigest: sourceTemplatesDigest(schedule),
  };
}

function validateStoragePreflight(report) {
  object(report, 'storage preflight report');
  if (report.ok !== true) {
    throw new Error(`storage preflight failed closed: ${report.reason ?? 'insufficient or unknown capacity'}`);
  }
  if (report.evidenceDigest !== undefined) digest(report.evidenceDigest, 'storage preflight evidenceDigest');
  return copy(report);
}

function validateFreshAdmission(admission, contract, usedUIDs) {
  object(admission, 'fresh network admission');
  if (admission.cleanStart !== true) throw new Error('fresh network admission must attest cleanStart=true');
  const uid = string(admission.uid, 'fresh network admission uid');
  if (uid === contract.sourceNetworkUID) throw new Error('fresh network reused the source network UID');
  if (usedUIDs.has(uid)) throw new Error(`fresh network UID ${uid} was already used`);
  if (string(admission.logicalNetworkName, 'fresh network logicalNetworkName') !== contract.logicalNetworkName) {
    throw new Error('fresh network changed the logical network name');
  }
  if (digest(admission.manifestDigest, 'fresh network manifestDigest') !== contract.manifestDigest) {
    throw new Error('fresh network changed the admitted manifest');
  }
  if (digest(admission.imagesDigest, 'fresh network imagesDigest') !== contract.imagesDigest) {
    throw new Error('fresh network changed the admitted images');
  }
  if (digest(admission.sourceTemplatesDigest, 'fresh network sourceTemplatesDigest')
      !== contract.sourceTemplatesDigest) {
    throw new Error('fresh network changed the admitted campaign source templates');
  }
  return {
    uid,
    cleanStart: true,
    logicalNetworkName: admission.logicalNetworkName,
    manifestDigest: admission.manifestDigest,
    imagesDigest: admission.imagesDigest,
    sourceTemplatesDigest: admission.sourceTemplatesDigest,
    ...(admission.generation === undefined ? {} : {
      generation: integer(admission.generation, 'fresh network generation', {minimum: 1}),
    }),
  };
}

function classifyAttempt(observation, expectedFailure) {
  object(observation, 'attempt observation');
  const evidenceDigest = digest(observation.evidenceDigest, 'attempt observation evidenceDigest');
  const evidenceURI = string(observation.evidenceURI, 'attempt observation evidenceURI');
  if (observation.evidenceExported !== true) {
    return {
      outcome: 'Inconclusive', evidenceDigest, evidenceURI,
      observed: {assertion: expectedFailure.assertion, status: 'unknown'},
      reason: 'EvidenceNotExported', preserve: true,
    };
  }
  const verdict = object(observation.verdict, 'attempt observation verdict');
  if (verdict.expectedFailureObserved === true) {
    const assertion = string(verdict.assertion, 'attempt observation verdict.assertion');
    const status = string(verdict.status, 'attempt observation verdict.status');
    if (assertion !== expectedFailure.assertion || status !== expectedFailure.status) {
      return {
        outcome: 'Inconclusive', evidenceDigest, evidenceURI,
        observed: {assertion, status}, reason: 'DifferentFailureObserved', preserve: true,
      };
    }
    return {
      outcome: 'FailureReproduced', evidenceDigest, evidenceURI,
      observed: {assertion, status}, reason: 'ExpectedFailureObserved', preserve: false,
    };
  }
  if (verdict.expectedFailureObserved === false && verdict.experimentCompleted === true
      && verdict.assertionEvaluated === true) {
    return {
      outcome: 'FailureAbsent', evidenceDigest, evidenceURI,
      observed: {assertion: expectedFailure.assertion, status: 'absent'},
      reason: 'ExpectedFailureExplicitlyAbsent', preserve: false,
    };
  }
  return {
    outcome: 'Inconclusive', evidenceDigest, evidenceURI,
    observed: {
      assertion: verdict.assertion ?? expectedFailure.assertion,
      status: verdict.status ?? 'unknown',
    },
    reason: verdict.reason ?? 'NoConclusiveExpectedFailureVerdict', preserve: true,
  };
}

function executionReceipt(state) {
  const unsigned = copy(state);
  delete unsigned.integrity;
  return {...unsigned, integrity: {algorithm: 'sha256', digest: sha256Value(unsigned)}};
}

function validateAdapter(adapter) {
  for (const method of [
    'storagePreflight', 'assertExclusive', 'recreateNetwork', 'submitRun',
    'submitReplay', 'waitForRun', 'exportEvidence', 'deleteAttemptNetwork', 'preserveForTriage',
  ]) {
    if (typeof adapter?.[method] !== 'function') throw new Error(`adapter.${method} is required`);
  }
}

/**
 * Execute bounded hierarchical ddmin counterfactuals serially.
 *
 * The adapter is the only environment-specific layer. It may create/watch
 * StacksNetwork and AttacknetRun resources, but must never create a
 * FaultCampaign or Chaos Mesh resource itself. The in-cluster run controller
 * remains the sole executor of an admitted schedule.
 */
export async function executeDdmin(options, adapter) {
  object(options, 'options');
  validateAdapter(adapter);
  const schedule = copy(object(options.schedule, 'options.schedule'));
  validateResolvedSchedule(schedule);
  const expectedFailure = {
    assertion: string(options.expectedFailure?.assertion, 'options.expectedFailure.assertion'),
    status: string(options.expectedFailure?.status, 'options.expectedFailure.status'),
  };
  const maximum = integer(options.maxAttempts, 'options.maxAttempts', {minimum: 1, maximum: 64});
  const root = resolve(string(options.evidenceDirectory, 'options.evidenceDirectory'));
  const contract = admittedInputContract(schedule);
  const storage = validateStoragePreflight(await adapter.storagePreflight({contract, evidenceDirectory: root}));
  await adapter.assertExclusive({logicalNetworkName: contract.logicalNetworkName, maxActive: 1});

  let plan = options.plan
    ? copy(object(options.plan, 'options.plan'))
    : createDdminPlan(schedule, {requireFreshNetwork: true, maxAttempts: maximum, expectedFailure});
  if (options.plan) {
    if (digest(options.resumePlanDigest, 'options.resumePlanDigest') !== sha256Value(plan)) {
      throw new Error('resumed ddmin plan does not match its durable execution receipt digest');
    }
  }
  if (plan.baselineScheduleDigest !== schedule.integrity.digest) {
    throw new Error('resumed ddmin plan does not match the supplied source schedule');
  }
  if (plan.maxAttempts > maximum || plan.attempts.length > maximum) {
    throw new Error('resumed ddmin plan exceeds the executor attempt budget');
  }
  if (canonicalJson(plan.expectedFailure) !== canonicalJson(expectedFailure)) {
    throw new Error('resumed ddmin plan changes the expected failure');
  }
  if (plan.pendingAttempt) {
    throw new Error('resuming a ddmin plan with an unclassified pending attempt requires triage');
  }
  const statePath = join(root, 'execution.json');
  const planPath = join(root, 'ddmin-plan.json');
  const state = {
    schemaVersion: DDMIN_EXECUTION_SCHEMA,
    phase: 'Running',
    startedAt: options.startedAt ?? new Date().toISOString(),
    maxActive: 1,
    maxAttempts: maximum,
    contract,
    storagePreflight: storage,
    attempts: [],
    planDigest: null,
    result: null,
  };
  atomicWrite(planPath, plan);
  state.planDigest = sha256Value(plan);
  atomicWrite(statePath, executionReceipt(state));

  const usedUIDs = new Set(plan.attempts.map(attempt => attempt.freshNetwork.uid));
  {
    const attempt = {
      id: `replay-baseline-${schedule.integrity.digest.slice(7, 19)}`,
      ordinal: 0,
      schedule,
      expectedFailure,
      counterfactual: null,
    };
    const attemptDirectory = join(root, 'baseline-replay');
    mkdirSync(attemptDirectory, {recursive: true});
    atomicWrite(join(attemptDirectory, 'attempt.json'), attempt);
    let admitted;
    try {
      admitted = validateFreshAdmission(await adapter.recreateNetwork({
        attempt, contract, attemptDirectory, evidenceDirectory: root, baselineReplay: true,
      }), contract, usedUIDs);
      usedUIDs.add(admitted.uid);
      atomicWrite(join(attemptDirectory, 'admission.json'), admitted);
      const run = await adapter.submitReplay({attempt, admitted, contract, attemptDirectory});
      const runReceipt = {
        name: string(run.name, 'baseline replay AttacknetRun name'),
        uid: string(run.uid, 'baseline replay AttacknetRun uid'),
        scheduleDigest: digest(run.scheduleDigest, 'baseline replay scheduleDigest'),
        candidateScheduleDigest: digest(run.candidateScheduleDigest,
          'baseline replay candidateScheduleDigest'),
      };
      if (runReceipt.candidateScheduleDigest !== schedule.integrity.digest) {
        throw new Error('baseline replay did not admit the exact source schedule');
      }
      atomicWrite(join(attemptDirectory, 'run.json'), runReceipt);
      const terminal = await adapter.waitForRun({attempt, admitted, run: runReceipt, attemptDirectory});
      const observation = await adapter.exportEvidence({
        attempt, admitted, run: runReceipt, terminal, attemptDirectory,
      });
      const classified = classifyAttempt(observation, expectedFailure);
      state.baselineReplay = {
        id: attempt.id, outcome: classified.outcome, reason: classified.reason,
        evidenceURI: classified.evidenceURI, evidenceDigest: classified.evidenceDigest,
        networkUID: admitted.uid, sourceScheduleDigest: schedule.integrity.digest,
      };
      atomicWrite(join(attemptDirectory, 'outcome.json'), {
        ...classified, freshNetwork: admitted, run: runReceipt,
      });
      atomicWrite(statePath, executionReceipt(state));
      if (classified.outcome !== 'FailureReproduced') {
        state.phase = 'PausedForTriage';
        state.result = {
          outcome: classified.outcome === 'FailureAbsent' ? 'FailureAbsent' : 'Inconclusive',
          reason: classified.outcome === 'FailureAbsent'
            ? 'SourceFailureDidNotReproduceOnFreshNetwork' : classified.reason,
          preservedAttempt: attempt.id,
          preservedNetworkUID: admitted.uid,
        };
        await adapter.preserveForTriage({
          attempt, admitted, run: runReceipt, observation,
          reason: state.result.reason, attemptDirectory,
        });
        atomicWrite(statePath, executionReceipt(state));
        return executionReceipt(state);
      }
      await adapter.deleteAttemptNetwork({attempt, admitted, run: runReceipt, attemptDirectory});
    } catch (error) {
      const reason = String(error?.message ?? error);
      state.phase = 'PausedForTriage';
      state.result = {
        outcome: 'Inconclusive', reason, preservedAttempt: attempt.id,
        ...(admitted ? {preservedNetworkUID: admitted.uid} : {}),
      };
      atomicWrite(join(attemptDirectory, 'executor-error.json'), {reason});
      atomicWrite(statePath, executionReceipt(state));
      await adapter.preserveForTriage({attempt, admitted, reason, attemptDirectory});
      return executionReceipt(state);
    }
  }
  while (!TERMINAL.has(plan.phase)) {
    const issued = issueDdminAttempt(plan);
    plan = issued.plan;
    atomicWrite(planPath, plan);
    if (!issued.attempt) break;

    const attempt = issued.attempt;
    const attemptDirectory = join(root, 'attempts', attempt.id);
    mkdirSync(attemptDirectory, {recursive: true});
    atomicWrite(join(attemptDirectory, 'attempt.json'), attempt);
    let admitted;
    try {
      await adapter.assertExclusive({logicalNetworkName: contract.logicalNetworkName, maxActive: 1});
      admitted = validateFreshAdmission(await adapter.recreateNetwork({
        attempt, contract, attemptDirectory, evidenceDirectory: root,
      }), contract, usedUIDs);
      usedUIDs.add(admitted.uid);
      atomicWrite(join(attemptDirectory, 'admission.json'), admitted);

      const run = await adapter.submitRun({attempt, admitted, contract, attemptDirectory});
      object(run, 'submitted AttacknetRun');
      const runReceipt = {
        name: string(run.name, 'submitted AttacknetRun name'),
        uid: string(run.uid, 'submitted AttacknetRun uid'),
        scheduleDigest: digest(run.scheduleDigest, 'submitted AttacknetRun scheduleDigest'),
        candidateScheduleDigest: digest(run.candidateScheduleDigest,
          'submitted AttacknetRun candidateScheduleDigest'),
      };
      if (runReceipt.candidateScheduleDigest !== attempt.schedule.integrity.digest) {
        throw new Error('submitted AttacknetRun did not admit the exact ddmin reduction candidate');
      }
      atomicWrite(join(attemptDirectory, 'run.json'), runReceipt);

      const terminal = await adapter.waitForRun({attempt, admitted, run: runReceipt, attemptDirectory});
      const observation = await adapter.exportEvidence({
        attempt, admitted, run: runReceipt, terminal, attemptDirectory,
      });
      const classified = classifyAttempt(observation, expectedFailure);
      const result = {
        attemptId: attempt.id,
        outcome: classified.outcome,
        observed: classified.observed,
        evidenceDigest: classified.evidenceDigest,
        freshNetwork: {
          uid: admitted.uid,
          cleanStart: true,
          manifestDigest: admitted.manifestDigest,
          imagesDigest: admitted.imagesDigest,
        },
      };
      atomicWrite(join(attemptDirectory, 'outcome.json'), {
        ...classified, freshNetwork: admitted, run: runReceipt,
      });
      plan = recordDdminOutcome(plan, result);
      atomicWrite(planPath, plan);
      state.attempts.push({
        id: attempt.id, outcome: classified.outcome, reason: classified.reason,
        evidenceURI: classified.evidenceURI, evidenceDigest: classified.evidenceDigest,
        networkUID: admitted.uid, candidateDigest: attempt.schedule.integrity.digest,
      });
      state.planDigest = sha256Value(plan);
      atomicWrite(statePath, executionReceipt(state));

      if (classified.preserve) {
        state.phase = 'PausedForTriage';
        state.result = {
          outcome: 'Inconclusive', reason: classified.reason,
          preservedAttempt: attempt.id, preservedNetworkUID: admitted.uid,
        };
        await adapter.preserveForTriage({
          attempt, admitted, run: runReceipt, observation, reason: classified.reason, attemptDirectory,
        });
        atomicWrite(statePath, executionReceipt(state));
        return executionReceipt(state);
      }

      // Evidence is exported, digested and durably recorded above before the
      // fresh counterfactual network may be deleted.
      await adapter.deleteAttemptNetwork({attempt, admitted, run: runReceipt, attemptDirectory});
    } catch (error) {
      const reason = String(error?.message ?? error);
      state.phase = 'PausedForTriage';
      state.result = {
        outcome: 'Inconclusive', reason,
        preservedAttempt: attempt.id,
        ...(admitted ? {preservedNetworkUID: admitted.uid} : {}),
      };
      state.planDigest = sha256Value(plan);
      atomicWrite(join(attemptDirectory, 'executor-error.json'), {reason});
      atomicWrite(statePath, executionReceipt(state));
      await adapter.preserveForTriage({attempt, admitted, reason, attemptDirectory});
      return executionReceipt(state);
    }
  }

  state.phase = plan.phase === 'Complete' ? 'Complete' : plan.phase;
  state.planDigest = sha256Value(plan);
  state.result = copy(plan.result);
  state.completedAt = options.completedAt ?? new Date().toISOString();
  atomicWrite(statePath, executionReceipt(state));
  return executionReceipt(state);
}

export function evidenceDigestFor(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}
