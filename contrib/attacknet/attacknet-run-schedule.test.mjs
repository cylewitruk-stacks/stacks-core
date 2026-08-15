import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

import {
  ATTACKNET_SCHEDULE_SCHEMA,
  consumeDdminCandidate,
  consumeReplayPlan,
  createDdminPlan,
  describeDdminCandidate,
  issueDdminAttempt,
  recordDdminOutcome,
  resolveAttacknetSchedule,
  validateResolvedSchedule,
} from './attacknet-run-schedule.mjs';
import {sha256Value} from './run-descriptor.mjs';

const imageDigest = `sha256:${'a'.repeat(64)}`;

function campaign(name, target, duration = '10s') {
  return {
    metadata: {name, uid: `uid-${name}`, generation: 3},
    spec: {
      template: true,
      networkRef: 'attacknet',
      target: {actors: [target]},
      fault: {type: 'pod', action: 'pod-kill', mode: 'all', duration, parameters: {gracePeriod: 0}},
      safety: {
        maxUnavailableSignerPercent: 30,
        maxUnavailableMinerPercent: 50,
        allowQuorumLoss: false,
        allowMinerMajorityOutage: false,
        allowBurnchain: false,
        allowExtendedDuration: false,
        allowExtremeSeverity: false,
        allowUnenrolledNetworkTargets: false,
      },
    },
  };
}

function fixture() {
  const campaigns = [campaign('kill-a', 'miner-1'), campaign('kill-b', 'miner-2', '12s')];
  const manifest = {
    network: 'attacknet', namespace: 'attacknet-system',
    actors: [
      {service: 'bitcoin', role: 'burnchain'},
      {service: 'miner-1', role: 'miner'}, {service: 'miner-2', role: 'miner'},
      {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1},
      {service: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 1},
      {service: 'signer-3', role: 'signer', signerIndex: 3, signerWeight: 1},
      {service: 'signer-4', role: 'signer', signerIndex: 4, signerWeight: 1},
    ],
  };
  const catalog = campaigns.map((source, index) => ({
    name: index === 0 ? 'alpha' : 'beta', campaignRef: source.metadata.name,
    expectedUID: source.metadata.uid, expectedGeneration: source.metadata.generation,
    expectedSpecDigest: sha256Value(source.spec),
  }));
  const run = {
    metadata: {name: 'seeded-run'},
    spec: {
      networkRef: 'attacknet', seed: 'repeatable-001', decisionAlgorithm: 'hmac-sha256-decisions/v1',
      campaignCatalog: catalog,
      sequence: [
        {id: 'first', campaign: 'alpha', delayAfterSeconds: 3, enabled: true},
        {id: 'second', campaign: 'beta', delayAfterSeconds: 0, enabled: true},
      ],
      budgets: {
        maxCampaigns: 4, maxWallTimeSeconds: 120, maxCumulativeFaultSeconds: 60,
        maxActiveFaults: 1, maxSignerImpactPercent: 30, maxBurnchainFaults: 0,
        maxInconclusiveCampaigns: 1,
      },
    },
  };
  const context = {
    network: {uid: 'network-uid-1', generation: 7}, manifest, campaigns,
    images: [{scope: 'stacks-actors', requestedRef: 'stacks:main',
      resolvedRef: `stacks@${imageDigest}`, resolvedDigest: imageDigest}],
    decisionSpaces: {
      first: {
        campaignAliases: ['beta', 'alpha'],
        targetSets: [['signer-1'], ['miner-2'], ['miner-1']],
        parameterVariants: [{gracePeriod: 1}, {gracePeriod: 0}],
      },
    },
  };
  return {run, context};
}

test('resolves a deterministic, immutable and budgeted schedule', () => {
  const {run, context} = fixture();
  const left = resolveAttacknetSchedule(run, context);
  const right = resolveAttacknetSchedule(structuredClone(run), structuredClone(context));
  assert.deepEqual(left, right);
  assert.equal(left.schemaVersion, ATTACKNET_SCHEDULE_SCHEMA);
  assert.equal(left.network.uid, 'network-uid-1');
  assert.equal(left.actions.length, 2);
  assert.deepEqual(left.actions.map(action => action.order), [1, 2]);
  assert.equal(left.actions[0].choiceReceipts.length, 3);
  assert.deepEqual(left.actions[0].imageConstraints, left.imageConstraints);
  assert.equal(left.actions[0].source.generation, 3);
  assert.match(left.actions[0].source.specDigest, /^sha256:/);
  assert.equal(left.actions[1].notBeforeOffsetSeconds,
    left.actions[0].budgetCharge.faultSeconds + 3);
  assert.equal(left.budgets.usage.campaigns, 2);
  assert.equal(validateResolvedSchedule(left), true);
});

test('canonical choice spaces ignore incidental option ordering but seed and namespaces matter', () => {
  const {run, context} = fixture();
  const original = resolveAttacknetSchedule(run, context);
  context.decisionSpaces.first.campaignAliases.reverse();
  context.decisionSpaces.first.targetSets.reverse();
  context.decisionSpaces.first.parameterVariants.reverse();
  assert.deepEqual(resolveAttacknetSchedule(run, context), original);

  run.spec.seed = 'repeatable-002';
  const changed = resolveAttacknetSchedule(run, context);
  assert.notEqual(changed.integrity.digest, original.integrity.digest);
  assert.notEqual(changed.actions[0].choiceReceipts[0].digest,
    original.actions[0].choiceReceipts[0].digest);
});

test('rejects stale source constraints, unresolved images, and aggregate budget violations', () => {
  let value = fixture();
  value.context.campaigns[0].metadata.uid = 'replacement-uid';
  assert.throws(() => resolveAttacknetSchedule(value.run, value.context), /UID constraint/);

  value = fixture();
  delete value.context.images[0].resolvedDigest;
  assert.throws(() => resolveAttacknetSchedule(value.run, value.context), /resolvedDigest/);

  value = fixture();
  value.run.spec.budgets.maxCampaigns = 1;
  assert.throws(() => resolveAttacknetSchedule(value.run, value.context), /campaigns 2>1/);

  value = fixture();
  value.context.decisionSpaces.first.targetSets = [['bitcoin']];
  assert.throws(() => resolveAttacknetSchedule(value.run, value.context), /burnchain faults require/);
});

test('schedule validation detects spec, budget, and integrity tampering', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  let tampered = structuredClone(schedule);
  tampered.actions[0].resolved.campaignSpec.fault.duration = '99s';
  assert.throws(() => validateResolvedSchedule(tampered), /campaign spec digest mismatch/);
  tampered = structuredClone(schedule);
  tampered.budgets.usage.campaigns = 0;
  assert.throws(() => validateResolvedSchedule(tampered), /budget usage mismatch/);
  tampered = structuredClone(schedule);
  tampered.budgets.headroom.campaigns = 999;
  assert.throws(() => validateResolvedSchedule(tampered), /budget headroom mismatch/);
  tampered = structuredClone(schedule);
  tampered.run.seed = 'changed';
  assert.throws(() => validateResolvedSchedule(tampered), /integrity mismatch/);
});

test('legacy descriptor replay actions normalize into the same resolved schedule contract', () => {
  const {run, context} = fixture();
  delete context.decisionSpaces;
  const replayPlan = {
    strategy: 'failure-prefix/v1',
    derivedFrom: {runId: 'failed-run', descriptorDigest: `sha256:${'b'.repeat(64)}`},
    schedule: [
      {order: 1, offsetMs: 0, type: 'cadence-transition', payload: {
        policy: 'burnchain', from: 'pause', to: 'interval:10s', reason: 'ready',
      }},
      {order: 2, offsetMs: 5000, type: 'fault-decision', payload: {
        campaign: 'alpha', decision: 'applied', faultKind: 'PodChaos',
        targets: ['miner-2'], parameters: {gracePeriod: 1},
      }},
    ],
    expectedFailure: {assertion: 'chain-progress', status: 'fail', originalSequence: 3},
    disclosure: 'Prefix replay is not proof of causal minimality.',
  };
  const replay = consumeReplayPlan(replayPlan, run, context);
  assert.equal(validateResolvedSchedule(replay), true);
  assert.equal(replay.replay.enabled, true);
  assert.deepEqual(replay.actions.map(action => action.kind), ['cadence-transition', 'fault-campaign']);
  assert.equal(replay.actions[1].notBeforeOffsetSeconds, 5);
  assert.deepEqual(replay.actions[1].resolved.targets, ['miner-2']);
  assert.equal(replay.actions[1].resolved.parameters.gracePeriod, 1);
});

test('resolved replay enforces fresh network identity and exact image constraints', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  const plan = {resolvedSchedule: schedule};
  assert.throws(() => consumeReplayPlan(plan, run, context), /fresh network UID/);
  context.network = {uid: 'fresh-replay-network', generation: 1};
  const replay = consumeReplayPlan(plan, run, context);
  assert.equal(replay.network.uid, 'fresh-replay-network');
  assert.equal(replay.replay.sourceScheduleDigest, schedule.integrity.digest);
  assert.deepEqual(replay.actions, schedule.actions);
  context.images[0].resolvedDigest = `sha256:${'d'.repeat(64)}`;
  context.images[0].resolvedRef = `stacks@${context.images[0].resolvedDigest}`;
  assert.throws(() => consumeReplayPlan(plan, run, context), /image constraints/);
});

function resultFor(plan, issued, outcome, uid) {
  return {
    attemptId: issued.attempt.id, outcome,
    freshNetwork: {
      uid, cleanStart: true, manifestDigest: plan.candidate.network.manifestDigest,
      imagesDigest: sha256Value(plan.candidate.imageConstraints),
    },
    observed: outcome === 'FailureReproduced'
      ? structuredClone(plan.expectedFailure) : {assertion: 'chain-progress', status: 'pass'},
    evidenceDigest: `sha256:${'c'.repeat(64)}`,
  };
}

test('ddmin is adaptive, counterfactual, and accepts evidence only from unique fresh networks', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  let plan = createDdminPlan(schedule, {
    requireFreshNetwork: true, maxAttempts: 12,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'},
  });
  assert.equal(plan.result.causalMinimalityClaimed, false);
  let issued = issueDdminAttempt(plan);
  plan = issued.plan;
  assert.equal(issued.attempt.counterfactual.dimension, 'campaigns');
  assert.equal(issued.attempt.freshNetworkRequirement.cleanStateRequired, true);
  assert.equal(issued.attempt.schedule.actions.filter(action => action.kind === 'fault-campaign').length, 1);

  let invalid = resultFor(plan, issued, 'FailureReproduced', schedule.network.uid);
  assert.throws(() => recordDdminOutcome(plan, invalid), /different from the source/);
  invalid = resultFor(plan, issued, 'FailureReproduced', 'fresh-1');
  invalid.freshNetwork.cleanStart = false;
  assert.throws(() => recordDdminOutcome(plan, invalid), /cleanStart=true/);

  plan = recordDdminOutcome(plan, resultFor(plan, issued, 'FailureReproduced', 'fresh-1'));
  assert.equal(plan.candidate.actions.filter(action => action.kind === 'fault-campaign').length, 1);
  assert.equal(plan.result.causalMinimalityClaimed, false);

  issued = issueDdminAttempt(plan);
  plan = issued.plan;
  assert.ok(issued.attempt, 'target or parameter minimization must follow campaign reduction');
  const duplicate = resultFor(plan, issued, 'FailureAbsent', 'fresh-1');
  assert.throws(() => recordDdminOutcome(plan, duplicate), /already used/);
  plan = recordDdminOutcome(plan, resultFor(plan, issued, 'FailureAbsent', 'fresh-2'));
  assert.equal(plan.attempts.length, 2);
  assert.equal(plan.result.causalMinimalityClaimed, false);
});

test('ddmin candidate admission permits only source removals on a fresh identical network', () => {
  const {run, context} = fixture();
  const source = resolveAttacknetSchedule(run, context);
  const issued = issueDdminAttempt(createDdminPlan(source, {
    requireFreshNetwork: true, maxAttempts: 4,
    expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
  }));
  const reduction = describeDdminCandidate(source, issued.attempt.schedule);
  const fresh = structuredClone(context);
  fresh.network = {uid: 'network-uid-ddmin-fresh', generation: 1};
  const admitted = consumeDdminCandidate(reduction, source, fresh);
  assert.equal(admitted.network.uid, 'network-uid-ddmin-fresh');
  assert.equal(admitted.replay.sourceScheduleDigest, source.integrity.digest);
  assert.equal(admitted.replay.candidateScheduleDigest, issued.attempt.schedule.integrity.digest);
  assert.deepEqual(admitted.actions.map(action => action.instructionId),
    issued.attempt.schedule.actions.map(action => action.instructionId));

  const reordered = describeDdminCandidate(source, source);
  reordered.retained.reverse();
  assert.throws(() => consumeDdminCandidate(reordered, source, fresh), /may not reorder/);
  const widened = structuredClone(reduction);
  widened.retained[0].removedTargets = ['not-a-source-target'];
  assert.throws(() => consumeDdminCandidate(widened, source, fresh), /unknown target/);
  fresh.network.uid = source.network.uid;
  assert.throws(() => consumeDdminCandidate(reduction, source, fresh), /fresh network UID/);
});

test('ddmin records inconclusive counterfactuals without a minimality claim', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  let plan = createDdminPlan(schedule, {requireFreshNetwork: true, maxAttempts: 1,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'}});
  const issued = issueDdminAttempt(plan);
  plan = recordDdminOutcome(issued.plan, resultFor(issued.plan, issued, 'Inconclusive', 'fresh-inc'));
  const exhausted = issueDdminAttempt(plan).plan;
  assert.equal(exhausted.phase, 'BudgetExhausted');
  assert.equal(exhausted.result.causalMinimalityClaimed, false);
  assert.match(exhausted.result.statement, /no minimality claim/i);
});

test('ddmin issuance is deterministic and completion means observed one-minimality, never causal minimality', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  const options = {requireFreshNetwork: true, maxAttempts: 20,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'}};
  let plan = createDdminPlan(schedule, options);
  const same = createDdminPlan(schedule, options);
  assert.deepEqual(issueDdminAttempt(plan), issueDdminAttempt(same));
  let uid = 0;
  while (!new Set(['Complete', 'Inconclusive', 'BudgetExhausted']).has(plan.phase)) {
    const issued = issueDdminAttempt(plan);
    plan = issued.plan;
    if (!issued.attempt) break;
    uid += 1;
    plan = recordDdminOutcome(plan, resultFor(plan, issued, 'FailureAbsent', `fresh-complete-${uid}`));
  }
  assert.equal(plan.phase, 'Complete');
  assert.equal(plan.result.oneMinimalUnderObservedCounterfactuals, true);
  assert.equal(plan.result.causalMinimalityClaimed, false);
  assert.match(plan.result.statement, /fresh-network counterfactual reruns/);
});

test('ddmin rejects mismatched counterfactual evidence and source-only schedules', () => {
  const {run, context} = fixture();
  const schedule = resolveAttacknetSchedule(run, context);
  let plan = createDdminPlan(schedule, {requireFreshNetwork: true, maxAttempts: 3,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'}});
  const issued = issueDdminAttempt(plan);
  plan = issued.plan;
  let result = resultFor(plan, issued, 'FailureReproduced', 'fresh-wrong-manifest');
  result.freshNetwork.manifestDigest = `sha256:${'e'.repeat(64)}`;
  assert.throws(() => recordDdminOutcome(plan, result), /manifest digest differs/);
  result = resultFor(plan, issued, 'FailureReproduced', 'fresh-wrong-failure');
  result.observed.assertion = 'another-assertion';
  assert.throws(() => recordDdminOutcome(plan, result), /must match the expected failure/);

  const cadenceOnly = structuredClone(schedule);
  cadenceOnly.actions = [{order: 1, kind: 'cadence-transition', instructionId: 'cadence',
    notBeforeOffsetSeconds: 0, delayAfterSeconds: 0, payload: {to: 'pause'}}];
  cadenceOnly.budgets.usage = {
    campaigns: 0, cumulativeFaultSeconds: 0, maximumSignerImpactPercent: 0,
    burnchainFaults: 0, maximumActiveFaults: 0, plannedWallTimeSeconds: 0,
  };
  cadenceOnly.budgets.headroom = {
    campaigns: cadenceOnly.budgets.limits.maxCampaigns,
    cumulativeFaultSeconds: cadenceOnly.budgets.limits.maxCumulativeFaultSeconds,
    signerImpactPercent: cadenceOnly.budgets.limits.maxSignerImpactPercent,
    burnchainFaults: cadenceOnly.budgets.limits.maxBurnchainFaults,
    wallTimeSeconds: cadenceOnly.budgets.limits.maxWallTimeSeconds,
  };
  const unsigned = structuredClone(cadenceOnly);
  delete unsigned.integrity;
  cadenceOnly.integrity = {algorithm: 'sha256', digest: sha256Value(unsigned)};
  assert.throws(() => createDdminPlan(cadenceOnly, {requireFreshNetwork: true, maxAttempts: 3,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'}}), /at least one fault-campaign/);
});

test('CLI writes deterministic resolve, replay, and ddmin artifacts', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-schedule-'));
  const cli = new URL('./attacknet-run-schedule.mjs', import.meta.url).pathname;
  const {run, context} = fixture();
  const resolveInput = join(root, 'resolve.json');
  const schedulePath = join(root, 'schedule.json');
  writeFileSync(resolveInput, JSON.stringify({run, context}));
  let child = spawnSync(process.execPath, [cli, 'resolve', resolveInput, schedulePath], {encoding: 'utf8'});
  assert.equal(child.status, 0, child.stderr);
  const schedule = JSON.parse(readFileSync(schedulePath, 'utf8'));
  assert.equal(validateResolvedSchedule(schedule), true);

  const initInput = join(root, 'init.json');
  const planPath = join(root, 'plan.json');
  writeFileSync(initInput, JSON.stringify({schedule, options: {requireFreshNetwork: true, maxAttempts: 3,
    expectedFailure: {assertion: 'chain-progress', status: 'fail'}}}));
  child = spawnSync(process.execPath, [cli, 'ddmin-init', initInput, planPath], {encoding: 'utf8'});
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(readFileSync(planPath, 'utf8')).schemaVersion, 'stacks-attacknet-ddmin/v1');
});
