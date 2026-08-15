import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AttacknetRunReconciler, FaultCampaignReconciler, FINALIZER, digest,
  artifactDigest, classifyTerminalAssertion, decodeSchedule, networkManifest, podEffectResults,
  prometheusMetrics, stableName,
} from './controller.mjs';
import {
  createDdminPlan, describeDdminCandidate, issueDdminAttempt,
} from '../../../attacknet/attacknet-run-schedule.mjs';

const uid = name => `uid-${name}`;
const clone = value => value === null || value === undefined ? value : structuredClone(value);

class FakeApi {
  constructor() {
    this.objects = new Map();
    this.pods = [];
  }
  key(group, plural, name) { return `${group}/${plural}/${name}`; }
  put(plural, value, group = 'testing.stacks.org') {
    this.objects.set(this.key(group, plural, value.metadata.name), clone(value));
  }
  async get(plural, name, options = {}) {
    const group = options.group ?? 'testing.stacks.org';
    const value = this.objects.get(this.key(group, plural, name));
    if (!value && !options.allow404) throw new Error(`missing ${group}/${plural}/${name}`);
    return clone(value ?? null);
  }
  async list(plural, options = {}) {
    if ((options.group ?? 'testing.stacks.org') === '' && plural === 'pods') return {items: clone(this.pods)};
    const group = options.group ?? 'testing.stacks.org';
    return {items: [...this.objects.entries()]
      .filter(([key]) => key.startsWith(`${group}/${plural}/`)).map(([, value]) => clone(value))};
  }
  async create(plural, body, options = {}) {
    const group = options.group ?? 'testing.stacks.org';
    const value = clone(body);
    value.metadata.uid ??= uid(value.metadata.name);
    value.metadata.resourceVersion ??= '1';
    this.put(plural, value, group);
    return clone(value);
  }
  async patch(plural, name, body, options = {}) {
    const group = options.group ?? 'testing.stacks.org';
    const key = this.key(group, plural, name);
    const current = this.objects.get(key);
    if (!current) throw new Error(`missing ${key}`);
    if (options.subresource === 'status') current.status = clone(body.status);
    else current.metadata = {...current.metadata, ...(body.metadata ?? {})};
    current.metadata.resourceVersion = String(Number(current.metadata.resourceVersion ?? 0) + 1);
    return clone(current);
  }
  async delete(plural, name, options = {}) {
    const group = options.group ?? 'testing.stacks.org';
    this.objects.delete(this.key(group, plural, name));
    return {};
  }
}

function network() {
  return {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    metadata: {name: 'demo', namespace: 'hacknet', uid: uid('demo'), generation: 3, resourceVersion: '1'},
    spec: {defaults: {image: 'stacks:test'}, actors: [
      {name: 'miner-1', role: 'miner', ports: [{name: 'p2p', containerPort: 20444}]},
      {name: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1},
      {name: 'signer-node-1', role: 'companion', signerIndex: 1, signerWeight: 1, ports: [{name: 'p2p', containerPort: 20444}]},
      {name: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 2},
      {name: 'signer-node-2', role: 'companion', signerIndex: 2, signerWeight: 2},
      {name: 'signer-3', role: 'signer', signerIndex: 3, signerWeight: 3},
      {name: 'signer-node-3', role: 'companion', signerIndex: 3, signerWeight: 3},
    ]},
    status: {phase: 'Ready'},
  };
}

function pod(actor, role) {
  return {
    metadata: {name: `demo-${actor}-0`, uid: uid(actor), labels: {
      'testing.stacks.org/network': 'demo', 'testing.stacks.org/actor': actor,
      'testing.stacks.org/role': role,
    }},
    spec: {nodeName: 'worker-1'},
    status: {
    phase: 'Running', conditions: [{type: 'Ready', status: 'True'}],
    podIP: '10.244.1.23',
      containerStatuses: [
        {name: 'actor', ready: true, image: 'stacks:test', imageID: `docker-pullable://stacks@test@sha256:${'a'.repeat(64)}`, restartCount: 0},
        {name: 'attacknet-probe', ready: true, image: 'probe:test', imageID: 'sha256:probe', restartCount: 0},
      ],
    },
  };
}

function networkPods(value = network()) {
  return value.spec.actors.map((actor, index) => {
    const result = pod(actor.name, actor.role);
    result.status.podIP = `10.244.1.${index + 20}`;
    return result;
  });
}

function campaign({template = false, effect = true} = {}) {
  return {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'FaultCampaign',
    metadata: {
      name: template ? 'kill-signer-template' : 'kill-signer', namespace: 'hacknet',
      uid: uid(template ? 'template' : 'campaign'), generation: 1, resourceVersion: '1',
      finalizers: template ? [] : [FINALIZER], creationTimestamp: '2026-01-01T00:00:00Z',
    },
    spec: {
      template, networkRef: 'demo', target: {actors: ['signer-1']},
      fault: {type: 'pod', action: 'pod-kill', mode: 'one', duration: '1s', parameters: {}},
      safety: {maxUnavailableSignerPercent: 30, maxUnavailableMinerPercent: 50},
      effectAssertions: effect ? [{type: 'PodRestarted'}] : [],
      recoveryAssertions: [{type: 'TargetReady'}],
    },
  };
}

function networkCampaign() {
  const value = campaign();
  value.metadata.name = 'delay-signer';
  value.metadata.uid = uid('delay-signer');
  value.spec.fault = {
    type: 'network', action: 'delay', mode: 'all', duration: '1s',
    parameters: {
      delay: {latency: '750ms', correlation: '0', jitter: '0ms'},
      peerTarget: {actors: ['signer-node-1']},
    },
  };
  value.spec.effectAssertions = [{type: 'NetworkDegraded'}];
  return value;
}

function attacknetRun(source, overrides = {}) {
  const spec = {
    networkRef: 'demo', seed: 'opaque-seed',
    campaignCatalog: [{name: 'kill', campaignRef: source.metadata.name}],
    sequence: [{id: 'step-one', campaign: 'kill', delayAfterSeconds: 0}],
    budgets: {
      maxCampaigns: 1, maxWallTimeSeconds: 1800,
      maxCumulativeFaultSeconds: 60, maxActiveFaults: 1,
      maxSignerImpactPercent: 30, maxBurnchainFaults: 0,
      maxInconclusiveCampaigns: 0,
    },
    stopPolicy: {
      onCampaignFailure: 'Stop', onInconclusive: 'Stop',
      onBudgetExhausted: 'Stop', onSuccess: 'Continue',
    },
    ...overrides,
  };
  return {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'AttacknetRun',
    metadata: {
      name: 'run-a', namespace: 'hacknet', uid: uid('run-a'), generation: 1,
      resourceVersion: '1', creationTimestamp: '2026-01-01T00:00:00Z',
    },
    spec,
  };
}

test('authoritative manifest rejects inconsistent signer ownership and remains canonical', () => {
  const fixture = network();
  const manifest = networkManifest(fixture);
  assert.deepEqual(manifest.actors[1], {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1});
  fixture.spec.actors[2].signerWeight = 2;
  assert.throws(() => networkManifest(fixture), /inconsistent authoritative weight/);
  assert.equal(digest({b: 2, a: 1}), digest({a: 1, b: 2}));
  assert.ok(stableName('x'.repeat(63), 'child').length <= 63);
});

test('template campaigns validate without creating a fault', async () => {
  const api = new FakeApi();
  const value = campaign({template: true});
  api.put('faultcampaigns', value);
  await new FaultCampaignReconciler(api).reconcile(value);
  const admitted = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(admitted.status.phase, 'Pending');
  assert.equal(admitted.status.reason, 'TemplateReady');
  assert.equal((await api.list('podchaos', {group: 'chaos-mesh.org'})).items.length, 0);
});

test('Pod effect proof is tied to the immutable admitted UID', () => {
  const value = campaign();
  value.status = {resolvedTargets: [{
    actor: 'signer-1', podUid: uid('signer-1'), restartCount: 0,
  }]};
  const unchanged = podEffectResults(value, [pod('signer-1', 'signer')]);
  assert.equal(unchanged[0].outcome, 'Failed');
  const replacement = pod('signer-1', 'signer');
  replacement.metadata.uid = uid('signer-1-replacement');
  const observed = podEffectResults(value, [replacement]);
  assert.equal(observed[0].outcome, 'Proven');
  assert.match(observed[0].message, /admitted Pod UID disappeared/);
});

test('campaign proves admission/injection/recovery but never invents effect evidence', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  api.put('faultcampaigns', campaign());
  const reconciler = new FaultCampaignReconciler(api);

  let value = await api.get('faultcampaigns', 'kill-signer');
  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Admitted');
  assert.equal(value.status.resolvedTargets[0].podUid, uid('signer-1'));

  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Injecting');
  const chaos = await api.get('podchaos', 'kill-signer', {group: 'chaos-mesh.org'});
  chaos.status = {conditions: [{type: 'AllInjected', status: 'True'}]};
  api.put('podchaos', chaos, 'chaos-mesh.org');

  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Active');
  const recovered = await api.get('podchaos', 'kill-signer', {group: 'chaos-mesh.org'});
  recovered.status.conditions.push({type: 'AllRecovered', status: 'True'});
  api.put('podchaos', recovered, 'chaos-mesh.org');

  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Recovering');
  assert.equal(value.status.cleanup.allRecovered, true);
  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Inconclusive');
  assert.equal(value.status.reason, 'EffectNotProven');
});

test('trusted before/during/after probes prove a network effect and its recovery', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = networkCampaign();
  api.put('faultcampaigns', value);
  let calls = 0;
  const probes = {probe: async (target, request) => {
    const latency = calls++ === 1 ? 800 : 10;
    return {observation: {
      actor: target.actor, probe: 'network', status: 'ok',
      probeName: `${request.peer}-${request.port}`, peerActor: request.peer,
      attempts: 5, successes: 5, latencyMsP50: latency, latencyMsP95: latency,
      protocolErrors: 0, throughputBytesPerSecond: null,
    }};
  }};
  const reconciler = new FaultCampaignReconciler(api, probes);

  let current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Admitted');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  const chaos = await api.get('networkchaos', value.metadata.name, {group: 'chaos-mesh.org'});
  chaos.status = {conditions: [{type: 'AllInjected', status: 'True'}]};
  api.put('networkchaos', chaos, 'chaos-mesh.org');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Active');
  const recovered = await api.get('networkchaos', value.metadata.name, {group: 'chaos-mesh.org'});
  recovered.status.conditions.push({type: 'AllRecovered', status: 'True'});
  api.put('networkchaos', recovered, 'chaos-mesh.org');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Passed');
  assert.equal(current.status.effectResults[0].outcome, 'Proven');
  assert.equal(current.status.recoveryResults[0].outcome, 'Proven');
});

test('an unready co-located probe cannot supply baseline evidence', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  const target = pod('signer-1', 'signer');
  target.status.containerStatuses.find(item => item.name === 'attacknet-probe').ready = false;
  // Model the short interval before Kubernetes updates the aggregate Pod Ready
  // condition. The controller still checks the probe container explicitly.
  api.pods = [target];
  const value = networkCampaign();
  api.put('faultcampaigns', value);
  let calls = 0;
  const reconciler = new FaultCampaignReconciler(api, {probe: async () => { calls += 1; }});

  await reconciler.reconcile(await api.get('faultcampaigns', value.metadata.name));
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'ProbeBaselineUnavailable');
  assert.equal(calls, 0);
});

test('AttacknetRun snapshots a referenced template into exactly one owned execution', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source);
  api.put('attacknetruns', run);
  await new AttacknetRunReconciler(api).reconcile(run, [source]);
  let updated = await api.get('attacknetruns', 'run-a');
  assert.equal(updated.status.phase, 'Preparing');
  assert.match(updated.status.scheduleRef.digest, /^sha256:[0-9a-f]{64}$/);
  await new AttacknetRunReconciler(api).reconcile(updated, [source]);
  updated = await api.get('attacknetruns', 'run-a');
  assert.equal(updated.status.phase, 'Running');
  const child = await api.get('faultcampaigns', updated.status.activeCampaign);
  assert.equal(child.spec.template, false);
  assert.equal(child.metadata.ownerReferences[0].uid, run.metadata.uid);
  assert.equal(child.metadata.annotations['testing.stacks.org/source-template-uid'], source.metadata.uid);
  assert.equal(child.metadata.annotations['testing.stacks.org/source-template-digest'], artifactDigest(source.spec));
});

test('AttacknetRun refuses a campaign whose resolved signer impact exceeds the aggregate run budget', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source, {
    budgets: {
      ...attacknetRun(source).spec.budgets,
      maxSignerImpactPercent: 10,
    },
  });
  api.put('attacknetruns', run);
  await new AttacknetRunReconciler(api).reconcile(run, [source]);
  let updated = await api.get('attacknetruns', run.metadata.name);
  await new AttacknetRunReconciler(api).reconcile(updated, [source]);
  updated = await api.get('attacknetruns', run.metadata.name);
  assert.equal(updated.status.phase, 'Failed');
  assert.equal(updated.status.reason, 'ScheduleAdmissionFailed');
  assert.match(updated.status.message, /maximum signer impact percent/);
  assert.equal((await api.list('faultcampaigns')).items.length, 1);
});

test('a run spec change after schedule sealing fails instead of changing execution', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source);
  api.put('attacknetruns', run);
  const reconciler = new AttacknetRunReconciler(api);
  await reconciler.reconcile(run, [source]);
  const changed = await api.get('attacknetruns', run.metadata.name);
  changed.metadata.generation += 1;
  changed.spec.seed = 'different-seed';
  api.put('attacknetruns', changed);

  await reconciler.reconcile(changed, [source]);
  const result = await api.get('attacknetruns', run.metadata.name);
  assert.equal(result.status.phase, 'Failed');
  assert.equal(result.status.reason, 'AdmittedRunChanged');
  assert.equal((await api.list('faultcampaigns')).items.length, 1);
});

test('replay consumes a sealed source schedule only on a fresh matching network identity', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const firstNetwork = network();
  api.put('stacksnetworks', firstNetwork);
  api.pods = networkPods(firstNetwork);
  api.put('faultcampaigns', source);
  const original = attacknetRun(source);
  api.put('attacknetruns', original);
  const reconciler = new AttacknetRunReconciler(api);
  await reconciler.reconcile(original, [source]);
  const resolvedOriginal = await api.get('attacknetruns', original.metadata.name);
  resolvedOriginal.status.phase = 'Failed';
  resolvedOriginal.status.reason = 'ExpectedFailureForReplay';
  api.put('attacknetruns', resolvedOriginal);

  const freshNetwork = network();
  freshNetwork.metadata.uid = 'uid-demo-fresh';
  api.put('stacksnetworks', freshNetwork);
  api.pods = networkPods(freshNetwork);
  const replay = attacknetRun(source);
  replay.metadata.name = 'run-replay';
  replay.metadata.uid = uid('run-replay');
  replay.spec.replay = {
    enabled: true, sourceRunRef: original.metadata.name,
    descriptorURI: `k8s://attacknetruns/${original.metadata.name}/resolved-schedule`,
    descriptorDigest: resolvedOriginal.status.scheduleRef.digest,
    attemptId: 'replay-baseline',
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed',
    requireSameResolvedImages: true, verifyExpectedFailure: true,
  };
  api.put('attacknetruns', replay);
  await reconciler.reconcile(replay, [source]);
  const resolvedReplay = await api.get('attacknetruns', replay.metadata.name);
  assert.equal(resolvedReplay.status.phase, 'Preparing');
  const configMap = await api.get('configmaps', resolvedReplay.status.scheduleRef.name, {group: ''});
  const replaySchedule = decodeSchedule(configMap);
  assert.equal(replaySchedule.replay.enabled, true);
  assert.equal(replaySchedule.replay.sourceNetwork.uid, firstNetwork.metadata.uid);
  assert.equal(replaySchedule.network.uid, freshNetwork.metadata.uid);
});

test('ddmin run admits only a removal from a terminal sealed schedule on a fresh network', async () => {
  const api = new FakeApi();
  const first = campaign({template: true, effect: false});
  const second = structuredClone(first);
  second.metadata.name = 'kill-signer-second-template';
  second.metadata.uid = uid('second-template');
  api.put('faultcampaigns', first);
  api.put('faultcampaigns', second);
  const originalNetwork = network();
  api.put('stacksnetworks', originalNetwork);
  api.pods = networkPods(originalNetwork);
  const sourceRun = attacknetRun(first);
  sourceRun.spec.campaignCatalog.push({name: 'kill-second', campaignRef: second.metadata.name});
  sourceRun.spec.sequence.push({id: 'step-two', campaign: 'kill-second', delayAfterSeconds: 0});
  sourceRun.spec.budgets.maxCampaigns = 2;
  api.put('attacknetruns', sourceRun);
  const reconciler = new AttacknetRunReconciler(api);
  await reconciler.reconcile(sourceRun, [first, second]);
  const sealedSourceRun = await api.get('attacknetruns', sourceRun.metadata.name);
  const sourceConfigMap = await api.get('configmaps', sealedSourceRun.status.scheduleRef.name, {group: ''});
  const sourceSchedule = decodeSchedule(sourceConfigMap);
  sealedSourceRun.status.phase = 'Failed';
  sealedSourceRun.status.reason = 'ExpectedFailure';
  api.put('attacknetruns', sealedSourceRun);

  const issued = issueDdminAttempt(createDdminPlan(sourceSchedule, {
    requireFreshNetwork: true, maxAttempts: 2,
    expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
  }));
  const reduction = describeDdminCandidate(sourceSchedule, issued.attempt.schedule);
  const fresh = network();
  fresh.metadata.uid = 'uid-demo-ddmin-fresh';
  fresh.metadata.generation = 1;
  api.put('stacksnetworks', fresh);
  api.pods = networkPods(fresh);

  const attempt = attacknetRun(first);
  attempt.metadata.name = issued.attempt.id;
  attempt.metadata.uid = uid(issued.attempt.id);
  attempt.spec = structuredClone(sourceRun.spec);
  attempt.spec.replay = {enabled: false};
  attempt.spec.resume = {enabled: false};
  attempt.spec.minimization = {
    enabled: true, strategy: 'DeltaDebug', maxAttempts: 1, requireFreshNetwork: true,
    sourceRunRef: sourceRun.metadata.name,
    sourceScheduleDigest: reduction.sourceScheduleDigest,
    candidateScheduleDigest: reduction.candidateScheduleDigest,
    attemptId: issued.attempt.id,
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed', retained: reduction.retained,
  };
  api.put('attacknetruns', attempt);
  await reconciler.reconcile(attempt, [first, second]);
  let current = await api.get('attacknetruns', attempt.metadata.name);
  assert.equal(current.status.phase, 'Preparing');
  const admittedConfigMap = await api.get('configmaps', current.status.scheduleRef.name, {group: ''});
  const admitted = decodeSchedule(admittedConfigMap);
  assert.equal(admitted.network.uid, fresh.metadata.uid);
  assert.equal(admitted.actions.length, 1);
  assert.equal(admitted.replay.candidateScheduleDigest, issued.attempt.schedule.integrity.digest);

  current.status.startedAt = new Date(Date.now() - 2000).toISOString();
  await reconciler.reconcile(current, [first, second]);
  current = await api.get('attacknetruns', attempt.metadata.name);
  assert.equal(current.status.phase, 'Running', JSON.stringify(current.status));
  const child = await api.get('faultcampaigns', current.status.activeCampaign);
  child.status = {
    phase: 'Passed', reason: 'EffectAndRecoveryProven', completedAt: '2026-01-01T00:00:10Z',
    recoveryResults: [{assertion: 'TargetReady', outcome: 'Failed', actor: 'signer-1'}],
  };
  api.put('faultcampaigns', child);
  await reconciler.reconcile(current, [first, second, child]);
  current = await api.get('attacknetruns', attempt.metadata.name);
  assert.equal(current.status.phase, 'Passed');
  assert.equal(current.status.terminalClassification.outcome, 'FailureReproduced');
  assert.equal(current.status.terminalClassification.causalMinimalityClaimed, false);
});

test('terminal assertion classification fails closed on missing or ambiguous evidence', () => {
  const source = campaign({template: true});
  const run = attacknetRun(source, {minimization: {
    enabled: true, attemptId: 'ddmin-001', candidateScheduleDigest: `sha256:${'c'.repeat(64)}`,
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed',
  }});
  const missing = classifyTerminalAssertion(run, [{metadata: {name: 'child', uid: 'uid-child'},
    status: {phase: 'Failed', reason: 'ControllerError'}}], `sha256:${'d'.repeat(64)}`);
  assert.equal(missing.outcome, 'Inconclusive');
  assert.equal(missing.reason, 'ExpectedAssertionNotEvaluated');
  const absent = classifyTerminalAssertion(run, [{metadata: {name: 'child', uid: 'uid-child'},
    status: {phase: 'Passed', recoveryResults: [
      {assertion: 'TargetReady', outcome: 'Proven', actor: 'signer-1'},
    ]}}], `sha256:${'d'.repeat(64)}`);
  assert.equal(absent.outcome, 'FailureAbsent');

  const conflicting = classifyTerminalAssertion(run, [{metadata: {name: 'child', uid: 'uid-child'},
    status: {phase: 'Passed', recoveryResults: [
      {assertion: 'TargetReady', outcome: 'Failed', actor: 'signer-1'},
      {assertion: 'TargetReady', outcome: 'Proven', actor: 'signer-2'},
    ]}}], `sha256:${'d'.repeat(64)}`);
  assert.equal(conflicting.outcome, 'Inconclusive');
  assert.equal(conflicting.reason, 'ConflictingExpectedAssertionEvidence');

  const replay = attacknetRun(source, {replay: {
    enabled: true, verifyExpectedFailure: true, attemptId: 'replay-baseline',
    descriptorDigest: `sha256:${'f'.repeat(64)}`,
    expectedAssertion: 'TargetReady', expectedStatus: 'Failed',
  }});
  const reproduced = classifyTerminalAssertion(replay, [{metadata: {name: 'child', uid: 'uid-child'},
    status: {phase: 'Inconclusive', recoveryResults: [
      {assertion: 'TargetReady', outcome: 'Failed', actor: 'signer-1'},
    ]}}], `sha256:${'d'.repeat(64)}`);
  assert.equal(reproduced.attemptId, 'replay-baseline');
  assert.equal(reproduced.outcome, 'FailureReproduced');
});

test('FaultCampaign finalizer removes an owned fault before permitting deletion', async () => {
  const api = new FakeApi();
  const value = campaign();
  value.metadata.deletionTimestamp = '2026-01-01T00:00:00Z';
  api.put('faultcampaigns', value);
  api.put('podchaos', {
    metadata: {name: value.metadata.name, uid: uid('chaos')},
    status: {conditions: [{type: 'AllRecovered', status: 'True'}]},
  }, 'chaos-mesh.org');
  await new FaultCampaignReconciler(api).reconcile(value);
  const updated = await api.get('faultcampaigns', value.metadata.name);
  assert.deepEqual(updated.metadata.finalizers, []);
  assert.equal(await api.get('podchaos', value.metadata.name, {
    group: 'chaos-mesh.org', allow404: true,
  }), null);
});

test('run-controller metrics expose bounded orchestrator state and assertion outcomes', () => {
  const value = networkCampaign();
  value.status = {
    phase: 'Passed', reason: 'EffectAndRecoveryProven',
    resolvedTargets: [{actor: 'signer-1', role: 'signer', node: 'worker-1'}],
    effectResults: [{actor: 'signer-1', assertion: 'NetworkDegraded', outcome: 'Proven'}],
    recoveryResults: [{actor: 'signer-1', assertion: 'TargetReady', outcome: 'Proven'}],
  };
  const run = attacknetRun(campaign({template: true}));
  run.status = {
    phase: 'Running', reason: 'CampaignActive', attribution: 'Untriaged',
    scheduleRef: {digest: `sha256:${'b'.repeat(64)}`}, scheduleSummary: {replay: false},
    budgetUsage: {campaigns: 1, wallTimeSeconds: 42},
    terminalClassification: {
      attemptId: 'ddmin-001', candidateScheduleDigest: `sha256:${'c'.repeat(64)}`,
      expectedAssertion: 'TargetReady', expectedStatus: 'Failed', outcome: 'FailureAbsent',
      reason: 'ExpectedAssertionEvaluatedWithoutExpectedStatus',
      evidenceDigest: `sha256:${'d'.repeat(64)}`, causalMinimalityClaimed: false,
    },
  };
  const output = prometheusMetrics([value], [run]);
  assert.match(output, /attacknet_fault_campaign_info\{[^\n]*phase="Passed"/);
  assert.match(output, /attacknet_fault_campaign_target_info\{[^\n]*actor="signer-1"/);
  assert.match(output, /assertion="NetworkDegraded",outcome="Proven"/);
  assert.match(output, /attacknet_run_info\{[^\n]*phase="Running"[^\n]*schedule_digest="sha256:b{64}"/);
  assert.match(output, /attacknet_run_budget_usage\{[^\n]*budget="wallTimeSeconds"\} 42/);
  assert.match(output, /attacknet_run_minimization_outcome\{[^\n]*outcome="FailureAbsent"/);
  assert.match(output, /causal_minimality_claimed="false"/);
  assert.doesNotMatch(output, /pod_uid/);
});
