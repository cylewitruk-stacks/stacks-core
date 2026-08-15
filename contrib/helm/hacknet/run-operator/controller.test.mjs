import assert from 'node:assert/strict';
import test from 'node:test';
import {EventEmitter} from 'node:events';

import {
  AttacknetRunReconciler, FaultCampaignReconciler, RunController, SignerSetClient, FINALIZER, digest,
  artifactDigest, classifyTerminalAssertion, decodeSchedule, networkManifest, podEffectResults,
  prometheusMetrics, resolvedNetworkImages, stableName,
} from './controller.mjs';
import {
  createDdminPlan, describeDdminCandidate, issueDdminAttempt,
} from '../../../attacknet/attacknet-run-schedule.mjs';
import {compileCampaign} from '../../../attacknet/fault-campaign.mjs';

const uid = name => `uid-${name}`;
const clone = value => value === null || value === undefined ? value : structuredClone(value);
const signerKey = index => `02${index.toString(16).padStart(64, '0')}`;

class FakeSignerSets {
  constructor({error = null, weights = null, digest: signerSetDigest = null} = {}) {
    this.error = error;
    this.weights = weights;
    this.digest = signerSetDigest;
    this.calls = 0;
  }
  async resolve(_network, _pods, manifest) {
    this.calls += 1;
    if (this.error) throw this.error;
    const resolved = structuredClone(manifest);
    if (this.weights) {
      for (const actor of resolved.actors) {
        const weight = this.weights[actor.signerPublicKey];
        if (weight !== undefined) actor.signerWeight = weight;
      }
    }
    const total = resolved.actors.filter(actor => actor.role === 'signer')
      .reduce((sum, actor) => sum + actor.signerWeight, 0);
    return {
      rewardCycle: 11, observedTotalWeight: total,
      signerSetDigest: this.digest ?? `sha256:${'b'.repeat(64)}`, observedFrom: 'miner-1',
      manifest: resolved,
    };
  }
}

const runReconciler = (api, signerSets = new FakeSignerSets()) =>
  new AttacknetRunReconciler(api, signerSets);
const faultReconciler = (api, probes, signerSets = new FakeSignerSets()) =>
  new FaultCampaignReconciler(api, probes, signerSets, {
    ioPressureImage: 'stacks-hacknet-io-pressure:test',
    ioPressureImagePullPolicy: 'IfNotPresent',
  });

class FakeApi {
  constructor() {
    this.objects = new Map();
    this.pods = [];
    this.put('configmaps', {
      apiVersion: 'v1', kind: 'ConfigMap',
      metadata: {name: 'attacknet-environment-lease', namespace: 'hacknet', uid: uid('environment-lease')},
      data: {network: 'demo', owner: 'test', purpose: 'test', acquiredAt: '2026-01-01T00:00:00Z'},
    }, '');
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
      {name: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1, signerPublicKey: signerKey(1)},
      {name: 'signer-node-1', role: 'companion', signerIndex: 1, signerWeight: 1, signerPublicKey: signerKey(1), ports: [{name: 'rpc', containerPort: 20443}, {name: 'p2p', containerPort: 20444}]},
      {name: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 2, signerPublicKey: signerKey(2)},
      {name: 'signer-node-2', role: 'companion', signerIndex: 2, signerWeight: 2, signerPublicKey: signerKey(2)},
      {name: 'signer-3', role: 'signer', signerIndex: 3, signerWeight: 3, signerPublicKey: signerKey(3)},
      {name: 'signer-node-3', role: 'companion', signerIndex: 3, signerWeight: 3, signerPublicKey: signerKey(3)},
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
    spec: {
      nodeName: 'worker-1', securityContext: {fsGroup: 65532},
      containers: [{name: 'actor', volumeMounts: [{name: 'data', mountPath: '/data'}]}],
      volumes: [{name: 'data', persistentVolumeClaim: {claimName: `data-demo-${actor}-0`}}],
    },
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
  value.spec.recoveryAssertions = [{type: 'NetworkRecovered'}];
  return value;
}

function ioCampaign() {
  const value = campaign();
  value.metadata.name = 'delay-io';
  value.metadata.uid = uid('delay-io');
  value.spec.fault = {
    type: 'io', action: 'latency', mode: 'all', duration: '1s',
    parameters: {
      volumePath: '/data', path: '/data/.attacknet-probe-signer-1/*',
      methods: ['FSYNC'], delay: '100ms', percent: 100,
      containerNames: ['actor', 'attacknet-probe'],
    },
  };
  value.spec.safety.allowExtremeSeverity = true;
  value.spec.effectAssertions = [{type: 'IODegraded'}];
  value.spec.recoveryAssertions = [{type: 'IORecovered'}];
  return value;
}

function ioPressureCampaign() {
  const value = campaign();
  value.metadata.name = 'pressure-signer-disk';
  value.metadata.uid = uid('pressure-signer-disk');
  value.spec.fault = {
    type: 'io-pressure', action: 'disk-pressure', mode: 'all', duration: '1s',
    parameters: {
      containerNames: ['actor'], severity: 'low', workers: 1, bytesMiB: 32,
      writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
    },
  };
  value.spec.effectAssertions = [{type: 'IOPressureObserved'}];
  value.spec.recoveryAssertions = [{type: 'IOPressureRecovered'}];
  return value;
}

function timeCampaign() {
  const value = campaign();
  value.metadata.name = 'skew-signer-clock';
  value.metadata.uid = uid('skew-signer-clock');
  value.spec.fault = {
    type: 'time', mode: 'all', duration: '1s',
    parameters: {
      timeOffset: '-30s', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor'],
    },
  };
  value.spec.effectAssertions = [{type: 'ClockSkewObserved'}];
  value.spec.recoveryAssertions = [{type: 'ClockSkewCleared'}];
  return value;
}

function ioContainerRecords(value, {injectedCount = 0, recoveredCount = 0} = {}) {
  return value.spec.fault.parameters.containerNames.map(container => ({
    id: `${value.metadata.namespace}/demo-signer-1-0/${container}`,
    injectedCount,
    recoveredCount,
    phase: injectedCount === 0 ? 'Not Injected/Wait' : 'Injected/Wait',
    events: [{type: injectedCount === 0 ? 'Failed' : 'Succeeded', operation: 'Apply',
      message: injectedCount === 0 ? 'native helper unavailable' : 'injected'}],
  }));
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
  assert.deepEqual(manifest.actors[1], {
    service: 'signer-1', role: 'signer', signerIndex: 1,
    signerWeight: 1, signerPublicKey: signerKey(1),
  });
  fixture.spec.actors[2].signerWeight = 2;
  assert.throws(() => networkManifest(fixture), /inconsistent authoritative weight/);
  assert.equal(digest({b: 2, a: 1}), digest({a: 1, b: 2}));
  assert.ok(stableName('x'.repeat(63), 'child').length <= 63);
});

test('admitted image identity is canonical across actor declaration order', () => {
  const fixture = network();
  const pods = networkPods(fixture);
  fixture.spec.actors.reverse();
  const images = resolvedNetworkImages(fixture, {items: pods});
  const scopes = images.map(image => image.scope);
  assert.deepEqual(scopes, [...scopes].sort((left, right) => left.localeCompare(right)));
  assert.deepEqual(images, resolvedNetworkImages(network(), {items: networkPods()}));
});

function fakeHttpJson(responses) {
  const requested = [];
  const request = (options, callback) => {
    const call = new EventEmitter();
    call.end = () => queueMicrotask(() => {
      requested.push(options.path);
      const response = new EventEmitter();
      response.statusCode = 200;
      callback(response);
      queueMicrotask(() => {
        response.emit('data', Buffer.from(JSON.stringify(responses[options.path])));
        response.emit('end');
      });
    });
    call.destroy = error => call.emit('error', error);
    return call;
  };
  return {request, requested};
}

test('signer-set client joins admitted identities to the current canonical reward set', async () => {
  const fixture = network();
  const httpFixture = fakeHttpJson({
    '/v2/pox': {current_cycle: {id: 11}},
    '/v3/stacker_set/11': {stacker_set: {signers: [
      {signing_key: signerKey(3), weight: 3},
      {signing_key: signerKey(1), weight: 1},
      {signing_key: signerKey(2), weight: 2},
    ]}},
  });
  const report = await new SignerSetClient({request: httpFixture.request})
    .verify(fixture, {items: networkPods(fixture)}, networkManifest(fixture));
  assert.equal(report.rewardCycle, 11);
  assert.equal(report.declaredTotalWeight, 6);
  assert.equal(report.observedTotalWeight, 6);
  assert.equal(report.observedFrom, 'signer-node-1');
  assert.deepEqual(httpFixture.requested, ['/v2/pox', '/v3/stacker_set/11']);
});

test('signer-set client resolves legitimate canonical weight drift without changing identities', async () => {
  const fixture = network();
  const httpFixture = fakeHttpJson({
    '/v2/pox': {current_cycle: {id: 12}},
    '/v3/stacker_set/12': {stacker_set: {signers: [
      {signing_key: signerKey(3), weight: 2},
      {signing_key: signerKey(1), weight: 1},
      {signing_key: signerKey(2), weight: 2},
    ]}},
  });
  const resolved = await new SignerSetClient({request: httpFixture.request})
    .resolve(fixture, {items: networkPods(fixture)}, networkManifest(fixture));
  assert.equal(resolved.rewardCycle, 12);
  assert.equal(resolved.weightsMatch, false);
  assert.equal(resolved.observedTotalWeight, 5);
  assert.equal(resolved.manifest.actors.find(actor => actor.service === 'signer-3').signerWeight, 2);
  assert.equal(resolved.manifest.actors.find(actor => actor.service === 'signer-node-3').signerWeight, 2);
});

test('run admission fails closed when live signer identities do not match the manifest', async () => {
  const api = new FakeApi();
  const source = campaign({template: true});
  const run = attacknetRun(source);
  api.put('stacksnetworks', network());
  api.put('faultcampaigns', source);
  api.put('attacknetruns', run);
  api.pods = networkPods();
  const signerSets = new FakeSignerSets({error: new Error('declared signer identities do not match reward cycle 11')});
  await runReconciler(api, signerSets).reconcile(run, [source]);
  const failed = await api.get('attacknetruns', run.metadata.name);
  assert.equal(failed.status.phase, 'Failed');
  assert.equal(failed.status.reason, 'ScheduleAdmissionFailed');
  assert.match(failed.status.message, /identities do not match reward cycle 11/);
  assert.equal(signerSets.calls, 1);
});

test('FaultCampaign admission charges canonical current-cycle weights', async () => {
  const api = new FakeApi();
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  const value = campaign();
  api.put('faultcampaigns', value);
  const signerSets = new FakeSignerSets({weights: {
    [signerKey(1)]: 1, [signerKey(2)]: 4, [signerKey(3)]: 4,
  }});
  await faultReconciler(api, undefined, signerSets).reconcile(value);
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Admitted');
  assert.equal(current.status.admission.signerSetTotalWeight, 9);
  assert.equal(current.status.admission.signerImpact.affectedWeight, 1);
  assert.equal(current.status.admission.signerImpact.percent, 100 / 9);
  assert.match(current.status.admission.signerSetDigest, /^sha256:/);
});

test('IOChaos fails admission before resource creation when the target architecture is unsupported', async () => {
  const api = new FakeApi();
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = [pod('signer-1', 'signer')];
  const value = ioCampaign();
  api.put('faultcampaigns', value);
  const probes = {probe: async (target, request) => ({
    schemaVersion: 'stacks-attacknet-probe-response/v1',
    actor: target.actor, kind: request.kind, observedAt: '2026-08-15T16:00:00Z',
    observation: {
      actor: target.actor, probe: 'system', status: 'ok',
      platform: 'linux', architecture: 'arm64',
    },
  })};

  await faultReconciler(api, probes).reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'FaultCapabilityUnavailable');
  assert.equal(current.status.capabilityEvidence[0].architecture, 'arm64');
  assert.equal(current.status.capabilityEvidence[0].supported, false);
  assert.match(current.status.message, /supports x64/);
  assert.equal((await api.list('iochaos', {group: 'chaos-mesh.org'})).items.length, 0);

  // Admission failure is terminal; the next reconciliation releases the
  // serialization lease only after confirming that no Chaos resource exists.
  await faultReconciler(api, probes).reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.cleanup.absent, true);
  assert.equal(await api.get('configmaps', 'attacknet-mutation-lease', {
    group: '', allow404: true,
  }), null);
});

test('TimeChaos fails admission before resource creation when its platform canary profile excludes the target architecture', async () => {
  const api = new FakeApi();
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = [pod('signer-1', 'signer')];
  const value = timeCampaign();
  api.put('faultcampaigns', value);
  const probes = {probe: async (target, request) => ({
    schemaVersion: 'stacks-attacknet-probe-response/v1',
    actor: target.actor, kind: request.kind, observedAt: '2026-08-15T17:45:00Z',
    observation: {
      actor: target.actor, probe: 'system', status: 'ok',
      platform: 'linux', architecture: 'arm64',
    },
  })};

  await faultReconciler(api, probes).reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'FaultCapabilityUnavailable');
  assert.equal(current.status.capabilityEvidence[0].architecture, 'arm64');
  assert.equal(current.status.capabilityEvidence[0].supported, false);
  assert.match(current.status.message, /TimeChaos platform profile supports x64/);
  assert.equal((await api.list('timechaos', {group: 'chaos-mesh.org'})).items.length, 0);

  await faultReconciler(api, probes).reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.cleanup.absent, true);
  assert.equal(await api.get('configmaps', 'attacknet-mutation-lease', {
    group: '', allow404: true,
  }), null);
});

test('FaultCampaign refuses to create Chaos after its canonical signer set changes', async () => {
  const api = new FakeApi();
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  const value = campaign();
  api.put('faultcampaigns', value);
  let calls = 0;
  const signerSets = {
    async resolve(_network, _pods, manifest) {
      calls += 1;
      return new FakeSignerSets({
        weights: calls === 1
          ? {[signerKey(1)]: 1, [signerKey(2)]: 2, [signerKey(3)]: 3}
          : {[signerKey(1)]: 1, [signerKey(2)]: 2, [signerKey(3)]: 2},
        digest: `sha256:${(calls === 1 ? 'b' : 'c').repeat(64)}`,
      }).resolve(_network, _pods, manifest);
    },
  };
  const reconciler = faultReconciler(api, undefined, signerSets);
  await reconciler.reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Admitted');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'SignerSetChangedBeforeInjection');
  assert.equal((await api.list('podchaos', {group: 'chaos-mesh.org'})).items.length, 0);
});

test('template campaigns validate without creating a fault', async () => {
  const api = new FakeApi();
  const value = campaign({template: true});
  api.put('faultcampaigns', value);
  await faultReconciler(api).reconcile(value);
  const admitted = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(admitted.status.phase, 'Pending');
  assert.equal(admitted.status.reason, 'TemplateReady');
  assert.equal((await api.list('podchaos', {group: 'chaos-mesh.org'})).items.length, 0);
});

test('an executable campaign exclusively holds and releases the shared mutation lease', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = campaign();
  api.put('faultcampaigns', value);
  const reconciler = faultReconciler(api);

  await reconciler.reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Admitted');
  const lease = await api.get('configmaps', 'attacknet-mutation-lease', {group: ''});
  assert.deepEqual(lease.data, {
    network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
    purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid,
    acquiredAt: lease.data.acquiredAt,
  });

  current.status = {...current.status, phase: 'Passed', reason: 'EffectAndRecoveryProven'};
  api.put('faultcampaigns', current);
  await reconciler.reconcile(current);
  assert.equal(await api.get('configmaps', 'attacknet-mutation-lease', {
    group: '', allow404: true,
  }), null);
});

test('a terminal campaign retains the mutation lease until owned Chaos is confirmed absent', async () => {
  const api = new FakeApi();
  const value = campaign();
  value.status = {
    phase: 'Failed', reason: 'InjectionTimeout',
    cleanup: {absent: false, allRecovered: true, observedAt: '2026-01-01T00:00:00Z'},
  };
  api.put('faultcampaigns', value);
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('campaign-lease')},
    data: {
      network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
      purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid,
    },
  }, '');
  api.put('podchaos', {
    metadata: {name: value.metadata.name, uid: uid('chaos')},
    status: {conditions: [{type: 'AllRecovered', status: 'True'}]},
  }, 'chaos-mesh.org');
  const deleteResource = api.delete.bind(api);
  let deletionSettled = false;
  api.delete = async (plural, name, options = {}) => {
    if (plural === 'podchaos' && !deletionSettled) return {};
    return deleteResource(plural, name, options);
  };
  const reconciler = faultReconciler(api);

  await reconciler.reconcile(value);
  assert.ok(await api.get('podchaos', value.metadata.name, {group: 'chaos-mesh.org'}));
  assert.ok(await api.get('configmaps', 'attacknet-mutation-lease', {group: ''}));

  deletionSettled = true;
  await reconciler.reconcile(await api.get('faultcampaigns', value.metadata.name));
  const terminal = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(terminal.status.cleanup.absent, true);
  assert.equal(terminal.status.cleanup.allRecovered, true);
  assert.equal(await api.get('configmaps', 'attacknet-mutation-lease', {
    group: '', allow404: true,
  }), null);
});

test('an IO injection timeout preserves the exact zero-injection daemon records', async () => {
  const api = new FakeApi();
  const admittedNetwork = network();
  api.put('stacksnetworks', admittedNetwork);
  api.pods = [pod('signer-1', 'signer')];
  const value = ioCampaign();
  const compiled = compileCampaign({metadata: {name: value.metadata.name}, spec: value.spec},
    networkManifest(admittedNetwork));
  value.status = {
    phase: 'Injecting', reason: 'ChaosResourceCreated',
    admission: {
      networkUid: admittedNetwork.metadata.uid,
      networkGeneration: admittedNetwork.metadata.generation,
      compiledDigest: artifactDigest(compiled.resource),
    },
    resolvedTargets: [{
      actor: 'signer-1', role: 'signer', pod: 'demo-signer-1-0',
      podUid: uid('signer-1'), node: 'worker-1', podIP: '10.244.1.23',
    }],
    chaos: {kind: 'IOChaos', name: value.metadata.name, uid: uid('io-chaos'),
      createdAt: '2020-01-01T00:00:00Z'},
  };
  api.put('faultcampaigns', value);
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('io-lease')},
    data: {network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
      purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid},
  }, '');
  api.put('iochaos', {
    metadata: {name: value.metadata.name, uid: uid('io-chaos'), resourceVersion: '7'},
    status: {
      conditions: [{type: 'AllInjected', status: 'False'}],
      experiment: {containerRecords: ioContainerRecords(value)},
    },
  }, 'chaos-mesh.org');

  await faultReconciler(api).reconcile(value);
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'InjectionTimeout');
  assert.equal(current.status.actualInjection.allInjectedObserved, false);
  assert.equal(current.status.actualInjection.chaosResourceVersion, '7');
  assert.deepEqual(current.status.actualInjection.records.containerRecords,
    ioContainerRecords(value));
  assert.match(current.status.message, /native helper unavailable/);
});

test('a terminal IO campaign may clear only an exact proven zero-injection records finalizer', async () => {
  const api = new FakeApi();
  const value = ioCampaign();
  value.status = {
    phase: 'Failed', reason: 'InjectionTimeout',
    resolvedTargets: [{
      actor: 'signer-1', role: 'signer', pod: 'demo-signer-1-0',
      podUid: uid('signer-1'), node: 'worker-1', podIP: '10.244.1.23',
    }],
    cleanup: {absent: false, allRecovered: false, observedAt: '2026-01-01T00:00:00Z'},
  };
  api.put('faultcampaigns', value);
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('io-lease')},
    data: {network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
      purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid},
  }, '');
  api.put('iochaos', {
    metadata: {
      name: value.metadata.name, uid: uid('io-chaos'), resourceVersion: '7',
      deletionTimestamp: '2020-01-01T00:00:00Z', finalizers: ['chaos-mesh/records'],
    },
    status: {
      conditions: [{type: 'AllInjected', status: 'False'}],
      experiment: {containerRecords: ioContainerRecords(value)},
    },
  }, 'chaos-mesh.org');
  const patchResource = api.patch.bind(api);
  api.patch = async (plural, name, body, options = {}) => {
    const result = await patchResource(plural, name, body, options);
    if (plural === 'iochaos' && body.metadata?.finalizers?.length === 0) {
      api.objects.delete(api.key('chaos-mesh.org', plural, name));
    }
    return result;
  };

  await faultReconciler(api).reconcile(value);
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.cleanup.absent, true);
  assert.equal(current.status.cleanup.allRecovered, false);
  assert.equal(current.status.cleanup.method, 'ZeroInjectionFinalizerAbort');
  assert.equal(current.status.cleanup.zeroInjectionProven, true);
  assert.equal(await api.get('iochaos', value.metadata.name, {
    group: 'chaos-mesh.org', allow404: true,
  }), null);
  assert.equal(await api.get('configmaps', 'attacknet-mutation-lease', {
    group: '', allow404: true,
  }), null);
});

test('any observed IO injection forbids the zero-injection finalizer escape', async () => {
  const api = new FakeApi();
  const value = ioCampaign();
  value.status = {
    phase: 'Failed', reason: 'InjectionTimeout',
    resolvedTargets: [{actor: 'signer-1', pod: 'demo-signer-1-0', podUid: uid('signer-1')}],
    cleanup: {absent: false, allRecovered: false, observedAt: '2026-01-01T00:00:00Z'},
  };
  api.put('faultcampaigns', value);
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('io-lease')},
    data: {network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
      purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid},
  }, '');
  api.put('iochaos', {
    metadata: {
      name: value.metadata.name, uid: uid('io-chaos'), resourceVersion: '7',
      deletionTimestamp: '2020-01-01T00:00:00Z', finalizers: ['chaos-mesh/records'],
    },
    status: {
      conditions: [{type: 'AllInjected', status: 'False'}],
      experiment: {containerRecords: ioContainerRecords(value, {injectedCount: 1})},
    },
  }, 'chaos-mesh.org');

  await faultReconciler(api).reconcile(value);
  const remaining = await api.get('iochaos', value.metadata.name, {group: 'chaos-mesh.org'});
  assert.deepEqual(remaining.metadata.finalizers, ['chaos-mesh/records']);
  assert.ok(await api.get('configmaps', 'attacknet-mutation-lease', {group: ''}));
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.cleanup.absent, false);
});

test('a foreign mutation holder keeps a pending campaign inert', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('foreign-lease')},
    data: {network: 'demo', owner: 'human:123', purpose: 'lifecycle', token: 'foreign-token'},
  }, '');
  const value = campaign();
  api.put('faultcampaigns', value);

  await faultReconciler(api).reconcile(value);
  const current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Pending');
  assert.equal(current.status.reason, 'WaitingForMutationLease');
  assert.equal((await api.list('podchaos', {group: 'chaos-mesh.org'})).items.length, 0);
  const lease = await api.get('configmaps', 'attacknet-mutation-lease', {group: ''});
  assert.equal(lease.data.token, 'foreign-token');
});

test('losing the mutation lease after injection fails closed and removes only owned Chaos', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = campaign();
  api.put('faultcampaigns', value);
  const reconciler = faultReconciler(api);

  await reconciler.reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Injecting');
  assert.ok(await api.get('podchaos', value.metadata.name, {group: 'chaos-mesh.org'}));

  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('replacement-lease')},
    data: {network: 'demo', owner: 'human:456', purpose: 'teardown', token: 'replacement-token'},
  }, '');
  await new RunController(api).reconcileOnce();

  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'ControllerError');
  assert.match(current.status.message, /lost its mutation lease/);
  assert.equal(await api.get('podchaos', value.metadata.name, {
    group: 'chaos-mesh.org', allow404: true,
  }), null);
  const foreign = await api.get('configmaps', 'attacknet-mutation-lease', {group: ''});
  assert.equal(foreign.data.token, 'replacement-token');
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
  const reconciler = faultReconciler(api);

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
  assert.equal(value.status.phase, 'Injecting');
  assert.equal(value.status.reason, 'WaitingForEffectEvidence');
  assert.equal(value.status.effectResults[0].outcome, 'Failed');
  const recovered = await api.get('podchaos', 'kill-signer', {group: 'chaos-mesh.org'});
  recovered.status.conditions = [
    {type: 'AllInjected', status: 'False'},
    {type: 'AllRecovered', status: 'True'},
  ];
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

test('one-shot pod-kill cleans up from trusted effect evidence without waiting for AllRecovered', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  api.put('faultcampaigns', campaign());
  const reconciler = faultReconciler(api);

  let value = await api.get('faultcampaigns', 'kill-signer');
  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  const chaos = await api.get('podchaos', 'kill-signer', {group: 'chaos-mesh.org'});
  chaos.status = {conditions: [
    {type: 'AllInjected', status: 'True'},
    {type: 'AllRecovered', status: 'False'},
  ]};
  api.put('podchaos', chaos, 'chaos-mesh.org');
  const replacement = pod('signer-1', 'signer');
  replacement.metadata.uid = uid('signer-1-replacement');
  api.pods = [replacement];

  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Recovering');
  assert.equal(value.status.reason, 'OneShotEffectObserved');
  assert.equal(value.status.effectResults[0].outcome, 'Proven');
  assert.equal(value.status.cleanup.allRecovered, false);
  assert.equal(value.status.cleanup.absent, true);
  assert.equal(await api.get('podchaos', 'kill-signer', {
    group: 'chaos-mesh.org', allow404: true,
  }), null);

  await reconciler.reconcile(value);
  value = await api.get('faultcampaigns', 'kill-signer');
  assert.equal(value.status.phase, 'Passed');
  assert.equal(value.status.recoveryResults[0].outcome, 'Proven');
});

test('an active one-shot campaign resumes cleanup from durable effect evidence after restart', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  const replacement = pod('signer-1', 'signer');
  replacement.metadata.uid = uid('signer-1-replacement');
  api.pods = [replacement];
  const value = campaign();
  value.status = {
    phase: 'Active', reason: 'AllInjectedObserved',
    admission: {
      networkUid: uid('demo'), networkGeneration: 3,
      compiledDigest: null, admittedAt: '2026-01-01T00:00:00Z',
      signerImpact: {}, minerImpact: {},
    },
    resolvedTargets: [{
      actor: 'signer-1', role: 'signer', pod: 'demo-signer-1-0',
      podUid: uid('signer-1'), podIP: '10.244.1.23', node: 'worker-1',
      restartCount: 0, requestedImage: 'stacks:test', resolvedImageId: 'sha256:test',
    }],
    effectResults: [{
      assertion: 'PodRestarted', outcome: 'Proven', actor: 'signer-1',
      podUid: uid('signer-1'), observedAt: '2026-01-01T00:00:01Z',
    }],
  };
  api.put('faultcampaigns', value);
  const compiled = compileCampaign(
    {metadata: {name: value.metadata.name}, spec: value.spec}, networkManifest(network()),
  );
  value.status.admission.compiledDigest = artifactDigest(compiled.resource);
  api.put('faultcampaigns', value);
  api.put('configmaps', {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {name: 'attacknet-mutation-lease', namespace: 'hacknet', uid: uid('campaign-lease')},
    data: {
      network: 'demo', owner: `faultcampaign:${value.metadata.uid}`,
      purpose: `faultcampaign:${value.metadata.name}`, token: value.metadata.uid,
    },
  }, '');
  api.put('podchaos', {
    metadata: {name: value.metadata.name, uid: uid('chaos')},
    status: {conditions: [
      {type: 'AllInjected', status: 'True'},
      {type: 'AllRecovered', status: 'False'},
    ]},
  }, 'chaos-mesh.org');
  const reconciler = faultReconciler(api);

  await reconciler.reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Recovering');
  assert.equal(current.status.reason, 'OneShotEffectObserved');
  assert.equal(current.status.cleanup.absent, true);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Passed');
});

test('pod-failure effect polling survives aggregate network unready and proves recovery', async () => {
  const api = new FakeApi();
  const admittedNetwork = network();
  api.put('stacksnetworks', admittedNetwork);
  const target = pod('signer-1', 'signer');
  api.pods = [target];
  const value = campaign();
  value.spec.fault.action = 'pod-failure';
  value.spec.effectAssertions = [{type: 'PodUnavailable', actor: 'signer-1'}];
  api.put('faultcampaigns', value);
  const reconciler = faultReconciler(api);

  await reconciler.reconcile(value);
  let current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  const chaos = await api.get('podchaos', value.metadata.name, {group: 'chaos-mesh.org'});
  chaos.status = {conditions: [{type: 'AllInjected', status: 'True'}]};
  api.put('podchaos', chaos, 'chaos-mesh.org');

  // AllInjected can precede kubelet's Ready=False observation.
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Injecting');
  assert.equal(current.status.reason, 'WaitingForEffectEvidence');

  // The fault itself makes the aggregate StacksNetwork non-Ready. An admitted
  // campaign must continue its state machine instead of regressing to Pending.
  admittedNetwork.status.phase = 'Degraded';
  api.put('stacksnetworks', admittedNetwork);
  target.status.conditions.find(item => item.type === 'Ready').status = 'False';
  target.status.containerStatuses[0].ready = false;
  api.pods = [target];
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Active');
  assert.equal(current.status.effectResults[0].outcome, 'Proven');

  const recovered = await api.get('podchaos', value.metadata.name, {group: 'chaos-mesh.org'});
  recovered.status.conditions = [
    {type: 'AllInjected', status: 'False'},
    {type: 'AllRecovered', status: 'True'},
  ];
  api.put('podchaos', recovered, 'chaos-mesh.org');
  admittedNetwork.status.phase = 'Ready';
  api.put('stacksnetworks', admittedNetwork);
  target.status.conditions.find(item => item.type === 'Ready').status = 'True';
  target.status.containerStatuses[0].ready = true;
  api.pods = [target];
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Recovering');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Passed');
  assert.equal(current.status.reason, 'EffectAndRecoveryProven');
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
  const reconciler = faultReconciler(api, probes);

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
  assert.equal(current.status.effectResults[0].assertion, 'NetworkDegraded');
  assert.equal(current.status.recoveryResults[0].outcome, 'Proven');
  assert.equal(current.status.recoveryResults[0].assertion, 'NetworkRecovered');
  assert.equal(current.status.recoveryResults[0].message,
    'trusted after-fault probe classified recovery=proven');
  assert.doesNotMatch(current.status.recoveryResults[0].message, /delay=true/);
});

test('bounded controller-owned I/O-pressure Pod requires active evidence and strict cleanup', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = ioPressureCampaign();
  api.put('faultcampaigns', value);
  // The first post-fault sample is still elevated. Recovery assertions are a
  // bounded polling window, so the controller must retain Recovering and take
  // another trusted sample instead of making the first noisy result terminal.
  const samples = [4, 12, 8, 4.5];
  const probes = {probe: async (target, request) => {
    assert.equal(request.kind, 'io');
    assert.equal(request.operation, 'FSYNC');
    const latency = samples.shift();
    return {observation: {
      actor: target.actor, probe: 'io', status: 'ok', probeName: `fsync-${request.file}`,
      path: `/data/.attacknet-probe-${target.actor}/${request.file}`, operation: 'FSYNC',
      attempts: 5, successes: 5, errorCounts: {}, latencyMsP50: latency,
      latencyMsP95: latency, contentDigest: 'sha256:content', attributesDigest: 'sha256:attributes',
    }};
  }};
  const reconciler = faultReconciler(api, probes);

  let current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Admitted');
  assert.equal(current.status.capabilityEvidence.length, 1);
  assert.equal(current.status.capabilityEvidence[0].supported, true);
  assert.equal(current.status.capabilityEvidence[0].source, 'attacknet-run-operator/v1');

  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  const pressureName = 'io-pressure-pressure-signer-disk';
  const pressure = await api.get('pods', pressureName, {group: ''});
  assert.equal(pressure.kind, 'Pod');
  assert.equal(pressure.metadata.labels['testing.stacks.org/mechanism'],
    'controller-owned-io-pressure-pod');
  assert.equal(pressure.spec.nodeName, 'worker-1');
  assert.equal(pressure.spec.automountServiceAccountToken, false);
  assert.equal(pressure.spec.containers[0].image, 'stacks-hacknet-io-pressure:test');
  assert.equal(pressure.spec.containers[0].command, undefined);
  assert.deepEqual(pressure.spec.containers[0].args, [
    '--duration-seconds', '1', '--workers', '1', '--bytes-mib', '32',
    '--write-size-kib', '256', '--scratch-path',
    '/data/.attacknet-io-pressure-uid-pressure-signer-disk',
  ]);
  assert.deepEqual(pressure.spec.containers[0].resources.limits, {cpu: '250m', memory: '64Mi'});
  assert.equal(pressure.spec.volumes[0].persistentVolumeClaim.claimName,
    'data-demo-signer-1-0');
  assert.match(current.status.chaos.resourceDigest, /^sha256:[0-9a-f]{64}$/);
  pressure.status = {
    phase: 'Running', containerStatuses: [{
      name: 'io-pressure', image: 'stacks-hacknet-io-pressure:test',
      imageID: `docker-pullable://stacks-hacknet-io-pressure@sha256:${'c'.repeat(64)}`,
      state: {running: {startedAt: '2026-01-01T00:00:01Z'}},
    }],
  };
  api.put('pods', pressure, '');

  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Active');
  assert.deepEqual(current.status.effectResults, []);
  assert.equal(current.status.actualInjection.allInjectedObserved, true);
  assert.equal(current.status.actualInjection.mechanism, 'controller-owned-io-pressure-pod');
  assert.equal(current.status.actualInjection.podUid, uid(pressureName));
  assert.equal(current.status.actualInjection.node, 'worker-1');
  assert.equal(current.status.actualInjection.phase, 'Running');
  assert.equal(current.status.actualInjection.pvcClaim, 'data-demo-signer-1-0');

  const completed = await api.get('pods', pressureName, {group: ''});
  completed.status.phase = 'Succeeded';
  api.put('pods', completed, '');
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Recovering');
  assert.equal(current.status.cleanup.absent, true);
  assert.equal(current.status.cleanup.allRecovered, true);
  assert.equal(await api.get('pods', pressureName, {
    group: '', allow404: true,
  }), null);

  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Recovering');
  assert.equal(current.status.reason, 'WaitingForRecoveryEvidence');
  assert.equal(current.status.effectResults[0].outcome, 'Proven');
  assert.equal(current.status.recoveryResults[0].outcome, 'Failed');

  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Passed', JSON.stringify(current.status, null, 2));
  assert.equal(current.status.effectResults[0].assertion, 'IOPressureObserved');
  assert.equal(current.status.effectResults[0].outcome, 'Proven');
  assert.equal(current.status.recoveryResults[0].assertion, 'IOPressureRecovered');
  assert.equal(current.status.recoveryResults[0].outcome, 'Proven');
  assert.match(current.status.effectResults[0].message, /both configured/);
  assert.match(current.status.recoveryResults[0].message, /returned below both/);
  assert.equal(samples.length, 0);
});

test('I/O-pressure refuses a pre-existing Pod with an arbitrary execution contract', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = ioPressureCampaign();
  api.put('faultcampaigns', value);
  const reconciler = faultReconciler(api, {probe: async target => ({observation: {
    actor: target.actor, probe: 'io', status: 'ok', probeName: 'fsync-pressure',
    path: `/data/.attacknet-probe-${target.actor}/pressure.dat`, operation: 'FSYNC',
    attempts: 5, successes: 5, errorCounts: {}, latencyMsP50: 1, latencyMsP95: 2,
    contentDigest: 'sha256:content', attributesDigest: 'sha256:attributes',
  }})});
  await reconciler.reconcile(await api.get('faultcampaigns', value.metadata.name));
  const admitted = await api.get('faultcampaigns', value.metadata.name);
  api.put('pods', {
    apiVersion: 'v1', kind: 'Pod', metadata: {
      name: 'io-pressure-pressure-signer-disk', uid: uid('foreign-pressure'),
      ownerReferences: [{uid: value.metadata.uid, controller: true}],
    },
    spec: {containers: [{name: 'io-pressure', image: 'attacker/image', command: ['/bin/sh']}]},
  }, '');
  await assert.rejects(() => reconciler.reconcile(admitted), /different trusted execution contract/);
  await assert.rejects(() => reconciler.removeChaos(admitted), /refusing to delete unowned/);
  const foreign = await api.get('pods', 'io-pressure-pressure-signer-disk', {group: ''});
  assert.deepEqual(foreign.spec.containers[0].command, ['/bin/sh']);
});

test('I/O-pressure fails closed before Pod creation without a chart-owned image', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = ioPressureCampaign();
  api.put('faultcampaigns', value);
  const probes = {probe: async target => ({observation: {
    actor: target.actor, probe: 'io', status: 'ok', probeName: 'fsync-pressure',
    path: `/data/.attacknet-probe-${target.actor}/pressure.dat`, operation: 'FSYNC',
    attempts: 5, successes: 5, errorCounts: {}, latencyMsP50: 1, latencyMsP95: 2,
    contentDigest: 'sha256:content', attributesDigest: 'sha256:attributes',
  }})};
  const reconciler = new FaultCampaignReconciler(api, probes, new FakeSignerSets(), {
    ioPressureImage: '', ioPressureImagePullPolicy: 'IfNotPresent',
  });
  await reconciler.reconcile(await api.get('faultcampaigns', value.metadata.name));
  const failed = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(failed.status.phase, 'Failed');
  assert.equal(failed.status.reason, 'FaultCapabilityUnavailable');
  assert.equal(await api.get('pods', 'io-pressure-pressure-signer-disk', {
    group: '', allow404: true,
  }), null);
});

test('I/O-pressure refuses a target without an exact /data persistent claim', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  const targetPod = pod('signer-1', 'signer');
  targetPod.spec.volumes = [];
  api.pods = [targetPod];
  const value = ioPressureCampaign();
  api.put('faultcampaigns', value);
  const probes = {probe: async target => ({observation: {
    actor: target.actor, probe: 'io', status: 'ok', probeName: 'fsync-pressure',
    path: `/data/.attacknet-probe-${target.actor}/pressure.dat`, operation: 'FSYNC',
    attempts: 5, successes: 5, errorCounts: {}, latencyMsP50: 1, latencyMsP95: 2,
    contentDigest: 'sha256:content', attributesDigest: 'sha256:attributes',
  }})};
  const reconciler = faultReconciler(api, probes);
  await reconciler.reconcile(await api.get('faultcampaigns', value.metadata.name));
  const admitted = await api.get('faultcampaigns', value.metadata.name);
  await assert.rejects(
    () => reconciler.reconcile(admitted),
    /does not mount a persistent data claim/,
  );
  assert.equal(await api.get('pods', 'io-pressure-pressure-signer-disk', {
    group: '', allow404: true,
  }), null);
});

test('partial injection fails immediately with daemon evidence instead of timing out', async () => {
  const api = new FakeApi();
  api.put('stacksnetworks', network());
  api.pods = [pod('signer-1', 'signer')];
  const value = networkCampaign();
  api.put('faultcampaigns', value);
  const probes = {probe: async (target, request) => ({observation: {
    actor: target.actor, probe: 'network', status: 'ok',
    probeName: `${request.peer}-${request.port}`, peerActor: request.peer,
    attempts: 5, successes: 5, latencyMsP50: 10, latencyMsP95: 10,
    protocolErrors: 0, throughputBytesPerSecond: null,
  }})};
  const reconciler = faultReconciler(api, probes);

  let current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  const chaos = await api.get('networkchaos', value.metadata.name, {group: 'chaos-mesh.org'});
  chaos.status = {
    conditions: [
      {type: 'AllInjected', status: 'False'},
      {type: 'AllRecovered', status: 'True'},
    ],
    experiment: {containerRecords: [{events: [{type: 'Failed', message: 'injection refused'}]}]},
  };
  api.put('networkchaos', chaos, 'chaos-mesh.org');

  await reconciler.reconcile(current);
  current = await api.get('faultcampaigns', value.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'InjectionFailed');
  assert.match(current.status.message, /injection refused/);
  assert.equal(current.status.actualInjection.allInjectedObserved, false);
  assert.equal(current.status.cleanup.allRecovered, true);
  assert.equal(current.status.cleanup.absent, true);
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
  const reconciler = faultReconciler(api, {probe: async () => { calls += 1; }});

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
  await runReconciler(api).reconcile(run, [source]);
  let updated = await api.get('attacknetruns', 'run-a');
  assert.equal(updated.status.phase, 'Preparing');
  assert.match(updated.status.scheduleRef.digest, /^sha256:[0-9a-f]{64}$/);
  await runReconciler(api).reconcile(updated, [source]);
  updated = await api.get('attacknetruns', 'run-a');
  assert.equal(updated.status.phase, 'Running');
  const child = await api.get('faultcampaigns', updated.status.activeCampaign);
  assert.equal(child.spec.template, false);
  assert.equal(child.metadata.ownerReferences[0].uid, run.metadata.uid);
  assert.equal(child.metadata.annotations['testing.stacks.org/source-template-uid'], source.metadata.uid);
  assert.equal(child.metadata.annotations['testing.stacks.org/source-template-digest'], artifactDigest(source.spec));
});

test('AttacknetRun seals canonical cycle weights into its safety budget', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source);
  api.put('attacknetruns', run);
  const signerSets = new FakeSignerSets({weights: {
    [signerKey(1)]: 1, [signerKey(2)]: 4, [signerKey(3)]: 4,
  }});
  await runReconciler(api, signerSets).reconcile(run, [source]);
  const current = await api.get('attacknetruns', run.metadata.name);
  const scheduleMap = await api.get('configmaps', current.status.scheduleRef.name, {group: ''});
  const schedule = decodeSchedule(scheduleMap);
  assert.equal(current.status.scheduleSummary.signerSetTotalWeight, 9);
  assert.equal(schedule.actions[0].budgetCharge.signerImpactPercent, 100 / 9);
  assert.equal(schedule.budgets.usage.maximumSignerImpactPercent, 100 / 9);
});

test('AttacknetRun refuses injection if the pinned canonical signer set changes', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source);
  api.put('attacknetruns', run);
  let calls = 0;
  const signerSets = {
    async resolve(_network, _pods, manifest) {
      calls += 1;
      const weights = calls === 1
        ? {[signerKey(1)]: 1, [signerKey(2)]: 2, [signerKey(3)]: 3}
        : {[signerKey(1)]: 1, [signerKey(2)]: 2, [signerKey(3)]: 2};
      return new FakeSignerSets({
        weights, digest: `sha256:${(calls === 1 ? 'b' : 'c').repeat(64)}`,
      }).resolve(_network, _pods, manifest);
    },
  };
  const reconciler = runReconciler(api, signerSets);
  await reconciler.reconcile(run, [source]);
  let current = await api.get('attacknetruns', run.metadata.name);
  await reconciler.reconcile(current, [source]);
  current = await api.get('attacknetruns', run.metadata.name);
  assert.equal(current.status.phase, 'Failed');
  assert.equal(current.status.reason, 'SignerSetChangedBeforeCampaign');
  assert.equal((await api.list('faultcampaigns')).items.length, 1);
});

test('an active run remains Running while its admitted fault makes the network unready', async () => {
  const api = new FakeApi();
  const source = campaign({template: true, effect: false});
  const admitted = network();
  api.put('stacksnetworks', admitted);
  api.pods = networkPods(admitted);
  api.put('faultcampaigns', source);
  const run = attacknetRun(source);
  api.put('attacknetruns', run);
  const reconciler = runReconciler(api);

  await reconciler.reconcile(run, [source]);
  let current = await api.get('attacknetruns', run.metadata.name);
  await reconciler.reconcile(current, [source]);
  current = await api.get('attacknetruns', run.metadata.name);
  const child = await api.get('faultcampaigns', current.status.activeCampaign);
  child.status = {phase: 'Active', reason: 'AllInjectedObserved'};
  api.put('faultcampaigns', child);
  admitted.status.phase = 'Degraded';
  api.put('stacksnetworks', admitted);

  await reconciler.reconcile(current, [source, child]);
  current = await api.get('attacknetruns', run.metadata.name);
  assert.equal(current.status.phase, 'Running');
  assert.equal(current.status.reason, 'CampaignActive');
  assert.equal(current.status.activeCampaign, child.metadata.name);
  assert.equal(current.status.budgetUsage.activeFaults, 1);
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
  await runReconciler(api).reconcile(run, [source]);
  let updated = await api.get('attacknetruns', run.metadata.name);
  await runReconciler(api).reconcile(updated, [source]);
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
  const reconciler = runReconciler(api);
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
  const reconciler = runReconciler(api);
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
  const reconciler = runReconciler(api);
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
  await faultReconciler(api).reconcile(value);
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
    recoveryResults: [{actor: 'signer-1', assertion: 'NetworkRecovered', outcome: 'Proven'}],
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
