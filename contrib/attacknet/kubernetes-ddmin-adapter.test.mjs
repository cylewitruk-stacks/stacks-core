import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createDdminPlan, issueDdminAttempt, resolveAttacknetSchedule,
} from './attacknet-run-schedule.mjs';
import {KubernetesDdminAdapter} from './kubernetes-ddmin-adapter.mjs';

const resolvedDigest = `sha256:${'a'.repeat(64)}`;

function fixture() {
  const campaigns = ['one', 'two'].map(name => ({
    metadata: {name: `template-${name}`, uid: `uid-${name}`, generation: 1},
    spec: {
      template: true, networkRef: 'attacknet', target: {actors: ['signer-1']},
      fault: {type: 'pod', action: 'pod-kill', mode: 'all', duration: '1s', parameters: {}},
      safety: {maxUnavailableSignerPercent: 30, maxUnavailableMinerPercent: 50},
    },
  }));
  const spec = {
    networkRef: 'attacknet', seed: 'seed',
    campaignCatalog: campaigns.map((campaign, index) => ({
      name: `campaign-${index + 1}`, campaignRef: campaign.metadata.name,
    })),
    sequence: campaigns.map((campaign, index) => ({
      id: `step-${index + 1}`, campaign: `campaign-${index + 1}`, delayAfterSeconds: 0,
    })),
    budgets: {
      maxCampaigns: 2, maxWallTimeSeconds: 60, maxCumulativeFaultSeconds: 10,
      maxActiveFaults: 1, maxSignerImpactPercent: 30, maxBurnchainFaults: 0,
      maxInconclusiveCampaigns: 1,
    },
    stopPolicy: {
      onCampaignFailure: 'Stop', onInconclusive: 'Stop',
      onBudgetExhausted: 'Stop', onSuccess: 'Continue',
    },
    attributionPolicy: {
      requiredOnFailure: true, requireIncidentBundle: true,
      allowedTerminalStates: ['Inconclusive'],
    },
    replay: {enabled: false, requireSameResolvedImages: true, verifyExpectedFailure: true},
    resume: {enabled: false, requireSameSeed: true, requireSameResolvedImages: true},
    minimization: {enabled: false, strategy: 'DeltaDebug', maxAttempts: 0, requireFreshNetwork: true},
  };
  const sourceRun = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'AttacknetRun',
    metadata: {name: 'source-run', namespace: 'hacknet-system', uid: 'uid-source-run', generation: 1},
    spec,
  };
  const schedule = resolveAttacknetSchedule(sourceRun, {
    network: {uid: 'uid-source-network', generation: 1},
    manifest: {network: 'attacknet', namespace: 'hacknet-system', actors: [
      {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1},
      {service: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 1},
      {service: 'signer-3', role: 'signer', signerIndex: 3, signerWeight: 1},
      {service: 'signer-4', role: 'signer', signerIndex: 4, signerWeight: 1},
    ]},
    campaigns,
    images: [{scope: 'signer-1', requestedRef: 'stacks:test',
      resolvedRef: `stacks@${resolvedDigest}`, resolvedDigest}],
  });
  const issued = issueDdminAttempt(createDdminPlan(schedule, {
    requireFreshNetwork: true, maxAttempts: 2,
    expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
  }));
  return {sourceRun, schedule, attempt: issued.attempt};
}

class FakeRunner {
  constructor() { this.calls = []; this.created = null; }
  run(command, args, options = {}) {
    this.calls.push({command, args: [...args], input: options.input});
    if (args.includes('create')) {
      this.created = JSON.parse(options.input);
      return {status: 0, stdout: JSON.stringify({
        ...this.created, metadata: {...this.created.metadata, uid: 'uid-attempt-run'},
      }), stderr: ''};
    }
    if (args.includes('get') && args.includes('attacknetrun')) {
      return {status: 0, stdout: JSON.stringify({
        ...this.created,
        metadata: {...this.created.metadata, uid: 'uid-attempt-run'},
        status: {phase: 'Preparing', scheduleRef: {digest: `sha256:${'b'.repeat(64)}`}},
      }), stderr: ''};
    }
    if (command === 'sleep') return {status: 0, stdout: '', stderr: ''};
    throw new Error(`unexpected fake command: ${command} ${args.join(' ')}`);
  }
}

test('Kubernetes adapter submits only a constrained AttacknetRun ddmin reduction', async () => {
  const {sourceRun, schedule, attempt} = fixture();
  const runner = new FakeRunner();
  const adapter = new KubernetesDdminAdapter({
    namespace: 'hacknet-system', network: 'attacknet', sourceRunRef: 'source-run',
    generatedDirectory: '/tmp/generated', attacknetDirectory: '/tmp/attacknet',
    kubectl: '/tmp/agent-controlled-command',
  }, runner);
  assert.equal(adapter.kubectl, 'kubectl');
  assert.notEqual(adapter.attacknetDirectory, '/tmp/attacknet');
  adapter.sourceRun = sourceRun;
  adapter.sourceSchedule = schedule;
  const result = await adapter.submitRun({attempt, admitted: {uid: 'uid-fresh-network'}});
  assert.equal(result.candidateScheduleDigest, attempt.schedule.integrity.digest);
  assert.equal(runner.created.kind, 'AttacknetRun');
  assert.equal(runner.created.spec.minimization.sourceScheduleDigest, schedule.integrity.digest);
  assert.equal(runner.created.spec.minimization.candidateScheduleDigest, attempt.schedule.integrity.digest);
  assert.equal(runner.created.spec.minimization.retained.length, 1);
  assert.equal(runner.created.spec.replay.enabled, false);
  assert.equal(runner.created.spec.resume.enabled, false);
  assert.equal(runner.calls.some(call => /chaos/i.test(call.args.join(' '))), false);
  assert.equal(runner.calls.some(call => call.args.includes('faultcampaign')), false);

  const replayAttempt = {...attempt, id: 'replay-baseline', schedule,
    expectedFailure: {assertion: 'TargetReady', status: 'Failed'}};
  const replay = await adapter.submitReplay({attempt: replayAttempt,
    admitted: {uid: 'uid-fresh-replay'}});
  assert.equal(replay.candidateScheduleDigest, schedule.integrity.digest);
  assert.equal(runner.created.spec.replay.enabled, true);
  assert.equal(runner.created.spec.replay.attemptId, 'replay-baseline');
  assert.equal(runner.created.spec.minimization.enabled, false);
});

test('Kubernetes adapter refuses to overlap even one existing active run', () => {
  const runner = {run: () => ({status: 0, stderr: '', stdout: JSON.stringify({items: [{
    metadata: {name: 'already-running'}, status: {phase: 'Running'},
  }]})})};
  const adapter = new KubernetesDdminAdapter({
    namespace: 'hacknet-system', network: 'attacknet', sourceRunRef: 'source-run',
    generatedDirectory: '/tmp/generated', attacknetDirectory: '/tmp/attacknet',
  }, runner);
  assert.throws(() => adapter.assertExclusive({maxActive: 1}), /second active AttacknetRun/);
});
