import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {executeDdmin, evidenceDigestFor} from './ddmin-executor.mjs';
import {resolveAttacknetSchedule} from './attacknet-run-schedule.mjs';
import {sha256Value} from './run-descriptor.mjs';

const imageDigest = `sha256:${'a'.repeat(64)}`;

function fixture() {
  const campaigns = ['one', 'two'].map((name, index) => ({
    metadata: {name: `template-${name}`, uid: `uid-${name}`, generation: 1},
    spec: {
      template: true, networkRef: 'attacknet', target: {actors: [`miner-${index + 1}`]},
      fault: {type: 'pod', action: 'pod-kill', mode: 'all', duration: '1s', parameters: {}},
      safety: {maxUnavailableSignerPercent: 30, maxUnavailableMinerPercent: 50},
    },
  }));
  const run = {
    metadata: {name: 'source'},
    spec: {
      networkRef: 'attacknet', seed: 'seed',
      campaignCatalog: campaigns.map((campaign, index) => ({
        name: `c${index + 1}`, campaignRef: campaign.metadata.name,
      })),
      sequence: campaigns.map((campaign, index) => ({id: `step-${index + 1}`, campaign: `c${index + 1}`})),
      budgets: {
        maxCampaigns: 4, maxWallTimeSeconds: 60, maxCumulativeFaultSeconds: 10,
        maxActiveFaults: 1, maxSignerImpactPercent: 30, maxBurnchainFaults: 0,
        maxInconclusiveCampaigns: 1,
      },
    },
  };
  const context = {
    network: {uid: 'source-network', generation: 1},
    manifest: {network: 'attacknet', namespace: 'hacknet-system', actors: [
      {service: 'miner-1', role: 'miner'}, {service: 'miner-2', role: 'miner'},
      {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1},
    ]},
    campaigns,
    images: [{scope: 'actors', requestedRef: 'stacks:test',
      resolvedRef: `stacks@${imageDigest}`, resolvedDigest: imageDigest}],
  };
  return resolveAttacknetSchedule(run, context);
}

class FakeAdapter {
  constructor(outcomes = []) {
    this.outcomes = [...outcomes];
    this.events = [];
    this.network = 0;
  }
  async storagePreflight() {
    this.events.push('storage');
    return {ok: true, evidenceDigest: `sha256:${'b'.repeat(64)}`};
  }
  async assertExclusive({maxActive}) {
    assert.equal(maxActive, 1);
    this.events.push('exclusive');
  }
  async recreateNetwork({attempt, contract}) {
    this.network += 1;
    this.events.push(`recreate:${attempt.id}`);
    return {
      uid: `fresh-${this.network}`, generation: 1, cleanStart: true,
      logicalNetworkName: contract.logicalNetworkName,
      manifestDigest: contract.manifestDigest,
      imagesDigest: contract.imagesDigest,
      sourceTemplatesDigest: contract.sourceTemplatesDigest,
    };
  }
  async submitRun({attempt}) {
    this.events.push(`submit:${attempt.id}`);
    return {
      name: `run-${attempt.id}`, uid: `run-uid-${attempt.id}`,
      scheduleDigest: `sha256:${'d'.repeat(64)}`,
      candidateScheduleDigest: attempt.schedule.integrity.digest,
    };
  }
  async submitReplay({attempt}) {
    this.events.push(`submit-replay:${attempt.id}`);
    return {
      name: `run-${attempt.id}`, uid: `run-uid-${attempt.id}`,
      scheduleDigest: `sha256:${'d'.repeat(64)}`,
      candidateScheduleDigest: attempt.schedule.integrity.digest,
    };
  }
  async waitForRun({attempt}) {
    this.events.push(`wait:${attempt.id}`);
    return {status: {phase: 'Passed'}};
  }
  async exportEvidence({attempt}) {
    const outcome = this.outcomes.shift() ?? 'FailureAbsent';
    this.events.push(`export:${attempt.id}`);
    const verdict = outcome === 'FailureReproduced'
      ? {expectedFailureObserved: true, assertionEvaluated: true, experimentCompleted: true,
          assertion: 'TargetReady', status: 'Failed'}
      : outcome === 'FailureAbsent'
        ? {expectedFailureObserved: false, assertionEvaluated: true, experimentCompleted: true}
        : {expectedFailureObserved: null, assertionEvaluated: false, experimentCompleted: false,
            reason: 'another failure'};
    return {
      evidenceExported: true,
      evidenceDigest: evidenceDigestFor({attempt: attempt.id, outcome}),
      evidenceURI: `file:///evidence/${attempt.id}.json`, verdict,
    };
  }
  async deleteAttemptNetwork({attempt}) { this.events.push(`delete:${attempt.id}`); }
  async preserveForTriage({attempt}) { this.events.push(`preserve:${attempt.id}`); }
}

test('executor serializes fresh counterfactuals and exports durable evidence before deletion', async () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-ddmin-'));
  const adapter = new FakeAdapter(['FailureReproduced', 'FailureAbsent', 'FailureAbsent']);
  const result = await executeDdmin({
    schedule: fixture(), expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
    maxAttempts: 2, evidenceDirectory: root,
    startedAt: '2026-01-01T00:00:00.000Z', completedAt: '2026-01-01T00:01:00.000Z',
  }, adapter);
  assert.equal(result.phase, 'Complete');
  assert.equal(result.maxActive, 1);
  assert.equal(result.baselineReplay.outcome, 'FailureReproduced');
  const baselineId = result.baselineReplay.id;
  assert.ok(adapter.events.indexOf(`export:${baselineId}`) < adapter.events.indexOf(`delete:${baselineId}`));
  assert.equal(result.attempts.length, 2);
  assert.notEqual(result.attempts[0].networkUID, result.attempts[1].networkUID);
  for (const attempt of result.attempts) {
    assert.ok(adapter.events.indexOf(`export:${attempt.id}`) < adapter.events.indexOf(`delete:${attempt.id}`));
    assert.ok(existsSync(join(root, 'attempts', attempt.id, 'evidence-receipt.json')) === false);
  }
  const persisted = JSON.parse(readFileSync(join(root, 'execution.json'), 'utf8'));
  assert.equal(persisted.integrity.digest, result.integrity.digest);
});

test('executor refuses to minimize a source failure that is absent on fresh replay', async () => {
  const adapter = new FakeAdapter(['FailureAbsent']);
  const result = await executeDdmin({
    schedule: fixture(), expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
    maxAttempts: 3, evidenceDirectory: mkdtempSync(join(tmpdir(), 'attacknet-ddmin-absent-')),
  }, adapter);
  assert.equal(result.phase, 'PausedForTriage');
  assert.equal(result.result.outcome, 'FailureAbsent');
  assert.equal(result.result.reason, 'SourceFailureDidNotReproduceOnFreshNetwork');
  assert.equal(result.attempts.length, 0);
  assert.equal(adapter.events.some(event => event.startsWith('submit:')), false);
  assert.equal(adapter.events.some(event => event.startsWith('delete:')), false);
  assert.ok(adapter.events.some(event => event.startsWith('preserve:')));
});

test('executor fails closed before mutation when storage is unavailable', async () => {
  const adapter = new FakeAdapter();
  adapter.storagePreflight = async () => ({ok: false, reason: 'zero bytes available'});
  await assert.rejects(() => executeDdmin({
    schedule: fixture(), expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
    maxAttempts: 1, evidenceDirectory: mkdtempSync(join(tmpdir(), 'attacknet-ddmin-storage-')),
  }, adapter), /storage preflight failed closed/);
  assert.deepEqual(adapter.events, []);
});

test('executor preserves an inconclusive network and never treats ambiguity as absence', async () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-ddmin-inc-'));
  const adapter = new FakeAdapter(['Inconclusive']);
  const result = await executeDdmin({
    schedule: fixture(), expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
    maxAttempts: 3, evidenceDirectory: root,
  }, adapter);
  assert.equal(result.phase, 'PausedForTriage');
  assert.equal(result.result.outcome, 'Inconclusive');
  assert.ok(adapter.events.some(event => event.startsWith('preserve:')));
  assert.equal(adapter.events.some(event => event.startsWith('delete:')), false);
  assert.ok(existsSync(join(root, 'attempts', result.result.preservedAttempt,
    'PRESERVED-FOR-TRIAGE.json')) === false);
});

test('admission drift pauses and preserves rather than executing or cleaning up', async () => {
  const adapter = new FakeAdapter();
  adapter.recreateNetwork = async ({contract}) => ({
    uid: 'fresh-drift', cleanStart: true, logicalNetworkName: contract.logicalNetworkName,
    manifestDigest: contract.manifestDigest, imagesDigest: `sha256:${'e'.repeat(64)}`,
    sourceTemplatesDigest: contract.sourceTemplatesDigest,
  });
  const result = await executeDdmin({
    schedule: fixture(), expectedFailure: {assertion: 'TargetReady', status: 'Failed'},
    maxAttempts: 1, evidenceDirectory: mkdtempSync(join(tmpdir(), 'attacknet-ddmin-drift-')),
  }, adapter);
  assert.equal(result.phase, 'PausedForTriage');
  assert.match(result.result.reason, /admitted images/);
  assert.equal(adapter.events.some(event => event.startsWith('submit:')), false);
  assert.equal(adapter.events.some(event => event.startsWith('delete:')), false);
});
