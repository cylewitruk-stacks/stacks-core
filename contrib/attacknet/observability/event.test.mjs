import assert from 'node:assert/strict';
import test from 'node:test';

import {buildEvent, runCli} from './event.mjs';

test('event builder records orchestrator occurrence time and structured details', () => {
  const event = buildEvent({
    kind: 'fault.injected', network: 'attacknet', runId: 'run-1', phase: 'fault-active',
    campaign: 'partition-a', actor: 'miner-2', faultType: 'NetworkChaos',
    details: {instruction: 4},
  }, () => '2026-08-15T00:00:00.000Z');
  assert.deepEqual(event, {
    kind: 'fault.injected', network: 'attacknet', runId: 'run-1', phase: 'fault-active',
    occurredAt: '2026-08-15T00:00:00.000Z', campaign: 'partition-a', actor: 'miner-2',
    faultType: 'NetworkChaos', details: {instruction: 4},
  });
});

test('CLI requires identity fields and parses detail JSON', () => {
  const event = runCli([
    '--kind=invariant.observed', '--network=attacknet', '--run-id=run-1',
    '--phase=verification', '--details={"name":"chain-progress","passed":false}',
  ]);
  assert.deepEqual(event.details, {name: 'chain-progress', passed: false});
  assert.throws(() => runCli(['--kind=note', '--network=attacknet']), /runId is required/);
  assert.throws(() => runCli([
    '--kind=note', '--network=attacknet', '--run-id=run-1', '--details=[]',
  ]), /JSON object/);
});

test('oversized composed event IDs are deterministically bounded for idempotency', () => {
  const oversized = `run-${'r'.repeat(80)}-campaign-${'c'.repeat(80)}-injected`;
  const first = buildEvent({kind: 'note', network: 'attacknet', runId: 'run-1', eventId: oversized});
  const second = buildEvent({kind: 'note', network: 'attacknet', runId: 'run-1', eventId: oversized});
  assert.equal(first.eventId.length, 128);
  assert.equal(first.eventId, second.eventId);
  assert.match(first.eventId, /-[0-9a-f]{24}$/);
});
