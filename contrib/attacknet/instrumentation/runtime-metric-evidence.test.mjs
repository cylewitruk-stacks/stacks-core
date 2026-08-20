import assert from 'node:assert/strict';
import test from 'node:test';

import {buildRuntimeMetricEvidence, metricFamilies} from './runtime-metric-evidence.mjs';

const inventory = {families: [
  {family: 'stacks_signer_ready', type: 'gauge'},
  {family: 'stacks_signer_events', type: 'counter'},
  {family: 'stacks_signer_latency_seconds', type: 'histogram'},
]};

test('runtime evidence recognizes gauges, counter totals, and histogram components', () => {
  const metrics = '# TYPE stacks_signer_ready gauge\nstacks_signer_ready 1\nstacks_signer_events_total 2\nstacks_signer_latency_seconds_bucket{le="1"} 3\n';
  assert(metricFamilies(metrics).has('stacks_signer_ready'));
  const evidence = buildRuntimeMetricEvidence({
    actor: 'signer-1', role: 'signer', podUID: 'pod', runtimeImageID: 'sha256:a', inventory,
    requiredFamilies: inventory.families.map(item => item.family), metrics, collectedAt: '2026-08-18T00:00:00Z',
  });
  assert.equal(evidence.result, 'Passed');
  assert.deepEqual(evidence.missingFamilies, []);
});

test('admission identity cannot substitute for an absent metric family', () => {
  const evidence = buildRuntimeMetricEvidence({
    actor: 'signer-1', role: 'signer', podUID: 'pod', runtimeImageID: 'sha256:a', inventory,
    requiredFamilies: ['stacks_signer_ready'], metrics: 'up 1\n', collectedAt: '2026-08-18T00:00:00Z',
  });
  assert.equal(evidence.result, 'Failed');
  assert.deepEqual(evidence.missingFamilies, ['stacks_signer_ready']);
});
