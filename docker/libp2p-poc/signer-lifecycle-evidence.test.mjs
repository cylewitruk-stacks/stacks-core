import assert from 'node:assert/strict';
import test from 'node:test';

import {evaluateSignerLifecycle} from './signer-lifecycle-evidence.mjs';

function fixture({suffix = '', generation = 10, admitted, pending = 0, released = 0, expired = 0}) {
  const resolved = {
    released,
    expired,
    unauthorized: 0,
    redundant: 0,
    binding_failed: 0,
    malformed: 0,
  };
  return [
    `stacks_signer_native_network_generation_start_timestamp_seconds ${generation}`,
    `stacks_signer_deferred_miner_authorizations_admitted${suffix} ${admitted}`,
    `stacks_signer_deferred_miner_authorizations_pending ${pending}`,
    ...Object.entries(resolved).map(([resolution, value]) =>
      `stacks_signer_deferred_miner_authorizations_resolved${suffix}{resolution="${resolution}"} ${value}`),
    `stacks_signer_deferred_miner_authorization_observations${suffix}{observation="delivered"} ${admitted}`,
    `stacks_signer_block_policy_rejections${suffix}{reject_code="1"} 0`,
  ].join('\n');
}

test('accepts the unsuffixed Prometheus counters exported by the signer', () => {
  const result = evaluateSignerLifecycle(
    fixture({admitted: 1, released: 1}),
    fixture({admitted: 3, released: 2, expired: 1}),
  );
  assert.deepEqual(result.failures, []);
  assert.equal(result.outcomes.released, 2);
});

test('also accepts OTLP-normalized total counter names', () => {
  const result = evaluateSignerLifecycle(
    fixture({suffix: '_total', admitted: 0}),
    fixture({suffix: '_total', admitted: 2, released: 1, pending: 1}),
  );
  assert.deepEqual(result.failures, []);
});

test('rejects process-stable counter resets under either naming convention', () => {
  const result = evaluateSignerLifecycle(
    fixture({admitted: 2, released: 2}),
    fixture({suffix: '_total', admitted: 1, released: 1}),
  );
  assert.match(result.failures.join(', '), /reset 2->1/);
});

test('rejects non-conserved signer lifecycle accounting', () => {
  const result = evaluateSignerLifecycle(
    fixture({admitted: 0}),
    fixture({admitted: 3, released: 1}),
  );
  assert.match(result.failures.join(', '), /conservation failed admitted=3 pending=0 resolved=1/);
});
