import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const attacknet = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const repository = resolve(attacknet, '..', '..');
const patch = join(attacknet, 'test', 'fixtures', 'adversaries', 'deterministic-signer.patch');

test('bounded signer fixture applies cleanly and remains compile-time isolated', () => {
  execFileSync('git', ['-C', repository, 'apply', '--check', patch]);
  const source = readFileSync(patch, 'utf8');
  const changedFiles = [...source.matchAll(/^diff --git a\/(.+?) b\/(.+)$/gm)]
    .map(([, from, to]) => ({from, to}));
  assert.deepEqual(changedFiles.map(item => item.from).sort(), [
    'stacks-signer/src/lib.rs',
    'stacks-signer/src/monitoring/mod.rs',
    'stacks-signer/src/monitoring/prometheus.rs',
    'stacks-signer/src/v0/signer.rs',
  ]);
  assert.deepEqual(changedFiles.map(item => item.to).sort(), changedFiles.map(item => item.from).sort());
  assert.match(source, /#\[cfg\(feature = "testing"\)\]/);
  assert.match(source, /stacks-signer-testing\/v1/);
  assert.match(source, /stacks-signer-adversarial-selector\/v1/);
  assert.match(source, /"withhold" \| "delay" \| "suppress-peer-responses"/);
  assert.match(source, /stacks_signer_attacknet_policy_matches_total/);
  assert.match(source, /stacks_signer_attacknet_policy_evaluations/);
  assert.match(source, /deny_unknown_fields/);
  assert.match(source, /max_evaluations/);
  assert.match(source, /65_536/);
  assert.match(source, /attacknet_response_delay_with/);
  assert.match(
    source,
    /initialize_attacknet_policy_observation\(\);[\s\S]*start_serving_monitoring_metrics/,
  );
  assert.match(source, /ATTACKNET_POLICY_OBSERVATION_STARTED: OnceLock/);
  assert.match(source, /start_attacknet_session_monitor/);
  assert.match(source, /Duration::from_millis\(500\)/);
  assert.doesNotMatch(source, /TEST_REJECT_ALL_BLOCK_PROPOSAL/);
});
