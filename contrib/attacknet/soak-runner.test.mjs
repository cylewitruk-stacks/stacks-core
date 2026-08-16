import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync, statSync} from 'node:fs';
import test from 'node:test';

const path = new URL('./soak-runner.sh', import.meta.url).pathname;

test('measured soak runner is executable and documents its evidence boundary', () => {
  assert.notEqual(statSync(path).mode & 0o111, 0);
  const result = spawnSync(path, ['--help'], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /first exact paused cohort/);
  assert.match(result.stdout, /MINIMUM_NEW_BURN_BLOCKS/);
});

test('target comes from the measured contract rather than a hard-coded height', () => {
  const source = readFileSync(path, 'utf8');
  assert.match(source, /soak-evidence\.mjs" start/);
  assert.match(source, /targetHeight/);
  assert.doesNotMatch(source, /target_height=[0-9]/);
  assert.match(source, /environment-assert/);
  assert.match(source, /burnchain-policy\.sh/);
  assert.match(source, /start-signer-metrics/);
  assert.match(source, /end-signer-metrics/);
  assert.match(source, /signer-metric-deltas\.mjs/);
  assert.match(source, /run-ledger\.mjs" append/);
  assert.match(source, /record-event\.sh/);
  assert.match(source, /assertion:\s*"measured-soak"/);
});
