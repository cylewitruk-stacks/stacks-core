import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

import {resolveProgressWindow} from './progress-window.mjs';

test('default window exceeds one configured burn interval with bounded jitter margin', () => {
  assert.equal(resolveProgressWindow({protocol: {steadyBurnIntervalSeconds: 60}}), 75);
  assert.equal(resolveProgressWindow({protocol: {steadyBurnIntervalSeconds: 20}}), 35);
  assert.equal(resolveProgressWindow({protocol: {steadyBurnIntervalSeconds: 100}}), 125);
});

test('explicit bounded override wins and malformed cadence fails closed', () => {
  assert.equal(resolveProgressWindow({protocol: {steadyBurnIntervalSeconds: 60}}, '90'), 90);
  assert.throws(() => resolveProgressWindow({protocol: {steadyBurnIntervalSeconds: 60}}, '0'), /1 through 7200/);
  assert.throws(() => resolveProgressWindow({protocol: {}}), /steadyBurnIntervalSeconds/);
});

test('campaign recovery derives its default from the manifest cadence', () => {
  const source = readFileSync(new URL('./campaign-runner.sh', import.meta.url), 'utf8');
  assert.match(source, /progress-window\.mjs/);
  assert.match(source, /ATTACKNET_PROGRESS_WINDOW_SECONDS="\$\{post_chaos_progress_window\}"/);
  assert.doesNotMatch(source, /ATTACKNET_POST_CHAOS_PROGRESS_SECONDS:-45/);
  assert.match(source, /post-chaos-progress-window\.json/);
});
