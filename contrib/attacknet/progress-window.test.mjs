import assert from 'node:assert/strict';
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
