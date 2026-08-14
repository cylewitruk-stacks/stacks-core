import assert from 'node:assert/strict';
import test from 'node:test';

import {heightCohort, progress} from './invariants.mjs';

test('height cohort accepts bounded lag and reports both dimensions', () => {
  const result = heightCohort([
    {actor: 'miner-1', info: {burn_block_height: 250, stacks_tip_height: 10, stacks_tip: 'a'}},
    {actor: 'follower-1', info: {burn_block_height: 249, stacks_tip_height: 9, stacks_tip: 'b'}},
  ], 2);
  assert.equal(result.ok, true);
  assert.equal(result.burnDrift, 1);
  assert.equal(result.stacksDrift, 1);
});

test('height cohort fails rather than hiding excessive drift', () => {
  assert.equal(heightCohort([
    {actor: 'miner-1', info: {burn_block_height: 250, stacks_tip_height: 10}},
    {actor: 'follower-1', info: {burn_block_height: 246, stacks_tip_height: 7}},
  ], 2).ok, false);
});

test('progress requires the configured burn-block delta', () => {
  assert.equal(progress({burnHeight: 20}, {burnHeight: 22}, 2).ok, true);
  assert.equal(progress({burnHeight: 20}, {burnHeight: 21}, 2).ok, false);
});
