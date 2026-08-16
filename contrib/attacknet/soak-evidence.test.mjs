import assert from 'node:assert/strict';
import test from 'node:test';

import {completeSoakContract, createSoakContract} from './soak-evidence.mjs';

function cohort(height, stacks = 302) {
  return {
    ok: true,
    burnDrift: 0,
    stacksDrift: 0,
    forkedHeights: [],
    rows: [
      {actor: 'miner-1', burnHeight: height, stacksHeight: stacks, stacksTip: '00'},
      {actor: 'follower-1', burnHeight: height, stacksHeight: stacks, stacksTip: '00'},
    ],
  };
}

test('derives the target from the first real paused sample', () => {
  const contract = createSoakContract({
    network: 'attacknet', startedAt: '2026-08-16T00:00:00Z',
    minimumNewBurnBlocks: 300, bitcoinHeight: 503, cohort: cohort(503),
    faultRunName: 'verified-soak',
  });
  assert.equal(contract.startHeight, 503);
  assert.equal(contract.firstSampleHeight, 503);
  assert.equal(contract.targetHeight, 803);
  const result = completeSoakContract(contract, {
    completedAt: '2026-08-16T01:00:00Z', bitcoinHeight: 803,
    cohort: cohort(803, 602), sampleCount: 61, faultRunPhase: 'Passed',
  });
  assert.equal(result.status, 'passed');
  assert.equal(result.observedNewBurnBlocks, 300);
});

test('rejects a start cohort not caught up to the paused Bitcoin height', () => {
  const stale = cohort(502);
  assert.throws(() => createSoakContract({
    network: 'attacknet', startedAt: '2026-08-16T00:00:00Z',
    minimumNewBurnBlocks: 300, bitcoinHeight: 503, cohort: stale,
  }), /does not equal Bitcoin height/);
});

test('does not pass without the full observed interval and deterministic fault run', () => {
  const contract = createSoakContract({
    network: 'attacknet', startedAt: '2026-08-16T00:00:00Z',
    minimumNewBurnBlocks: 300, bitcoinHeight: 503, cohort: cohort(503), faultRunName: 'faults',
  });
  assert.throws(() => completeSoakContract(contract, {
    completedAt: '2026-08-16T01:00:00Z', bitcoinHeight: 802,
    cohort: cohort(802), sampleCount: 61, faultRunPhase: 'Passed',
  }), /only 299/);
  assert.throws(() => completeSoakContract(contract, {
    completedAt: '2026-08-16T01:00:00Z', bitcoinHeight: 803,
    cohort: cohort(803), sampleCount: 61, faultRunPhase: 'Inconclusive',
  }), /finished as Inconclusive/);
});
