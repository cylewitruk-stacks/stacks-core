import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {summarizeSignerMetricDeltas} from './signer-metric-deltas.mjs';

const names = [
  'stacks_signer_block_proposals_received',
  'stacks_signer_block_responses_sent{response_type="accepted"}',
  'stacks_signer_block_responses_sent{response_type="rejected"}',
  'stacks_signer_block_validation_responses{response_type="accepted"}',
  'stacks_signer_block_validation_responses{response_type="rejected"}',
];

function fixture(directory, actor, values) {
  writeFileSync(join(directory, `${actor}.txt`), `${names.map((name, index) => `${name} ${values[index]}`).join('\n')}\n`);
}

test('reports window deltas instead of mistaking cumulative rejection counters for soak events', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-signer-deltas-'));
  const start = join(root, 'start');
  const end = join(root, 'end');
  mkdirSync(start);
  mkdirSync(end);
  fixture(start, 'signer-1', [10, 8, 2, 9, 1]);
  fixture(end, 'signer-1', [20, 16, 4, 19, 1]);
  const result = summarizeSignerMetricDeltas(start, end);
  assert.equal(result.actors[0].counters.validationsRejected.start, 1);
  assert.equal(result.actors[0].counters.validationsRejected.delta, 0);
  assert.equal(result.zeroValidationRejections, true);
});

test('fails closed when a signer counter reset makes the windows incomparable', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-signer-deltas-'));
  const start = join(root, 'start');
  const end = join(root, 'end');
  mkdirSync(start);
  mkdirSync(end);
  fixture(start, 'signer-1', [10, 8, 2, 9, 1]);
  fixture(end, 'signer-1', [2, 2, 0, 2, 0]);
  assert.throws(() => summarizeSignerMetricDeltas(start, end), /decreased.*restart/);
});

test('treats an uninstantiated labelled counter as zero but not a failed scrape', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-signer-deltas-'));
  const start = join(root, 'start');
  const end = join(root, 'end');
  mkdirSync(start);
  mkdirSync(end);
  fixture(start, 'signer-1', [10, 8, 2, 9, 0]);
  fixture(end, 'signer-1', [20, 16, 4, 19, 0]);
  for (const directory of [start, end]) {
    const path = join(directory, 'signer-1.txt');
    writeFileSync(path, readFileWithoutRejected(path));
  }
  assert.equal(summarizeSignerMetricDeltas(start, end).zeroValidationRejections, true);
  writeFileSync(join(end, 'signer-1.txt'), '# attacknet_capture_error probe=signer_metrics\n');
  assert.throws(() => summarizeSignerMetricDeltas(start, end), /capture error/);
});

function readFileWithoutRejected(path) {
  return readFileSync(path, 'utf8').split('\n')
    .filter(line => !line.startsWith('stacks_signer_block_validation_responses{response_type="rejected"}'))
    .join('\n');
}
