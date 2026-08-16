#!/usr/bin/env node

import {readdirSync, readFileSync, writeFileSync} from 'node:fs';
import {basename, join} from 'node:path';

const COUNTERS = Object.freeze({
  proposalsReceived: 'stacks_signer_block_proposals_received',
  responsesAccepted: 'stacks_signer_block_responses_sent{response_type="accepted"}',
  responsesRejected: 'stacks_signer_block_responses_sent{response_type="rejected"}',
  validationsAccepted: 'stacks_signer_block_validation_responses{response_type="accepted"}',
  validationsRejected: 'stacks_signer_block_validation_responses{response_type="rejected"}',
});

function parseMetrics(path) {
  const contents = readFileSync(path, 'utf8');
  if (contents.includes('attacknet_capture_error')) {
    throw new Error(`${path} contains an attacknet capture error`);
  }
  const values = new Map();
  for (const raw of contents.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.lastIndexOf(' ');
    if (separator < 1) continue;
    const value = Number(line.slice(separator + 1));
    if (Number.isFinite(value)) values.set(line.slice(0, separator), value);
  }
  return values;
}

function signerFiles(directory) {
  return readdirSync(directory)
    .filter(name => /^signer-\d+\.txt$/.test(name))
    .sort((left, right) => Number(left.match(/\d+/)[0]) - Number(right.match(/\d+/)[0]));
}

export function summarizeSignerMetricDeltas(baselineDirectory, finalDirectory) {
  const baselineFiles = signerFiles(baselineDirectory);
  const finalFiles = signerFiles(finalDirectory);
  if (baselineFiles.length === 0) throw new Error('baseline contains no signer metric files');
  if (baselineFiles.join('\n') !== finalFiles.join('\n')) {
    throw new Error('baseline and final signer inventories differ');
  }

  const totals = Object.fromEntries(Object.keys(COUNTERS).map(name => [name, 0]));
  const actors = baselineFiles.map(file => {
    const before = parseMetrics(join(baselineDirectory, file));
    const after = parseMetrics(join(finalDirectory, file));
    const counters = {};
    for (const [name, metric] of Object.entries(COUNTERS)) {
      // Prometheus client libraries commonly omit a labelled counter until its
      // first increment. Absence is therefore the canonical representation of
      // zero, provided the scrape itself did not carry a capture-error marker.
      const start = before.get(metric) ?? 0;
      const end = after.get(metric) ?? 0;
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < 0) {
        throw new Error(`${file} counter ${metric} is not a non-negative integer`);
      }
      if (end < start) {
        throw new Error(`${file} counter ${metric} decreased from ${start} to ${end}; process restart or evidence mismatch`);
      }
      const delta = end - start;
      counters[name] = {start, end, delta};
      totals[name] += delta;
    }
    return {actor: basename(file, '.txt'), counters};
  });

  return {
    schemaVersion: 'stacks-attacknet-signer-metric-deltas/v1',
    baselineDirectory,
    finalDirectory,
    signerCount: actors.length,
    counterResets: 0,
    totals,
    validationRejectionsObserved: totals.validationsRejected,
    zeroValidationRejections: totals.validationsRejected === 0,
    actors,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [baselineDirectory, finalDirectory, output] = process.argv.slice(2);
  if (!baselineDirectory || !finalDirectory || baselineDirectory === '--help') {
    process.stdout.write('usage: signer-metric-deltas.mjs BASELINE_METRICS FINAL_METRICS [OUTPUT.json]\n');
    process.exit(baselineDirectory === '--help' ? 0 : 2);
  }
  const encoded = `${JSON.stringify(summarizeSignerMetricDeltas(baselineDirectory, finalDirectory), null, 2)}\n`;
  if (output) writeFileSync(output, encoded);
  else process.stdout.write(encoded);
}
