import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const COUNTER_BASES = [
  'stacks_signer_deferred_miner_authorizations_admitted',
  'stacks_signer_deferred_miner_authorization_observations',
  'stacks_signer_deferred_miner_authorizations_resolved',
  'stacks_signer_block_policy_rejections',
];
const RESOLUTIONS = [
  'released',
  'expired',
  'unauthorized',
  'redundant',
  'binding_failed',
  'malformed',
];

export function parsePrometheus(text) {
  const metrics = new Map();
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^(\S+)\s+([-+0-9.eE]+)$/);
    if (match) metrics.set(match[1], Number(match[2]));
  }
  return metrics;
}

function splitSeries(series) {
  const labelAt = series.indexOf('{');
  return labelAt < 0
    ? [series, '']
    : [series.slice(0, labelAt), series.slice(labelAt)];
}

function alternateCounterSeries(series) {
  const [name, labels] = splitSeries(series);
  return `${name.endsWith('_total') ? name.slice(0, -6) : `${name}_total`}${labels}`;
}

function counterValue(metrics, base, labels = '') {
  return metrics.get(`${base}${labels}`) ?? metrics.get(`${base}_total${labels}`) ?? 0;
}

function isTrackedCounter(series) {
  const [name] = splitSeries(series);
  const base = name.endsWith('_total') ? name.slice(0, -6) : name;
  return COUNTER_BASES.includes(base);
}

export function evaluateSignerLifecycle(beforeText, afterText, name = 'signer') {
  const before = parsePrometheus(beforeText);
  const after = parsePrometheus(afterText);
  const failures = [];
  const beforeGeneration = before.get(
    'stacks_signer_native_network_generation_start_timestamp_seconds',
  ) ?? 0;
  const afterGeneration = after.get(
    'stacks_signer_native_network_generation_start_timestamp_seconds',
  ) ?? 0;
  if (!(beforeGeneration > 0) || beforeGeneration !== afterGeneration) {
    failures.push(`${name}: process generation changed ${beforeGeneration}->${afterGeneration}`);
  }
  for (const [series, end] of after) {
    if (!isTrackedCounter(series)) continue;
    const start = before.get(series) ?? before.get(alternateCounterSeries(series)) ?? 0;
    if (end < start) failures.push(`${name}:${series} reset ${start}->${end}`);
  }
  const admitted = counterValue(
    after,
    'stacks_signer_deferred_miner_authorizations_admitted',
  );
  const pending = after.get('stacks_signer_deferred_miner_authorizations_pending') ?? 0;
  const outcomes = Object.fromEntries(RESOLUTIONS.map(resolution => [
    resolution,
    counterValue(
      after,
      'stacks_signer_deferred_miner_authorizations_resolved',
      `{resolution="${resolution}"}`,
    ),
  ]));
  const resolved = Object.values(outcomes).reduce((total, value) => total + value, 0);
  if (admitted !== pending + resolved) {
    failures.push(
      `${name}: conservation failed admitted=${admitted} pending=${pending} resolved=${resolved}`,
    );
  }
  return {failures, admitted, pending, outcomes};
}

export function assertSignerLifecycleEvidence(baselineDir, finalDir) {
  const names = fs.readdirSync(finalDir).filter(name => name.endsWith('.txt'));
  const failures = [];
  let released = 0;
  for (const name of names) {
    const result = evaluateSignerLifecycle(
      fs.readFileSync(path.join(baselineDir, name), 'utf8'),
      fs.readFileSync(path.join(finalDir, name), 'utf8'),
      name,
    );
    failures.push(...result.failures);
    released += result.outcomes.released;
  }
  if (released < 1) failures.push('no signer reported a released deferred proposal');
  if (failures.length) {
    throw new Error(`signer lifecycle evidence failed: ${failures.join(', ')}`);
  }
  return {released, conservedSigners: names.length};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [baselineDir, finalDir] = process.argv.slice(2);
  if (!baselineDir || !finalDir) {
    throw new Error('usage: signer-lifecycle-evidence.mjs BASELINE_DIR FINAL_DIR');
  }
  console.log(JSON.stringify(assertSignerLifecycleEvidence(baselineDir, finalDir)));
}
