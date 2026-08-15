#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';

function parseLabels(value) {
  if (!value) return {};
  return Object.fromEntries([...value.matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"/g)]
    .map(match => [match[1], match[2]]));
}

export function parsePrometheus(text) {
  const samples = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)$/.exec(line);
    if (!match) continue;
    const value = Number(match[3]);
    if (Number.isFinite(value)) samples.push({name: match[1], labels: parseLabels(match[2]), value});
  }
  return samples;
}

function sum(samples, name, predicate = () => true) {
  return samples.filter(sample => sample.name === name && predicate(sample.labels))
    .reduce((total, sample) => total + sample.value, 0);
}

export function pressureDelta(beforeText, afterText) {
  const before = parsePrometheus(beforeText);
  const after = parsePrometheus(afterText);
  const key = sample => `${sample.labels.method ?? 'unknown'}:${sample.labels.code ?? 'unknown'}`;
  const beforeRequests = new Map(before.filter(sample => sample.name === 'hacknet_operator_api_requests_total')
    .map(sample => [key(sample), sample.value]));
  const byMethodCode = {};
  for (const sample of after.filter(item => item.name === 'hacknet_operator_api_requests_total')) {
    byMethodCode[key(sample)] = Math.max(0, sample.value - (beforeRequests.get(key(sample)) ?? 0));
  }
  const requestCount = Object.values(byMethodCode).reduce((total, value) => total + value, 0);
  const throttled = Object.entries(byMethodCode)
    .filter(([label]) => label.endsWith(':429')).reduce((total, [, value]) => total + value, 0);
  const serverErrors = Object.entries(byMethodCode)
    .filter(([label]) => /:5\d\d$/.test(label)).reduce((total, [, value]) => total + value, 0);
  const transportErrors = Object.entries(byMethodCode)
    .filter(([label]) => label.endsWith(':error')).reduce((total, [, value]) => total + value, 0);
  const reconcileBefore = sum(before, 'hacknet_operator_reconcile_duration_seconds_count');
  const reconcileAfter = sum(after, 'hacknet_operator_reconcile_duration_seconds_count');
  const durationBefore = sum(before, 'hacknet_operator_reconcile_duration_seconds_sum');
  const durationAfter = sum(after, 'hacknet_operator_reconcile_duration_seconds_sum');
  const reconcileCount = Math.max(0, reconcileAfter - reconcileBefore);
  const reconcileDurationSeconds = Math.max(0, durationAfter - durationBefore);
  const processStartBefore = sum(before, 'hacknet_operator_process_start_time_seconds');
  const processStartAfter = sum(after, 'hacknet_operator_process_start_time_seconds');
  const processStable = processStartBefore > 0 && processStartBefore === processStartAfter;
  const apiDurationCount = Math.max(0,
    sum(after, 'hacknet_operator_api_request_duration_seconds_count')
      - sum(before, 'hacknet_operator_api_request_duration_seconds_count'));
  const apiDurationSeconds = Math.max(0,
    sum(after, 'hacknet_operator_api_request_duration_seconds_sum')
      - sum(before, 'hacknet_operator_api_request_duration_seconds_sum'));
  return {
    schemaVersion: 1,
    ok: processStable && throttled === 0 && serverErrors === 0 && transportErrors === 0,
    process: {stable: processStable, startTimeSeconds: processStartAfter},
    api: {
      requestCount, byMethodCode, throttled, serverErrors, transportErrors,
      durationSeconds: apiDurationSeconds,
      meanDurationSeconds: apiDurationCount ? apiDurationSeconds / apiDurationCount : 0,
    },
    reconcile: {
      count: reconcileCount,
      durationSeconds: reconcileDurationSeconds,
      meanDurationSeconds: reconcileCount ? reconcileDurationSeconds / reconcileCount : 0,
      lastDurationSeconds: sum(after, 'hacknet_operator_reconcile_last_duration_seconds'),
      lastApiRequests: sum(after, 'hacknet_operator_reconcile_last_api_requests'),
      maxDurationSecondsSinceStart: sum(after, 'hacknet_operator_reconcile_duration_seconds_max'),
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [beforePath, afterPath, outputPath] = process.argv.slice(2);
  if (!beforePath || !afterPath) throw new Error('usage: operator-pressure.mjs BEFORE.prom AFTER.prom [OUTPUT.json]');
  const result = pressureDelta(readFileSync(beforePath, 'utf8'), readFileSync(afterPath, 'utf8'));
  const encoded = `${JSON.stringify(result, null, 2)}\n`;
  if (outputPath) writeFileSync(outputPath, encoded); else process.stdout.write(encoded);
  if (!result.ok) process.exitCode = 1;
}
