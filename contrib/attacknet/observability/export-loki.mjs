#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {mkdirSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const NETWORK = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

function canonicalLabels(labels) {
  return Object.fromEntries(Object.entries(labels ?? {}).sort(([left], [right]) => left.localeCompare(right)));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  return JSON.stringify(value);
}

function normalizedNanoseconds(value, name) {
  if (typeof value !== 'string' || !value.length) throw new Error(`${name} is required`);
  if (/^[0-9]+$/.test(value)) {
    const result = BigInt(value);
    if (result < 0n) throw new Error(`${name} must not be negative`);
    return result;
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error(`${name} must be nanoseconds or RFC3339`);
  return BigInt(milliseconds) * 1_000_000n;
}

function entryKey(entry) {
  return createHash('sha256').update(canonicalJson(entry)).digest('hex');
}

export function flattenStreams(result) {
  if (!Array.isArray(result)) throw new Error('Loki streams result must be an array');
  const entries = [];
  for (const stream of result) {
    const labels = canonicalLabels(stream.stream);
    if (!Array.isArray(stream.values)) throw new Error('Loki stream values must be an array');
    for (const value of stream.values) {
      if (!Array.isArray(value) || value.length !== 2 || !/^[0-9]+$/.test(value[0]) || typeof value[1] !== 'string') {
        throw new Error('Loki stream entry must contain a nanosecond timestamp and line');
      }
      entries.push({timestampNs: value[0], labels, line: value[1]});
    }
  }
  return entries.sort((left, right) => {
    const timestamp = BigInt(left.timestampNs) - BigInt(right.timestampNs);
    if (timestamp !== 0n) return timestamp < 0n ? -1 : 1;
    return canonicalJson(left.labels).localeCompare(canonicalJson(right.labels)) || left.line.localeCompare(right.line);
  });
}

export async function exportLokiRange({endpoint, network, start, end, limit = 5000, maxPages = 1000, request = fetch}) {
  if (typeof endpoint !== 'string' || !/^https?:\/\/[^/]+\/?$/.test(endpoint)) throw new Error('endpoint must be an HTTP origin');
  if (!NETWORK.test(network)) throw new Error('network must be a bounded DNS label');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('limit must be an integer from 1 through 5000');
  if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 10000) throw new Error('maxPages must be a bounded positive integer');
  const startNs = normalizedNanoseconds(start, 'start');
  const endNs = normalizedNanoseconds(end, 'end');
  if (startNs > endNs) throw new Error('start must not exceed end');

  const selector = `{attacknet_network=${JSON.stringify(network)}}`;
  const entries = new Map();
  const pages = [];
  let cursor = startNs;
  let complete = false;
  let failure;

  for (let page = 1; page <= maxPages; page += 1) {
    const url = new URL('/loki/api/v1/query_range', endpoint);
    url.searchParams.set('query', selector);
    url.searchParams.set('start', cursor.toString());
    url.searchParams.set('end', endNs.toString());
    url.searchParams.set('direction', 'forward');
    url.searchParams.set('limit', String(limit));
    const response = await request(url);
    if (!response.ok) throw new Error(`Loki query failed with HTTP ${response.status}`);
    const body = await response.json();
    if (body.status !== 'success' || body.data?.resultType !== 'streams') throw new Error('Loki returned an unexpected query response');
    const flattened = flattenStreams(body.data.result);
    let added = 0;
    for (const entry of flattened) {
      const key = entryKey(entry);
      if (!entries.has(key)) {
        entries.set(key, entry);
        added += 1;
      }
    }
    const maximumTimestamp = flattened.length ? BigInt(flattened.at(-1).timestampNs) : null;
    pages.push({page, startNs: cursor.toString(), rawEntries: flattened.length, newEntries: added, maximumTimestampNs: maximumTimestamp?.toString() ?? null});
    if (flattened.length < limit) {
      complete = true;
      break;
    }
    if (maximumTimestamp === null || maximumTimestamp < cursor || added === 0) {
      failure = 'pagination made no progress; more than one page may share a timestamp';
      break;
    }
    // Loki's range start is inclusive. Re-query the boundary timestamp and
    // de-duplicate it so entries sharing that timestamp cannot be skipped.
    cursor = maximumTimestamp;
  }
  if (!complete && !failure) failure = `pagination exceeded maxPages=${maxPages}`;

  const logs = [...entries.values()].sort((left, right) => {
    const timestamp = BigInt(left.timestampNs) - BigInt(right.timestampNs);
    if (timestamp !== 0n) return timestamp < 0n ? -1 : 1;
    return canonicalJson(left.labels).localeCompare(canonicalJson(right.labels)) || left.line.localeCompare(right.line);
  });
  return {
    metadata: {
      schemaVersion: 'stacks-attacknet-loki-export/v1',
      complete,
      selector,
      startNs: startNs.toString(),
      endNs: endNs.toString(),
      direction: 'forward',
      pageLimit: limit,
      pageCount: pages.length,
      entryCount: logs.length,
      failure: failure ?? null,
      pages,
    },
    logs,
  };
}

async function main() {
  const values = Object.fromEntries(process.argv.slice(2).map(argument => {
    const match = argument.match(/^--([^=]+)=(.*)$/s);
    if (!match) throw new Error(`invalid option: ${argument}`);
    return [match[1], match[2]];
  }));
  const destination = values.destination;
  if (!destination) throw new Error('--destination is required');
  mkdirSync(destination, {recursive: true});
  let result;
  try {
    result = await exportLokiRange({
      endpoint: values.endpoint,
      network: values.network,
      start: values.start,
      end: values.end,
      limit: values.limit === undefined ? 5000 : Number(values.limit),
      maxPages: values['max-pages'] === undefined ? 1000 : Number(values['max-pages']),
    });
    const buildResponse = await fetch(new URL('/loki/api/v1/status/buildinfo', values.endpoint));
    if (!buildResponse.ok) throw new Error(`Loki build-info query failed with HTTP ${buildResponse.status}`);
    result.metadata.buildInfo = await buildResponse.json();
  } catch (error) {
    writeFileSync(join(destination, 'export.json'), `${JSON.stringify({
      schemaVersion: 'stacks-attacknet-loki-export/v1', complete: false,
      failure: error instanceof Error ? error.message : String(error),
    }, null, 2)}\n`);
    throw error;
  }
  writeFileSync(join(destination, 'logs.jsonl'), result.logs.map(entry => JSON.stringify(entry)).join('\n') + (result.logs.length ? '\n' : ''));
  writeFileSync(join(destination, 'export.json'), `${JSON.stringify({...result.metadata, exportedAt: new Date().toISOString()}, null, 2)}\n`);
  if (!result.metadata.complete) throw new Error(result.metadata.failure);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
