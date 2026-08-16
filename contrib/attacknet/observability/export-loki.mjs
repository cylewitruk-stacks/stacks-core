#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {once} from 'node:events';
import {createWriteStream, mkdirSync, renameSync, statSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {fileURLToPath} from 'node:url';
import {createGzip} from 'node:zlib';

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

export async function exportLokiRange({endpoint, network, start, end, limit = 5000, maxPages = 1000, request = fetch, onEntries}) {
  if (typeof endpoint !== 'string' || !/^https?:\/\/[^/]+\/?$/.test(endpoint)) throw new Error('endpoint must be an HTTP origin');
  if (!NETWORK.test(network)) throw new Error('network must be a bounded DNS label');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('limit must be an integer from 1 through 5000');
  if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 10000) throw new Error('maxPages must be a bounded positive integer');
  const startNs = normalizedNanoseconds(start, 'start');
  const endNs = normalizedNanoseconds(end, 'end');
  if (startNs > endNs) throw new Error('start must not exceed end');

  const selector = `{attacknet_network=${JSON.stringify(network)}}`;
  if (onEntries !== undefined && typeof onEntries !== 'function') throw new Error('onEntries must be a function');
  const logs = onEntries ? null : [];
  const pages = [];
  let cursor = startNs;
  let boundarySeen = new Set();
  let entryCount = 0;
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
    const pageSeen = new Set();
    const fresh = [];
    for (const entry of flattened) {
      const key = entryKey(entry);
      if (pageSeen.has(key)) continue;
      pageSeen.add(key);
      if (BigInt(entry.timestampNs) === cursor && boundarySeen.has(key)) continue;
      fresh.push(entry);
    }
    const added = fresh.length;
    if (added) {
      if (onEntries) await onEntries(fresh);
      else logs.push(...fresh);
      entryCount += added;
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
    // Loki's range start is inclusive. Retain only hashes at the next cursor,
    // rather than the complete export, so a multi-hour run remains bounded by
    // one response page. Entries before the cursor cannot recur in a correctly
    // ordered forward query.
    const nextBoundarySeen = maximumTimestamp === cursor ? new Set(boundarySeen) : new Set();
    for (const entry of flattened) {
      if (BigInt(entry.timestampNs) === maximumTimestamp) nextBoundarySeen.add(entryKey(entry));
    }
    boundarySeen = nextBoundarySeen;
    cursor = maximumTimestamp;
  }
  if (!complete && !failure) failure = `pagination exceeded maxPages=${maxPages}`;

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
      entryCount,
      failure: failure ?? null,
      pages,
    },
    ...(logs ? {logs} : {}),
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
  const partialLogs = join(destination, 'logs.jsonl.gz.partial');
  const finalLogs = join(destination, 'logs.jsonl.gz');
  let result;
  let gzip;
  let compression;
  let compressionFinished = false;
  let uncompressedBytes = 0;
  try {
    const buildResponse = await fetch(new URL('/loki/api/v1/status/buildinfo', values.endpoint));
    if (!buildResponse.ok) throw new Error(`Loki build-info query failed with HTTP ${buildResponse.status}`);
    const buildInfo = await buildResponse.json();
    gzip = createGzip();
    compression = pipeline(gzip, createWriteStream(partialLogs, {flags: 'w'}));
    result = await exportLokiRange({
      endpoint: values.endpoint,
      network: values.network,
      start: values.start,
      end: values.end,
      limit: values.limit === undefined ? 5000 : Number(values.limit),
      maxPages: values['max-pages'] === undefined ? 1000 : Number(values['max-pages']),
      onEntries: async entries => {
        const chunk = `${entries.map(entry => JSON.stringify(entry)).join('\n')}\n`;
        uncompressedBytes += Buffer.byteLength(chunk);
        if (!gzip.write(chunk)) await once(gzip, 'drain');
      },
    });
    gzip.end();
    await compression;
    compressionFinished = true;
    result.metadata.buildInfo = buildInfo;
    result.metadata.logArtifact = 'logs.jsonl.gz';
    result.metadata.compression = 'gzip';
    result.metadata.uncompressedBytes = uncompressedBytes;
    result.metadata.compressedBytes = statSync(partialLogs).size;
    writeFileSync(join(destination, 'export.json'), `${JSON.stringify({...result.metadata, exportedAt: new Date().toISOString()}, null, 2)}\n`);
    if (!result.metadata.complete) throw new Error(result.metadata.failure);
    renameSync(partialLogs, finalLogs);
  } catch (error) {
    if (gzip && !compressionFinished) {
      gzip.destroy();
      try { await compression; } catch {}
    }
    const failure = error instanceof Error ? error.message : String(error);
    const metadata = result?.metadata ? {
      ...result.metadata,
      complete: false,
      failure: result.metadata.failure ?? failure,
      logArtifact: null,
      partialLogArtifact: 'logs.jsonl.gz.partial',
      compression: 'gzip',
      uncompressedBytes,
      compressedBytes: (() => { try { return statSync(partialLogs).size; } catch { return 0; } })(),
    } : {
      schemaVersion: 'stacks-attacknet-loki-export/v1', complete: false,
      failure, partialLogArtifact: 'logs.jsonl.gz.partial',
    };
    writeFileSync(join(destination, 'export.json'), `${JSON.stringify(metadata, null, 2)}\n`);
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
