#!/usr/bin/env node

import {createReadStream, writeFileSync} from 'node:fs';
import {createGunzip} from 'node:zlib';
import {createInterface} from 'node:readline';

const WARNING_LEVELS = new Set(['warn', 'warning', 'error', 'erro', 'fatal']);

function increment(object, key, amount = 1) {
  object[key] = (object[key] ?? 0) + amount;
}

function normalizedFamily(line) {
  const text = String(line ?? '').trim();
  const parsed = /^(?:[A-Z]+)\s+\[[^\]]+\]\s+\[([^\]]+)\]\s+\[[^\]]+\]\s+(.*)$/.exec(text);
  const source = parsed?.[1] ?? '<unstructured>';
  const message = parsed?.[2] ?? text;
  return `${source} ${message}`
    .replace(/\b[0-9a-f]{64}\b/gi, '<hash>')
    .replace(/\b[0-9a-f]{32,63}\b/gi, '<hex>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '<uuid>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, '<address>')
    .replace(/\b\d+(?:\.\d+)?\b/g, '<n>')
    .slice(0, 500);
}

function sortedCounts(counts, limit = null) {
  const rows = Object.entries(counts).map(([key, count]) => ({key, count}))
    .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key));
  return limit === null ? rows : rows.slice(0, limit);
}

export async function summarizeLokiExport(input, {top = 50} = {}) {
  if (!Number.isSafeInteger(top) || top < 1 || top > 1000) throw new Error('top must be 1..1000');
  const byLevel = {};
  const byActor = {};
  const warningErrorByActor = {};
  const families = {};
  const suspicious = {};
  let entries = 0;
  let malformed = 0;
  const reader = createInterface({input: createReadStream(input).pipe(createGunzip()), crlfDelay: Infinity});
  for await (const line of reader) {
    if (!line) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      malformed += 1;
      continue;
    }
    entries += 1;
    const actor = String(entry.labels?.attacknet_actor ?? '<unknown>');
    const level = String(entry.labels?.detected_level ?? '<unknown>').toLowerCase();
    increment(byActor, actor);
    increment(byLevel, level);
    if (WARNING_LEVELS.has(level)) {
      increment(warningErrorByActor, actor);
      increment(families, `${level}\t${actor}\t${normalizedFamily(entry.line)}`);
    }
    if (/panic|segmentation fault|out of memory|no space left|\benospc\b|fatal runtime|assertion failed|stack overflow/i.test(entry.line ?? '')) {
      increment(suspicious, `${actor}\t${normalizedFamily(entry.line)}`);
    }
  }
  return {
    schemaVersion: 'stacks-attacknet-log-summary/v1',
    source: input,
    entries,
    malformed,
    byLevel: Object.fromEntries(sortedCounts(byLevel).map(({key, count}) => [key, count])),
    byActor: Object.fromEntries(sortedCounts(byActor).map(({key, count}) => [key, count])),
    warningErrorByActor: Object.fromEntries(
      sortedCounts(warningErrorByActor).map(({key, count}) => [key, count]),
    ),
    topWarningErrorFamilies: sortedCounts(families, top).map(({key, count}) => {
      const [level, actor, family] = key.split('\t');
      return {level, actor, family, count};
    }),
    suspiciousFamilies: sortedCounts(suspicious, top).map(({key, count}) => {
      const [actor, family] = key.split('\t');
      return {actor, family, count};
    }),
  };
}

function option(name, fallback) {
  const prefix = `--${name}=`;
  const argument = process.argv.find(value => value.startsWith(prefix));
  return argument ? argument.slice(prefix.length) : fallback;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = process.argv[2];
  if (!input || input === '--help') {
    process.stdout.write('usage: summarize-loki-export.mjs LOGS.jsonl.gz [OUTPUT.json] [--top=N]\n');
    process.exit(input === '--help' ? 0 : 2);
  }
  const output = process.argv[3];
  const result = await summarizeLokiExport(input, {top: Number(option('top', 50))});
  const encoded = `${JSON.stringify(result, null, 2)}\n`;
  if (output) writeFileSync(output, encoded);
  else process.stdout.write(encoded);
}
