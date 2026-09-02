import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {gzipSync} from 'node:zlib';

import {summarizeLokiExport} from './summarize-loki-export.mjs';

test('streams actor levels and bounded normalized warning families', async () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-log-summary-'));
  const input = join(root, 'logs.jsonl.gz');
  const entries = [
    {labels: {attacknet_actor: 'miner-1', detected_level: 'info'}, line: 'INFO [1] [a.rs:1] [main] healthy'},
    {labels: {attacknet_actor: 'miner-1', detected_level: 'warn'}, line: 'WARN [2] [a.rs:2] [main] retry block 123'},
    {labels: {attacknet_actor: 'miner-1', detected_level: 'warn'}, line: 'WARN [3] [a.rs:2] [main] retry block 456'},
    {labels: {attacknet_actor: 'signer-1', detected_level: 'error'}, line: 'ERRO [4] [b.rs:4] [main] no space left on device'},
  ];
  writeFileSync(input, gzipSync(`${entries.map(JSON.stringify).join('\n')}\n`));
  const result = await summarizeLokiExport(input, {top: 10});
  assert.equal(result.entries, 4);
  assert.deepEqual(result.byLevel, {warn: 2, error: 1, info: 1});
  assert.equal(result.topWarningErrorFamilies[0].count, 2);
  assert.match(result.topWarningErrorFamilies[0].family, /retry block <n>/);
  assert.equal(result.suspiciousFamilies[0].actor, 'signer-1');
});

test('malformed lines remain explicit instead of disappearing', async () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-log-summary-'));
  const input = join(root, 'logs.jsonl.gz');
  writeFileSync(input, gzipSync('{bad json}\n'));
  const result = await summarizeLokiExport(input);
  assert.equal(result.entries, 0);
  assert.equal(result.malformed, 1);
});
