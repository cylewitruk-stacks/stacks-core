import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {exportLokiRange, flattenStreams} from './export-loki.mjs';

const observability = dirname(fileURLToPath(import.meta.url));

function response(result) {
  return {ok: true, json: async () => ({status: 'success', data: {resultType: 'streams', result}})};
}

test('flattens and deterministically orders labelled streams', () => {
  assert.deepEqual(flattenStreams([
    {stream: {role: 'miner', actor: 'm1'}, values: [['12', 'later']]},
    {stream: {actor: 'f1', role: 'follower'}, values: [['10', 'first']]},
  ]), [
    {timestampNs: '10', labels: {actor: 'f1', role: 'follower'}, line: 'first'},
    {timestampNs: '12', labels: {actor: 'm1', role: 'miner'}, line: 'later'},
  ]);
});

test('paginates inclusively without duplicating the boundary timestamp', async () => {
  const starts = [];
  const pages = [
    [{stream: {actor: 'one'}, values: [['10', 'a'], ['11', 'b']]}],
    [{stream: {actor: 'one'}, values: [['11', 'b'], ['12', 'c']]}],
    [{stream: {actor: 'one'}, values: [['12', 'c']]}],
  ];
  const result = await exportLokiRange({
    endpoint: 'http://loki.test', network: 'attacknet', start: '10', end: '20', limit: 2,
    request: async url => { starts.push(url.searchParams.get('start')); return response(pages.shift()); },
  });
  assert.deepEqual(starts, ['10', '11', '12']);
  assert.equal(result.metadata.complete, true);
  assert.deepEqual(result.logs.map(entry => entry.line), ['a', 'b', 'c']);
});

test('streams pages without retaining the complete export in memory', async () => {
  const pages = [
    [{stream: {actor: 'one'}, values: [['10', 'a'], ['11', 'b']]}],
    [{stream: {actor: 'one'}, values: [['11', 'b'], ['12', 'c']]}],
    [{stream: {actor: 'one'}, values: [['12', 'c']]}],
  ];
  const written = [];
  const result = await exportLokiRange({
    endpoint: 'http://loki.test', network: 'attacknet', start: '10', end: '20', limit: 2,
    request: async () => response(pages.shift()),
    onEntries: entries => written.push(...entries),
  });
  assert.equal(result.metadata.complete, true);
  assert.equal(result.metadata.entryCount, 3);
  assert.equal(Object.hasOwn(result, 'logs'), false);
  assert.deepEqual(written.map(entry => entry.line), ['a', 'b', 'c']);
});

test('fails visibly instead of skipping an overfull identical timestamp', async () => {
  const result = await exportLokiRange({
    endpoint: 'http://loki.test', network: 'attacknet', start: '10', end: '20', limit: 2,
    request: async () => response([{stream: {actor: 'one'}, values: [['10', 'a'], ['10', 'b']]}]),
  });
  assert.equal(result.metadata.complete, false);
  assert.match(result.metadata.failure, /no progress/);
});

test('rejects malformed scope and range inputs', async () => {
  await assert.rejects(exportLokiRange({endpoint: 'http://loki', network: 'bad\nquery', start: '1', end: '2'}), /network/);
  await assert.rejects(exportLokiRange({endpoint: 'http://loki', network: 'good', start: '3', end: '2'}), /start/);
});

test('disabled export still emits the complete compressed artifact contract', () => {
  const destination = mkdtempSync(join(tmpdir(), 'attacknet-loki-disabled-'));
  execFileSync(join(observability, 'export-loki.sh'), [destination, '1', '2'], {
    env: {...process.env, ATTACKNET_OBSERVABILITY_ENABLED: '0'},
  });
  const metadata = JSON.parse(readFileSync(join(destination, 'export.json'), 'utf8'));
  assert.equal(metadata.complete, true);
  assert.equal(metadata.logArtifact, 'logs.jsonl.gz');
  assert.equal(metadata.uncompressedBytes, 0);
  assert.ok(metadata.compressedBytes > 0);
  assert.equal(gunzipSync(readFileSync(join(destination, 'logs.jsonl.gz'))).length, 0);
  assert.match(readFileSync(join(destination, 'digests.sha256'), 'utf8'), /logs\.jsonl\.gz/);
});
