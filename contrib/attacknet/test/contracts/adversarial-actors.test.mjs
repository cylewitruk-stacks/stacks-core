import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const attacknet = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const repository = resolve(attacknet, '..', '..');
const patch = join(attacknet, 'test', 'fixtures', 'adversaries', 'rejecting-signer.patch');

test('bounded signer fixture applies cleanly and remains compile-time isolated', () => {
  execFileSync('git', ['-C', repository, 'apply', '--check', patch]);
  const source = readFileSync(patch, 'utf8');
  const changedFiles = [...source.matchAll(/^diff --git a\/(.+?) b\/(.+)$/gm)]
    .map(([, from, to]) => ({from, to}));
  assert.deepEqual(changedFiles, [{
    from: 'stacks-signer/src/v0/signer.rs',
    to: 'stacks-signer/src/v0/signer.rs',
  }]);
  assert.match(source, /#\[cfg\(feature = "testing"\)\]/);
  assert.match(source, /TEST_REJECT_ALL_BLOCK_PROPOSAL/);
  assert.match(source, /TEST_IGNORE_ALL_BLOCK_PROPOSALS/);
  assert.match(source, /"reject-all"/);
  assert.match(source, /"ignore-all"/);
});
