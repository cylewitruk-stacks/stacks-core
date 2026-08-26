import assert from 'node:assert/strict';
import test from 'node:test';

import {canonicalJson, sha256File, sha256Value} from './artifact-digest.mjs';

test('artifact digests use recursively sorted canonical JSON', () => {
  const left = {z: [{b: 2, a: 1}], a: 'Malmö'};
  const right = {a: 'Malmö', z: [{a: 1, b: 2}]};
  assert.equal(canonicalJson(left), '{"a":"Malmö","z":[{"a":1,"b":2}]}');
  assert.equal(sha256Value(left), sha256Value(right));
});

test('artifact digests fail closed on values outside the JSON contract', () => {
  assert.throws(() => canonicalJson({value: Number.NaN}), /non-finite/);
  assert.throws(() => canonicalJson({value: undefined}), /undefined/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic/);
});

test('file digests accept an injected byte reader', () => {
  assert.equal(
    sha256File('ignored', () => Buffer.from('attacknet')),
    'sha256:3ad7d3eacad2f729a95b67eb0bc4b2ff2c9e847af4b1bb4625b0851ec8dbc3f3',
  );
});
