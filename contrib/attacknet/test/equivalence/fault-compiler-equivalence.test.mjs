import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
import test from 'node:test';

import assert from 'node:assert/strict';

import {loadEquivalenceFixtures} from '../support/equivalence-fixtures.mjs';

const ATTACKNET_DIR = dirname(fileURLToPath(import.meta.url));
const OPERATOR_DIR = join(ATTACKNET_DIR, '..', '..', '..', 'helm', 'hacknet', 'operator');
const fixtures = loadEquivalenceFixtures();
const {manifest, cases} = fixtures.json('fault-compiler.json');

test('Go compiler preserves the approved v1alpha1 contract for every fault type', () => {
  const result = spawnSync('go', ['run', './cmd/compile-check'], {
    cwd: OPERATOR_DIR,
    encoding: 'utf8',
    env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/private/tmp/attacknet-go-cache'},
    input: JSON.stringify({cases: cases.map(value => ({campaign: value.campaign, manifest}))}),
  });
  assert.equal(result.status, 0, `Go compiler failed:\n${result.stderr}`);
  assert.deepEqual(JSON.parse(result.stdout).cases, cases.map(value => value.expected));
});
