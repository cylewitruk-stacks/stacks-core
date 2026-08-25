import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

import {validateControllerEquivalence} from './controller-equivalence.mjs';

const matrix = JSON.parse(readFileSync(new URL('./controller-equivalence-v1.json', import.meta.url), 'utf8'));

test('controller migration maps every behavior domain and the required live integration seams', () => {
  assert.equal(validateControllerEquivalence(matrix), matrix);
  assert.ok(matrix.entries.length >= 25);
  for (const required of [
    'topology-admitted-inventory',
    'reversible-network-fault',
    'one-shot-pod-kill',
    'controller-restart-resume',
  ]) {
    assert.ok(matrix.entries.some(entry => entry.live.includes(required)), `missing ${required}`);
  }
  const identity = matrix.entries.find(entry => entry.id === 'fault-live-identity-barrier');
  assert.ok(identity.tests.includes(
    'contrib/helm/hacknet/operator/internal/fault/reconciler_contract_test.go',
  ));
  assert.deepEqual(identity.live, ['one-shot-pod-kill']);
});

test('controller migration matrix fails closed on drift and missing mappings', () => {
  const duplicate = structuredClone(matrix);
  duplicate.entries[1].id = duplicate.entries[0].id;
  assert.throws(() => validateControllerEquivalence(duplicate), /duplicate id/);

  const missing = structuredClone(matrix);
  missing.entries[0].go = ['contrib/helm/hacknet/operator/internal/not-present.go'];
  assert.throws(() => validateControllerEquivalence(missing), /cannot resolve/);

  const staleLegacySymbol = structuredClone(matrix);
  staleLegacySymbol.entries[0].legacy = [
    'contrib/helm/hacknet/operator/controller.py:Reconciler.not_a_real_method',
  ];
  assert.throws(() => validateControllerEquivalence(staleLegacySymbol), /cannot resolve its member/);
});
