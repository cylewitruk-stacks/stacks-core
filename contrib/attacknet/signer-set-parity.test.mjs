import assert from 'node:assert/strict';
import test from 'node:test';

import {
  declaredSignerSet, observedSignerSet, resolveCanonicalSignerSet, verifySignerSetParity,
} from './signer-set-parity.mjs';

const key = index => `02${index.toString(16).padStart(64, '0')}`;
const manifest = {
  actors: [
    {service: 'signer-1', role: 'signer', signerIndex: 1, signerPublicKey: key(1), signerWeight: 1},
    {service: 'signer-node-1', role: 'companion', signerIndex: 1, signerPublicKey: key(1), signerWeight: 1},
    {service: 'signer-2', role: 'signer', signerIndex: 2, signerPublicKey: key(2), signerWeight: 3},
  ],
};
const response = {stacker_set: {signers: [
  {signing_key: key(2), weight: 3}, {signing_key: key(1), weight: 1},
]}};

test('extracts only signer actors and verifies an unordered authoritative set', () => {
  assert.equal(declaredSignerSet(manifest).length, 2);
  assert.equal(observedSignerSet(response).length, 2);
  assert.deepEqual(verifySignerSetParity(manifest, response, {rewardCycle: 11}), {
    schemaVersion: 'stacks-attacknet-signer-set-parity/v1', ok: true, rewardCycle: 11,
    declaredCount: 2, observedCount: 2, declaredTotalWeight: 4, observedTotalWeight: 4,
    canonicalThresholdWeight: 3, missing: [], unexpected: [], mismatched: [],
    signerSetDigest: verifySignerSetParity(manifest, response).signerSetDigest,
  });
});

test('rejects understated weights with a machine-readable report', () => {
  const bad = structuredClone(manifest);
  bad.actors.find(actor => actor.service === 'signer-2').signerWeight = 2;
  assert.throws(() => verifySignerSetParity(bad, response, {rewardCycle: 11}), error => {
    assert.equal(error.report.ok, false);
    assert.deepEqual(error.report.mismatched, [{
      actor: 'signer-2', signingKey: key(2), declared: 2, observed: 3,
    }]);
    assert.equal(error.report.declaredTotalWeight, 3);
    assert.equal(error.report.observedTotalWeight, 4);
    return true;
  });
});

test('runtime resolution preserves exact identities and overlays canonical cycle weights', () => {
  const changed = structuredClone(response);
  changed.stacker_set.signers[0].weight = 2;
  const {manifest: resolved, report} = resolveCanonicalSignerSet(manifest, changed, {rewardCycle: 12});
  assert.equal(report.ok, true);
  assert.equal(report.identityMatch, true);
  assert.equal(report.weightsMatch, false);
  assert.equal(report.declaredTotalWeight, 4);
  assert.equal(report.observedTotalWeight, 3);
  assert.equal(report.canonicalThresholdWeight, 3);
  assert.deepEqual(report.mismatched, [{
    actor: 'signer-2', signingKey: key(2), declared: 3, observed: 2,
  }]);
  assert.equal(resolved.actors.find(actor => actor.service === 'signer-2').signerWeight, 2);
  assert.equal(resolved.actors.find(actor => actor.service === 'signer-node-1').signerWeight, 1);
  assert.equal(manifest.actors.find(actor => actor.service === 'signer-2').signerWeight, 3);
});

test('runtime resolution never treats a changed signer identity as weight drift', () => {
  const changed = structuredClone(response);
  changed.stacker_set.signers[0].signing_key = key(3);
  assert.throws(() => resolveCanonicalSignerSet(manifest, changed, {rewardCycle: 12}), error => {
    assert.match(error.message, /identities do not match/);
    assert.equal(error.report.missing.length, 1);
    assert.equal(error.report.unexpected.length, 1);
    return true;
  });
});

test('rejects missing, unexpected, duplicate, or malformed identities', () => {
  assert.throws(() => verifySignerSetParity(manifest, {stacker_set: {signers: [response.stacker_set.signers[0]]}}), /does not match/);
  assert.throws(() => observedSignerSet({stacker_set: {signers: [
    {signing_key: key(1), weight: 1}, {signing_key: key(1), weight: 1},
  ]}}), /duplicate observed/);
  assert.throws(() => declaredSignerSet({actors: [{
    service: 'signer-1', role: 'signer', signerIndex: 1, signerPublicKey: 'bad', signerWeight: 1,
  }]}), /compressed secp256k1/);
});
