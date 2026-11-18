import assert from 'node:assert/strict';
import test from 'node:test';

import type {PublicNetworkState} from '../shared/model.js';
import {projectPublicPortal} from './public_projection.js';

test('public projection is an explicit safe copy without enrollment or source metadata', () => {
  const key = '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c';
  const network: PublicNetworkState = {
    source: 'http://private-node.internal:20443',
    health: 'healthy',
    observedAt: '2026-08-09T12:00:00.000Z',
    currentEpoch: 'Epoch40',
    burnHeight: 300,
    currentRewardCycle: 15,
    nextRewardCycle: 16,
    rewardCycles: [{
      id: 15, phase: 'current', status: 'available', totalWeight: 15,
      totalStackedMicroStx: '300000000000', signerKeys: [key],
    }],
    signers: [{
      publicKey: key, entityName: 'Public signer', weight: 15,
      stackedAmountMicroStx: '300000000000', rewardCycles: [15],
      enrolledActorId: 'private-actor-id',
    }],
    error: 'private backend detail',
  };

  const projected = projectPublicPortal(network, 'regtest', Date.parse('2026-08-09T12:00:01.000Z'));
  const serialized = JSON.stringify(projected);
  assert.equal(projected.summary.totalWeight, 15);
  assert.equal(projected.publicNetwork.signers[0]?.entityName, 'Public signer');
  assert.doesNotMatch(serialized, /private-node|private-actor-id|private backend detail/);
  assert.doesNotMatch(serialized, /nodes|links|reporters|signerQuorumRounds/);
});
