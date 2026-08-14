import assert from 'node:assert/strict';
import test from 'node:test';

import {StacksPublicDataClient} from './public_chain.js';

const key = '02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c';

test('loads current public signer weights while retaining a pending next cycle', async () => {
  const fetcher: typeof fetch = async input => {
    const path = new URL(String(input)).pathname;
    if (path === '/v2/pox') {
      return Response.json({
        current_burnchain_block_height: 496,
        current_epoch: 'Epoch40',
        current_cycle: {id: 24},
        next_cycle: {id: 25},
      });
    }
    if (path === '/v3/stacker_set/24') {
      return Response.json({stacker_set: {signers: [
        {signing_key: key, stacked_amt: 300_000_000_000, weight: 15},
      ]}});
    }
    return Response.json({err_type: 'not_available_try_again'}, {status: 400});
  };
  const snapshot = await new StacksPublicDataClient('http://node.invalid', 2_000, fetcher).snapshot(1_800_000_000_000);
  assert.equal(snapshot.health, 'healthy');
  assert.equal(snapshot.signers[0]?.publicKey, key);
  assert.equal(snapshot.signers[0]?.weight, 15);
  assert.equal(snapshot.rewardCycles.find(cycle => cycle.id === 25)?.status, 'pending');
});
