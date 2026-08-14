import assert from 'node:assert/strict';
import test from 'node:test';

import {inventory} from './manifest-inventory.mjs';

const manifest = {actors: [
  {service: 'miner-1', type: 'node', role: 'miner'},
  {service: 'signer-node-1', type: 'node', role: 'companion'},
  {service: 'signer-1', type: 'signer', role: 'signer'},
  {service: 'follower-1', type: 'node', role: 'follower'},
]};

test('inventory derives every group from actor metadata', () => {
  assert.deepEqual(inventory(manifest, 'actors'), ['miner-1', 'signer-node-1', 'signer-1', 'follower-1']);
  assert.deepEqual(inventory(manifest, 'nodes'), ['miner-1', 'signer-node-1', 'follower-1']);
  assert.deepEqual(inventory(manifest, 'signers'), ['signer-1']);
  assert.deepEqual(inventory(manifest, 'companions'), ['signer-node-1']);
  assert.deepEqual(inventory(manifest, 'miners'), ['miner-1']);
  assert.deepEqual(inventory(manifest, 'followers'), ['follower-1']);
});
