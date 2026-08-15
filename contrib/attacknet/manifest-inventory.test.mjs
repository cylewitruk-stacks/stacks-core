import assert from 'node:assert/strict';
import test from 'node:test';

import {inventory} from './manifest-inventory.mjs';

const manifest = {actors: [
  {service: 'miner-1', type: 'node', role: 'miner'},
  {service: 'miner-2', type: 'node', role: 'miner', activationGate: {kind: 'burn-height', height: 223}},
  {service: 'signer-node-1', type: 'node', role: 'companion'},
  {service: 'signer-1', type: 'signer', role: 'signer'},
  {service: 'follower-1', type: 'node', role: 'follower'},
], workloads: [
  {service: 'bitcoin', type: 'infrastructure', role: 'burnchain'},
  {service: 'bitcoin-miner', type: 'infrastructure', role: 'infrastructure'},
  {service: 'stacker', type: 'infrastructure', role: 'infrastructure'},
  {service: 'miner-1', type: 'node', role: 'miner'},
  {service: 'miner-2', type: 'node', role: 'miner', activationGate: {kind: 'burn-height', height: 223}},
  {service: 'signer-node-1', type: 'node', role: 'companion'},
  {service: 'signer-1', type: 'signer', role: 'signer'},
  {service: 'follower-1', type: 'node', role: 'follower'},
]};

test('inventory derives every group from actor metadata', () => {
  assert.deepEqual(inventory(manifest, 'actors'), ['miner-1', 'miner-2', 'signer-node-1', 'signer-1', 'follower-1']);
  assert.deepEqual(inventory(manifest, 'nodes'), ['miner-1', 'miner-2', 'signer-node-1', 'follower-1']);
  assert.deepEqual(inventory(manifest, 'signers'), ['signer-1']);
  assert.deepEqual(inventory(manifest, 'companions'), ['signer-node-1']);
  assert.deepEqual(inventory(manifest, 'miners'), ['miner-1', 'miner-2']);
  assert.deepEqual(inventory(manifest, 'followers'), ['follower-1']);
  assert.deepEqual(inventory(manifest, 'bootstrap-foundation'), [
    'bitcoin', 'bitcoin-miner', 'stacker', 'miner-1', 'signer-node-1', 'follower-1',
  ]);
  assert.deepEqual(inventory(manifest, 'pre-activation-nodes'), [
    'miner-1', 'signer-node-1', 'follower-1',
  ]);
  assert.deepEqual(inventory(manifest, 'activation-gated'), ['miner-2']);
});
