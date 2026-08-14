import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {buildTopology, renderTopology} from './topology.mjs';

test('stage topology derives actor inventory from requested counts', () => {
  const topology = buildTopology({minerCount: 2, signerCount: 4, followerCount: 2});
  assert.equal(topology.actors.filter(actor => actor.role === 'miner').length, 2);
  assert.equal(topology.actors.filter(actor => actor.role === 'companion').length, 4);
  assert.equal(topology.actors.filter(actor => actor.role === 'signer').length, 4);
  assert.equal(topology.actors.filter(actor => actor.role === 'follower').length, 2);
});

test('full topology is 28 protocol actors plus three bootstrap workloads', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-topology-'));
  const topology = buildTopology({minerCount: 3, signerCount: 10, followerCount: 5});
  const {resource, manifest} = renderTopology(topology, output);
  assert.equal(manifest.actors.length, 28);
  assert.equal(resource.spec.actors.length, 31);
  assert.deepEqual(manifest.counts, {miners: 3, signers: 10, followers: 5});
});

test('mainnet profile contains legacy transport and current-main image only', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-main-profile-'));
  renderTopology(buildTopology(), output);
  const rendered = readFileSync(join(output, 'stacksnetwork.json'), 'utf8');
  assert.doesNotMatch(rendered, /libp2p/i);
  assert.match(rendered, /stacks-core-attacknet:main/);
  assert.match(rendered, /stackerdb/);
  assert.match(rendered, /\$\{SERVICE:bitcoin\}/);
});

test('Compose and Kubernetes renderers contain the same workload names', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-parity-'));
  const {resource} = renderTopology(
    buildTopology({minerCount: 2, signerCount: 3, followerCount: 2}),
    output,
  );
  const compose = JSON.parse(readFileSync(join(output, 'compose.yaml'), 'utf8'));
  assert.deepEqual(
    Object.keys(compose.services).sort(),
    resource.spec.actors.map(actor => actor.name).sort(),
  );
});

test('invalid counts fail before rendering', () => {
  assert.throws(() => buildTopology({minerCount: 0}), /minerCount/);
  assert.throws(() => buildTopology({signerCount: 11}), /signerCount/);
  assert.throws(() => buildTopology({followerCount: 6}), /followerCount/);
});

test('per-actor images express mixed-version and modified builds', () => {
  const topology = buildTopology({
    minerCount: 2,
    signerCount: 2,
    actorImages: {'miner-2': 'stacks:v4.0.2', 'signer-2': 'stacks:malicious'},
  });
  assert.equal(topology.actors.find(actor => actor.name === 'miner-1').image, 'stacks-core-attacknet:main');
  assert.equal(topology.actors.find(actor => actor.name === 'miner-2').image, 'stacks:v4.0.2');
  assert.equal(topology.actors.find(actor => actor.name === 'signer-2').image, 'stacks:malicious');
  assert.throws(() => buildTopology({actorImages: {'signer-9': 'stacks:old'}}), /unknown actor/);
});
