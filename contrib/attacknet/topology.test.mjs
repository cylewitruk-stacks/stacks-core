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
  assert.equal(manifest.workloads.length, 31);
  assert.equal(resource.spec.actors.length, 31);
  assert.deepEqual(manifest.counts, {miners: 3, signers: 10, followers: 5});
});

test('every stacker key is paired with the same address funded at genesis', () => {
  const topology = buildTopology({signerCount: 10});
  const output = mkdtempSync(join(tmpdir(), 'attacknet-address-fixtures-'));
  const {resource} = renderTopology(topology, output);
  const stacker = resource.spec.actors.find(actor => actor.name === 'stacker');
  const expected = stacker.env.find(item => item.name === 'STACKING_ADDRESSES').value.split(',');
  assert.deepEqual(expected, topology.signers.map(([, address]) => address));
  // This tenth fixture caused the first full-cluster chain stall. Keep its
  // independently-derived address explicit so a copied typo cannot regress.
  assert.equal(expected[9], 'ST3MWT31K0SX74MHJCEWGZY5MR05X61FC5HEVK3W1');
  for (const actor of topology.actors.filter(actor => actor.role === 'miner')) {
    const config = actor.config.files['config.toml'];
    for (const address of expected) assert.match(config, new RegExp(`address = "${address}"`));
  }
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

test('nodes advertise their runtime container address rather than a DNS socket', () => {
  const topology = buildTopology();
  const miner = topology.actors.find(actor => actor.name === 'miner-1');
  assert.equal(miner.command[1], '/etc/stacks/configure-node.sh');
  assert.match(miner.config.files['config.toml'], /p2p_address = "__NODE_IP__:20444"/);
  assert.match(miner.config.files['config.toml'], /data_url = "http:\/\/__NODE_IP__:20443"/);
  assert.match(miner.config.files['config.toml'], /public_ip_address = "__NODE_IP__:20444"/);
  assert.match(miner.config.files['config.toml'], /private_neighbors = true/);
  assert.match(miner.config.files['configure-node.sh'], /hostname -i/);
});

test('signer starts concurrently with its companion to avoid an event-delivery cycle', () => {
  const signer = buildTopology().actors.find(actor => actor.name === 'signer-1');
  assert.deepEqual(signer.dependencies, []);
  assert.equal(signer.runtimeExposure, 'reachable');
});

test('burnchain cadence is initially paused until the topology is ready', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-paused-clock-'));
  renderTopology(buildTopology(), output);
  assert.match(readFileSync(join(output, 'policy.env'), 'utf8'), /^MODE=pause$/m);
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

test('post-Nakamoto miners are activation-gated in the manifest but not the CRD', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-activation-gate-'));
  const {resource, manifest} = renderTopology(buildTopology({minerCount: 3}), output);
  assert.equal(manifest.workloads.find(actor => actor.service === 'miner-1').activationGate, undefined);
  assert.deepEqual(manifest.workloads.find(actor => actor.service === 'miner-2').activationGate,
    {kind: 'burn-height', height: 223});
  const delayedMiner = resource.spec.actors.find(actor => actor.name === 'miner-2');
  assert.equal(delayedMiner.activationGate, undefined);
  assert.equal(delayedMiner.env.find(item => item.name === 'NAKAMOTO_SOURCE_HOST').value,
    '${SERVICE:miner-1}');
});

test('renderers resolve delayed-miner activation discovery for each backend', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-activation-discovery-'));
  renderTopology(buildTopology({minerCount: 2}), output, {network: 'scope-a'});
  const compose = JSON.parse(readFileSync(join(output, 'compose.yaml'), 'utf8'));
  assert.equal(compose.services['miner-2'].environment.NAKAMOTO_SOURCE_HOST, 'miner-1');
  const resource = JSON.parse(readFileSync(join(output, 'stacksnetwork.json'), 'utf8'));
  assert.equal(resource.spec.actors.find(actor => actor.name === 'miner-2')
    .env.find(item => item.name === 'NAKAMOTO_SOURCE_HOST').value, '${SERVICE:miner-1}');
});
