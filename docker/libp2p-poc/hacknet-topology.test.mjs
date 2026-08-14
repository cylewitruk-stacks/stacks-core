import assert from 'node:assert/strict';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {renderHacknetTopology} from './hacknet-topology.mjs';
import {actorToken, buildTopology} from './topology.mjs';

test('renders the shared topology without rewriting semantic config values', () => {
  const output = mkdtempSync(join(tmpdir(), 'stacks-hacknet-render-'));
  const topology = buildTopology({signerCount: 2, minerCount: 2, followerCount: 1});
  const {resource, secret, policyConfigMap} = renderHacknetTopology(topology, output, {
    network: 'parity',
    namespace: 'attacknet-test',
    suspended: true,
  });

  assert.equal(resource.spec.actors.length, topology.actors.length + 6);
  assert.equal(resource.spec.suspended, true);
  assert.equal(resource.spec.actors.filter(actor => actor.role === 'signer').length, 2);
  assert.equal(resource.spec.actors.filter(actor => actor.role === 'companion').length, 2);

  const miner = resource.spec.actors.find(actor => actor.name === 'miner-1');
  const config = miner.config.files['config.toml'];
  assert.match(config, /chain = "bitcoin"/);
  assert.match(config, /allow_stale_bitcoin_tip = true/);
  assert.match(config, /wallet_name = "libp2p-poc-miner-1"/);
  assert.match(config, /peer_host = "\$\{SERVICE:bitcoin\}"/);
  assert.match(config, /advertise = \["\/dns4\/\$\{SERVICE:miner-1\}\//);
  assert.doesNotMatch(config, /chain = "\$\{SERVICE:bitcoin\}"/);

  for (const actor of topology.actors) {
    assert.equal(secret.stringData[actor.id], actorToken(actor.id));
    const workload = resource.spec.actors.find(item => item.name === actor.service);
    assert.equal(workload.telemetry.tokenSecretRef.key, actor.id);
  }
  const clock = resource.spec.actors.find(actor => actor.name === 'bitcoin-miner');
  assert.equal(clock.command.at(-1), '/opt/hacknet/burnchain-clock.sh');
  assert.equal(clock.runtimePolicy.configMapRef.name, 'parity-burnchain-policy');
  assert.equal(clock.env.some(item => item.name.startsWith('STACKS_')), false);
  assert.match(clock.config.files['burnchain-clock.sh'], /Deliberately Stacks-blind/);
  assert.equal(secret.metadata.name, 'parity-federation-tokens');
  assert.equal(policyConfigMap.metadata.name, 'parity-burnchain-policy');
  assert.match(policyConfigMap.data['policy.env'], /INTERVAL_SECONDS=20/);
});

test('maximum topology fits operator actor and service-port bounds', () => {
  const output = mkdtempSync(join(tmpdir(), 'stacks-hacknet-maximum-'));
  const topology = buildTopology({signerCount: 10, minerCount: 3, followerCount: 5});
  const {resource} = renderHacknetTopology(topology, output);
  assert.equal(topology.actors.length, 28);
  assert.equal(resource.spec.actors.length, 34);
  assert.ok(resource.spec.actors.length <= 100);
  const collector = resource.spec.actors.find(actor => actor.name === 'telemetry-collector');
  assert.equal(collector.ports.length, 30);
  assert.ok(collector.ports.length <= 32);
  assert.equal(new Set(resource.spec.actors.map(actor => actor.name)).size, 34);
});

test('mixed and malicious builds are selected per logical actor', () => {
  const output = mkdtempSync(join(tmpdir(), 'stacks-hacknet-images-'));
  const topology = buildTopology({signerCount: 2, minerCount: 2, followerCount: 1});
  const {resource} = renderHacknetTopology(topology, output, {
    actorImages: {
      'miner-2': 'registry.invalid/stacks-node:forgotten-upgrade',
      'signer-2': 'registry.invalid/stacks-signer:adversarial',
    },
  });
  assert.equal(resource.spec.actors.find(actor => actor.name === 'miner-1').image,
    'stacks-core-libp2p-poc:local');
  assert.equal(resource.spec.actors.find(actor => actor.name === 'miner-2').image,
    'registry.invalid/stacks-node:forgotten-upgrade');
  assert.equal(resource.spec.actors.find(actor => actor.name === 'signer-2').image,
    'registry.invalid/stacks-signer:adversarial');
  assert.throws(() => renderHacknetTopology(topology, output, {
    actorImages: {'not-an-actor': 'registry.invalid/nope:latest'},
  }), /unknown actor/);
});
