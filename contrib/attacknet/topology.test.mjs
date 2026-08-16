import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

import {buildTopology, renderTopology} from './topology.mjs';

test('--help is read-only and documents trusted probes', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-topology-help-'));
  const script = resolve('contrib/attacknet/topology.mjs');
  const result = spawnSync(process.execPath, [script, '--help'], {cwd: root, encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--probes=true\|false/);
  assert.match(result.stdout, /--actor-image=ACTOR=IMAGE/);
  assert.equal(existsSync(join(root, 'generated')), false);
});

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

test('trusted probes are default-off and explicitly parameterized for Kubernetes', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-probes-'));
  const disabled = renderTopology(buildTopology(), output).resource;
  assert.deepEqual(disabled.spec.probe, {
    enabled: false, image: 'stacks-hacknet-probe:dev', imagePullPolicy: 'IfNotPresent',
  });
  const enabled = renderTopology(buildTopology(), output, {
    probes: true, probeImage: 'registry.local/attacknet-probe:sha-123',
  }).resource;
  assert.deepEqual(enabled.spec.probe, {
    enabled: true, image: 'registry.local/attacknet-probe:sha-123', imagePullPolicy: 'IfNotPresent',
  });
});

test('admitted topology carries authoritative signer ownership and weight', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-signer-weights-'));
  const {resource, manifest} = renderTopology(buildTopology({signerCount: 4}), output);
  for (const index of [1, 2, 3, 4]) {
    const weight = Math.floor((((index - 1) % 3) + 1) * 1.5);
    for (const name of [`signer-${index}`, `signer-node-${index}`]) {
      const admitted = resource.spec.actors.find(actor => actor.name === name);
      const recorded = manifest.actors.find(actor => actor.service === name);
      assert.deepEqual(
        {index: admitted.signerIndex, weight: admitted.signerWeight},
        {index, weight},
      );
      assert.deepEqual(
        {index: recorded.signerIndex, weight: recorded.signerWeight},
        {index, weight},
      );
      assert.match(admitted.signerPublicKey, /^(02|03)[0-9a-f]{64}$/);
      assert.equal(recorded.signerPublicKey, admitted.signerPublicKey);
    }
  }
});

test('declared full signer weights match the deterministic PoX reward set', () => {
  const topology = buildTopology({signerCount: 10});
  const signers = topology.actors.filter(actor => actor.role === 'signer');
  assert.deepEqual(signers.map(actor => actor.signerWeight), [1, 3, 4, 1, 3, 4, 1, 3, 4, 1]);
  assert.equal(signers.reduce((total, actor) => total + actor.signerWeight, 0), 25);
  assert.equal(new Set(signers.map(actor => actor.signerPublicKey)).size, 10);
  for (const signer of signers) {
    const companion = topology.actors.find(actor => actor.name === `signer-node-${signer.signerIndex}`);
    assert.equal(companion.signerWeight, signer.signerWeight);
  }
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

test('stacker execution is explicit and readiness proves its status contract', () => {
  const topology = buildTopology({minerCount: 1, signerCount: 1, followerCount: 1});
  const output = mkdtempSync(join(tmpdir(), 'attacknet-stacker-contract-'));
  const stacker = renderTopology(topology, output).resource.spec.actors
    .find(actor => actor.name === 'stacker');
  assert.deepEqual(stacker.command, ['npx', 'tsx', '/stacker/stacking.ts']);
  assert.deepEqual(stacker.readinessProbe.exec.command,
    ['test', '-s', '/tmp/attacknet-stacker-status.json']);
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
  assert.match(miner.config.files['config.toml'], /inv_sync_interval = 5/);
  assert.match(miner.config.files['config.toml'], /download_interval = 1/);
  assert.match(miner.config.files['configure-node.sh'], /hostname -i/);
});

test('every node receives deterministic diverse non-self bootstrap identities', () => {
  const topology = buildTopology({minerCount: 3, signerCount: 10, followerCount: 5});
  const nodes = topology.actors.filter(actor => actor.role !== 'signer');
  for (const actor of nodes) {
    assert.equal(
      actor.runtimeExposure,
      'reachable',
      `${actor.name} must publish a resolvable endpoint before readiness`,
    );
    const match = actor.config.files['config.toml'].match(/^bootstrap_node = "([^"]+)"$/m);
    assert.ok(match, `${actor.name} must have bootstrap peers`);
    const peers = match[1].split(',');
    assert.equal(peers.length, 3, `${actor.name} bootstrap count`);
    assert.equal(new Set(peers).size, peers.length, `${actor.name} bootstrap identities are unique`);
    assert.equal(
      peers.some(peer => peer.endsWith(`@\${SERVICE:${actor.name}}:20444`)),
      false,
      `${actor.name} must not bootstrap to itself`,
    );
  }

  const miner = nodes.find(actor => actor.name === 'miner-1');
  assert.match(miner.config.files['config.toml'], /\$\{SERVICE:follower-1\}:20444/);
  assert.match(miner.config.files['config.toml'], /\$\{SERVICE:follower-2\}:20444/);
  const follower = nodes.find(actor => actor.name === 'follower-1');
  assert.match(follower.config.files['config.toml'], /\$\{SERVICE:miner-1\}:20444/);
  assert.match(follower.config.files['config.toml'], /\$\{SERVICE:follower-2\}:20444/);
});

test('small topology bootstrap adapts without self references', () => {
  const topology = buildTopology({minerCount: 1, signerCount: 1, followerCount: 0});
  for (const actor of topology.actors.filter(actor => actor.role !== 'signer')) {
    const match = actor.config.files['config.toml'].match(/^bootstrap_node = "([^"]+)"$/m);
    assert.ok(match, `${actor.name} must retain one recovery peer`);
    const peers = match[1].split(',');
    assert.equal(peers.length, 1);
    assert.equal(peers[0].endsWith(`@\${SERVICE:${actor.name}}:20444`), false);
  }
});

test('companion waits for the signer event socket without creating a dependency cycle', () => {
  const actors = buildTopology().actors;
  const signer = actors.find(actor => actor.name === 'signer-1');
  const companion = actors.find(actor => actor.name === 'signer-node-1');
  assert.deepEqual(signer.dependencies, []);
  assert.match(signer.readinessProbe.exec.command[2], /stacks_signer_runloop_ready 1/);
  assert.match(signer.readinessProbe.exec.command[2],
    /stacks_signer_registered_for_current_reward_cycle 1/);
  assert.equal(signer.runtimeExposure, 'reachable');
  assert.deepEqual(
    companion.dependencies.find(item => item.actor === 'signer-1'),
    {actor: 'signer-1', port: 30000},
  );
});

test('legacy signer companions subscribe to miner and signer StackerDBs', () => {
  const actors = buildTopology({signerCount: 2}).actors;
  for (const companion of actors.filter(actor => actor.role === 'companion')) {
    assert.match(companion.config.files['config.toml'], /^miner = false$/m);
    assert.match(companion.config.files['config.toml'], /^stacker = true$/m);
  }
  const follower = actors.find(actor => actor.role === 'follower');
  assert.match(follower.config.files['config.toml'], /^stacker = false$/m);
});

test('bootstrap suppresses companion observers and signers until the reward set is frozen', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-observer-bootstrap-'));
  const {resource, bootstrapResource} = renderTopology(buildTopology({signerCount: 2}), output);
  for (const name of ['signer-node-1', 'signer-node-2']) {
    const finalConfig = resource.spec.actors.find(actor => actor.name === name).config.files['config.toml'];
    const bootstrapConfig = bootstrapResource.spec.actors.find(actor => actor.name === name).config.files['config.toml'];
    assert.match(finalConfig, /\[\[events_observer\]\]/);
    assert.doesNotMatch(bootstrapConfig, /\[\[events_observer\]\]/);
    assert.equal(
      bootstrapResource.spec.actors.find(actor => actor.name === name)
        .dependencies.some(item => item.actor.startsWith('signer-')),
      false,
    );
  }
  for (const name of ['signer-1', 'signer-2']) {
    assert.equal(resource.spec.actors.find(actor => actor.name === name).suspended, undefined);
    assert.equal(bootstrapResource.spec.actors.find(actor => actor.name === name).suspended, true);
  }
  assert.deepEqual(
    JSON.parse(readFileSync(join(output, 'stacksnetwork.bootstrap.json'), 'utf8')),
    bootstrapResource,
  );
  const bootstrapCompose = JSON.parse(readFileSync(join(output, 'compose.bootstrap.yaml'), 'utf8'));
  assert.equal(bootstrapCompose.services['signer-1'], undefined);
  assert.equal(bootstrapCompose.services['signer-2'], undefined);
  assert.equal(bootstrapCompose.services['signer-node-1'].depends_on?.['signer-1'], undefined);
  assert.doesNotMatch(
    readFileSync(join(output, bootstrapCompose.services['signer-node-1'].volumes[0].split(':')[0]), 'utf8'),
    /\[\[events_observer\]\]/,
  );
});

test('burnchain cadence is initially paused until the topology is ready', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-paused-clock-'));
  renderTopology(buildTopology(), output);
  assert.match(readFileSync(join(output, 'policy.env'), 'utf8'), /^MODE=pause$/m);
  assert.match(readFileSync(join(output, 'policy.env'), 'utf8'), /^INTERVAL_SECONDS=60$/m);
  const compose = JSON.parse(readFileSync(join(output, 'compose.yaml'), 'utf8'));
  const healthcheck = compose.services['bitcoin-miner'].healthcheck;
  assert.deepEqual(healthcheck.test.slice(0, 3), ['CMD', 'perl', '-MIO::Socket::INET']);
  assert.match(healthcheck.test[4], /PeerPort=>18500/);
  assert.doesNotMatch(healthcheck.test.join(' '), /curl/);
});

test('Compose renders enrolled telemetry and an independently partitionable burnchain path', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-compose-harness-'));
  renderTopology(buildTopology({minerCount: 1, signerCount: 2, followerCount: 1}), output,
    {network: 'compose-proof'});
  const compose = JSON.parse(readFileSync(join(output, 'compose.yaml'), 'utf8'));
  const telemetry = JSON.parse(readFileSync(join(output, 'compose.observability.yaml'), 'utf8'));
  const prometheus = JSON.parse(readFileSync(join(output, 'prometheus.compose.yml'), 'utf8'));
  assert.deepEqual(compose.services.bitcoin.networks, ['burnchain']);
  assert.deepEqual(compose.services['follower-1'].networks, ['default', 'burnchain']);
  assert.deepEqual(compose.services['signer-1'].networks, undefined);
  assert.equal(telemetry.services.prometheus.image, 'prom/prometheus:v3.5.0');
  const targets = prometheus.scrape_configs.flatMap(job => job.static_configs);
  assert.deepEqual(targets.map(target => target.labels.attacknet_actor).sort(),
    ['follower-1', 'miner-1', 'signer-1', 'signer-2', 'signer-node-1', 'signer-node-2']);
  assert.ok(targets.every(target => target.labels.attacknet_network === 'compose-proof'));
});

test('Compose phase transition only changes companion config mounts and adds signers', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-compose-phases-'));
  renderTopology(buildTopology({minerCount: 1, signerCount: 2, followerCount: 1}), output);
  const bootstrap = JSON.parse(readFileSync(join(output, 'compose.bootstrap.yaml'), 'utf8'));
  const final = JSON.parse(readFileSync(join(output, 'compose.yaml'), 'utf8'));
  for (const actor of ['bitcoin', 'bitcoin-miner', 'stacker', 'miner-1', 'follower-1']) {
    assert.deepEqual(bootstrap.services[actor], final.services[actor], `${actor} must not roll`);
  }
  assert.equal(bootstrap.services['signer-1'], undefined);
  assert.match(bootstrap.services['signer-node-1'].volumes.join(' '), /configs-bootstrap/);
  assert.match(final.services['signer-node-1'].volumes.join(' '), /\.\/configs\//);
});

test('manifest exposes deterministic protocol phase barriers', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-protocol-phases-'));
  const {manifest} = renderTopology(buildTopology(), output);
  assert.deepEqual(manifest.protocol, {
    burnchainBootstrapHeight: 202,
    signerEnrollmentHeight: 208,
    signerSetCutoffHeight: 215,
    observerEnableHeight: 220,
    signerRegistrationHeight: 222,
    nakamotoActivationHeight: 223,
    steadyBurnIntervalSeconds: 60,
  });
  assert.equal(manifest.workloads.find(actor => actor.service === 'signer-1').stacksAddress,
    'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H');
});

test('Compose and Kubernetes renderers preserve workload identity, commands, dependencies, and config', () => {
  const composeExpand = value => value
    .replaceAll('${NETWORK}', 'attacknet')
    .replaceAll('${NAMESPACE}', 'compose')
    .replaceAll(/\$\{SERVICE:([a-z][-a-z0-9]*[a-z0-9])\}/g, '$1');
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
  for (const actor of resource.spec.actors) {
    const service = compose.services[actor.name];
    assert.equal(service.image, actor.image, `${actor.name} image`);
    assert.deepEqual(service.entrypoint, actor.command, `${actor.name} command`);
    assert.deepEqual(service.command, actor.args, `${actor.name} args`);
    assert.deepEqual(
      service.environment,
      Object.fromEntries((actor.env ?? []).map(item => [item.name, composeExpand(item.value)])),
      `${actor.name} environment`,
    );
    assert.deepEqual(
      Object.keys(service.depends_on ?? {}).sort(),
      (actor.dependencies ?? []).map(item => item.actor).sort(),
      `${actor.name} dependencies`,
    );
    for (const [filename, source] of Object.entries(actor.config?.files ?? {})) {
      const mount = service.volumes.find(item => item.includes(`/${actor.name}/${filename}:`));
      assert.ok(mount, `${actor.name} ${filename} mount`);
      const rendered = readFileSync(join(output, mount.split(':')[0]), 'utf8');
      const expected = composeExpand(source);
      assert.equal(rendered, expected, `${actor.name} ${filename} contents`);
    }
    if (actor.storage?.enabled) {
      assert.ok(service.volumes.includes(`${actor.name}-data:${actor.storage.mountPath}`));
    }
  }
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

test('per-actor environment expresses bounded adversarial behavior without affecting peers', () => {
  const topology = buildTopology({
    signerCount: 2,
    actorEnvs: {'signer-2': [{name: 'STACKS_SIGNER_TEST_DIRECTIVE', value: 'reject-all'}]},
  });
  assert.deepEqual(topology.actors.find(actor => actor.name === 'signer-2').env, [
    {name: 'RUST_LOG', value: 'info'},
    {name: 'STACKS_SIGNER_TEST_DIRECTIVE', value: 'reject-all'},
  ]);
  assert.deepEqual(topology.actors.find(actor => actor.name === 'signer-1').env, [{name: 'RUST_LOG', value: 'info'}]);
  assert.throws(() => buildTopology({actorEnvs: {'signer-9': [{name: 'SAFE', value: '1'}]}}), /unknown actor/);
  assert.throws(() => buildTopology({actorEnvs: {'signer-1': [{name: 'RUST_LOG', value: 'trace'}]}}), /already defined/);
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
