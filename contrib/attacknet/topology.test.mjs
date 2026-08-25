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

test('zero-signer topologies omit signer workloads and the unused stacker', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-zero-signers-'));
  const topology = buildTopology({minerCount: 1, signerCount: 0, followerCount: 1});
  const {resource, manifest} = renderTopology(topology, output);
  assert.equal(topology.signers.length, 0);
  assert.equal(resource.spec.actors.some(actor => actor.role === 'signer'), false);
  assert.equal(resource.spec.actors.some(actor => actor.role === 'companion'), false);
  assert.equal(resource.spec.actors.some(actor => actor.name === 'stacker'), false);
  assert.equal(manifest.workloads.length, 4);

  const cliOutput = mkdtempSync(join(tmpdir(), 'attacknet-zero-signers-cli-'));
  const result = spawnSync(process.execPath, [resolve('contrib/attacknet/topology.mjs'),
    '--miners=1', '--signers=0', '--followers=1', `--output=${cliOutput}`], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Rendered 4 workloads/);
});

test('full topology is 28 protocol actors plus three bootstrap workloads', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-topology-'));
  const topology = buildTopology({minerCount: 3, signerCount: 10, followerCount: 5});
  const {resource, manifest} = renderTopology(topology, output);
  assert.equal(manifest.actors.length, 28);
  assert.equal(manifest.workloads.length, 31);
  assert.equal(resource.spec.actors.length, 31);
  assert.deepEqual(manifest.counts, {miners: 3, signers: 10, followers: 5});
  for (const retiredArtifact of [
    'compose.yaml', 'compose.bootstrap.yaml', 'compose.observability.yaml',
    'prometheus.compose.yml',
  ]) {
    assert.equal(existsSync(join(output, retiredArtifact)), false, retiredArtifact);
  }
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
    additionalServices: [{
      name: 'attacknet-prometheus', serviceName: 'attacknet-attacknet-prometheus',
      ports: [{name: 'http', port: 9090}],
    }],
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
  assert.match(follower.config.files['config.toml'], /\$\{SERVICE:follower-2\}:20444/);

  const alwaysOn = new Set(['miner-1', ...Array.from({length: 5}, (_, index) => `follower-${index + 1}`)]);
  const selectedBy = new Map([...alwaysOn].map(actor => [actor, 0]));
  for (const actor of nodes) {
    const peers = actor.config.files['config.toml']
      .match(/^bootstrap_node = "([^"]+)"$/m)[1]
      .split(',')
      .map(peer => peer.match(/\$\{SERVICE:([^}]+)\}/)[1]);
    assert.equal(peers.every(peer => alwaysOn.has(peer)), true, `${actor.name} bootstrap peers must be always-on`);
    for (const peer of peers) selectedBy.set(peer, selectedBy.get(peer) + 1);
  }
  assert.deepEqual(
    [...selectedBy.values()],
    [...alwaysOn].map(() => 9),
    'rotated selection must distribute full-topology dials evenly across always-on bootstrap nodes',
  );
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

test('healthy topology makes queued event delivery explicit and retains blocking as a scenario knob', () => {
  const queued = buildTopology({signerCount: 1});
  for (const actor of queued.actors.filter(actor => actor.role !== 'signer')) {
    assert.match(actor.config.files['config.toml'], /^event_dispatcher_blocking = false$/m);
    assert.match(actor.config.files['config.toml'], /^event_dispatcher_queue_size = 1000$/m);
    assert.equal(actor.eventDispatchMode, 'queued');
  }
  const blocking = buildTopology({signerCount: 1, eventDispatchMode: 'blocking'});
  assert.match(blocking.actors.find(actor => actor.role === 'companion').config.files['config.toml'],
    /^event_dispatcher_blocking = true$/m);
  assert.throws(() => buildTopology({eventDispatchMode: 'implicit'}), /queued or blocking/);
});

test('rendered actors declare instrumentation profile, provenance, image, and dispatch mode', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-instrumentation-profile-'));
  const {manifest, resource} = renderTopology(buildTopology({
    instrumentationProfile: 'patched-main', instrumentationProvenance: 'attacknet-patch',
    actorInstrumentation: {'signer-1': 'release:unavailable'},
  }), output);
  const miner = manifest.actors.find(actor => actor.service === 'miner-1');
  assert.deepEqual(miner.instrumentation, {profile: 'patched-main', provenance: 'attacknet-patch'});
  assert.equal(miner.eventDispatchMode, 'queued');
  assert.equal(miner.requestedImage, 'stacks-core-attacknet:main');
  assert.deepEqual(manifest.actors.find(actor => actor.service === 'signer-1').instrumentation,
    {profile: 'release', provenance: 'unavailable'});
  assert.equal(manifest.protocol.eventDispatchMode, 'queued');
  assert.equal(resource.spec.actors.some(actor => actor.instrumentation || actor.eventDispatchMode), false,
    'capability declarations must not leak into the strict StacksNetwork CRD actor schema');
  const mixed = renderTopology(buildTopology({
    instrumentationProfile: 'partial-main', instrumentationProvenance: 'mixed',
  }), mkdtempSync(join(tmpdir(), 'attacknet-mixed-instrumentation-')));
  assert.deepEqual(mixed.manifest.actors.find(actor => actor.service === 'miner-1').instrumentation,
    {profile: 'partial-main', provenance: 'mixed'});
  assert.deepEqual(mixed.manifest.workloads.find(actor => actor.service === 'bitcoin').instrumentation,
    {profile: 'unmodified', provenance: 'unavailable'});
  assert.throws(() => buildTopology({actorInstrumentation: {bitcoin: 'partial-main:mixed'}}),
    /unknown actor/);
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
});

test('burnchain cadence is initially paused until the topology is ready', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-paused-clock-'));
  const {resource} = renderTopology(buildTopology(), output);
  assert.match(readFileSync(join(output, 'policy.env'), 'utf8'), /^MODE=pause$/m);
  assert.match(readFileSync(join(output, 'policy.env'), 'utf8'), /^INTERVAL_SECONDS=60$/m);
  assert.deepEqual(resource.spec.actors.find(actor => actor.name === 'bitcoin-miner').readinessProbe, {
    httpGet: {path: '/', port: 'bootstrap'},
    periodSeconds: 2,
    failureThreshold: 60,
  });
});

test('node actors receive isolated hot-reloadable realtime policies', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-clock-policy-'));
  const {resource, clockPolicy} = renderTopology(
    buildTopology({minerCount: 1, signerCount: 2, followerCount: 1}), output,
    {network: 'clock-proof'},
  );
  const clockActors = resource.spec.actors
    .filter(actor => ['miner', 'companion', 'follower', 'adversary'].includes(actor.role));
  assert.deepEqual(Object.keys(clockPolicy.data).sort(), clockActors.map(actor => actor.name).sort());
  assert.ok(Object.values(clockPolicy.data).every(value => value === '+0s\n'));
  assert.equal(clockPolicy.metadata.name, 'clock-proof-clock-policy');

  for (const actor of clockActors) {
    assert.deepEqual(actor.runtimePolicy, {
      configMapRef: {name: 'clock-proof-clock-policy'}, mountPath: '/run/attacknet-clock',
    });
    const environment = Object.fromEntries(actor.env.map(item => [item.name, item.value]));
    assert.equal(environment.LD_PRELOAD, '/usr/lib/stacks-attacknet/libfaketime.so.1');
    assert.equal(environment.FAKETIME_TIMESTAMP_FILE, `/run/attacknet-clock/${actor.name}`);
    assert.equal(environment.FAKETIME_DONT_FAKE_MONOTONIC, '1');
    assert.equal(environment.FAKETIME_NO_CACHE, '1');
  }
  const signer = resource.spec.actors.find(actor => actor.name === 'signer-1');
  assert.equal(signer.runtimePolicy, undefined, 'signers lack a process-clock metric today');
});

test('Kubernetes phase transition only changes signer-node configuration and signer suspension', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-kubernetes-phases-'));
  const {resource: final, bootstrapResource: bootstrap} = renderTopology(
    buildTopology({minerCount: 1, signerCount: 2, followerCount: 1}), output,
  );
  for (const actor of ['bitcoin', 'bitcoin-miner', 'stacker', 'miner-1', 'follower-1']) {
    assert.deepEqual(
      bootstrap.spec.actors.find(candidate => candidate.name === actor),
      final.spec.actors.find(candidate => candidate.name === actor),
      `${actor} must not roll`,
    );
  }
  assert.equal(bootstrap.spec.actors.find(actor => actor.name === 'signer-1').suspended, true);
  assert.equal(final.spec.actors.find(actor => actor.name === 'signer-1').suspended, undefined);
  assert.doesNotMatch(
    bootstrap.spec.actors.find(actor => actor.name === 'signer-node-1').config.files['config.toml'],
    /\[\[events_observer\]\]/,
  );
  assert.match(
    final.spec.actors.find(actor => actor.name === 'signer-node-1').config.files['config.toml'],
    /\[\[events_observer\]\]/,
  );
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
    eventDispatchMode: 'queued',
  });
  assert.equal(manifest.workloads.find(actor => actor.service === 'signer-1').stacksAddress,
    'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H');
});

test('Kubernetes renderer preserves workload identity and requested images', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-kubernetes-renderer-'));
  const {resource, manifest} = renderTopology(
    buildTopology({minerCount: 2, signerCount: 3, followerCount: 2}),
    output,
  );
  assert.deepEqual(
    manifest.workloads.map(actor => actor.service).sort(),
    resource.spec.actors.map(actor => actor.name).sort(),
  );
  for (const actor of resource.spec.actors) {
    const workload = manifest.workloads.find(candidate => candidate.service === actor.name);
    assert.equal(workload.requestedImage, actor.image, `${actor.name} image`);
    assert.equal(workload.role, actor.role, `${actor.name} role`);
  }
  assert.deepEqual(JSON.parse(readFileSync(join(output, 'stacksnetwork.json'), 'utf8')), resource);
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

test('Kubernetes renderer preserves delayed-miner activation discovery', () => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-activation-discovery-'));
  renderTopology(buildTopology({minerCount: 2}), output, {network: 'scope-a'});
  const resource = JSON.parse(readFileSync(join(output, 'stacksnetwork.json'), 'utf8'));
  assert.equal(resource.spec.actors.find(actor => actor.name === 'miner-2')
    .env.find(item => item.name === 'NAKAMOTO_SOURCE_HOST').value, '${SERVICE:miner-1}');
});
