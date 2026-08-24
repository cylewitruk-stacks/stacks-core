#!/usr/bin/env node

import {createECDH} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const LIMITS = Object.freeze({miners: 3, signers: 10, followers: 5});
const CONTRACT_ACCOUNT = 'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H';
const GENESIS_BALANCE = 10_000_000_000_000_000n;

const SIGNERS = Object.freeze([
  ['41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc01', 'ST24VB7FBXCBV6P0SRDSPSW0Y2J9XHDXNHW9Q8S7H'],
  ['9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee01', 'ST2XAK68AR2TKBQBFNYSK9KN2AY9CVA91A7CSK63Z'],
  ['3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb7401', 'ST1J9R0VMA5GQTW65QVHW1KVSKD7MCGT27X37A551'],
  ['444444444444444444444444444444444444444444444444444444444444444401', 'ST361P1W3HRW7VTPD1S935RF8PJFMRAF4GJMPMQZN'],
  ['454545454545454545454545454545454545454545454545454545454545454501', 'ST1GY0T7R417K2Q2S17DJE3SVEMKRQ2EPJ4PGD5B8'],
  ['464646464646464646464646464646464646464646464646464646464646464601', 'ST2YS424BPZM2TR8TKEAFQDTA1441AAVR9ZP7K4S0'],
  ['474747474747474747474747474747474747474747474747474747474747474701', 'ST332XG8HFYG31EBQ2RWZ3R85AQ6VXTGXQHJYH0K5'],
  ['484848484848484848484848484848484848484848484848484848484848484801', 'ST2N5TCTPRMT6EXTFSCPTGBQ0K04B44H79XPH6YXS'],
  ['494949494949494949494949494949494949494949494949494949494949494901', 'ST64T36C5EABZ2T1Y6KWN03RSWAKJK59QHE2D83N'],
  ['4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a01', 'ST3MWT31K0SX74MHJCEWGZY5MR05X61FC5HEVK3W1'],
]);

const MINERS = Object.freeze([
  ['11', '044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1', 'n2PEoV6Abxnrpzoqqq1TJT5kw8G2dMPpBd', '19ec1c3e31d139c989a23a27eac60d1abfad5277d3ae9604242514c738258efa01'],
  ['12', '046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7eb1c2784a65901538479361e94c0a2597973adef0836a6a7eddf50b7997c88a3', 'n3BxbFxkvGbF9ANka8TXuihwKZBd9xaJVg', '616161616161616161616161616161616161616161616161616161616161616101'],
  ['13', '041d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599b6d846ca00fd42d38558d26a5ec4b91ae19bd68c5ab01497e0b57f52a2e0d5ef', 'mnZXRioUVq35tsCRk1DSoYUhwWaTGSz7a8', '626262626262626262626262626262626262626262626262626262626262626201'],
]);

const service = actor => `\${SERVICE:${actor}}`;
const repeated = byte => byte.repeat(32);

function parseCount(name, fallback, maximum) {
  const marker = `--${name}=`;
  const raw = process.argv.find(value => value.startsWith(marker))?.slice(marker.length) ?? String(fallback);
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${name} must be within [0, ${maximum}], received ${raw}`);
  }
  return value;
}

function option(name, fallback) {
  const marker = `--${name}=`;
  return process.argv.find(value => value.startsWith(marker))?.slice(marker.length) ?? fallback;
}

function repeatedMapOption(name) {
  const marker = `--${name}=`;
  return Object.fromEntries(process.argv.filter(value => value.startsWith(marker)).map(value => {
    const pair = value.slice(marker.length);
    const separator = pair.indexOf('=');
    if (separator < 1 || separator === pair.length - 1) {
      throw new Error(`${name} must use actor=image, received ${pair}`);
    }
    return [pair.slice(0, separator), pair.slice(separator + 1)];
  }));
}

function repeatedActorEnvOption() {
  const marker = '--actor-env=';
  const result = {};
  for (const argument of process.argv.filter(value => value.startsWith(marker))) {
    const binding = argument.slice(marker.length);
    const actorSeparator = binding.indexOf(':');
    const valueSeparator = binding.indexOf('=', actorSeparator + 1);
    if (actorSeparator < 1 || valueSeparator <= actorSeparator + 1) {
      throw new Error(`actor-env must use ACTOR:NAME=VALUE, received ${binding}`);
    }
    const actor = binding.slice(0, actorSeparator);
    const name = binding.slice(actorSeparator + 1, valueSeparator);
    const value = binding.slice(valueSeparator + 1);
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) throw new Error(`invalid actor environment name ${name}`);
    result[actor] ??= [];
    if (result[actor].some(entry => entry.name === name)) throw new Error(`duplicate actor environment ${actor}:${name}`);
    result[actor].push({name, value});
  }
  return result;
}

function usage() {
  return `usage: topology.mjs [options]

Options:
  --network=NAME             StacksNetwork name (default: attacknet)
  --namespace=NAME           Kubernetes namespace (default: hacknet-system)
  --miners=N                 miner count, 0-${LIMITS.miners} (default: 1)
  --signers=N                signer/companion pair count, 0-${LIMITS.signers} (default: 1)
  --followers=N              follower count, 0-${LIMITS.followers} (default: 1)
  --node-image=IMAGE         default Stacks node/signer image (default: stacks-core-attacknet:main)
  --stacker-image=IMAGE      dedicated stacking-client image (default: stacks-attacknet-stacker:local)
  --actor-image=ACTOR=IMAGE  per-actor image override; repeatable
  --actor-env=ACTOR:NAME=VALUE
                              per-actor environment value; repeatable
  --event-dispatch=queued|blocking
                              explicit node event-delivery mode (default: queued)
  --instrumentation-profile=ID
                              capability-manifest profile (default: unmodified)
  --instrumentation-provenance=merged|attacknet-patch|mixed|unavailable
                              default 22-family provenance (default: unavailable)
  --actor-instrumentation=ACTOR=PROFILE:PROVENANCE
                              per-actor capability override; repeatable
  --probes=true|false        add trusted fault-probe sidecars (default: false)
  --probe-image=IMAGE        trusted fault-probe image
  --output=DIR               rendered output directory
  --help                     print this text without rendering
`;
}

function legacyPublicKey(seedByte) {
  const key = createECDH('secp256k1');
  key.setPrivateKey(Buffer.from(repeated(seedByte), 'hex'));
  return key.getPublicKey('hex', 'compressed');
}

function signerPublicKey(signer) {
  const key = createECDH('secp256k1');
  // Stacks private-key strings append one compression byte to the 32-byte
  // secp256k1 scalar.  The reward-set endpoint publishes the corresponding
  // compressed public key.
  key.setPrivateKey(Buffer.from(signer[0].slice(0, 64), 'hex'));
  return key.getPublicKey('hex', 'compressed');
}

function epochsAndBalances(signers) {
  const epochs = [
    ['1.0', 0], ['2.0', 0], ['2.05', 203], ['2.1', 204], ['2.2', 206],
    ['2.3', 207], ['2.4', 208], ['2.5', 209], ['3.0', 223], ['3.1', 224],
    ['3.2', 225], ['3.3', 226], ['3.4', 227], ['4.0', 245],
  ].map(([name, height]) => `[[burnchain.epochs]]\nepoch_name = "${name}"\nstart_height = ${height}`);
  const balances = signers.map(([, address]) =>
    `[[ustx_balance]]\naddress = "${address}"\namount = ${GENESIS_BALANCE}`);
  return [...epochs, ...balances].join('\n\n');
}

function nodeConfig({name, seedByte, miner, minerIndex, signerIndex, signers, bootstrapPeers, eventDispatchMode}) {
  // On the current-main legacy transport, `stacker` is also the subscription
  // switch for the boot `.miners` and signer StackerDB replicas.  A signer
  // companion is not a miner, but it must set this flag or proposals can only
  // exist in the winning miner's local database and never reach the signer.
  const subscribesToSignerStackerDBs = miner || signerIndex !== undefined;
  const bootstrap = bootstrapPeers.length === 0 ? '' : `bootstrap_node = "${bootstrapPeers
    .map(peer => `${legacyPublicKey(peer.seedByte)}@${service(peer.name)}:20444`)
    .join(',')}"`;
  const observer = signerIndex === undefined ? '' : `
[[events_observer]]
endpoint = "${service(`signer-${signerIndex}`)}:30000"
events_keys = ["stackerdb", "block_proposal", "burn_blocks"]
`;
  const mining = miner ? `
[miner]
first_attempt_time_ms = 1000
subsequent_attempt_time_ms = 2000
block_commit_delay_ms = 1000
mining_key = "${MINERS[minerIndex][3]}"
block_reward_recipient = "STQM73RQC4EX0A07KWG1J5ECZJYBZS4SJ4ERC6WN"
activated_vrf_key_path = "/data/node/activated-vrf-key.json"
` : '';
  const wallet = miner ? `
wallet_name = "attacknet-miner-${minerIndex + 1}"
local_mining_public_key = "${MINERS[minerIndex][1]}"` : '';
  return `[node]
name = "attacknet-${name}"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
data_url = "http://__NODE_IP__:20443"
p2p_address = "__NODE_IP__:20444"
prometheus_bind = "0.0.0.0:20446"
working_dir = "/data/node"
seed = "${repeated(seedByte)}"
local_peer_seed = "${repeated(seedByte)}"
miner = ${miner}
stacker = ${subscribesToSignerStackerDBs}
event_dispatcher_blocking = ${eventDispatchMode === 'blocking'}
event_dispatcher_queue_size = 1000
use_test_genesis_chainstate = true
pox_5_sbtc_contract = "${CONTRACT_ACCOUNT}.sbtc-token"
pox_5_sbtc_registry_contract = "${CONTRACT_ACCOUNT}.sbtc-registry"
pox_sync_sample_secs = 0
wait_time_for_blocks = 0
wait_time_for_microblocks = 0
mine_microblocks = false
${bootstrap}
${mining}
[connection_options]
public_ip_address = "__NODE_IP__:20444"
private_neighbors = true
# The burnchain is intentionally time-compressed. Keep discovery and block
# inventory scans proportionally faster than their mainnet defaults while the
# StackerDB state machine continues to enforce the same authorization rules.
walk_interval = 5
inv_sync_interval = 5
download_interval = 1
auth_token = "12345"
${observer}
[burnchain]
chain = "bitcoin"
mode = "nakamoto-neon"
poll_time_secs = 1
magic_bytes = "T3"
pox_prepare_length = 5
pox_reward_length = 20
burn_fee_cap = 20000
peer_host = "${service('bitcoin')}"
peer_port = 18444
rpc_port = 18443
rpc_ssl = false
username = "devnet"
password = "devnet"
timeout = 30${wallet}

${epochsAndBalances(signers)}
`;
}

function signerConfig(index, signer) {
  return `stacks_private_key = "${signer[0]}"
node_host = "${service(`signer-node-${index}`)}:20443"
endpoint = "0.0.0.0:30000"
network = "testnet"
auth_password = "12345"
db_path = "/data/signer.sqlite"
metrics_endpoint = "0.0.0.0:31000"
event_timeout_ms = 250
`;
}

function env(name, value) {
  return {name, value: String(value)};
}

function signerConsensusWeight(index) {
  const targetSlots = ((index - 1) % 3) + 1;
  // The stacker deliberately locks 1.5 times the reported minimum per target
  // slot. Consensus assigns floor(amount / minimum) weight, so the admitted
  // weights are 1, 3, 4—not the input multipliers 1, 2, 3. Keep fault-safety
  // metadata aligned with the on-chain signer set.
  return Math.floor(targetSlots * 1.5);
}

function nodeActor({name, role, seedByte, miner = false, minerIndex, signerIndex, signers, image, bootstrapPeers, eventDispatchMode}) {
  const delayedMiner = miner && minerIndex > 0;
  const files = {
    'config.toml': nodeConfig({
      name, seedByte, miner, minerIndex, signerIndex, signers, bootstrapPeers, eventDispatchMode,
    }),
    'configure-node.sh': readFileSync(join(ROOT, 'configure-node.sh'), 'utf8'),
  };
  if (delayedMiner) files['join-after-nakamoto.sh'] = readFileSync(join(ROOT, 'join-after-nakamoto.sh'), 'utf8');
  const dependencies = [{actor: 'bitcoin', port: 18443}, {actor: 'bitcoin-miner', port: 18500}];
  if (name !== 'miner-1') dependencies.push({actor: 'miner-1', port: 20443});
  // A companion can replay historical burn-block observer events while it
  // catches up.  Its signer binds the event socket before initializing the
  // RPC-dependent runloop, so wait for that socket before starting IBD.  The
  // signer intentionally does not wait for the companion, which keeps this
  // ordering acyclic.
  if (role === 'companion') dependencies.push({actor: `signer-${signerIndex}`, port: 30000});
  return {
    name,
    role,
    ...(signerIndex === undefined ? {} : {
      signerIndex,
      signerWeight: signerConsensusWeight(signerIndex),
      signerPublicKey: signerPublicKey(signers[signerIndex - 1]),
    }),
    activationGate: delayedMiner ? {kind: 'burn-height', height: 223} : undefined,
    image,
    imagePullPolicy: 'IfNotPresent',
    // Stacks resolves every configured bootstrap hostname before the node RPC
    // endpoint can become Ready. Publish node endpoints while they are still
    // starting so reciprocal, diverse bootstrap lists cannot deadlock behind
    // Kubernetes readiness-gated DNS. This changes discovery only: init
    // dependency probes still require the requested TCP port to accept, and
    // Pod readiness continues to reflect /v2/info.
    runtimeExposure: 'reachable',
    command: delayedMiner
      ? ['/bin/bash', '/etc/stacks/configure-node.sh', '/bin/bash', '/etc/stacks/join-after-nakamoto.sh']
      : ['/bin/bash', '/etc/stacks/configure-node.sh', 'stacks-node', 'start', '--config', '/tmp/stacks-attacknet-config.toml'],
    config: {files, key: 'config.toml', mountPath: '/etc/stacks'},
    env: [
      env('RUST_LOG', 'info'),
      ...(delayedMiner ? [env('NAKAMOTO_SOURCE_HOST', service('miner-1'))] : []),
    ],
    dependencies,
    ports: [
      {name: 'rpc', containerPort: 20443},
      {name: 'p2p', containerPort: 20444},
      {name: 'metrics', containerPort: 20446},
    ],
    readinessProbe: {httpGet: {path: '/v2/info', port: 'rpc'}, periodSeconds: 5, failureThreshold: 90},
    startupProbe: {httpGet: {path: '/v2/info', port: 'rpc'}, periodSeconds: 5, failureThreshold: 180},
    storage: {enabled: true, size: '2Gi', mountPath: '/data'},
    resources: {requests: {cpu: '100m', memory: '256Mi'}, limits: {cpu: '4', memory: '4Gi'}},
  };
}

function signerActor(index, signer, image) {
  return {
    name: `signer-${index}`,
    role: 'signer',
    signerIndex: index,
    signerWeight: signerConsensusWeight(index),
    signerPublicKey: signerPublicKey(signer),
    image,
    imagePullPolicy: 'IfNotPresent',
    command: ['stacks-signer', 'run', '--config', '/etc/stacks/signer.toml'],
    // The event receiver binds before the RPC-dependent signer runloop starts.
    // This readiness check is therefore both meaningful and safe while the
    // companion waits on it; the signer itself must not wait on the companion.
    runtimeExposure: 'reachable',
    config: {files: {'signer.toml': signerConfig(index, signer)}, key: 'signer.toml', mountPath: '/etc/stacks'},
    env: [env('RUST_LOG', 'info')],
    dependencies: [],
    ports: [{name: 'events', containerPort: 30000}, {name: 'metrics', containerPort: 31000}],
    readinessProbe: {
      exec: {
        command: [
          '/bin/sh', '-c',
          "metrics=$(curl --fail --silent http://127.0.0.1:31000/metrics) && printf '%s\\n' \"$metrics\" | grep -q '^stacks_signer_runloop_ready 1$' && printf '%s\\n' \"$metrics\" | grep -q '^stacks_signer_registered_for_current_reward_cycle 1$'",
        ],
      },
      periodSeconds: 2,
      failureThreshold: 180,
    },
    storage: {enabled: true, size: '512Mi', mountPath: '/data'},
    resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '2', memory: '2Gi'}},
  };
}

export function buildTopology({minerCount = 1, signerCount = 1, followerCount = 1, nodeImage = 'stacks-core-attacknet:main', stackerImage = 'stacks-attacknet-stacker:local', actorImages = {}, actorEnvs = {}, eventDispatchMode = 'queued', instrumentationProfile = 'unmodified', instrumentationProvenance = 'unavailable', actorInstrumentation = {}} = {}) {
  if (minerCount < 1 || minerCount > LIMITS.miners) throw new Error('minerCount out of range');
  if (signerCount < 1 || signerCount > LIMITS.signers) throw new Error('signerCount out of range');
  if (followerCount < 0 || followerCount > LIMITS.followers) throw new Error('followerCount out of range');
  if (!['queued', 'blocking'].includes(eventDispatchMode)) throw new Error('eventDispatchMode must be queued or blocking');
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/.test(instrumentationProfile)) throw new Error('instrumentationProfile is invalid');
  if (!['merged', 'attacknet-patch', 'mixed', 'unavailable'].includes(instrumentationProvenance)) throw new Error('instrumentationProvenance is invalid');
  const signers = SIGNERS.slice(0, signerCount);
  const nodeIdentities = [
    ...Array.from({length: minerCount}, (_, index) => ({
      name: `miner-${index + 1}`, seedByte: MINERS[index][0],
    })),
    ...Array.from({length: signerCount}, (_, index) => ({
      name: `signer-node-${index + 1}`, seedByte: (0x21 + index).toString(16),
    })),
    ...Array.from({length: followerCount}, (_, index) => ({
      name: `follower-${index + 1}`, seedByte: (0x31 + index).toString(16),
    })),
  ];
  // Bootstrap is a recovery mechanism, not an architectural dependency on a
  // single privileged actor. Spread initial dials evenly across nodes that are
  // guaranteed to be listening throughout preactivation. Late companions and
  // activation-gated miners are deliberately excluded: a peer that misses one
  // of those listeners can fill its ordinary neighbor set and never retry the
  // missed bootstrap entry. Small topologies fall back to the complete node
  // set so every node still retains a non-self recovery peer.
  const alwaysOnBootstrap = [
    nodeIdentities.find(actor => actor.name === 'miner-1'),
    ...nodeIdentities.filter(actor => actor.name.startsWith('follower-')),
  ].filter(Boolean);
  const bootstrapOrder = alwaysOnBootstrap.length >= 2 ? alwaysOnBootstrap : nodeIdentities;
  const bootstrapPeersFor = name => {
    const position = nodeIdentities.findIndex(actor => actor.name === name);
    if (position < 0) throw new Error(`node identity ${name} is absent from topology`);
    const count = Math.min(3, bootstrapOrder.length - (bootstrapOrder.some(actor => actor.name === name) ? 1 : 0));
    const peers = [];
    for (let offset = 0; peers.length < count; offset += 1) {
      const candidate = bootstrapOrder[(position + offset) % bootstrapOrder.length];
      if (candidate.name !== name && !peers.includes(candidate)) peers.push(candidate);
    }
    return peers;
  };
  const actors = [];
  for (let index = 0; index < minerCount; index += 1) {
    const name = `miner-${index + 1}`;
    actors.push(nodeActor({name, role: 'miner', seedByte: MINERS[index][0], miner: true, minerIndex: index, signers, image: actorImages[name] ?? nodeImage, bootstrapPeers: bootstrapPeersFor(name), eventDispatchMode}));
  }
  for (let index = 1; index <= signerCount; index += 1) {
    const companion = `signer-node-${index}`;
    const signer = `signer-${index}`;
    actors.push(nodeActor({name: companion, role: 'companion', seedByte: (0x20 + index).toString(16), signerIndex: index, signers, image: actorImages[companion] ?? nodeImage, bootstrapPeers: bootstrapPeersFor(companion), eventDispatchMode}));
    actors.push(signerActor(index, signers[index - 1], actorImages[signer] ?? nodeImage));
  }
  for (let index = 1; index <= followerCount; index += 1) {
    const name = `follower-${index}`;
    actors.push(nodeActor({name, role: 'follower', seedByte: (0x30 + index).toString(16), signers, image: actorImages[name] ?? nodeImage, bootstrapPeers: bootstrapPeersFor(name), eventDispatchMode}));
  }
  const knownActors = new Set(actors.map(actor => actor.name));
  for (const name of Object.keys(actorImages)) {
    if (!knownActors.has(name)) throw new Error(`actor image override references unknown actor ${name}`);
  }
  for (const [name, declaration] of Object.entries(actorInstrumentation)) {
    if (!knownActors.has(name)) throw new Error(`actor instrumentation references unknown actor ${name}`);
    const actor = actors.find(candidate => candidate.name === name);
    if (!['miner', 'companion', 'follower', 'signer'].includes(actor.role)) {
      throw new Error(`actor instrumentation cannot target non-protocol actor ${name}`);
    }
    if (!/^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?:(?:merged|attacknet-patch|mixed|unavailable)$/.test(declaration)) {
      throw new Error(`actor instrumentation ${name} must use PROFILE:merged|attacknet-patch|mixed|unavailable`);
    }
  }
  for (const actor of actors) {
    const instrumentable = ['miner', 'companion', 'follower', 'signer'].includes(actor.role);
    const fallback = instrumentable
      ? `${instrumentationProfile}:${instrumentationProvenance}`
      : 'unmodified:unavailable';
    const [profile, provenance] = (actorInstrumentation[actor.name] ?? fallback).split(':');
    actor.instrumentation = {profile, provenance};
    if (actor.role !== 'signer') actor.eventDispatchMode = eventDispatchMode;
  }
  for (const [name, entries] of Object.entries(actorEnvs)) {
    if (!knownActors.has(name)) throw new Error(`actor environment override references unknown actor ${name}`);
    if (!Array.isArray(entries)) throw new Error(`actor environment override for ${name} must be an array`);
    const actor = actors.find(candidate => candidate.name === name);
    const occupied = new Set((actor.env ?? []).map(entry => entry.name));
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)
          || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(entry.name ?? '')
          || typeof entry.value !== 'string') throw new Error(`invalid actor environment override for ${name}`);
      if (occupied.has(entry.name)) throw new Error(`actor environment ${name}:${entry.name} is already defined`);
      occupied.add(entry.name);
      actor.env.push({name: entry.name, value: entry.value});
    }
  }
  return {minerCount, signerCount, followerCount, nodeImage, stackerImage, actors, signers, eventDispatchMode, instrumentationProfile, instrumentationProvenance};
}

function infrastructureActors(topology, network) {
  const wallets = Array.from({length: topology.minerCount}, (_, index) => `attacknet-miner-${index + 1}`);
  const addresses = MINERS.slice(0, topology.minerCount).map(miner => miner[2]);
  const stackingKeys = topology.signers.map(signer => signer[0]);
  return [
    {
      name: 'bitcoin', role: 'burnchain', image: 'bitcoin/bitcoin:25.2', imagePullPolicy: 'IfNotPresent',
      command: ['bitcoind'], args: ['-conf=/home/bitcoin/.bitcoin/bitcoin.conf', '-datadir=/home/bitcoin/.bitcoin', '-nosettings'],
      config: {files: {'bitcoin.conf': readFileSync(join(ROOT, 'bitcoin.conf'), 'utf8')}, key: 'bitcoin.conf', mountPath: '/home/bitcoin/.bitcoin'},
      ports: [{name: 'rpc', containerPort: 18443}, {name: 'p2p', containerPort: 18444}],
      readinessProbe: {exec: {command: ['bitcoin-cli', '-regtest', '-rpcuser=devnet', '-rpcpassword=devnet', 'getblockchaininfo']}, periodSeconds: 3, failureThreshold: 90},
      storage: {enabled: true, size: '4Gi', mountPath: '/home/bitcoin/.bitcoin/regtest'},
      resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '2', memory: '2Gi'}},
    },
    {
      name: 'bitcoin-miner', role: 'infrastructure', image: 'bitcoin/bitcoin:25.2', imagePullPolicy: 'IfNotPresent',
      command: ['/bin/bash', '/opt/attacknet/burnchain-clock.sh'],
      config: {files: {'burnchain-clock.sh': readFileSync(join(ROOT, 'burnchain-clock.sh'), 'utf8')}, key: 'burnchain-clock.sh', mountPath: '/opt/attacknet'},
      env: [env('BITCOIN_RPC_HOST', service('bitcoin')), env('MINER_WALLETS', wallets.join(',')), env('MINER_BTC_ADDRS', addresses.join(',')), env('BURNCHAIN_DEFAULT_INTERVAL_SECONDS', 20)],
      runtimePolicy: {configMapRef: {name: `${network}-burnchain-policy`}, mountPath: '/run/hacknet-policy'},
      dependencies: [{actor: 'bitcoin', port: 18443}], ports: [{name: 'bootstrap', containerPort: 18500}],
      readinessProbe: {httpGet: {path: '/', port: 'bootstrap'}, periodSeconds: 2, failureThreshold: 60},
      storage: {enabled: false}, resources: {requests: {cpu: '20m', memory: '64Mi'}, limits: {cpu: '1', memory: '512Mi'}},
    },
    {
      name: 'stacker', role: 'infrastructure', image: topology.stackerImage, imagePullPolicy: 'IfNotPresent',
      // Do not inherit the image entrypoint: a mistaken node image otherwise
      // starts stacks-node, passes a process-only readiness check, and silently
      // misses the finite PoX enrollment window. Custom stacker images must
      // implement this narrow, observable execution contract.
      command: ['npx', 'tsx', '/stacker/stacking.ts'],
      env: [env('STACKS_CORE_RPC_HOST', service('miner-1')), env('STACKS_CORE_RPC_PORT', 20443), env('STACKING_KEYS', stackingKeys.join(',')), env('STACKING_ADDRESSES', topology.signers.map(([, address]) => address).join(',')), env('STACKING_CYCLES', 12), env('POX5_STACKING_CYCLES', 96), env('POX5_RENEWAL_WINDOW_CYCLES', 48), env('STACKING_INTERVAL', 2), env('EPOCH_4_FIXTURE_DEPLOY_HEIGHT', 223)],
      dependencies: [{actor: 'miner-1', port: 20443}],
      readinessProbe: {exec: {command: ['test', '-s', '/tmp/attacknet-stacker-status.json']}, periodSeconds: 2, failureThreshold: 60},
      storage: {enabled: false}, resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '1', memory: '1Gi'}},
    },
  ];
}

export function renderTopology(topology, output, {
  network = 'attacknet',
  namespace = 'hacknet-system',
  probes = false,
  probeImage = 'stacks-hacknet-probe:dev',
} = {}) {
  mkdirSync(output, {recursive: true});
  const clockPolicyName = `${network}-clock-policy`;
  const clockCapableRoles = new Set(['miner', 'companion', 'follower', 'adversary']);
  const actors = [...infrastructureActors(topology, network), ...topology.actors].map(actor => {
    if (!clockCapableRoles.has(actor.role)) return actor;
    if (actor.runtimePolicy) {
      throw new Error(`actor ${actor.name} already uses runtimePolicy and cannot mount the attacknet clock policy`);
    }
    return {
      ...actor,
      runtimePolicy: {configMapRef: {name: clockPolicyName}, mountPath: '/run/attacknet-clock'},
      env: [
        ...(actor.env ?? []),
        env('LD_PRELOAD', '/usr/lib/stacks-attacknet/libfaketime.so.1'),
        env('FAKETIME_TIMESTAMP_FILE', `/run/attacknet-clock/${actor.name}`),
        env('FAKETIME_DONT_FAKE_MONOTONIC', '1'),
        env('FAKETIME_NO_CACHE', '1'),
      ],
    };
  });
  // activationGate belongs to the assertion manifest. The current
  // operator does not need it to build the Pod, so do not leak it into the CRD.
  const resourceActors = actors.map(({
    activationGate: _activationGate,
    instrumentation: _instrumentation,
    eventDispatchMode: _eventDispatchMode,
    ...actor
  }) => actor);
  const resource = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    metadata: {name: network, namespace, labels: {'testing.stacks.org/profile': 'mainnet-legacy-transport'}},
    spec: {
      defaults: {nodeImage: topology.nodeImage, imagePullPolicy: 'IfNotPresent', storage: {enabled: true, size: '2Gi'}},
      telemetry: {enabled: false},
      probe: {enabled: probes, image: probeImage, imagePullPolicy: 'IfNotPresent'},
      actors: resourceActors,
    },
  };
  // During initial IBD a node emits historical burn-block notifications.  A
  // signer cannot initialize until its companion RPC and canonical reward set
  // are usable. Starting it earlier can cache NotRegistered for the whole
  // reward cycle. Bootstrap companions without observers or signer dependency,
  // keep signers scaled to zero, then start both against the frozen reward set.
  const bootstrapResource = JSON.parse(JSON.stringify(resource));
  for (const actor of bootstrapResource.spec.actors.filter(actor => actor.role === 'companion')) {
    actor.config.files['config.toml'] = actor.config.files['config.toml'].replace(
      /\n\[\[events_observer\]\]\nendpoint = "[^"\n]+"\nevents_keys = \[[^\n]+\]\n/,
      '\n',
    );
    actor.dependencies = (actor.dependencies ?? []).filter(item => !item.actor.startsWith('signer-'));
  }
  for (const actor of bootstrapResource.spec.actors.filter(actor => actor.role === 'signer')) {
    actor.suspended = true;
  }
  const manifestActor = actor => ({
    service: actor.name,
    type: actor.role === 'signer' ? 'signer' : actor.role === 'burnchain' || actor.role === 'infrastructure' ? 'infrastructure' : 'node',
    role: actor.role,
    companion: actor.role === 'signer' ? `signer-node-${actor.name.slice('signer-'.length)}` : undefined,
    signerIndex: actor.signerIndex,
    signerWeight: actor.signerWeight,
    signerPublicKey: actor.signerPublicKey,
    stacksAddress: actor.role === 'signer'
      ? topology.signers[actor.signerIndex - 1][1]
      : undefined,
    activationGate: actor.activationGate,
    requestedImage: actor.image,
    instrumentation: actor.instrumentation ?? {profile: 'unmodified', provenance: 'unavailable'},
    eventDispatchMode: actor.eventDispatchMode,
  });
  const manifest = {
    schemaVersion: 1, profile: 'mainnet-legacy-transport', network, namespace,
    protocol: {
      burnchainBootstrapHeight: 202,
      // PoX-4 becomes available with Epoch 2.4. Pause here and let the
      // stacker submit before advancing one burn block at a time. The reward
      // set for cycle 11 is frozen when its prepare phase starts at 215.
      signerEnrollmentHeight: 208,
      signerSetCutoffHeight: 215,
      observerEnableHeight: 220,
      // The signer runloops adopt the already-frozen cycle-11 reward set on
      // burn-block events after observers are enabled. Height 222 is the last
      // deterministic participation barrier before Nakamoto activates.
      signerRegistrationHeight: 222,
      nakamotoActivationHeight: 223,
      steadyBurnIntervalSeconds: 60,
      eventDispatchMode: topology.eventDispatchMode,
    },
    counts: {miners: topology.minerCount, signers: topology.signerCount, followers: topology.followerCount},
    images: {node: topology.nodeImage, stacker: topology.stackerImage},
    actors: topology.actors.map(manifestActor),
    workloads: actors.map(manifestActor),
  };
  const policy = {apiVersion: 'v1', kind: 'ConfigMap', metadata: {name: `${network}-burnchain-policy`, namespace}, data: {'policy.env': 'GENERATION=1\nMODE=pause\nINTERVAL_SECONDS=60\nJITTER_SECONDS=0\nBURST_BLOCKS=0\nBURST_TARGET_HEIGHT=0\nADDRESS_MODE=round-robin\nFIXED_ADDRESS_INDEX=0\n'}};
  const clockPolicy = {
    apiVersion: 'v1', kind: 'ConfigMap',
    metadata: {
      name: clockPolicyName, namespace,
      labels: {
        'testing.stacks.org/network': network,
        'testing.stacks.org/clock-policy': 'true',
        'app.kubernetes.io/managed-by': 'stacks-attacknet-lifecycle',
      },
    },
    data: Object.fromEntries(
      actors.filter(actor => clockCapableRoles.has(actor.role)).map(actor => [actor.name, '+0s\n']),
    ),
  };
  writeFileSync(join(output, 'stacksnetwork.json'), `${JSON.stringify(resource, null, 2)}\n`);
  writeFileSync(join(output, 'stacksnetwork.bootstrap.json'), `${JSON.stringify(bootstrapResource, null, 2)}\n`);
  writeFileSync(join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(output, 'burnchain-policy.configmap.json'), `${JSON.stringify(policy, null, 2)}\n`);
  writeFileSync(join(output, 'clock-policy.configmap.json'), `${JSON.stringify(clockPolicy, null, 2)}\n`);
  writeFileSync(join(output, 'policy.env'), policy.data['policy.env']);
  return {resource, bootstrapResource, manifest, policy, clockPolicy};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes('--help')) {
    process.stdout.write(usage());
    process.exit(0);
  }
  const topology = buildTopology({
    minerCount: parseCount('miners', 1, LIMITS.miners),
    signerCount: parseCount('signers', 1, LIMITS.signers),
    followerCount: parseCount('followers', 1, LIMITS.followers),
    nodeImage: option('node-image', 'stacks-core-attacknet:main'),
    stackerImage: option('stacker-image', 'stacks-attacknet-stacker:local'),
    actorImages: repeatedMapOption('actor-image'),
    actorEnvs: repeatedActorEnvOption(),
    eventDispatchMode: option('event-dispatch', 'queued'),
    instrumentationProfile: option('instrumentation-profile', 'unmodified'),
    instrumentationProvenance: option('instrumentation-provenance', 'unavailable'),
    actorInstrumentation: repeatedMapOption('actor-instrumentation'),
  });
  const output = resolve(option('output', join(ROOT, 'generated')));
  const probeEnabled = option('probes', 'false');
  if (!['true', 'false'].includes(probeEnabled)) throw new Error('probes must be true or false');
  renderTopology(topology, output, {
    network: option('network', 'attacknet'),
    namespace: option('namespace', 'hacknet-system'),
    probes: probeEnabled === 'true',
    probeImage: option('probe-image', 'stacks-hacknet-probe:dev'),
  });
  console.log(`Rendered ${topology.actors.length + 3} workloads to ${output}`);
}
