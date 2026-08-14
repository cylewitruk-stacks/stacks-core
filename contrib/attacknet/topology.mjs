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
  ['4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a01', 'ST350FBN4H0EKWQCW6BTFK97RGXFS5QJ78E9NST20'],
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

function legacyPublicKey(seedByte) {
  const key = createECDH('secp256k1');
  key.setPrivateKey(Buffer.from(repeated(seedByte), 'hex'));
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

function nodeConfig({name, seedByte, miner, minerIndex, signerIndex, signers}) {
  const bootstrap = name === 'miner-1' ? '' :
    `bootstrap_node = "${legacyPublicKey('11')}@${service('miner-1')}:20444"`;
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
stacker = ${miner}
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

function nodeActor({name, role, seedByte, miner = false, minerIndex, signerIndex, signers, image}) {
  const delayedMiner = miner && minerIndex > 0;
  const files = {
    'config.toml': nodeConfig({name, seedByte, miner, minerIndex, signerIndex, signers}),
    'configure-node.sh': readFileSync(join(ROOT, 'configure-node.sh'), 'utf8'),
  };
  if (delayedMiner) files['join-after-nakamoto.sh'] = readFileSync(join(ROOT, 'join-after-nakamoto.sh'), 'utf8');
  const dependencies = [{actor: 'bitcoin', port: 18443}, {actor: 'bitcoin-miner', port: 18500}];
  if (name !== 'miner-1') dependencies.push({actor: 'miner-1', port: 20443});
  return {
    name,
    role,
    activationGate: delayedMiner ? {kind: 'burn-height', height: 223} : undefined,
    image,
    imagePullPolicy: 'IfNotPresent',
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
    image,
    imagePullPolicy: 'IfNotPresent',
    command: ['stacks-signer', 'run', '--config', '/etc/stacks/signer.toml'],
    // Companion event delivery must be able to reach the signer before the
    // companion RPC becomes Ready; otherwise their startup dependencies cycle.
    // The signer node client retries while its companion finishes booting, so
    // intentionally do not add a readiness/TCP dependency on the companion.
    runtimeExposure: 'reachable',
    config: {files: {'signer.toml': signerConfig(index, signer)}, key: 'signer.toml', mountPath: '/etc/stacks'},
    env: [env('RUST_LOG', 'info')],
    dependencies: [],
    ports: [{name: 'events', containerPort: 30000}, {name: 'metrics', containerPort: 31000}],
    readinessProbe: {exec: {command: ['test', '-r', '/proc/1/status']}, periodSeconds: 5},
    storage: {enabled: true, size: '512Mi', mountPath: '/data'},
    resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '2', memory: '2Gi'}},
  };
}

export function buildTopology({minerCount = 1, signerCount = 1, followerCount = 1, nodeImage = 'stacks-core-attacknet:main', stackerImage = 'stacks-attacknet-stacker:local', actorImages = {}} = {}) {
  if (minerCount < 1 || minerCount > LIMITS.miners) throw new Error('minerCount out of range');
  if (signerCount < 1 || signerCount > LIMITS.signers) throw new Error('signerCount out of range');
  if (followerCount < 0 || followerCount > LIMITS.followers) throw new Error('followerCount out of range');
  const signers = SIGNERS.slice(0, signerCount);
  const actors = [];
  for (let index = 0; index < minerCount; index += 1) {
    const name = `miner-${index + 1}`;
    actors.push(nodeActor({name, role: 'miner', seedByte: MINERS[index][0], miner: true, minerIndex: index, signers, image: actorImages[name] ?? nodeImage}));
  }
  for (let index = 1; index <= signerCount; index += 1) {
    const companion = `signer-node-${index}`;
    const signer = `signer-${index}`;
    actors.push(nodeActor({name: companion, role: 'companion', seedByte: (0x20 + index).toString(16), signerIndex: index, signers, image: actorImages[companion] ?? nodeImage}));
    actors.push(signerActor(index, signers[index - 1], actorImages[signer] ?? nodeImage));
  }
  for (let index = 1; index <= followerCount; index += 1) {
    const name = `follower-${index}`;
    actors.push(nodeActor({name, role: 'follower', seedByte: (0x30 + index).toString(16), signers, image: actorImages[name] ?? nodeImage}));
  }
  const knownActors = new Set(actors.map(actor => actor.name));
  for (const name of Object.keys(actorImages)) {
    if (!knownActors.has(name)) throw new Error(`actor image override references unknown actor ${name}`);
  }
  return {minerCount, signerCount, followerCount, nodeImage, stackerImage, actors, signers};
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
      env: [env('STACKS_CORE_RPC_HOST', service('miner-1')), env('STACKS_CORE_RPC_PORT', 20443), env('STACKING_KEYS', stackingKeys.join(',')), env('STACKING_CYCLES', 12), env('POX5_STACKING_CYCLES', 96), env('POX5_RENEWAL_WINDOW_CYCLES', 48), env('STACKING_INTERVAL', 2), env('EPOCH_4_FIXTURE_DEPLOY_HEIGHT', 223)],
      dependencies: [{actor: 'miner-1', port: 20443}],
      readinessProbe: {exec: {command: ['test', '-r', '/proc/1/status']}, periodSeconds: 5},
      storage: {enabled: false}, resources: {requests: {cpu: '50m', memory: '128Mi'}, limits: {cpu: '1', memory: '1Gi'}},
    },
  ];
}

function expandCompose(value, network) {
  if (typeof value === 'string') {
    return value
      .replaceAll('${NETWORK}', network)
      .replaceAll('${NAMESPACE}', 'compose')
      .replaceAll(/\$\{SERVICE:([a-z][-a-z0-9]*[a-z0-9])\}/g, '$1');
  }
  if (Array.isArray(value)) return value.map(item => expandCompose(item, network));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expandCompose(item, network)]));
  }
  return value;
}

function composeHealthcheck(actor) {
  if (actor.role === 'burnchain') {
    return {test: ['CMD', 'bitcoin-cli', '-regtest', '-rpcuser=devnet', '-rpcpassword=devnet', 'getblockchaininfo'], interval: '5s', timeout: '3s', retries: 90};
  }
  if (actor.name === 'bitcoin-miner') {
    return {test: ['CMD-SHELL', 'curl --fail --silent http://127.0.0.1:18500/ >/dev/null'], interval: '3s', timeout: '2s', retries: 90};
  }
  if (actor.role === 'signer' || actor.name === 'stacker') {
    return {test: ['CMD-SHELL', 'test -r /proc/1/status'], interval: '5s', timeout: '2s', retries: 60};
  }
  return {test: ['CMD-SHELL', 'curl --fail --silent http://127.0.0.1:20443/v2/info >/dev/null'], interval: '5s', timeout: '3s', retries: 180};
}

function renderCompose(actors, output, network) {
  const services = {};
  const volumes = {};
  const configsRoot = join(output, 'configs');
  mkdirSync(configsRoot, {recursive: true});
  for (const original of actors) {
    const actor = expandCompose(original, network);
    const serviceSpec = {
      image: actor.image,
      restart: 'unless-stopped',
      environment: Object.fromEntries((actor.env ?? []).map(item => [item.name, item.value])),
      healthcheck: composeHealthcheck(actor),
    };
    if (actor.command) serviceSpec.entrypoint = actor.command;
    if (actor.args) serviceSpec.command = actor.args;
    if (actor.dependencies?.length) {
      serviceSpec.depends_on = Object.fromEntries(actor.dependencies.map(item => [item.actor, {condition: 'service_started'}]));
    }
    const mounts = [];
    if (actor.config?.files) {
      const actorDirectory = join(configsRoot, actor.name);
      mkdirSync(actorDirectory, {recursive: true});
      for (const [filename, contents] of Object.entries(actor.config.files)) {
        writeFileSync(join(actorDirectory, filename), expandCompose(contents, network));
        mounts.push(`./configs/${actor.name}/${filename}:${actor.config.mountPath}/${filename}:ro`);
      }
    }
    if (actor.runtimePolicy) mounts.push(`./policy.env:${actor.runtimePolicy.mountPath}/policy.env:ro`);
    if (actor.storage?.enabled) {
      const volume = `${actor.name}-data`;
      mounts.push(`${volume}:${actor.storage.mountPath}`);
      volumes[volume] = {};
    }
    if (mounts.length) serviceSpec.volumes = mounts;
    services[actor.name] = serviceSpec;
  }
  const compose = {name: network, services, volumes};
  writeFileSync(join(output, 'compose.yaml'), `${JSON.stringify(compose, null, 2)}\n`);
}

export function renderTopology(topology, output, {network = 'attacknet', namespace = 'hacknet-system'} = {}) {
  mkdirSync(output, {recursive: true});
  const actors = [...infrastructureActors(topology, network), ...topology.actors];
  // activationGate belongs to the backend-neutral run manifest.  The current
  // operator does not need it to build the Pod, so do not leak it into the CRD.
  const resourceActors = actors.map(({activationGate: _activationGate, ...actor}) => actor);
  const resource = {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'StacksNetwork',
    metadata: {name: network, namespace, labels: {'testing.stacks.org/profile': 'mainnet-legacy-transport'}},
    spec: {
      defaults: {nodeImage: topology.nodeImage, imagePullPolicy: 'IfNotPresent', storage: {enabled: true, size: '2Gi'}},
      telemetry: {enabled: false}, actors: resourceActors,
    },
  };
  const manifestActor = actor => ({
    service: actor.name,
    type: actor.role === 'signer' ? 'signer' : actor.role === 'burnchain' || actor.role === 'infrastructure' ? 'infrastructure' : 'node',
    role: actor.role,
    companion: actor.role === 'signer' ? `signer-node-${actor.name.slice('signer-'.length)}` : undefined,
    signerIndex: actor.role === 'signer'
      ? Number(actor.name.slice('signer-'.length))
      : actor.role === 'companion' ? Number(actor.name.slice('signer-node-'.length)) : undefined,
    signerWeight: ['signer', 'companion'].includes(actor.role)
      ? ((Number(actor.name.slice(actor.role === 'signer' ? 'signer-'.length : 'signer-node-'.length)) - 1) % 3) + 1
      : undefined,
    activationGate: actor.activationGate,
  });
  const manifest = {
    schemaVersion: 1, profile: 'mainnet-legacy-transport', network, namespace,
    counts: {miners: topology.minerCount, signers: topology.signerCount, followers: topology.followerCount},
    images: {node: topology.nodeImage, stacker: topology.stackerImage},
    actors: topology.actors.map(manifestActor),
    workloads: actors.map(manifestActor),
  };
  const policy = {apiVersion: 'v1', kind: 'ConfigMap', metadata: {name: `${network}-burnchain-policy`, namespace}, data: {'policy.env': 'GENERATION=1\nMODE=pause\nINTERVAL_SECONDS=20\nJITTER_SECONDS=0\nBURST_BLOCKS=0\nADDRESS_MODE=round-robin\nFIXED_ADDRESS_INDEX=0\n'}};
  writeFileSync(join(output, 'stacksnetwork.json'), `${JSON.stringify(resource, null, 2)}\n`);
  writeFileSync(join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(output, 'burnchain-policy.configmap.json'), `${JSON.stringify(policy, null, 2)}\n`);
  writeFileSync(join(output, 'policy.env'), policy.data['policy.env']);
  renderCompose(actors, output, network);
  return {resource, manifest, policy};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const topology = buildTopology({
    minerCount: parseCount('miners', 1, LIMITS.miners),
    signerCount: parseCount('signers', 1, LIMITS.signers),
    followerCount: parseCount('followers', 1, LIMITS.followers),
    nodeImage: option('node-image', 'stacks-core-attacknet:main'),
    stackerImage: option('stacker-image', 'stacks-attacknet-stacker:local'),
    actorImages: repeatedMapOption('actor-image'),
  });
  const output = resolve(option('output', join(ROOT, 'generated')));
  renderTopology(topology, output, {network: option('network', 'attacknet'), namespace: option('namespace', 'hacknet-system')});
  console.log(`Rendered ${topology.actors.length + 3} workloads to ${output}`);
}
