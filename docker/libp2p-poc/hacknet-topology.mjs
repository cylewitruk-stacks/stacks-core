#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

import {actorToken, buildTopology, renderTopology} from './topology.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(ROOT, '../..');

function option(name, fallback) {
  const marker = `--${name}=`;
  return process.argv.find(argument => argument.startsWith(marker))?.slice(marker.length)
    ?? fallback;
}

function repeatedMapOption(name) {
  const marker = `--${name}=`;
  return Object.fromEntries(process.argv.filter(argument => argument.startsWith(marker)).map(argument => {
    const pair = argument.slice(marker.length);
    const separator = pair.indexOf('=');
    if (separator < 1 || separator === pair.length - 1) {
      throw new Error(`${name} must use actor=value, received ${pair}`);
    }
    return [pair.slice(0, separator), pair.slice(separator + 1)];
  }));
}

function countOption(name, fallback, maximum) {
  const raw = option(name, String(fallback));
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be within [1, ${maximum}], received ${raw}`);
  }
  return value;
}

function env(name, value) {
  return {name, value: String(value)};
}

function servicePlaceholder(actor) {
  return `\${SERVICE:${actor}}`;
}

function replaceConfigServiceHosts(text, names) {
  let result = text;
  for (const name of [...names].sort((left, right) => right.length - left.length)) {
    const replacement = servicePlaceholder(name);
    result = result
      .replaceAll(`/dns4/${name}/`, `/dns4/${replacement}/`)
      .replaceAll(`endpoint = "${name}:`, `endpoint = "${replacement}:`)
      .replaceAll(`node_host = "${name}:`, `node_host = "${replacement}:`)
      .replaceAll(`peer_host = "${name}"`, `peer_host = "${replacement}"`);
  }
  return result;
}

function parseEnvironment(text) {
  return Object.fromEntries(text.trim().split('\n').filter(Boolean).map(line => {
    const separator = line.indexOf('=');
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
}

function nodeActor(actor, topology, generated, common) {
  const config = replaceConfigServiceHosts(
    readFileSync(join(generated, `configs/${actor.service}.toml`), 'utf8'),
    ['bitcoin', ...topology.actors.map(item => item.service)],
  );
  const delayedMiner = actor.role === 'miner' && actor.service !== 'miner-1';
  const files = {"config.toml": config};
  if (delayedMiner) {
    files['join-after-nakamoto.sh'] = readFileSync(join(ROOT, 'join-after-nakamoto.sh'), 'utf8')
      .replace('/config.toml', '/etc/stacks/config.toml');
  }
  const dependencies = [
    {actor: 'bitcoin', port: 18443},
    {actor: 'bitcoin-miner', port: 18500},
  ];
  if (actor.service !== 'miner-1') dependencies.push({actor: 'miner-1', port: 20443});
  return {
    name: actor.service,
    role: actor.role,
    image: common.nodeImage,
    imagePullPolicy: 'IfNotPresent',
    command: delayedMiner
      ? ['/bin/bash', '/etc/stacks/join-after-nakamoto.sh']
      : ['stacks-node', 'start', '--config', '/etc/stacks/config.toml'],
    config: {files, key: 'config.toml', mountPath: '/etc/stacks'},
    env: [
      env('RUST_LOG', 'info,stacks_network=info'),
      ...(delayedMiner ? [
        env('NAKAMOTO_SOURCE_HOST', servicePlaceholder('miner-1')),
        env('NAKAMOTO_ACTIVATION_HEIGHT', '223'),
      ] : []),
    ],
    dependencies,
    storage: {enabled: true, size: '2Gi', mountPath: '/data'},
    resources: common.nodeResources,
    telemetry: common.telemetry(actor, topology),
    annotations: {
      'testing.stacks.org/actor-id': actor.id,
      'testing.stacks.org/transport-peer-id': actor.transportPeerId,
    },
  };
}

function signerActor(actor, topology, generated, common) {
  const config = replaceConfigServiceHosts(
    readFileSync(join(generated, `configs/${actor.service}.toml`), 'utf8'),
    topology.actors.map(item => item.service),
  );
  return {
    name: actor.service,
    role: 'signer',
    image: common.nodeImage,
    imagePullPolicy: 'IfNotPresent',
    command: ['stacks-signer', 'run', '--config', '/etc/stacks/signer.toml'],
    config: {files: {'signer.toml': config}, key: 'signer.toml', mountPath: '/etc/stacks'},
    env: [env('RUST_LOG', 'info,stacks_network=info')],
    storage: {enabled: true, size: '512Mi', mountPath: '/data'},
    resources: common.signerResources,
    telemetry: common.telemetry(actor, topology),
    annotations: {
      'testing.stacks.org/actor-id': actor.id,
      'testing.stacks.org/transport-peer-id': actor.transportPeerId,
      'testing.stacks.org/signer-public-key': actor.signerPublicKey,
      'testing.stacks.org/companion-actor-id': actor.companionActorId,
    },
  };
}

function infrastructureActors(topology, generated, common) {
  const topologyEnv = parseEnvironment(readFileSync(join(generated, 'topology.env'), 'utf8'));
  const burnchainClock = readFileSync(join(ROOT, 'burnchain-clock.sh'), 'utf8');
  const bitcoinConfig = readFileSync(join(ROOT, 'bitcoin.conf'), 'utf8');
  const prometheusConfig = readFileSync(
    join(REPO_ROOT, 'contrib/stacks-network-observer/federation/prometheus.yml'),
    'utf8',
  ).replaceAll('telemetry-collector', servicePlaceholder('telemetry-collector'));
  const observerEnrollment = readFileSync(join(generated, 'poc-enrollments.json'), 'utf8');
  const collectorConfig = readFileSync(join(generated, 'collector.yaml'), 'utf8');
  const collectorPorts = topology.actors.map((actor, index) => ({
    name: `otlp-${index + 1}`,
    containerPort: 4318 + index,
  }));
  collectorPorts.push(
    {name: 'metrics', containerPort: 9464},
    {name: 'internal', containerPort: 8888},
  );

  return [
    {
      name: 'bitcoin',
      role: 'burnchain',
      image: 'bitcoin/bitcoin:25.2',
      imagePullPolicy: 'IfNotPresent',
      command: ['bitcoind'],
      args: ['-conf=/home/bitcoin/.bitcoin/bitcoin.conf', '-datadir=/home/bitcoin/.bitcoin', '-nosettings'],
      config: {files: {'bitcoin.conf': bitcoinConfig}, key: 'bitcoin.conf', mountPath: '/home/bitcoin/.bitcoin'},
      storage: {enabled: true, size: '4Gi', mountPath: '/home/bitcoin/.bitcoin/regtest'},
      resources: common.infrastructureResources,
    },
    {
      name: 'bitcoin-miner',
      role: 'infrastructure',
      image: 'bitcoin/bitcoin:25.2',
      imagePullPolicy: 'IfNotPresent',
      command: ['/bin/bash', '/opt/hacknet/burnchain-clock.sh'],
      config: {
        files: {'burnchain-clock.sh': burnchainClock},
        key: 'burnchain-clock.sh',
        mountPath: '/opt/hacknet',
      },
      env: [
        env('BITCOIN_RPC_HOST', servicePlaceholder('bitcoin')),
        env('MINER_WALLETS', topologyEnv.MINER_WALLETS),
        env('MINER_BTC_ADDRS', topologyEnv.MINER_BTC_ADDRS),
        env('BURNCHAIN_DEFAULT_INTERVAL_SECONDS', '20'),
      ],
      runtimePolicy: {
        configMapRef: {name: `${common.network}-burnchain-policy`},
        mountPath: '/run/hacknet-policy',
      },
      dependencies: [{actor: 'bitcoin', port: 18443}],
      ports: [{name: 'bootstrap', containerPort: 18500}],
      readinessProbe: {httpGet: {path: '/', port: 'bootstrap'}, periodSeconds: 2, failureThreshold: 30},
      storage: {enabled: false},
      resources: common.infrastructureResources,
    },
    {
      name: 'stacker',
      role: 'infrastructure',
      image: common.stackerImage,
      imagePullPolicy: 'IfNotPresent',
      env: [
        env('STACKS_CORE_RPC_HOST', servicePlaceholder('miner-1')),
        env('STACKS_CORE_RPC_PORT', '20443'),
        env('POX5_SIGNER_ACCOUNTS', topologyEnv.POX5_SIGNER_ACCOUNTS),
        env('STACKING_KEYS', topologyEnv.STACKING_KEYS),
        env('STACKING_CYCLES', '12'),
        env('POX5_STACKING_CYCLES', '96'),
        env('POX5_RENEWAL_WINDOW_CYCLES', '48'),
        env('STACKING_INTERVAL', '2'),
        env('EPOCH_4_FIXTURE_DEPLOY_HEIGHT', '223'),
      ],
      dependencies: [{actor: 'miner-1', port: 20443}],
      readinessProbe: {exec: {command: ['test', '-r', '/proc/1/status']}, periodSeconds: 5},
      storage: {enabled: false},
      resources: common.infrastructureResources,
    },
    {
      name: 'telemetry-collector',
      role: 'infrastructure',
      image: 'ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0',
      imagePullPolicy: 'IfNotPresent',
      args: ['--config=/etc/otelcol-contrib/collector.yaml'],
      config: {files: {'collector.yaml': collectorConfig}, key: 'collector.yaml', mountPath: '/etc/otelcol-contrib'},
      ports: collectorPorts,
      readinessProbe: {tcpSocket: {port: 'metrics'}, periodSeconds: 5, failureThreshold: 30},
      storage: {enabled: false},
      resources: {requests: {cpu: '50m', memory: '256Mi'}, limits: {cpu: '1', memory: '1Gi'}},
    },
    {
      name: 'prometheus',
      role: 'infrastructure',
      image: 'prom/prometheus:v3.13.1',
      imagePullPolicy: 'IfNotPresent',
      args: [
        '--config.file=/etc/prometheus/prometheus.yml',
        '--storage.tsdb.path=/prometheus',
        '--storage.tsdb.retention.time=6h',
        '--storage.tsdb.retention.size=256MB',
        '--web.enable-lifecycle',
      ],
      config: {files: {'prometheus.yml': prometheusConfig}, key: 'prometheus.yml', mountPath: '/etc/prometheus'},
      dependencies: [{actor: 'telemetry-collector', port: 9464}],
      ports: [{name: 'web', containerPort: 9090}],
      readinessProbe: {httpGet: {path: '/-/ready', port: 'web'}, periodSeconds: 5, failureThreshold: 30},
      storage: {enabled: true, size: '1Gi', mountPath: '/prometheus'},
      resources: common.infrastructureResources,
    },
    {
      name: 'observer',
      role: 'infrastructure',
      image: common.observerImage,
      imagePullPolicy: 'IfNotPresent',
      config: {
        files: {'poc-enrollments.json': observerEnrollment},
        key: 'poc-enrollments.json',
        mountPath: '/app/federation',
      },
      env: [
        env('STACKS_OBSERVER_PROMETHEUS_URL', `http://${servicePlaceholder('prometheus')}:9090`),
        env('STACKS_OBSERVER_ENROLLMENTS_FILE', '/app/federation/poc-enrollments.json'),
        env('STACKS_OBSERVER_STACKS_API_URL', `http://${servicePlaceholder('miner-1')}:20443`),
        env('STACKS_OBSERVER_EXPECTED_BURN_CADENCE_SECONDS', '20'),
        env('STACKS_OBSERVER_PUBLIC_NETWORK_LABEL', 'Stacks attacknet regtest'),
        env('STACKS_OBSERVER_AUTH_MODE', 'development-password'),
        env('STACKS_OBSERVER_ALLOW_INSECURE_DEVELOPMENT_AUTH', 'true'),
        env('STACKS_OBSERVER_DEV_EMAIL', 'user@host.com'),
        env('STACKS_OBSERVER_DEV_PASSWORD_HASH', 'scrypt$v1$16384$8$1$00112233445566778899aabbccddeeff$36399bbc41eef2d142e319a445abe043a9a177fa4da34f2d1a0946ec6a01db0c'),
        env('STACKS_OBSERVER_SESSION_SECURE', 'false'),
      ],
      dependencies: [{actor: 'prometheus', port: 9090}, {actor: 'miner-1', port: 20443}],
      ports: [{name: 'web', containerPort: 4319}],
      readinessProbe: {httpGet: {path: '/healthz', port: 'web'}, periodSeconds: 5, failureThreshold: 30},
      storage: {enabled: false},
      resources: common.infrastructureResources,
    },
  ];
}

export function renderHacknetTopology(topology, output, options = {}) {
  renderTopology(topology, output);
  const network = options.network ?? 'attacknet';
  const namespace = options.namespace ?? 'hacknet-system';
  const nodeImage = options.nodeImage ?? 'stacks-core-libp2p-poc:local';
  const common = {
    network,
    nodeImage,
    stackerImage: options.stackerImage ?? 'stacks-libp2p-poc-stacker:local',
    observerImage: options.observerImage ?? 'stacks-network-observer:local',
    nodeResources: {requests: {cpu: '50m', memory: '256Mi'}, limits: {cpu: '1500m', memory: '1536Mi'}},
    signerResources: {requests: {cpu: '25m', memory: '128Mi'}, limits: {cpu: '750m', memory: '768Mi'}},
    infrastructureResources: {requests: {cpu: '25m', memory: '64Mi'}, limits: {cpu: '1', memory: '768Mi'}},
    telemetry(actor, currentTopology) {
      const index = currentTopology.actors.findIndex(item => item.id === actor.id);
      return {
        enabled: true,
        exporterEndpoint: `http://${servicePlaceholder('telemetry-collector')}:${4318 + index}`,
        tokenSecretRef: {name: `${network}-federation-tokens`, key: actor.id},
        metricsPort: actor.type === 'signer' ? 31000 : 20446,
      };
    },
  };
  const generated = resolve(output);
  let actors = [
    ...infrastructureActors(topology, generated, common),
    ...topology.actors.map(actor => actor.type === 'signer'
      ? signerActor(actor, topology, generated, common)
      : nodeActor(actor, topology, generated, common)),
  ];
  const actorImages = options.actorImages ?? {};
  const actorNames = new Set(actors.map(actor => actor.name));
  for (const name of Object.keys(actorImages)) {
    if (!actorNames.has(name)) throw new Error(`actor image override names unknown actor ${name}`);
  }
  actors = actors.map(actor => actorImages[actor.name]
    ? {...actor, image: actorImages[actor.name]}
    : actor);
  const resource = {
    apiVersion: 'testing.stacks.org/v1alpha1',
    kind: 'StacksNetwork',
    metadata: {name: network, namespace},
    spec: {
      suspended: options.suspended ?? false,
      defaults: {
        nodeImage,
        signerImage: nodeImage,
        imagePullPolicy: 'IfNotPresent',
        dependencyImage: 'busybox:1.36.1',
        storage: {enabled: true, size: '1Gi', storageClassName: options.storageClassName ?? 'standard'},
        containerSecurityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ['ALL']}},
        podSecurityContext: {seccompProfile: {type: 'RuntimeDefault'}},
        topologySpreadConstraints: [{
          maxSkew: 1,
          topologyKey: 'kubernetes.io/hostname',
          whenUnsatisfiable: 'ScheduleAnyway',
          labelSelector: {matchLabels: {'testing.stacks.org/network': network}},
        }],
      },
      telemetry: {enabled: false},
      actors,
    },
  };
  const secret = {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {name: `${network}-federation-tokens`, namespace},
    type: 'Opaque',
    stringData: Object.fromEntries(topology.actors.map(actor => [actor.id, actorToken(actor.id)])),
  };
  const policyConfigMap = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {name: `${network}-burnchain-policy`, namespace},
    data: {
      'policy.env': [
        'GENERATION=1',
        'MODE=run',
        'INTERVAL_SECONDS=20',
        'JITTER_SECONDS=0',
        'BURST_BLOCKS=0',
        'ADDRESS_MODE=round-robin',
        'FIXED_ADDRESS_INDEX=0',
        '',
      ].join('\n'),
    },
  };
  writeFileSync(join(generated, 'stacksnetwork.json'), `${JSON.stringify(resource, null, 2)}\n`);
  writeFileSync(join(generated, 'federation-tokens.secret.json'), `${JSON.stringify(secret, null, 2)}\n`);
  writeFileSync(join(generated, 'burnchain-policy.configmap.json'), `${JSON.stringify(policyConfigMap, null, 2)}\n`);
  return {resource, secret, policyConfigMap};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const topology = buildTopology({
    signerCount: countOption('signers', 10, 10),
    minerCount: countOption('miners', 3, 3),
    followerCount: countOption('followers', 5, 5),
  });
  const output = resolve(ROOT, option('output', 'generated'));
  const {resource} = renderHacknetTopology(topology, output, {
    network: option('network', 'attacknet'),
    namespace: option('namespace', 'hacknet-system'),
    nodeImage: option('node-image', 'stacks-core-libp2p-poc:local'),
    stackerImage: option('stacker-image', 'stacks-libp2p-poc-stacker:local'),
    observerImage: option('observer-image', 'stacks-network-observer:local'),
    storageClassName: option('storage-class', 'standard'),
    actorImages: repeatedMapOption('actor-image'),
    suspended: process.argv.includes('--suspended'),
  });
  console.log(`Rendered ${resource.spec.actors.length} Kubernetes actors to ${output}`);
}
