#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const RUNTIME_REVISION = '52e0d2812c514cad29d9fd2603eb2b8b3d93b0c3';
const WORKLOAD_REVISION = 'f8a853a0f21c9edebec92398fb56500ae10e1a22';
const ATTACKNET_PREFIX = 'contrib/attacknet/';
const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const OUTPUT = resolve(REPOSITORY, 'contrib/attacknet/test/fixtures/equivalence/v1alpha1');

const pythonRenderer = String.raw`
import json
import sys
import types

module = types.ModuleType("legacy_controller")
sys.modules[module.__name__] = module
exec(compile(sys.stdin.read(), "controller.py", "exec"), module.__dict__)
with open(sys.argv[1], encoding="utf-8") as source:
    network = json.load(source)
network["metadata"]["uid"] = "offline-render-check"
network["metadata"]["generation"] = 1
print(json.dumps(module.build_resources(network), sort_keys=True, separators=(",", ":")))
`;

function gitFile(revision, path) {
  return execFileSync('git', ['show', `${revision}:${path}`], {cwd: REPOSITORY});
}

function materialize(directory, path) {
  const destination = join(directory, path.slice(ATTACKNET_PREFIX.length));
  mkdirSync(dirname(destination), {recursive: true});
  writeFileSync(destination, gitFile(RUNTIME_REVISION, path));
  return destination;
}

function writeJson(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

function campaign(name, fault, target = {actors: ['signer-node-2']}) {
  return {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'FaultCampaign',
    metadata: {name, namespace: 'hacknet-system'},
    spec: {
      networkRef: 'attacknet', target,
      fault: {mode: 'one', duration: '30s', ...fault},
      safety: {
        maxUnavailableSignerPercent: 30, maxUnavailableMinerPercent: 50,
        allowQuorumLoss: false, allowBurnchain: false,
        allowExtendedDuration: false, allowExtremeSeverity: false,
        allowMinerMajorityOutage: false, allowUnenrolledNetworkTargets: false,
      },
    },
  };
}

async function generate() {
  const working = mkdtempSync(join(tmpdir(), 'attacknet-a1-fixtures-'));
  const generated = mkdtempSync(join(tmpdir(), 'attacknet-a1-render-'));
  try {
    for (const path of [
      'contrib/attacknet/legacy/v1alpha1/runtime/topology.mjs',
      'contrib/attacknet/legacy/v1alpha1/runtime/configure-node.sh',
      'contrib/attacknet/legacy/v1alpha1/runtime/join-after-nakamoto.sh',
      'contrib/attacknet/legacy/v1alpha1/runtime/burnchain-clock.sh',
      'contrib/attacknet/config/bitcoin/bitcoin.conf',
      'contrib/attacknet/legacy/v1alpha1/runtime/fault-campaign.mjs',
      'contrib/attacknet/legacy/v1alpha1/runtime/run-descriptor.mjs',
    ]) materialize(working, path);

    const runtime = join(working, 'legacy/v1alpha1/runtime');
    const topologyModule = await import(pathToFileURL(join(runtime, 'topology.mjs')));
    const faultModule = await import(pathToFileURL(join(runtime, 'fault-campaign.mjs')));
    const controller = gitFile(WORKLOAD_REVISION, 'contrib/helm/hacknet/operator/controller.py');
    const scenarios = [
      {id: 'baseline-probes', counts: {minerCount: 1, signerCount: 1, followerCount: 1}, probes: true},
      {id: 'multi-actor-probes', counts: {minerCount: 3, signerCount: 3, followerCount: 2}, probes: true},
      {id: 'probes-disabled', counts: {minerCount: 1, signerCount: 1, followerCount: 1}, probes: false},
      {
        id: 'storage-disabled', counts: {minerCount: 1, signerCount: 1, followerCount: 1}, probes: false,
        configure(resource) {
          const actor = resource.spec.actors.find(candidate => candidate.name === 'follower-1');
          if (!actor) throw new Error('storage-disabled fixture lost follower-1');
          actor.storage = {enabled: false};
        },
      },
    ];
    for (const scenario of scenarios) {
      const directory = join(generated, scenario.id);
      const topology = topologyModule.buildTopology(scenario.counts);
      const {resource} = topologyModule.renderTopology(topology, directory, {
        network: 'equivalence', namespace: 'attacknet-equivalence', probes: scenario.probes,
      });
      scenario.configure?.(resource);
      const input = join(OUTPUT, 'topology', `${scenario.id}.input.json`);
      const expected = join(OUTPUT, 'topology', `${scenario.id}.expected.json`);
      writeJson(input, resource);
      writeFileSync(expected, `${execFileSync('python3', ['-c', pythonRenderer, input], {
        cwd: REPOSITORY, input: controller, encoding: 'utf8',
      }).trim()}\n`);
    }

    const manifest = {
      network: 'attacknet', namespace: 'hacknet-system', actors: [
        {service: 'miner-1', role: 'miner'},
        {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 8},
        {service: 'signer-node-1', role: 'companion', signerIndex: 1, signerWeight: 8},
        {service: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 2},
        {service: 'signer-node-2', role: 'companion', signerIndex: 2, signerWeight: 2},
      ],
    };
    const cases = [
      campaign('pod-failure', {type: 'pod', action: 'pod-failure', parameters: {}}),
      campaign('network-delay', {type: 'network', action: 'delay', parameters: {
        direction: 'both', peerTarget: {actors: ['miner-1'], mode: 'all'}, delay: {latency: '100ms'},
      }}),
      campaign('dns-error', {type: 'dns', action: 'error', parameters: {patterns: ['invalid.*']}}),
      campaign('io-latency', {type: 'io', action: 'latency', parameters: {
        volumePath: '/data', path: '/data/**', delay: '10ms', methods: ['READ', 'WRITE'],
      }}),
      campaign('time-offset', {type: 'time', parameters: {
        timeOffset: '+1m', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor'],
      }}),
      campaign('io-pressure', {type: 'io-pressure', action: 'disk-pressure', parameters: {
        containerNames: ['actor'], severity: 'low', workers: 1, bytesMiB: 32,
        writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
      }}),
      campaign('clock-skew', {type: 'clock-skew', parameters: {
        timeOffset: '-30s', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor'],
      }}),
    ];
    writeJson(join(OUTPUT, 'fault-compiler.json'), {
      manifest,
      cases: cases.map(value => ({campaign: value, expected: faultModule.compileCampaign(value, manifest)})),
    });

    const entries = [];
    for (const path of [
      'fault-compiler.json',
      ...scenarios.flatMap(({id}) => [`topology/${id}.input.json`, `topology/${id}.expected.json`]),
    ].sort()) {
      entries.push({path, digest: sha256(join(OUTPUT, path))});
    }
    writeJson(join(OUTPUT, 'manifest.json'), {
      schema: 'stacks-attacknet-v1alpha1-equivalence-fixtures/v1',
      origin: {
        runtimeRevision: RUNTIME_REVISION,
        topologyOracle: 'contrib/attacknet/legacy/v1alpha1/runtime/topology.mjs',
        faultOracle: 'contrib/attacknet/legacy/v1alpha1/runtime/fault-campaign.mjs',
        workloadRevision: WORKLOAD_REVISION,
        workloadOracle: 'contrib/helm/hacknet/operator/controller.py',
      },
      entries,
    });
    process.stdout.write(`generated ${entries.length} equivalence fixtures under ${relative(REPOSITORY, OUTPUT)}\n`);
  } finally {
    rmSync(working, {recursive: true, force: true});
    rmSync(generated, {recursive: true, force: true});
  }
}

await generate();
