import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
import test from 'node:test';

import {compileCampaign} from './fault-campaign.mjs';

const ATTACKNET_DIR = dirname(fileURLToPath(import.meta.url));
const OPERATOR_DIR = join(ATTACKNET_DIR, '..', 'helm', 'hacknet', 'operator');
const manifest = {
  network: 'attacknet', namespace: 'hacknet-system', actors: [
    {service: 'miner-1', role: 'miner'},
    {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 8},
    {service: 'signer-node-1', role: 'companion', signerIndex: 1, signerWeight: 8},
    {service: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 2},
    {service: 'signer-node-2', role: 'companion', signerIndex: 2, signerWeight: 2},
  ],
};
const safety = {
  maxUnavailableSignerPercent: 30,
  maxUnavailableMinerPercent: 50,
  allowQuorumLoss: false,
  allowBurnchain: false,
  allowExtendedDuration: false,
  allowExtremeSeverity: false,
  allowMinerMajorityOutage: false,
  allowUnenrolledNetworkTargets: false,
};

function campaign(name, fault, target = {actors: ['signer-node-2']}) {
  return {
    apiVersion: 'testing.stacks.org/v1alpha1', kind: 'FaultCampaign',
    metadata: {name, namespace: manifest.namespace},
    spec: {networkRef: manifest.network, target, fault: {mode: 'one', duration: '30s', ...fault}, safety},
  };
}

const campaigns = [
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

test('Go and JavaScript production compilers emit identical contracts for every fault type', () => {
  const expected = campaigns.map(value => compileCampaign(value, manifest));
  const result = spawnSync('go', ['run', './cmd/compile-check'], {
    cwd: OPERATOR_DIR,
    encoding: 'utf8',
    env: {...process.env, GOCACHE: process.env.GOCACHE ?? '/private/tmp/attacknet-go-cache'},
    input: JSON.stringify({cases: campaigns.map(value => ({campaign: value, manifest}))}),
  });
  assert.equal(result.status, 0, `Go compiler failed:\n${result.stderr}`);
  assert.deepEqual(JSON.parse(result.stdout).cases, expected);
});
