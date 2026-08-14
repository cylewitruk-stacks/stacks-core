import assert from 'node:assert/strict';
import test from 'node:test';

import {compileCampaign} from './fault-campaign.mjs';

const manifest = {
  network: 'attacknet', namespace: 'hacknet-system', actors: [
    {service: 'miner-1', role: 'miner'},
    {service: 'signer-node-1', role: 'companion', signerIndex: 1, signerWeight: 1},
    {service: 'signer-1', role: 'signer', signerIndex: 1, signerWeight: 1},
    {service: 'signer-node-2', role: 'companion', signerIndex: 2, signerWeight: 2},
    {service: 'signer-2', role: 'signer', signerIndex: 2, signerWeight: 2},
    {service: 'signer-node-3', role: 'companion', signerIndex: 3, signerWeight: 7},
    {service: 'signer-3', role: 'signer', signerIndex: 3, signerWeight: 7},
  ],
};

function campaign(overrides = {}) {
  return {metadata: {name: 'companion-pause'}, spec: {
    networkRef: 'attacknet', target: {actors: ['signer-node-2']},
    fault: {type: 'pod', action: 'pod-failure', mode: 'all', duration: '30s'},
    safety: {}, ...overrides,
  }};
}

test('compiles a bounded actor fault with an enrolled-network selector', () => {
  const result = compileCampaign(campaign(), manifest);
  assert.equal(result.resource.kind, 'PodChaos');
  assert.deepEqual(result.resource.spec.selector.expressionSelectors[0].values, ['signer-node-2']);
  assert.equal(result.evidence.signerImpact.affectedWeight, 2);
});

test('deduplicates signer and companion weight for quorum safety', () => {
  const result = compileCampaign(campaign({target: {actors: ['signer-node-2', 'signer-2']}}), manifest);
  assert.equal(result.evidence.signerImpact.affectedWeight, 2);
});

test('requires conspicuous opt-in for quorum loss, burnchain, and long faults', () => {
  assert.throws(() => compileCampaign(campaign({target: {actors: ['signer-3']}}), manifest), /signer impact/);
  const burnchainManifest = {...manifest, actors: [...manifest.actors, {service: 'bitcoin', role: 'burnchain'}]};
  assert.throws(() => compileCampaign(campaign({target: {actors: ['bitcoin']}}), burnchainManifest), /allowBurnchain/);
  assert.throws(() => compileCampaign(campaign({fault: {type: 'pod', action: 'pod-failure', duration: '11m'}}), manifest), /allowExtendedDuration/);
});

test('compiles network, DNS, I/O, and explicit clock-source faults', () => {
  const cases = [
    [{type: 'network', action: 'delay', parameters: {delay: {latency: '250ms'}}}, 'NetworkChaos'],
    [{type: 'dns', action: 'error', parameters: {patterns: ['*.svc.cluster.local']}}, 'DNSChaos'],
    [{type: 'io', action: 'latency', parameters: {volumePath: '/data', path: '/data/**', delay: '100ms'}}, 'IOChaos'],
    [{type: 'time', parameters: {timeOffset: '-30s', clockIds: ['CLOCK_REALTIME']}}, 'TimeChaos'],
  ];
  for (const [fault, kind] of cases) {
    assert.equal(compileCampaign(campaign({fault: {...fault, duration: '20s'}}), manifest).resource.kind, kind);
  }
});
