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

test('rejects overlong campaign names and non-positive durations', () => {
  const overlong = campaign();
  overlong.metadata.name = `a${'b'.repeat(63)}`;
  assert.throws(() => compileCampaign(overlong, manifest), /at most 63/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'pod', action: 'pod-failure', mode: 'all', duration: '0s',
  }}), manifest), /greater than zero/);
});

test('validates mode values without string or NaN coercion bypasses', () => {
  assert.throws(() => compileCampaign(campaign({
    safety: {maxUnavailableSignerPercent: 'NaN'},
  }), manifest), /finite number/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'pod', action: 'pod-failure', mode: 'fixed', duration: '30s',
  }}), manifest), /value is required/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'pod', action: 'pod-failure', mode: 'fixed-percent', value: 'NaN', duration: '30s',
  }}), manifest), /finite numeric/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'pod', action: 'pod-failure', mode: 'one', value: 1, duration: '30s',
  }}), manifest), /value is forbidden/);

  const fixed = compileCampaign(campaign({
    target: {roles: ['signer']},
    fault: {type: 'pod', action: 'pod-failure', mode: 'fixed', value: 1, duration: '30s'},
    safety: {allowQuorumLoss: true},
  }), manifest);
  assert.equal(fixed.resource.spec.value, '1');
  assert.equal(fixed.evidence.maximumAffectedActors, 1);
});

test('validates target and parameter collection types', () => {
  assert.throws(() => compileCampaign(campaign({target: {actors: 'signer-1'}}), manifest), /must be an array/);
  assert.throws(() => compileCampaign(campaign({target: {actors: ['signer-1', 3]}}), manifest), /non-empty string/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'dns', action: 'error', duration: '30s', parameters: {patterns: '*.internal'},
  }}), manifest), /must be an array/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'time', duration: '30s', parameters: {timeOffset: '-30s', clockIds: ['NOT_A_CLOCK']},
  }}), manifest), /unsupported value/);
});

test('requires action-specific parameters and bounds severity', () => {
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'delay', duration: '30s', parameters: {},
  }}), manifest), /requires parameters.delay/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'loss', duration: '30s', parameters: {loss: {loss: '101'}},
  }}), manifest), /0..100/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'loss', duration: '30s', parameters: {loss: {loss: '75'}},
  }}), manifest), /allowExtremeSeverity/);
  assert.doesNotThrow(() => compileCampaign(campaign({
    fault: {type: 'network', action: 'loss', duration: '30s', parameters: {loss: {loss: '75'}}},
    safety: {allowExtremeSeverity: true},
  }), manifest));
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'pod', action: 'container-kill', duration: '30s', parameters: {},
  }}), manifest), /containerNames/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'io', action: 'latency', duration: '30s', parameters: {volumePath: '/data'},
  }}), manifest), /parameters.delay/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'time', duration: '30s', parameters: {timeOffset: '-10m'},
  }}), manifest), /allowExtremeSeverity/);
});

test('rejects raw network selector escape and compiles enrolled peerTarget safely', () => {
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'partition', duration: '30s', parameters: {
      target: {mode: 'all', selector: {namespaces: ['kube-system']}},
    },
  }}), manifest), /allowUnenrolledNetworkTargets/);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'partition', duration: '30s', parameters: {
      externalTargets: ['10.0.0.0/8'],
    },
  }}), manifest), /allowUnenrolledNetworkTargets/);

  const compiled = compileCampaign(campaign({fault: {
    type: 'network', action: 'partition', duration: '30s', parameters: {
      peerTarget: {actors: ['miner-1'], mode: 'all'},
    },
  }}), manifest);
  assert.equal(compiled.resource.spec.target.selector.namespaces[0], 'hacknet-system');
  assert.equal(compiled.resource.spec.target.selector.labelSelectors['testing.stacks.org/network'], 'attacknet');
  assert.deepEqual(compiled.evidence.peerSelectedActors, ['miner-1']);
  assert.equal(compiled.resource.spec.direction, 'both');
});

test('bounds worst-case miner-majority outage independently of signer quorum', () => {
  const minerManifest = {...manifest, actors: [
    ...manifest.actors,
    {service: 'miner-2', role: 'miner'},
    {service: 'miner-3', role: 'miner'},
  ]};
  const outage = campaign({
    target: {roles: ['miner']},
    fault: {type: 'pod', action: 'pod-failure', mode: 'fixed', value: 2, duration: '30s'},
  });
  assert.throws(() => compileCampaign(outage, minerManifest), /allowMinerMajorityOutage/);
  outage.spec.safety = {allowMinerMajorityOutage: true};
  const compiled = compileCampaign(outage, minerManifest);
  assert.equal(compiled.evidence.minerImpact.affectedCount, 2);
  assert.equal(compiled.evidence.minerImpact.totalCount, 3);
});

test('one mode uses mode-aware impact instead of treating every candidate as unavailable', () => {
  const minerManifest = {...manifest, actors: [
    ...manifest.actors,
    {service: 'miner-2', role: 'miner'},
    {service: 'miner-3', role: 'miner'},
  ]};
  const compiled = compileCampaign(campaign({
    target: {roles: ['miner']},
    fault: {type: 'pod', action: 'pod-failure', mode: 'one', duration: '30s'},
  }), minerManifest);
  assert.equal(compiled.evidence.minerImpact.affectedCount, 1);
});
