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
    [{type: 'clock-skew', parameters: {
      timeOffset: '-30s', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor'],
    }}, 'ClockSkewPolicy'],
  ];
  for (const [fault, kind] of cases) {
    assert.equal(compileCampaign(campaign({fault: {...fault, duration: '20s'}}), manifest).resource.kind, kind);
  }
  const portable = compileCampaign(campaign({fault: {
    type: 'clock-skew', duration: '20s',
    parameters: {timeOffset: '-30s', clockIds: ['CLOCK_REALTIME'], containerNames: ['actor']},
  }}), manifest);
  assert.equal(portable.resource.apiVersion, 'testing.stacks.org/internal');
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'clock-skew', duration: '20s',
    parameters: {timeOffset: '-30s', clockIds: ['CLOCK_MONOTONIC'], containerNames: ['actor']},
  }}), manifest), /only CLOCK_REALTIME/);
});

test('compiles bounded disk I/O pressure to a trusted controller descriptor without accepting execution input', () => {
  const compiled = compileCampaign(campaign({fault: {
    type: 'io-pressure', action: 'disk-pressure', mode: 'all', duration: '45s',
    parameters: {
      containerNames: ['actor'], severity: 'low', workers: 1, bytesMiB: 32,
      writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
    },
  }}), manifest);
  assert.equal(compiled.resource.kind, 'IOPressurePod');
  assert.equal(compiled.resource.apiVersion, 'testing.stacks.org/internal');
  assert.equal(compiled.resource.spec.action, undefined);
  assert.deepEqual(Object.keys(compiled.resource.spec).sort(), [
    'bytesMiB', 'containerNames', 'duration', 'mode', 'selector', 'workers', 'writeSizeKiB',
  ]);
  assert.deepEqual(compiled.resource.spec.containerNames, ['actor']);
  assert.equal(compiled.resource.spec.image, undefined);
  assert.equal(compiled.resource.spec.command, undefined);
  assert.equal(compiled.resource.spec.workers, 1);
  assert.equal(compiled.resource.spec.bytesMiB, 32);
  assert.equal(compiled.resource.spec.writeSizeKiB, 256);
  assert.deepEqual(compiled.evidence.ioPressure, {
    semantic: 'disk-io-pressure', severity: 'low', workers: 1, bytesMiB: 32,
    writeSizeKiB: 256, tempPath: '/data', minimumLatencyMultiplier: 2,
    minimumAddedLatencyMs: 5,
  });
  assert.equal(
    JSON.parse(compiled.resource.metadata.annotations['testing.stacks.org/io-pressure-contract']).minimumLatencyMultiplier,
    2,
  );
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'io-pressure', action: 'disk-pressure', duration: '30s',
    parameters: {stressngStressors: '--hdd 8192'},
  }}), manifest), /unsupported fault.parameters field stressngStressors/);
  assert.throws(() => compileCampaign(campaign({
    target: {roles: ['companion']},
    fault: {
      type: 'io-pressure', action: 'disk-pressure', mode: 'one', duration: '30s',
      parameters: {
        containerNames: ['actor'], severity: 'low', workers: 1, bytesMiB: 32,
        writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
      },
    },
  }), manifest), /exactly one actor target/);
});

test('disk I/O pressure caps container count, resources, duration, severity, and evidence thresholds', () => {
  const base = {
    containerNames: ['actor'], severity: 'medium', workers: 1, bytesMiB: 64,
    writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
  };
  const fault = parameters => ({
    type: 'io-pressure', action: 'disk-pressure', duration: '30s',
    parameters: {...base, ...parameters},
  });
  assert.throws(() => compileCampaign(campaign({fault: fault({
    containerNames: ['actor', 'attacknet-probe'],
  })}), manifest), /exactly the actor container/);
  assert.throws(() => compileCampaign(campaign({fault: fault({
    containerNames: ['attacknet-probe'],
  })}), manifest), /exactly the actor container/);
  assert.throws(() => compileCampaign(campaign({fault: fault({workers: 3})}), manifest), /1..2/);
  assert.throws(() => compileCampaign(campaign({fault: fault({bytesMiB: 512})}), manifest), /16..256/);
  assert.throws(() => compileCampaign(campaign({fault: fault({writeSizeKiB: 2048})}), manifest), /4..1024/);
  assert.throws(() => compileCampaign(campaign({fault: fault({minimumLatencyMultiplier: 1})}), manifest), /1.1..20/);
  assert.throws(() => compileCampaign(campaign({fault: fault({minimumAddedLatencyMs: 0})}), manifest), /0.5..5000/);
  const missingThreshold = fault({});
  delete missingThreshold.parameters.minimumAddedLatencyMs;
  assert.throws(() => compileCampaign(campaign({fault: missingThreshold}), manifest), /requires fault.parameters.minimumAddedLatencyMs/);
  assert.throws(() => compileCampaign(campaign({fault: {
    ...fault({severity: 'low'}), duration: '61s',
  }}), manifest), /low disk-pressure duration must not exceed 60s/);
  assert.throws(() => compileCampaign(campaign({fault: fault({severity: 'high'})}), manifest), /allowExtremeSeverity/);
  assert.doesNotThrow(() => compileCampaign(campaign({
    fault: {...fault({severity: 'high', workers: 4, bytesMiB: 512}), duration: '300s'},
    safety: {allowExtremeSeverity: true},
  }), manifest));
  assert.throws(() => compileCampaign(campaign({
    fault: {...fault({severity: 'high'}), duration: '301s'},
    safety: {allowExtremeSeverity: true},
  }), manifest), /high disk-pressure duration must not exceed 300s/);
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
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'time', duration: '30s', parameters: {
      timeOffset: '-30s', containerNames: ['actor', 'attacknet-probe'],
    },
  }}), manifest), /at most one container per Pod/);
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

test('compiles the Prometheus harness target to a network-scoped server-owned selector', () => {
  const compiled = compileCampaign(campaign({fault: {
    type: 'network', action: 'partition', duration: '30s', parameters: {
      harnessTarget: 'prometheus', direction: 'both',
    },
  }}), manifest);
  assert.deepEqual(compiled.evidence.peerSelectedActors, ['attacknet-prometheus']);
  assert.deepEqual(compiled.resource.spec.target, {
    mode: 'all', selector: {namespaces: ['hacknet-system'], labelSelectors: {
      'testing.stacks.org/network': 'attacknet',
      'app.kubernetes.io/name': 'attacknet-prometheus',
    }},
  });
  assert.equal(compiled.resource.spec.harnessTarget, undefined);
  assert.throws(() => compileCampaign(campaign({fault: {
    type: 'network', action: 'partition', duration: '30s', parameters: {
      harnessTarget: 'prometheus', peerTarget: {actors: ['miner-1']},
    },
  }}), manifest), /use exactly one/);
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
