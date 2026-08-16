#!/usr/bin/env node

import {writeFileSync} from 'node:fs';

const API_VERSION = 'testing.stacks.org/v1alpha1';

function dnsLabel(value, field) {
  if (typeof value !== 'string' || value.length > 40
      || !/^[a-z]([-a-z0-9]*[a-z0-9])?$/.test(value)) {
    throw new Error(`${field} must be a DNS label of at most 40 characters`);
  }
  return value;
}

function option(name, fallback) {
  const prefix = `--${name}=`;
  const argument = process.argv.find(value => value.startsWith(prefix));
  return argument ? argument.slice(prefix.length) : fallback;
}

function safety() {
  return {
    maxUnavailableSignerPercent: 30,
    maxUnavailableMinerPercent: 50,
    allowQuorumLoss: false,
    allowBurnchain: false,
    allowExtendedDuration: false,
    allowExtremeSeverity: false,
    allowMinerMajorityOutage: false,
    allowUnenrolledNetworkTargets: false,
  };
}

function campaign(namespace, name, networkRef, target, fault, effect, recovery) {
  return {
    apiVersion: API_VERSION,
    kind: 'FaultCampaign',
    metadata: {name, namespace},
    spec: {
      template: true,
      networkRef,
      target: {actors: [target]},
      fault,
      safety: safety(),
      effectAssertions: [{type: effect, actor: target, timeoutSeconds: 120}],
      recoveryAssertions: [{type: recovery, actor: target, timeoutSeconds: 300}],
    },
  };
}

export function buildFinalSoakRun({
  network = 'attacknet', namespace = 'hacknet-system', name = 'final-soak',
  seed = 'stacks-final-soak-v1',
} = {}) {
  dnsLabel(network, 'network');
  dnsLabel(namespace, 'namespace');
  dnsLabel(name, 'name');
  if (typeof seed !== 'string' || seed.length === 0 || seed.length > 256) {
    throw new Error('seed must be a non-empty string of at most 256 characters');
  }

  const names = {
    pod: `${name}-pod`, network: `${name}-network`, dns: `${name}-dns`, io: `${name}-io`,
  };
  for (const [kind, value] of Object.entries(names)) dnsLabel(value, `${kind} campaign name`);

  const campaigns = [
    campaign(namespace, names.pod, network, 'signer-node-10', {
      type: 'pod', action: 'pod-kill', mode: 'all', duration: '20s', parameters: {gracePeriod: 0},
    }, 'PodRestarted', 'TargetReady'),
    campaign(namespace, names.network, network, 'follower-5', {
      type: 'network', action: 'delay', mode: 'all', duration: '30s',
      parameters: {
        direction: 'both', peerTarget: {actors: ['miner-1'], mode: 'all'},
        delay: {latency: '750ms', jitter: '100ms', correlation: '50'},
      },
    }, 'NetworkDegraded', 'NetworkRecovered'),
    campaign(namespace, names.dns, network, 'follower-4', {
      type: 'dns', action: 'error', mode: 'all', duration: '20s',
      parameters: {patterns: [`${network}-miner-1.${namespace}.svc.cluster.local`]},
    }, 'DNSDegraded', 'DNSRecovered'),
    campaign(namespace, names.io, network, 'follower-3', {
      type: 'io-pressure', action: 'disk-pressure', mode: 'all', duration: '45s',
      parameters: {
        containerNames: ['actor'], severity: 'low', workers: 1, bytesMiB: 32,
        writeSizeKiB: 256, minimumLatencyMultiplier: 2, minimumAddedLatencyMs: 5,
      },
    }, 'IOPressureObserved', 'IOPressureRecovered'),
  ];

  const run = {
    apiVersion: API_VERSION,
    kind: 'AttacknetRun',
    metadata: {name, namespace},
    spec: {
      networkRef: network,
      seed,
      decisionAlgorithm: 'hmac-sha256-decisions/v1',
      campaignCatalog: [
        {name: 'pod-restart', campaignRef: names.pod},
        {name: 'network-delay', campaignRef: names.network},
        {name: 'dns-error', campaignRef: names.dns},
        {name: 'io-pressure', campaignRef: names.io},
      ],
      sequence: [
        {id: 'restart-one-companion', campaign: 'pod-restart', delayAfterSeconds: 15, enabled: true},
        {id: 'delay-one-follower-path', campaign: 'network-delay', delayAfterSeconds: 15, enabled: true},
        {id: 'break-one-follower-dns', campaign: 'dns-error', delayAfterSeconds: 15, enabled: true},
        {id: 'pressure-one-follower-pvc', campaign: 'io-pressure', delayAfterSeconds: 15, enabled: true},
      ],
      budgets: {
        maxCampaigns: 4,
        maxWallTimeSeconds: 3600,
        maxCumulativeFaultSeconds: 120,
        maxActiveFaults: 1,
        maxSignerImpactPercent: 30,
        maxBurnchainFaults: 0,
        maxInconclusiveCampaigns: 0,
      },
      stopPolicy: {
        onCampaignFailure: 'PauseForTriage',
        onInconclusive: 'PauseForTriage',
        onBudgetExhausted: 'Stop',
        onSuccess: 'Continue',
      },
      attributionPolicy: {
        requiredOnFailure: true,
        requireIncidentBundle: true,
        allowedTerminalStates: ['Triaged', 'Remediated', 'Inconclusive'],
      },
      replay: {enabled: false, requireSameResolvedImages: true, verifyExpectedFailure: true},
      resume: {enabled: false, requireSameSeed: true, requireSameResolvedImages: true},
      minimization: {enabled: false, strategy: 'FailurePrefix', maxAttempts: 0, requireFreshNetwork: true},
    },
  };
  return {apiVersion: 'v1', kind: 'List', items: [...campaigns, run]};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = buildFinalSoakRun({
    network: option('network', 'attacknet'),
    namespace: option('namespace', 'hacknet-system'),
    name: option('name', 'final-soak'),
    seed: option('seed', 'stacks-final-soak-v1'),
  });
  const output = option('output', '');
  const encoded = `${JSON.stringify(result, null, 2)}\n`;
  if (output) writeFileSync(output, encoded);
  else process.stdout.write(encoded);
}
