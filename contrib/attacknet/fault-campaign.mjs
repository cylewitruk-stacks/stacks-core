#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';

const NETWORK_LABEL = 'testing.stacks.org/network';
const ACTOR_LABEL = 'testing.stacks.org/actor';
const ROLE_LABEL = 'testing.stacks.org/role';
const TYPES = Object.freeze({pod: 'PodChaos', network: 'NetworkChaos', dns: 'DNSChaos', io: 'IOChaos', time: 'TimeChaos'});
const ACTIONS = Object.freeze({
  pod: new Set(['pod-kill', 'pod-failure', 'container-kill']),
  network: new Set(['netem', 'delay', 'loss', 'duplicate', 'corrupt', 'partition', 'bandwidth']),
  dns: new Set(['error', 'random']),
  io: new Set(['latency', 'fault', 'attrOverride', 'mistake']),
});
const MODES = new Set(['one', 'all', 'fixed', 'fixed-percent', 'random-max-percent']);

function requireName(value, field) {
  if (typeof value !== 'string' || !/^[a-z]([-a-z0-9]*[a-z0-9])?$/.test(value)) {
    throw new Error(`${field} must be a DNS label`);
  }
  return value;
}

function durationSeconds(value) {
  const match = /^(\d+)(ms|s|m|h)$/.exec(value ?? '');
  if (!match) throw new Error(`duration must use an integer ms/s/m/h value, received ${value}`);
  const scalar = {ms: 0.001, s: 1, m: 60, h: 3600}[match[2]];
  return Number(match[1]) * scalar;
}

function selectedActors(target, manifest) {
  const actors = manifest.workloads ?? manifest.actors ?? [];
  const names = target.actors ?? [];
  const roles = target.roles ?? [];
  if (names.length === 0 && roles.length === 0) throw new Error('target requires actors or roles');
  const known = new Set(actors.map(actor => actor.service));
  for (const name of names) if (!known.has(name)) throw new Error(`unknown target actor ${name}`);
  const selected = actors.filter(actor =>
    (names.length === 0 || names.includes(actor.service))
      && (roles.length === 0 || roles.includes(actor.role)));
  if (selected.length === 0) throw new Error('target selector matches no actors');
  return selected;
}

function signerImpact(selected, manifest) {
  const total = new Map();
  for (const actor of manifest.workloads ?? manifest.actors ?? []) {
    if (actor.signerIndex) total.set(actor.signerIndex, actor.signerWeight);
  }
  const affected = new Map();
  for (const actor of selected) {
    if (actor.signerIndex) affected.set(actor.signerIndex, actor.signerWeight);
  }
  const totalWeight = [...total.values()].reduce((sum, value) => sum + value, 0);
  const affectedWeight = [...affected.values()].reduce((sum, value) => sum + value, 0);
  return {totalWeight, affectedWeight, percent: totalWeight ? affectedWeight * 100 / totalWeight : 0};
}

function selector(target, manifest) {
  const expressions = [];
  if (target.actors?.length) expressions.push({key: ACTOR_LABEL, operator: 'In', values: target.actors});
  if (target.roles?.length) expressions.push({key: ROLE_LABEL, operator: 'In', values: target.roles});
  return {namespaces: [manifest.namespace], labelSelectors: {[NETWORK_LABEL]: manifest.network}, expressionSelectors: expressions};
}

export function compileCampaign(campaign, manifest) {
  const metadata = campaign.metadata ?? {};
  const spec = campaign.spec ?? {};
  const name = requireName(metadata.name, 'metadata.name');
  if (spec.networkRef !== manifest.network) throw new Error(`networkRef ${spec.networkRef} does not match manifest ${manifest.network}`);
  const fault = spec.fault ?? {};
  if (!(fault.type in TYPES)) throw new Error(`unsupported fault type ${fault.type}`);
  if (fault.type !== 'time' && !ACTIONS[fault.type].has(fault.action)) throw new Error(`unsupported ${fault.type} action ${fault.action}`);
  const mode = fault.mode ?? 'one';
  if (!MODES.has(mode)) throw new Error(`unsupported fault mode ${mode}`);
  const duration = fault.duration ?? '30s';
  const safety = spec.safety ?? {};
  if (durationSeconds(duration) > 600 && safety.allowExtendedDuration !== true) {
    throw new Error('faults longer than 10m require safety.allowExtendedDuration=true');
  }
  const selected = selectedActors(spec.target ?? {}, manifest);
  if (selected.some(actor => actor.role === 'burnchain') && safety.allowBurnchain !== true) {
    throw new Error('burnchain faults require safety.allowBurnchain=true');
  }
  const impact = signerImpact(selected, manifest);
  const maxUnavailable = safety.maxUnavailableSignerPercent ?? 30;
  if (impact.percent > maxUnavailable && safety.allowQuorumLoss !== true) {
    throw new Error(`selected signer impact ${impact.percent.toFixed(1)}% exceeds ${maxUnavailable}%`);
  }
  const chaosSpec = {mode, duration, selector: selector(spec.target, manifest)};
  if (fault.value !== undefined) chaosSpec.value = String(fault.value);
  if (fault.type !== 'time') chaosSpec.action = fault.action;
  const parameters = fault.parameters ?? {};
  const allowed = {
    pod: ['containerNames', 'gracePeriod'],
    network: ['direction', 'target', 'targetDevice', 'device', 'delay', 'loss', 'duplicate', 'corrupt', 'bandwidth', 'rate', 'externalTargets'],
    dns: ['patterns', 'containerNames'],
    io: ['volumePath', 'path', 'methods', 'delay', 'errno', 'percent', 'mistake', 'attr', 'containerNames'],
    time: ['timeOffset', 'clockIds', 'containerNames'],
  }[fault.type];
  for (const [key, value] of Object.entries(parameters)) {
    if (!allowed.includes(key)) throw new Error(`unsupported ${fault.type} parameter ${key}`);
    chaosSpec[key] = value;
  }
  if (fault.type === 'io' && !chaosSpec.volumePath) throw new Error('I/O chaos requires parameters.volumePath');
  if (fault.type === 'time' && !chaosSpec.timeOffset) throw new Error('time chaos requires parameters.timeOffset');
  const resource = {
    apiVersion: 'chaos-mesh.org/v1alpha1', kind: TYPES[fault.type],
    metadata: {name, namespace: manifest.namespace, labels: {[NETWORK_LABEL]: manifest.network, 'testing.stacks.org/campaign': name}},
    spec: chaosSpec,
  };
  return {resource, evidence: {selectedActors: selected.map(actor => actor.service), signerImpact: impact, safety}};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [campaignPath, manifestPath, outputPath] = process.argv.slice(2);
  if (!campaignPath || !manifestPath) throw new Error('usage: fault-campaign.mjs CAMPAIGN MANIFEST [OUTPUT]');
  const compiled = compileCampaign(JSON.parse(readFileSync(campaignPath, 'utf8')), JSON.parse(readFileSync(manifestPath, 'utf8')));
  if (outputPath) {
    writeFileSync(outputPath, `${JSON.stringify(compiled.resource, null, 2)}\n`);
    writeFileSync(`${outputPath}.evidence.json`, `${JSON.stringify(compiled.evidence, null, 2)}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(compiled, null, 2)}\n`);
  }
}
