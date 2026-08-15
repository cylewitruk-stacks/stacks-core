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
const SAFETY_FIELDS = Object.freeze({
  allowBurnchain: 'boolean',
  allowExtendedDuration: 'boolean',
  allowExtremeSeverity: 'boolean',
  allowMinerMajorityOutage: 'boolean',
  allowQuorumLoss: 'boolean',
  allowUnenrolledNetworkTargets: 'boolean',
  maxUnavailableMinerPercent: 'number',
  maxUnavailableSignerPercent: 'number',
});
const NETWORK_COMMON_FIELDS = new Set(['direction', 'peerTarget', 'target', 'targetDevice', 'device', 'externalTargets']);
const IO_METHODS = new Set([
  'READ', 'WRITE', 'FLUSH', 'FSYNC', 'FDATASYNC', 'READDIR', 'SYNC', 'OPEN', 'MKDIR',
  'MKNOD', 'CHOWN', 'CHMOD', 'UTIMES', 'LINK', 'UNLINK', 'RENAME',
]);
const CLOCK_IDS = new Set(['CLOCK_REALTIME', 'CLOCK_MONOTONIC', 'CLOCK_PROCESS_CPUTIME_ID', 'CLOCK_THREAD_CPUTIME_ID']);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, field) {
  if (!isObject(value)) throw new Error(`${field} must be an object`);
  return value;
}

function rejectUnknownFields(value, allowed, field) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`unsupported ${field} field ${key}`);
  }
}

function requireName(value, field) {
  if (typeof value !== 'string' || value.length > 63 || !/^[a-z]([-a-z0-9]*[a-z0-9])?$/.test(value)) {
    throw new Error(`${field} must be a DNS label of at most 63 characters`);
  }
  return value;
}

function requireString(value, field, {nonempty = true, maxLength = 1024} = {}) {
  if (typeof value !== 'string' || (nonempty && value.length === 0) || value.length > maxLength) {
    throw new Error(`${field} must be ${nonempty ? 'a non-empty' : 'a'} string of at most ${maxLength} characters`);
  }
  return value;
}

function stringArray(value, field, {required = false, allowed} = {}) {
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  if (required && value.length === 0) throw new Error(`${field} must not be empty`);
  if (value.length > 256) throw new Error(`${field} must contain at most 256 entries`);
  const result = value.map((entry, index) => {
    const text = requireString(entry, `${field}[${index}]`, {maxLength: 1024});
    if (allowed && !allowed.has(text)) throw new Error(`${field}[${index}] has unsupported value ${text}`);
    return text;
  });
  if (new Set(result).size !== result.length) throw new Error(`${field} must not contain duplicates`);
  return result;
}

function finiteNumber(value, field, {min = -Infinity, max = Infinity, integer = false} = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) {
    const range = `${Number.isFinite(min) ? min : '-Infinity'}..${Number.isFinite(max) ? max : 'Infinity'}`;
    throw new Error(`${field} must be a finite ${integer ? 'integer ' : ''}number in ${range}`);
  }
  return value;
}

function numericParameter(value, field, options = {}) {
  let number = value;
  if (typeof value === 'string' && /^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)) number = Number(value);
  if (typeof number !== 'number' || !Number.isFinite(number)) {
    throw new Error(`${field} must be a finite numeric value`);
  }
  finiteNumber(number, field, options);
  return number;
}

function durationSeconds(value, field = 'duration', {allowZero = false, signed = false} = {}) {
  if (typeof value !== 'string') throw new Error(`${field} must be a string`);
  const expression = signed ? /^([+-]?)(\d+)(ms|s|m|h)$/ : /^(\d+)(ms|s|m|h)$/;
  const match = expression.exec(value);
  if (!match) throw new Error(`${field} must use an integer ${signed ? 'signed ' : ''}ms/s/m/h value, received ${value}`);
  const sign = signed && match[1] === '-' ? -1 : 1;
  const amountIndex = signed ? 2 : 1;
  const unitIndex = signed ? 3 : 2;
  const scalar = {ms: 0.001, s: 1, m: 60, h: 3600}[match[unitIndex]];
  const result = sign * Number(match[amountIndex]) * scalar;
  if (!Number.isFinite(result) || (!allowZero && result === 0)) throw new Error(`${field} must be greater than zero`);
  return result;
}

function validateTarget(target, field = 'target', extraFields = []) {
  requireObject(target, field);
  rejectUnknownFields(target, new Set(['actors', 'roles', ...extraFields]), field);
  const actors = target.actors === undefined ? [] : stringArray(target.actors, `${field}.actors`);
  const roles = target.roles === undefined ? [] : stringArray(target.roles, `${field}.roles`);
  if (actors.length === 0 && roles.length === 0) throw new Error(`${field} requires actors or roles`);
  return {...target, actors, roles};
}

function manifestActors(manifest) {
  const actors = manifest.workloads ?? manifest.actors;
  if (!Array.isArray(actors) || actors.length === 0) throw new Error('manifest actors must be a non-empty array');
  const services = new Set();
  const signerWeights = new Map();
  return actors.map((actor, index) => {
    requireObject(actor, `manifest.actors[${index}]`);
    const service = requireName(actor.service, `manifest.actors[${index}].service`);
    const role = requireString(actor.role, `manifest.actors[${index}].role`, {maxLength: 63});
    if (services.has(service)) throw new Error(`manifest contains duplicate actor ${service}`);
    services.add(service);
    if (actor.signerIndex !== undefined) {
      finiteNumber(actor.signerIndex, `manifest actor ${service} signerIndex`, {min: 1, integer: true});
      if (actor.signerWeight === undefined) throw new Error(`manifest actor ${service} with signerIndex requires signerWeight`);
      finiteNumber(actor.signerWeight, `manifest actor ${service} signerWeight`, {min: Number.MIN_VALUE});
      const priorWeight = signerWeights.get(actor.signerIndex);
      if (priorWeight !== undefined && priorWeight !== actor.signerWeight) {
        throw new Error(`manifest signer ${actor.signerIndex} has inconsistent weights`);
      }
      signerWeights.set(actor.signerIndex, actor.signerWeight);
    } else if (actor.signerWeight !== undefined) {
      throw new Error(`manifest actor ${service} with signerWeight requires signerIndex`);
    }
    return {...actor, service, role};
  });
}

function selectedActors(target, actors, field = 'target') {
  const names = target.actors;
  const roles = target.roles;
  const known = new Set(actors.map(actor => actor.service));
  for (const name of names) if (!known.has(name)) throw new Error(`unknown ${field} actor ${name}`);
  const selected = actors.filter(actor =>
    (names.length === 0 || names.includes(actor.service))
      && (roles.length === 0 || roles.includes(actor.role)));
  if (selected.length === 0) throw new Error(`${field} selector matches no actors`);
  return selected;
}

function normalizedMode(mode, value, candidateCount, field = 'fault') {
  if (typeof mode !== 'string' || !MODES.has(mode)) throw new Error(`unsupported fault mode ${mode}`);
  if (mode === 'one' || mode === 'all') {
    if (value !== undefined) throw new Error(`${field}.value is forbidden when mode is ${mode}`);
    return {mode, value: undefined, maximumCount: mode === 'one' ? 1 : candidateCount};
  }
  if (value === undefined) throw new Error(`${field}.value is required when mode is ${mode}`);
  const parsed = numericParameter(value, `${field}.value`, {
    min: 1, max: mode === 'fixed' ? candidateCount : 100, integer: true,
  });
  const maximumCount = mode === 'fixed' ? parsed : Math.ceil(candidateCount * parsed / 100);
  return {mode, value: String(parsed), maximumCount};
}

function signerImpact(selected, actors, maximumCount) {
  const total = new Map();
  for (const actor of actors) {
    if (actor.signerIndex !== undefined) total.set(actor.signerIndex, actor.signerWeight ?? 0);
  }
  const candidate = new Map();
  for (const actor of selected) {
    if (actor.signerIndex !== undefined) candidate.set(actor.signerIndex, actor.signerWeight ?? 0);
  }
  const totalWeight = [...total.values()].reduce((sum, value) => sum + value, 0);
  const selectedWeights = [...candidate.values()].sort((left, right) => right - left).slice(0, maximumCount);
  const affectedWeight = selectedWeights.reduce((sum, value) => sum + value, 0);
  return {totalWeight, affectedWeight, percent: totalWeight ? affectedWeight * 100 / totalWeight : 0};
}

function minerImpact(selected, actors, maximumCount) {
  const totalCount = actors.filter(actor => actor.role === 'miner').length;
  const candidateCount = selected.filter(actor => actor.role === 'miner').length;
  const affectedCount = Math.min(candidateCount, maximumCount);
  return {totalCount, affectedCount, percent: totalCount ? affectedCount * 100 / totalCount : 0};
}

function selector(target, manifest) {
  const expressions = [];
  if (target.actors.length) expressions.push({key: ACTOR_LABEL, operator: 'In', values: target.actors});
  if (target.roles.length) expressions.push({key: ROLE_LABEL, operator: 'In', values: target.roles});
  return {namespaces: [manifest.namespace], labelSelectors: {[NETWORK_LABEL]: manifest.network}, expressionSelectors: expressions};
}

function validateSafety(input) {
  const safety = requireObject(input, 'spec.safety');
  rejectUnknownFields(safety, new Set(Object.keys(SAFETY_FIELDS)), 'spec.safety');
  for (const [field, value] of Object.entries(safety)) {
    if (SAFETY_FIELDS[field] === 'boolean' && typeof value !== 'boolean') throw new Error(`spec.safety.${field} must be a boolean`);
  }
  const maxUnavailableSignerPercent = safety.maxUnavailableSignerPercent === undefined
    ? 30 : finiteNumber(safety.maxUnavailableSignerPercent, 'spec.safety.maxUnavailableSignerPercent', {min: 0, max: 100});
  const maxUnavailableMinerPercent = safety.maxUnavailableMinerPercent === undefined
    ? 50 : finiteNumber(safety.maxUnavailableMinerPercent, 'spec.safety.maxUnavailableMinerPercent', {min: 0, max: 100});
  if (maxUnavailableSignerPercent > 30 && safety.allowQuorumLoss !== true) {
    throw new Error('maxUnavailableSignerPercent above 30 requires safety.allowQuorumLoss=true');
  }
  if (maxUnavailableMinerPercent > 50 && safety.allowMinerMajorityOutage !== true) {
    throw new Error('maxUnavailableMinerPercent above 50 requires safety.allowMinerMajorityOutage=true');
  }
  return {...safety, maxUnavailableSignerPercent, maxUnavailableMinerPercent};
}

function requireExtreme(condition, safety, message) {
  if (condition && safety.allowExtremeSeverity !== true) throw new Error(`${message} requires safety.allowExtremeSeverity=true`);
}

function validatePercentage(value, field, safety, extremeAbove = 50) {
  const result = numericParameter(value, field, {min: 0, max: 100});
  requireExtreme(result > extremeAbove, safety, `${field} above ${extremeAbove}%`);
  return result;
}

function validateDelay(value, field, safety) {
  const delay = requireObject(value, field);
  rejectUnknownFields(delay, new Set(['latency', 'correlation', 'jitter']), field);
  const latency = durationSeconds(delay.latency, `${field}.latency`);
  requireExtreme(latency > 5, safety, `${field}.latency above 5s`);
  if (delay.jitter !== undefined) durationSeconds(delay.jitter, `${field}.jitter`, {allowZero: true});
  if (delay.correlation !== undefined) validatePercentage(delay.correlation, `${field}.correlation`, safety, 100);
}

function validatePacketEffect(value, field, key, safety) {
  const effect = requireObject(value, field);
  rejectUnknownFields(effect, new Set([key, 'correlation']), field);
  if (effect[key] === undefined) throw new Error(`${field}.${key} is required`);
  validatePercentage(effect[key], `${field}.${key}`, safety);
  if (effect.correlation !== undefined) validatePercentage(effect.correlation, `${field}.correlation`, safety, 100);
}

function validateBandwidth(value, field, safety) {
  const bandwidth = requireObject(value, field);
  rejectUnknownFields(bandwidth, new Set(['rate', 'limit', 'buffer', 'peakrate', 'minburst']), field);
  const rate = requireString(bandwidth.rate, `${field}.rate`, {maxLength: 64});
  if (!/^\d+(?:\.\d+)?(?:bps|kbps|mbps|gbps)$/.test(rate)) throw new Error(`${field}.rate must be a bps/kbps/mbps/gbps rate`);
  const bitsPerSecond = Number(rate.match(/^\d+(?:\.\d+)?/)[0]) * {bps: 1, kbps: 1e3, mbps: 1e6, gbps: 1e9}[rate.match(/[a-z]+$/)[0]];
  requireExtreme(bitsPerSecond < 10_000, safety, `${field}.rate below 10kbps`);
  for (const key of ['limit', 'buffer', 'minburst']) {
    if (bandwidth[key] !== undefined) finiteNumber(bandwidth[key], `${field}.${key}`, {min: 1, max: 2 ** 31 - 1, integer: true});
  }
  if (bandwidth.peakrate !== undefined) requireString(bandwidth.peakrate, `${field}.peakrate`, {maxLength: 64});
}

function validateNetworkParameters(action, parameters, safety, actors, manifest) {
  const actionFields = {
    netem: new Set(['delay', 'loss', 'duplicate', 'corrupt']),
    delay: new Set(['delay']),
    loss: new Set(['loss']),
    duplicate: new Set(['duplicate']),
    corrupt: new Set(['corrupt']),
    partition: new Set([]),
    bandwidth: new Set(['bandwidth']),
  }[action];
  rejectUnknownFields(parameters, new Set([...NETWORK_COMMON_FIELDS, ...actionFields]), 'fault.parameters');
  if (parameters.direction !== undefined && !new Set(['to', 'from', 'both']).has(parameters.direction)) {
    throw new Error('fault.parameters.direction must be to, from, or both');
  }
  for (const field of ['targetDevice', 'device']) {
    if (parameters[field] !== undefined) requireString(parameters[field], `fault.parameters.${field}`, {maxLength: 64});
  }
  if (parameters.target !== undefined && parameters.peerTarget !== undefined) {
    throw new Error('use either fault.parameters.peerTarget or raw target, not both');
  }
  if ((parameters.target !== undefined || parameters.externalTargets !== undefined)
      && safety.allowUnenrolledNetworkTargets !== true) {
    throw new Error('raw target/externalTargets require safety.allowUnenrolledNetworkTargets=true; use peerTarget for enrolled actors');
  }

  let peerEvidence;
  if (parameters.peerTarget !== undefined) {
    const peerTarget = validateTarget(parameters.peerTarget, 'fault.parameters.peerTarget', ['mode', 'value']);
    const peerSelected = selectedActors(peerTarget, actors, 'peerTarget');
    const peerMode = normalizedMode(peerTarget.mode ?? 'all', peerTarget.value, peerSelected.length, 'fault.parameters.peerTarget');
    parameters.target = {mode: peerMode.mode, selector: selector(peerTarget, manifest)};
    if (peerMode.value !== undefined) parameters.target.value = peerMode.value;
    delete parameters.peerTarget;
    peerEvidence = peerSelected.map(actor => actor.service);
  }
  if (parameters.target !== undefined && !isObject(parameters.target)) throw new Error('fault.parameters.target must be an object');
  if (parameters.externalTargets !== undefined) stringArray(parameters.externalTargets, 'fault.parameters.externalTargets', {required: true});

  if (action === 'netem' && !['delay', 'loss', 'duplicate', 'corrupt'].some(field => parameters[field] !== undefined)) {
    throw new Error('network netem requires delay, loss, duplicate, or corrupt parameters');
  }
  if (action === 'partition' && parameters.target === undefined && parameters.externalTargets === undefined) {
    throw new Error('network partition requires peerTarget, raw target, or externalTargets');
  }
  if (action !== 'netem' && action !== 'partition' && parameters[action] === undefined) {
    throw new Error(`network ${action} requires parameters.${action}`);
  }
  if (parameters.delay !== undefined) validateDelay(parameters.delay, 'fault.parameters.delay', safety);
  if (parameters.loss !== undefined) validatePacketEffect(parameters.loss, 'fault.parameters.loss', 'loss', safety);
  if (parameters.duplicate !== undefined) validatePacketEffect(parameters.duplicate, 'fault.parameters.duplicate', 'duplicate', safety);
  if (parameters.corrupt !== undefined) validatePacketEffect(parameters.corrupt, 'fault.parameters.corrupt', 'corrupt', safety);
  if (parameters.bandwidth !== undefined) validateBandwidth(parameters.bandwidth, 'fault.parameters.bandwidth', safety);
  if (parameters.target !== undefined && parameters.direction === undefined) parameters.direction = 'both';
  return peerEvidence;
}

function validatePodParameters(action, parameters, safety) {
  const allowed = action === 'container-kill' ? new Set(['containerNames'])
    : action === 'pod-kill' ? new Set(['gracePeriod']) : new Set();
  rejectUnknownFields(parameters, allowed, 'fault.parameters');
  if (action === 'container-kill') stringArray(parameters.containerNames, 'fault.parameters.containerNames', {required: true});
  if (parameters.gracePeriod !== undefined) {
    finiteNumber(parameters.gracePeriod, 'fault.parameters.gracePeriod', {min: 0, max: 3600, integer: true});
    requireExtreme(parameters.gracePeriod > 60, safety, 'fault.parameters.gracePeriod above 60s');
  }
}

function validateDnsParameters(parameters) {
  rejectUnknownFields(parameters, new Set(['patterns', 'containerNames']), 'fault.parameters');
  const patterns = stringArray(parameters.patterns, 'fault.parameters.patterns', {required: true});
  for (const [index, pattern] of patterns.entries()) {
    if (pattern.length > 253) throw new Error(`fault.parameters.patterns[${index}] exceeds 253 characters`);
  }
  if (parameters.containerNames !== undefined) stringArray(parameters.containerNames, 'fault.parameters.containerNames', {required: true});
}

function validateIoParameters(action, parameters, safety) {
  const common = ['volumePath', 'path', 'methods', 'percent', 'containerNames'];
  const actionField = {latency: 'delay', fault: 'errno', attrOverride: 'attr', mistake: 'mistake'}[action];
  rejectUnknownFields(parameters, new Set([...common, actionField]), 'fault.parameters');
  const volumePath = requireString(parameters.volumePath, 'fault.parameters.volumePath', {maxLength: 4096});
  if (!volumePath.startsWith('/')) throw new Error('fault.parameters.volumePath must be absolute');
  if (parameters.path !== undefined) {
    const path = requireString(parameters.path, 'fault.parameters.path', {maxLength: 4096});
    if (!path.startsWith('/')) throw new Error('fault.parameters.path must be absolute');
  }
  if (parameters.methods !== undefined) stringArray(parameters.methods, 'fault.parameters.methods', {required: true, allowed: IO_METHODS});
  if (parameters.containerNames !== undefined) stringArray(parameters.containerNames, 'fault.parameters.containerNames', {required: true});
  if (parameters.percent !== undefined) validatePercentage(parameters.percent, 'fault.parameters.percent', safety);
  if (parameters[actionField] === undefined) throw new Error(`I/O ${action} requires parameters.${actionField}`);
  if (action === 'latency') {
    const delay = durationSeconds(parameters.delay, 'fault.parameters.delay');
    requireExtreme(delay > 5, safety, 'fault.parameters.delay above 5s');
  } else if (action === 'fault') {
    finiteNumber(parameters.errno, 'fault.parameters.errno', {min: 1, max: 4095, integer: true});
  } else {
    const object = requireObject(parameters[actionField], `fault.parameters.${actionField}`);
    if (Object.keys(object).length === 0) throw new Error(`fault.parameters.${actionField} must not be empty`);
  }
}

function validateTimeParameters(parameters, safety) {
  rejectUnknownFields(parameters, new Set(['timeOffset', 'clockIds', 'containerNames']), 'fault.parameters');
  const offset = durationSeconds(parameters.timeOffset, 'fault.parameters.timeOffset', {signed: true});
  if (Math.abs(offset) > 24 * 3600) throw new Error('fault.parameters.timeOffset must not exceed 24h');
  requireExtreme(Math.abs(offset) > 5 * 60, safety, 'fault.parameters.timeOffset beyond 5m');
  if (parameters.clockIds !== undefined) stringArray(parameters.clockIds, 'fault.parameters.clockIds', {required: true, allowed: CLOCK_IDS});
  if (parameters.containerNames !== undefined) stringArray(parameters.containerNames, 'fault.parameters.containerNames', {required: true});
}

export function compileCampaign(campaign, manifest) {
  requireObject(campaign, 'campaign');
  requireObject(manifest, 'manifest');
  const metadata = requireObject(campaign.metadata, 'metadata');
  const spec = requireObject(campaign.spec, 'spec');
  const name = requireName(metadata.name, 'metadata.name');
  const network = requireName(manifest.network, 'manifest.network');
  requireName(manifest.namespace, 'manifest.namespace');
  if (typeof spec.networkRef !== 'string' || spec.networkRef !== network) {
    throw new Error(`networkRef ${spec.networkRef} does not match manifest ${network}`);
  }
  const actors = manifestActors(manifest);
  const fault = requireObject(spec.fault, 'spec.fault');
  if (typeof fault.type !== 'string' || !(fault.type in TYPES)) throw new Error(`unsupported fault type ${fault.type}`);
  if (fault.type !== 'time' && (typeof fault.action !== 'string' || !ACTIONS[fault.type].has(fault.action))) {
    throw new Error(`unsupported ${fault.type} action ${fault.action}`);
  }
  if (fault.type === 'time' && fault.action !== undefined) throw new Error('time faults must not specify action');
  const target = validateTarget(spec.target, 'spec.target');
  const selected = selectedActors(target, actors);
  const mode = normalizedMode(fault.mode ?? 'one', fault.value, selected.length);
  const duration = fault.duration ?? '30s';
  const seconds = durationSeconds(duration);
  const safety = validateSafety(spec.safety ?? {});
  if (seconds > 600 && safety.allowExtendedDuration !== true) {
    throw new Error('faults longer than 10m require safety.allowExtendedDuration=true');
  }
  if (seconds > 3600) requireExtreme(true, safety, 'faults longer than 1h');
  if (seconds > 24 * 3600) throw new Error('fault duration must not exceed 24h');
  if (selected.some(actor => actor.role === 'burnchain') && safety.allowBurnchain !== true) {
    throw new Error('burnchain faults require safety.allowBurnchain=true');
  }
  const signer = signerImpact(selected, actors, mode.maximumCount);
  if (signer.percent > safety.maxUnavailableSignerPercent && safety.allowQuorumLoss !== true) {
    throw new Error(`selected signer impact ${signer.percent.toFixed(1)}% exceeds ${safety.maxUnavailableSignerPercent}%`);
  }
  const miner = minerImpact(selected, actors, mode.maximumCount);
  if (miner.percent > safety.maxUnavailableMinerPercent && safety.allowMinerMajorityOutage !== true) {
    throw new Error(`selected miner impact ${miner.percent.toFixed(1)}% exceeds ${safety.maxUnavailableMinerPercent}% and requires safety.allowMinerMajorityOutage=true`);
  }

  const parameters = fault.parameters === undefined ? {} : {...requireObject(fault.parameters, 'fault.parameters')};
  let peerSelectedActors;
  if (fault.type === 'pod') validatePodParameters(fault.action, parameters, safety);
  if (fault.type === 'network') peerSelectedActors = validateNetworkParameters(fault.action, parameters, safety, actors, manifest);
  if (fault.type === 'dns') validateDnsParameters(parameters);
  if (fault.type === 'io') validateIoParameters(fault.action, parameters, safety);
  if (fault.type === 'time') validateTimeParameters(parameters, safety);

  const chaosSpec = {mode: mode.mode, duration, selector: selector(target, manifest)};
  if (mode.value !== undefined) chaosSpec.value = mode.value;
  if (fault.type !== 'time') chaosSpec.action = fault.action;
  Object.assign(chaosSpec, parameters);
  const resource = {
    apiVersion: 'chaos-mesh.org/v1alpha1', kind: TYPES[fault.type],
    metadata: {name, namespace: manifest.namespace, labels: {[NETWORK_LABEL]: network, 'testing.stacks.org/campaign': name}},
    spec: chaosSpec,
  };
  return {
    resource,
    evidence: {
      selectedActors: selected.map(actor => actor.service),
      ...(peerSelectedActors ? {peerSelectedActors} : {}),
      signerImpact: signer,
      minerImpact: miner,
      maximumAffectedActors: mode.maximumCount,
      safety,
    },
  };
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
