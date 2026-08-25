#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';

export const FAULT_EFFECT_SCHEMA = 'stacks-attacknet-fault-effect/v1';
export const FAULT_PROBE_SCHEMA = 'stacks-attacknet-fault-probe/v1';

const VERDICTS = Object.freeze({proven: 'Proven', failed: 'Failed', inconclusive: 'Inconclusive'});
const KIND_TO_PROBE = Object.freeze({
  PodChaos: 'pod-state',
  NetworkChaos: 'network',
  DNSChaos: 'dns',
  IOChaos: 'io',
  IOPressurePod: 'io',
  TimeChaos: 'clock',
  ClockSkewPolicy: 'clock',
});
const EXPECTED_AUTHORITY = Object.freeze({
  PodChaos: 'kubernetes-api',
  NetworkChaos: 'active-probe',
  DNSChaos: 'active-probe',
  IOChaos: 'active-probe',
  IOPressurePod: 'active-probe',
  TimeChaos: 'application-process-metric',
  ClockSkewPolicy: 'application-process-metric',
});
const PHASES = new Set(['before', 'during', 'after']);
const POD_PHASES = new Set(['Pending', 'Running', 'Succeeded', 'Failed', 'Unknown']);
const ACTIONS = Object.freeze({
  PodChaos: new Set(['pod-kill', 'pod-failure', 'container-kill']),
  NetworkChaos: new Set(['netem', 'delay', 'loss', 'duplicate', 'corrupt', 'partition', 'bandwidth']),
  DNSChaos: new Set(['error', 'random']),
  IOChaos: new Set(['latency', 'fault', 'attrOverride', 'mistake']),
  IOPressurePod: new Set(['disk-pressure']),
  TimeChaos: new Set(['time']),
  ClockSkewPolicy: new Set(['time']),
});

const CLOCK_KINDS = new Set(['TimeChaos', 'ClockSkewPolicy']);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function object(value, field) {
  if (!isObject(value)) throw new Error(`${field} must be an object`);
  return value;
}

function exactFields(value, allowed, field) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${field} contains unsupported field ${key}`);
  }
}

function string(value, field, maxLength = 1024) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be a non-empty string of at most ${maxLength} characters`);
  }
  return value;
}

function boolean(value, field) {
  if (typeof value !== 'boolean') throw new Error(`${field} must be a boolean`);
  return value;
}

function number(value, field, {min = -Infinity, max = Infinity, integer = false} = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) {
    throw new Error(`${field} must be a finite ${integer ? 'integer ' : ''}number in ${min}..${max}`);
  }
  return value;
}

function nullableString(value, field, maxLength = 1024) {
  if (value === null) return null;
  return string(value, field, maxLength);
}

function stringArray(value, field, {maxItems = 256} = {}) {
  if (!Array.isArray(value) || value.length > maxItems) throw new Error(`${field} must be an array of at most ${maxItems} strings`);
  const result = value.map((item, index) => string(item, `${field}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${field} must not contain duplicates`);
  return result;
}

function statusFields(observation, field) {
  const status = observation.status;
  if (status !== 'ok' && status !== 'error') throw new Error(`${field}.status must be ok or error`);
  if (status === 'error') string(observation.error, `${field}.error`, 4096);
  if (status === 'ok' && observation.error !== undefined) throw new Error(`${field}.error is only valid when status=error`);
  return status;
}

function durationSeconds(value, field) {
  if (typeof value !== 'string') throw new Error(`${field} must be a duration string`);
  const match = /^([+-]?)(\d+)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error(`${field} must use an integer ms/s/m/h value`);
  const scalar = {ms: 0.001, s: 1, m: 60, h: 3600}[match[3]];
  const result = (match[1] === '-' ? -1 : 1) * Number(match[2]) * scalar;
  if (!Number.isFinite(result) || result === 0) throw new Error(`${field} must be non-zero`);
  return result;
}

function unsignedDurationSeconds(value, field) {
  const result = durationSeconds(value, field);
  if (result < 0) throw new Error(`${field} must be positive`);
  return result;
}

function normalizeSource(value, field, authority) {
  const source = object(value, field);
  exactFields(source, new Set(['trust', 'authority', 'collector', 'contentTrust']), field);
  if (source.trust !== 'orchestrator-observed') {
    throw new Error(`${field}.trust must be orchestrator-observed; actor-supplied evidence is not authoritative`);
  }
  if (source.authority !== authority) throw new Error(`${field}.authority must be ${authority}`);
  return {
    trust: source.trust,
    authority: source.authority,
    collector: string(source.collector, `${field}.collector`, 256),
    ...(source.contentTrust === undefined ? {} : {
      contentTrust: string(source.contentTrust, `${field}.contentTrust`, 64),
    }),
  };
}

function normalizeInjection(value, field, expectedAuthority = 'chaos-mesh-status') {
  if (value === undefined) return {allInjectedObserved: false};
  const injection = object(value, field);
  exactFields(injection, new Set(['allInjectedObserved', 'source']), field);
  const source = object(injection.source, `${field}.source`);
  exactFields(source, new Set(['trust', 'authority', 'collector']), `${field}.source`);
  if (source.trust !== 'orchestrator-observed' || source.authority !== expectedAuthority) {
    throw new Error(`${field}.source must be orchestrator-observed ${expectedAuthority}`);
  }
  return {
    allInjectedObserved: boolean(injection.allInjectedObserved, `${field}.allInjectedObserved`),
    source: {...source, collector: string(source.collector, `${field}.source.collector`, 256)},
  };
}

function normalizeCommonObservation(value, field, expectedProbe) {
  const observation = object(value, field);
  const actor = string(observation.actor, `${field}.actor`, 253);
  if (observation.probe !== expectedProbe) throw new Error(`${field}.probe must be ${expectedProbe}`);
  const status = statusFields(observation, field);
  return {observation, actor, status};
}

function normalizePodObservation(value, field) {
  const {observation, actor, status} = normalizeCommonObservation(value, field, 'pod-state');
  const allowed = new Set(['actor', 'probe', 'status', 'error', 'targetPodUid', 'targetPresent', 'currentPodUid', 'podPhase', 'containerRestartCount', 'containerReady']);
  exactFields(observation, allowed, field);
  if (status === 'error') return {actor, probe: 'pod-state', status, error: observation.error};
  const result = {
    actor, probe: 'pod-state', status,
    targetPodUid: string(observation.targetPodUid, `${field}.targetPodUid`, 253),
    targetPresent: boolean(observation.targetPresent, `${field}.targetPresent`),
    currentPodUid: nullableString(observation.currentPodUid, `${field}.currentPodUid`, 253),
    podPhase: observation.podPhase,
    containerRestartCount: observation.containerRestartCount,
    containerReady: observation.containerReady,
  };
  if (!POD_PHASES.has(result.podPhase)) throw new Error(`${field}.podPhase is invalid`);
  if (result.containerRestartCount !== null) number(result.containerRestartCount, `${field}.containerRestartCount`, {min: 0, max: 1e9, integer: true});
  if (result.containerReady !== null) boolean(result.containerReady, `${field}.containerReady`);
  if (result.targetPresent && result.currentPodUid !== result.targetPodUid) {
    throw new Error(`${field} says targetPresent but currentPodUid differs from targetPodUid`);
  }
  return result;
}

function normalizeNetworkObservation(value, field) {
  const {observation, actor, status} = normalizeCommonObservation(value, field, 'network');
  const allowed = new Set([
    'actor', 'probe', 'status', 'error', 'probeName', 'peerActor', 'attempts', 'successes',
    'latencyMsP50', 'latencyMsP95', 'protocolErrors', 'throughputBytesPerSecond',
  ]);
  exactFields(observation, allowed, field);
  if (status === 'error') return {actor, probe: 'network', status, error: observation.error};
  const attempts = number(observation.attempts, `${field}.attempts`, {min: 1, max: 10_000, integer: true});
  const successes = number(observation.successes, `${field}.successes`, {min: 0, max: attempts, integer: true});
  const result = {
    actor, probe: 'network', status,
    probeName: string(observation.probeName, `${field}.probeName`, 128),
    peerActor: string(observation.peerActor, `${field}.peerActor`, 253),
    attempts, successes,
    latencyMsP50: observation.latencyMsP50,
    latencyMsP95: observation.latencyMsP95,
    protocolErrors: observation.protocolErrors ?? 0,
    throughputBytesPerSecond: observation.throughputBytesPerSecond,
  };
  for (const key of ['latencyMsP50', 'latencyMsP95']) {
    if (result[key] !== null) number(result[key], `${field}.${key}`, {min: 0, max: 3_600_000});
  }
  if (successes > 0 && (result.latencyMsP50 === null || result.latencyMsP95 === null)) {
    throw new Error(`${field} needs latency values when successes > 0`);
  }
  number(result.protocolErrors, `${field}.protocolErrors`, {min: 0, max: attempts, integer: true});
  if (result.throughputBytesPerSecond !== null) {
    number(result.throughputBytesPerSecond, `${field}.throughputBytesPerSecond`, {min: 0, max: 1e15});
  }
  return result;
}

function normalizeDnsObservation(value, field) {
  const {observation, actor, status} = normalizeCommonObservation(value, field, 'dns');
  const allowed = new Set(['actor', 'probe', 'status', 'error', 'probeName', 'query', 'controlQuery', 'querySucceeded', 'controlSucceeded', 'answers', 'controlAnswers']);
  exactFields(observation, allowed, field);
  if (status === 'error') return {actor, probe: 'dns', status, error: observation.error};
  return {
    actor, probe: 'dns', status,
    probeName: string(observation.probeName, `${field}.probeName`, 128),
    query: string(observation.query, `${field}.query`, 253),
    controlQuery: string(observation.controlQuery, `${field}.controlQuery`, 253),
    querySucceeded: boolean(observation.querySucceeded, `${field}.querySucceeded`),
    controlSucceeded: boolean(observation.controlSucceeded, `${field}.controlSucceeded`),
    answers: stringArray(observation.answers, `${field}.answers`),
    controlAnswers: stringArray(observation.controlAnswers, `${field}.controlAnswers`),
  };
}

function normalizeErrorCounts(value, field, attempts) {
  const counts = object(value, field);
  if (Object.keys(counts).length > 128) throw new Error(`${field} contains too many errno entries`);
  let total = 0;
  const result = {};
  for (const [key, count] of Object.entries(counts)) {
    if (!/^[1-9]\d{0,3}$/.test(key) || Number(key) > 4095) throw new Error(`${field} contains invalid errno ${key}`);
    result[key] = number(count, `${field}.${key}`, {min: 0, max: attempts, integer: true});
    total += result[key];
  }
  if (total > attempts) throw new Error(`${field} total exceeds attempts`);
  return result;
}

function normalizeIoObservation(value, field) {
  const {observation, actor, status} = normalizeCommonObservation(value, field, 'io');
  const allowed = new Set([
    'actor', 'probe', 'status', 'error', 'probeName', 'path', 'operation', 'attempts', 'successes',
    'errorCounts', 'latencyMsP50', 'latencyMsP95', 'contentDigest', 'attributesDigest',
  ]);
  exactFields(observation, allowed, field);
  if (status === 'error') return {actor, probe: 'io', status, error: observation.error};
  const attempts = number(observation.attempts, `${field}.attempts`, {min: 1, max: 10_000, integer: true});
  const successes = number(observation.successes, `${field}.successes`, {min: 0, max: attempts, integer: true});
  const result = {
    actor, probe: 'io', status,
    probeName: string(observation.probeName, `${field}.probeName`, 128),
    path: string(observation.path, `${field}.path`, 4096),
    operation: string(observation.operation, `${field}.operation`, 64),
    attempts, successes,
    errorCounts: normalizeErrorCounts(observation.errorCounts, `${field}.errorCounts`, attempts),
    latencyMsP50: number(observation.latencyMsP50, `${field}.latencyMsP50`, {min: 0, max: 3_600_000}),
    latencyMsP95: number(observation.latencyMsP95, `${field}.latencyMsP95`, {min: 0, max: 3_600_000}),
    contentDigest: observation.contentDigest === null ? null : string(observation.contentDigest, `${field}.contentDigest`, 256),
    attributesDigest: observation.attributesDigest === null ? null : string(observation.attributesDigest, `${field}.attributesDigest`, 256),
  };
  if (successes + Object.values(result.errorCounts).reduce((sum, count) => sum + count, 0) > attempts) {
    throw new Error(`${field} successes plus errors exceeds attempts`);
  }
  return result;
}

function normalizeClockObservation(value, field) {
  const {observation, actor, status} = normalizeCommonObservation(value, field, 'clock');
  const allowed = new Set(['actor', 'probe', 'status', 'error', 'control', 'wallEpochSeconds', 'monotonicSeconds', 'sampleWindowMs', 'metric']);
  exactFields(observation, allowed, field);
  if (status === 'error') return {actor, probe: 'clock', status, error: observation.error};
  if (observation.metric !== 'stacks_node_process_wall_clock_seconds') {
    throw new Error(`${field}.metric must be stacks_node_process_wall_clock_seconds`);
  }
  return {
    actor, probe: 'clock', status,
    control: boolean(observation.control, `${field}.control`),
    wallEpochSeconds: number(observation.wallEpochSeconds, `${field}.wallEpochSeconds`, {min: 0, max: 1e12}),
    monotonicSeconds: number(observation.monotonicSeconds, `${field}.monotonicSeconds`, {min: 0, max: 1e12}),
    sampleWindowMs: number(observation.sampleWindowMs, `${field}.sampleWindowMs`, {min: 0, max: 5000}),
    metric: observation.metric,
  };
}

function normalizePhase(value, expectedPhase, kind) {
  const phase = object(value, expectedPhase);
  exactFields(phase, new Set(['schemaVersion', 'phase', 'source', 'capturedAt', 'injection', 'observations']), expectedPhase);
  if (phase.schemaVersion !== FAULT_PROBE_SCHEMA) throw new Error(`${expectedPhase}.schemaVersion must be ${FAULT_PROBE_SCHEMA}`);
  if (phase.phase !== expectedPhase || !PHASES.has(phase.phase)) throw new Error(`${expectedPhase}.phase must be ${expectedPhase}`);
  const source = normalizeSource(phase.source, `${expectedPhase}.source`, EXPECTED_AUTHORITY[kind]);
  if (CLOCK_KINDS.has(kind) && source.contentTrust !== 'actor-self-reported') {
    throw new Error(`${expectedPhase}.source.contentTrust must disclose actor-self-reported time content`);
  }
  if (!CLOCK_KINDS.has(kind) && source.contentTrust !== undefined) {
    throw new Error(`${expectedPhase}.source.contentTrust is only valid for TimeChaos`);
  }
  if (phase.capturedAt !== undefined && !Number.isFinite(Date.parse(phase.capturedAt))) {
    throw new Error(`${expectedPhase}.capturedAt must be RFC 3339 when present`);
  }
  const injection = normalizeInjection(phase.injection, `${expectedPhase}.injection`,
    kind === 'IOPressurePod' ? 'kubernetes-pod-status'
      : kind === 'ClockSkewPolicy' ? 'controller-clock-policy'
        : 'chaos-mesh-status');
  if (!Array.isArray(phase.observations) || phase.observations.length > 10_000) {
    throw new Error(`${expectedPhase}.observations must be an array of at most 10000 entries`);
  }
  const normalizer = {
    PodChaos: normalizePodObservation,
    NetworkChaos: normalizeNetworkObservation,
    DNSChaos: normalizeDnsObservation,
    IOChaos: normalizeIoObservation,
    IOPressurePod: normalizeIoObservation,
    TimeChaos: normalizeClockObservation,
    ClockSkewPolicy: normalizeClockObservation,
  }[kind];
  return {
    schemaVersion: phase.schemaVersion,
    phase: phase.phase,
    source,
    ...(phase.capturedAt === undefined ? {} : {capturedAt: new Date(Date.parse(phase.capturedAt)).toISOString()}),
    injection,
    observations: phase.observations.map((observation, index) => normalizer(observation, `${expectedPhase}.observations[${index}]`)),
  };
}

function normalizeResolvedTargets(value, selectedActors) {
  const resolved = object(value, 'resolvedTargets');
  exactFields(resolved, new Set(['schemaVersion', 'network', 'namespace', 'resolvedAt', 'targets']), 'resolvedTargets');
  if (resolved.schemaVersion !== 1) throw new Error('resolvedTargets.schemaVersion must be 1');
  string(resolved.network, 'resolvedTargets.network', 63);
  string(resolved.namespace, 'resolvedTargets.namespace', 63);
  if (!Number.isFinite(Date.parse(resolved.resolvedAt))) throw new Error('resolvedTargets.resolvedAt must be RFC 3339');
  if (!Array.isArray(resolved.targets) || resolved.targets.length === 0 || resolved.targets.length > 256) {
    throw new Error('resolvedTargets.targets must be a non-empty array of at most 256 entries');
  }
  const targets = resolved.targets.map((target, index) => {
    object(target, `resolvedTargets.targets[${index}]`);
    exactFields(target, new Set(['actor', 'role', 'pod', 'podUid', 'podIP', 'node', 'requestedImage', 'resolvedImageId', 'restartCount']), `resolvedTargets.targets[${index}]`);
    const actor = string(target.actor, `resolvedTargets.targets[${index}].actor`, 253);
    const restartCount = number(target.restartCount, `resolvedTargets.targets[${index}].restartCount`, {min: 0, max: 1e9, integer: true});
    if (target.requestedImage !== null) string(target.requestedImage, `resolvedTargets.targets[${index}].requestedImage`, 4096);
    if (target.resolvedImageId !== null) string(target.resolvedImageId, `resolvedTargets.targets[${index}].resolvedImageId`, 4096);
    return {
      actor,
      role: string(target.role, `resolvedTargets.targets[${index}].role`, 63),
      pod: string(target.pod, `resolvedTargets.targets[${index}].pod`, 253),
      podUid: string(target.podUid, `resolvedTargets.targets[${index}].podUid`, 253),
      ...(target.podIP === undefined ? {} : {podIP: string(target.podIP, `resolvedTargets.targets[${index}].podIP`, 64)}),
      node: string(target.node, `resolvedTargets.targets[${index}].node`, 253),
      requestedImage: target.requestedImage,
      resolvedImageId: target.resolvedImageId,
      restartCount,
    };
  });
  const actors = targets.map(target => target.actor);
  if (new Set(actors).size !== actors.length) throw new Error('resolvedTargets contains duplicate actors');
  if (actors.length !== selectedActors.length || actors.some(actor => !selectedActors.includes(actor))) {
    throw new Error('resolvedTargets actors must exactly match compiled evidence selectedActors');
  }
  return {...resolved, targets};
}

function expectedAffected(spec, candidates) {
  const mode = spec.mode;
  if (mode === 'all') return {minimum: candidates, maximum: candidates};
  if (mode === 'one') return {minimum: 1, maximum: 1};
  const raw = Number(spec.value);
  if (!Number.isInteger(raw) || raw < 1) throw new Error('compiled campaign mode value is invalid');
  if (mode === 'fixed') {
    if (raw > candidates) throw new Error('compiled fixed campaign value exceeds candidates');
    return {minimum: raw, maximum: raw};
  }
  if (raw > 100) throw new Error('compiled percentage campaign value exceeds 100');
  const maximum = Math.ceil(candidates * raw / 100);
  if (mode === 'fixed-percent') return {minimum: maximum, maximum};
  if (mode === 'random-max-percent') return {minimum: 1, maximum};
  throw new Error(`compiled campaign has unsupported mode ${mode}`);
}

function mapByActor(observations) {
  const result = new Map();
  for (const observation of observations) {
    if (!result.has(observation.actor)) result.set(observation.actor, []);
    result.get(observation.actor).push(observation);
  }
  return result;
}

function observationKey(observation) {
  if (observation.probe === 'network') return `${observation.probeName}\0${observation.peerActor}`;
  if (observation.probe === 'dns') return `${observation.probeName}\0${observation.query}\0${observation.controlQuery}`;
  if (observation.probe === 'io') return `${observation.probeName}\0${observation.path}\0${observation.operation}`;
  return observation.probe;
}

function keyed(observations) {
  const result = new Map();
  for (const observation of observations.filter(item => item.status === 'ok')) {
    const key = observationKey(observation);
    if (result.has(key)) throw new Error(`probe artifact contains duplicate observation key ${key}`);
    result.set(key, observation);
  }
  return result;
}

function sameAnswers(left, right) {
  return [...left].sort().join('\0') === [...right].sort().join('\0');
}

function globMatches(pattern, query) {
  const expression = pattern.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${expression}$`).test(query);
}

function parsePercent(value, field) {
  const result = Number(value);
  if (!Number.isFinite(result) || result < 0 || result > 100) throw new Error(`${field} must be a percentage`);
  return result;
}

function parseRate(value, field) {
  const match = /^(\d+(?:\.\d+)?)(bps|kbps|mbps|gbps)$/.exec(value ?? '');
  if (!match) throw new Error(`${field} must be a bps/kbps/mbps/gbps rate`);
  return Number(match[1]) * {bps: 1 / 8, kbps: 1e3 / 8, mbps: 1e6 / 8, gbps: 1e9 / 8}[match[2]];
}

function podEvaluation(action, target, before, during, after) {
  const baseline = before.find(item => item.status === 'ok');
  const active = during.find(item => item.status === 'ok');
  const recovered = after.find(item => item.status === 'ok');
  if (!baseline || baseline.targetPodUid !== target.podUid || !baseline.targetPresent
      || baseline.currentPodUid !== target.podUid || baseline.containerRestartCount !== target.restartCount) {
    return {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: 'baseline Pod identity/restart evidence is missing or does not match the admitted target'};
  }
  let proven = false;
  if (action === 'pod-kill') proven = Boolean(active && (!active.targetPresent || active.currentPodUid !== target.podUid));
  if (action === 'pod-failure') {
    proven = Boolean(active && (!active.targetPresent || active.podPhase === 'Failed' || active.podPhase === 'Unknown' || active.containerReady === false));
  }
  if (action === 'container-kill') {
    proven = [active, recovered].some(item => item && item.containerRestartCount !== null && item.containerRestartCount > baseline.containerRestartCount);
  }
  if (!active && !(action === 'container-kill' && recovered)) {
    return {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: 'during Pod API evidence is missing'};
  }
  const recovery = recovered
    ? (recovered.currentPodUid !== null && recovered.podPhase === 'Running' && recovered.containerReady === true ? 'proven' : 'failed')
    : 'inconclusive';
  return {
    actor: target.actor,
    effect: proven ? 'proven' : 'failed', recovery,
    reason: proven ? 'Kubernetes Pod UID/readiness/restart evidence observed the requested effect' : 'admitted Pod state did not exhibit the requested effect',
    metrics: {targetPodUid: target.podUid, baselineRestarts: baseline.containerRestartCount, during: active ?? null, after: recovered ?? null},
  };
}

function networkContract(action, spec, baseline, active) {
  if (baseline.successes === 0) return {usable: false, proven: false, reason: 'baseline named peer was unreachable'};
  const beforeRate = baseline.successes / baseline.attempts;
  const duringRate = active.successes / active.attempts;
  const latencyDeltaMs = active.successes > 0 ? active.latencyMsP95 - baseline.latencyMsP95 : null;
  const protocolErrorDelta = active.protocolErrors - baseline.protocolErrors;
  const throughputRatio = baseline.throughputBytesPerSecond > 0 && active.throughputBytesPerSecond !== null
    ? active.throughputBytesPerSecond / baseline.throughputBytesPerSecond : null;
  const checks = [];
  const parameters = spec;
  const evaluate = effect => {
    if (effect === 'partition') checks.push({name: 'partition', proven: duringRate === 0});
    if (effect === 'delay') {
      const requestedMs = unsignedDurationSeconds(parameters.delay.latency, 'compiled network delay latency') * 1000;
      checks.push({name: 'delay', proven: latencyDeltaMs !== null && latencyDeltaMs >= Math.max(10, requestedMs * 0.5)});
    }
    if (effect === 'loss') {
      const requested = parsePercent(parameters.loss.loss, 'compiled network loss');
      checks.push({name: 'loss', proven: (beforeRate - duringRate) * 100 >= Math.max(5, requested * 0.5)});
    }
    if (effect === 'duplicate' || effect === 'corrupt') checks.push({name: effect, proven: protocolErrorDelta > 0});
    if (effect === 'bandwidth') {
      const requested = parseRate(parameters.bandwidth.rate, 'compiled network bandwidth rate');
      checks.push({name: 'bandwidth', proven: active.throughputBytesPerSecond !== null && active.throughputBytesPerSecond <= requested * 1.25 && throughputRatio < 0.8});
    }
  };
  if (action === 'netem') {
    for (const effect of ['delay', 'loss', 'duplicate', 'corrupt']) if (parameters[effect] !== undefined) evaluate(effect);
  } else {
    evaluate(action);
  }
  return {
    usable: true,
    proven: checks.length > 0 && checks.every(check => check.proven),
    reason: checks.length === 0 ? 'no supported network effect contract was present' : checks.map(check => `${check.name}=${check.proven}`).join(', '),
    metrics: {beforeRate, duringRate, latencyDeltaMs, protocolErrorDelta, throughputRatio, checks},
  };
}

function networkRecovered(action, baseline, after) {
  if (!after || baseline.successes === 0) return after ? 'failed' : 'inconclusive';
  const beforeRate = baseline.successes / baseline.attempts;
  const afterRate = after.successes / after.attempts;
  const reachable = afterRate >= Math.max(0.5, beforeRate - 0.1);
  const latency = after.successes === 0 || baseline.latencyMsP95 === null
    ? false : after.latencyMsP95 <= Math.max(baseline.latencyMsP95 * 2, baseline.latencyMsP95 + 50);
  const throughput = action !== 'bandwidth'
    || (after.throughputBytesPerSecond !== null
      && baseline.throughputBytesPerSecond > 0
      && after.throughputBytesPerSecond >= baseline.throughputBytesPerSecond * 0.8);
  return reachable && latency && throughput ? 'proven' : 'failed';
}

function networkEvaluation(action, spec, target, before, during, after, allowedPeers) {
  const baseline = keyed(before);
  const active = keyed(during);
  const recovered = keyed(after);
  let comparable = 0;
  let usable = 0;
  const details = [];
  for (const [key, beforeObservation] of baseline) {
    const duringObservation = active.get(key);
    if (!duringObservation) continue;
    if (allowedPeers && !allowedPeers.has(beforeObservation.peerActor)) continue;
    comparable += 1;
    const contract = networkContract(action, spec, beforeObservation, duringObservation);
    if (!contract.usable) continue;
    usable += 1;
    details.push({key, ...contract});
    if (contract.proven) {
      return {
        actor: target.actor, effect: 'proven', recovery: networkRecovered(action, beforeObservation, recovered.get(key)),
        reason: `named reachability/latency/throughput probe observed ${contract.reason}`, metrics: contract.metrics,
      };
    }
  }
  return comparable === 0 || usable === 0
    ? {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: comparable === 0 ? 'no matching before/during named network probe' : 'named network probe lacked a healthy baseline'}
    : {actor: target.actor, effect: 'failed', recovery: 'inconclusive', reason: 'named network probes did not exhibit the requested delta', metrics: {probes: details}};
}

function dnsEvaluation(action, spec, target, before, during, after) {
  const baseline = keyed(before);
  const active = keyed(during);
  const recovered = keyed(after);
  const patterns = spec.patterns;
  let comparable = 0;
  let usable = 0;
  for (const [key, first] of baseline) {
    const second = active.get(key);
    if (!second || !patterns.some(pattern => globMatches(pattern, first.query))) continue;
    comparable += 1;
    if (first.query === first.controlQuery || !first.querySucceeded || !first.controlSucceeded || !second.controlSucceeded) continue;
    usable += 1;
    const proven = action === 'error'
      ? !second.querySucceeded
      : second.querySucceeded && !sameAnswers(first.answers, second.answers);
    if (!proven) continue;
    const final = recovered.get(key);
    const recovery = final
      ? (final.querySucceeded && final.controlSucceeded && sameAnswers(first.answers, final.answers) ? 'proven' : 'failed')
      : 'inconclusive';
    return {
      actor: target.actor, effect: 'proven', recovery,
      reason: `selected DNS query changed under ${action} while its control query remained healthy`,
      metrics: {probe: key, beforeAnswers: first.answers, duringAnswers: second.answers, duringQuerySucceeded: second.querySucceeded},
    };
  }
  return comparable === 0 || usable === 0
    ? {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: comparable === 0 ? 'no matching selected-query/control DNS probe' : 'selected DNS probe lacked a healthy independent control'}
    : {actor: target.actor, effect: 'failed', recovery: 'inconclusive', reason: 'DNS probes did not isolate the requested effect from the control query'};
}

function errorCount(observation, errno) {
  return observation.errorCounts[String(errno)] ?? 0;
}

function ioEvaluation(action, spec, target, before, during, after) {
  const baseline = keyed(before);
  const active = keyed(during);
  const recovered = keyed(after);
  let comparable = 0;
  let usable = 0;
  for (const [key, first] of baseline) {
    const second = active.get(key);
    if (!second || !first.path.startsWith(spec.volumePath) || !second.path.startsWith(spec.volumePath)
      || (spec.path !== undefined && !globMatches(spec.path, first.path))
      || (Array.isArray(spec.methods) && !spec.methods.includes(first.operation))) continue;
    comparable += 1;
    let proven = false;
    let metric;
    if (action === 'latency') {
      if (first.successes === 0) continue;
      usable += 1;
      const requestedMs = unsignedDurationSeconds(spec.delay, 'compiled I/O delay') * 1000;
      const delta = second.latencyMsP95 - first.latencyMsP95;
      proven = first.successes > 0 && second.successes > 0 && delta >= Math.max(5, requestedMs * 0.5);
      metric = {latencyDeltaMs: delta, requestedMs};
    } else if (action === 'fault') {
      usable += 1;
      const delta = errorCount(second, spec.errno) - errorCount(first, spec.errno);
      proven = delta > 0;
      metric = {errno: spec.errno, errorCountDelta: delta};
    } else if (action === 'attrOverride') {
      if (first.attributesDigest === null || second.attributesDigest === null) continue;
      usable += 1;
      proven = first.attributesDigest !== null && second.attributesDigest !== null && first.attributesDigest !== second.attributesDigest;
      metric = {before: first.attributesDigest, during: second.attributesDigest};
    } else if (action === 'mistake') {
      if (first.contentDigest === null || second.contentDigest === null) continue;
      usable += 1;
      proven = first.contentDigest !== null && second.contentDigest !== null && first.contentDigest !== second.contentDigest;
      metric = {before: first.contentDigest, during: second.contentDigest};
    }
    if (!proven) continue;
    const final = recovered.get(key);
    let recovery = 'inconclusive';
    if (final) {
      if (action === 'latency') recovery = final.latencyMsP95 <= Math.max(first.latencyMsP95 * 2, first.latencyMsP95 + 25) ? 'proven' : 'failed';
      if (action === 'fault') recovery = errorCount(final, spec.errno) <= errorCount(first, spec.errno) ? 'proven' : 'failed';
      if (action === 'attrOverride') recovery = final.attributesDigest === first.attributesDigest ? 'proven' : 'failed';
      if (action === 'mistake') recovery = final.contentDigest === first.contentDigest ? 'proven' : 'failed';
    }
    return {actor: target.actor, effect: 'proven', recovery, reason: `named I/O operation observed ${action} evidence`, metrics: metric};
  }
  return comparable === 0 || usable === 0
    ? {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: comparable === 0 ? 'no matching before/during I/O operation probe' : 'I/O operation probe lacked a usable baseline'}
    : {actor: target.actor, effect: 'failed', recovery: 'inconclusive', reason: 'I/O operation probes did not exhibit the requested effect'};
}

function normalizeIoPressureContract(value) {
  const contract = object(value, 'evidence.ioPressure');
  exactFields(contract, new Set([
    'semantic', 'severity', 'workers', 'bytesMiB', 'writeSizeKiB', 'tempPath',
    'minimumLatencyMultiplier', 'minimumAddedLatencyMs',
  ]), 'evidence.ioPressure');
  if (contract.semantic !== 'disk-io-pressure') {
    throw new Error('evidence.ioPressure.semantic must be disk-io-pressure');
  }
  if (!new Set(['low', 'medium', 'high']).has(contract.severity)) {
    throw new Error('evidence.ioPressure.severity must be low, medium, or high');
  }
  if (contract.tempPath !== '/data') throw new Error('evidence.ioPressure.tempPath must be /data');
  return {
    semantic: contract.semantic,
    severity: contract.severity,
    workers: number(contract.workers, 'evidence.ioPressure.workers', {min: 1, max: 4, integer: true}),
    bytesMiB: number(contract.bytesMiB, 'evidence.ioPressure.bytesMiB', {min: 16, max: 512, integer: true}),
    writeSizeKiB: number(contract.writeSizeKiB, 'evidence.ioPressure.writeSizeKiB', {min: 4, max: 1024, integer: true}),
    tempPath: contract.tempPath,
    minimumLatencyMultiplier: number(contract.minimumLatencyMultiplier,
      'evidence.ioPressure.minimumLatencyMultiplier', {min: 1.1, max: 20}),
    minimumAddedLatencyMs: number(contract.minimumAddedLatencyMs,
      'evidence.ioPressure.minimumAddedLatencyMs', {min: 0.5, max: 5000}),
  };
}

function ioPressureEvaluation(target, before, during, after, contract) {
  const baseline = keyed(before);
  const active = keyed(during);
  const recovered = keyed(after);
  let comparable = 0;
  let usable = 0;
  const details = [];
  for (const [key, first] of baseline) {
    const second = active.get(key);
    if (!second || first.operation !== 'FSYNC' || second.operation !== 'FSYNC'
        || !first.path.startsWith(`${contract.tempPath}/`)
        || !second.path.startsWith(`${contract.tempPath}/`)) continue;
    comparable += 1;
    if (first.successes === 0 || second.successes === 0) continue;
    usable += 1;
    const denominator = Math.max(first.latencyMsP95, 0.001);
    const latencyMultiplier = second.latencyMsP95 / denominator;
    const addedLatencyMs = second.latencyMsP95 - first.latencyMsP95;
    const proven = latencyMultiplier >= contract.minimumLatencyMultiplier
      && addedLatencyMs >= contract.minimumAddedLatencyMs;
    const metrics = {
      baselineLatencyMsP95: first.latencyMsP95,
      duringLatencyMsP95: second.latencyMsP95,
      latencyMultiplier, addedLatencyMs,
      minimumLatencyMultiplier: contract.minimumLatencyMultiplier,
      minimumAddedLatencyMs: contract.minimumAddedLatencyMs,
    };
    details.push({key, proven, ...metrics});
    if (!proven) continue;
    const final = recovered.get(key);
    let recovery = 'inconclusive';
    let recoveryReason = 'trusted after-fault I/O pressure probe is missing';
    if (final && final.operation === 'FSYNC' && final.path.startsWith(`${contract.tempPath}/`)
        && final.successes > 0) {
      const recoveredLatencyMultiplier = final.latencyMsP95 / denominator;
      const recoveredAddedLatencyMs = final.latencyMsP95 - first.latencyMsP95;
      const recoveredBelowThreshold = recoveredLatencyMultiplier < contract.minimumLatencyMultiplier
        && recoveredAddedLatencyMs < contract.minimumAddedLatencyMs;
      recovery = recoveredBelowThreshold ? 'proven' : 'failed';
      recoveryReason = recoveredBelowThreshold
        ? `FSYNC latency returned below both configured disk-pressure effect thresholds: multiplier=${recoveredLatencyMultiplier.toFixed(3)} (<${contract.minimumLatencyMultiplier}), addedMs=${recoveredAddedLatencyMs.toFixed(3)} (<${contract.minimumAddedLatencyMs})`
        : `FSYNC latency remained at or above a configured disk-pressure effect threshold: multiplier=${recoveredLatencyMultiplier.toFixed(3)}, addedMs=${recoveredAddedLatencyMs.toFixed(3)}`;
      Object.assign(metrics, {
        afterLatencyMsP95: final.latencyMsP95,
        recoveredLatencyMultiplier, recoveredAddedLatencyMs,
      });
    }
    return {
      actor: target.actor, effect: 'proven', recovery,
      reason: `FSYNC latency met both configured disk-pressure effect thresholds: multiplier=${latencyMultiplier.toFixed(3)} (>=${contract.minimumLatencyMultiplier}), addedMs=${addedLatencyMs.toFixed(3)} (>=${contract.minimumAddedLatencyMs})`,
      recoveryReason, metrics,
    };
  }
  return comparable === 0 || usable === 0
    ? {
      actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive',
      reason: comparable === 0
        ? 'no matching before/during FSYNC pressure probe under /data'
        : 'FSYNC pressure probe lacked a successful baseline and active sample',
    }
    : {
      actor: target.actor, effect: 'failed', recovery: 'inconclusive',
      reason: 'FSYNC latency did not meet both configured disk-pressure effect thresholds',
      metrics: {probes: details},
    };
}

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function clockShift(first, second) {
  return (second.wallEpochSeconds - first.wallEpochSeconds) - (second.monotonicSeconds - first.monotonicSeconds);
}

function timeEvaluations(spec, targets, before, during, after) {
  const successful = [before, during, after].map(phase => phase.filter(item => item.status === 'ok'));
  for (const phase of successful) {
    if (new Set(phase.map(item => item.actor)).size !== phase.length) throw new Error('clock probes contain duplicate actors');
  }
  const byPhase = successful.map(phase => new Map(phase.map(item => [item.actor, item])));
  const targetNames = new Set(targets.map(target => target.actor));
  for (const phase of byPhase) {
    for (const target of targets) {
      const observation = phase.get(target.actor);
      if (observation && observation.control) throw new Error(`selected actor ${target.actor} cannot be marked as a clock control`);
    }
  }
  const controls = [...byPhase[0].values()]
    .filter(item => item.control && !targetNames.has(item.actor)
      && byPhase[1].get(item.actor)?.control === true && byPhase[2].get(item.actor)?.control === true
      && byPhase[1].get(item.actor).monotonicSeconds >= item.monotonicSeconds
      && byPhase[2].get(item.actor).monotonicSeconds >= item.monotonicSeconds)
    .map(item => item.actor);
  if (controls.length === 0) {
    return targets.map(target => ({actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: 'no independent control clock was observed in all phases'}));
  }
  const controlDuring = median(controls.map(actor => clockShift(byPhase[0].get(actor), byPhase[1].get(actor))));
  const controlAfter = median(controls.map(actor => clockShift(byPhase[0].get(actor), byPhase[2].get(actor))));
  const requestedOffsetSeconds = durationSeconds(spec.timeOffset, 'compiled timeOffset');
  const toleranceSeconds = Math.max(1, Math.min(5, Math.abs(requestedOffsetSeconds) * 0.2));
  return targets.map(target => {
    const first = byPhase[0].get(target.actor);
    const second = byPhase[1].get(target.actor);
    const final = byPhase[2].get(target.actor);
    if (!first || !second) return {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: 'target clock probe is missing before or during'};
    if (second.monotonicSeconds < first.monotonicSeconds || (final && final.monotonicSeconds < first.monotonicSeconds)) {
      return {actor: target.actor, effect: 'inconclusive', recovery: 'inconclusive', reason: 'target monotonic clock moved backwards, invalidating the clock comparison'};
    }
    const observedOffsetSeconds = clockShift(first, second) - controlDuring;
    const effect = Math.abs(observedOffsetSeconds - requestedOffsetSeconds) <= toleranceSeconds ? 'proven' : 'failed';
    let recovery = 'inconclusive';
    let recoveredOffsetSeconds = null;
    if (final) {
      recoveredOffsetSeconds = clockShift(first, final) - controlAfter;
      recovery = Math.abs(recoveredOffsetSeconds) <= toleranceSeconds ? 'proven' : 'failed';
    }
    return {
      actor: target.actor, effect, recovery,
      reason: effect === 'proven' ? 'wall-clock shift matched requested offset relative to monotonic and control clocks' : 'wall-clock shift did not match requested offset',
      metrics: {requestedOffsetSeconds, observedOffsetSeconds, recoveredOffsetSeconds, toleranceSeconds, controlActors: controls},
    };
  });
}

function aggregateEffect(evaluations, expected) {
  const count = state => evaluations.filter(item => item.effect === state).length;
  const proven = count('proven');
  const inconclusive = count('inconclusive');
  if (proven >= expected.minimum) return VERDICTS.proven;
  if (proven + inconclusive >= expected.minimum) return VERDICTS.inconclusive;
  return VERDICTS.failed;
}

function aggregateRecovery(evaluations) {
  const affected = evaluations.filter(item => item.effect === 'proven');
  if (affected.length === 0) return VERDICTS.inconclusive;
  if (affected.some(item => item.recovery === 'failed')) return VERDICTS.failed;
  if (affected.some(item => item.recovery === 'inconclusive')) return VERDICTS.inconclusive;
  return VERDICTS.proven;
}

export function evaluateFaultEffect({campaign, evidence, resolvedTargets, before, during, after}) {
  const compiled = object(campaign, 'campaign');
  const kind = compiled.kind;
  if (!(kind in KIND_TO_PROBE)) throw new Error(`campaign.kind ${kind} is unsupported`);
  object(compiled.metadata, 'campaign.metadata');
  const name = string(compiled.metadata.name, 'campaign.metadata.name', 63);
  const spec = object(compiled.spec, 'campaign.spec');
  const action = CLOCK_KINDS.has(kind) ? 'time'
    : kind === 'IOPressurePod' ? 'disk-pressure'
      : string(spec.action, 'campaign.spec.action', 64);
  if (!ACTIONS[kind].has(action)) throw new Error(`campaign action ${action} is unsupported for ${kind}`);
  const compilerEvidence = object(evidence, 'evidence');
  const selectedActors = stringArray(compilerEvidence.selectedActors, 'evidence.selectedActors');
  if (selectedActors.length === 0) throw new Error('evidence.selectedActors must not be empty');
  const peerSelectedActors = compilerEvidence.peerSelectedActors === undefined
    ? null : new Set(stringArray(compilerEvidence.peerSelectedActors, 'evidence.peerSelectedActors'));
  const ioPressureContract = kind === 'IOPressurePod'
    ? normalizeIoPressureContract(compilerEvidence.ioPressure) : null;
  if (kind === 'IOPressurePod') {
    const annotation = compiled.metadata.annotations?.['testing.stacks.org/io-pressure-contract'];
    if (typeof annotation !== 'string') {
      throw new Error('IOPressurePod is missing its compiled I/O-pressure contract annotation');
    }
    let annotatedContract;
    try {
      annotatedContract = normalizeIoPressureContract(JSON.parse(annotation));
    } catch (error) {
      throw new Error(`IOPressurePod has an invalid compiled I/O-pressure contract annotation: ${error.message}`);
    }
    if (JSON.stringify(annotatedContract) !== JSON.stringify(ioPressureContract)) {
      throw new Error('IOPressurePod compiled I/O-pressure contract does not match compiler evidence');
    }
  }
  const targets = normalizeResolvedTargets(resolvedTargets, selectedActors);
  const campaignNetwork = compiled.metadata.labels?.['testing.stacks.org/network'];
  if (compiled.metadata.namespace !== targets.namespace || campaignNetwork !== targets.network) {
    throw new Error('compiled campaign and resolvedTargets namespace/network do not match');
  }
  const expected = expectedAffected(spec, selectedActors.length);
  const phases = {
    before: normalizePhase(before, 'before', kind),
    during: normalizePhase(during, 'during', kind),
    after: normalizePhase(after, 'after', kind),
  };
  if (!CLOCK_KINDS.has(kind)) {
    for (const [phaseName, phase] of Object.entries(phases)) {
      for (const observation of phase.observations) {
        if (!selectedActors.includes(observation.actor)) {
          throw new Error(`${phaseName} probe contains non-target actor ${observation.actor}`);
        }
      }
    }
  }
  const maps = Object.fromEntries(Object.entries(phases).map(([phase, value]) => [phase, mapByActor(value.observations)]));
  let evaluations;
  if (CLOCK_KINDS.has(kind)) {
    evaluations = timeEvaluations(spec, targets.targets, phases.before.observations, phases.during.observations, phases.after.observations);
  } else {
    const evaluator = {
      PodChaos: (target, first, second, third) => podEvaluation(action, target, first, second, third),
      NetworkChaos: (target, first, second, third) => networkEvaluation(action, spec, target, first, second, third, peerSelectedActors),
      DNSChaos: (target, first, second, third) => dnsEvaluation(action, spec, target, first, second, third),
      IOChaos: (target, first, second, third) => ioEvaluation(action, spec, target, first, second, third),
      IOPressurePod: (target, first, second, third) => ioPressureEvaluation(target, first, second, third, ioPressureContract),
    }[kind];
    evaluations = targets.targets.map(target => evaluator(
      target,
      maps.before.get(target.actor) ?? [],
      maps.during.get(target.actor) ?? [],
      maps.after.get(target.actor) ?? [],
    ));
  }
  const verdict = aggregateEffect(evaluations, expected);
  const recoveryVerdict = aggregateRecovery(evaluations);
  return {
    schemaVersion: FAULT_EFFECT_SCHEMA,
    verdict,
    campaign: {name, kind, action},
    expectedAffected: {...expected, candidates: selectedActors.length},
    effect: {
      verdict,
      provenActors: evaluations.filter(item => item.effect === 'proven').map(item => item.actor),
      failedActors: evaluations.filter(item => item.effect === 'failed').map(item => item.actor),
      inconclusiveActors: evaluations.filter(item => item.effect === 'inconclusive').map(item => item.actor),
    },
    recovery: {
      verdict: recoveryVerdict,
      provenActors: evaluations.filter(item => item.effect === 'proven' && item.recovery === 'proven').map(item => item.actor),
      failedActors: evaluations.filter(item => item.effect === 'proven' && item.recovery === 'failed').map(item => item.actor),
      inconclusiveActors: evaluations.filter(item => item.effect === 'proven' && item.recovery === 'inconclusive').map(item => item.actor),
    },
    injection: {
      allInjectedObserved: phases.during.injection.allInjectedObserved,
      evidentiaryWeight: 'context-only; never sufficient to prove a fault effect',
    },
    trust: {
      phases: Object.fromEntries(Object.entries(phases).map(([phase, value]) => [phase, value.source])),
      timestampAuthority: 'orchestrator kernel-clock/monotonic deltas and direct probes only; actor-supplied timestamps are excluded',
    },
    evaluations,
  };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [campaignPath, evidencePath, targetsPath, beforePath, duringPath, afterPath, outputPath] = process.argv.slice(2);
  if (!campaignPath || !evidencePath || !targetsPath || !beforePath || !duringPath || !afterPath) {
    throw new Error('usage: fault-effect-evidence.mjs CAMPAIGN EVIDENCE TARGETS BEFORE DURING AFTER [OUTPUT]');
  }
  try {
    const result = evaluateFaultEffect({
      campaign: readJson(campaignPath),
      evidence: readJson(evidencePath),
      resolvedTargets: readJson(targetsPath),
      before: readJson(beforePath),
      during: readJson(duringPath),
      after: readJson(afterPath),
    });
    const serialized = `${JSON.stringify(result, null, 2)}\n`;
    if (outputPath) writeFileSync(outputPath, serialized);
    else process.stdout.write(serialized);
    process.exitCode = {[VERDICTS.proven]: 0, [VERDICTS.failed]: 1, [VERDICTS.inconclusive]: 2}[result.verdict];
  } catch (error) {
    process.stderr.write(`fault-effect evidence invalid: ${error.message}\n`);
    process.exitCode = 3;
  }
}
