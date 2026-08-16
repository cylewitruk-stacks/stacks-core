#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import process from 'node:process';
import {gunzipSync, gzipSync} from 'node:zlib';

import {compileCampaign} from '../../../attacknet/fault-campaign.mjs';
import {resolveCampaignTargets} from '../../../attacknet/campaign-targets.mjs';
import {evaluateFaultEffect} from '../../../attacknet/fault-effect-evidence.mjs';
import {
  consumeDdminCandidate, consumeReplayPlan, resolveAttacknetSchedule, validateResolvedSchedule,
} from '../../../attacknet/attacknet-run-schedule.mjs';
import {
  resolveCanonicalSignerSet, verifySignerSetParity,
} from '../../../attacknet/signer-set-parity.mjs';
import {
  PROCESS_WALL_CLOCK_METRIC, ProbeClient, baselineUsable, buildProbeRequest, controlTarget, probePhase,
} from './probe-client.mjs';

export const GROUP = 'testing.stacks.org';
export const VERSION = 'v1alpha1';
export const FINALIZER = 'testing.stacks.org/fault-cleanup';
export const TERMINAL_PHASES = new Set(['Passed', 'Failed', 'Inconclusive']);
export const MINIMIZATION_OUTCOMES = new Set(['FailureReproduced', 'FailureAbsent', 'Inconclusive']);
const ENVIRONMENT_LEASE = 'attacknet-environment-lease';
const MUTATION_LEASE = 'attacknet-mutation-lease';
const SCHEDULE_FORMAT = 'stacks-attacknet-schedule-configmap/v1';
const CHAOS_PLURALS = Object.freeze({
  PodChaos: 'podchaos', NetworkChaos: 'networkchaos', DNSChaos: 'dnschaos',
  IOChaos: 'iochaos', TimeChaos: 'timechaos',
});
const IO_PRESSURE_MECHANISM = 'controller-owned-io-pressure-pod';
const CLOCK_POLICY_MECHANISM = 'controller-owned-application-clock-policy';
const CLOCK_POLICY_ZERO = '+0s\n';
const IO_PRESSURE_MOUNT = '/data';
const IO_PRESSURE_RESOURCES = Object.freeze({
  low: {requests: {cpu: '25m', memory: '24Mi'}, limits: {cpu: '250m', memory: '64Mi'}},
  medium: {requests: {cpu: '50m', memory: '24Mi'}, limits: {cpu: '500m', memory: '64Mi'}},
  high: {requests: {cpu: '100m', memory: '24Mi'}, limits: {cpu: '1', memory: '96Mi'}},
});
const DURATION_UNITS = Object.freeze({ms: 0.001, s: 1, m: 60, h: 3600});
const RUNTIME_ARCHITECTURES = new Set(['x64', 'arm64', 'ppc64', 's390x']);

const now = () => new Date().toISOString();
const canonical = value => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
};
export const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export const artifactDigest = value => `sha256:${digest(value)}`;

export function classifyTerminalAssertion(run, children, scheduleDigest) {
  const minimization = run.spec?.minimization;
  const replay = run.spec?.replay;
  const expectation = minimization?.enabled === true ? {
    attemptId: minimization.attemptId,
    candidateScheduleDigest: minimization.candidateScheduleDigest,
    expectedAssertion: minimization.expectedAssertion,
    expectedStatus: minimization.expectedStatus,
  } : replay?.enabled === true && replay.verifyExpectedFailure === true ? {
    attemptId: replay.attemptId,
    candidateScheduleDigest: replay.descriptorDigest,
    expectedAssertion: replay.expectedAssertion,
    expectedStatus: replay.expectedStatus,
  } : null;
  if (!expectation) return null;
  const {expectedAssertion, expectedStatus} = expectation;
  if (!expectedAssertion || !expectedStatus || !scheduleDigest) {
    throw new Error('minimization assertion classification lacks an immutable expected assertion or schedule');
  }
  const evidence = children.map(child => ({
    name: child.metadata.name,
    uid: child.metadata.uid,
    phase: child.status?.phase ?? 'Pending',
    reason: child.status?.reason ?? '',
    effectResults: child.status?.effectResults ?? [],
    recoveryResults: child.status?.recoveryResults ?? [],
  })).sort((left, right) => left.name.localeCompare(right.name));
  const observations = evidence.flatMap(child => [
    ...child.effectResults.map(result => ({child: child.name, source: 'effect', ...result})),
    ...child.recoveryResults.map(result => ({child: child.name, source: 'recovery', ...result})),
  ]).filter(result => result.assertion === expectedAssertion);
  let outcome;
  let reason;
  if (observations.length > 256) {
    outcome = 'Inconclusive';
    reason = 'AssertionEvidenceLimitExceeded';
  } else if (observations.length > 0
      && observations.every(result => result.outcome === expectedStatus)) {
    outcome = 'FailureReproduced';
    reason = 'ExpectedAssertionObserved';
  } else if (observations.some(result => result.outcome === expectedStatus)) {
    // An assertion name alone does not identify an actor or phase. Conflicting
    // outcomes therefore cannot truthfully establish that the source failure
    // reproduced; require the caller to narrow the expected assertion first.
    outcome = 'Inconclusive';
    reason = 'ConflictingExpectedAssertionEvidence';
  } else if (observations.length > 0
      && observations.every(result => new Set(['Proven', 'Failed']).has(result.outcome))) {
    outcome = 'FailureAbsent';
    reason = 'ExpectedAssertionEvaluatedWithoutExpectedStatus';
  } else {
    outcome = 'Inconclusive';
    reason = observations.length === 0 ? 'ExpectedAssertionNotEvaluated' : 'ExpectedAssertionInconclusive';
  }
  const evidenceDigest = artifactDigest({
    runUID: run.metadata.uid,
    scheduleDigest,
    attemptId: expectation.attemptId,
    expectedAssertion,
    expectedStatus,
    evidence,
  });
  return {
    attemptId: expectation.attemptId,
    candidateScheduleDigest: expectation.candidateScheduleDigest,
    expectedAssertion,
    expectedStatus,
    outcome,
    reason,
    observationCount: observations.length,
    observations: observations.slice(0, 256).map(result => ({
      child: result.child, source: result.source, outcome: result.outcome,
      ...(result.actor ? {actor: result.actor} : {}),
    })),
    evidenceDigest,
    evidenceURI: `k8s://attacknetruns/${run.metadata.name}/terminal-assertion-evidence`,
    causalMinimalityClaimed: false,
  };
}

export function durationSeconds(value) {
  const match = /^(\d+)(ms|s|m|h)$/.exec(value ?? '');
  if (!match) throw new Error(`invalid bounded duration ${value}`);
  return Number(match[1]) * DURATION_UNITS[match[2]];
}

function elapsedSeconds(timestamp) {
  const parsed = Date.parse(timestamp ?? '');
  return Number.isFinite(parsed) ? Math.max(0, (Date.now() - parsed) / 1000) : Infinity;
}

function assertionTimeout(assertions, fallback) {
  const values = (assertions ?? []).map(item => item.timeoutSeconds)
    .filter(item => Number.isInteger(item) && item > 0);
  return values.length ? Math.max(...values) : fallback;
}

function ioPressureLatencyP95(phase, actor) {
  const observation = phase?.observations?.find(item => item.actor === actor);
  const value = observation?.status === 'ok' ? observation.latencyMsP95 : NaN;
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`I/O-pressure probe for ${actor} lacks a finite non-negative p95 latency`);
  }
  return value;
}

export function strongestIoPressurePhase(priorJson, candidate, actor) {
  if (!priorJson) return candidate;
  let prior;
  try {
    prior = JSON.parse(priorJson);
  } catch (error) {
    throw new Error(`stored I/O-pressure probe evidence is malformed: ${error.message}`);
  }
  // The I/O-pressure effect contract requires both a latency multiplier and
  // an absolute latency increase against one immutable baseline. For the same
  // actor and baseline, a larger p95 monotonically strengthens both clauses,
  // so retaining the maximum is sufficient and keeps status bounded to one
  // observation instead of accumulating an unbounded sample history.
  return ioPressureLatencyP95(candidate, actor) > ioPressureLatencyP95(prior, actor)
    ? candidate : prior;
}

export function stableName(...parts) {
  const candidate = parts.filter(Boolean).join('-').toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').replace(/-+/g, '-');
  if (candidate.length <= 63) return candidate;
  const suffix = digest(candidate).slice(0, 10);
  return `${candidate.slice(0, 52).replace(/-+$/g, '')}-${suffix}`;
}

export function networkManifest(network) {
  const metadata = network?.metadata ?? {};
  const actors = network?.spec?.actors;
  if (!metadata.name || !metadata.namespace || !metadata.uid || !Array.isArray(actors)) {
    throw new Error('referenced StacksNetwork is missing admitted identity or actors');
  }
  const signerWeights = new Map();
  const normalized = actors.map(actor => {
    if (!actor.name || !actor.role) throw new Error('StacksNetwork actor lacks name or role');
    if (actor.signerIndex !== undefined) {
      if (!Number.isInteger(actor.signerIndex) || actor.signerIndex < 1
          || typeof actor.signerWeight !== 'number' || !Number.isFinite(actor.signerWeight)
          || actor.signerWeight <= 0
          || !/^(02|03)[0-9a-f]{64}$/.test(actor.signerPublicKey ?? '')) {
        throw new Error(`actor ${actor.name} has invalid authoritative signer ownership`);
      }
      const prior = signerWeights.get(actor.signerIndex);
      if (prior !== undefined
          && (prior.weight !== actor.signerWeight || prior.publicKey !== actor.signerPublicKey)) {
        throw new Error(`signer ${actor.signerIndex} has inconsistent authoritative weight`);
      }
      signerWeights.set(actor.signerIndex, {
        weight: actor.signerWeight, publicKey: actor.signerPublicKey,
      });
    } else if (actor.signerWeight !== undefined) {
      throw new Error(`actor ${actor.name} has signerWeight without signerIndex`);
    }
    return {
      service: actor.name, role: actor.role,
      ...(actor.signerIndex === undefined ? {} : {
        signerIndex: actor.signerIndex, signerWeight: actor.signerWeight,
        signerPublicKey: actor.signerPublicKey,
      }),
    };
  });
  return {schemaVersion: 1, network: metadata.name, namespace: metadata.namespace, actors: normalized};
}

function getJson({hostname, port, path, timeoutMs = 5_000, request = http.request}) {
  return new Promise((resolve, reject) => {
    const call = request({hostname, port, path, method: 'GET', timeout: timeoutMs}, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > 1_048_576) call.destroy(new Error(`response ${path} exceeds 1 MiB`));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        if ((response.statusCode ?? 0) !== 200) {
          const error = new Error(`Stacks RPC ${path} returned HTTP ${response.statusCode ?? 0}`);
          error.code = response.statusCode;
          reject(error);
          return;
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error(`Stacks RPC ${path} returned invalid JSON`)); }
      });
    });
    call.on('timeout', () => call.destroy(Object.assign(new Error(`Stacks RPC ${path} timed out`), {code: 'ETIMEDOUT'})));
    call.on('error', reject);
    call.end();
  });
}

export class SignerSetClient {
  constructor({request = http.request, timeoutMs = 5_000} = {}) {
    this.request = request;
    this.timeoutMs = timeoutMs;
  }
  async observe(network, pods) {
    const actors = network.spec?.actors ?? [];
    const roleOrder = role => ({miner: 0, companion: 1, follower: 2}[role] ?? 9);
    const nodes = actors.filter(actor => ['miner', 'companion', 'follower'].includes(actor.role))
      .sort((left, right) => (roleOrder(left.role) - roleOrder(right.role)
        || left.name.localeCompare(right.name)));
    const selected = nodes.flatMap(actor => {
      const rpc = (actor.ports ?? []).find(port => port.name === 'rpc');
      const pod = (pods.items ?? []).find(item => !item.metadata?.deletionTimestamp
        && item.metadata?.labels?.['testing.stacks.org/actor'] === actor.name
        && podReady(item) && item.status?.podIP);
      return rpc && pod ? [{actor, pod, port: rpc.containerPort ?? rpc.servicePort}] : [];
    })[0];
    if (!selected || !Number.isInteger(selected.port)) {
      throw new Error('no Ready enrolled Stacks RPC endpoint is available for signer-set verification');
    }
    const request = this.request;
    const timeoutMs = this.timeoutMs;
    const endpoint = {hostname: selected.pod.status.podIP, port: selected.port, timeoutMs, request};
    const pox = await getJson({...endpoint, path: '/v2/pox'});
    const rewardCycle = pox.current_cycle?.id;
    if (!Number.isSafeInteger(rewardCycle) || rewardCycle < 0) {
      throw new Error('Stacks RPC /v2/pox lacks a current reward cycle');
    }
    const rewardSet = await getJson({...endpoint, path: `/v3/stacker_set/${rewardCycle}`});
    return {rewardCycle, rewardSet, observedFrom: selected.actor.name};
  }
  async verify(network, pods, manifest = networkManifest(network)) {
    const {rewardCycle, rewardSet, observedFrom} = await this.observe(network, pods);
    return {...verifySignerSetParity(manifest, rewardSet, {rewardCycle}), observedFrom};
  }
  async resolve(network, pods, manifest = networkManifest(network)) {
    const {rewardCycle, rewardSet, observedFrom} = await this.observe(network, pods);
    const resolved = resolveCanonicalSignerSet(manifest, rewardSet, {rewardCycle});
    return {...resolved.report, manifest: resolved.manifest, observedFrom};
  }
}

function actorRequestedImage(network, actor) {
  const image = actor.image ?? network.spec?.defaults?.image;
  if (typeof image !== 'string' || image.length === 0) {
    throw new Error(`actor ${actor.name} has no requested image`);
  }
  return image;
}

export function resolvedNetworkImages(network, pods) {
  const items = pods?.items ?? [];
  return (network.spec?.actors ?? []).map(actor => {
    const matches = items.filter(pod => !pod.metadata?.deletionTimestamp
      && pod.metadata?.labels?.['testing.stacks.org/network'] === network.metadata.name
      && pod.metadata?.labels?.['testing.stacks.org/actor'] === actor.name);
    if (matches.length !== 1 || !podReady(matches[0])) {
      throw new Error(`actor ${actor.name} does not resolve to one Ready admitted Pod`);
    }
    const container = matches[0].status?.containerStatuses?.find(item => item.name === 'actor');
    const resolvedRef = container?.imageID;
    const match = /sha256:[0-9a-f]{64}/.exec(resolvedRef ?? '');
    if (!match) throw new Error(`actor ${actor.name} lacks an immutable admitted image digest`);
    return {
      scope: actor.name,
      requestedRef: actorRequestedImage(network, actor),
      resolvedRef,
      resolvedDigest: match[0],
    };
  }).sort((left, right) => left.scope.localeCompare(right.scope));
}

export function encodeSchedule(schedule) {
  validateResolvedSchedule(schedule);
  return gzipSync(Buffer.from(JSON.stringify(schedule))).toString('base64');
}

export function decodeSchedule(configMap) {
  if (configMap?.metadata?.annotations?.['testing.stacks.org/schedule-format'] !== SCHEDULE_FORMAT) {
    throw new Error('schedule ConfigMap has an unsupported format');
  }
  const encoded = configMap.binaryData?.['schedule.json.gz'];
  if (typeof encoded !== 'string' || encoded.length === 0) throw new Error('schedule ConfigMap has no payload');
  const schedule = JSON.parse(gunzipSync(Buffer.from(encoded, 'base64')).toString('utf8'));
  validateResolvedSchedule(schedule);
  const expected = configMap.metadata.annotations['testing.stacks.org/schedule-digest'];
  if (schedule.integrity.digest !== expected) throw new Error('schedule ConfigMap digest annotation mismatch');
  return schedule;
}

function conditionTrue(resource, type) {
  return (resource?.status?.conditions ?? []).some(item => item.type === type && item.status === 'True');
}

function injectionFailureMessage(resource) {
  const records = resource?.status?.experiment?.containerRecords ?? [];
  const messages = records.flatMap(record => record.events ?? [])
    .filter(event => event.type === 'Failed')
    .map(event => String(event.message ?? 'Chaos Mesh injection failed').trim())
    .filter((message, index, values) => message && values.indexOf(message) === index)
    .slice(0, 3);
  return (messages.length ? messages.join('; ') : 'Chaos Mesh recovered before AllInjected became true')
    .slice(0, 1000);
}

function actualInjectionEvidence(resource, allInjectedObserved = false) {
  return {
    allInjectedObserved,
    chaosResourceVersion: resource?.metadata?.resourceVersion ?? 'unknown',
    records: resource?.status?.experiment ?? resource?.status?.instances ?? null,
  };
}

function zeroInjectionFinalizerAbortSafe(campaign, resource) {
  if (campaign.spec?.fault?.type !== 'io'
      || campaign.status?.phase !== 'Failed'
      || !['InjectionFailed', 'InjectionTimeout'].includes(campaign.status?.reason)
      || conditionTrue(resource, 'AllInjected')
      || elapsedSeconds(resource?.metadata?.deletionTimestamp) < 30) return false;
  const containers = campaign.spec?.fault?.parameters?.containerNames;
  const targets = campaign.status?.resolvedTargets;
  const records = resource?.status?.experiment?.containerRecords;
  if (!Array.isArray(containers) || containers.length === 0
      || !Array.isArray(targets) || targets.length === 0
      || !Array.isArray(records)) return false;
  const expected = new Set(targets.flatMap(target => containers.map(container =>
    `${campaign.metadata.namespace}/${target.pod}/${container}`)));
  if (records.length !== expected.size) return false;
  return records.every(record => expected.delete(record.id)
    && record.injectedCount === 0
    && record.recoveredCount === 0
    && record.phase === 'Not Injected/Wait'
    && (record.events ?? []).some(event => event.type === 'Failed' && event.operation === 'Apply')
    && !(record.events ?? []).some(event => event.type === 'Succeeded'))
    && expected.size === 0;
}

function podReady(pod) {
  return pod?.status?.phase === 'Running'
    && (pod.status.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True')
    && (pod.status.containerStatuses ?? []).some(item => item.name === 'actor' && item.ready === true);
}

function probeTargetReady(target, pods) {
  const pod = (pods.items ?? pods).find(item => item.metadata?.uid === target.podUid);
  const probe = pod?.status?.containerStatuses?.find(item => item.name === 'attacknet-probe');
  return podReady(pod) && probe?.ready === true && pod.status?.podIP === target.podIP;
}

function minimumAffected(spec, candidates) {
  if (spec.mode === 'all') return candidates;
  if (spec.mode === 'one' || spec.mode === undefined) return 1;
  const value = Number(spec.value);
  if (spec.mode === 'fixed') return value;
  if (spec.mode === 'fixed-percent') return Math.ceil(candidates * value / 100);
  if (spec.mode === 'random-max-percent') return 1;
  throw new Error(`unsupported admitted mode ${spec.mode}`);
}

export function podEffectResults(campaign, pods) {
  const action = campaign.spec.fault.action;
  const assertion = {
    'pod-kill': 'PodRestarted', 'pod-failure': 'PodUnavailable',
    'container-kill': 'ContainerRestarted',
  }[action];
  const network = campaign.spec.networkRef;
  return (campaign.status?.resolvedTargets ?? []).map(target => {
    const current = (pods.items ?? pods).filter(pod =>
      pod.metadata?.labels?.['testing.stacks.org/network'] === network
      && pod.metadata?.labels?.['testing.stacks.org/actor'] === target.actor
      && !pod.metadata?.deletionTimestamp);
    const same = current.find(pod => pod.metadata.uid === target.podUid);
    const actorStatus = same?.status?.containerStatuses?.find(item => item.name === 'actor');
    let outcome = 'Failed';
    let message = 'admitted Pod state did not exhibit the requested effect';
    if (action === 'pod-kill' && !same) {
      outcome = 'Proven';
      message = 'the admitted Pod UID disappeared after injection';
    } else if (action === 'pod-failure' && same && !podReady(same)) {
      outcome = 'Proven';
      message = 'the admitted Pod became unavailable after injection';
    } else if (action === 'pod-failure' && !same) {
      outcome = 'Inconclusive';
      message = 'the admitted Pod disappeared instead of exhibiting pod-failure state';
    } else if (action === 'container-kill' && same
        && Number(actorStatus?.restartCount ?? -1) > target.restartCount) {
      outcome = 'Proven';
      message = 'the actor container restart count increased after injection';
    } else if (action === 'container-kill' && !same) {
      outcome = 'Inconclusive';
      message = 'the admitted Pod UID changed, so a container restart cannot be attributed';
    }
    return {assertion, outcome, actor: target.actor, podUid: target.podUid, observedAt: now(), message};
  });
}

function ownerReference(resource) {
  return [{
    apiVersion: `${GROUP}/${VERSION}`, kind: resource.kind,
    name: resource.metadata.name, uid: resource.metadata.uid, controller: true,
  }];
}

function status(base, phase, reason, extra = {}) {
  return {
    ...base,
    observedGeneration: base?.observedGeneration,
    phase, reason, lastTransitionTime: now(), ...extra,
  };
}

function metricLabel(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function metric(name, labels, value = 1) {
  const encoded = Object.entries(labels).map(([key, item]) => `${key}="${metricLabel(item)}"`).join(',');
  return `${name}{${encoded}} ${value}`;
}

export function prometheusMetrics(campaigns, runs) {
  const lines = [
    '# HELP attacknet_fault_campaign_info Current orchestrator-observed FaultCampaign state.',
    '# TYPE attacknet_fault_campaign_info gauge',
    '# HELP attacknet_fault_campaign_target_info Exact actor targets admitted for a FaultCampaign.',
    '# TYPE attacknet_fault_campaign_target_info gauge',
    '# HELP attacknet_fault_campaign_assertion_outcome Trusted effect and recovery assertion outcomes.',
    '# TYPE attacknet_fault_campaign_assertion_outcome gauge',
    '# HELP attacknet_run_info Current orchestrator-observed AttacknetRun state.',
    '# TYPE attacknet_run_info gauge',
    '# HELP attacknet_run_budget_usage Current AttacknetRun budget consumption.',
    '# TYPE attacknet_run_budget_usage gauge',
    '# HELP attacknet_run_minimization_outcome Trusted terminal ddmin counterfactual classification.',
    '# TYPE attacknet_run_minimization_outcome gauge',
  ];
  for (const campaign of campaigns) {
    const base = {
      evidence_source: 'orchestrator_observed',
      network: campaign.spec?.networkRef ?? '', campaign: campaign.metadata?.name ?? '',
    };
    lines.push(metric('attacknet_fault_campaign_info', {
      ...base, type: campaign.spec?.fault?.type ?? '', phase: campaign.status?.phase ?? 'Pending',
      reason: campaign.status?.reason ?? '', template: campaign.spec?.template === true ? 'true' : 'false',
    }));
    for (const target of campaign.status?.resolvedTargets ?? []) {
      lines.push(metric('attacknet_fault_campaign_target_info', {
        ...base, actor: target.actor, role: target.role, node: target.node,
      }));
    }
    for (const result of [
      ...(campaign.status?.effectResults ?? []), ...(campaign.status?.recoveryResults ?? []),
    ]) {
      lines.push(metric('attacknet_fault_campaign_assertion_outcome', {
        ...base, actor: result.actor, assertion: result.assertion, outcome: result.outcome,
      }));
    }
  }
  for (const run of runs) {
    const base = {
      evidence_source: 'orchestrator_observed', network: run.spec?.networkRef ?? '',
      run: run.metadata?.name ?? '',
    };
    lines.push(metric('attacknet_run_info', {
      ...base, phase: run.status?.phase ?? 'Pending', reason: run.status?.reason ?? '',
      attribution: run.status?.attribution ?? 'Untriaged',
      replay: run.status?.scheduleSummary?.replay === true ? 'true' : 'false',
      minimization: run.spec?.minimization?.enabled === true ? 'true' : 'false',
      schedule_digest: run.status?.scheduleRef?.digest ?? '',
    }));
    for (const [budget, value] of Object.entries(run.status?.budgetUsage ?? {})) {
      if (typeof value === 'number' && Number.isFinite(value)) {
        lines.push(metric('attacknet_run_budget_usage', {...base, budget}, value));
      }
    }
    const classification = run.status?.terminalClassification;
    if (classification) {
      lines.push(metric('attacknet_run_minimization_outcome', {
        ...base,
        attempt: classification.attemptId,
        candidate_digest: classification.candidateScheduleDigest,
        expected_assertion: classification.expectedAssertion,
        expected_status: classification.expectedStatus,
        outcome: classification.outcome,
        reason: classification.reason,
        evidence_digest: classification.evidenceDigest,
        causal_minimality_claimed: 'false',
      }));
    }
  }
  return `${lines.join('\n')}\n`;
}

export class ApiError extends Error {
  constructor(code, method, path, body = '') {
    super(`Kubernetes API ${method} ${path} returned ${code}: ${body.slice(0, 500)}`);
    this.code = code;
  }
}

function transientError(error) {
  if (error instanceof ApiError) return error.code === 409 || error.code === 429 || error.code >= 500;
  return new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN'])
    .has(error?.code);
}

function supportedArchitectures(value, environmentName) {
  const entries = (Array.isArray(value) ? value : String(value).split(','))
    .map(item => String(item).trim()).filter(Boolean);
  if (entries.length === 0 || entries.some(item => !RUNTIME_ARCHITECTURES.has(item))) {
    throw new Error(`${environmentName} must be a non-empty supported architecture list`);
  }
  return new Set(entries);
}

function ioChaosArchitectures(value = process.env.IOCHAOS_SUPPORTED_ARCHITECTURES ?? 'x64') {
  return supportedArchitectures(value, 'IOCHAOS_SUPPORTED_ARCHITECTURES');
}

function timeChaosArchitectures(value = process.env.TIMECHAOS_SUPPORTED_ARCHITECTURES ?? 'x64') {
  return supportedArchitectures(value, 'TIMECHAOS_SUPPORTED_ARCHITECTURES');
}

export class KubernetesApi {
  constructor({namespace = process.env.WATCH_NAMESPACE, baseUrl, tokenPath, caPath} = {}) {
    this.namespace = namespace;
    this.baseUrl = baseUrl ?? `https://${process.env.KUBERNETES_SERVICE_HOST}:${process.env.KUBERNETES_SERVICE_PORT_HTTPS ?? 443}`;
    this.tokenPath = tokenPath ?? '/var/run/secrets/kubernetes.io/serviceaccount/token';
    this.caPath = caPath ?? '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt';
  }

  async request(method, path, body, contentType = 'application/json', allow404 = false) {
    const [tokenValue, ca] = await Promise.all([
      readFile(this.tokenPath, 'utf8'), readFile(this.caPath),
    ]);
    const token = tokenValue.trim();
    if (!token) throw new Error('projected service-account token is empty');
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const result = await new Promise((resolve, reject) => {
      const request = https.request(new URL(path, this.baseUrl), {
        method, ca, timeout: 30_000,
        headers: {
          Authorization: `Bearer ${token}`, Accept: 'application/json',
          'Content-Type': contentType,
          ...(payload === undefined ? {} : {'Content-Length': Buffer.byteLength(payload)}),
        },
      }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({
          status: response.statusCode ?? 0,
          text: Buffer.concat(chunks).toString('utf8'),
        }));
      });
      request.on('timeout', () => request.destroy(new Error(`Kubernetes API ${method} ${path} timed out`)));
      request.on('error', reject);
      if (payload !== undefined) request.write(payload);
      request.end();
    });
    if (allow404 && result.status === 404) return null;
    if (result.status < 200 || result.status >= 300) throw new ApiError(result.status, method, path, result.text);
    return result.text ? JSON.parse(result.text) : null;
  }

  customPath(plural, name = '', group = GROUP, version = VERSION) {
    return `/apis/${group}/${version}/namespaces/${this.namespace}/${plural}${name ? `/${name}` : ''}`;
  }
  corePath(plural, name = '') {
    return `/api/v1/namespaces/${this.namespace}/${plural}${name ? `/${name}` : ''}`;
  }
  list(plural, {group = GROUP, version = VERSION, labels} = {}) {
    const base = group === '' ? this.corePath(plural) : this.customPath(plural, '', group, version);
    return this.request('GET', `${base}${labels ? `?labelSelector=${encodeURIComponent(labels)}` : ''}`);
  }
  get(plural, name, {group = GROUP, version = VERSION, allow404 = false} = {}) {
    const path = group === '' ? this.corePath(plural, name) : this.customPath(plural, name, group, version);
    return this.request('GET', path, undefined, 'application/json', allow404);
  }
  create(plural, body, {group = GROUP, version = VERSION} = {}) {
    const path = group === '' ? this.corePath(plural) : this.customPath(plural, '', group, version);
    return this.request('POST', path, body);
  }
  patch(plural, name, body, {group = GROUP, version = VERSION, subresource = ''} = {}) {
    let path = group === '' ? this.corePath(plural, name) : this.customPath(plural, name, group, version);
    if (subresource) path += `/${subresource}`;
    return this.request('PATCH', path, body, 'application/merge-patch+json');
  }
  delete(plural, name, {group = GROUP, version = VERSION, allow404 = true} = {}) {
    const path = group === '' ? this.corePath(plural, name) : this.customPath(plural, name, group, version);
    return this.request('DELETE', path, {propagationPolicy: 'Background'}, 'application/json', allow404);
  }
}

function chaosIdentity(campaign) {
  const type = campaign.spec?.fault?.type;
  const kind = {
    pod: 'PodChaos', network: 'NetworkChaos', dns: 'DNSChaos', io: 'IOChaos',
    'io-pressure': 'IOPressurePod', time: 'TimeChaos',
    'clock-skew': 'ClockSkewPolicy',
  }[type];
  if (!kind) throw new Error(`unsupported fault type ${type}`);
  if (kind === 'IOPressurePod') {
    return {
      kind, plural: 'pods', group: '', version: 'v1',
      name: stableName('io-pressure', campaign.metadata.name),
    };
  }
  if (kind === 'ClockSkewPolicy') {
    return {
      kind, plural: 'configmaps', group: '', version: 'v1',
      name: `${campaign.spec.networkRef}-clock-policy`,
    };
  }
  return {
    kind, plural: CHAOS_PLURALS[kind], group: 'chaos-mesh.org',
    version: 'v1alpha1', name: campaign.metadata.name,
  };
}

function clockPolicyContract(campaign, policy) {
  return {
    mechanism: CLOCK_POLICY_MECHANISM,
    network: campaign.spec.networkRef,
    policyName: policy.metadata?.name,
    policyUid: policy.metadata?.uid,
    policyActors: Object.keys(policy.data ?? {}).sort(),
    actors: (campaign.status?.resolvedTargets ?? []).map(target => target.actor).sort(),
    offset: campaign.spec?.fault?.parameters?.timeOffset,
  };
}

function clockPolicyMatches(policy, campaign, expectedOffset) {
  if (policy.metadata?.labels?.['testing.stacks.org/network'] !== campaign.spec.networkRef
      || policy.metadata?.labels?.['testing.stacks.org/clock-policy'] !== 'true') return false;
  const selected = new Set((campaign.status?.resolvedTargets ?? []).map(target => target.actor));
  return selected.size > 0
    && [...selected].every(actor => policy.data?.[actor] === expectedOffset)
    && Object.entries(policy.data ?? {}).every(([actor, value]) =>
      value === (selected.has(actor) ? expectedOffset : CLOCK_POLICY_ZERO));
}

function identityOptions(identity, allow404 = false) {
  return {group: identity.group, version: identity.version, allow404};
}

function ioPressurePodRunning(resource) {
  const container = resource?.status?.containerStatuses?.find(item => item.name === 'io-pressure');
  return resource?.status?.phase === 'Running'
    && container?.state?.running !== undefined
    && typeof container?.imageID === 'string' && container.imageID.length > 0;
}

function ioPressureActualInjection(resource, target) {
  const container = resource.status.containerStatuses.find(item => item.name === 'io-pressure');
  return {
    mechanism: IO_PRESSURE_MECHANISM,
    allInjectedObserved: true,
    podUid: resource.metadata.uid,
    image: container.image,
    imageID: container.imageID,
    node: resource.spec.nodeName,
    phase: resource.status.phase,
    targetActor: target.actor,
    targetPodUid: target.podUid,
    pvcClaim: resource.spec.volumes.find(item => item.name === 'actor-data')
      ?.persistentVolumeClaim?.claimName,
    observedAt: now(),
  };
}

function pressureTargetStorage(campaign, pods) {
  const [target] = campaign.status?.resolvedTargets ?? [];
  if (!target || campaign.status.resolvedTargets.length !== 1) {
    throw new Error('disk-pressure requires exactly one admitted actor target');
  }
  const pod = (pods.items ?? []).find(item => item.metadata?.uid === target.podUid);
  if (!pod || pod.metadata?.deletionTimestamp || pod.spec?.nodeName !== target.node) {
    throw new Error('the exact admitted disk-pressure target Pod or node changed');
  }
  const actor = pod.spec?.containers?.find(item => item.name === 'actor');
  const mount = actor?.volumeMounts?.find(item => item.mountPath === IO_PRESSURE_MOUNT);
  const volume = pod.spec?.volumes?.find(item => item.name === mount?.name);
  const claimName = volume?.persistentVolumeClaim?.claimName;
  if (typeof claimName !== 'string' || claimName.length === 0) {
    throw new Error('the admitted actor does not mount a persistent data claim at /data');
  }
  return {target, pod, claimName};
}

function buildIoPressurePod(campaign, compiled, pods, {image, pullPolicy}) {
  if (typeof image !== 'string' || image.length === 0) {
    throw new Error('trusted I/O-pressure image is not configured');
  }
  const {target, pod, claimName} = pressureTargetStorage(campaign, pods);
  const contract = compiled.evidence.ioPressure;
  const duration = Math.ceil(durationSeconds(compiled.resource.spec.duration));
  const scratch = `${IO_PRESSURE_MOUNT}/.attacknet-io-pressure-${campaign.metadata.uid}`;
  const fsGroup = Number(pod.spec?.securityContext?.fsGroup ?? 65532);
  if (!Number.isSafeInteger(fsGroup) || fsGroup <= 0) throw new Error('target Pod fsGroup is not a safe non-root integer');
  return {
    apiVersion: 'v1', kind: 'Pod',
    metadata: {
      name: chaosIdentity(campaign).name, namespace: campaign.metadata.namespace,
      ownerReferences: ownerReference(campaign),
      labels: {
        'testing.stacks.org/network': campaign.spec.networkRef,
        'testing.stacks.org/campaign': campaign.metadata.name,
        'testing.stacks.org/mechanism': IO_PRESSURE_MECHANISM,
      },
      annotations: {
        'testing.stacks.org/io-pressure-contract': JSON.stringify(contract),
        'testing.stacks.org/target-pod-uid': target.podUid,
        'testing.stacks.org/target-pvc': claimName,
      },
    },
    spec: {
      automountServiceAccountToken: false,
      restartPolicy: 'Never',
      terminationGracePeriodSeconds: 10,
      nodeName: target.node,
      securityContext: {
        runAsNonRoot: true, fsGroup, fsGroupChangePolicy: 'OnRootMismatch',
        seccompProfile: {type: 'RuntimeDefault'},
      },
      containers: [{
        name: 'io-pressure', image, imagePullPolicy: pullPolicy,
        args: [
          '--duration-seconds', String(duration),
          '--workers', String(contract.workers),
          '--bytes-mib', String(contract.bytesMiB),
          '--write-size-kib', String(contract.writeSizeKiB),
          '--scratch-path', scratch,
        ],
        securityContext: {
          allowPrivilegeEscalation: false, capabilities: {drop: ['ALL']},
          readOnlyRootFilesystem: true, runAsNonRoot: true,
          runAsUser: 65532, runAsGroup: 65532,
          seccompProfile: {type: 'RuntimeDefault'},
        },
        resources: structuredClone(IO_PRESSURE_RESOURCES[contract.severity]),
        volumeMounts: [{name: 'actor-data', mountPath: IO_PRESSURE_MOUNT}],
      }],
      volumes: [{name: 'actor-data', persistentVolumeClaim: {claimName}}],
    },
  };
}

function ioPressurePodContract(resource) {
  const container = resource?.spec?.containers?.find(item => item.name === 'io-pressure');
  const volume = resource?.spec?.volumes?.find(item => item.name === 'actor-data');
  return {
    ownerUid: resource?.metadata?.ownerReferences?.find(item => item.controller === true)?.uid,
    labels: {
      network: resource?.metadata?.labels?.['testing.stacks.org/network'],
      campaign: resource?.metadata?.labels?.['testing.stacks.org/campaign'],
      mechanism: resource?.metadata?.labels?.['testing.stacks.org/mechanism'],
    },
    annotations: {
      contract: resource?.metadata?.annotations?.['testing.stacks.org/io-pressure-contract'],
      targetPodUid: resource?.metadata?.annotations?.['testing.stacks.org/target-pod-uid'],
      targetPvc: resource?.metadata?.annotations?.['testing.stacks.org/target-pvc'],
    },
    pod: {
      automountServiceAccountToken: resource?.spec?.automountServiceAccountToken,
      restartPolicy: resource?.spec?.restartPolicy,
      terminationGracePeriodSeconds: resource?.spec?.terminationGracePeriodSeconds,
      nodeName: resource?.spec?.nodeName,
      securityContext: resource?.spec?.securityContext,
    },
    container: container ? {
      image: container.image, imagePullPolicy: container.imagePullPolicy,
      command: container.command, args: container.args,
      securityContext: container.securityContext, resources: container.resources,
      volumeMounts: container.volumeMounts,
    } : null,
    volume: volume?.persistentVolumeClaim?.claimName,
    containerCount: resource?.spec?.containers?.length,
    volumeCount: resource?.spec?.volumes?.length,
  };
}

function campaignDocument(campaign) {
  return {metadata: {name: campaign.metadata.name}, spec: campaign.spec};
}

export class FaultCampaignReconciler {
  constructor(api, probes = new ProbeClient(), signerSets = new SignerSetClient(), capabilities = {}) {
    this.api = api;
    this.probes = probes;
    this.signerSets = signerSets;
    this.ioChaosArchitectures = ioChaosArchitectures(capabilities.ioChaosArchitectures);
    this.timeChaosArchitectures = timeChaosArchitectures(capabilities.timeChaosArchitectures);
    this.ioPressure = {
      image: capabilities.ioPressureImage ?? process.env.IO_PRESSURE_IMAGE,
      pullPolicy: capabilities.ioPressureImagePullPolicy
        ?? process.env.IO_PRESSURE_IMAGE_PULL_POLICY ?? 'IfNotPresent',
    };
    if (!new Set(['Always', 'IfNotPresent', 'Never']).has(this.ioPressure.pullPolicy)) {
      throw new Error('IO pressure imagePullPolicy must be Always, IfNotPresent, or Never');
    }
  }

  async patchStatus(campaign, next) {
    next.observedGeneration = campaign.metadata.generation;
    await this.api.patch('faultcampaigns', campaign.metadata.name,
      {metadata: {resourceVersion: campaign.metadata.resourceVersion}, status: next}, {subresource: 'status'});
  }

  async patchFinalizers(campaign, finalizers) {
    await this.api.patch('faultcampaigns', campaign.metadata.name, {
      metadata: {resourceVersion: campaign.metadata.resourceVersion, finalizers},
    });
  }

  async removeChaos(campaign) {
    const identity = chaosIdentity(campaign);
    if (identity.kind === 'ClockSkewPolicy') {
      // No policy mutation occurred for pre-admission failures.
      if (!campaign.status?.chaos?.uid) return {absent: true, allRecovered: true, method: 'Normal'};
      let current = await this.api.get(identity.plural, identity.name,
        identityOptions(identity, true));
      if (!current) return {absent: false, allRecovered: false, method: 'ClockPolicyMissing'};
      if (current.metadata?.uid !== campaign.status.chaos.uid
          || current.metadata?.labels?.['testing.stacks.org/network'] !== campaign.spec.networkRef
          || current.metadata?.labels?.['testing.stacks.org/clock-policy'] !== 'true') {
        throw new Error(`refusing to mutate unbound clock policy ${identity.name}`);
      }
      const reset = Object.fromEntries(
        (campaign.status?.resolvedTargets ?? []).map(target => [target.actor, CLOCK_POLICY_ZERO]),
      );
      if (!clockPolicyMatches(current, campaign, CLOCK_POLICY_ZERO)) {
        await this.api.patch(identity.plural, identity.name, {
          metadata: {resourceVersion: current.metadata.resourceVersion}, data: reset,
        }, identityOptions(identity));
        current = await this.api.get(identity.plural, identity.name, identityOptions(identity));
      }
      const cleared = clockPolicyMatches(current, campaign, CLOCK_POLICY_ZERO);
      return {absent: cleared, allRecovered: cleared, method: 'ClockPolicyReset'};
    }
    const current = await this.api.get(identity.plural, identity.name,
      identityOptions(identity, true));
    if (!current) return {absent: true, allRecovered: true};
    if (identity.kind === 'IOPressurePod'
        && (current.metadata?.ownerReferences?.find(item => item.controller === true)?.uid
          !== campaign.metadata.uid
          || !campaign.status?.chaos?.uid
          || current.metadata?.uid !== campaign.status.chaos.uid)) {
      throw new Error(`refusing to delete unowned ${identity.plural}/${identity.name}`);
    }
    const allRecovered = identity.kind === 'IOPressurePod'
      ? current.status?.phase === 'Succeeded' : conditionTrue(current, 'AllRecovered');
    if (!current.metadata?.deletionTimestamp) {
      await this.api.delete(identity.plural, identity.name, identityOptions(identity));
    }
    let remaining = await this.api.get(identity.plural, identity.name,
      identityOptions(identity, true));
    let method = 'Normal';
    if (identity.kind !== 'IOPressurePod' && remaining && zeroInjectionFinalizerAbortSafe(campaign, remaining)) {
      const finalizers = (remaining.metadata?.finalizers ?? [])
        .filter(item => item !== 'chaos-mesh/records');
      if (finalizers.length !== (remaining.metadata?.finalizers ?? []).length) {
        await this.api.patch(identity.plural, identity.name, {
          metadata: {resourceVersion: remaining.metadata.resourceVersion, finalizers},
        }, identityOptions(identity));
        method = 'ZeroInjectionFinalizerAbort';
        remaining = await this.api.get(identity.plural, identity.name,
          identityOptions(identity, true));
      }
    }
    return {absent: !remaining, allRecovered, method};
  }

  leaseOwner(campaign) { return `faultcampaign:${campaign.metadata.uid}`; }

  async holdMutationLease(campaign, network, acquire) {
    const environment = await this.api.get('configmaps', ENVIRONMENT_LEASE,
      {group: '', allow404: true});
    if (environment?.data?.network !== network) {
      throw new Error(`active environment lease is not ${network}`);
    }
    let lease = await this.api.get('configmaps', MUTATION_LEASE, {group: '', allow404: true});
    const owner = this.leaseOwner(campaign);
    if (!lease && acquire) {
      const desired = {
        apiVersion: 'v1', kind: 'ConfigMap',
        metadata: {name: MUTATION_LEASE, namespace: campaign.metadata.namespace},
        data: {
          network, owner, purpose: `faultcampaign:${campaign.metadata.name}`,
          token: campaign.metadata.uid, acquiredAt: now(),
        },
      };
      try { lease = await this.api.create('configmaps', desired, {group: ''}); }
      catch (error) {
        if (!(error instanceof ApiError) || error.status !== 409) throw error;
        lease = await this.api.get('configmaps', MUTATION_LEASE, {group: '', allow404: true});
      }
    }
    if (!lease) return false;
    return lease.data?.network === network && lease.data?.owner === owner
      && lease.data?.token === campaign.metadata.uid;
  }

  async releaseMutationLease(campaign) {
    const lease = await this.api.get('configmaps', MUTATION_LEASE, {group: '', allow404: true});
    if (!lease) return;
    if (lease.data?.owner !== this.leaseOwner(campaign)
        || lease.data?.token !== campaign.metadata.uid) return;
    await this.api.delete('configmaps', MUTATION_LEASE, {group: '', allow404: true});
  }

  async faultCapabilityEvidence(campaign, pods, targets) {
    const type = campaign.spec?.fault?.type;
    if (type === 'clock-skew') {
      const policyName = `${campaign.spec.networkRef}-clock-policy`;
      const policy = await this.api.get('configmaps', policyName, {group: '', allow404: true});
      return targets.map(target => {
        const pod = (pods.items ?? []).find(item => item.metadata?.uid === target.podUid);
        const actor = pod?.spec?.containers?.find(item => item.name === 'actor');
        const env = Object.fromEntries((actor?.env ?? [])
          .filter(item => typeof item.value === 'string').map(item => [item.name, item.value]));
        const mount = actor?.volumeMounts?.find(item => item.mountPath === '/run/attacknet-clock');
        const volume = pod?.spec?.volumes?.find(item => item.name === mount?.name);
        const cleanPolicy = Object.keys(policy?.data ?? {}).length > 0
          && Object.values(policy.data).every(value => value === CLOCK_POLICY_ZERO);
        const supported = policy?.metadata?.labels?.['testing.stacks.org/network'] === campaign.spec.networkRef
          && policy?.metadata?.labels?.['testing.stacks.org/clock-policy'] === 'true'
          && cleanPolicy
          && policy?.data?.[target.actor] === CLOCK_POLICY_ZERO
          && volume?.configMap?.name === policyName
          && env.LD_PRELOAD === '/usr/lib/stacks-attacknet/libfaketime.so.1'
          && env.FAKETIME_TIMESTAMP_FILE === `/run/attacknet-clock/${target.actor}`
          && env.FAKETIME_DONT_FAKE_MONOTONIC === '1'
          && env.FAKETIME_NO_CACHE === '1';
        return {
          actor: target.actor, podUid: target.podUid,
          source: 'attacknet-run-operator/v1', observedAt: now(),
          platform: 'application-clock-policy', architecture: 'image-contract', supported,
          reason: supported
            ? `${CLOCK_POLICY_MECHANISM} is mounted and initialized at zero offset`
            : `${CLOCK_POLICY_MECHANISM} image, environment, volume, or zero-offset policy contract is incomplete`,
        };
      });
    }
    if (type === 'io-pressure') {
      return targets.map(target => ({
        actor: target.actor, podUid: target.podUid,
        source: 'attacknet-run-operator/v1', observedAt: now(),
        platform: 'kubernetes-core-pod', architecture: 'native-image',
        supported: typeof this.ioPressure.image === 'string' && this.ioPressure.image.length > 0,
        reason: typeof this.ioPressure.image === 'string' && this.ioPressure.image.length > 0
          ? `${IO_PRESSURE_MECHANISM} configured with trusted image ${this.ioPressure.image}`
          : `${IO_PRESSURE_MECHANISM} has no trusted image configured`,
      }));
    }
    if (type !== 'io' && type !== 'time') return [];
    const kind = type === 'io' ? 'IOChaos' : 'TimeChaos';
    const architectures = type === 'io'
      ? this.ioChaosArchitectures : this.timeChaosArchitectures;
    return Promise.all(targets.map(async target => {
      const base = {
        actor: target.actor, podUid: target.podUid,
        source: 'attacknet-probe/v1', observedAt: now(),
      };
      try {
        if (!probeTargetReady(target, pods)) {
          throw new Error('exact admitted attacknet-probe container is not Ready');
        }
        const response = await this.probes.probe(target, {kind: 'system'});
        const observation = response.observation;
        if (observation?.probe !== 'system' || observation?.status !== 'ok'
            || typeof observation.platform !== 'string'
            || typeof observation.architecture !== 'string') {
          throw new Error('system capability observation is malformed');
        }
        const supported = observation.platform === 'linux'
          && architectures.has(observation.architecture);
        return {
          ...base, observedAt: response.observedAt ?? base.observedAt,
          platform: observation.platform, architecture: observation.architecture,
          supported,
          reason: supported
            ? `${kind} platform profile admits ${observation.platform}/${observation.architecture}`
            : `${kind} platform profile supports ${[...architectures].sort().join(',')}; target reports ${observation.platform}/${observation.architecture}`,
        };
      } catch (error) {
        return {
          ...base, platform: 'unknown', architecture: 'unknown', supported: false,
          reason: `${kind} capability could not be established: ${String(error.message ?? error).slice(0, 512)}`,
        };
      }
    }));
  }

  async collectProbePhase(campaign, compiled, network, pods, phase, allInjectedObserved = false) {
    const identity = chaosIdentity(campaign);
    const selectedActors = compiled.evidence.selectedActors;
    const responses = await Promise.all((campaign.status?.resolvedTargets ?? []).map(async target => {
      try {
        if (!probeTargetReady(target, pods)) {
          throw new Error('exact admitted attacknet-probe container is not Ready at its recorded Pod IP');
        }
        const request = buildProbeRequest({
          kind: identity.kind, campaign, compiledEvidence: compiled.evidence, network, target,
        });
        return await this.probes.probe(target, request);
      } catch (error) {
        return {actor: target.actor, error: String(error.message ?? error)};
      }
    }));
    if (identity.kind === 'TimeChaos' || identity.kind === 'ClockSkewPolicy') {
      try {
        const control = controlTarget(network, pods, selectedActors);
        responses.push(await this.probes.probe(control, {
          kind: 'processClock', peer: control.actor, port: 'metrics',
          metric: PROCESS_WALL_CLOCK_METRIC, control: true,
        }));
      } catch (error) {
        responses.push({actor: 'independent-control', error: String(error.message ?? error)});
      }
    }
    return probePhase({kind: identity.kind, phase, responses, allInjectedObserved});
  }

  async deletion(campaign) {
    if (!(campaign.metadata.finalizers ?? []).includes(FINALIZER)) return;
    const cleanup = await this.removeChaos(campaign);
    if (!cleanup.absent) return;
    await this.releaseMutationLease(campaign);
    await this.patchFinalizers(campaign, (campaign.metadata.finalizers ?? []).filter(item => item !== FINALIZER));
  }

  async reconcile(campaign, serialized = true) {
    if (campaign.metadata.deletionTimestamp) return this.deletion(campaign);
    if (campaign.spec?.template === true) {
      if (campaign.status?.phase !== 'Pending' || campaign.status?.reason !== 'TemplateReady') {
        await this.patchStatus(campaign, status(campaign.status, 'Pending', 'TemplateReady', {
          templateDigest: artifactDigest(campaign.spec),
        }));
      }
      return;
    }
    if (!(campaign.metadata.finalizers ?? []).includes(FINALIZER)) {
      await this.patchFinalizers(campaign, [...(campaign.metadata.finalizers ?? []), FINALIZER]);
      return;
    }
    if (TERMINAL_PHASES.has(campaign.status?.phase)) {
      if (chaosIdentity(campaign).kind === 'ClockSkewPolicy'
          && campaign.status?.chaos?.uid
          && !(campaign.status?.recoveryResults ?? []).some(result =>
            result.assertion === 'ClockSkewCleared' && result.outcome === 'Proven')) {
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'WaitingForClockRecoveryEvidence', {
          cleanup: {...cleanup, observedAt: now()}, completedAt: null,
        }));
        return;
      }
      const cleanup = await this.removeChaos(campaign);
      if (!cleanup.absent) return;
      if (campaign.status?.cleanup?.absent !== true) {
        await this.patchStatus(campaign, {
          ...campaign.status,
          cleanup: {
            absent: true,
            allRecovered: campaign.status?.cleanup?.allRecovered ?? cleanup.allRecovered,
            method: cleanup.method ?? campaign.status?.cleanup?.method ?? 'Normal',
            zeroInjectionProven: cleanup.method === 'ZeroInjectionFinalizerAbort'
              || campaign.status?.cleanup?.zeroInjectionProven === true,
            observedAt: now(),
          },
        });
      }
      await this.releaseMutationLease(campaign);
      return;
    }
    if (!serialized && (!campaign.status?.phase || campaign.status.phase === 'Pending')) {
      if (campaign.status?.reason !== 'SerializedBehindActiveFault') {
        await this.patchStatus(campaign, status(campaign.status, 'Pending', 'SerializedBehindActiveFault'));
      }
      return;
    }

    const network = await this.api.get('stacksnetworks', campaign.spec.networkRef);
    const phase = campaign.status?.phase ?? 'Pending';
    // A fault is expected to make its target, and therefore possibly the
    // aggregate StacksNetwork, temporarily non-Ready. Readiness gates admission
    // only; regressing an admitted execution to Pending loses the state needed
    // to observe and clean up that very fault.
    if (phase === 'Pending' && network.status?.phase !== 'Ready') {
      await this.patchStatus(campaign, status(campaign.status, 'Pending', 'NetworkNotReady'));
      return;
    }
    const declaredManifest = networkManifest(network);
    let manifest = declaredManifest;
    let pods = null;
    let signerSet = null;
    if (phase === 'Pending') {
      pods = await this.api.list('pods', {
        group: '', labels: `testing.stacks.org/network=${declaredManifest.network}`,
      });
      try {
        signerSet = await this.signerSets.resolve(network, pods, declaredManifest);
        manifest = signerSet.manifest;
      } catch (error) {
        if (transientError(error)) throw error;
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'SignerSetAdmissionFailed', {
          message: String(error.message ?? error).slice(0, 1000), completedAt: now(),
        }));
        return;
      }
    }
    const compiled = compileCampaign(campaignDocument(campaign), manifest);
    const compiledDigest = artifactDigest(compiled.resource);
    const ownsMutationLease = await this.holdMutationLease(
      campaign, manifest.network, phase === 'Pending',
    );
    if (!ownsMutationLease) {
      if (phase !== 'Pending') {
        throw new Error(`FaultCampaign ${campaign.metadata.name} lost its mutation lease`);
      }
      if (campaign.status?.reason !== 'WaitingForMutationLease') {
        await this.patchStatus(campaign, status(campaign.status, 'Pending', 'WaitingForMutationLease'));
      }
      return;
    }

    if (phase === 'Pending') {
      const resolved = resolveCampaignTargets(manifest, compiled.evidence, pods);
      const capabilityEvidence = await this.faultCapabilityEvidence(campaign, pods, resolved.targets);
      const unavailable = capabilityEvidence.filter(item => !item.supported);
      if (unavailable.length > 0) {
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'FaultCapabilityUnavailable', {
          resolvedTargets: resolved.targets,
          capabilityEvidence,
          message: unavailable.map(item => `${item.actor}: ${item.reason}`).join('; ').slice(0, 1000),
          completedAt: now(),
        }));
        return;
      }
      let probeArtifacts = campaign.status?.probeArtifacts ?? {};
      if (chaosIdentity(campaign).kind !== 'PodChaos') {
        // The admitted identities must be present on status before the probe
        // plan can bind observations to exact Pod UIDs. Use a local view for
        // this pre-admission baseline; no Chaos resource exists yet.
        const baselineCampaign = {...campaign, status: {...campaign.status, resolvedTargets: resolved.targets}};
        const before = await this.collectProbePhase(baselineCampaign, compiled, network, pods, 'before');
        if (!baselineUsable(chaosIdentity(campaign).kind, before, compiled.evidence.selectedActors)) {
          await this.patchStatus(campaign, status(campaign.status, 'Failed', 'ProbeBaselineUnavailable', {
            resolvedTargets: resolved.targets,
            probeArtifacts: {beforeJson: JSON.stringify(before)}, completedAt: now(),
          }));
          return;
        }
        probeArtifacts = {beforeJson: JSON.stringify(before)};
      }
      await this.patchStatus(campaign, status(campaign.status, 'Admitted', 'SafetyPolicySatisfied', {
        admission: {
          networkUid: network.metadata.uid, networkGeneration: network.metadata.generation,
          compiledDigest, admittedAt: now(), signerImpact: compiled.evidence.signerImpact,
          minerImpact: compiled.evidence.minerImpact,
          signerSetRewardCycle: signerSet.rewardCycle,
          signerSetTotalWeight: signerSet.observedTotalWeight,
          signerSetDigest: signerSet.signerSetDigest,
          signerSetObservedFrom: signerSet.observedFrom,
        },
        resolvedTargets: resolved.targets,
        capabilityEvidence,
        probeArtifacts,
      }));
      return;
    }

    if (campaign.status?.admission?.networkUid !== network.metadata.uid
        || campaign.status?.admission?.networkGeneration !== network.metadata.generation
        || campaign.status?.admission?.compiledDigest !== compiledDigest) {
      await this.patchStatus(campaign, status(campaign.status, 'Failed', 'AdmissionInputChanged'));
      await this.removeChaos(campaign);
      return;
    }

    if (phase === 'Admitted') {
      const currentPods = await this.api.list('pods', {
        group: '', labels: `testing.stacks.org/network=${declaredManifest.network}`,
      });
      let currentSignerSet;
      try {
        currentSignerSet = await this.signerSets.resolve(network, currentPods, declaredManifest);
      } catch (error) {
        if (transientError(error)) throw error;
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'SignerSetChangedBeforeInjection', {
          message: String(error.message ?? error).slice(0, 1000), completedAt: now(),
        }));
        await this.removeChaos(campaign);
        return;
      }
      if (currentSignerSet.signerSetDigest !== campaign.status?.admission?.signerSetDigest) {
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'SignerSetChangedBeforeInjection', {
          message: `canonical signer set changed from ${campaign.status?.admission?.signerSetDigest ?? 'unknown'} to ${currentSignerSet.signerSetDigest}`,
          completedAt: now(),
        }));
        await this.removeChaos(campaign);
        return;
      }
    }

    const identity = chaosIdentity(campaign);
    if (phase === 'Admitted') {
      if (identity.kind === 'ClockSkewPolicy') {
        const policy = await this.api.get(identity.plural, identity.name,
          identityOptions(identity, true));
        if (!policy || !clockPolicyMatches(policy, campaign, CLOCK_POLICY_ZERO)) {
          await this.patchStatus(campaign, status(campaign.status, 'Failed', 'ClockPolicyUnavailable', {
            message: 'application clock policy disappeared, changed identity, or was non-zero before injection',
            completedAt: now(),
          }));
          return;
        }
        const offset = `${campaign.spec.fault.parameters.timeOffset}\n`;
        const values = Object.fromEntries(
          campaign.status.resolvedTargets.map(target => [target.actor, offset]),
        );
        const contractDigest = artifactDigest(clockPolicyContract(campaign, policy));
        await this.api.patch(identity.plural, identity.name, {
          metadata: {resourceVersion: policy.metadata.resourceVersion}, data: values,
        }, identityOptions(identity));
        const admitted = await this.api.get(identity.plural, identity.name, identityOptions(identity));
        if (!clockPolicyMatches(admitted, campaign, offset)) {
          throw new Error('application clock policy mutation was not durably admitted');
        }
        await this.patchStatus(campaign, status(campaign.status, 'Injecting', 'ClockPolicyApplied', {
          chaos: {
            kind: identity.kind, name: identity.name, uid: admitted.metadata.uid, createdAt: now(),
            mechanism: CLOCK_POLICY_MECHANISM, resourceDigest: contractDigest,
          },
        }));
        return;
      }
      const existing = await this.api.get(identity.plural, identity.name,
        identityOptions(identity, true));
      if (existing && existing.metadata?.ownerReferences?.[0]?.uid !== campaign.metadata.uid) {
        throw new Error(`refusing to adopt ${identity.plural}/${identity.name}`);
      }
      let desired = compiled.resource;
      if (identity.kind === 'IOPressurePod') {
        const currentPods = await this.api.list('pods', {
          group: '', labels: `testing.stacks.org/network=${manifest.network}`,
        });
        desired = buildIoPressurePod(campaign, compiled, currentPods, this.ioPressure);
      } else {
        desired.metadata.ownerReferences = ownerReference(campaign);
      }
      if (existing && identity.kind === 'IOPressurePod'
          && digest(ioPressurePodContract(existing)) !== digest(ioPressurePodContract(desired))) {
        throw new Error(`refusing to adopt ${identity.plural}/${identity.name} with a different trusted execution contract`);
      }
      const created = existing ?? await this.api.create(identity.plural, desired,
        identityOptions(identity));
      const pressureDigest = identity.kind === 'IOPressurePod'
        ? artifactDigest(ioPressurePodContract(created)) : null;
      if (identity.kind === 'IOPressurePod'
          && pressureDigest !== artifactDigest(ioPressurePodContract(desired))) {
        if (!existing && created.metadata?.ownerReferences?.[0]?.uid === campaign.metadata.uid) {
          await this.api.delete(identity.plural, identity.name, identityOptions(identity));
        }
        throw new Error('admission mutated the trusted I/O-pressure Pod execution contract');
      }
      await this.patchStatus(campaign, status(campaign.status, 'Injecting',
        identity.kind === 'IOPressurePod' ? 'PressurePodCreated' : 'ChaosResourceCreated', {
        chaos: {
          kind: identity.kind, name: identity.name, uid: created.metadata.uid, createdAt: now(),
          ...(identity.kind === 'IOPressurePod' ? {
            mechanism: IO_PRESSURE_MECHANISM,
            resourceDigest: pressureDigest,
          } : {}),
        },
      }));
      return;
    }

    const chaos = await this.api.get(identity.plural, identity.name,
      identityOptions(identity, true));
    if (phase === 'Injecting') {
      if (!chaos) throw new Error('Chaos resource disappeared before injection was observed');
      if (identity.kind === 'ClockSkewPolicy') {
        const offset = `${campaign.spec.fault.parameters.timeOffset}\n`;
        if (chaos.metadata?.uid !== campaign.status?.chaos?.uid
            || artifactDigest(clockPolicyContract(campaign, chaos)) !== campaign.status?.chaos?.resourceDigest
            || !clockPolicyMatches(chaos, campaign, offset)) {
          throw new Error('admitted application clock policy identity or values changed');
        }
        const pods = await this.api.list('pods', {
          group: '', labels: `testing.stacks.org/network=${manifest.network}`,
        });
        const during = await this.collectProbePhase(campaign, compiled, network, pods, 'during', true);
        const probeArtifacts = {...(campaign.status?.probeArtifacts ?? {}), duringJson: JSON.stringify(during)};
        let evaluation;
        try {
          const before = JSON.parse(probeArtifacts.beforeJson);
          const placeholderAfter = {
            ...before, phase: 'after', capturedAt: now(),
            injection: {
              allInjectedObserved: false,
              source: {
                trust: 'orchestrator-observed', authority: 'controller-clock-policy',
                collector: 'attacknet-run-operator/v1',
              },
            },
          };
          evaluation = evaluateFaultEffect({
            campaign: compiled.resource, evidence: compiled.evidence,
            resolvedTargets: {
              schemaVersion: 1, network: manifest.network, namespace: manifest.namespace,
              resolvedAt: campaign.status.admission.admittedAt,
              targets: campaign.status.resolvedTargets,
            },
            before, during,
            // Recovery is not classified in this phase. Supplying the clean
            // baseline as a placeholder lets the shared evaluator classify
            // only the requested before/during effect without trusting the
            // policy mutation itself as evidence.
            after: placeholderAfter,
          });
        } catch (error) {
          if (elapsedSeconds(campaign.status?.chaos?.createdAt)
              <= assertionTimeout(campaign.spec.effectAssertions, 90)) {
            await this.patchStatus(campaign, status(campaign.status, 'Injecting', 'WaitingForEffectEvidence', {
              probeArtifacts, message: String(error.message ?? error).slice(0, 1000),
            }));
            return;
          }
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'ClockPolicyResetAfterInvalidEvidence', {
            probeArtifacts, message: String(error.message ?? error).slice(0, 1000),
            cleanup: {...cleanup, observedAt: now()},
          }));
          return;
        }
        if (evaluation.effect.verdict === 'Proven') {
          await this.patchStatus(campaign, status(campaign.status, 'Active', 'ClockSkewObserved', {
            injectedAt: campaign.status?.injectedAt ?? now(),
            actualInjection: {
              mechanism: CLOCK_POLICY_MECHANISM, allInjectedObserved: true,
              configMapUid: chaos.metadata.uid, policyName: identity.name,
              requestedOffset: campaign.spec.fault.parameters.timeOffset, observedAt: now(),
            },
            probeArtifacts,
          }));
          return;
        }
        if (elapsedSeconds(campaign.status?.chaos?.createdAt)
            <= assertionTimeout(campaign.spec.effectAssertions, 90)) {
          await this.patchStatus(campaign, status(campaign.status, 'Injecting', 'WaitingForEffectEvidence', {
            actualInjection: {
              mechanism: CLOCK_POLICY_MECHANISM, allInjectedObserved: false,
              configMapUid: chaos.metadata.uid, policyName: identity.name,
              requestedOffset: campaign.spec.fault.parameters.timeOffset, observedAt: now(),
            },
            probeArtifacts,
          }));
          return;
        }
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'ClockPolicyResetAfterUnprovenEffect', {
          probeArtifacts, cleanup: {...cleanup, observedAt: now()},
        }));
        return;
      }
      if (identity.kind === 'IOPressurePod') {
        if (chaos.metadata?.uid !== campaign.status?.chaos?.uid
            || chaos.metadata?.ownerReferences?.[0]?.uid !== campaign.metadata.uid
            || artifactDigest(ioPressurePodContract(chaos)) !== campaign.status?.chaos?.resourceDigest) {
          throw new Error(`admitted ${identity.kind} identity or ownership changed`);
        }
        if (ioPressurePodRunning(chaos)) {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          const during = await this.collectProbePhase(campaign, compiled, network, pods, 'during', true);
          await this.patchStatus(campaign, status(campaign.status, 'Active', 'PressurePodRunning', {
            injectedAt: campaign.status?.injectedAt ?? now(),
            actualInjection: ioPressureActualInjection(chaos, campaign.status.resolvedTargets[0]),
            effectResults: campaign.status?.effectResults ?? [],
            probeArtifacts: {...(campaign.status?.probeArtifacts ?? {}), duringJson: JSON.stringify(during)},
          }));
          return;
        }
        if (['Succeeded', 'Failed'].includes(chaos.status?.phase)) {
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Failed',
            chaos.status.phase === 'Succeeded' ? 'InjectionNotObserved' : 'InjectionFailed', {
              actualInjection: {
                mechanism: IO_PRESSURE_MECHANISM, allInjectedObserved: false,
                podUid: chaos.metadata.uid, node: chaos.spec?.nodeName,
                phase: chaos.status.phase, observedAt: now(),
              },
              message: chaos.status.phase === 'Succeeded'
                ? 'I/O-pressure Pod completed before a Running process was observed'
                : 'I/O-pressure Pod failed before a Running process was observed',
              cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
            }));
          return;
        }
        if (elapsedSeconds(campaign.status?.chaos?.createdAt)
            > assertionTimeout(campaign.spec.effectAssertions, 90)) {
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Failed', 'InjectionTimeout', {
            actualInjection: {
              mechanism: IO_PRESSURE_MECHANISM, allInjectedObserved: false,
              podUid: chaos.metadata.uid, node: chaos.spec?.nodeName,
              phase: chaos.status?.phase ?? 'Unknown', observedAt: now(),
            },
            message: 'I/O-pressure Pod did not reach Running before the effect deadline',
            cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
          }));
        }
        return;
      }
      const allInjected = conditionTrue(chaos, 'AllInjected');
      const injectionObserved = allInjected
        || campaign.status?.actualInjection?.allInjectedObserved === true;
      if (injectionObserved) {
        let effectResults = campaign.status?.effectResults ?? [];
        let probeArtifacts = campaign.status?.probeArtifacts ?? {};
        const injectedAt = campaign.status?.injectedAt ?? now();
        const actualInjection = actualInjectionEvidence(chaos, true);
        if (identity.kind === 'PodChaos') {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          effectResults = podEffectResults(campaign, pods);
          const minimum = minimumAffected(compiled.resource.spec, campaign.status.resolvedTargets.length);
          if (effectResults.filter(item => item.outcome === 'Proven').length < minimum) {
            // Chaos Mesh can publish AllInjected before kubelet has propagated
            // the corresponding Pod readiness/restart observation. Keep the
            // execution in Injecting and retry the trusted Pod observation;
            // one early sample must never become the campaign's permanent
            // verdict.
            if (!conditionTrue(chaos, 'AllRecovered')
                && elapsedSeconds(injectedAt) <= assertionTimeout(campaign.spec.effectAssertions, 90)) {
              await this.patchStatus(campaign, status(campaign.status, 'Injecting', 'WaitingForEffectEvidence', {
                injectedAt, actualInjection,
                effectResults,
              }));
              return;
            }
          }
          // PodKill and ContainerKill are one-shot actions. Chaos Mesh records
          // their application, but there is no process state it can restore;
          // in particular PodKill can remain AllRecovered=False indefinitely.
          // Once Kubernetes proves the immutable admitted Pod disappeared or
          // the admitted container restarted, remove the bookkeeping resource
          // and independently require the replacement target to become Ready.
          if (['pod-kill', 'container-kill'].includes(compiled.resource.spec.action)
              && effectResults.filter(item => item.outcome === 'Proven').length >= minimum) {
            const cleanup = await this.removeChaos(campaign);
            await this.patchStatus(campaign, status(campaign.status, 'Recovering',
              'OneShotEffectObserved', {
                injectedAt, actualInjection, effectResults, probeArtifacts,
                cleanup: {...cleanup, observedAt: now()},
              }));
            return;
          }
        } else if (!conditionTrue(chaos, 'AllRecovered')) {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          const during = await this.collectProbePhase(campaign, compiled, network, pods, 'during', true);
          probeArtifacts = {...probeArtifacts, duringJson: JSON.stringify(during)};
        }
        if (conditionTrue(chaos, 'AllRecovered')) {
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'AllRecoveredObserved', {
            injectedAt, actualInjection, effectResults, probeArtifacts,
            cleanup: {...cleanup, observedAt: now()},
          }));
          return;
        }
        await this.patchStatus(campaign, status(campaign.status, 'Active', 'AllInjectedObserved', {
          injectedAt, actualInjection,
          effectResults,
          probeArtifacts,
        }));
      } else if (conditionTrue(chaos, 'AllRecovered')) {
        // A partially-applied fault can enter AllRecovered without ever
        // satisfying AllInjected (for example, one selected container rejects
        // injection). Waiting for the assertion timeout hides the actionable
        // daemon error and needlessly holds serialization. Preserve the exact
        // records and fail immediately; this is an apparatus failure, not
        // evidence that the requested data-plane effect occurred.
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'InjectionFailed', {
          actualInjection: actualInjectionEvidence(chaos, false),
          message: injectionFailureMessage(chaos),
          cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
        }));
      } else if (elapsedSeconds(campaign.status?.chaos?.createdAt) > assertionTimeout(campaign.spec.effectAssertions, 90)) {
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'InjectionTimeout', {
          actualInjection: actualInjectionEvidence(chaos, false),
          message: injectionFailureMessage(chaos),
          cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
        }));
      }
      return;
    }

    if (phase === 'Active') {
      if (!chaos) throw new Error('Chaos resource disappeared without recovery evidence');
      if (identity.kind === 'ClockSkewPolicy') {
        if (elapsedSeconds(campaign.status.injectedAt)
            < durationSeconds(compiled.resource.spec.duration)) return;
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'ClockPolicyReset', {
          cleanup: {...cleanup, observedAt: now()},
        }));
        return;
      }
      if (identity.kind === 'IOPressurePod') {
        if (ioPressurePodRunning(chaos)) {
          const deadline = durationSeconds(compiled.resource.spec.duration)
            + assertionTimeout(campaign.spec.recoveryAssertions, 300);
          if (elapsedSeconds(campaign.status.injectedAt) <= deadline) {
            const pods = await this.api.list('pods', {
              group: '', labels: `testing.stacks.org/network=${manifest.network}`,
            });
            const candidate = await this.collectProbePhase(
              campaign, compiled, network, pods, 'during', true,
            );
            const actor = campaign.status.resolvedTargets[0].actor;
            const strongest = strongestIoPressurePhase(
              campaign.status?.probeArtifacts?.duringJson, candidate, actor,
            );
            await this.patchStatus(campaign, status(campaign.status, 'Active',
              'SamplingEffectEvidence', {
                probeArtifacts: {
                  ...(campaign.status?.probeArtifacts ?? {}),
                  duringJson: JSON.stringify(strongest),
                },
              }));
            return;
          }
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Failed', 'RecoveryTimeout', {
            message: 'I/O-pressure Pod remained Running beyond its bounded duration and recovery deadline',
            cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
          }));
          return;
        }
        if (chaos.status?.phase === 'Succeeded') {
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'PressurePodCompleted', {
            cleanup: {...cleanup, observedAt: now()},
          }));
          return;
        }
        if (chaos.status?.phase === 'Failed') {
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Failed', 'PressurePodFailed', {
            message: 'controller-owned I/O-pressure Pod terminated unsuccessfully',
            cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
          }));
          return;
        }
        return;
      }
      if (identity.kind === 'PodChaos'
          && ['pod-kill', 'container-kill'].includes(compiled.resource.spec.action)) {
        const minimum = minimumAffected(compiled.resource.spec, campaign.status.resolvedTargets.length);
        const proven = (campaign.status?.effectResults ?? [])
          .filter(item => item.outcome === 'Proven').length;
        if (proven >= minimum) {
          // Re-enter the one-shot cleanup path after a controller restart or
          // rollout. The durable effect evidence, not the transient prior
          // phase, is the authority for this transition.
          const cleanup = await this.removeChaos(campaign);
          await this.patchStatus(campaign, status(campaign.status, 'Recovering',
            'OneShotEffectObserved', {
              cleanup: {...cleanup, observedAt: now()},
            }));
          return;
        }
      }
      if (!conditionTrue(chaos, 'AllRecovered')) {
        const deadline = durationSeconds(compiled.resource.spec.duration)
          + assertionTimeout(campaign.spec.recoveryAssertions, 300);
        if (elapsedSeconds(campaign.status.injectedAt) <= deadline) return;
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'RecoveryTimeout', {
          cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
        }));
        return;
      }
      const cleanup = await this.removeChaos(campaign);
      await this.patchStatus(campaign, status(campaign.status, 'Recovering', 'AllRecoveredObserved', {
        cleanup: {...cleanup, observedAt: now()},
      }));
      return;
    }

    if (phase === 'Recovering') {
      const remaining = identity.kind === 'ClockSkewPolicy' ? null
        : await this.api.get(identity.plural, identity.name, identityOptions(identity, true));
      if (remaining) return;
      // The absence check above is the authoritative cleanup barrier. Carry it
      // into the same status update that may become terminal; otherwise a
      // truthful but stale cleanup.absent=false can briefly coexist with
      // phase=Passed until the next reconcile.
      const completedCleanup = {
        ...(campaign.status?.cleanup ?? {}), absent: true, observedAt: now(),
      };
      const pods = await this.api.list('pods', {group: '', labels: `testing.stacks.org/network=${manifest.network}`});
      let recovered;
      try {
        recovered = resolveCampaignTargets(manifest, compiled.evidence, pods);
      } catch (error) {
        if (elapsedSeconds(campaign.status?.cleanup?.observedAt)
            <= assertionTimeout(campaign.spec.recoveryAssertions, 300)) return;
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'TargetRecoveryTimeout', {
          message: String(error.message ?? error).slice(0, 1000), cleanup: completedCleanup,
          completedAt: now(),
        }));
        return;
      }
      let probeArtifacts = campaign.status?.probeArtifacts ?? {};
      let effectResults = campaign.status?.effectResults ?? [];
      let recoveryResults = recovered.targets.map(target => ({
        assertion: 'TargetReady', outcome: 'Proven', actor: target.actor,
        podUid: target.podUid, observedAt: now(),
      }));
      let evidenceError = null;
      if (identity.kind !== 'PodChaos') {
        const after = await this.collectProbePhase(campaign, compiled, network, pods, 'after');
        probeArtifacts = {...probeArtifacts, afterJson: JSON.stringify(after)};
        try {
          const evaluation = evaluateFaultEffect({
            campaign: compiled.resource, evidence: compiled.evidence,
            resolvedTargets: {
              schemaVersion: 1, network: manifest.network, namespace: manifest.namespace,
              resolvedAt: campaign.status.admission.admittedAt,
              targets: campaign.status.resolvedTargets,
            },
            before: JSON.parse(probeArtifacts.beforeJson),
            during: JSON.parse(probeArtifacts.duringJson), after,
          });
          const assertion = {
            NetworkChaos: 'NetworkDegraded', DNSChaos: 'DNSDegraded',
            IOChaos: 'IODegraded', IOPressurePod: 'IOPressureObserved',
            TimeChaos: 'ClockSkewObserved', ClockSkewPolicy: 'ClockSkewObserved',
          }[identity.kind];
          const recoveryAssertion = {
            NetworkChaos: 'NetworkRecovered', DNSChaos: 'DNSRecovered',
            IOChaos: 'IORecovered', IOPressurePod: 'IOPressureRecovered',
            TimeChaos: 'ClockSkewCleared', ClockSkewPolicy: 'ClockSkewCleared',
          }[identity.kind];
          const title = value => value[0].toUpperCase() + value.slice(1);
          effectResults = evaluation.evaluations.map(item => ({
            assertion, outcome: title(item.effect), actor: item.actor,
            podUid: campaign.status.resolvedTargets.find(target => target.actor === item.actor)?.podUid,
            observedAt: now(), message: item.reason,
          }));
          recoveryResults = evaluation.evaluations.map(item => ({
            assertion: recoveryAssertion, outcome: title(item.recovery), actor: item.actor,
            podUid: campaign.status.resolvedTargets.find(target => target.actor === item.actor)?.podUid,
            observedAt: now(),
            message: item.recoveryReason
              ?? `trusted after-fault probe classified recovery=${item.recovery}`,
          }));
        } catch (error) {
          evidenceError = String(error.message ?? error).slice(0, 1000);
          effectResults = campaign.status.resolvedTargets.map(target => ({
            assertion: 'RequestedFaultEffect', outcome: 'Inconclusive', actor: target.actor,
            podUid: target.podUid, observedAt: now(), message: evidenceError,
          }));
          recoveryResults = campaign.status.resolvedTargets.map(target => ({
            assertion: 'TargetReady', outcome: 'Inconclusive', actor: target.actor,
            podUid: target.podUid, observedAt: now(), message: evidenceError,
          }));
        }
      }
      const required = campaign.spec.effectAssertions ?? [];
      const requiredRecovery = campaign.spec.recoveryAssertions ?? [];
      // User-supplied assertions may add requirements, but omitting them must
      // never turn Chaos Mesh's AllInjected bookkeeping into proof that the
      // requested fault was observable. At least one trusted effect result is
      // required for every execution.
      const minimum = minimumAffected(compiled.resource.spec, campaign.status.resolvedTargets.length);
      const provenResults = effectResults.filter(item => item.outcome === 'Proven');
      const recoveredResults = recoveryResults.filter(item => item.outcome === 'Proven');
      const effectProven = evidenceError === null && provenResults.length >= minimum
        && (required.length === 0 || required.every(assertion =>
          provenResults.some(result => result.assertion === assertion.type
            && (assertion.actor === undefined || result.actor === assertion.actor))));
      const recoveryProven = evidenceError === null && recoveredResults.length >= minimum
        && (requiredRecovery.length === 0 || requiredRecovery.every(assertion =>
          recoveredResults.some(result => result.assertion === assertion.type
            && (assertion.actor === undefined || result.actor === assertion.actor))));
      const proven = effectProven && recoveryProven;
      if ((effectProven || identity.kind === 'ClockSkewPolicy') && !recoveryProven
          && elapsedSeconds(campaign.status?.cleanup?.observedAt)
            <= assertionTimeout(campaign.spec.recoveryAssertions, 300)) {
        // Recovery is a bounded observation window, not a single sample. A
        // just-completed pressure process can leave the backing filesystem's
        // latency elevated for a short interval even though the injected Pod
        // is gone. Preserve the failed sample and poll again until the stated
        // recovery timeout instead of misclassifying one noisy observation as
        // a terminal result.
        await this.patchStatus(campaign, status(campaign.status,
          'Recovering', 'WaitingForRecoveryEvidence', {
            effectResults, recoveryResults, probeArtifacts, cleanup: completedCleanup,
            ...(evidenceError ? {message: evidenceError} : {}),
          }));
        return;
      }
      await this.patchStatus(campaign, status(campaign.status,
        proven ? 'Passed' : 'Inconclusive',
        proven ? 'EffectAndRecoveryProven'
          : evidenceError ? 'ProbeEvidenceInvalid'
            : effectProven ? 'RecoveryNotProven' : 'EffectNotProven', {
          effectResults, recoveryResults, probeArtifacts, cleanup: completedCleanup,
          ...(evidenceError ? {message: evidenceError} : {}),
          completedAt: now(),
        }));
    }
  }
}

function runOwner(run) { return ownerReference(run); }

export class AttacknetRunReconciler {
  constructor(api, signerSets = new SignerSetClient()) {
    this.api = api;
    this.signerSets = signerSets;
  }
  terminalFields(run, children) {
    const classification = classifyTerminalAssertion(run, children, run.status?.scheduleRef?.digest);
    return classification ? {terminalClassification: classification} : {};
  }
  async patchStatus(run, next) {
    next.observedGeneration = run.metadata.generation;
    await this.api.patch('attacknetruns', run.metadata.name,
      {metadata: {resourceVersion: run.metadata.resourceVersion}, status: next}, {subresource: 'status'});
  }

  async readSchedule(reference, expectedOwnerUid) {
    const configMap = await this.api.get('configmaps', reference.name, {group: ''});
    const owner = configMap.metadata?.ownerReferences?.find(item => item.controller === true);
    if (!owner || owner.uid !== expectedOwnerUid || configMap.metadata.uid !== reference.uid) {
      throw new Error('resolved schedule ConfigMap ownership or UID changed');
    }
    const schedule = decodeSchedule(configMap);
    if (schedule.integrity.digest !== reference.digest) throw new Error('resolved schedule reference digest changed');
    return schedule;
  }

  async persistSchedule(run, schedule) {
    const name = stableName(run.metadata.name, 'resolved-schedule');
    const payload = encodeSchedule(schedule);
    if (Buffer.byteLength(payload) > 900_000) throw new Error('compressed resolved schedule exceeds 900 KiB');
    let configMap = await this.api.get('configmaps', name, {group: '', allow404: true});
    if (!configMap) {
      configMap = await this.api.create('configmaps', {
        apiVersion: 'v1', kind: 'ConfigMap',
        metadata: {
          name, namespace: run.metadata.namespace, ownerReferences: runOwner(run),
          labels: {
            'testing.stacks.org/network': run.spec.networkRef,
            'testing.stacks.org/run': run.metadata.name,
            'testing.stacks.org/artifact': 'resolved-schedule',
          },
          annotations: {
            'testing.stacks.org/schedule-format': SCHEDULE_FORMAT,
            'testing.stacks.org/schedule-digest': schedule.integrity.digest,
            'testing.stacks.org/run-generation': String(run.metadata.generation),
            'testing.stacks.org/run-spec-digest': artifactDigest(run.spec),
          },
        },
        binaryData: {'schedule.json.gz': payload},
      }, {group: ''});
    }
    const owner = configMap.metadata?.ownerReferences?.find(item => item.controller === true);
    if (!owner || owner.uid !== run.metadata.uid) throw new Error(`refusing to adopt ConfigMap ${name}`);
    if (configMap.metadata.annotations?.['testing.stacks.org/run-generation'] !== String(run.metadata.generation)
        || configMap.metadata.annotations?.['testing.stacks.org/run-spec-digest'] !== artifactDigest(run.spec)) {
      throw new Error('an immutable resolved schedule already exists for a different run generation or spec');
    }
    const persisted = decodeSchedule(configMap);
    if (persisted.integrity.digest !== schedule.integrity.digest) {
      throw new Error('an immutable resolved schedule already exists with different contents');
    }
    return {
      name, uid: configMap.metadata.uid, digest: persisted.integrity.digest,
      runGeneration: run.metadata.generation, runSpecDigest: artifactDigest(run.spec),
    };
  }

  async prepareSchedule(run, network) {
    const declaredManifest = networkManifest(network);
    const pods = await this.api.list('pods', {
      group: '', labels: `testing.stacks.org/network=${declaredManifest.network}`,
    });
    const signerSet = await this.signerSets.resolve(network, pods, declaredManifest);
    const manifest = signerSet.manifest;
    const images = resolvedNetworkImages(network, pods);
    const sources = await Promise.all((run.spec.campaignCatalog ?? []).map(entry =>
      this.api.get('faultcampaigns', entry.campaignRef)));
    for (const source of sources) {
      if (source.spec?.template !== true) throw new Error(`catalog source ${source.metadata.name} is not a template`);
      if (source.spec.networkRef !== run.spec.networkRef) {
        throw new Error(`catalog source ${source.metadata.name} targets another network`);
      }
    }
    const context = {
      network: {uid: network.metadata.uid, generation: network.metadata.generation},
      manifest, images, campaigns: sources,
    };
    let schedule;
    if (run.spec.minimization?.enabled === true) {
      const minimization = run.spec.minimization;
      const sourceRun = await this.api.get('attacknetruns', minimization.sourceRunRef);
      if (!TERMINAL_PHASES.has(sourceRun.status?.phase)) {
        throw new Error('ddmin source run must be terminal before deriving a counterfactual');
      }
      if (!sourceRun.status?.scheduleRef) throw new Error('ddmin source run has no persisted resolved schedule');
      const sourceSchedule = await this.readSchedule(sourceRun.status.scheduleRef, sourceRun.metadata.uid);
      if (sourceSchedule.integrity.digest !== minimization.sourceScheduleDigest) {
        throw new Error('ddmin sourceScheduleDigest does not match the terminal source run');
      }
      if (network.metadata.uid === sourceSchedule.network.uid) {
        throw new Error('ddmin counterfactual requires a fresh network UID');
      }
      if (artifactDigest(run.spec.budgets) !== artifactDigest(sourceSchedule.budgets.limits)) {
        throw new Error('ddmin counterfactual budgets must equal the immutable source budgets');
      }
      schedule = consumeDdminCandidate({
        sourceScheduleDigest: minimization.sourceScheduleDigest,
        candidateScheduleDigest: minimization.candidateScheduleDigest,
        retained: minimization.retained,
      }, sourceSchedule, context);
      schedule.replay.attemptId = minimization.attemptId;
      const unsigned = structuredClone(schedule);
      delete unsigned.integrity;
      schedule.integrity = {algorithm: 'sha256', digest: artifactDigest(unsigned)};
      validateResolvedSchedule(schedule);
    } else if (run.spec.replay?.enabled === true) {
      const sourceRun = await this.api.get('attacknetruns', run.spec.replay.sourceRunRef);
      if (!TERMINAL_PHASES.has(sourceRun.status?.phase)) {
        throw new Error('source replay run must be terminal before its schedule can be replayed');
      }
      if (!sourceRun.status?.scheduleRef) throw new Error('source replay run has no persisted resolved schedule');
      const expectedUri = `k8s://attacknetruns/${sourceRun.metadata.name}/resolved-schedule`;
      if (run.spec.replay.descriptorURI !== expectedUri) {
        throw new Error(`replay descriptorURI must be ${expectedUri}`);
      }
      const sourceSchedule = await this.readSchedule(sourceRun.status.scheduleRef, sourceRun.metadata.uid);
      if (sourceSchedule.integrity.digest !== run.spec.replay.descriptorDigest) {
        throw new Error('replay descriptorDigest does not match the source resolved schedule');
      }
      schedule = consumeReplayPlan({resolvedSchedule: sourceSchedule}, run, context);
    } else {
      schedule = resolveAttacknetSchedule(run, context);
    }
    if (schedule.actions.some(action => action.kind !== 'fault-campaign')) {
      throw new Error('the Kubernetes run controller currently accepts only fault-campaign schedule actions');
    }
    const scheduleRef = await this.persistSchedule(run, schedule);
    return {schedule, scheduleRef, signerSet};
  }

  async reconcile(run, campaigns) {
    if (run.metadata.deletionTimestamp || TERMINAL_PHASES.has(run.status?.phase)
        || run.status?.phase === 'Paused') return;
    const spec = run.spec ?? {};
    const decisions = structuredClone(run.status?.decisions ?? []);
    const startedAt = run.status?.startedAt ?? now();
    const budgetUsage = {
      campaigns: 0, campaignsStarted: 0, campaignsCompleted: 0, activeFaults: 0,
      wallTimeSeconds: 0, cumulativeFaultSeconds: 0, maximumSignerImpactPercent: 0,
      burnchainFaults: 0, inconclusiveCampaigns: 0,
      minimizationAttempts: spec.minimization?.enabled === true ? 1 : 0,
      ...(run.status?.budgetUsage ?? {}),
    };
    budgetUsage.wallTimeSeconds = elapsedSeconds(startedAt);

    const network = await this.api.get('stacksnetworks', spec.networkRef);
    const owned = item => item.metadata?.ownerReferences?.some(owner => owner.uid === run.metadata.uid);
    const active = campaigns.find(item => owned(item) && !TERMINAL_PHASES.has(item.status?.phase));
    if (network.status?.phase !== 'Ready' && !active) {
      const scheduleSealed = Boolean(run.status?.scheduleRef);
      await this.patchStatus(run, status(run.status, scheduleSealed ? 'Running' : 'Pending',
        scheduleSealed ? 'WaitingForNetworkRecovery' : 'NetworkNotReady', {
        decisions, budgetUsage, startedAt,
      }));
      return;
    }
    if (!run.status?.scheduleRef) {
      let prepared;
      try {
        prepared = await this.prepareSchedule(run, network);
      } catch (error) {
        if (transientError(error)) throw error;
        await this.patchStatus(run, status(run.status, 'Failed', 'ScheduleAdmissionFailed', {
          decisions, budgetUsage, startedAt, completedAt: now(), attribution: 'Inconclusive',
          message: String(error.message ?? error).slice(0, 1000),
        }));
        return;
      }
      const {schedule, scheduleRef, signerSet} = prepared;
      await this.patchStatus(run, status(run.status, 'Preparing', 'ResolvedSchedulePersisted', {
        decisions, budgetUsage, startedAt, scheduleRef,
        scheduleSummary: {
          schemaVersion: schedule.schemaVersion,
          actions: schedule.actions.length,
          replay: schedule.replay.enabled,
          networkUid: schedule.network.uid,
          networkGeneration: schedule.network.generation,
          manifestDigest: schedule.network.manifestDigest,
          signerSetRewardCycle: signerSet.rewardCycle,
          signerSetTotalWeight: signerSet.observedTotalWeight,
          signerSetDigest: signerSet.signerSetDigest,
          signerSetObservedFrom: signerSet.observedFrom,
        },
      }));
      return;
    }
    const schedule = await this.readSchedule(run.status.scheduleRef, run.metadata.uid);
    if (run.status.scheduleRef.runGeneration !== run.metadata.generation
        || run.status.scheduleRef.runSpecDigest !== artifactDigest(run.spec)) {
      await this.patchStatus(run, status(run.status, 'Failed', 'AdmittedRunChanged', {
        decisions, budgetUsage, startedAt, completedAt: now(), attribution: 'Inconclusive',
      }));
      return;
    }
    if (schedule.network.uid !== network.metadata.uid
        || schedule.network.generation !== network.metadata.generation
        || schedule.network.name !== spec.networkRef) {
      await this.patchStatus(run, status(run.status, 'Failed', 'AdmittedNetworkChanged', {
        decisions, budgetUsage, startedAt, completedAt: now(), attribution: 'Inconclusive',
      }));
      return;
    }
    const sequence = schedule.actions;
    if (budgetUsage.wallTimeSeconds > spec.budgets.maxWallTimeSeconds) {
      const paused = spec.stopPolicy?.onBudgetExhausted === 'Pause';
      await this.patchStatus(run, status(run.status, paused ? 'Paused' : 'Failed', 'WallTimeBudgetExhausted', {
        decisions, budgetUsage, startedAt, ...(paused ? {} : {completedAt: now()}),
        attribution: paused ? 'Untriaged' : 'Inconclusive',
      }));
      return;
    }

    if (active) {
      if (run.status?.phase !== 'Running' || run.status?.reason !== 'CampaignActive'
          || run.status?.activeCampaign !== active.metadata.name
          || run.status?.budgetUsage?.activeFaults !== 1) {
        await this.patchStatus(run, status(run.status, 'Running', 'CampaignActive', {
          activeCampaign: active.metadata.name, decisions,
          budgetUsage: {...budgetUsage, activeFaults: 1}, startedAt,
        }));
      }
      return;
    }

    const children = campaigns.filter(owned);
    const completedNames = new Set(decisions.map(item => item.execution));
    for (const child of children.filter(item => TERMINAL_PHASES.has(item.status?.phase))) {
      if (!completedNames.has(child.metadata.name)) {
        decisions.push({
          index: decisions.length, execution: child.metadata.name,
          phase: child.status.phase, completedAt: child.status.completedAt ?? now(),
          source: child.metadata.annotations?.['testing.stacks.org/source-template'],
        });
        budgetUsage.campaignsCompleted += 1;
        if (child.status.phase === 'Inconclusive') budgetUsage.inconclusiveCampaigns += 1;
      }
    }
    budgetUsage.activeFaults = 0;
    const latest = decisions.at(-1);
    if (latest?.phase === 'Failed') {
      const paused = spec.stopPolicy?.onCampaignFailure === 'PauseForTriage';
      await this.patchStatus(run, status(run.status, paused ? 'Paused' : 'Failed', 'ChildCampaignFailed', {
        activeCampaign: null, decisions, budgetUsage, startedAt,
        ...(paused ? {} : {completedAt: now()}), attribution: 'Untriaged',
        ...(!paused ? this.terminalFields(run, children) : {}),
      }));
      return;
    }
    if (latest?.phase === 'Inconclusive'
        && (spec.stopPolicy?.onInconclusive !== 'Continue'
          || budgetUsage.inconclusiveCampaigns > spec.budgets.maxInconclusiveCampaigns)) {
      const paused = spec.stopPolicy?.onInconclusive === 'PauseForTriage';
      await this.patchStatus(run, status(run.status, paused ? 'Paused' : 'Inconclusive', 'ChildCampaignInconclusive', {
        activeCampaign: null, decisions, budgetUsage, startedAt,
        ...(paused ? {} : {completedAt: now()}), attribution: 'Untriaged',
        ...(!paused ? this.terminalFields(run, children) : {}),
      }));
      return;
    }
    if (latest?.phase === 'Passed' && spec.stopPolicy?.onSuccess === 'Stop') {
      await this.patchStatus(run, status(run.status, 'Passed', 'StoppedAfterSuccessfulCampaign', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'NotRequired',
        ...this.terminalFields(run, children),
      }));
      return;
    }
    if (decisions.length >= sequence.length || decisions.length >= spec.budgets.maxCampaigns) {
      await this.patchStatus(run, status(run.status, 'Passed', 'SequenceCompleted', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'NotRequired',
        ...this.terminalFields(run, children),
      }));
      return;
    }

    if (decisions.length > 0) {
      const priorItem = sequence[decisions.length - 1];
      const delay = priorItem.delayAfterSeconds ?? 0;
      if (delay > 0 && elapsedSeconds(decisions.at(-1).completedAt) < delay) {
        if (run.status?.reason !== 'InterCampaignDelay') {
          await this.patchStatus(run, status(run.status, 'Running', 'InterCampaignDelay', {
            activeCampaign: null, decisions, budgetUsage, startedAt,
          }));
        }
        return;
      }
    }

    const item = sequence[decisions.length];
    if (elapsedSeconds(startedAt) < item.notBeforeOffsetSeconds) {
      if (run.status?.reason !== 'ScheduledStartPending') {
        await this.patchStatus(run, status(run.status, 'Running', 'ScheduledStartPending', {
          activeCampaign: null, decisions, budgetUsage, startedAt,
        }));
      }
      return;
    }
    const sourceName = item.source.name;
    const sourceDigest = item.source.specDigest;
    const executionName = stableName(run.metadata.name, String(decisions.length + 1), item.instructionId);
    const resolvedSpec = structuredClone(item.resolved.campaignSpec);
    if (artifactDigest(resolvedSpec) !== item.resolved.campaignSpecDigest) {
      throw new Error(`resolved schedule campaign ${item.instructionId} failed its digest check`);
    }
    const executionSpec = {...resolvedSpec, template: false};
    const declaredManifest = networkManifest(network);
    let currentSignerSet;
    try {
      const pods = await this.api.list('pods', {
        group: '', labels: `testing.stacks.org/network=${declaredManifest.network}`,
      });
      currentSignerSet = await this.signerSets.resolve(network, pods, declaredManifest);
    } catch (error) {
      if (transientError(error)) throw error;
      await this.patchStatus(run, status(run.status, 'Failed', 'SignerSetParityFailed', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'Inconclusive', message: String(error.message ?? error).slice(0, 1000),
      }));
      return;
    }
    if (artifactDigest(currentSignerSet.manifest) !== schedule.network.manifestDigest) {
      await this.patchStatus(run, status(run.status, 'Failed', 'SignerSetChangedBeforeCampaign', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'Inconclusive',
        message: `canonical signer set changed from ${run.status?.scheduleSummary?.signerSetDigest ?? 'unknown'} to ${currentSignerSet.signerSetDigest}`,
      }));
      return;
    }
    const manifest = currentSignerSet.manifest;
    const compiled = compileCampaign({metadata: {name: executionName}, spec: executionSpec}, manifest);
    const nextUsage = {
      ...budgetUsage,
      campaigns: budgetUsage.campaigns + 1,
      campaignsStarted: budgetUsage.campaignsStarted + 1,
      activeFaults: 1,
      cumulativeFaultSeconds: budgetUsage.cumulativeFaultSeconds + item.budgetCharge.faultSeconds,
      maximumSignerImpactPercent: Math.max(
        budgetUsage.maximumSignerImpactPercent, item.budgetCharge.signerImpactPercent,
      ),
      burnchainFaults: budgetUsage.burnchainFaults + item.budgetCharge.burnchainFaults,
    };
    const exceeded = nextUsage.campaigns > spec.budgets.maxCampaigns
      || nextUsage.cumulativeFaultSeconds > spec.budgets.maxCumulativeFaultSeconds
      || nextUsage.maximumSignerImpactPercent > spec.budgets.maxSignerImpactPercent
      || nextUsage.burnchainFaults > spec.budgets.maxBurnchainFaults;
    if (exceeded) {
      const paused = spec.stopPolicy?.onBudgetExhausted === 'Pause';
      await this.patchStatus(run, status(run.status, paused ? 'Paused' : 'Failed', 'CampaignBudgetExhausted', {
        activeCampaign: null, decisions, budgetUsage, startedAt,
        ...(paused ? {} : {completedAt: now()}), attribution: 'Inconclusive',
      }));
      return;
    }
    const execution = {
      apiVersion: `${GROUP}/${VERSION}`, kind: 'FaultCampaign',
      metadata: {
        name: executionName, namespace: run.metadata.namespace,
        ownerReferences: runOwner(run),
        labels: {'testing.stacks.org/network': spec.networkRef, 'testing.stacks.org/run': run.metadata.name},
        annotations: {
          'testing.stacks.org/source-template': sourceName,
          'testing.stacks.org/source-template-uid': item.source.uid,
          'testing.stacks.org/source-template-generation': String(item.source.generation),
          'testing.stacks.org/source-template-digest': sourceDigest,
          'testing.stacks.org/schedule-digest': schedule.integrity.digest,
          'testing.stacks.org/instruction-id': item.instructionId,
        },
      },
      spec: executionSpec,
    };
    const existing = await this.api.get('faultcampaigns', executionName, {allow404: true});
    if (!existing) await this.api.create('faultcampaigns', execution);
    await this.patchStatus(run, status(run.status, 'Running', 'CampaignCreated', {
      activeCampaign: executionName, decisions, budgetUsage: nextUsage,
      resolvedCampaigns: [
        ...(run.status?.resolvedCampaigns ?? []).filter(entry => entry.name !== item.campaignAlias),
        {name: item.campaignAlias, sourceName, sourceUID: item.source.uid,
          sourceGeneration: item.source.generation, specDigest: sourceDigest},
      ],
      startedAt,
    }));
  }
}

export class RunController {
  constructor(api, {probes = new ProbeClient(), signerSets = new SignerSetClient()} = {}) {
    this.api = api;
    this.faults = new FaultCampaignReconciler(api, probes, signerSets);
    this.runs = new AttacknetRunReconciler(api, signerSets);
    this.observedCampaigns = [];
    this.observedRuns = [];
  }
  metrics() { return prometheusMetrics(this.observedCampaigns, this.observedRuns); }
  async reconcileOnce() {
    let dependencyFailure = null;
    const [campaignList, runList] = await Promise.all([
      this.api.list('faultcampaigns'), this.api.list('attacknetruns'),
    ]);
    const campaigns = [...(campaignList.items ?? [])].sort((a, b) =>
      `${a.metadata.creationTimestamp}/${a.metadata.name}`.localeCompare(`${b.metadata.creationTimestamp}/${b.metadata.name}`));
    this.observedCampaigns = campaigns;
    this.observedRuns = runList.items ?? [];
    const executions = campaigns.filter(item => item.spec?.template !== true && !TERMINAL_PHASES.has(item.status?.phase));
    const activeName = executions[0]?.metadata.name;
    for (const campaign of campaigns) {
      try { await this.faults.reconcile(campaign, campaign.metadata.name === activeName); }
      catch (error) {
        console.error(`FaultCampaign ${campaign.metadata.name}:`, error);
        if (transientError(error)) { dependencyFailure ??= error; continue; }
        if (!campaign.metadata.deletionTimestamp && !TERMINAL_PHASES.has(campaign.status?.phase)) {
          await this.faults.patchStatus(campaign, status(campaign.status, 'Failed', 'ControllerError', {
            message: String(error.message ?? error).slice(0, 1000), completedAt: now(),
          }));
          await this.faults.removeChaos(campaign).catch(cleanupError =>
            console.error(`FaultCampaign cleanup ${campaign.metadata.name}:`, cleanupError));
        }
      }
    }
    const refreshed = await this.api.list('faultcampaigns');
    this.observedCampaigns = refreshed.items ?? [];
    const runs = [...(runList.items ?? [])].sort((a, b) =>
      `${a.metadata.creationTimestamp ?? ''}/${a.metadata.name}`
        .localeCompare(`${b.metadata.creationTimestamp ?? ''}/${b.metadata.name}`));
    for (const run of runs) {
      try { await this.runs.reconcile(run, refreshed.items ?? []); }
      catch (error) {
        console.error(`AttacknetRun ${run.metadata.name}:`, error);
        if (transientError(error)) { dependencyFailure ??= error; continue; }
        if (!TERMINAL_PHASES.has(run.status?.phase)) {
          await this.runs.patchStatus(run, status(run.status, 'Failed', 'ControllerError', {
            message: String(error.message ?? error).slice(0, 1000), completedAt: now(),
          }));
        }
      }
    }
    if (dependencyFailure) throw dependencyFailure;
  }
}

async function main() {
  const namespace = process.env.WATCH_NAMESPACE
    ?? (await readFile('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'utf8')).trim();
  const api = new KubernetesApi({namespace});
  const controller = new RunController(api);
  const interval = Math.max(1, Math.min(60, Number(process.env.RECONCILE_INTERVAL_SECONDS ?? 5))) * 1000;
  let live = true;
  let ready = false;
  let lastProgress = Date.now();
  const server = http.createServer((request, response) => {
    const healthy = Date.now() - lastProgress < Math.max(90_000, interval * 4);
    if (request.url === '/metrics') {
      response.writeHead(200, {'Content-Type': 'text/plain; version=0.0.4; charset=utf-8'});
      response.end(controller.metrics());
      return;
    }
    const code = request.url === '/healthz' ? (healthy ? 200 : 503)
      : request.url === '/readyz' ? (ready ? 200 : 503) : 404;
    response.writeHead(code, {'Content-Type': 'text/plain'});
    response.end(code === 200 ? 'ok\n' : 'unavailable\n');
  });
  server.listen(8080, '0.0.0.0');
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { live = false; server.close(); });
  while (live) {
    lastProgress = Date.now();
    try { await controller.reconcileOnce(); ready = true; }
    catch (error) { ready = false; console.error('run-controller loop:', error); }
    lastProgress = Date.now();
    await new Promise(resolve => setTimeout(resolve, interval));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch(error => { console.error(error); process.exitCode = 1; });
