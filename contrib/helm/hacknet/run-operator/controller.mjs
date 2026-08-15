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
  ProbeClient, baselineUsable, buildProbeRequest, controlTarget, probePhase,
} from './probe-client.mjs';

export const GROUP = 'testing.stacks.org';
export const VERSION = 'v1alpha1';
export const FINALIZER = 'testing.stacks.org/fault-cleanup';
export const TERMINAL_PHASES = new Set(['Passed', 'Failed', 'Inconclusive']);
export const MINIMIZATION_OUTCOMES = new Set(['FailureReproduced', 'FailureAbsent', 'Inconclusive']);
const SCHEDULE_FORMAT = 'stacks-attacknet-schedule-configmap/v1';
const CHAOS_PLURALS = Object.freeze({
  PodChaos: 'podchaos', NetworkChaos: 'networkchaos', DNSChaos: 'dnschaos',
  IOChaos: 'iochaos', TimeChaos: 'timechaos',
});
const DURATION_UNITS = Object.freeze({ms: 0.001, s: 1, m: 60, h: 3600});

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
          || actor.signerWeight <= 0) {
        throw new Error(`actor ${actor.name} has invalid authoritative signer ownership`);
      }
      const prior = signerWeights.get(actor.signerIndex);
      if (prior !== undefined && prior !== actor.signerWeight) {
        throw new Error(`signer ${actor.signerIndex} has inconsistent authoritative weight`);
      }
      signerWeights.set(actor.signerIndex, actor.signerWeight);
    } else if (actor.signerWeight !== undefined) {
      throw new Error(`actor ${actor.name} has signerWeight without signerIndex`);
    }
    return {
      service: actor.name, role: actor.role,
      ...(actor.signerIndex === undefined ? {} : {
        signerIndex: actor.signerIndex, signerWeight: actor.signerWeight,
      }),
    };
  });
  return {schemaVersion: 1, network: metadata.name, namespace: metadata.namespace, actors: normalized};
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
  });
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
  const kind = {pod: 'PodChaos', network: 'NetworkChaos', dns: 'DNSChaos', io: 'IOChaos', time: 'TimeChaos'}[type];
  if (!kind) throw new Error(`unsupported fault type ${type}`);
  return {kind, plural: CHAOS_PLURALS[kind], name: campaign.metadata.name};
}

function campaignDocument(campaign) {
  return {metadata: {name: campaign.metadata.name}, spec: campaign.spec};
}

export class FaultCampaignReconciler {
  constructor(api, probes = new ProbeClient()) { this.api = api; this.probes = probes; }

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
    const current = await this.api.get(identity.plural, identity.name,
      {group: 'chaos-mesh.org', version: 'v1alpha1', allow404: true});
    if (!current) return {absent: true, allRecovered: true};
    const allRecovered = conditionTrue(current, 'AllRecovered');
    await this.api.delete(identity.plural, identity.name,
      {group: 'chaos-mesh.org', version: 'v1alpha1'});
    const remaining = await this.api.get(identity.plural, identity.name,
      {group: 'chaos-mesh.org', version: 'v1alpha1', allow404: true});
    return {absent: !remaining, allRecovered};
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
    if (identity.kind === 'TimeChaos') {
      try {
        const control = controlTarget(network, pods, selectedActors);
        responses.push(await this.probes.probe(control, {kind: 'clock', control: true}));
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
    if (TERMINAL_PHASES.has(campaign.status?.phase)) return;
    if (!serialized && (!campaign.status?.phase || campaign.status.phase === 'Pending')) {
      if (campaign.status?.reason !== 'SerializedBehindActiveFault') {
        await this.patchStatus(campaign, status(campaign.status, 'Pending', 'SerializedBehindActiveFault'));
      }
      return;
    }

    const network = await this.api.get('stacksnetworks', campaign.spec.networkRef);
    if (network.status?.phase !== 'Ready') {
      await this.patchStatus(campaign, status(campaign.status, 'Pending', 'NetworkNotReady'));
      return;
    }
    const manifest = networkManifest(network);
    const compiled = compileCampaign(campaignDocument(campaign), manifest);
    const compiledDigest = artifactDigest(compiled.resource);
    const phase = campaign.status?.phase ?? 'Pending';

    if (phase === 'Pending') {
      const pods = await this.api.list('pods', {group: '', labels: `testing.stacks.org/network=${manifest.network}`});
      const resolved = resolveCampaignTargets(manifest, compiled.evidence, pods);
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
        },
        resolvedTargets: resolved.targets,
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

    const identity = chaosIdentity(campaign);
    if (phase === 'Admitted') {
      compiled.resource.metadata.ownerReferences = ownerReference(campaign);
      const existing = await this.api.get(identity.plural, identity.name,
        {group: 'chaos-mesh.org', version: 'v1alpha1', allow404: true});
      if (existing && existing.metadata?.ownerReferences?.[0]?.uid !== campaign.metadata.uid) {
        throw new Error(`refusing to adopt ${identity.plural}/${identity.name}`);
      }
      const created = existing ?? await this.api.create(identity.plural, compiled.resource,
        {group: 'chaos-mesh.org', version: 'v1alpha1'});
      await this.patchStatus(campaign, status(campaign.status, 'Injecting', 'ChaosResourceCreated', {
        chaos: {kind: identity.kind, name: identity.name, uid: created.metadata.uid, createdAt: now()},
      }));
      return;
    }

    const chaos = await this.api.get(identity.plural, identity.name,
      {group: 'chaos-mesh.org', version: 'v1alpha1', allow404: true});
    if (phase === 'Injecting') {
      if (!chaos) throw new Error('Chaos resource disappeared before injection was observed');
      if (conditionTrue(chaos, 'AllInjected')) {
        let effectResults = campaign.status?.effectResults ?? [];
        let probeArtifacts = campaign.status?.probeArtifacts ?? {};
        if (identity.kind === 'PodChaos') {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          effectResults = podEffectResults(campaign, pods);
        } else {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          const during = await this.collectProbePhase(campaign, compiled, network, pods, 'during', true);
          probeArtifacts = {...probeArtifacts, duringJson: JSON.stringify(during)};
        }
        await this.patchStatus(campaign, status(campaign.status, 'Active', 'AllInjectedObserved', {
          injectedAt: now(), actualInjection: {
            allInjectedObserved: true,
            chaosResourceVersion: chaos.metadata.resourceVersion,
            records: chaos.status?.experiment ?? chaos.status?.instances ?? null,
          },
          effectResults,
          probeArtifacts,
        }));
      } else if (elapsedSeconds(campaign.status?.chaos?.createdAt) > assertionTimeout(campaign.spec.effectAssertions, 90)) {
        const cleanup = await this.removeChaos(campaign);
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'InjectionTimeout', {
          cleanup: {...cleanup, observedAt: now()}, completedAt: now(),
        }));
      }
      return;
    }

    if (phase === 'Active') {
      if (!chaos) throw new Error('Chaos resource disappeared without recovery evidence');
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
      const remaining = await this.api.get(identity.plural, identity.name,
        {group: 'chaos-mesh.org', version: 'v1alpha1', allow404: true});
      if (remaining) return;
      const pods = await this.api.list('pods', {group: '', labels: `testing.stacks.org/network=${manifest.network}`});
      let recovered;
      try {
        recovered = resolveCampaignTargets(manifest, compiled.evidence, pods);
      } catch (error) {
        if (elapsedSeconds(campaign.status?.cleanup?.observedAt)
            <= assertionTimeout(campaign.spec.recoveryAssertions, 300)) return;
        await this.patchStatus(campaign, status(campaign.status, 'Failed', 'TargetRecoveryTimeout', {
          message: String(error.message ?? error).slice(0, 1000), completedAt: now(),
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
            IOChaos: 'IODegraded', TimeChaos: 'ClockSkewObserved',
          }[identity.kind];
          const title = value => value[0].toUpperCase() + value.slice(1);
          effectResults = evaluation.evaluations.map(item => ({
            assertion, outcome: title(item.effect), actor: item.actor,
            podUid: campaign.status.resolvedTargets.find(target => target.actor === item.actor)?.podUid,
            observedAt: now(), message: item.reason,
          }));
          recoveryResults = evaluation.evaluations.map(item => ({
            assertion: 'TargetReady', outcome: title(item.recovery), actor: item.actor,
            podUid: campaign.status.resolvedTargets.find(target => target.actor === item.actor)?.podUid,
            observedAt: now(), message: item.reason,
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
      const proven = evidenceError === null && provenResults.length >= minimum
        && recoveredResults.length >= minimum
        && (required.length === 0 || required.every(assertion =>
          provenResults.some(result => result.assertion === assertion.type
            && (assertion.actor === undefined || result.actor === assertion.actor))))
        && (requiredRecovery.length === 0 || requiredRecovery.every(assertion =>
          recoveredResults.some(result => result.assertion === assertion.type
            && (assertion.actor === undefined || result.actor === assertion.actor))));
      await this.patchStatus(campaign, status(campaign.status,
        proven ? 'Passed' : 'Inconclusive',
        proven ? 'EffectAndRecoveryProven' : evidenceError ? 'ProbeEvidenceInvalid' : 'EffectNotProven', {
          effectResults, recoveryResults, probeArtifacts,
          ...(evidenceError ? {message: evidenceError} : {}),
          completedAt: now(),
        }));
    }
  }
}

function runOwner(run) { return ownerReference(run); }

export class AttacknetRunReconciler {
  constructor(api) { this.api = api; }
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
    const manifest = networkManifest(network);
    const pods = await this.api.list('pods', {
      group: '', labels: `testing.stacks.org/network=${manifest.network}`,
    });
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
    return {schedule, scheduleRef};
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
    if (network.status?.phase !== 'Ready') {
      await this.patchStatus(run, status(run.status, 'Pending', 'NetworkNotReady', {
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
      const {schedule, scheduleRef} = prepared;
      await this.patchStatus(run, status(run.status, 'Preparing', 'ResolvedSchedulePersisted', {
        decisions, budgetUsage, startedAt, scheduleRef,
        scheduleSummary: {
          schemaVersion: schedule.schemaVersion,
          actions: schedule.actions.length,
          replay: schedule.replay.enabled,
          networkUid: schedule.network.uid,
          networkGeneration: schedule.network.generation,
          manifestDigest: schedule.network.manifestDigest,
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

    const owned = item => item.metadata?.ownerReferences?.some(owner => owner.uid === run.metadata.uid);
    const active = campaigns.find(item => owned(item) && !TERMINAL_PHASES.has(item.status?.phase));
    if (active) {
      if (run.status?.activeCampaign !== active.metadata.name || run.status?.budgetUsage?.activeFaults !== 1) {
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
    const manifest = networkManifest(network);
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
  constructor(api) {
    this.api = api;
    this.faults = new FaultCampaignReconciler(api);
    this.runs = new AttacknetRunReconciler(api);
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
