#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import process from 'node:process';

import {compileCampaign} from '../../../attacknet/fault-campaign.mjs';
import {resolveCampaignTargets} from '../../../attacknet/campaign-targets.mjs';

export const GROUP = 'testing.stacks.org';
export const VERSION = 'v1alpha1';
export const FINALIZER = 'testing.stacks.org/fault-cleanup';
export const TERMINAL_PHASES = new Set(['Passed', 'Failed', 'Inconclusive']);
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

function conditionTrue(resource, type) {
  return (resource?.status?.conditions ?? []).some(item => item.type === type && item.status === 'True');
}

function podReady(pod) {
  return pod?.status?.phase === 'Running'
    && (pod.status.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True')
    && (pod.status.containerStatuses ?? []).some(item => item.name === 'actor' && item.ready === true);
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
  constructor(api) { this.api = api; }

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
      await this.patchStatus(campaign, status(campaign.status, 'Admitted', 'SafetyPolicySatisfied', {
        admission: {
          networkUid: network.metadata.uid, networkGeneration: network.metadata.generation,
          compiledDigest, admittedAt: now(), signerImpact: compiled.evidence.signerImpact,
          minerImpact: compiled.evidence.minerImpact,
        },
        resolvedTargets: resolved.targets,
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
        if (identity.kind === 'PodChaos') {
          const pods = await this.api.list('pods', {
            group: '', labels: `testing.stacks.org/network=${manifest.network}`,
          });
          effectResults = podEffectResults(campaign, pods);
        }
        await this.patchStatus(campaign, status(campaign.status, 'Active', 'AllInjectedObserved', {
          injectedAt: now(), actualInjection: {
            allInjectedObserved: true,
            chaosResourceVersion: chaos.metadata.resourceVersion,
            records: chaos.status?.experiment ?? chaos.status?.instances ?? null,
          },
          effectResults,
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
      const required = campaign.spec.effectAssertions ?? [];
      const effectResults = campaign.status?.effectResults ?? [];
      // User-supplied assertions may add requirements, but omitting them must
      // never turn Chaos Mesh's AllInjected bookkeeping into proof that the
      // requested fault was observable. At least one trusted effect result is
      // required for every execution.
      const minimum = minimumAffected(compiled.resource.spec, campaign.status.resolvedTargets.length);
      const provenResults = effectResults.filter(item => item.outcome === 'Proven');
      const proven = provenResults.length >= minimum
        && (required.length === 0 || required.every(assertion =>
          provenResults.some(result => result.assertion === assertion.type
            && (assertion.actor === undefined || result.actor === assertion.actor))));
      await this.patchStatus(campaign, status(campaign.status,
        proven ? 'Passed' : 'Inconclusive',
        proven ? 'EffectAndRecoveryProven' : 'EffectNotProven', {
          recoveryResults: recovered.targets.map(target => ({
            assertion: 'TargetReady', outcome: 'Proven', actor: target.actor,
            podUid: target.podUid, observedAt: now(),
          })),
          completedAt: now(),
        }));
    }
  }
}

function runOwner(run) { return ownerReference(run); }

export class AttacknetRunReconciler {
  constructor(api) { this.api = api; }
  async patchStatus(run, next) {
    next.observedGeneration = run.metadata.generation;
    await this.api.patch('attacknetruns', run.metadata.name,
      {metadata: {resourceVersion: run.metadata.resourceVersion}, status: next}, {subresource: 'status'});
  }

  async reconcile(run, campaigns) {
    if (run.metadata.deletionTimestamp || TERMINAL_PHASES.has(run.status?.phase)
        || run.status?.phase === 'Paused') return;
    const spec = run.spec ?? {};
    const sequence = (spec.sequence ?? []).filter(item => item.enabled !== false);
    const decisions = structuredClone(run.status?.decisions ?? []);
    const startedAt = run.status?.startedAt ?? now();
    const budgetUsage = {
      campaigns: 0, campaignsStarted: 0, campaignsCompleted: 0, activeFaults: 0,
      wallTimeSeconds: 0, cumulativeFaultSeconds: 0, maximumSignerImpactPercent: 0,
      burnchainFaults: 0, inconclusiveCampaigns: 0, minimizationAttempts: 0,
      ...(run.status?.budgetUsage ?? {}),
    };
    budgetUsage.wallTimeSeconds = elapsedSeconds(startedAt);
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
      }));
      return;
    }
    if (latest?.phase === 'Passed' && spec.stopPolicy?.onSuccess === 'Stop') {
      await this.patchStatus(run, status(run.status, 'Passed', 'StoppedAfterSuccessfulCampaign', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'NotRequired',
      }));
      return;
    }
    if (decisions.length >= sequence.length || decisions.length >= spec.budgets.maxCampaigns) {
      await this.patchStatus(run, status(run.status, 'Passed', 'SequenceCompleted', {
        activeCampaign: null, decisions, budgetUsage, startedAt, completedAt: now(),
        attribution: 'NotRequired',
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
    const catalogEntry = (spec.campaignCatalog ?? []).find(entry => entry.name === item.campaign);
    const sourceName = catalogEntry?.campaignRef;
    if (!sourceName) throw new Error(`sequence references unknown campaign alias ${item.campaign}`);
    const source = await this.api.get('faultcampaigns', sourceName);
    if (source.spec?.template !== true) throw new Error(`catalog source ${sourceName} is not a template`);
    if (source.spec.networkRef !== spec.networkRef) throw new Error(`catalog source ${sourceName} targets another network`);
    const sourceDigest = artifactDigest(source.spec);
    if (catalogEntry.expectedUID && catalogEntry.expectedUID !== source.metadata.uid) {
      throw new Error(`catalog source ${sourceName} UID does not match expectedUID`);
    }
    if (catalogEntry.expectedGeneration && catalogEntry.expectedGeneration !== source.metadata.generation) {
      throw new Error(`catalog source ${sourceName} generation does not match expectedGeneration`);
    }
    if (catalogEntry.expectedSpecDigest && catalogEntry.expectedSpecDigest !== sourceDigest) {
      throw new Error(`catalog source ${sourceName} digest does not match expectedSpecDigest`);
    }

    const executionName = stableName(run.metadata.name, String(decisions.length + 1), item.id);
    const executionSpec = {...structuredClone(source.spec), template: false};
    const network = await this.api.get('stacksnetworks', spec.networkRef);
    const manifest = networkManifest(network);
    const compiled = compileCampaign({metadata: {name: executionName}, spec: executionSpec}, manifest);
    const faultSeconds = durationSeconds(compiled.resource.spec.duration);
    const signerImpact = compiled.evidence.signerImpact.percent;
    const rolesByActor = new Map(manifest.actors.map(actor => [actor.service, actor.role]));
    const burnchainFault = compiled.evidence.selectedActors.some(actor => rolesByActor.get(actor) === 'burnchain');
    const nextUsage = {
      ...budgetUsage,
      campaigns: budgetUsage.campaigns + 1,
      campaignsStarted: budgetUsage.campaignsStarted + 1,
      activeFaults: 1,
      cumulativeFaultSeconds: budgetUsage.cumulativeFaultSeconds + faultSeconds,
      maximumSignerImpactPercent: Math.max(budgetUsage.maximumSignerImpactPercent, signerImpact),
      burnchainFaults: budgetUsage.burnchainFaults + (burnchainFault ? 1 : 0),
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
          'testing.stacks.org/source-template': source.metadata.name,
          'testing.stacks.org/source-template-uid': source.metadata.uid,
          'testing.stacks.org/source-template-generation': String(source.metadata.generation),
          'testing.stacks.org/source-template-digest': sourceDigest,
        },
      },
      spec: executionSpec,
    };
    const existing = await this.api.get('faultcampaigns', executionName, {allow404: true});
    if (!existing) await this.api.create('faultcampaigns', execution);
    await this.patchStatus(run, status(run.status, 'Running', 'CampaignCreated', {
      activeCampaign: executionName, decisions, budgetUsage: nextUsage,
      resolvedCampaigns: [
        ...(run.status?.resolvedCampaigns ?? []).filter(entry => entry.name !== item.campaign),
        {name: item.campaign, sourceName, sourceUID: source.metadata.uid,
          sourceGeneration: source.metadata.generation, specDigest: sourceDigest},
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
  }
  async reconcileOnce() {
    let dependencyFailure = null;
    const [campaignList, runList] = await Promise.all([
      this.api.list('faultcampaigns'), this.api.list('attacknetruns'),
    ]);
    const campaigns = [...(campaignList.items ?? [])].sort((a, b) =>
      `${a.metadata.creationTimestamp}/${a.metadata.name}`.localeCompare(`${b.metadata.creationTimestamp}/${b.metadata.name}`));
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
