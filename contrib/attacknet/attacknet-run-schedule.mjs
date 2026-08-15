#!/usr/bin/env node

import {readFileSync, renameSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';

import {canonicalJson, seededChoice, sha256Value} from './run-descriptor.mjs';
import {compileCampaign} from './fault-campaign.mjs';

export const ATTACKNET_SCHEDULE_SCHEMA = 'stacks-attacknet-schedule/v1';
export const ATTACKNET_DDMIN_SCHEMA = 'stacks-attacknet-ddmin/v1';
export const DECISION_ALGORITHM = 'hmac-sha256-decisions/v1';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const OUTCOMES = new Set(['FailureReproduced', 'FailureAbsent', 'Inconclusive']);

function object(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function array(value, field, {minimum = 0, maximum = Infinity} = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${field} must be an array with ${minimum}..${maximum} entries`);
  }
  return value;
}

function string(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function integer(value, field, {minimum = 0, maximum = Number.MAX_SAFE_INTEGER} = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${field} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function number(value, field, {minimum = 0, maximum = Number.MAX_VALUE} = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${field} must be a finite number in ${minimum}..${maximum}`);
  }
  return value;
}

function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

function durationSeconds(value, field) {
  const match = /^(\d+)(ms|s|m|h)$/.exec(string(value, field));
  if (!match) throw new Error(`${field} must use an integer ms/s/m/h duration`);
  const seconds = Number(match[1]) * {ms: 0.001, s: 1, m: 60, h: 3600}[match[2]];
  if (seconds <= 0) throw new Error(`${field} must be greater than zero`);
  return seconds;
}

function digest(value, field) {
  if (!SHA256.test(value ?? '')) throw new Error(`${field} must be a lowercase sha256 digest`);
  return value;
}

function unique(values, field) {
  if (new Set(values).size !== values.length) throw new Error(`${field} must not contain duplicates`);
  return values;
}

function canonicalOptions(values, field, normalize) {
  const result = array(values, field, {minimum: 1, maximum: 256}).map((value, index) =>
    normalize(value, `${field}[${index}]`));
  const keyed = result.map(value => [canonicalJson(value), value]).sort(([left], [right]) => left.localeCompare(right));
  unique(keyed.map(([key]) => key), field);
  return keyed.map(([, value]) => value);
}

function normalizeImages(images, field = 'context.images') {
  const normalized = array(images, field, {minimum: 1, maximum: 256}).map((image, index) => {
    object(image, `${field}[${index}]`);
    const result = {
      scope: string(image.scope, `${field}[${index}].scope`),
      requestedRef: string(image.requestedRef, `${field}[${index}].requestedRef`),
      resolvedRef: string(image.resolvedRef, `${field}[${index}].resolvedRef`),
      resolvedDigest: digest(image.resolvedDigest, `${field}[${index}].resolvedDigest`),
    };
    if (!result.resolvedRef.includes(result.resolvedDigest)) {
      throw new Error(`${field}[${index}].resolvedRef must contain resolvedDigest`);
    }
    return result;
  }).sort((left, right) => left.scope.localeCompare(right.scope));
  unique(normalized.map(image => image.scope), `${field} scopes`);
  return normalized;
}

function normalizeCatalog(entries) {
  const normalized = array(entries, 'run.spec.campaignCatalog', {minimum: 1, maximum: 64}).map((entry, index) => {
    object(entry, `run.spec.campaignCatalog[${index}]`);
    const result = {
      name: string(entry.name, `run.spec.campaignCatalog[${index}].name`),
      campaignRef: string(entry.campaignRef, `run.spec.campaignCatalog[${index}].campaignRef`),
    };
    if (entry.expectedUID !== undefined) result.expectedUID = string(entry.expectedUID, `catalog ${result.name}.expectedUID`);
    if (entry.expectedGeneration !== undefined) result.expectedGeneration = integer(entry.expectedGeneration, `catalog ${result.name}.expectedGeneration`, {minimum: 1});
    if (entry.expectedSpecDigest !== undefined) result.expectedSpecDigest = digest(entry.expectedSpecDigest, `catalog ${result.name}.expectedSpecDigest`);
    return result;
  }).sort((left, right) => left.name.localeCompare(right.name));
  unique(normalized.map(entry => entry.name), 'campaign catalog names');
  unique(normalized.map(entry => entry.campaignRef), 'campaign catalog references');
  return normalized;
}

function normalizeSequence(sequence, catalog) {
  const aliases = new Set(catalog.map(entry => entry.name));
  const normalized = array(sequence, 'run.spec.sequence', {minimum: 1, maximum: 256}).map((step, index) => {
    object(step, `run.spec.sequence[${index}]`);
    const result = {
      id: string(step.id, `run.spec.sequence[${index}].id`),
      campaign: string(step.campaign, `run.spec.sequence[${index}].campaign`),
      delayAfterSeconds: integer(step.delayAfterSeconds ?? 0, `run.spec.sequence[${index}].delayAfterSeconds`, {maximum: 3600}),
      enabled: step.enabled !== false,
    };
    if (!aliases.has(result.campaign)) throw new Error(`sequence ${result.id} references unknown campaign ${result.campaign}`);
    return result;
  });
  unique(normalized.map(step => step.id), 'sequence IDs');
  return normalized;
}

function normalizeBudgets(value) {
  object(value, 'run.spec.budgets');
  const budgets = {
    maxCampaigns: integer(value.maxCampaigns, 'budgets.maxCampaigns', {minimum: 1, maximum: 256}),
    maxWallTimeSeconds: integer(value.maxWallTimeSeconds, 'budgets.maxWallTimeSeconds', {minimum: 1, maximum: 86400}),
    maxCumulativeFaultSeconds: number(value.maxCumulativeFaultSeconds, 'budgets.maxCumulativeFaultSeconds', {minimum: 0, maximum: 86400}),
    maxActiveFaults: integer(value.maxActiveFaults, 'budgets.maxActiveFaults', {minimum: 1, maximum: 1}),
    maxSignerImpactPercent: number(value.maxSignerImpactPercent, 'budgets.maxSignerImpactPercent', {maximum: 100}),
    maxBurnchainFaults: integer(value.maxBurnchainFaults, 'budgets.maxBurnchainFaults', {maximum: 256}),
    maxInconclusiveCampaigns: integer(value.maxInconclusiveCampaigns, 'budgets.maxInconclusiveCampaigns', {maximum: 256}),
  };
  if (budgets.maxCumulativeFaultSeconds > budgets.maxWallTimeSeconds) {
    throw new Error('maxCumulativeFaultSeconds cannot exceed maxWallTimeSeconds');
  }
  return budgets;
}

function normalizeSources(sources) {
  const byName = new Map();
  for (const [index, source] of array(sources, 'context.campaigns', {minimum: 1, maximum: 64}).entries()) {
    object(source, `context.campaigns[${index}]`);
    object(source.metadata, `context.campaigns[${index}].metadata`);
    const name = string(source.metadata.name, `context.campaigns[${index}].metadata.name`);
    if (byName.has(name)) throw new Error(`duplicate campaign source ${name}`);
    const normalized = {
      metadata: {
        name,
        uid: string(source.metadata.uid, `campaign ${name} metadata.uid`),
        generation: integer(source.metadata.generation, `campaign ${name} metadata.generation`, {minimum: 1}),
      },
      spec: copy(object(source.spec, `campaign ${name} spec`)),
    };
    byName.set(name, normalized);
  }
  return byName;
}

function choose(seed, namespace, index, values) {
  const encoded = values.map(value => canonicalJson(value));
  const receipt = seededChoice(seed, namespace, index, encoded);
  return {value: values[receipt.choiceIndex], receipt: {...receipt, choicesDigest: sha256Value(encoded)}};
}

function choiceSpaceFor(decisionSpaces, instructionId) {
  if (decisionSpaces === undefined) return {};
  object(decisionSpaces, 'context.decisionSpaces');
  const space = decisionSpaces[instructionId] ?? {};
  object(space, `decisionSpaces.${instructionId}`);
  for (const field of Object.keys(space)) {
    if (!new Set(['campaignAliases', 'targetSets', 'parameterVariants']).has(field)) {
      throw new Error(`unsupported decisionSpaces.${instructionId}.${field}`);
    }
  }
  return space;
}

function resolveDecision(step, index, seed, catalog, decisionSpaces) {
  const space = choiceSpaceFor(decisionSpaces, step.id);
  const decisions = [];
  let campaignAlias = step.campaign;
  if (space.campaignAliases !== undefined) {
    const options = canonicalOptions(space.campaignAliases, `decisionSpaces.${step.id}.campaignAliases`, string);
    const known = new Set(catalog.map(entry => entry.name));
    for (const option of options) if (!known.has(option)) throw new Error(`decision space ${step.id} references unknown campaign ${option}`);
    const selected = choose(seed, `attacknet-run/${step.id}/campaign`, index, options);
    campaignAlias = selected.value;
    decisions.push({dimension: 'campaign', ...selected.receipt});
  }
  let targetActors;
  if (space.targetSets !== undefined) {
    const options = canonicalOptions(space.targetSets, `decisionSpaces.${step.id}.targetSets`, (set, field) =>
      unique(array(set, field, {minimum: 1, maximum: 256}).map((actor, actorIndex) =>
        string(actor, `${field}[${actorIndex}]`)).sort(), field));
    const selected = choose(seed, `attacknet-run/${step.id}/targets`, index, options);
    targetActors = selected.value;
    decisions.push({dimension: 'targets', ...selected.receipt});
  }
  let parameters;
  if (space.parameterVariants !== undefined) {
    const options = canonicalOptions(space.parameterVariants, `decisionSpaces.${step.id}.parameterVariants`, (variant, field) =>
      copy(object(variant, field)));
    const selected = choose(seed, `attacknet-run/${step.id}/parameters`, index, options);
    parameters = selected.value;
    decisions.push({dimension: 'parameters', ...selected.receipt});
  }
  return {campaignAlias, targetActors, parameters, decisions};
}

function resolveSource(alias, catalog, sources) {
  const entry = catalog.find(candidate => candidate.name === alias);
  if (!entry) throw new Error(`unknown campaign alias ${alias}`);
  const source = sources.get(entry.campaignRef);
  if (!source) throw new Error(`campaign source ${entry.campaignRef} was not supplied`);
  const specDigest = sha256Value(source.spec);
  if (entry.expectedUID && entry.expectedUID !== source.metadata.uid) throw new Error(`campaign ${alias} UID constraint does not match`);
  if (entry.expectedGeneration && entry.expectedGeneration !== source.metadata.generation) throw new Error(`campaign ${alias} generation constraint does not match`);
  if (entry.expectedSpecDigest && entry.expectedSpecDigest !== specDigest) throw new Error(`campaign ${alias} spec digest constraint does not match`);
  return {entry, source, specDigest};
}

function actorRoles(manifest) {
  return new Map(array(manifest.actors ?? manifest.workloads, 'context.manifest.actors', {minimum: 1, maximum: 512})
    .map(actor => [actor.service, actor.role]));
}

function scheduleStep({step, order, offsetSeconds, decision, catalog, sources, manifest, images}) {
  const {entry, source, specDigest} = resolveSource(decision.campaignAlias, catalog, sources);
  const spec = copy(source.spec);
  if (decision.targetActors !== undefined) spec.target = {actors: decision.targetActors, roles: []};
  if (decision.parameters !== undefined) spec.fault.parameters = copy(decision.parameters);
  const compiled = compileCampaign({metadata: {name: `plan-${String(order).padStart(3, '0')}`}, spec}, manifest);
  const roles = actorRoles(manifest);
  const faultSeconds = durationSeconds(compiled.resource.spec.duration, `sequence ${step.id} fault duration`);
  const targets = [...compiled.evidence.selectedActors].sort();
  const burnchainFault = targets.some(actor => roles.get(actor) === 'burnchain');
  return {
    order,
    kind: 'fault-campaign',
    instructionId: step.id,
    notBeforeOffsetSeconds: offsetSeconds,
    delayAfterSeconds: step.delayAfterSeconds,
    campaignAlias: decision.campaignAlias,
    source: {
      name: entry.campaignRef,
      uid: source.metadata.uid,
      generation: source.metadata.generation,
      specDigest,
    },
    imageConstraints: copy(images),
    resolved: {
      targets,
      parameters: copy(spec.fault.parameters ?? {}),
      campaignSpec: spec,
      campaignSpecDigest: sha256Value(spec),
    },
    choiceReceipts: decision.decisions,
    budgetCharge: {
      campaigns: 1,
      faultSeconds,
      signerImpactPercent: compiled.evidence.signerImpact.percent,
      burnchainFaults: burnchainFault ? 1 : 0,
    },
  };
}

function usageFor(actions) {
  const faults = actions.filter(action => action.kind === 'fault-campaign');
  return {
    campaigns: faults.length,
    cumulativeFaultSeconds: faults.reduce((sum, action) => sum + action.budgetCharge.faultSeconds, 0),
    maximumSignerImpactPercent: faults.reduce((maximum, action) =>
      Math.max(maximum, action.budgetCharge.signerImpactPercent), 0),
    burnchainFaults: faults.reduce((sum, action) => sum + action.budgetCharge.burnchainFaults, 0),
    maximumActiveFaults: faults.length === 0 ? 0 : 1,
    plannedWallTimeSeconds: actions.reduce((maximum, action) => Math.max(maximum,
      action.notBeforeOffsetSeconds + (action.budgetCharge?.faultSeconds ?? 0) + (action.delayAfterSeconds ?? 0)), 0),
  };
}

export function validateBudgetUsage(usage, budgets) {
  object(usage, 'usage');
  const normalized = normalizeBudgets(budgets);
  const checks = [
    ['campaigns', usage.campaigns, normalized.maxCampaigns],
    ['cumulative fault seconds', usage.cumulativeFaultSeconds, normalized.maxCumulativeFaultSeconds],
    ['maximum active faults', usage.maximumActiveFaults, normalized.maxActiveFaults],
    ['maximum signer impact percent', usage.maximumSignerImpactPercent, normalized.maxSignerImpactPercent],
    ['burnchain faults', usage.burnchainFaults, normalized.maxBurnchainFaults],
    ['planned wall time seconds', usage.plannedWallTimeSeconds, normalized.maxWallTimeSeconds],
  ];
  const exceeded = checks.filter(([, actual, maximum]) => actual > maximum)
    .map(([budget, actual, maximum]) => ({budget, actual, maximum}));
  if (exceeded.length > 0) {
    throw new Error(`resolved schedule exceeds aggregate budget: ${exceeded.map(item => `${item.budget} ${item.actual}>${item.maximum}`).join(', ')}`);
  }
  return {limits: normalized, usage: copy(usage), headroom: {
    campaigns: normalized.maxCampaigns - usage.campaigns,
    cumulativeFaultSeconds: normalized.maxCumulativeFaultSeconds - usage.cumulativeFaultSeconds,
    signerImpactPercent: normalized.maxSignerImpactPercent - usage.maximumSignerImpactPercent,
    burnchainFaults: normalized.maxBurnchainFaults - usage.burnchainFaults,
    wallTimeSeconds: normalized.maxWallTimeSeconds - usage.plannedWallTimeSeconds,
  }};
}

function sealSchedule(schedule) {
  const result = copy(schedule);
  delete result.integrity;
  result.integrity = {algorithm: 'sha256', digest: sha256Value(result)};
  return result;
}

export function validateResolvedSchedule(schedule) {
  object(schedule, 'schedule');
  if (schedule.schemaVersion !== ATTACKNET_SCHEDULE_SCHEMA) throw new Error('unsupported schedule schema');
  string(schedule.run.name, 'schedule.run.name');
  string(schedule.run.seed, 'schedule.run.seed');
  if (schedule.run.decisionAlgorithm !== DECISION_ALGORITHM) throw new Error('unsupported decision algorithm');
  string(schedule.network.name, 'schedule.network.name');
  string(schedule.network.uid, 'schedule.network.uid');
  integer(schedule.network.generation, 'schedule.network.generation', {minimum: 1});
  normalizeImages(schedule.imageConstraints, 'schedule.imageConstraints');
  const actions = array(schedule.actions, 'schedule.actions', {maximum: 256});
  let priorOffset = -1;
  actions.forEach((action, index) => {
    if (action.order !== index + 1) throw new Error('schedule action order must be contiguous');
    number(action.notBeforeOffsetSeconds, `actions[${index}].notBeforeOffsetSeconds`);
    if (action.notBeforeOffsetSeconds < priorOffset) throw new Error('schedule action offsets must be nondecreasing');
    priorOffset = action.notBeforeOffsetSeconds;
    if (!new Set(['fault-campaign', 'cadence-transition']).has(action.kind)) throw new Error(`unsupported schedule action kind ${action.kind}`);
    if (action.kind === 'fault-campaign') {
      string(action.instructionId, `actions[${index}].instructionId`);
      digest(action.source.specDigest, `actions[${index}].source.specDigest`);
      digest(action.resolved.campaignSpecDigest, `actions[${index}].resolved.campaignSpecDigest`);
      if (sha256Value(action.resolved.campaignSpec) !== action.resolved.campaignSpecDigest) {
        throw new Error(`actions[${index}] campaign spec digest mismatch`);
      }
      normalizeImages(action.imageConstraints, `actions[${index}].imageConstraints`);
      if (canonicalJson(action.imageConstraints) !== canonicalJson(schedule.imageConstraints)) {
        throw new Error(`actions[${index}] image constraints differ from the schedule`);
      }
    }
  });
  const expectedUsage = usageFor(actions);
  if (canonicalJson(expectedUsage) !== canonicalJson(schedule.budgets.usage)) throw new Error('schedule budget usage mismatch');
  const expectedBudgets = validateBudgetUsage(expectedUsage, schedule.budgets.limits);
  if (canonicalJson(expectedBudgets) !== canonicalJson(schedule.budgets)) {
    throw new Error('schedule budget headroom mismatch');
  }
  object(schedule.integrity, 'schedule.integrity');
  const unsigned = copy(schedule);
  delete unsigned.integrity;
  if (schedule.integrity.digest !== sha256Value(unsigned)) throw new Error('schedule integrity mismatch');
  return true;
}

export function resolveAttacknetSchedule(run, context) {
  object(run, 'run');
  const spec = object(run.spec ?? run, 'run.spec');
  object(context, 'context');
  const name = string(run.metadata?.name ?? context.runName ?? 'attacknet-run', 'run name');
  const seed = string(spec.seed, 'run.spec.seed');
  const decisionAlgorithm = spec.decisionAlgorithm ?? DECISION_ALGORITHM;
  if (decisionAlgorithm !== DECISION_ALGORITHM) throw new Error(`unsupported decision algorithm ${decisionAlgorithm}`);
  const catalog = normalizeCatalog(spec.campaignCatalog);
  const sequence = normalizeSequence(spec.sequence, catalog);
  const budgets = normalizeBudgets(spec.budgets);
  const sources = normalizeSources(context.campaigns);
  const manifest = copy(object(context.manifest, 'context.manifest'));
  const images = normalizeImages(context.images);
  const network = {
    name: string(spec.networkRef, 'run.spec.networkRef'),
    uid: string(context.network?.uid, 'context.network.uid'),
    generation: integer(context.network?.generation, 'context.network.generation', {minimum: 1}),
    manifestDigest: sha256Value(manifest),
  };
  if (manifest.network !== network.name) throw new Error(`manifest network ${manifest.network} does not match ${network.name}`);
  const enabled = sequence.filter(step => step.enabled);
  const actions = [];
  let offsetSeconds = 0;
  enabled.forEach((step, index) => {
    const decision = resolveDecision(step, index, seed, catalog, context.decisionSpaces);
    const action = scheduleStep({step, order: index + 1, offsetSeconds, decision, catalog, sources, manifest, images});
    actions.push(action);
    offsetSeconds += action.budgetCharge.faultSeconds + action.delayAfterSeconds;
  });
  const usage = usageFor(actions);
  const schedule = sealSchedule({
    schemaVersion: ATTACKNET_SCHEDULE_SCHEMA,
    run: {name, seed, decisionAlgorithm},
    network,
    catalogDigest: sha256Value(catalog),
    sequenceDigest: sha256Value(sequence),
    imageConstraints: images,
    actions,
    budgets: validateBudgetUsage(usage, budgets),
    replay: {enabled: false},
  });
  validateResolvedSchedule(schedule);
  return schedule;
}

function replayFaultAction(action, index, run, context, offsetSeconds) {
  const payload = object(action.payload, `replayPlan.schedule[${index}].payload`);
  const requestedCampaign = string(payload.campaign, `replayPlan.schedule[${index}].payload.campaign`);
  const decision = payload.decision ?? 'applied';
  // Selection, rejection, and reversion are ledger observations. Only an
  // actually-applied fault becomes an executable replay instruction.
  if (decision !== 'applied') return null;
  const catalog = normalizeCatalog(run.spec.campaignCatalog);
  const entry = catalog.find(candidate => candidate.name === requestedCampaign
    || candidate.campaignRef === requestedCampaign);
  if (!entry) throw new Error(`replay references unknown campaign ${requestedCampaign}`);
  const alias = entry.name;
  const step = {id: `replay-${action.order}`, campaign: alias, delayAfterSeconds: 0, enabled: true};
  const sources = normalizeSources(context.campaigns);
  const resolvedDecision = {
    campaignAlias: alias,
    targetActors: payload.targets === undefined ? undefined
      : unique(array(payload.targets, `replay targets ${index}`, {minimum: 1, maximum: 256}).map(String).sort(), 'replay targets'),
    parameters: payload.parameters === undefined ? undefined : copy(object(payload.parameters, `replay parameters ${index}`)),
    decisions: [{dimension: 'replay', choice: alias, choiceIndex: 0,
      digest: sha256Value({order: action.order, payload}), choicesDigest: sha256Value([payload])}],
  };
  return scheduleStep({step, order: 0, offsetSeconds, decision: resolvedDecision, catalog, sources,
    manifest: context.manifest, images: normalizeImages(context.images)});
}

export function consumeReplayPlan(replayPlan, run, context) {
  object(replayPlan, 'replayPlan');
  if (replayPlan.resolvedSchedule !== undefined) {
    validateResolvedSchedule(replayPlan.resolvedSchedule);
    const resolved = copy(replayPlan.resolvedSchedule);
    const manifestDigest = sha256Value(object(context.manifest, 'context.manifest'));
    if (resolved.network.manifestDigest !== manifestDigest) {
      throw new Error('replay network manifest differs from the source schedule');
    }
    const images = normalizeImages(context.images);
    if (canonicalJson(images) !== canonicalJson(resolved.imageConstraints)) {
      throw new Error('replay resolved image constraints do not match current images');
    }
    const sources = normalizeSources(context.campaigns);
    for (const action of resolved.actions.filter(candidate => candidate.kind === 'fault-campaign')) {
      const source = sources.get(action.source.name);
      if (!source || source.metadata.uid !== action.source.uid
          || source.metadata.generation !== action.source.generation
          || sha256Value(source.spec) !== action.source.specDigest) {
        throw new Error(`replay campaign source ${action.source.name} no longer satisfies its immutable constraints`);
      }
    }
    const sourceScheduleDigest = resolved.integrity.digest;
    const sourceNetwork = copy(resolved.network);
    const replayNetworkUid = string(context.network?.uid, 'context.network.uid');
    if (replayNetworkUid === sourceNetwork.uid) {
      throw new Error('resolved replay requires a fresh network UID');
    }
    resolved.network = {
      name: resolved.network.name,
      uid: replayNetworkUid,
      generation: integer(context.network?.generation, 'context.network.generation', {minimum: 1}),
      manifestDigest,
    };
    resolved.replay = {
      enabled: true, strategy: 'resolved-schedule/v1', sourceScheduleDigest, sourceNetwork,
      disclosure: 'The immutable instructions and images are replayed on a separately identified network; execution interleavings remain nondeterministic.',
    };
    const unsigned = copy(resolved);
    delete unsigned.integrity;
    resolved.integrity = {algorithm: 'sha256', digest: sha256Value(unsigned)};
    validateResolvedSchedule(resolved);
    return resolved;
  }
  const spec = object(run.spec ?? run, 'run.spec');
  const raw = array(replayPlan.schedule, 'replayPlan.schedule', {minimum: 1, maximum: 512});
  let priorOffset = -1;
  const actions = [];
  raw.forEach((action, index) => {
    object(action, `replayPlan.schedule[${index}]`);
    integer(action.order, `replayPlan.schedule[${index}].order`, {minimum: 1});
    const offsetMs = integer(action.offsetMs, `replayPlan.schedule[${index}].offsetMs`);
    if (offsetMs < priorOffset) throw new Error('replay offsets must be nondecreasing');
    priorOffset = offsetMs;
    if (action.type === 'cadence-transition') {
      actions.push({order: 0, kind: 'cadence-transition', instructionId: `replay-${action.order}`,
        notBeforeOffsetSeconds: offsetMs / 1000, delayAfterSeconds: 0, payload: copy(action.payload)});
    } else if (action.type === 'fault-decision') {
      const resolved = replayFaultAction(action, index, run, context, offsetMs / 1000);
      if (resolved) actions.push(resolved);
    } else {
      throw new Error(`replay action ${action.type} is not executable`);
    }
  });
  actions.forEach((action, index) => { action.order = index + 1; });
  const usage = usageFor(actions);
  const catalog = normalizeCatalog(spec.campaignCatalog);
  const sequence = normalizeSequence(spec.sequence, catalog);
  const schedule = sealSchedule({
    schemaVersion: ATTACKNET_SCHEDULE_SCHEMA,
    run: {
      name: string(run.metadata?.name ?? context.runName ?? 'attacknet-replay', 'run name'),
      seed: string(spec.seed, 'run.spec.seed'),
      decisionAlgorithm: spec.decisionAlgorithm ?? DECISION_ALGORITHM,
    },
    network: {
      name: string(spec.networkRef, 'run.spec.networkRef'),
      uid: string(context.network?.uid, 'context.network.uid'),
      generation: integer(context.network?.generation, 'context.network.generation', {minimum: 1}),
      manifestDigest: sha256Value(context.manifest),
    },
    catalogDigest: sha256Value(catalog), sequenceDigest: sha256Value(sequence),
    imageConstraints: normalizeImages(context.images), actions,
    budgets: validateBudgetUsage(usage, spec.budgets),
    replay: {
      enabled: true,
      strategy: string(replayPlan.strategy, 'replayPlan.strategy'),
      derivedFrom: copy(object(replayPlan.derivedFrom, 'replayPlan.derivedFrom')),
      expectedFailure: copy(object(replayPlan.expectedFailure, 'replayPlan.expectedFailure')),
      disclosure: string(replayPlan.disclosure, 'replayPlan.disclosure'),
    },
  });
  validateResolvedSchedule(schedule);
  return schedule;
}

function dimensionState(kind, actionIndex, items) {
  return {kind, actionIndex, items: [...items], granularity: 2, cursor: 0, round: 1, reproduced: false};
}

function firstDimension(schedule) {
  const campaigns = schedule.actions.filter(action => action.kind === 'fault-campaign').map(action => action.instructionId);
  return dimensionState('campaigns', null, campaigns);
}

function followingDimension(plan, current) {
  const faults = plan.candidate.actions.filter(action => action.kind === 'fault-campaign');
  if (current.kind === 'campaigns') {
    const first = faults.findIndex(action => action.resolved.targets.length > 1);
    if (first >= 0) return dimensionState('targets', first, faults[first].resolved.targets);
  }
  if (current.kind === 'targets') {
    const next = faults.findIndex((action, index) => index > current.actionIndex && action.resolved.targets.length > 1);
    if (next >= 0) return dimensionState('targets', next, faults[next].resolved.targets);
  }
  const start = current.kind === 'parameters' ? current.actionIndex + 1 : 0;
  const nextParameters = faults.findIndex((action, index) => index >= start
    && Object.keys(action.resolved.parameters).length > 0);
  if (nextParameters >= 0) {
    return dimensionState('parameters', nextParameters,
      Object.keys(faults[nextParameters].resolved.parameters).sort());
  }
  return null;
}

function chunks(items, count) {
  const result = [];
  for (let index = 0; index < count; index += 1) {
    const start = Math.floor(index * items.length / count);
    const end = Math.floor((index + 1) * items.length / count);
    if (start < end) result.push(items.slice(start, end));
  }
  return result;
}

function materializeCandidate(plan, removed) {
  const candidate = copy(plan.candidate);
  const state = plan.dimension;
  if (state.kind === 'campaigns') {
    const removedSet = new Set(removed);
    candidate.actions = candidate.actions.filter(action => action.kind !== 'fault-campaign'
      || !removedSet.has(action.instructionId));
  } else {
    const faults = candidate.actions.filter(action => action.kind === 'fault-campaign');
    const action = faults[state.actionIndex];
    if (!action) throw new Error('ddmin dimension action no longer exists');
    if (state.kind === 'targets') {
      const removedSet = new Set(removed);
      action.resolved.targets = action.resolved.targets.filter(target => !removedSet.has(target));
      action.resolved.campaignSpec.target = {actors: [...action.resolved.targets], roles: []};
    } else {
      for (const key of removed) delete action.resolved.parameters[key];
      action.resolved.campaignSpec.fault.parameters = copy(action.resolved.parameters);
    }
    action.resolved.campaignSpecDigest = sha256Value(action.resolved.campaignSpec);
  }
  candidate.actions.forEach((action, index) => { action.order = index + 1; });
  candidate.budgets = validateBudgetUsage(usageFor(candidate.actions), candidate.budgets.limits);
  const unsigned = copy(candidate);
  delete unsigned.integrity;
  candidate.integrity = {algorithm: 'sha256', digest: sha256Value(unsigned)};
  return candidate;
}

function sealCandidate(candidate) {
  candidate.actions.forEach((action, index) => { action.order = index + 1; });
  candidate.budgets = validateBudgetUsage(usageFor(candidate.actions), candidate.budgets.limits);
  const unsigned = copy(candidate);
  delete unsigned.integrity;
  candidate.integrity = {algorithm: 'sha256', digest: sha256Value(unsigned)};
  return candidate;
}

/**
 * Describe a candidate exclusively as removals from an immutable source
 * schedule. The controller accepts this compact description instead of an
 * arbitrary schedule supplied by the host-side minimizer.
 */
export function describeDdminCandidate(sourceSchedule, candidateSchedule) {
  validateResolvedSchedule(sourceSchedule);
  validateResolvedSchedule(candidateSchedule);
  const sourceByInstruction = new Map(sourceSchedule.actions.map(action => [action.instructionId, action]));
  const retained = [];
  for (const action of candidateSchedule.actions) {
    const source = sourceByInstruction.get(action.instructionId);
    if (!source || source.kind !== 'fault-campaign' || action.kind !== 'fault-campaign') {
      throw new Error(`ddmin candidate action ${action.instructionId} is not a source fault action`);
    }
    const sourceTargets = new Set(source.resolved.targets);
    if (action.resolved.targets.some(target => !sourceTargets.has(target))) {
      throw new Error(`ddmin candidate ${action.instructionId} adds a target`);
    }
    const sourceKeys = new Set(Object.keys(source.resolved.parameters));
    if (Object.keys(action.resolved.parameters).some(key => !sourceKeys.has(key))) {
      throw new Error(`ddmin candidate ${action.instructionId} adds a parameter`);
    }
    retained.push({
      instructionId: action.instructionId,
      removedTargets: source.resolved.targets.filter(target => !action.resolved.targets.includes(target)),
      removedParameters: Object.keys(source.resolved.parameters)
        .filter(key => !(key in action.resolved.parameters)).sort(),
    });
  }
  const reduction = {
    sourceScheduleDigest: sourceSchedule.integrity.digest,
    candidateScheduleDigest: candidateSchedule.integrity.digest,
    retained,
  };
  const reconstructed = applyDdminReduction(sourceSchedule, reduction);
  if (reconstructed.integrity.digest !== candidateSchedule.integrity.digest) {
    throw new Error('ddmin candidate contains changes other than permitted removals');
  }
  return reduction;
}

function applyDdminReduction(sourceSchedule, reduction) {
  object(reduction, 'ddmin reduction');
  if (digest(reduction.sourceScheduleDigest, 'ddmin reduction sourceScheduleDigest')
      !== sourceSchedule.integrity.digest) {
    throw new Error('ddmin reduction source schedule digest does not match');
  }
  const descriptors = array(reduction.retained, 'ddmin reduction retained', {minimum: 1, maximum: 256});
  const sourceByInstruction = new Map(sourceSchedule.actions.map(action => [action.instructionId, action]));
  const sourceOrder = new Map(sourceSchedule.actions.map((action, index) => [action.instructionId, index]));
  const seen = new Set();
  let priorSourceOrder = -1;
  const candidate = copy(sourceSchedule);
  candidate.actions = descriptors.map((descriptor, index) => {
    object(descriptor, `ddmin reduction retained[${index}]`);
    const instructionId = string(descriptor.instructionId, `ddmin reduction retained[${index}].instructionId`);
    if (seen.has(instructionId)) throw new Error(`duplicate ddmin instruction ${instructionId}`);
    seen.add(instructionId);
    const source = sourceByInstruction.get(instructionId);
    if (!source || source.kind !== 'fault-campaign') {
      throw new Error(`ddmin reduction references unknown fault action ${instructionId}`);
    }
    if (sourceOrder.get(instructionId) <= priorSourceOrder) {
      throw new Error('ddmin reduction may not reorder source actions');
    }
    priorSourceOrder = sourceOrder.get(instructionId);
    const action = copy(source);
    const removedTargets = unique(array(descriptor.removedTargets ?? [],
      `ddmin reduction ${instructionId}.removedTargets`, {maximum: 256}).map(String),
    `ddmin reduction ${instructionId}.removedTargets`);
    const sourceTargets = new Set(source.resolved.targets);
    if (removedTargets.some(target => !sourceTargets.has(target))) {
      throw new Error(`ddmin reduction ${instructionId} removes an unknown target`);
    }
    if (removedTargets.length > 0) {
      action.resolved.targets = source.resolved.targets.filter(target => !removedTargets.includes(target));
      if (action.resolved.targets.length === 0) throw new Error(`ddmin reduction ${instructionId} removes every target`);
      action.resolved.campaignSpec.target = {actors: [...action.resolved.targets], roles: []};
    }
    const removedParameters = unique(array(descriptor.removedParameters ?? [],
      `ddmin reduction ${instructionId}.removedParameters`, {maximum: 256}).map(String),
    `ddmin reduction ${instructionId}.removedParameters`);
    const sourceParameters = new Set(Object.keys(source.resolved.parameters));
    if (removedParameters.some(key => !sourceParameters.has(key))) {
      throw new Error(`ddmin reduction ${instructionId} removes an unknown parameter`);
    }
    if (removedParameters.length > 0) {
      for (const key of removedParameters) delete action.resolved.parameters[key];
      action.resolved.campaignSpec.fault.parameters = copy(action.resolved.parameters);
    }
    action.resolved.campaignSpecDigest = sha256Value(action.resolved.campaignSpec);
    return action;
  });
  return sealCandidate(candidate);
}

/**
 * Validate a host-issued ddmin reduction against the terminal source run and
 * bind the admitted candidate to a separately identified fresh network.
 */
export function consumeDdminCandidate(reduction, sourceSchedule, context) {
  validateResolvedSchedule(sourceSchedule);
  object(context, 'context');
  const candidate = applyDdminReduction(sourceSchedule, reduction);
  if (candidate.integrity.digest === sourceSchedule.integrity.digest) {
    throw new Error('ddmin counterfactual must remove at least one campaign, target, or parameter');
  }
  if (digest(reduction.candidateScheduleDigest, 'ddmin reduction candidateScheduleDigest')
      !== candidate.integrity.digest) {
    throw new Error('ddmin reduction candidate digest does not match permitted source removals');
  }
  const manifest = copy(object(context.manifest, 'context.manifest'));
  const manifestDigest = sha256Value(manifest);
  if (manifestDigest !== sourceSchedule.network.manifestDigest) {
    throw new Error('ddmin candidate network manifest differs from the source schedule');
  }
  const images = normalizeImages(context.images);
  if (canonicalJson(images) !== canonicalJson(sourceSchedule.imageConstraints)) {
    throw new Error('ddmin candidate resolved images differ from the source schedule');
  }
  const sources = normalizeSources(context.campaigns);
  // Removed campaigns remain part of the immutable experimental input set.
  // Require every source template, not only templates retained by this
  // counterfactual, so the host cannot combine reduction with source drift.
  for (const action of sourceSchedule.actions.filter(item => item.kind === 'fault-campaign')) {
    const source = sources.get(action.source.name);
    if (!source || source.metadata.uid !== action.source.uid
        || source.metadata.generation !== action.source.generation
        || sha256Value(source.spec) !== action.source.specDigest) {
      throw new Error(`ddmin candidate source ${action.source.name} no longer satisfies immutable constraints`);
    }
  }
  const uid = string(context.network?.uid, 'context.network.uid');
  if (uid === sourceSchedule.network.uid) throw new Error('ddmin candidate requires a fresh network UID');
  candidate.network = {
    name: sourceSchedule.network.name,
    uid,
    generation: integer(context.network?.generation, 'context.network.generation', {minimum: 1}),
    manifestDigest,
  };
  candidate.replay = {
    enabled: true,
    strategy: 'deterministic-hierarchical-ddmin/v1',
    sourceScheduleDigest: sourceSchedule.integrity.digest,
    sourceNetwork: copy(sourceSchedule.network),
    candidateScheduleDigest: reduction.candidateScheduleDigest,
    disclosure: 'This is a permitted removal-only counterfactual on a fresh network; it does not establish causal minimality.',
  };
  return sealCandidate(candidate);
}

function advanceDimension(plan) {
  let next = followingDimension(plan, plan.dimension);
  while (next && next.items.length <= (next.kind === 'parameters' ? 0 : 1)) next = followingDimension(plan, next);
  plan.dimension = next;
  if (!next) {
    plan.phase = plan.attempts.some(attempt => attempt.outcome === 'Inconclusive')
      ? 'Inconclusive' : 'Complete';
    plan.result = {
      scheduleDigest: plan.candidate.integrity.digest,
      empiricallyReduced: plan.candidate.integrity.digest !== plan.baselineScheduleDigest,
      oneMinimalUnderObservedCounterfactuals: plan.phase === 'Complete',
      causalMinimalityClaimed: false,
      statement: 'The candidate is reduced only under recorded fresh-network counterfactual reruns; this plan does not establish causal minimality.',
    };
  }
}

export function createDdminPlan(schedule, options = {}) {
  validateResolvedSchedule(schedule);
  if (options.requireFreshNetwork !== true) throw new Error('ddmin requires requireFreshNetwork=true');
  if (!schedule.actions.some(action => action.kind === 'fault-campaign')) {
    throw new Error('ddmin requires at least one fault-campaign action');
  }
  const maxAttempts = integer(options.maxAttempts ?? 64, 'maxAttempts', {minimum: 1, maximum: 256});
  const expectedFailure = object(options.expectedFailure, 'expectedFailure');
  const plan = {
    schemaVersion: ATTACKNET_DDMIN_SCHEMA,
    strategy: 'deterministic-hierarchical-ddmin/v1',
    phase: 'Planning',
    baselineScheduleDigest: schedule.integrity.digest,
    expectedFailure: {
      assertion: string(expectedFailure.assertion, 'expectedFailure.assertion'),
      status: string(expectedFailure.status, 'expectedFailure.status'),
    },
    freshNetworkRequirement: {
      required: true,
      cleanStateRequired: true,
      uniqueNetworkUIDPerAttempt: true,
      sameResolvedImagesRequired: true,
      sameNetworkManifestDigestRequired: true,
    },
    maxAttempts,
    candidate: copy(schedule),
    dimension: firstDimension(schedule),
    pendingAttempt: null,
    attempts: [],
    result: {
      empiricallyReduced: false,
      oneMinimalUnderObservedCounterfactuals: false,
      causalMinimalityClaimed: false,
      statement: 'No reduction claim exists until candidate removals are rerun on fresh networks.',
    },
  };
  if (plan.dimension.items.length <= 1) advanceDimension(plan);
  return plan;
}

function ddminAttemptId(plan, candidate, removed) {
  return `ddmin-${String(plan.attempts.length + 1).padStart(3, '0')}-${sha256Value({
    baseline: plan.baselineScheduleDigest, dimension: plan.dimension.kind,
    actionIndex: plan.dimension.actionIndex, removed, candidate: candidate.integrity.digest,
  }).slice(7, 19)}`;
}

export function issueDdminAttempt(input) {
  const plan = copy(object(input, 'plan'));
  if (plan.schemaVersion !== ATTACKNET_DDMIN_SCHEMA) throw new Error('unsupported ddmin schema');
  if (plan.pendingAttempt) throw new Error('record the pending ddmin attempt before issuing another');
  if (new Set(['Complete', 'Inconclusive', 'BudgetExhausted']).has(plan.phase)) return {plan, attempt: null};
  if (plan.attempts.length >= plan.maxAttempts) {
    plan.phase = 'BudgetExhausted';
    plan.result.statement = 'The minimization attempt budget was exhausted; no minimality claim is valid.';
    return {plan, attempt: null};
  }
  if (!plan.dimension) {
    plan.phase = 'Complete';
    return {plan, attempt: null};
  }
  const state = plan.dimension;
  const partitions = chunks(state.items, Math.min(state.granularity, state.items.length));
  if (state.cursor >= partitions.length) throw new Error('ddmin cursor exceeds its partition round');
  const removed = partitions[state.cursor];
  const candidate = materializeCandidate(plan, removed);
  const attempt = {
    id: ddminAttemptId(plan, candidate, removed),
    ordinal: plan.attempts.length + 1,
    counterfactual: {
      dimension: state.kind,
      instructionId: state.actionIndex === null ? null
        : plan.candidate.actions.filter(action => action.kind === 'fault-campaign')[state.actionIndex].instructionId,
      removed,
      hypothesis: `The expected failure still occurs without ${state.kind} ${removed.join(', ')}.`,
    },
    schedule: candidate,
    expectedFailure: copy(plan.expectedFailure),
    freshNetworkRequirement: copy(plan.freshNetworkRequirement),
    requiresAdmissionValidation: true,
    outcome: null,
  };
  plan.pendingAttempt = {id: attempt.id, candidateDigest: candidate.integrity.digest,
    removed, dimension: state.kind, actionIndex: state.actionIndex};
  plan.phase = 'AwaitingCounterfactual';
  return {plan, attempt};
}

function validateFreshNetwork(plan, result) {
  const fresh = object(result.freshNetwork, 'result.freshNetwork');
  if (fresh.cleanStart !== true) throw new Error('ddmin result must attest freshNetwork.cleanStart=true');
  const uid = string(fresh.uid, 'result.freshNetwork.uid');
  if (uid === plan.candidate.network.uid) throw new Error('ddmin attempt must use a network UID different from the source candidate');
  if (plan.attempts.some(attempt => attempt.freshNetwork.uid === uid)) {
    throw new Error(`fresh network UID ${uid} was already used by another ddmin attempt`);
  }
  if (digest(fresh.manifestDigest, 'result.freshNetwork.manifestDigest') !== plan.candidate.network.manifestDigest) {
    throw new Error('ddmin fresh network manifest digest differs from the candidate');
  }
  const imagesDigest = digest(fresh.imagesDigest, 'result.freshNetwork.imagesDigest');
  if (imagesDigest !== sha256Value(plan.candidate.imageConstraints)) {
    throw new Error('ddmin fresh network images differ from the candidate image constraints');
  }
  return {uid, cleanStart: true, manifestDigest: fresh.manifestDigest, imagesDigest};
}

export function recordDdminOutcome(input, result) {
  const plan = copy(object(input, 'plan'));
  object(result, 'result');
  if (!plan.pendingAttempt || plan.phase !== 'AwaitingCounterfactual') throw new Error('ddmin plan has no pending attempt');
  if (result.attemptId !== plan.pendingAttempt.id) throw new Error('ddmin result does not match pending attempt');
  if (!OUTCOMES.has(result.outcome)) throw new Error(`unsupported ddmin outcome ${result.outcome}`);
  const freshNetwork = validateFreshNetwork(plan, result);
  const observed = object(result.observed, 'result.observed');
  const evidenceDigest = digest(result.evidenceDigest, 'result.evidenceDigest');
  if (result.outcome === 'FailureReproduced') {
    if (observed.assertion !== plan.expectedFailure.assertion || observed.status !== plan.expectedFailure.status) {
      throw new Error('reproduced outcome must match the expected failure assertion and status');
    }
  }
  const pending = plan.pendingAttempt;
  const candidate = materializeCandidate(plan, pending.removed);
  if (candidate.integrity.digest !== pending.candidateDigest) throw new Error('pending ddmin candidate digest is not reproducible');
  plan.attempts.push({
    id: pending.id, ordinal: plan.attempts.length + 1, dimension: pending.dimension,
    instructionId: pending.actionIndex === null ? null
      : plan.candidate.actions.filter(action => action.kind === 'fault-campaign')[pending.actionIndex].instructionId,
    removed: pending.removed, candidateDigest: pending.candidateDigest,
    outcome: result.outcome, observed: copy(observed), evidenceDigest, freshNetwork,
  });
  plan.pendingAttempt = null;
  plan.phase = 'Planning';
  const state = plan.dimension;
  const partitionCount = chunks(state.items, Math.min(state.granularity, state.items.length)).length;
  if (result.outcome === 'FailureReproduced') {
    plan.candidate = candidate;
    state.items = state.items.filter(item => !pending.removed.includes(item));
    state.granularity = Math.max(2, state.granularity - 1);
    state.cursor = 0;
    state.round += 1;
    state.reproduced = true;
    if (state.items.length <= (state.kind === 'parameters' ? 0 : 1)) advanceDimension(plan);
  } else {
    state.cursor += 1;
    if (state.cursor >= partitionCount) {
      if (state.granularity >= state.items.length) {
        advanceDimension(plan);
      } else {
        state.granularity = Math.min(state.items.length, state.granularity * 2);
        state.cursor = 0;
        state.round += 1;
      }
    }
  }
  return plan;
}

function atomicWrite(path, value) {
  const temporary = join(dirname(path), `.${path.split('/').at(-1)}.${process.pid}.tmp`);
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {mode: 0o600});
  renameSync(temporary, path);
}

function output(path, value) {
  if (path) atomicWrite(path, value);
  else process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function runScheduleCli(argv) {
  const [command, inputPath, outputPath] = argv;
  if (!command || !inputPath) {
    throw new Error('usage: attacknet-run-schedule.mjs resolve|replay|ddmin-init|ddmin-next|ddmin-record INPUT [OUTPUT]');
  }
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  let result;
  if (command === 'resolve') result = resolveAttacknetSchedule(input.run, input.context);
  else if (command === 'replay') result = consumeReplayPlan(input.replayPlan, input.run, input.context);
  else if (command === 'ddmin-init') result = createDdminPlan(input.schedule, input.options);
  else if (command === 'ddmin-next') result = issueDdminAttempt(input.plan ?? input);
  else if (command === 'ddmin-record') result = recordDdminOutcome(input.plan, input.result);
  else throw new Error(`unknown command ${command}`);
  output(outputPath, result);
  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { runScheduleCli(process.argv.slice(2)); }
  catch (error) {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  }
}
