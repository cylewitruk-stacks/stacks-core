import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const chart = join(here, '..');

function load(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

const faultCRD = load(join(here, 'testing.stacks.org_faultcampaigns.yaml'));
const runCRD = load(join(here, 'testing.stacks.org_attacknetruns.yaml'));
const faultExample = load(join(chart, 'examples', 'fault-campaign.json'));
const runExample = load(join(chart, 'examples', 'attacknet-run.json'));

function schema(crd) {
  return crd.spec.versions.find(version => version.storage).schema.openAPIV3Schema;
}

function equal(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validate(value, candidate, path = '$') {
  const errors = [];
  const fail = message => errors.push(`${path}: ${message}`);
  if (candidate.nullable && value === null) return errors;
  if (candidate['x-kubernetes-preserve-unknown-fields']) return errors;
  if (candidate.enum && !candidate.enum.some(item => equal(item, value))) {
    fail(`not in enum ${JSON.stringify(candidate.enum)}`);
    return errors;
  }
  if (candidate.type === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      fail('must be an object');
      return errors;
    }
    for (const field of candidate.required ?? []) {
      if (!Object.hasOwn(value, field)) errors.push(`${path}.${field}: is required`);
    }
    if (candidate.additionalProperties === false) {
      for (const field of Object.keys(value)) {
        if (!Object.hasOwn(candidate.properties ?? {}, field)) errors.push(`${path}.${field}: unknown property`);
      }
    }
    for (const [field, child] of Object.entries(candidate.properties ?? {})) {
      if (Object.hasOwn(value, field)) errors.push(...validate(value[field], child, `${path}.${field}`));
    }
    return errors;
  }
  if (candidate.type === 'array') {
    if (!Array.isArray(value)) {
      fail('must be an array');
      return errors;
    }
    if (candidate.minItems !== undefined && value.length < candidate.minItems) fail(`has fewer than ${candidate.minItems} items`);
    if (candidate.maxItems !== undefined && value.length > candidate.maxItems) fail(`has more than ${candidate.maxItems} items`);
    if (candidate.uniqueItems && new Set(value.map(item => JSON.stringify(item))).size !== value.length) fail('contains duplicate items');
    value.forEach((item, index) => errors.push(...validate(item, candidate.items, `${path}[${index}]`)));
    return errors;
  }
  const typeValid = {
    string: typeof value === 'string',
    integer: Number.isSafeInteger(value),
    number: typeof value === 'number' && Number.isFinite(value),
    boolean: typeof value === 'boolean',
  }[candidate.type];
  if (!typeValid) {
    fail(`must be ${candidate.type}`);
    return errors;
  }
  if (candidate.type === 'string') {
    if (candidate.minLength !== undefined && value.length < candidate.minLength) fail(`is shorter than ${candidate.minLength}`);
    if (candidate.maxLength !== undefined && value.length > candidate.maxLength) fail(`is longer than ${candidate.maxLength}`);
    if (candidate.pattern && !new RegExp(candidate.pattern).test(value)) fail(`does not match ${candidate.pattern}`);
  }
  if (candidate.minimum !== undefined && value < candidate.minimum) fail(`is below ${candidate.minimum}`);
  if (candidate.maximum !== undefined && value > candidate.maximum) fail(`is above ${candidate.maximum}`);
  if (candidate.not?.enum?.some(item => equal(item, value))) fail(`matches prohibited value ${JSON.stringify(value)}`);
  return errors;
}

function clone(value) {
  return structuredClone(value);
}

function walkSchema(candidate, path = '$', nodes = []) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return nodes;
  nodes.push({candidate, path});
  for (const [name, child] of Object.entries(candidate.properties ?? {})) {
    walkSchema(child, `${path}.properties.${name}`, nodes);
  }
  if (candidate.items) walkSchema(candidate.items, `${path}.items`, nodes);
  if (candidate.additionalProperties && typeof candidate.additionalProperties === 'object') {
    walkSchema(candidate.additionalProperties, `${path}.additionalProperties`, nodes);
  }
  for (const [index, child] of (candidate.anyOf ?? []).entries()) {
    walkSchema(child, `${path}.anyOf[${index}]`, nodes);
  }
  return nodes;
}

function assertKubernetesCompatibleSchema(crd) {
  const root = schema(crd);
  const nodes = walkSchema(root);
  for (const {candidate, path} of nodes) {
    if (candidate.properties) {
      assert.notEqual(
        candidate.additionalProperties,
        false,
        `${path} combines properties with additionalProperties=false`,
      );
    }
    assert.equal(candidate.uniqueItems, undefined, `${path} uses CRD-costly uniqueItems`);
    if (candidate.type === 'array') {
      assert.ok(Number.isInteger(candidate.maxItems), `${path} must remain bounded by maxItems`);
    }
  }
  assert.doesNotMatch(JSON.stringify(root), /oldSelf/, 'transition CEL must remain out of the CRD schema');
}

test('FaultCampaign is a namespaced status API with bounded evidence phases', () => {
  assert.equal(faultCRD.spec.scope, 'Namespaced');
  assert.equal(faultCRD.spec.group, 'testing.stacks.org');
  assert.deepEqual(faultCRD.spec.versions.map(version => version.name), ['v1alpha1']);
  assert.deepEqual(faultCRD.spec.versions[0].subresources, {status: {}});
  const root = schema(faultCRD);
  assert.deepEqual(root.properties.status.properties.phase.enum, [
    'Pending', 'Admitted', 'Injecting', 'Active', 'Recovering', 'Passed', 'Failed', 'Inconclusive',
  ]);
  for (const field of ['resolvedTargets', 'actualInjection', 'effectResults', 'recoveryResults', 'cleanup', 'evidenceURI']) {
    assert.ok(root.properties.status.properties[field], `missing status.${field}`);
  }
  assert.equal(root.properties.spec.properties.fault.properties.duration.type, 'string');
  assert.equal(root.properties.spec.properties.fault.properties.duration.pattern, '^[0-9]+(ms|s|m|h)$');
  assert.equal(root.properties.spec.properties.safety.properties.maxUnavailableSignerPercent.type, 'number');
  assert.equal(root.properties.spec.properties.effectAssertions.maxItems, 16);
  assert.deepEqual(root.properties.spec.properties.effectAssertions.items.required, ['type']);
  assert.equal(root.properties.spec.properties.recoveryAssertions.maxItems, 16);
});

test('valid FaultCampaign example satisfies the structural OpenAPI subset', () => {
  assert.deepEqual(validate(faultExample, schema(faultCRD)), []);
  const withoutAssertions = clone(faultExample);
  delete withoutAssertions.spec.effectAssertions;
  delete withoutAssertions.spec.recoveryAssertions;
  assert.deepEqual(validate(withoutAssertions, schema(faultCRD)), []);
});

test('FaultCampaign status accepts the bounded controller evidence contract', () => {
  const value = clone(faultExample);
  value.status = {
    observedGeneration: 2, phase: 'Passed', reason: 'EffectAndRecoveryProven',
    lastTransitionTime: '2026-08-15T02:00:00Z',
    admission: {
      networkUid: '7ac3', networkGeneration: 1, compiledDigest: `sha256:${'a'.repeat(64)}`,
      admittedAt: '2026-08-15T01:59:00Z',
      signerImpact: {totalWeight: 19, affectedWeight: 0, percent: 0},
      minerImpact: {totalCount: 3, affectedCount: 1, percent: 33.333},
    },
    resolvedTargets: [{
      actor: 'miner-2', role: 'miner', pod: 'attacknet-miner-2-0', podUid: 'pod-uid',
      node: 'kind-worker', requestedImage: null, resolvedImageId: 'docker://sha256:abc', restartCount: 0,
    }],
    chaos: {kind: 'NetworkChaos', name: 'miner-delay-template', uid: 'chaos-uid', createdAt: '2026-08-15T01:59:05Z'},
    injectedAt: '2026-08-15T01:59:06Z',
    actualInjection: {allInjectedObserved: true, chaosResourceVersion: '42', records: null},
    cleanup: {absent: true, allRecovered: true, observedAt: '2026-08-15T02:00:00Z'},
    effectResults: [{assertion: 'NetworkDegraded', outcome: 'Proven', actor: 'miner-2', podUid: 'pod-uid', observedAt: '2026-08-15T01:59:10Z'}],
    recoveryResults: [{assertion: 'TargetReady', outcome: 'Proven', actor: 'miner-2', podUid: 'pod-uid', observedAt: '2026-08-15T02:00:00Z'}],
    completedAt: '2026-08-15T02:00:00Z', evidenceURI: 'file:///evidence/campaign.json',
  };
  assert.deepEqual(validate(value, schema(faultCRD)), []);
});

test('FaultCampaign schema rejects unbounded and weakly typed agent input', () => {
  let value = clone(faultExample);
  value.spec.fault.duration = '601seconds';
  assert.match(validate(value, schema(faultCRD)).join('\n'), /duration: does not match/);

  value = clone(faultExample);
  value.spec.safety.maxUnavailableSignerPercent = 'not-a-number';
  assert.match(validate(value, schema(faultCRD)).join('\n'), /maxUnavailableSignerPercent: must be number/);

  value = clone(faultExample);
  value.spec.effectAssertions = [{type: 'RunArbitraryCommand'}];
  assert.match(validate(value, schema(faultCRD)).join('\n'), /effectAssertions\[0\]\.type: not in enum/);
});

test('FaultCampaign uses Kubernetes-compatible pruning and bounded arrays', () => {
  assertKubernetesCompatibleSchema(faultCRD);
  const value = clone(faultExample);
  value.spec.fault.parameters.network = {externalTargets: ['203.0.113.1']};
  assert.deepEqual(validate(value, schema(faultCRD)), []);
  assert.equal(
    schema(faultCRD).properties.spec.properties.fault.properties.parameters['x-kubernetes-preserve-unknown-fields'],
    undefined,
    'undeclared parameters must be pruned before compiler admission',
  );
});

test('FaultCampaign CEL rules cover mode, action, parameter, and burnchain constraints', () => {
  const spec = schema(faultCRD).properties.spec;
  const rules = [
    ...(spec['x-kubernetes-validations'] ?? []),
    ...(spec.properties.fault['x-kubernetes-validations'] ?? []),
    ...(spec.properties.safety['x-kubernetes-validations'] ?? []),
  ].map(item => item.message).join('\n');
  for (const expected of [
    'fixed modes require value', 'invalid pod fault action',
    'I/O fault requires parameters.errno', 'burnchain role selection requires allowBurnchain',
    'signer impact above 30 percent', 'faults longer than 10m require allowExtendedDuration',
  ]) assert.match(rules, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.equal(
    spec.properties.fault.properties.parameters.properties.delay['x-kubernetes-preserve-unknown-fields'],
    true,
    'network-object/IO-string delay is intentionally validated by the compiler because CEL cannot type both shapes',
  );
});

test('AttacknetRun is a namespaced status API with a finite referenced catalog', () => {
  assert.equal(runCRD.spec.scope, 'Namespaced');
  assert.deepEqual(runCRD.spec.versions[0].subresources, {status: {}});
  const root = schema(runCRD);
  const spec = root.properties.spec;
  assert.equal(spec.properties.campaignCatalog.maxItems, 64);
  assert.equal(spec.properties.sequence.maxItems, 256);
  assert.deepEqual(spec.properties.budgets.properties.maxActiveFaults.enum, [1]);
  for (const field of ['activeChild', 'resolvedCampaigns', 'decisions', 'budgetUsage', 'attribution', 'evidenceURI']) {
    assert.ok(root.properties.status.properties[field], `missing status.${field}`);
  }
});

test('valid AttacknetRun example satisfies the structural OpenAPI subset', () => {
  assert.deepEqual(validate(runExample, schema(runCRD)), []);
});

test('AttacknetRun status accepts serialized controller decisions and budget evidence', () => {
  const value = clone(runExample);
  value.status = {
    observedGeneration: 1, phase: 'Passed', reason: 'SequenceCompleted',
    lastTransitionTime: '2026-08-15T02:10:00Z', startedAt: '2026-08-15T02:00:00Z',
    completedAt: '2026-08-15T02:10:00Z', activeCampaign: null,
    decisions: [{index: 0, execution: 'bounded-miner-delay-1-delay-miner-once', phase: 'Passed', completedAt: '2026-08-15T02:09:00Z', source: 'miner-delay-template'}],
    budgetUsage: {
      campaigns: 1, campaignsStarted: 1, campaignsCompleted: 1, activeFaults: 0,
      wallTimeSeconds: 600, cumulativeFaultSeconds: 45, maximumSignerImpactPercent: 0,
      burnchainFaults: 0, inconclusiveCampaigns: 0, minimizationAttempts: 0,
    },
    attribution: 'NotRequired', evidenceURI: 'file:///evidence/run.json',
  };
  assert.deepEqual(validate(value, schema(runCRD)), []);
});

test('AttacknetRun schema rejects concurrency and empty seeds', () => {
  let value = clone(runExample);
  value.spec.budgets.maxActiveFaults = 2;
  assert.match(validate(value, schema(runCRD)).join('\n'), /maxActiveFaults: not in enum/);

  value = clone(runExample);
  value.spec.seed = '';
  assert.match(validate(value, schema(runCRD)).join('\n'), /seed: is shorter than 1/);
});

test('AttacknetRun uses Kubernetes-compatible pruning and bounded arrays', () => {
  assertKubernetesCompatibleSchema(runCRD);
  const value = clone(runExample);
  value.spec.agentGetsClusterAdmin = true;
  assert.deepEqual(validate(value, schema(runCRD)), []);
  assert.equal(
    schema(runCRD).properties.spec['x-kubernetes-preserve-unknown-fields'],
    undefined,
    'undeclared run controls must be pruned before controller admission',
  );
});

test('AttacknetRun CEL rules bind sequence, budgets, replay, and resume', () => {
  const spec = schema(runCRD).properties.spec;
  const messages = [
    ...(spec['x-kubernetes-validations'] ?? []),
    ...(spec.properties.budgets['x-kubernetes-validations'] ?? []),
    ...(spec.properties.replay['x-kubernetes-validations'] ?? []),
    ...(spec.properties.resume['x-kubernetes-validations'] ?? []),
  ].map(item => item.message).join('\n');
  for (const expected of [
    'ordered sequence exceeds maxCampaigns', 'every sequence campaign must exist',
    'sequence instruction IDs must be unique', 'replay and resume cannot both be enabled',
    'enabled replay requires', 'enabled resume requires',
  ]) assert.match(messages, new RegExp(expected));
});
