import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validateBaseline} from './baseline.mjs';
import {buildPhaseZeroPacket} from './phase-zero-packet.mjs';
import {buildOfflineResult} from './offline-result.mjs';
import {
  REVIEW_PACKET_SCHEMA,
  REVIEW_VERDICT_SCHEMA,
  evaluatePhaseGate,
  sealReviewPacket,
  sha256,
  validateReviewPacket,
} from './phase-review.mjs';
import {validateSchema} from './schema-validator.mjs';

const here = new URL('.', import.meta.url).pathname;
const baselinePath = join(here, 'baseline-v1.json');
const contractPath = join(here, 'phase-0-contract.json');
const cleanDigest = `sha256:${createHash('sha256').update('').digest('hex')}`;

function load(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sealedPacket(contract, overrides = {}) {
  const inventory = contract.requiredInventory.map((id, index) => ({
    id,
    kind: id.split(':')[0],
    path: `review/item-${index}`,
    digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
  return sealReviewPacket(contract, {
    schemaVersion: REVIEW_PACKET_SCHEMA,
    phase: contract.phase,
    tier: contract.tier,
    candidate: {
      sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8',
      commitPending: false,
      dirtyPatchDigest: cleanDigest,
    },
    sourceDigest: cleanDigest,
    evidenceDigest: cleanDigest,
    requirements: [...contract.requirements],
    inventory,
    matrix: contract.requirements.map(requirement => ({requirement, evidence: [inventory[0].id], status: 'satisfied'})),
    compatibility: {
      runtimeBehaviorChanged: false,
      kubernetesResourcesChanged: false,
      evidenceInterpretationChanged: false,
      notes: 'Offline-only review contract.',
    },
    limitations: [{id: 'review-attestation', disposition: 'human custody required'}],
    reproduction: ['contrib/attacknet/check.sh'],
    ...overrides,
  });
}

function approval(reviewer, packet, overrides = {}) {
  return {
    schemaVersion: REVIEW_VERDICT_SCHEMA,
    reviewer,
    verdict: 'Approved',
    contractDigest: packet.contractDigest,
    packetDigest: packet.binding.digest,
    sourceDigest: packet.sourceDigest,
    evidenceDigest: packet.evidenceDigest,
    scope: 'complete',
    materialSource: 'direct-read',
    reviewedInventory: packet.inventory.map(item => item.id),
    omissions: [],
    reviewText: 'Reviewed the complete declared packet.',
    ...overrides,
  };
}

test('the tracked release baseline is structurally valid and digest substitution is detected', () => {
  const baseline = load(baselinePath);
  assert.equal(validateBaseline(baseline), true);
  const root = mkdtempSync(join(tmpdir(), 'attacknet-baseline-'));
  const artifact = join(root, 'evidence.json');
  writeFileSync(artifact, '{"passed":true}\n');
  chmodSync(artifact, 0o444);
  const fixture = structuredClone(baseline);
  fixture.evidence = [{
    id: 'fixture', path: 'evidence.json', status: 'passed',
    digest: `sha256:${createHash('sha256').update(readFileSync(artifact)).digest('hex')}`,
  }];
  fixture.capabilities = [{id: 'fixture', status: 'supported', evidence: ['fixture']}];
  assert.equal(validateBaseline(fixture, {verifyEvidence: true, root}), true);
  chmodSync(artifact, 0o644);
  writeFileSync(artifact, '{"passed":false}\n');
  assert.throws(() => validateBaseline(fixture, {verifyEvidence: true, root}), /evidence digest mismatch/);
});

test('deferred baseline capabilities require complete structured reopening records', () => {
  const baseline = load(baselinePath);
  const deferred = baseline.capabilities.find(item => item.status === 'deferred');
  const broken = structuredClone(baseline);
  delete broken.capabilities.find(item => item.id === deferred.id).reopenCondition;
  assert.throws(() => validateBaseline(broken), /reopenCondition/);
  assert(baseline.capabilities.find(item => item.id === 'multi-bitcoin-and-bounded-reorg-campaigns').status === 'not-done');
  assert(baseline.capabilities.some(item => item.id === 'enterprise-registry-and-identity-federation'));
  for (const [id, status] of [
    ['native-chaos-mesh-stresschaos-arm64', 'capability-rejected'],
    ['cold-start-capacity-reservation', 'not-done'],
    ['actor-egress-network-policy', 'not-done'],
    ['cryptographically-attested-active-probes', 'not-done'],
    ['teardown-centralized-log-corpus-export', 'not-done'],
    ['matching-kubernetes-client-packaging', 'not-done'],
  ]) {
    const capability = baseline.capabilities.find(item => item.id === id);
    assert.equal(capability?.status, status, `${id} was not migrated from the development backlog`);
    assert.ok(capability.reason?.length > 20, `${id} lacks a release-facing limitation reason`);
  }
});

test('offline result accepts only complete, unique, observed suite results', () => {
  const result = buildOfflineResult({
    sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8',
    recordedAt: '2026-08-19T00:00:00.000Z',
    suites: [
      'node:3:3:0',
      {name: 'python', tests: 2, passed: 2, failed: 0},
    ],
  });
  assert.equal(result.recordedAt, '2026-08-19T00:00:00.000Z');
  assert.deepEqual(result.suites.map(item => item.name), ['node', 'python']);
  assert.throws(() => buildOfflineResult({
    sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8', suites: ['node:3:2:1'],
  }), /invalid clean suite/);
  assert.throws(() => buildOfflineResult({
    sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8',
    suites: [{name: 'python', tests: 2, passed: 2, failed: 0, skipped: 1}],
  }), /unknown suite field skipped/);
  assert.throws(() => buildOfflineResult({
    sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8', suites: ['node:1:1:0', 'node:1:1:0'],
  }), /suite names must be unique/);
});

test('the phase gate requires two complete approvals over the exact contract and packet', () => {
  const contract = load(contractPath);
  const packet = sealedPacket(contract);
  const codex = approval('Codex', packet);
  const opus = approval('Claude Opus 5', packet);
  assert.equal(evaluatePhaseGate(contract, packet, [codex, opus]).status, 'Approved for Release 1 scope');
  assert.throws(() => evaluatePhaseGate(contract, packet, []), /missing approval/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex]), /missing approval/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, codex, opus]), /duplicate verdict/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {verdict: 'Changes requested'})]), /Changes requested/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {verdict: 'Inconclusive'})]), /Inconclusive/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {packetDigest: `sha256:${'a'.repeat(64)}`})]), /different source or evidence/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {contractDigest: `sha256:${'b'.repeat(64)}`})]), /different contract/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {scope: 'scoped'})]), /scoped or incomplete/);
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, approval('Claude Opus 5', packet, {omissions: ['not-read']})]), /records omissions/);
  const incomplete = approval('Claude Opus 5', packet);
  incomplete.reviewedInventory.pop();
  assert.throws(() => evaluatePhaseGate(contract, packet, [codex, incomplete]), /did not review/);
});

test('empty or modified contracts cannot vacuously close a phase', () => {
  const contract = load(contractPath);
  for (const field of ['requiredReviewers', 'requiredInventory', 'requirements']) {
    const altered = structuredClone(contract);
    altered[field] = [];
    assert.throws(() => validateReviewPacket(altered, sealedPacket(contract)), /at least|non-empty/);
  }
  const packet = sealedPacket(contract);
  const altered = structuredClone(contract);
  altered.requirements.push('invented-requirement');
  assert.throws(() => validateReviewPacket(altered, packet), /contractDigest|omits requirement/);
});

test('schemas reject unknown fields and missing review text', () => {
  const contract = load(contractPath);
  const packet = sealedPacket(contract);
  const unknownPacket = structuredClone(packet);
  unknownPacket.unreviewed = true;
  assert.throws(() => validateReviewPacket(contract, unknownPacket), /not allowed/);
  const verdict = approval('Codex', packet);
  delete verdict.reviewText;
  assert.throws(() => evaluatePhaseGate(contract, packet, [verdict]), /reviewText is required/);
});

test('schema validation fails closed on unsupported or structurally ambiguous keywords', () => {
  assert.throws(
    () => validateSchema({value: 'accepted'}, {
      type: 'object',
      properties: {value: {type: 'string', oneOf: [{const: 'rejected'}]}},
    }),
    /unsupported schema keyword oneOf/,
  );
  assert.throws(
    () => validateSchema({value: 'accepted'}, {properties: {value: {type: 'string'}}}),
    /properties requires explicit type object/,
  );
  assert.throws(
    () => validateSchema(['duplicate', 'duplicate'], {type: 'array', uniqueItems: 'true'}),
    /uniqueItems must be boolean/,
  );
  assert.equal(validateSchema({value: 'accepted'}, {
    type: 'object', additionalProperties: false, required: ['value'],
    properties: {value: {type: 'string', const: 'accepted'}},
  }), true);
  assert.throws(
    () => validateSchema('accepted', {
      $defs: {text: {type: 'string'}},
      $ref: '#/$defs/text',
      const: 'rejected',
    }),
    /must equal "rejected"/,
  );
});

test('matrix, compatibility, inventory kinds, and commit state fail closed', () => {
  const contract = load(contractPath);
  const failed = sealedPacket(contract);
  failed.matrix[0].status = 'failed';
  failed.binding.digest = sha256((({binding, ...rest}) => rest)(failed));
  assert.throws(() => validateReviewPacket(contract, failed), /is failed/);

  assert.throws(() => sealedPacket(contract, {compatibility: {
    runtimeBehaviorChanged: true,
    kubernetesResourcesChanged: false,
    evidenceInterpretationChanged: false,
    notes: 'Must upgrade.',
  }}), /requires Full/);

  const unsupported = sealedPacket(contract);
  unsupported.inventory[0].kind = 'mystery';
  assert.throws(() => sealReviewPacket(contract, unsupported), /kind/);

  const pending = sealedPacket(contract, {candidate: {
    sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8',
    commitPending: true,
    dirtyPatchDigest: `sha256:${'f'.repeat(64)}`,
  }});
  assert.throws(() => evaluatePhaseGate(contract, pending, []), /uncommitted candidate/);
});

test('packet generation can be tested in a clean clone without local evidence archives', () => {
  const contract = load(contractPath);
  const fixtureInventory = contract.requiredInventory.map((id, index) => ({
    id, kind: id.split(':')[0], path: `fixture/${index}`, digest: `sha256:${String(index + 1).padStart(64, '0')}`,
  }));
  const packet = buildPhaseZeroPacket({
    candidate: {sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8', commitPending: false, dirtyPatchDigest: cleanDigest},
    inventory: fixtureInventory,
  });
  assert.equal(validateReviewPacket(contract, packet), true);
  assert.equal(packet.limitations.some(item => item.id === 'uncommitted-candidate'), false);

  const dirty = buildPhaseZeroPacket({
    candidate: {
      sourceRevision: 'e1515979a2dbce6e9de0d842b249d229901a0cc8',
      commitPending: true,
      dirtyPatchDigest: `sha256:${'f'.repeat(64)}`,
    },
    inventory: fixtureInventory,
  });
  assert.equal(dirty.limitations.some(item => item.id === 'uncommitted-candidate'), true);
});
