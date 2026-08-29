import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {validateBaseline} from './baseline.mjs';
import {buildPhaseZeroPacket} from './phase-zero-packet.mjs';
import {buildOfflineResult} from './offline-result.mjs';
import {
  REVIEW_CONTRACT_SCHEMA,
  REVIEW_PACKET_SCHEMA,
  REVIEW_PACKET_SCHEMA_V1,
  REVIEW_VERDICT_SCHEMA,
  evaluatePhaseGate,
  reviewToolingDigest,
  sealReviewPacket,
  sha256,
  validateReviewPacket,
} from './phase-review.mjs';
import {validateSchema} from './schema-validator.mjs';

const here = new URL('.', import.meta.url).pathname;
const repositoryRoot = new URL('../../../', import.meta.url).pathname;
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
    schemaVersion: contract.schemaVersion === 'stacks-attacknet-phase-review-contract/v1'
      ? REVIEW_PACKET_SCHEMA_V1 : REVIEW_PACKET_SCHEMA,
    ...(contract.reviewId ? {reviewId: contract.reviewId} : {}),
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
  assert.equal(
    [...baseline.evidence, ...baseline.capabilities].some(item => item.id.includes('compose')),
    false,
  );
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

test('tracked amendment gate records resolve and match the baseline', () => {
  const baseline = load(baselinePath);
  const gateRecords = baseline.evidence.filter(item => item.path.endsWith('/gate-result.json'));
  assert.ok(gateRecords.length >= 2, 'approved gate records are missing');
  for (const evidence of gateRecords) {
    assert.doesNotThrow(() => execFileSync(
      'git', ['ls-files', '--error-unmatch', evidence.path],
      {cwd: repositoryRoot, stdio: 'ignore'},
    ), `${evidence.id} must resolve to a tracked gate record`);
  }
  assert.equal(validateBaseline({
    ...baseline,
    evidence: gateRecords,
    capabilities: gateRecords.map((evidence, index) => ({
      id: `gate-record-${index}`,
      status: 'supported',
      evidence: [evidence.id],
    })),
  }, {verifyEvidence: true, root: repositoryRoot}), true);
});

test('deferred baseline capabilities require complete structured reopening records', () => {
  const baseline = load(baselinePath);
  const deferred = baseline.capabilities.find(item => item.status === 'deferred');
  const broken = structuredClone(baseline);
  delete broken.capabilities.find(item => item.id === deferred.id).reopenCondition;
  assert.throws(() => validateBaseline(broken), /reopenCondition/);
  assert(baseline.capabilities.some(item => item.id === 'enterprise-registry-and-identity-federation'));
  for (const [id, status] of [
    ['native-chaos-mesh-stresschaos-arm64', 'capability-rejected'],
    ['cold-start-capacity-reservation', 'not-done'],
    ['actor-egress-network-policy', 'not-done'],
    ['cryptographically-attested-active-probes', 'not-done'],
    ['matching-kubernetes-client-packaging', 'not-done'],
  ]) {
    const capability = baseline.capabilities.find(item => item.id === id);
    assert.equal(capability?.status, status, `${id} was not migrated from the development backlog`);
    assert.ok(capability.reason?.length > 20, `${id} lacks a release-facing limitation reason`);
  }
});

test('the baseline advertises approved A8 capabilities from bound evidence', () => {
  const baseline = load(baselinePath);
  const evidenceId = 'release-1-a8-trusted-observations';
  assert.ok(baseline.evidence.some(item => item.id === evidenceId));
  for (const id of [
    'identity-bound-protocol-observations-and-fail-closed-assertions',
    'teardown-centralized-log-corpus-export',
  ]) {
    const capability = baseline.capabilities.find(item => item.id === id);
    assert.equal(capability?.status, 'supported');
    assert.deepEqual(capability.evidence, [evidenceId]);
  }
});

test('the baseline advertises approved A9 capability from bound evidence', () => {
  const baseline = load(baselinePath);
  const evidenceId = 'release-1-a9-bounded-bitcoin-reorganizations';
  const evidence = baseline.evidence.find(item => item.id === evidenceId);
  assert.deepEqual(evidence, {
    id: evidenceId,
    path: 'contrib/attacknet/evidence-packets/release-1-a9/gate-result.json',
    digest: 'sha256:a1f4794d4a1612e984ee2aa5d3ca819a4d4cdbc1afcd07d4014c989a58330040',
    status: 'passed',
  });
  assert.doesNotThrow(() => execFileSync(
    'git', ['ls-files', '--error-unmatch', evidence.path],
    {cwd: repositoryRoot, stdio: 'ignore'},
  ));
  const bounded = baseline.capabilities.find(
    item => item.id === 'bounded-bitcoin-regtest-reorganization-and-flash-campaigns',
  );
  assert.equal(bounded?.status, 'supported');
  assert.deepEqual(bounded.evidence, [evidenceId]);
  assert.equal(validateBaseline(
    {...baseline, evidence: [evidence], capabilities: [bounded]},
    {verifyEvidence: true, root: repositoryRoot},
  ), true);
});

test('the baseline advertises approved A10 capability from bound evidence', () => {
  const baseline = load(baselinePath);
  const evidenceId = 'release-1-a10-multi-bitcoin-split-views';
  const evidence = baseline.evidence.find(item => item.id === evidenceId);
  assert.deepEqual(evidence, {
    id: evidenceId,
    path: 'contrib/attacknet/evidence-packets/release-1-a10/gate-result.json',
    digest: 'sha256:a2e31bee5ea086d9552f0ea7d50ca74600bff6e7c16876db2d8e3047855986ee',
    status: 'passed',
  });
  assert.doesNotThrow(() => execFileSync(
    'git', ['ls-files', '--error-unmatch', evidence.path],
    {cwd: repositoryRoot, stdio: 'ignore'},
  ));
  const splitViews = baseline.capabilities.find(
    item => item.id === 'multi-bitcoin-follower-split-view-campaigns',
  );
  assert.equal(splitViews?.status, 'supported');
  assert.deepEqual(splitViews.evidence, [evidenceId]);
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
  assert.equal(result.schemaVersion, 'stacks-attacknet-offline-check-result/v1');
  assert.equal(result.status, 'passed');
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

test('the packet verifier CLI validates the declared contract and packet', () => {
  const contract = load(contractPath);
  const packet = sealedPacket(contract);
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-packet-verifier-'));
  const localContract = join(directory, 'contract.json');
  const localPacket = join(directory, 'packet.json');
  writeFileSync(localContract, `${JSON.stringify(contract)}\n`);
  writeFileSync(localPacket, `${JSON.stringify(packet)}\n`);
  const output = JSON.parse(execFileSync(process.execPath, [
    join(here, 'phase-review.mjs'), 'verify-packet',
    `--contract=${localContract}`, `--packet=${localPacket}`,
  ], {encoding: 'utf8'}));
  assert.equal(output.status, 'valid');
  assert.equal(output.packetDigest, packet.binding.digest);
});

test('v1 approvals remain verifiable while v2 makes review IDs mandatory', () => {
  const historical = load(contractPath);
  const historicalPacket = sealedPacket(historical);
  const historicalVerdicts = historical.requiredReviewers
    .map(reviewer => approval(reviewer, historicalPacket));
  assert.equal(evaluatePhaseGate(historical, historicalPacket, historicalVerdicts).reviewId, undefined);
  assert.throws(
    () => sealedPacket({...historical, reviewId: 'not-a-v1-field'}),
    /reviewId is not allowed/,
  );

  const contract = {
    ...historical,
    schemaVersion: REVIEW_CONTRACT_SCHEMA,
    reviewId: 'release-1-amendment-a1',
  };
  const packet = sealedPacket(contract);
  const verdicts = contract.requiredReviewers.map(reviewer => approval(reviewer, packet));
  const result = evaluatePhaseGate(contract, packet, verdicts);
  assert.equal(result.reviewId, contract.reviewId);

  const missingContractId = structuredClone(contract);
  delete missingContractId.reviewId;
  assert.throws(() => sealedPacket(missingContractId), /reviewId/);

  const missingPacketId = structuredClone(packet);
  delete missingPacketId.reviewId;
  delete missingPacketId.binding;
  assert.throws(() => sealReviewPacket(contract, missingPacketId), /reviewId/);

  assert.throws(
    () => sealedPacket(contract, {reviewId: 'release-1-amendment-a2'}),
    /reviewId does not match/,
  );
  const wrongPacketVersion = structuredClone(packet);
  wrongPacketVersion.schemaVersion = REVIEW_PACKET_SCHEMA_V1;
  delete wrongPacketVersion.reviewId;
  delete wrongPacketVersion.binding;
  assert.throws(() => sealReviewPacket(contract, wrongPacketVersion), /schema version does not match/);
});

test('inventory digests use locale-independent UTF-16 code-unit ordering', () => {
  const contract = {
    ...load(contractPath),
    requiredInventory: ['source:z', 'source:a', 'source:A'],
    requirements: ['deterministic-order'],
  };
  const packet = sealedPacket(contract);
  const byId = new Map(packet.inventory.map(item => [item.id, item]));
  const ordered = ['source:A', 'source:a', 'source:z'].map(id => byId.get(id));
  assert.equal(packet.sourceDigest, sha256(ordered));

  const resealed = sealReviewPacket(contract, {
    ...packet,
    inventory: [...packet.inventory].reverse(),
  });
  assert.equal(resealed.sourceDigest, packet.sourceDigest);
});

test('packets identify their exact review tooling and use portable locators', () => {
  const contract = load(contractPath);
  const packet = sealedPacket(contract);
  assert.equal(packet.toolingDigest, reviewToolingDigest());

  const wrongTooling = structuredClone(packet);
  wrongTooling.toolingDigest = `sha256:${'f'.repeat(64)}`;
  wrongTooling.binding.digest = sha256((({binding, ...rest}) => rest)(wrongTooling));
  assert.throws(() => validateReviewPacket(contract, wrongTooling), /requires review tooling.*candidate revision/);

  for (const path of ['/Users/reviewer/evidence.json', '../evidence.json', 'review\\evidence.json']) {
    const invalid = structuredClone(packet);
    invalid.inventory[0].path = path;
    assert.throws(() => sealReviewPacket(contract, invalid), /portable relative locator/);
  }
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
