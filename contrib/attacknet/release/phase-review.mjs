#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {loadSchema, validateSchema} from './schema-validator.mjs';

export const REVIEW_CONTRACT_SCHEMA_V1 = 'stacks-attacknet-phase-review-contract/v1';
export const REVIEW_PACKET_SCHEMA_V1 = 'stacks-attacknet-phase-review-packet/v1';
export const REVIEW_CONTRACT_SCHEMA = 'stacks-attacknet-phase-review-contract/v2';
export const REVIEW_PACKET_SCHEMA = 'stacks-attacknet-phase-review-packet/v2';
export const REVIEW_VERDICT_SCHEMA = 'stacks-attacknet-phase-review-verdict/v1';

const releaseDir = dirname(fileURLToPath(import.meta.url));
const contractSchemas = new Map([
  [REVIEW_CONTRACT_SCHEMA_V1, loadSchema(join(releaseDir, 'review-contract-v1.schema.json'))],
  [REVIEW_CONTRACT_SCHEMA, loadSchema(join(releaseDir, 'review-contract.schema.json'))],
]);
const packetSchemas = new Map([
  [REVIEW_PACKET_SCHEMA_V1, loadSchema(join(releaseDir, 'review-packet-v1.schema.json'))],
  [REVIEW_PACKET_SCHEMA, loadSchema(join(releaseDir, 'review-packet.schema.json'))],
]);
const verdictSchema = loadSchema(join(releaseDir, 'review-verdict.schema.json'));
const REVIEW_TOOLING_FILES = Object.freeze([
  'phase-review.mjs',
  'schema-validator.mjs',
  'review-contract-v1.schema.json',
  'review-contract.schema.json',
  'review-packet-v1.schema.json',
  'review-packet.schema.json',
  'review-verdict.schema.json',
]);
const SOURCE_KINDS = new Set(['source', 'document', 'analysis', 'instructions', 'diff']);
const EVIDENCE_KINDS = new Set(['evidence', 'test']);
const INVENTORY_KINDS = new Set([...SOURCE_KINDS, ...EVIDENCE_KINDS]);

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('review data must be canonical JSON values');
}

export function sha256(value) {
  return `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`;
}

function sha256Bytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function reviewToolingDigest() {
  return sha256(REVIEW_TOOLING_FILES.map(path => ({
    path,
    digest: sha256Bytes(readFileSync(join(releaseDir, path))),
  })));
}

function object(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${field} must be an object`);
  return value;
}

function string(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function digest(value, field) {
  string(value, field);
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`${field} must be a lowercase sha256 digest`);
  return value;
}

function strings(value, field, {nonEmpty = false} = {}) {
  if (!Array.isArray(value) || (nonEmpty && value.length === 0)) throw new Error(`${field} must be a${nonEmpty ? ' non-empty' : 'n'} array`);
  value.forEach((item, index) => string(item, `${field}[${index}]`));
  if (new Set(value).size !== value.length) throw new Error(`${field} contains duplicates`);
  return value;
}

function portableRelativeLocator(value, field) {
  const locator = string(value, field);
  if (locator.startsWith('/') || locator.includes('\\') || locator.split('/').includes('..')) {
    throw new Error(`${field} must be a portable relative locator`);
  }
  return locator;
}

function inventoryIds(packet) {
  if (!Array.isArray(packet.inventory) || packet.inventory.length === 0) throw new Error('packet.inventory must be a non-empty array');
  const ids = packet.inventory.map((item, index) => {
    object(item, `packet.inventory[${index}]`);
    string(item.kind, `packet.inventory[${index}].kind`);
    if (!INVENTORY_KINDS.has(item.kind)) throw new Error(`packet.inventory[${index}].kind is unsupported`);
    portableRelativeLocator(item.path, `packet.inventory[${index}].path`);
    digest(item.digest, `packet.inventory[${index}].digest`);
    return string(item.id, `packet.inventory[${index}].id`);
  });
  if (new Set(ids).size !== ids.length) throw new Error('packet.inventory contains duplicate ids');
  return ids;
}

function scopedInventoryDigest(packet, kinds) {
  return sha256(packet.inventory
    .filter(item => kinds.has(item.kind))
    .map(({id, kind, path, digest: itemDigest}) => ({id, kind, path, digest: itemDigest}))
    // Use the same locale-independent UTF-16 code-unit ordering as
    // Array.prototype.sort() and canonical() above.  localeCompare() depends
    // on the host's locale and ICU build, so it cannot define an artifact
    // digest that independent reviewers must reproduce byte-for-byte.
    .sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
}

function unsignedPacket(packet) {
  const copy = structuredClone(packet);
  delete copy.binding;
  return copy;
}

export function validateReviewPacket(contract, packet) {
  const contractSchema = contractSchemas.get(contract?.schemaVersion);
  const packetSchema = packetSchemas.get(packet?.schemaVersion);
  if (!contractSchema) throw new Error('unsupported review contract schema');
  if (!packetSchema) throw new Error('unsupported review packet schema');
  validateSchema(contract, contractSchema, 'contract');
  validateSchema(packet, packetSchema, 'packet');
  const expectedPacketSchema = contract.schemaVersion === REVIEW_CONTRACT_SCHEMA_V1
    ? REVIEW_PACKET_SCHEMA_V1 : REVIEW_PACKET_SCHEMA;
  if (packet.schemaVersion !== expectedPacketSchema) {
    throw new Error('packet schema version does not match contract schema version');
  }
  digest(packet.toolingDigest, 'packet.toolingDigest');
  const expectedToolingDigest = reviewToolingDigest();
  if (packet.toolingDigest !== expectedToolingDigest) {
    throw new Error(`packet requires review tooling ${packet.toolingDigest}; current tooling is ${expectedToolingDigest}; run the verifier from the candidate revision`);
  }
  if (packet.reviewId !== contract.reviewId) throw new Error('packet reviewId does not match contract');
  if (packet.phase !== contract.phase) throw new Error('packet phase does not match contract');
  object(packet.candidate, 'packet.candidate');
  string(packet.candidate.sourceRevision, 'packet.candidate.sourceRevision');
  if (!/^[0-9a-f]{40}$/.test(packet.candidate.sourceRevision)) {
    throw new Error('packet.candidate.sourceRevision must be an exact 40-character commit');
  }
  if (typeof packet.candidate.commitPending !== 'boolean') throw new Error('packet.candidate.commitPending must be boolean');
  digest(packet.candidate.dirtyPatchDigest, 'packet.candidate.dirtyPatchDigest');
  const expectedContractDigest = sha256(contract);
  if (packet.contractDigest !== expectedContractDigest) throw new Error('packet contractDigest does not match contract');
  digest(packet.sourceDigest, 'packet.sourceDigest');
  digest(packet.evidenceDigest, 'packet.evidenceDigest');
  if (packet.evidenceRoot !== undefined) portableRelativeLocator(packet.evidenceRoot, 'packet.evidenceRoot');
  strings(packet.requirements, 'packet.requirements');
  const ids = new Set(inventoryIds(packet));
  const expectedSource = scopedInventoryDigest(packet, SOURCE_KINDS);
  const expectedEvidence = scopedInventoryDigest(packet, EVIDENCE_KINDS);
  if (packet.sourceDigest !== expectedSource) throw new Error('packet sourceDigest does not match source inventory');
  if (packet.evidenceDigest !== expectedEvidence) throw new Error('packet evidenceDigest does not match evidence inventory');
  const required = strings(contract.requiredInventory, 'contract.requiredInventory', {nonEmpty: true});
  const requirements = strings(contract.requirements, 'contract.requirements', {nonEmpty: true});
  strings(contract.requiredReviewers, 'contract.requiredReviewers', {nonEmpty: true});
  for (const id of required) if (!ids.has(id)) throw new Error(`packet omits required inventory ${id}`);
  for (const requirement of requirements) if (!packet.requirements.includes(requirement)) throw new Error(`packet omits requirement ${requirement}`);
  const matrix = new Map();
  for (const row of packet.matrix) {
    if (matrix.has(row.requirement)) throw new Error(`packet matrix duplicates requirement ${row.requirement}`);
    matrix.set(row.requirement, row);
    for (const evidence of row.evidence) if (!ids.has(evidence)) throw new Error(`packet matrix references unknown evidence ${evidence}`);
    if (row.status === 'not-applicable' && !row.reason) throw new Error(`packet matrix ${row.requirement} requires a reason`);
  }
  for (const requirement of requirements) {
    const row = matrix.get(requirement);
    if (!row) throw new Error(`packet matrix omits requirement ${requirement}`);
    if (row.status !== 'satisfied') throw new Error(`packet requirement ${requirement} is ${row.status}`);
    if (row.evidence.length === 0) throw new Error(`packet requirement ${requirement} has no evidence`);
  }
  const fullRequired = packet.compatibility.runtimeBehaviorChanged
    || packet.compatibility.kubernetesResourcesChanged
    || packet.compatibility.evidenceInterpretationChanged;
  const expectedTier = fullRequired ? 'Full' : contract.tier;
  if (packet.tier !== expectedTier) throw new Error(`packet compatibility requires ${expectedTier} review tier`);
  object(packet.binding, 'packet.binding');
  if (packet.binding.algorithm !== 'sha256') throw new Error('packet binding algorithm must be sha256');
  if (packet.binding.digest !== sha256(unsignedPacket(packet))) throw new Error('packet binding digest mismatch');
  return true;
}

export function resolveEvidenceInventoryPath(packetPath, packet, item) {
  if (!EVIDENCE_KINDS.has(item?.kind)) throw new Error('only evidence and test inventory items resolve against evidenceRoot');
  const evidenceRoot = portableRelativeLocator(packet?.evidenceRoot, 'packet.evidenceRoot');
  const locator = portableRelativeLocator(item.path, 'inventory item path');
  return resolve(dirname(packetPath), evidenceRoot, locator);
}

export function sealReviewPacket(contract, input) {
  const packet = structuredClone(input);
  delete packet.binding;
  packet.toolingDigest = reviewToolingDigest();
  packet.contractDigest = sha256(contract);
  inventoryIds(packet);
  packet.sourceDigest = scopedInventoryDigest(packet, SOURCE_KINDS);
  packet.evidenceDigest = scopedInventoryDigest(packet, EVIDENCE_KINDS);
  packet.binding = {algorithm: 'sha256', digest: sha256(packet)};
  validateReviewPacket(contract, packet);
  return packet;
}

export function evaluatePhaseGate(contract, packet, verdicts) {
  validateReviewPacket(contract, packet);
  if (packet.candidate.commitPending) {
    throw new Error('cannot complete a phase for an uncommitted candidate');
  }
  if (!Array.isArray(verdicts)) throw new Error('verdicts must be an array');
  const packetDigest = packet.binding.digest;
  const requiredReviewers = new Set(strings(contract.requiredReviewers, 'contract.requiredReviewers', {nonEmpty: true}));
  const seen = new Set();
  const packetInventory = new Set(inventoryIds(packet));
  for (const verdict of verdicts) {
    validateSchema(verdict, verdictSchema, 'verdict');
    if (verdict.schemaVersion !== REVIEW_VERDICT_SCHEMA) throw new Error('unsupported review verdict schema');
    const reviewer = string(verdict.reviewer, 'verdict.reviewer');
    if (seen.has(reviewer)) throw new Error(`duplicate verdict for ${reviewer}`);
    seen.add(reviewer);
    if (verdict.verdict !== 'Approved') throw new Error(`${reviewer} verdict is ${verdict.verdict}`);
    if (verdict.contractDigest !== packet.contractDigest) throw new Error(`${reviewer} reviewed a different contract`);
    if (verdict.packetDigest !== packetDigest || verdict.sourceDigest !== packet.sourceDigest || verdict.evidenceDigest !== packet.evidenceDigest) {
      throw new Error(`${reviewer} reviewed different source or evidence digests`);
    }
    if (verdict.scope !== 'complete') throw new Error(`${reviewer} review is scoped or incomplete`);
    const omissions = strings(verdict.omissions, `${reviewer}.omissions`);
    if (omissions.length !== 0) throw new Error(`${reviewer} review records omissions`);
    const reviewed = new Set(strings(verdict.reviewedInventory, `${reviewer}.reviewedInventory`));
    for (const id of packetInventory) if (!reviewed.has(id)) throw new Error(`${reviewer} did not review ${id}`);
  }
  for (const reviewer of requiredReviewers) if (!seen.has(reviewer)) throw new Error(`missing approval from ${reviewer}`);
  return {
    status: `Approved for ${contract.releaseScope} scope`,
    ...(packet.reviewId ? {reviewId: packet.reviewId} : {}),
    phase: packet.phase,
    packetDigest,
    contractDigest: packet.contractDigest,
  };
}

function load(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function main(argv) {
  if (argv[0] === 'tooling-digest' && argv.length === 1) {
    console.log(reviewToolingDigest());
    return 0;
  }
  if (argv.length < 3 || argv[0] !== 'gate') {
    console.error('usage: phase-review.mjs tooling-digest | gate CONTRACT PACKET VERDICT...');
    return 2;
  }
  const result = evaluatePhaseGate(load(argv[1]), load(argv[2]), argv.slice(3).map(load));
  console.log(JSON.stringify(result));
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
