import {readFileSync} from 'node:fs';

import type {NodeRole} from '../shared/model.js';

const ACTOR_ID = /^[a-z][a-z0-9-]{2,63}$/;
export const SIGNER_PUBLIC_KEY = /^(02|03)[0-9a-f]{64}$/;
export const TRANSPORT_PEER_ID = /^[1-9A-HJ-NP-Za-km-z]{32,128}$/;
const MAX_ACTORS = 512;
const MAX_ENTITY_NAME = 96;

export interface ExpectedActor {
  id: string;
  label: string;
  role: NodeRole;
  signerPublicKey?: string;
  transportPeerId?: string;
  entityName?: string;
  companionActorId?: string;
}

interface EnrollmentDocument {
  version: number;
  network: string;
  actors: unknown[];
  signerEntities?: unknown[];
}

/**
 * Load the server-owned actor registry. Token authentication establishes the
 * actor ID at the collector; this registry binds that ID to public signer
 * identity and presentation metadata. No client-provided identity is used.
 */
export function loadEnrollments(path: string | undefined, legacy: string | undefined): ExpectedActor[] {
  if (!path) return parseLegacyExpectedActors(legacy);
  const decoded = JSON.parse(readFileSync(path, 'utf8')) as EnrollmentDocument;
  if (decoded.version !== 1 || typeof decoded.network !== 'string' || !Array.isArray(decoded.actors)) {
    throw new Error('invalid observer enrollment document');
  }
  if (decoded.actors.length === 0 || decoded.actors.length > MAX_ACTORS) {
    throw new Error(`observer enrollment actor count must be between 1 and ${MAX_ACTORS}`);
  }
  const entityNames = parseEntityNames(decoded.signerEntities ?? []);
  const actors = decoded.actors.map((value, index) => parseActor(value, index, entityNames));
  const actorIds = new Set<string>();
  const signerKeys = new Set<string>();
  const transportPeerIds = new Set<string>();
  for (const actor of actors) {
    if (actorIds.has(actor.id)) throw new Error(`duplicate enrolled actor ID: ${actor.id}`);
    actorIds.add(actor.id);
    if (actor.signerPublicKey) {
      if (signerKeys.has(actor.signerPublicKey)) {
        throw new Error(`signer public key is bound to multiple actors: ${actor.signerPublicKey}`);
      }
      signerKeys.add(actor.signerPublicKey);
    }
    if (actor.transportPeerId) {
      if (transportPeerIds.has(actor.transportPeerId)) {
        throw new Error(`transport PeerId is bound to multiple actors: ${actor.transportPeerId}`);
      }
      transportPeerIds.add(actor.transportPeerId);
    }
  }
  for (const actor of actors) {
    if (actor.companionActorId && !actorIds.has(actor.companionActorId)) {
      throw new Error(`actor ${actor.id} references unknown companion ${actor.companionActorId}`);
    }
  }
  return actors;
}

function parseEntityNames(values: unknown[]): Map<string, string> {
  if (values.length > MAX_ACTORS) throw new Error('too many signer entity records');
  const result = new Map<string, string>();
  for (const [index, value] of values.entries()) {
    const record = object(value, `signerEntities[${index}]`);
    const publicKey = signerKey(record.publicKey, `signerEntities[${index}].publicKey`);
    const entityName = boundedString(record.entityName, `signerEntities[${index}].entityName`, MAX_ENTITY_NAME);
    if (result.has(publicKey)) throw new Error(`duplicate signer entity public key: ${publicKey}`);
    result.set(publicKey, entityName);
  }
  return result;
}

function parseActor(value: unknown, index: number, entityNames: Map<string, string>): ExpectedActor {
  const record = object(value, `actors[${index}]`);
  const id = boundedString(record.id, `actors[${index}].id`, 64);
  if (!ACTOR_ID.test(id)) throw new Error(`actors[${index}].id is not a bounded actor ID`);
  const role = nodeRole(record.role, `actors[${index}].role`);
  const signerPublicKey = record.signerPublicKey === undefined
    ? undefined
    : signerKey(record.signerPublicKey, `actors[${index}].signerPublicKey`);
  if (role === 'signer' && !signerPublicKey) {
    throw new Error(`actors[${index}] is a signer without a public key binding`);
  }
  if (role !== 'signer' && signerPublicKey) {
    throw new Error(`actors[${index}] binds a signer key to a non-signer role`);
  }
  const configuredEntity = record.entityName === undefined
    ? undefined
    : boundedString(record.entityName, `actors[${index}].entityName`, MAX_ENTITY_NAME);
  const actor: ExpectedActor = {
    id,
    label: boundedString(record.label, `actors[${index}].label`, 64),
    role,
  };
  if (record.transportPeerId !== undefined) {
    const transportPeerId = boundedString(record.transportPeerId, `actors[${index}].transportPeerId`, 128);
    if (!TRANSPORT_PEER_ID.test(transportPeerId)) {
      throw new Error(`actors[${index}].transportPeerId is not a bounded transport PeerId`);
    }
    actor.transportPeerId = transportPeerId;
  }
  if (signerPublicKey) actor.signerPublicKey = signerPublicKey;
  const entityName = signerPublicKey ? configuredEntity ?? entityNames.get(signerPublicKey) : undefined;
  if (entityName) actor.entityName = entityName;
  if (record.companionActorId !== undefined) {
    actor.companionActorId = boundedActorId(
      record.companionActorId,
      `actors[${index}].companionActorId`,
    );
  }
  return actor;
}

function boundedActorId(value: unknown, path: string): string {
  const id = boundedString(value, path, 64);
  if (!ACTOR_ID.test(id)) throw new Error(`${path} is not a bounded actor ID`);
  return id;
}

export function parseLegacyExpectedActors(value: string | undefined): ExpectedActor[] {
  return (value ?? '').split(',').filter(Boolean).flatMap(entry => {
    const [id, label, rawRole] = entry.split(':');
    if (!id || !ACTOR_ID.test(id)) return [];
    return [{id, label: label || id, role: permissiveRole(rawRole)}];
  });
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${path} must be an object`);
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, path: string, max: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new Error(`${path} must be a non-empty string of at most ${max} characters`);
  }
  return value;
}

function signerKey(value: unknown, path: string): string {
  const key = boundedString(value, path, 66).toLowerCase();
  if (!SIGNER_PUBLIC_KEY.test(key)) throw new Error(`${path} must be a compressed secp256k1 public key`);
  return key;
}

function nodeRole(value: unknown, path: string): NodeRole {
  if (typeof value !== 'string') throw new Error(`${path} must be a node role`);
  const role = permissiveRole(value);
  if (role === 'unknown' && value !== 'unknown') throw new Error(`${path} is not a supported role`);
  return role;
}

function permissiveRole(value: string | undefined): NodeRole {
  return value === 'miner' || value === 'signer' || value === 'follower' ||
    value === 'bootstrap' || value === 'companion' || value === 'unknown' ? value : 'unknown';
}
