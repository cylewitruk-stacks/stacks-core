#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const CONTROLLER_EQUIVALENCE_SCHEMA = 'stacks-attacknet-controller-equivalence/v1';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');

function sourcePath(locator) {
  return locator.split(':', 1)[0];
}

function requireLegacy(revision, locator, root) {
  const path = sourcePath(locator);
  const symbol = locator.slice(path.length + 1);
  if (!locator.includes(':')) {
    execFileSync('git', ['cat-file', '-e', `${revision}:${path}`], {cwd: root, stdio: 'ignore'});
    return;
  }
  if (!symbol) throw new Error(`legacy locator ${locator} has an empty symbol`);
  const source = execFileSync('git', ['show', `${revision}:${path}`], {cwd: root, encoding: 'utf8'});
  const parts = symbol.split('.');
  if (parts.length === 1) {
    if (!new RegExp(`\\b${parts[0]}\\b`).test(source)) {
      throw new Error(`legacy locator ${locator} cannot resolve its symbol`);
    }
    return;
  }
  if (parts.length !== 2) throw new Error(`legacy locator ${locator} has unsupported symbol depth`);
  const [owner, member] = parts;
  const ownerMatch = new RegExp(`(?:export\\s+)?class\\s+${owner}\\b`).exec(source);
  if (!ownerMatch) throw new Error(`legacy locator ${locator} cannot resolve its owner`);
  const suffix = source.slice(ownerMatch.index + ownerMatch[0].length);
  const nextClass = /\n(?:export\s+)?class\s+/.exec(suffix);
  const ownerEnd = nextClass
    ? ownerMatch.index + ownerMatch[0].length + nextClass.index
    : source.length;
  const body = source.slice(ownerMatch.index, ownerEnd);
  if (!new RegExp(`\\b${member}\\s*\\(`).test(body)) {
    throw new Error(`legacy locator ${locator} cannot resolve its member`);
  }
}

/** Validate that the migration matrix is complete, pinned, and resolvable. */
export function validateControllerEquivalence(matrix, root = repositoryRoot) {
  if (matrix?.schemaVersion !== CONTROLLER_EQUIVALENCE_SCHEMA) {
    throw new Error('controller equivalence matrix uses an unsupported schema');
  }
  if (!/^[0-9a-f]{40}$/.test(matrix.legacyRevision)) {
    throw new Error('controller equivalence matrix requires an exact legacy revision');
  }
  if (!Array.isArray(matrix.entries) || matrix.entries.length === 0) {
    throw new Error('controller equivalence matrix requires entries');
  }
  const ids = new Set();
  const domains = new Set();
  for (const [index, entry] of matrix.entries.entries()) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`controller equivalence entry ${index} must be an object`);
    }
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.id) || ids.has(entry.id)) {
      throw new Error(`controller equivalence entry ${index} has an invalid or duplicate id`);
    }
    ids.add(entry.id);
    if (typeof entry.domain !== 'string' || entry.domain.length === 0) {
      throw new Error(`controller equivalence entry ${entry.id} requires a domain`);
    }
    domains.add(entry.domain);
    for (const field of ['legacy', 'go', 'tests', 'live']) {
      if (!Array.isArray(entry[field]) || (field !== 'live' && entry[field].length === 0)
        || entry[field].some(value => typeof value !== 'string' || value.length === 0)) {
        throw new Error(`controller equivalence entry ${entry.id}.${field} is incomplete`);
      }
    }
    for (const locator of entry.legacy) requireLegacy(matrix.legacyRevision, locator, root);
    for (const path of [...entry.go, ...entry.tests]) {
      if (!existsSync(resolve(root, path))) {
        throw new Error(`controller equivalence entry ${entry.id} cannot resolve ${path}`);
      }
    }
  }
  for (const required of ['topology', 'identity', 'signer-set', 'fault', 'run', 'api', 'security', 'packaging', 'integration']) {
    if (!domains.has(required)) throw new Error(`controller equivalence matrix omits ${required}`);
  }
  return matrix;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] ?? resolve(releaseDirectory, 'controller-equivalence-v1.json');
  const matrix = validateControllerEquivalence(JSON.parse(readFileSync(path, 'utf8')));
  process.stdout.write(`${JSON.stringify({
    schemaVersion: matrix.schemaVersion,
    legacyRevision: matrix.legacyRevision,
    entries: matrix.entries.length,
    domains: [...new Set(matrix.entries.map(entry => entry.domain))].sort(),
    liveScenarios: [...new Set(matrix.entries.flatMap(entry => entry.live))].sort(),
    status: 'mapped-for-direct-review',
  }, null, 2)}\n`);
}
