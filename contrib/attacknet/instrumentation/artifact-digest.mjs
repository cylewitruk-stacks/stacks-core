import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Encode a JSON-compatible value with recursively sorted object keys. */
export function canonicalJson(value) {
  const seen = new Set();
  function visit(item) {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new Error('canonical JSON cannot encode a non-finite number');
      return item;
    }
    if (Array.isArray(item)) return item.map(visit);
    if (!isObject(item)) throw new Error(`canonical JSON cannot encode ${typeof item}`);
    if (seen.has(item)) throw new Error('canonical JSON cannot encode a cyclic object');
    seen.add(item);
    const result = {};
    for (const key of Object.keys(item).sort()) {
      if (item[key] === undefined) throw new Error(`canonical JSON cannot encode undefined at ${key}`);
      result[key] = visit(item[key]);
    }
    seen.delete(item);
    return result;
  }
  return JSON.stringify(visit(value));
}

/** Return the canonical SHA-256 digest of a JSON-compatible value. */
export function sha256Value(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

/** Return the SHA-256 digest of one file or injected byte reader. */
export function sha256File(path, readFile = readFileSync) {
  return `sha256:${createHash('sha256').update(readFile(path)).digest('hex')}`;
}
