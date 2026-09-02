import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {isAbsolute, resolve} from 'node:path';
import {gunzipSync} from 'node:zlib';

const ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function absolute(path, root) {
  return isAbsolute(path) ? path : resolve(root, path);
}

function digestFile(path, root) {
  return `sha256:${createHash('sha256').update(readFileSync(absolute(path, root))).digest('hex')}`;
}

function load(path, root) {
  return JSON.parse(readFileSync(absolute(path, root), 'utf8'));
}

function safeArchiveEntry(path) {
  return typeof path === 'string' && path.length > 0 && !path.startsWith('/') && !path.includes('\\')
    && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..'
      && /^[A-Za-z0-9_+@=.-]+$/.test(segment));
}

function tarString(buffer, start, length) {
  const end = buffer.indexOf(0, start);
  return buffer.subarray(start, end >= start && end < start + length ? end : start + length).toString('utf8');
}

function tarSize(header) {
  const raw = tarString(header, 124, 12).trim();
  if (!/^[0-7]*$/.test(raw)) throw new Error('live evidence archive contains an unsupported tar size');
  const value = raw === '' ? 0 : Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('live evidence archive tar size is invalid');
  return value;
}

function paxPath(content) {
  let offset = 0;
  let path;
  while (offset < content.length) {
    const space = content.indexOf(0x20, offset);
    if (space < 0) throw new Error('live evidence archive contains malformed PAX metadata');
    const length = Number.parseInt(content.subarray(offset, space).toString('ascii'), 10);
    if (!Number.isSafeInteger(length) || length <= space - offset || offset + length > content.length) {
      throw new Error('live evidence archive contains malformed PAX metadata');
    }
    const record = content.subarray(space + 1, offset + length - 1).toString('utf8');
    const equals = record.indexOf('=');
    if (equals > 0 && record.slice(0, equals) === 'path') path = record.slice(equals + 1);
    offset += length;
  }
  return path;
}

function parseArchive(path, root) {
  const encoded = readFileSync(absolute(path, root));
  const archive = encoded[0] === 0x1f && encoded[1] === 0x8b ? gunzipSync(encoded) : encoded;
  const files = new Map();
  const directories = new Set();
  let nextPath;
  let terminated = false;
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      if (archive.subarray(offset).some(byte => byte !== 0)) {
        throw new Error('live evidence archive contains non-zero trailing data');
      }
      terminated = true;
      break;
    }
    const size = tarSize(header);
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (contentEnd > archive.length) throw new Error('live evidence archive is truncated');
    const type = String.fromCharCode(header[156] || 0x30);
    const prefix = tarString(header, 345, 155);
    const headerPath = [prefix, tarString(header, 0, 100)].filter(Boolean).join('/');
    const content = archive.subarray(contentStart, contentEnd);
    if (type === 'x') {
      nextPath = paxPath(content) ?? nextPath;
    } else if (type === 'g') {
      // Global PAX metadata cannot change evidence member identity.
    } else if (type === 'L') {
      nextPath = content.subarray(0, content.indexOf(0) >= 0 ? content.indexOf(0) : content.length).toString('utf8');
    } else {
      const member = (nextPath ?? headerPath).replace(/^\.\//, '').replace(/\/$/, '');
      nextPath = undefined;
      if (member === '' && type === '5') {
        offset = contentStart + Math.ceil(size / 512) * 512;
        continue;
      }
      if (!safeArchiveEntry(member)) throw new Error(`live evidence archive contains unsafe member ${member}`);
      if (type === '5') {
        if (directories.has(member) || files.has(member)) throw new Error(`live evidence archive duplicates ${member}`);
        directories.add(member);
      } else if (type === '0') {
        if (files.has(member) || directories.has(member)) throw new Error(`live evidence archive duplicates ${member}`);
        files.set(member, Buffer.from(content));
      } else {
        throw new Error(`live evidence archive contains non-regular member ${member}`);
      }
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  if (!terminated || nextPath) throw new Error('live evidence archive is not cleanly terminated');
  return {files, directories};
}

function directoryAncestors(path) {
  const parts = path.split('/');
  const result = [];
  for (let index = 1; index < parts.length; index++) result.push(parts.slice(0, index).join('/'));
  return result;
}

/** Validate portable, candidate-bound live evidence shared by review checkpoints. */
export function validatePortableLiveSummary(summary, candidate, {
  root,
  schema,
  checkpoint,
  requiredArtifacts,
  requiredAssertions,
  binding = {field: 'candidateRevision', value: candidate.sourceRevision, description: 'candidate revision'},
}) {
  object(summary, 'live summary');
  if (summary.schema !== schema) throw new Error('live summary uses an unsupported schema');
  if (summary[binding.field] !== binding.value) {
    throw new Error(`live evidence does not pin the ${binding.description}`);
  }
  if (candidate.commitPending) throw new Error(`${checkpoint} packet requires a clean committed candidate`);

  const archive = object(summary.archive, 'live summary archive');
  for (const key of ['path', 'digest', 'indexPath', 'indexDigest', 'indexEntry', 'location']) {
    if (typeof archive[key] !== 'string' || archive[key].length === 0) {
      throw new Error(`live summary archive.${key} is required`);
    }
  }
  if (!safeArchiveEntry(archive.indexEntry)) {
    throw new Error('live summary archive.indexEntry must be a portable relative path');
  }
  if (digestFile(archive.path, root) !== archive.digest) throw new Error('live evidence archive digest mismatch');
  if (digestFile(archive.indexPath, root) !== archive.indexDigest) {
    throw new Error('live evidence archive index digest mismatch');
  }

  const index = load(archive.indexPath, root);
  if (index.schema !== ARCHIVE_INDEX_SCHEMA || index[binding.field] !== binding.value) {
    throw new Error(`live evidence archive index does not pin the supported schema and ${binding.description}`);
  }
  if (!Array.isArray(index.entries) || index.entries.length === 0) {
    throw new Error('live evidence archive index entries are required');
  }
  const indexed = new Map();
  for (const [position, entry] of index.entries.entries()) {
    object(entry, `live evidence archive index entry ${position}`);
    if (!safeArchiveEntry(entry.path)) {
      throw new Error(`live evidence archive index entry ${position} has an unsafe path`);
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(entry.digest)
      || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new Error(`live evidence archive index entry ${position} is incomplete`);
    }
    if (indexed.has(entry.path)) throw new Error(`live evidence archive index duplicates ${entry.path}`);
    indexed.set(entry.path, entry);
  }
  const contents = parseArchive(archive.path, root);
  const externalIndex = readFileSync(absolute(archive.indexPath, root));
  const embeddedIndex = contents.files.get(archive.indexEntry);
  if (!embeddedIndex || !embeddedIndex.equals(externalIndex)) {
    throw new Error('live evidence archive omits or changes its index');
  }
  const expectedFiles = new Set([archive.indexEntry, ...indexed.keys()]);
  for (const member of contents.files.keys()) {
    if (!expectedFiles.has(member)) throw new Error(`live evidence archive contains unindexed member ${member}`);
  }
  for (const expected of expectedFiles) {
    if (!contents.files.has(expected)) throw new Error(`live evidence archive omits ${expected}`);
  }
  const expectedDirectories = new Set([...expectedFiles].flatMap(directoryAncestors));
  for (const directory of contents.directories) {
    if (!expectedDirectories.has(directory)) throw new Error(`live evidence archive contains unindexed directory ${directory}`);
  }
  for (const [path, entry] of indexed) {
    const bytes = contents.files.get(path);
    const actualDigest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    if (bytes.length !== entry.size || actualDigest !== entry.digest) {
      throw new Error(`live evidence archive member ${path} does not match its index`);
    }
  }

  const artifacts = object(summary.artifacts, 'live summary artifacts');
  for (const key of requiredArtifacts) {
    const artifact = object(artifacts[key], `live summary artifacts.${key}`);
    if (typeof artifact.path !== 'string' || typeof artifact.digest !== 'string'
      || typeof artifact.archiveEntry !== 'string') {
      throw new Error(`live summary artifact ${key} is incomplete`);
    }
    if (digestFile(artifact.path, root) !== artifact.digest) {
      throw new Error(`live summary artifact ${key} digest mismatch`);
    }
    if (indexed.get(artifact.archiveEntry)?.digest !== artifact.digest
      || !contents.files.has(artifact.archiveEntry)) {
      throw new Error(`live evidence archive does not bind artifact ${key}`);
    }
  }

  const assertions = Array.isArray(summary.assertions) ? summary.assertions : [];
  const byId = new Map(assertions.map(assertion => [assertion?.id, assertion]));
  if (byId.size !== assertions.length) throw new Error('live summary contains duplicate assertion IDs');
  for (const id of requiredAssertions) {
    if (byId.get(id)?.status !== 'passed') {
      throw new Error(`live summary assertion ${id} is not passed`);
    }
  }
  return summary;
}
