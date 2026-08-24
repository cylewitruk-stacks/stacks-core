import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {isAbsolute, resolve} from 'node:path';

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

function archiveMembers(path, root) {
  return new Set(execFileSync('tar', ['-tf', absolute(path, root)], {encoding: 'utf8'})
    .split('\n').filter(Boolean).map(member => member.replace(/^\.\//, '').replace(/\/$/, '')));
}

function safeArchiveEntry(path) {
  return typeof path === 'string' && path.length > 0 && !path.startsWith('/')
    && !path.includes('\\') && !path.split('/').includes('..');
}

/** Validate portable, candidate-bound live evidence shared by review checkpoints. */
export function validatePortableLiveSummary(summary, candidate, {
  root,
  schema,
  checkpoint,
  requiredArtifacts,
  requiredAssertions,
}) {
  object(summary, 'live summary');
  if (summary.schema !== schema) throw new Error('live summary uses an unsupported schema');
  if (summary.candidateRevision !== candidate.sourceRevision) {
    throw new Error('live evidence does not pin the candidate revision');
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
  if (index.schema !== ARCHIVE_INDEX_SCHEMA || index.candidateRevision !== candidate.sourceRevision) {
    throw new Error('live evidence archive index does not pin the supported schema and candidate');
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
  const members = archiveMembers(archive.path, root);
  if (!members.has(archive.indexEntry)) throw new Error('live evidence archive omits its index');

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
      || !members.has(artifact.archiveEntry)) {
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
