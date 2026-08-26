#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from '../../hacknet-offline-result.mjs';
import {validateA6Verification} from './verify.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');

export const A6_SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a6-evidence/v1';
export const A6_ARCHIVE_INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';
export const A6_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'attacknet-result.json',
  hacknetCheck: 'hacknet-result.json',
});
export const A6_ASSERTIONS = Object.freeze([
  'signed-a5-child-and-exact-candidate-diff',
  'stable-public-directory-boundary',
  'frozen-legacy-runtime-not-publicly-dispatched',
  'canonical-go-cli-and-image-contexts-resolve',
  'legacy-equivalence-contracts-pass',
  'operator-attacknet-hacknet-and-helm-offline-checks-pass',
]);

function fail(message) {
  throw new Error(message);
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestFile(path) {
  return digestBytes(readFileSync(path));
}

function load(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`${label} is not readable JSON: ${error.message}`);
  }
}

function portablePath(root, path) {
  const value = relative(root, path);
  if (!value || value.startsWith('..') || isAbsolute(value) || value.includes('\\')) {
    fail(`evidence path is not portable from the repository root: ${path}`);
  }
  return value;
}

/** Validate the whole-product Attacknet result used by A6. */
export function validateA6AttacknetResult(value, candidateRevision) {
  if (value?.schemaVersion !== 'stacks-attacknet-offline-check-result/v1'
    || value.sourceRevision !== candidateRevision || value.status !== 'passed'
    || !Array.isArray(value.suites) || value.suites.length === 0) {
    fail('Attacknet check is not a passed candidate-bound result');
  }
  for (const suite of value.suites) {
    if (typeof suite?.name !== 'string' || suite.name.length === 0
      || !Number.isSafeInteger(suite.tests) || suite.tests < 1
      || suite.passed !== suite.tests || suite.failed !== 0) {
      fail('Attacknet check contains an incomplete suite');
    }
  }
  return value;
}

/** Validate the whole-product Hacknet result used by A6. */
export function validateA6HacknetResult(value, candidateRevision) {
  validateHacknetOfflineResult(value);
  if (value.sourceRevision !== candidateRevision) fail('Hacknet check does not pin the candidate');
  for (const required of ['go', 'helm']) {
    if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
      fail(`A6 requires a passed Hacknet ${required} check`);
    }
  }
  return value;
}

function archiveIndex(candidateRevision, root) {
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const archivePath = relative(root, path);
      if (archivePath === 'archive-index.json' || archivePath === 'archive') continue;
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) {
        entries.push({path: archivePath, digest: digestFile(path), size: statSync(path).size});
      } else fail(`unsupported archive entry ${archivePath}`);
    }
  };
  visit(root);
  return {schema: A6_ARCHIVE_INDEX_SCHEMA, candidateRevision, entries};
}

/** Assemble a portable A6 archive from candidate-bound offline verification. */
export function assembleA6Evidence({
  candidateRevision,
  inputDirectory,
  outputDirectory,
  archiveLocation,
  root = repositoryRoot,
}) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) fail('candidateRevision must be a full Git SHA');
  if (typeof archiveLocation !== 'string' || archiveLocation.length === 0) fail('archiveLocation is required');
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);
  if (output === root || !portablePath(root, output)) fail('outputDirectory must be inside the repository');
  rmSync(output, {recursive: true, force: true});
  mkdirSync(join(output, 'artifacts'), {recursive: true});
  mkdirSync(join(output, 'archive'), {recursive: true});

  const artifacts = {};
  for (const [key, filename] of Object.entries(A6_ARTIFACTS)) {
    const source = join(input, filename);
    const archiveEntry = `artifacts/${filename}`;
    const target = join(output, archiveEntry);
    copyFileSync(source, target);
    if (key === 'candidateDiff') {
      if (statSync(target).size === 0) fail('candidate diff is empty');
    } else {
      const value = load(target, key);
      if (key === 'verification') validateA6Verification(value, candidateRevision);
      else if (key === 'attacknetCheck') validateA6AttacknetResult(value, candidateRevision);
      else validateA6HacknetResult(value, candidateRevision);
    }
    artifacts[key] = {path: portablePath(root, target), archiveEntry, digest: digestFile(target)};
  }

  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(candidateRevision, output), null, 2)}\n`);
  const archiveName = `release-1-a6-evidence-${candidateRevision.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts']);
  const summary = {
    schema: A6_SUMMARY_SCHEMA,
    candidateRevision,
    archive: {
      path: portablePath(root, archivePath),
      digest: digestFile(archivePath),
      indexPath: portablePath(root, indexPath),
      indexDigest: digestFile(indexPath),
      indexEntry: 'archive-index.json',
      location: archiveLocation,
    },
    artifacts,
    assertions: A6_ASSERTIONS.map(id => ({id, status: 'passed'})),
  };
  writeFileSync(join(output, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--input=', '--output=', '--archive-location='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) fail(`unknown option ${unknown}`);
  const options = {
    candidateRevision: value('--candidate='),
    inputDirectory: value('--input='),
    outputDirectory: value('--output='),
    archiveLocation: value('--archive-location='),
  };
  for (const [name, option] of Object.entries(options)) if (!option) fail(`${name} is required`);
  process.stdout.write(`${JSON.stringify(assembleA6Evidence(options), null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
