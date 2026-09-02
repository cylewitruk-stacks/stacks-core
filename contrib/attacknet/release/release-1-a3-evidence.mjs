#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {
  copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {validateHacknetOfflineResult} from './hacknet-offline-result.mjs';
import {validateClockPolicyProof} from './release-1-a3-clock-live.mjs';
import {A3_CHECK_IDS} from './release-1-a3-verify.mjs';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const SUMMARY_SCHEMA = 'stacks-attacknet-release-1-a3-live-evidence/v1';
const INDEX_SCHEMA = 'stacks-attacknet-evidence-archive-index/v1';

export const A3_ARTIFACTS = Object.freeze({
  candidateDiff: 'candidate.patch',
  verification: 'verification.json',
  attacknetCheck: 'offline-result.json',
  hacknetCheck: 'hacknet-result.json',
  clockPolicyLive: 'clock-policy-live.json',
});

export const A3_ASSERTIONS = Object.freeze([
  'signed-a2-child-and-exact-candidate-diff',
  'go-unit-race-and-envtest-contracts',
  'structural-exact-rbac-contract',
  'expanded-topology-equivalence-profiles',
  'clock-policy-admission-fails-closed-before-mutation',
  'clock-policy-scenario-cleanup',
  'whole-product-verification',
]);

function fail(message) {
  throw new Error(message);
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
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

function requireCandidate(value, candidate, label) {
  if (!value || typeof value !== 'object' || value.candidateRevision !== candidate) {
    fail(`${label} does not pin the candidate revision`);
  }
  return value;
}

/** Validate one complete A3 offline verification result. */
export function validateA3Verification(value, candidate) {
  requireCandidate(value, candidate, 'A3 verification');
  if (value.schema !== 'stacks-attacknet-release-1-a3-verification/v1' || value.outcome !== 'Passed') {
    fail('A3 verification is not passed');
  }
  if (!/^1\.36\.[0-9]+$/.test(value.kubernetesVersion ?? '')) {
    fail('A3 verification omits the exact Kubernetes 1.36 envtest version');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== value.checks?.length) fail('A3 verification duplicates check IDs');
  for (const id of A3_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0
      || typeof check.command !== 'string' || !Number.isSafeInteger(check.durationMs)) {
      fail(`A3 verification check ${id} is not a complete pass`);
    }
  }
  return value;
}

function validateAttacknetResult(value, candidate) {
  if (!value || typeof value !== 'object' || value.sourceRevision !== candidate
    || value.schemaVersion !== 'stacks-attacknet-offline-check-result/v1' || value.status !== 'passed') {
    fail('Attacknet check is not passed');
  }
}

function archiveIndex(candidate, root) {
  const entries = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      const archivePath = relative(root, path);
      if (archivePath === 'archive-index.json' || archivePath === 'archive') continue;
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) entries.push({path: archivePath, digest: digestFile(path), size: statSync(path).size});
      else fail(`unsupported archive entry ${archivePath}`);
    }
  };
  visit(root);
  return {schema: INDEX_SCHEMA, candidateRevision: candidate, entries};
}

/** Validate and archive all A3 command and live evidence under one portable root. */
export function assembleReleaseOneA3Evidence({
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
  for (const [key, filename] of Object.entries(A3_ARTIFACTS)) {
    const source = join(input, filename);
    const archiveEntry = `artifacts/${filename}`;
    const target = join(output, archiveEntry);
    copyFileSync(source, target);
    if (key === 'candidateDiff') {
      if (statSync(target).size === 0) fail('candidate diff is empty');
    } else {
      const value = load(target, key);
      if (key === 'verification') validateA3Verification(value, candidateRevision);
      if (key === 'attacknetCheck') validateAttacknetResult(value, candidateRevision);
      if (key === 'hacknetCheck') {
        validateHacknetOfflineResult(value);
        if (value.sourceRevision !== candidateRevision) fail('Hacknet check does not pin the candidate');
        for (const required of ['go', 'envtest', 'helm']) {
          if (value.optionalChecks?.find(check => check.name === required)?.status !== 'passed') {
            fail(`A3 requires a passed Hacknet ${required} check`);
          }
        }
      }
      if (key === 'clockPolicyLive') {
        requireCandidate(value, candidateRevision, 'clock-policy proof');
        validateClockPolicyProof(value);
      }
    }
    artifacts[key] = {path: portablePath(root, target), archiveEntry, digest: digestFile(target)};
  }

  const indexPath = join(output, 'archive-index.json');
  writeFileSync(indexPath, `${JSON.stringify(archiveIndex(candidateRevision, output), null, 2)}\n`);
  const archiveName = `release-1-a3-evidence-${candidateRevision.slice(0, 12)}.tar.gz`;
  const archivePath = join(output, 'archive', archiveName);
  execFileSync('tar', ['-czf', archivePath, '-C', output, 'archive-index.json', 'artifacts'], {env: {...process.env, COPYFILE_DISABLE: '1'}});
  const summary = {
    schema: SUMMARY_SCHEMA,
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
    assertions: A3_ASSERTIONS.map(id => ({id, status: 'passed'})),
  };
  writeFileSync(join(output, 'live-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
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
  const summary = assembleReleaseOneA3Evidence(options);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
