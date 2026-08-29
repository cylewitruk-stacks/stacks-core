#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, statfsSync, statSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {A10_STORAGE_MINIMUM_AVAILABLE_BYTES} from './limits.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');

export const A10_PARENT_REVISION = '6a8f0afb94f610e36f56d2fc8e4adf7c7398471e';
export const A10_VERIFICATION_SCHEMA = 'stacks-attacknet-release-1-a10-verification/v1';
export const A10_ATTESTATION_SCHEMA = 'stacks-attacknet-release-1-a10-candidate-attestation/v1';
export const A10_CHECK_IDS = Object.freeze([
  'host-storage-preflight', 'operator-verify', 'operator-race', 'kubernetes-envtest', 'helm-lint',
  'helm-render-and-rbac', 'whole-attacknet-check', 'whole-hacknet-check',
]);

const digest = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const quote = value => /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;

function run({id, executable, arguments_: arguments__, cwd = repositoryRoot, env = process.env, input}) {
  const startedAt = new Date();
  const result = spawnSync(executable, arguments__, {
    cwd, env, input, encoding: 'utf8', maxBuffer: 128 << 20,
  });
  const stdout = result.stdout ?? '';
  const stderr = `${result.error ? `${result.error.message}\n` : ''}${result.stderr ?? ''}`;
  const exitCode = result.status ?? (result.error ? -1 : 0);
  return {
    id, status: exitCode === 0 && !result.error ? 'passed' : 'failed',
    command: [executable, ...arguments__].map(quote).join(' '),
    cwd: relative(repositoryRoot, cwd) || '.', startedAt: startedAt.toISOString(),
    durationMs: Date.now() - startedAt.getTime(), exitCode,
    outputDigest: digest(Buffer.from(`${stdout}\0${stderr}`)), stdout, stderr,
  };
}

function passed(check) {
  if (check.status !== 'passed') throw new Error(`${check.id} failed (${check.command})\n${check.stderr || check.stdout}`);
  return check;
}

/** Require enough host storage for Go race binaries and evidence output. */
export function hostStoragePreflight(path, minimumAvailableBytes = A10_STORAGE_MINIMUM_AVAILABLE_BYTES) {
  if (!Number.isSafeInteger(minimumAvailableBytes) || minimumAvailableBytes < 0) {
    throw new Error('host storage minimum must be a non-negative safe integer');
  }
  const startedAt = new Date();
  let availableBytes = 0;
  let error;
  try {
    const stats = statfsSync(path);
    availableBytes = Number(stats.bavail) * Number(stats.bsize);
  } catch (caught) {
    error = caught;
  }
  const stdout = `${JSON.stringify({availableBytes, minimumAvailableBytes, path: resolve(path)})}\n`;
  const stderr = error ? `${error.message}\n` : availableBytes < minimumAvailableBytes
    ? `host filesystem has ${availableBytes} available bytes; ${minimumAvailableBytes} required\n` : '';
  const exitCode = error || availableBytes < minimumAvailableBytes ? 1 : 0;
  return {
    id: 'host-storage-preflight', status: exitCode === 0 ? 'passed' : 'failed',
    command: `node:fs.statfsSync ${quote(resolve(path))}`, cwd: relative(repositoryRoot, resolve(path)) || '.',
    startedAt: startedAt.toISOString(), durationMs: Date.now() - startedAt.getTime(), exitCode,
    outputDigest: digest(Buffer.from(`${stdout}\0${stderr}`)), stdout, stderr,
  };
}

function git(...arguments_) {
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_: arguments_})).stdout.trim();
}

function binaryPatch(tree) {
  const patch = spawnSync('git', ['diff', '--binary', A10_PARENT_REVISION, tree], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 128 << 20,
  });
  if (patch.status !== 0 || !patch.stdout?.length) throw new Error('qualified A10 diff could not be captured');
  return patch.stdout;
}

/** Bind qualification to the exact staged A10 tree before the candidate commit. */
export function requireA10QualifiedTree(expectedTree = undefined) {
  if (git('rev-parse', 'HEAD') !== A10_PARENT_REVISION) throw new Error(`A10 qualification HEAD must equal ${A10_PARENT_REVISION}`);
  if (git('diff', '--name-only')) throw new Error('A10 qualification requires the worktree to match the staged index');
  if (git('ls-files', '--others', '--exclude-standard')) throw new Error('A10 qualification requires no untracked files');
  const qualifiedTree = git('write-tree');
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree) || (expectedTree && qualifiedTree !== expectedTree)) {
    throw new Error('A10 qualified tree does not match the staged index');
  }
  const patch = binaryPatch(qualifiedTree);
  return {qualifiedTree, parentRevision: A10_PARENT_REVISION, patchDigest: digest(patch), patch};
}

/** Bind one final signed child commit to the already-qualified A10 tree. */
export function bindA10SignedCandidate(candidateRevision, qualification, evidenceSummaryDigest) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '') || git('rev-parse', 'HEAD') !== candidateRevision) throw new Error('candidate must be the full HEAD SHA');
  if (git('status', '--porcelain', '--untracked-files=all')) throw new Error('A10 packet assembly requires a clean worktree');
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  const parents = git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean);
  if (parents.length !== 1 || parents[0] !== A10_PARENT_REVISION || qualification?.parentRevision !== A10_PARENT_REVISION) throw new Error('A10 must be one signed non-merge child of its qualified base');
  const candidateTree = git('show', '-s', '--format=%T', candidateRevision);
  if (candidateTree !== qualification.qualifiedTree || digest(binaryPatch(candidateRevision)) !== qualification.patchDigest) throw new Error('signed A10 candidate differs from the qualified tree or diff');
  if (!/^sha256:[0-9a-f]{64}$/.test(evidenceSummaryDigest ?? '')) throw new Error('A10 attestation requires a sealed evidence summary digest');
  return {schema: A10_ATTESTATION_SCHEMA, candidateRevision, candidateTree,
    parentRevision: A10_PARENT_REVISION, patchDigest: qualification.patchDigest,
    evidenceSummaryDigest, signatureVerified: true, recordedAt: new Date().toISOString()};
}

/** Validate the lightweight post-sign A10 candidate attestation. */
export function validateA10CandidateAttestation(value, qualification, evidenceSummaryDigest) {
  if (value?.schema !== A10_ATTESTATION_SCHEMA || !/^[0-9a-f]{40}$/.test(value.candidateRevision ?? '')
    || value.candidateTree !== qualification?.qualifiedTree || value.parentRevision !== A10_PARENT_REVISION
    || value.patchDigest !== qualification?.patchDigest || value.evidenceSummaryDigest !== evidenceSummaryDigest
    || value.signatureVerified !== true || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A10 candidate attestation is invalid');
  }
  return value;
}

/** Validate one complete qualified-tree-bound A10 verification record. */
export function validateA10Verification(value, qualifiedTree) {
  if (value?.schema !== A10_VERIFICATION_SCHEMA || value.qualifiedTree !== qualifiedTree
    || value.parentRevision !== A10_PARENT_REVISION || !/^sha256:[0-9a-f]{64}$/.test(value.patchDigest ?? '')
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A10 verification is not a complete pass');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== A10_CHECK_IDS.length || checks.size !== value.checks?.length) throw new Error('A10 verification contains duplicate, missing, or unknown checks');
  for (const id of A10_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0 || typeof check.command !== 'string'
      || !Number.isSafeInteger(check.durationMs) || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')) {
      throw new Error(`A10 verification check ${id} is incomplete`);
    }
  }
  return value;
}

/** Run Full-tier offline verification once against the staged A10 tree. */
export function runA10Verification({qualifiedTree, outputDirectory, envtestAssets}) {
  const qualification = requireA10QualifiedTree(qualifiedTree);
  if (!envtestAssets || !statSync(envtestAssets).isDirectory()) throw new Error('envtestAssets must identify an installed envtest directory');
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  const goCache = join(output, 'go-cache');
  mkdirSync(goCache, {recursive: true});
  const environment = {...process.env, GOCACHE: goCache, KUBEBUILDER_ASSETS: resolve(envtestAssets), ATTACKNET_QUALIFIED_TREE: qualification.qualifiedTree};
  const checks = [];
  checks.push(passed(hostStoragePreflight(output)));
  checks.push(passed(run({id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'operator-race', executable: 'go', arguments_: ['test', '-race', './...'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'kubernetes-envtest', executable: 'make', arguments_: ['test-integration'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'helm-lint', executable: 'helm', arguments_: ['lint', 'contrib/helm/hacknet']})));
  const rendered = passed(run({id: 'helm-render', executable: 'helm', arguments_: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds']}));
  checks.push(passed(run({id: 'helm-render-and-rbac', executable: 'go', arguments_: ['run', './cmd/rbac-check'], cwd: operatorDirectory, env: environment, input: rendered.stdout})));
  checks.push(passed(run({id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/test/check.sh'], env: {...environment, ATTACKNET_OFFLINE_RESULT: join(output, 'attacknet-result.json')}})));
  checks.push(passed(run({id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'], env: {...environment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')}})));
  const result = {schema: A10_VERIFICATION_SCHEMA, qualifiedTree: qualification.qualifiedTree,
    parentRevision: qualification.parentRevision, patchDigest: qualification.patchDigest,
    outcome: 'Passed', recordedAt: new Date().toISOString(), checks};
  validateA10Verification(result, qualification.qualifiedTree);
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeFileSync(join(output, 'candidate.patch'), qualification.patch);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  for (const required of ['--qualified-tree=', '--output=', '--envtest-assets=']) {
    if (!value(required)) throw new Error(`${required.slice(2, -1)} is required`);
  }
  runA10Verification({qualifiedTree: value('--qualified-tree='), outputDirectory: value('--output='), envtestAssets: value('--envtest-assets=')});
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
