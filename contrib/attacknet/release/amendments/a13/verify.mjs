#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, statSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');

export const A13_PARENT_REVISION = 'b49aaceb46facff030ee1c995f26b25b01e30c73';
export const A13_VERIFICATION_SCHEMA = 'stacks-attacknet-release-1-a13-verification/v1';
export const A13_ATTESTATION_SCHEMA = 'stacks-attacknet-release-1-a13-candidate-attestation/v1';
export const A13_CHECK_IDS = Object.freeze([
  'operator-verify', 'operator-race', 'kubernetes-envtest', 'helm-lint',
  'helm-render-and-rbac', 'whole-attacknet-check', 'whole-hacknet-check',
]);

const digest = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const quote = value => /^[A-Za-z0-9_./:=+,-]+$/.test(value)
  ? value : `'${value.replaceAll("'", "'\\''")}'`;

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
  if (check.status !== 'passed') {
    throw new Error(`${check.id} failed (${check.command})\n${check.stdout}\n${check.stderr}`);
  }
  return check;
}

function git(...arguments_) {
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_: arguments_})).stdout.trim();
}

function binaryPatch(tree) {
  const result = spawnSync('git', ['diff', '--binary', A13_PARENT_REVISION, tree], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 128 << 20,
  });
  if (result.status !== 0 || !result.stdout?.length) throw new Error('qualified A13 diff could not be captured');
  return result.stdout;
}

/** Bind all qualification to the exact staged A13 tree. */
export function requireA13QualifiedTree(expectedTree = undefined) {
  if (git('rev-parse', 'HEAD') !== A13_PARENT_REVISION) {
    throw new Error(`A13 qualification HEAD must equal ${A13_PARENT_REVISION}`);
  }
  if (git('diff', '--name-only') || git('ls-files', '--others', '--exclude-standard')) {
    throw new Error('A13 qualification requires all candidate content staged and no unstaged or untracked files');
  }
  const qualifiedTree = git('write-tree');
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree) || expectedTree && qualifiedTree !== expectedTree) {
    throw new Error('A13 qualified tree does not match the staged index');
  }
  const patch = binaryPatch(qualifiedTree);
  return {qualifiedTree, parentRevision: A13_PARENT_REVISION, patchDigest: digest(patch), patch};
}

/** Bind one final hardware-signed commit to the already qualified tree. */
export function bindA13SignedCandidate(candidateRevision, qualification, evidenceSummaryDigest) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '') || git('rev-parse', 'HEAD') !== candidateRevision) {
    throw new Error('candidate must be the full HEAD SHA');
  }
  if (git('status', '--porcelain', '--untracked-files=all')) throw new Error('A13 assembly requires a clean worktree');
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  const parents = git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean);
  const candidateTree = git('show', '-s', '--format=%T', candidateRevision);
  if (parents.length !== 1 || parents[0] !== A13_PARENT_REVISION
    || candidateTree !== qualification?.qualifiedTree
    || digest(binaryPatch(candidateRevision)) !== qualification?.patchDigest
    || !/^sha256:[0-9a-f]{64}$/.test(evidenceSummaryDigest ?? '')) {
    throw new Error('signed A13 candidate differs from the qualified tree, base, diff, or evidence');
  }
  return {
    schema: A13_ATTESTATION_SCHEMA, candidateRevision, candidateTree,
    parentRevision: A13_PARENT_REVISION, patchDigest: qualification.patchDigest,
    evidenceSummaryDigest, signatureVerified: true, recordedAt: new Date().toISOString(),
  };
}

/** Validate the lightweight post-sign candidate attestation. */
export function validateA13CandidateAttestation(value, qualification, evidenceSummaryDigest) {
  if (value?.schema !== A13_ATTESTATION_SCHEMA
    || !/^[0-9a-f]{40}$/.test(value.candidateRevision ?? '')
    || value.candidateTree !== qualification?.qualifiedTree
    || value.parentRevision !== A13_PARENT_REVISION
    || value.patchDigest !== qualification?.patchDigest
    || value.evidenceSummaryDigest !== evidenceSummaryDigest
    || value.signatureVerified !== true || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A13 candidate attestation is invalid');
  }
  return value;
}

/** Validate a complete qualified-tree verification record. */
export function validateA13Verification(value, qualifiedTree) {
  if (value?.schema !== A13_VERIFICATION_SCHEMA || value.qualifiedTree !== qualifiedTree
    || value.parentRevision !== A13_PARENT_REVISION
    || !/^sha256:[0-9a-f]{64}$/.test(value.patchDigest ?? '')
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A13 verification is not a complete pass');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== A13_CHECK_IDS.length || checks.size !== value.checks?.length) {
    throw new Error('A13 verification contains duplicate, missing, or unknown checks');
  }
  for (const id of A13_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0 || typeof check.command !== 'string'
      || !Number.isSafeInteger(check.durationMs) || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')) {
      throw new Error(`A13 verification check ${id} is incomplete`);
    }
  }
  return value;
}

/** Run Full-tier offline verification once against the staged A13 tree. */
export function runA13Verification({qualifiedTree, outputDirectory, envtestAssets}) {
  const qualification = requireA13QualifiedTree(qualifiedTree);
  if (!envtestAssets || !statSync(envtestAssets).isDirectory()) {
    throw new Error('envtestAssets must identify an installed envtest directory');
  }
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  const environment = {
    ...process.env, GOCACHE: join(output, 'go-cache'), KUBEBUILDER_ASSETS: resolve(envtestAssets),
    ATTACKNET_QUALIFIED_TREE: qualification.qualifiedTree,
  };
  mkdirSync(environment.GOCACHE, {recursive: true});
  const checks = [];
  checks.push(passed(run({id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'operator-race', executable: 'go', arguments_: ['test', '-race', './...'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'kubernetes-envtest', executable: 'make', arguments_: ['test-integration'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'helm-lint', executable: 'helm', arguments_: ['lint', 'contrib/helm/hacknet'], env: environment})));
  const rendered = passed(run({id: 'helm-render', executable: 'helm', arguments_: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds'], env: environment}));
  checks.push(passed(run({id: 'helm-render-and-rbac', executable: 'go', arguments_: ['run', './cmd/rbac-check'], cwd: operatorDirectory, env: environment, input: rendered.stdout})));
  checks.push(passed(run({id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/test/check.sh'], env: {...environment, ATTACKNET_OFFLINE_RESULT: join(output, 'attacknet-result.json')}})));
  checks.push(passed(run({id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'], env: {...environment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')}})));
  requireA13QualifiedTree(qualifiedTree);
  const result = {
    schema: A13_VERIFICATION_SCHEMA, qualifiedTree: qualification.qualifiedTree,
    parentRevision: qualification.parentRevision, patchDigest: qualification.patchDigest,
    outcome: 'Passed', recordedAt: new Date().toISOString(), checks,
  };
  validateA13Verification(result, qualifiedTree);
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeFileSync(join(output, 'candidate.patch'), qualification.patch);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const qualifiedTree = value('--qualified-tree=');
  const outputDirectory = value('--output=');
  const envtestAssets = value('--envtest-assets=');
  if (!qualifiedTree || !outputDirectory || !envtestAssets) {
    throw new Error('usage: verify.mjs --qualified-tree=TREE --output=DIR --envtest-assets=DIR');
  }
  runA13Verification({qualifiedTree, outputDirectory, envtestAssets});
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
