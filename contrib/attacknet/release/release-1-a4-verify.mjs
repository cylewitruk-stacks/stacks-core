#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, statSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const RESULT_SCHEMA = 'stacks-attacknet-release-1-a4-verification/v1';
const APPROVED_A3_REVISION = '5b6d3018374d24946c12ec46406ee6abed10ca56';

export const A4_CHECK_IDS = Object.freeze([
  'operator-verify',
  'operator-race',
  'kubernetes-1.36-envtest',
  'fault-compiler-equivalence',
  'topology-equivalence-profiles',
  'helm-lint',
  'helm-render',
  'structural-rbac-contract',
  'whole-attacknet-check',
  'whole-hacknet-check',
]);

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function quote(value) {
  return /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

function run({id, executable, arguments_: args, cwd = repositoryRoot, env = process.env, input}) {
  const startedAt = new Date();
  const result = spawnSync(executable, args, {
    cwd, env, input, encoding: 'utf8', maxBuffer: 64 << 20,
  });
  const stdout = result.stdout ?? '';
  const stderr = `${result.error ? `${result.error.message}\n` : ''}${result.stderr ?? ''}`;
  const exitCode = result.status ?? (result.error ? -1 : 0);
  return {
    id,
    status: exitCode === 0 && !result.error ? 'passed' : 'failed',
    command: [executable, ...args].map(quote).join(' '),
    cwd: relative(repositoryRoot, cwd) || '.',
    startedAt: startedAt.toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    exitCode,
    outputDigest: digest(Buffer.from(`${stdout}\0${stderr}`)),
    stdout,
    stderr,
  };
}

function passed(check) {
  if (check.status !== 'passed') throw new Error(`${check.id} failed (${check.command})\n${check.stderr || check.stdout}`);
  return check;
}

function git(...arguments_) {
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_})).stdout.trim();
}

function requireCandidate(candidateRevision) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) throw new Error('candidate must be a full Git SHA');
  if (git('rev-parse', 'HEAD') !== candidateRevision) throw new Error('candidate must equal HEAD');
  if (git('status', '--porcelain', '--untracked-files=all')) throw new Error('A4 verification requires a clean worktree');
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  if (git('rev-parse', `${candidateRevision}^`) !== APPROVED_A3_REVISION) {
    throw new Error(`A4 must be one commit directly on approved A3 ${APPROVED_A3_REVISION}`);
  }
  if (git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean).length !== 1) {
    throw new Error('A4 candidate must be a non-merge commit');
  }
}

/** Run the candidate-bound offline verification required by Amendment A4. */
export function runReleaseOneA4Verification({
  candidateRevision,
  outputDirectory,
  envtestAssets,
  kubernetesVersion = '1.36.2',
}) {
  requireCandidate(candidateRevision);
  if (!/^1\.36\.[0-9]+$/.test(kubernetesVersion ?? '')) {
    throw new Error('kubernetesVersion must identify an exact Kubernetes 1.36 patch release');
  }
  if (!envtestAssets || !statSync(envtestAssets).isDirectory()) {
    throw new Error('envtestAssets must identify an installed envtest binary directory');
  }
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  const goEnvironment = {...process.env, KUBEBUILDER_ASSETS: resolve(envtestAssets)};
  const checks = [];
  checks.push(passed(run({
    id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory,
    env: goEnvironment,
  })));
  checks.push(passed(run({
    id: 'operator-race', executable: 'go', arguments_: ['test', '-race', './...'],
    cwd: operatorDirectory, env: goEnvironment,
  })));
  checks.push(passed(run({
    id: 'kubernetes-1.36-envtest', executable: 'make', arguments_: ['test-integration'],
    cwd: operatorDirectory, env: goEnvironment,
  })));
  checks.push(passed(run({
    id: 'fault-compiler-equivalence', executable: 'node',
    arguments_: ['--test', 'contrib/attacknet/fault-compiler-equivalence.test.mjs'], env: goEnvironment,
  })));
  checks.push(passed(run({
    id: 'topology-equivalence-profiles', executable: 'node',
    arguments_: ['--test', 'contrib/attacknet/topology-render-equivalence.test.mjs'], env: goEnvironment,
  })));
  checks.push(passed(run({
    id: 'helm-lint', executable: 'helm', arguments_: ['lint', 'contrib/helm/hacknet'],
  })));
  const rendered = passed(run({
    id: 'helm-render', executable: 'helm',
    arguments_: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds'],
  }));
  checks.push(rendered);
  checks.push(passed(run({
    id: 'structural-rbac-contract', executable: 'go', arguments_: ['run', './cmd/rbac-check'],
    cwd: operatorDirectory, env: goEnvironment, input: rendered.stdout,
  })));
  checks.push(passed(run({
    id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/check.sh'],
    env: {...goEnvironment, ATTACKNET_OFFLINE_RESULT: join(output, 'offline-result.json')},
  })));
  checks.push(passed(run({
    id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'],
    env: {...goEnvironment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')},
  })));
  const result = {
    schema: RESULT_SCHEMA,
    candidateRevision,
    outcome: 'Passed',
    recordedAt: new Date().toISOString(),
    kubernetesVersion,
    checks,
  };
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  const patch = spawnSync('git', ['diff', '--binary', APPROVED_A3_REVISION, candidateRevision], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 64 << 20,
  });
  if (patch.status !== 0 || !patch.stdout?.length) throw new Error('candidate diff could not be captured');
  writeFileSync(join(output, 'candidate.patch'), patch.stdout);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--output=', '--envtest-assets=', '--kubernetes-version='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const candidateRevision = value('--candidate=');
  const outputDirectory = value('--output=');
  const envtestAssets = value('--envtest-assets=');
  if (!candidateRevision || !outputDirectory || !envtestAssets) {
    throw new Error('usage: release-1-a4-verify.mjs --candidate=SHA --output=DIR --envtest-assets=DIR [--kubernetes-version=1.36.2]');
  }
  runReleaseOneA4Verification({
    candidateRevision, outputDirectory, envtestAssets,
    kubernetesVersion: value('--kubernetes-version=') ?? '1.36.2',
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
