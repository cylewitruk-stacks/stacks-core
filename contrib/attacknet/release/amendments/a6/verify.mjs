#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const APPROVED_A5_REVISION = '7b16b53c520778a143767751f0b95275f0d7a0d9';

export const A6_VERIFICATION_SCHEMA = 'stacks-attacknet-release-1-a6-verification/v1';
export const A6_CHECK_IDS = Object.freeze([
  'operator-verify',
  'whole-attacknet-check',
  'whole-hacknet-check',
]);

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function quote(value) {
  return /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

function run({id, executable, arguments_: args, cwd = repositoryRoot, env = process.env}) {
  const startedAt = new Date();
  const result = spawnSync(executable, args, {
    cwd, env, encoding: 'utf8', maxBuffer: 64 << 20,
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
  if (check.status !== 'passed') {
    throw new Error(`${check.id} failed (${check.command})\n${check.stderr || check.stdout}`);
  }
  return check;
}

function git(...arguments_) {
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_})).stdout.trim();
}

/** Validate the immutable, direct-child A6 candidate before running checks. */
export function requireA6Candidate(candidateRevision) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) throw new Error('candidate must be a full Git SHA');
  if (git('rev-parse', 'HEAD') !== candidateRevision) throw new Error('candidate must equal HEAD');
  if (git('status', '--porcelain', '--untracked-files=all')) throw new Error('A6 verification requires a clean worktree');
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  const parents = git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean);
  if (parents.length !== 1 || parents[0] !== APPROVED_A5_REVISION) {
    throw new Error(`A6 must be one signed non-merge commit directly on approved A5 ${APPROVED_A5_REVISION}`);
  }
}

/** Validate one complete A6 offline verification record. */
export function validateA6Verification(value, candidateRevision) {
  if (value?.schema !== A6_VERIFICATION_SCHEMA || value.candidateRevision !== candidateRevision
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A6 verification is not a passed candidate-bound result');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== value.checks?.length || checks.size !== A6_CHECK_IDS.length) {
    throw new Error('A6 verification contains duplicate, missing, or unexpected checks');
  }
  for (const id of A6_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0
      || typeof check.command !== 'string' || !Number.isSafeInteger(check.durationMs)
      || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')
      || typeof check.stdout !== 'string' || typeof check.stderr !== 'string') {
      throw new Error(`A6 verification check ${id} is not a complete pass`);
    }
  }
  return value;
}

/** Run the candidate-bound Reduced-tier verification required by A6. */
export function runA6Verification({candidateRevision, outputDirectory}) {
  requireA6Candidate(candidateRevision);
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  const goCache = join(output, 'go-cache');
  mkdirSync(goCache, {recursive: true});
  const environment = {...process.env, GOCACHE: goCache};
  const checks = [
    passed(run({id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory, env: environment})),
    passed(run({
      id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/test/check.sh'],
      env: {...environment, ATTACKNET_OFFLINE_RESULT: join(output, 'attacknet-result.json')},
    })),
    passed(run({
      id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'],
      env: {...environment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')},
    })),
  ];
  const result = {
    schema: A6_VERIFICATION_SCHEMA,
    candidateRevision,
    outcome: 'Passed',
    recordedAt: new Date().toISOString(),
    checks,
  };
  validateA6Verification(result, candidateRevision);
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  const patch = spawnSync('git', ['diff', '--binary', APPROVED_A5_REVISION, candidateRevision], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 128 << 20,
  });
  if (patch.status !== 0 || !patch.stdout?.length) throw new Error('candidate diff could not be captured');
  writeFileSync(join(output, 'candidate.patch'), patch.stdout);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--output='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const candidateRevision = value('--candidate=');
  const outputDirectory = value('--output=');
  if (!candidateRevision || !outputDirectory) {
    throw new Error('usage: verify.mjs --candidate=SHA --output=DIR');
  }
  runA6Verification({candidateRevision, outputDirectory});
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
