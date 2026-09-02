#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');

export const A12_PARENT_REVISION = '827b45897bd22e9d226b3ccfa54f70239f922e03';
export const A12_VERIFICATION_SCHEMA = 'stacks-attacknet-release-1-a12-verification/v1';
export const A12_ATTESTATION_SCHEMA = 'stacks-attacknet-release-1-a12-candidate-attestation/v1';
export const A12_CHECK_IDS = Object.freeze([
  'patched-signer-rust-tests',
  'operator-verify', 'operator-race', 'kubernetes-envtest', 'helm-lint',
  'helm-render-and-rbac', 'whole-attacknet-check', 'whole-hacknet-check',
]);

function patchedSignerRustTests(qualification, environment) {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-a12-signer-tests-'));
  const source = join(root, 'source');
  let worktreeAdded = false;
  try {
    passed(run({
      id: 'patched-signer-worktree', executable: 'git',
      arguments_: ['worktree', 'add', '--detach', source, A12_PARENT_REVISION],
    }));
    worktreeAdded = true;
    passed(run({
      id: 'patched-signer-qualified-tree', executable: 'git',
      arguments_: ['apply', '--binary', '-'], cwd: source, input: qualification.patch,
    }));
    const policyPatch = join(source,
      'contrib/attacknet/test/fixtures/adversaries/deterministic-signer.patch');
    passed(run({
      id: 'patched-signer-policy', executable: 'git',
      arguments_: ['apply', '--binary', policyPatch], cwd: source,
    }));
    return passed(run({
      id: 'patched-signer-rust-tests', executable: 'cargo',
      arguments_: [
        'nextest', 'run', '-p', 'stacks-signer', '--features',
        'monitoring_prom,testing', 'attacknet_policy_tests',
      ],
      cwd: source,
      env: {
        ...environment, CARGO_INCREMENTAL: '0', RUSTC_WRAPPER: '',
        CARGO_TARGET_DIR: process.env.ATTACKNET_A12_CARGO_TARGET_DIR
          ?? join(tmpdir(), 'attacknet-a12-cargo-target'),
      },
    }));
  } finally {
    if (worktreeAdded) {
      passed(run({
        id: 'patched-signer-worktree-remove', executable: 'git',
        arguments_: ['worktree', 'remove', '--force', source],
      }));
    }
    rmSync(root, {recursive: true, force: true});
  }
}

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
    const diagnostic = [check.stdout, check.stderr].filter(Boolean).join('\n');
    throw new Error(`${check.id} failed (${check.command})\n${diagnostic}`);
  }
  return check;
}

function git(...arguments_) {
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_: arguments_})).stdout.trim();
}

function binaryPatch(tree) {
  const result = spawnSync('git', ['diff', '--binary', A12_PARENT_REVISION, tree], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 128 << 20,
  });
  if (result.status !== 0 || !result.stdout?.length) {
    throw new Error('qualified A12 diff could not be captured');
  }
  return result.stdout;
}

/** Bind qualification to the exact staged A12 tree before the candidate commit. */
export function requireA12QualifiedTree(expectedTree = undefined) {
  if (git('rev-parse', 'HEAD') !== A12_PARENT_REVISION) {
    throw new Error(`A12 qualification HEAD must equal ${A12_PARENT_REVISION}`);
  }
  if (git('diff', '--name-only')) {
    throw new Error('A12 qualification requires the worktree to match the staged index');
  }
  if (git('ls-files', '--others', '--exclude-standard')) {
    throw new Error('A12 qualification requires no untracked files');
  }
  const qualifiedTree = git('write-tree');
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree) || expectedTree && qualifiedTree !== expectedTree) {
    throw new Error('A12 qualified tree does not match the staged index');
  }
  const patch = binaryPatch(qualifiedTree);
  return {
    qualifiedTree, parentRevision: A12_PARENT_REVISION,
    patchDigest: digest(patch), patch,
  };
}

/** Bind one final hardware-signed commit to the qualified A12 tree. */
export function bindA12SignedCandidate(candidateRevision, qualification, evidenceSummaryDigest) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '') || git('rev-parse', 'HEAD') !== candidateRevision) {
    throw new Error('candidate must be the full HEAD SHA');
  }
  if (git('status', '--porcelain', '--untracked-files=all')) {
    throw new Error('A12 packet assembly requires a clean worktree');
  }
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  const parents = git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean);
  if (parents.length !== 1 || parents[0] !== A12_PARENT_REVISION
    || qualification?.parentRevision !== A12_PARENT_REVISION) {
    throw new Error('A12 must be one signed non-merge child of its qualified base');
  }
  const candidateTree = git('show', '-s', '--format=%T', candidateRevision);
  if (candidateTree !== qualification.qualifiedTree
    || digest(binaryPatch(candidateRevision)) !== qualification.patchDigest) {
    throw new Error('signed A12 candidate differs from the qualified tree or diff');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(evidenceSummaryDigest ?? '')) {
    throw new Error('A12 attestation requires a sealed evidence summary digest');
  }
  return {
    schema: A12_ATTESTATION_SCHEMA, candidateRevision, candidateTree,
    parentRevision: A12_PARENT_REVISION, patchDigest: qualification.patchDigest,
    evidenceSummaryDigest, signatureVerified: true, recordedAt: new Date().toISOString(),
  };
}

/** Validate the lightweight post-sign A12 candidate attestation. */
export function validateA12CandidateAttestation(value, qualification, evidenceSummaryDigest) {
  if (value?.schema !== A12_ATTESTATION_SCHEMA
    || !/^[0-9a-f]{40}$/.test(value.candidateRevision ?? '')
    || value.candidateTree !== qualification?.qualifiedTree
    || value.parentRevision !== A12_PARENT_REVISION
    || value.patchDigest !== qualification?.patchDigest
    || value.evidenceSummaryDigest !== evidenceSummaryDigest
    || value.signatureVerified !== true
    || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A12 candidate attestation is invalid');
  }
  return value;
}

/** Validate one complete qualified-tree-bound A12 verification record. */
export function validateA12Verification(value, qualifiedTree) {
  if (value?.schema !== A12_VERIFICATION_SCHEMA || value.qualifiedTree !== qualifiedTree
    || value.parentRevision !== A12_PARENT_REVISION
    || !/^sha256:[0-9a-f]{64}$/.test(value.patchDigest ?? '')
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A12 verification is not a complete pass');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== A12_CHECK_IDS.length || checks.size !== value.checks?.length) {
    throw new Error('A12 verification contains duplicate, missing, or unknown checks');
  }
  for (const id of A12_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0 || typeof check.command !== 'string'
      || !Number.isSafeInteger(check.durationMs) || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')) {
      throw new Error(`A12 verification check ${id} is incomplete`);
    }
  }
  return value;
}

/** Run Full-tier offline verification once against the staged A12 tree. */
export function runA12Verification({qualifiedTree, outputDirectory, envtestAssets}) {
  const qualification = requireA12QualifiedTree(qualifiedTree);
  if (!envtestAssets || !statSync(envtestAssets).isDirectory()) {
    throw new Error('envtestAssets must identify an installed envtest directory');
  }
  const output = resolve(outputDirectory);
  mkdirSync(output, {recursive: true});
  const goCache = join(output, 'go-cache');
  mkdirSync(goCache, {recursive: true});
  const environment = {
    ...process.env, GOCACHE: goCache, KUBEBUILDER_ASSETS: resolve(envtestAssets),
    ATTACKNET_QUALIFIED_TREE: qualification.qualifiedTree,
  };
  const checks = [];
  checks.push(patchedSignerRustTests(qualification, environment));
  checks.push(passed(run({id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'operator-race', executable: 'go', arguments_: ['test', '-race', './...'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'kubernetes-envtest', executable: 'make', arguments_: ['test-integration'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'helm-lint', executable: 'helm', arguments_: ['lint', 'contrib/helm/hacknet'], env: environment})));
  const rendered = passed(run({id: 'helm-render', executable: 'helm', arguments_: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds'], env: environment}));
  checks.push(passed(run({id: 'helm-render-and-rbac', executable: 'go', arguments_: ['run', './cmd/rbac-check'], cwd: operatorDirectory, env: environment, input: rendered.stdout})));
  checks.push(passed(run({id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/test/check.sh'], env: {...environment, ATTACKNET_OFFLINE_RESULT: join(output, 'attacknet-result.json')}})));
  checks.push(passed(run({id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'], env: {...environment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')}})));
  const result = {
    schema: A12_VERIFICATION_SCHEMA, qualifiedTree: qualification.qualifiedTree,
    parentRevision: qualification.parentRevision, patchDigest: qualification.patchDigest,
    outcome: 'Passed', recordedAt: new Date().toISOString(), checks,
  };
  validateA12Verification(result, qualification.qualifiedTree);
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeFileSync(join(output, 'candidate.patch'), qualification.patch);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  for (const required of ['--qualified-tree=', '--output=', '--envtest-assets=']) {
    if (!value(required)) throw new Error(`${required.slice(2, -1)} is required`);
  }
  runA12Verification({
    qualifiedTree: value('--qualified-tree='), outputDirectory: value('--output='),
    envtestAssets: value('--envtest-assets='),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}
