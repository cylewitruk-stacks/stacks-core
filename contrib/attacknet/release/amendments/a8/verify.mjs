#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync, statSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {isMainModule, isMaterializedSource, runMaterializedEntrypoint} from './qualified-source.mjs';

const amendmentDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(amendmentDirectory, '../../../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const APPROVED_A7_ROADMAP_REVISION = 'c428fcbb42bb8884cc1fe47055576130ba061346';

export const A8_VERIFICATION_SCHEMA = 'stacks-attacknet-release-1-a8-verification/v1';
export const A8_CANDIDATE_ATTESTATION_SCHEMA = 'stacks-attacknet-release-1-a8-candidate-attestation/v1';
export const A8_CHECK_IDS = Object.freeze([
  'operator-verify',
  'operator-race',
  'kubernetes-envtest',
  'helm-lint',
  'helm-render-and-rbac',
  'whole-attacknet-check',
  'whole-hacknet-check',
]);

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function quote(value) {
  return /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

function run({id, executable, arguments_: arguments__, cwd = repositoryRoot, env = process.env, input}) {
  const startedAt = new Date();
  const result = spawnSync(executable, arguments__, {
    cwd, env, input, encoding: 'utf8', maxBuffer: 128 << 20,
  });
  const stdout = result.stdout ?? '';
  const stderr = `${result.error ? `${result.error.message}\n` : ''}${result.stderr ?? ''}`;
  const exitCode = result.status ?? (result.error ? -1 : 0);
  return {
    id,
    status: exitCode === 0 && !result.error ? 'passed' : 'failed',
    command: [executable, ...arguments__].map(quote).join(' '),
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
  return passed(run({id: `git-${arguments_[0]}`, executable: 'git', arguments_: arguments_})).stdout.trim();
}

function binaryPatch(tree) {
  const patch = spawnSync('git', ['diff', '--binary', APPROVED_A7_ROADMAP_REVISION, tree], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 128 << 20,
  });
  if (patch.status !== 0 || !patch.stdout?.length) throw new Error('qualified A8 diff could not be captured');
  return patch.stdout;
}

/** Bind qualification to the exact staged tree without requiring a commit. */
export function requireA8QualifiedTree(expectedTree = undefined) {
  if (git('diff', '--name-only')) throw new Error('A8 qualification requires the worktree to match the staged index');
  if (git('ls-files', '--others', '--exclude-standard')) throw new Error('A8 qualification requires no untracked files');
  const qualifiedTree = git('write-tree');
  if (!/^[0-9a-f]{40}$/.test(qualifiedTree) || (expectedTree && qualifiedTree !== expectedTree)) {
    throw new Error('A8 qualified tree does not match the staged index');
  }
  const parents = git('show', '-s', '--format=%P', 'HEAD').split(' ').filter(Boolean);
  if (parents.length !== 1 || parents[0] !== APPROVED_A7_ROADMAP_REVISION) {
    throw new Error(`A8 qualification HEAD must be one non-merge commit directly on ${APPROVED_A7_ROADMAP_REVISION}`);
  }
  const patch = binaryPatch(qualifiedTree);
  return {
    qualifiedTree,
    parentRevision: APPROVED_A7_ROADMAP_REVISION,
    patchDigest: digest(patch),
    patch,
  };
}

/** Prove that one final signed commit contains exactly the qualified tree. */
export function bindA8SignedCandidate(candidateRevision, qualification, evidenceSummaryDigest) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) throw new Error('candidate must be a full Git SHA');
  if (git('rev-parse', 'HEAD') !== candidateRevision) throw new Error('candidate must equal HEAD');
  if (git('status', '--porcelain', '--untracked-files=all')) throw new Error('A8 packet assembly requires a clean worktree');
  passed(run({id: 'candidate-signature', executable: 'git', arguments_: ['verify-commit', candidateRevision]}));
  const parents = git('show', '-s', '--format=%P', candidateRevision).split(' ').filter(Boolean);
  if (parents.length !== 1 || parents[0] !== APPROVED_A7_ROADMAP_REVISION
    || qualification?.parentRevision !== APPROVED_A7_ROADMAP_REVISION) {
    throw new Error(`A8 must be one signed non-merge commit directly on ${APPROVED_A7_ROADMAP_REVISION}`);
  }
  const candidateTree = git('show', '-s', '--format=%T', candidateRevision);
  if (candidateTree !== qualification.qualifiedTree) {
    throw new Error('signed A8 candidate tree differs from the qualified tree');
  }
  const patchDigest = digest(binaryPatch(candidateRevision));
  if (patchDigest !== qualification.patchDigest) {
    throw new Error('signed A8 candidate diff differs from the qualified diff');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(evidenceSummaryDigest ?? '')) {
    throw new Error('signed A8 candidate attestation requires the sealed evidence summary digest');
  }
  return {
    schema: A8_CANDIDATE_ATTESTATION_SCHEMA,
    candidateRevision, candidateTree, parentRevision: APPROVED_A7_ROADMAP_REVISION,
    patchDigest, evidenceSummaryDigest, signatureVerified: true,
    recordedAt: new Date().toISOString(),
  };
}

/** Validate the lightweight post-sign attestation against sealed qualification evidence. */
export function validateA8CandidateAttestation(value, qualification, evidenceSummaryDigest) {
  if (value?.schema !== A8_CANDIDATE_ATTESTATION_SCHEMA
    || !/^[0-9a-f]{40}$/.test(value.candidateRevision ?? '')
    || value.candidateTree !== qualification?.qualifiedTree
    || value.parentRevision !== APPROVED_A7_ROADMAP_REVISION
    || value.patchDigest !== qualification?.patchDigest
    || value.evidenceSummaryDigest !== evidenceSummaryDigest
    || value.signatureVerified !== true
    || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A8 candidate attestation does not bind the signed commit to sealed qualification evidence');
  }
  return value;
}

/** Validate one complete qualified-tree-bound A8 verification record. */
export function validateA8Verification(value, qualifiedTree) {
  if (value?.schema !== A8_VERIFICATION_SCHEMA || value.qualifiedTree !== qualifiedTree
    || value.parentRevision !== APPROVED_A7_ROADMAP_REVISION
    || !/^sha256:[0-9a-f]{64}$/.test(value.patchDigest ?? '')
    || value.outcome !== 'Passed' || !Number.isFinite(Date.parse(value.recordedAt ?? ''))) {
    throw new Error('A8 verification is not a passed qualified-tree-bound result');
  }
  const checks = new Map((value.checks ?? []).map(check => [check?.id, check]));
  if (checks.size !== value.checks?.length || checks.size !== A8_CHECK_IDS.length) {
    throw new Error('A8 verification contains duplicate, missing, or unexpected checks');
  }
  for (const id of A8_CHECK_IDS) {
    const check = checks.get(id);
    if (check?.status !== 'passed' || check.exitCode !== 0
      || typeof check.command !== 'string' || !Number.isSafeInteger(check.durationMs)
      || !Number.isFinite(Date.parse(check.startedAt ?? ''))
      || !/^sha256:[0-9a-f]{64}$/.test(check.outputDigest ?? '')) {
      throw new Error(`A8 verification check ${id} is not a complete pass`);
    }
  }
  return value;
}

/** Run Full-tier offline verification once against the exact staged A8 tree. */
export function runA8Verification({qualifiedTree, outputDirectory, envtestAssets}) {
  const qualification = requireA8QualifiedTree(qualifiedTree);
  if (!envtestAssets || !statSync(envtestAssets).isDirectory()) {
    throw new Error('envtestAssets must identify an installed envtest binary directory');
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
  checks.push(passed(run({id: 'operator-verify', executable: 'make', arguments_: ['verify'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'operator-race', executable: 'go', arguments_: ['test', '-race', './...'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'kubernetes-envtest', executable: 'make', arguments_: ['test-integration'], cwd: operatorDirectory, env: environment})));
  checks.push(passed(run({id: 'helm-lint', executable: 'helm', arguments_: ['lint', 'contrib/helm/hacknet']})));
  const rendered = passed(run({
    id: 'helm-render', executable: 'helm',
    arguments_: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds'],
  }));
  checks.push(passed(run({
    id: 'helm-render-and-rbac', executable: 'go', arguments_: ['run', './cmd/rbac-check'],
    cwd: operatorDirectory, env: environment, input: rendered.stdout,
  })));
  checks.push(passed(run({
    id: 'whole-attacknet-check', executable: 'bash', arguments_: ['contrib/attacknet/test/check.sh'],
    env: {...environment, ATTACKNET_OFFLINE_RESULT: join(output, 'attacknet-result.json')},
  })));
  checks.push(passed(run({
    id: 'whole-hacknet-check', executable: 'bash', arguments_: ['contrib/helm/hacknet/scripts/check.sh'],
    env: {...environment, HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json')},
  })));
  const result = {
    schema: A8_VERIFICATION_SCHEMA,
    qualifiedTree: qualification.qualifiedTree,
    parentRevision: qualification.parentRevision,
    patchDigest: qualification.patchDigest,
    outcome: 'Passed',
    recordedAt: new Date().toISOString(),
    checks,
  };
  validateA8Verification(result, qualification.qualifiedTree);
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeFileSync(join(output, 'candidate.patch'), qualification.patch);
  return result;
}

function main(arguments_) {
  const value = prefix => arguments_.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--qualified-tree=', '--output=', '--envtest-assets='];
  const unknown = arguments_.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const qualifiedTree = value('--qualified-tree=');
  const outputDirectory = value('--output=');
  const envtestAssets = value('--envtest-assets=');
  if (!qualifiedTree || !outputDirectory || !envtestAssets) {
    throw new Error('usage: verify.mjs --qualified-tree=TREE --output=DIR --envtest-assets=DIR');
  }
  if (!isMaterializedSource(repositoryRoot)) {
    runMaterializedEntrypoint({
      repositoryRoot,
      qualifiedTree,
      script: 'contrib/attacknet/release/amendments/a8/verify.mjs',
      arguments_: [
        `--qualified-tree=${qualifiedTree}`,
        `--output=${resolve(outputDirectory)}`,
        `--envtest-assets=${resolve(envtestAssets)}`,
      ],
    });
    return;
  }
  runA8Verification({qualifiedTree, outputDirectory, envtestAssets});
}

if (isMainModule(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
