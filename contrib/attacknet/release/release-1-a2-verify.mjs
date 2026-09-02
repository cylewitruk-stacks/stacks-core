#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  cpSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const releaseDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(releaseDirectory, '../../..');
const operatorDirectory = join(repositoryRoot, 'contrib/helm/hacknet/operator');
const RESULT_SCHEMA = 'stacks-attacknet-release-1-a2-result/v1';
const APPROVED_A1_REVISION = 'f8a853a0f21c9edebec92398fb56500ae10e1a22';

export const A2_OFFLINE_CHECK_IDS = Object.freeze({
  goVerify: Object.freeze([
    'go-build', 'go-format', 'go-generate-clean', 'go-vet', 'go-unit', 'go-race',
  ]),
  envtest: Object.freeze(['kubernetes-1.36-envtest']),
  helmRender: Object.freeze([
    'helm-lint', 'helm-render', 'crd-contracts', 'rbac-security-contracts',
  ]),
});

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function shellQuote(value) {
  return /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

function displayCommand(executable, args) {
  return [executable, ...args].map(shellQuote).join(' ');
}

function runObserved({id, executable, args, cwd, env = process.env}) {
  const startedAt = new Date();
  const result = spawnSync(executable, args, {
    cwd, env, encoding: 'utf8', maxBuffer: 64 << 20,
  });
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  const exitCode = result.status ?? (result.error ? -1 : 0);
  return {
    id,
    status: exitCode === 0 && !result.error ? 'passed' : 'failed',
    command: displayCommand(executable, args),
    cwd: relative(repositoryRoot, cwd) || '.',
    startedAt: startedAt.toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    exitCode,
    outputDigest: digestBytes(Buffer.from(`${stdout}\0${stderr}`)),
    stdout,
    stderr: `${result.error ? `${result.error.message}\n` : ''}${stderr}`,
  };
}

function requirePassed(check) {
  if (check.status !== 'passed') {
    throw new Error(`${check.id} failed (${check.command})\n${check.stderr || check.stdout}`);
  }
  return check;
}

function walkGoFiles(directory) {
  const files = [];
  const visit = path => {
    for (const entry of readdirSync(path, {withFileTypes: true})
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const candidate = join(path, entry.name);
      if (entry.isDirectory()) visit(candidate);
      else if (entry.isFile() && entry.name.endsWith('.go')) files.push(candidate);
    }
  };
  visit(directory);
  return files;
}

function formatCheck() {
  const files = walkGoFiles(operatorDirectory).map(path => relative(repositoryRoot, path));
  const check = runObserved({id: 'go-format', executable: 'gofmt', args: ['-l', ...files], cwd: repositoryRoot});
  if (check.status === 'passed' && check.stdout.trim().length > 0) {
    check.status = 'failed';
    check.stderr += `Go files require formatting:\n${check.stdout}`;
  }
  return check;
}

function generationCheck() {
  const temporary = mkdtempSync(join(tmpdir(), 'attacknet-a2-generate-'));
  const isolated = join(temporary, 'operator');
  try {
    cpSync(operatorDirectory, isolated, {recursive: true});
    const generated = join(isolated, 'api/v1alpha1/zz_generated.deepcopy.go');
    const before = readFileSync(generated);
    const check = runObserved({
      id: 'go-generate-clean', executable: 'make', args: ['generate'], cwd: isolated,
    });
    if (check.status === 'passed' && digestBytes(before) !== digestBytes(readFileSync(generated))) {
      check.status = 'failed';
      check.stderr += 'Generated deepcopy output differs from the committed source.\n';
    }
    check.command = 'make generate (isolated candidate copy)';
    check.cwd = 'contrib/helm/hacknet/operator';
    return check;
  } finally {
    rmSync(temporary, {recursive: true, force: true});
  }
}

function writeResult(path, candidateRevision, checks, extra = {}) {
  const outcome = checks.every(check => check.status === 'passed') ? 'Passed' : 'Failed';
  const result = {
    schema: RESULT_SCHEMA,
    candidateRevision,
    outcome,
    recordedAt: new Date().toISOString(),
    checks,
    ...extra,
  };
  writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`);
  if (outcome !== 'Passed') throw new Error(`${path} contains failed verification checks`);
  return result;
}

function requireCandidate(candidateRevision) {
  if (!/^[0-9a-f]{40}$/.test(candidateRevision ?? '')) {
    throw new Error('candidateRevision must be a full Git SHA');
  }
  const head = requirePassed(runObserved({
    id: 'candidate-head', executable: 'git', args: ['rev-parse', 'HEAD'], cwd: repositoryRoot,
  })).stdout.trim();
  if (head !== candidateRevision) throw new Error('candidateRevision must equal HEAD');
  const status = requirePassed(runObserved({
    id: 'candidate-clean', executable: 'git', args: ['status', '--porcelain', '--untracked-files=all'], cwd: repositoryRoot,
  })).stdout.trim();
  if (status.length > 0) throw new Error('A2 verification requires a clean candidate worktree');
  requirePassed(runObserved({
    id: 'candidate-signature', executable: 'git', args: ['verify-commit', candidateRevision], cwd: repositoryRoot,
  }));
  const parent = requirePassed(runObserved({
    id: 'candidate-parent', executable: 'git', args: ['rev-parse', `${candidateRevision}^`], cwd: repositoryRoot,
  })).stdout.trim();
  if (parent !== APPROVED_A1_REVISION) {
    throw new Error(`A2 candidate must be directly based on approved A1 ${APPROVED_A1_REVISION}`);
  }
}

/** Run the complete machine-produced A2 offline verification set. */
export function runReleaseOneA2OfflineVerification({
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
  const goEnvironment = {...process.env};
  const goChecks = [
    runObserved({id: 'go-build', executable: 'go', args: ['build', './...'], cwd: operatorDirectory, env: goEnvironment}),
    formatCheck(),
    generationCheck(),
    runObserved({id: 'go-vet', executable: 'go', args: ['vet', './...'], cwd: operatorDirectory, env: goEnvironment}),
    runObserved({id: 'go-unit', executable: 'go', args: ['test', './...'], cwd: operatorDirectory, env: goEnvironment}),
    runObserved({id: 'go-race', executable: 'go', args: ['test', '-race', './...'], cwd: operatorDirectory, env: goEnvironment}),
  ];
  writeResult(join(output, 'go-verify.json'), candidateRevision, goChecks);

  const envtestChecks = [runObserved({
    id: 'kubernetes-1.36-envtest', executable: 'go',
    args: ['test', '-tags=integration', './internal/integration', '-count=1'],
    cwd: operatorDirectory, env: {...goEnvironment, KUBEBUILDER_ASSETS: resolve(envtestAssets)},
  })];
  writeResult(join(output, 'envtest.json'), candidateRevision, envtestChecks, {kubernetesVersion});

  const helmChecks = [
    runObserved({id: 'helm-lint', executable: 'helm', args: ['lint', 'contrib/helm/hacknet'], cwd: repositoryRoot}),
    runObserved({
      id: 'helm-render', executable: 'helm',
      args: ['template', 'hacknet', 'contrib/helm/hacknet', '--namespace', 'hacknet-system', '--include-crds'],
      cwd: repositoryRoot,
    }),
    runObserved({
      id: 'crd-contracts', executable: 'node',
      args: ['--test', 'contrib/helm/hacknet/crds/attacknet-crds.test.mjs'], cwd: repositoryRoot,
    }),
    runObserved({
      id: 'rbac-security-contracts', executable: 'node',
      args: ['--test', 'contrib/helm/hacknet/security-contract.test.mjs'], cwd: repositoryRoot,
    }),
  ];
  writeResult(join(output, 'helm-render.json'), candidateRevision, helmChecks);

  const attacknet = runObserved({
    id: 'whole-attacknet-check', executable: 'bash', args: ['contrib/attacknet/check.sh'],
    cwd: repositoryRoot, env: {...process.env, ATTACKNET_OFFLINE_RESULT: join(output, 'offline-result.json')},
  });
  requirePassed(attacknet);
  const hacknet = runObserved({
    id: 'whole-hacknet-check', executable: 'bash', args: ['contrib/helm/hacknet/scripts/check.sh'],
    cwd: repositoryRoot,
    env: {
      ...process.env,
      KUBEBUILDER_ASSETS: resolve(envtestAssets),
      HACKNET_OFFLINE_RESULT: join(output, 'hacknet-result.json'),
    },
  });
  requirePassed(hacknet);

  const patch = spawnSync('git', ['diff', '--binary', APPROVED_A1_REVISION, candidateRevision], {
    cwd: repositoryRoot, encoding: null, maxBuffer: 64 << 20,
  });
  if (patch.status !== 0 || !patch.stdout?.length) throw new Error('candidate diff could not be captured');
  writeFileSync(join(output, 'candidate.patch'), patch.stdout);
  return {goChecks, envtestChecks, helmChecks, attacknet, hacknet};
}

function main(args) {
  const value = prefix => args.find(argument => argument.startsWith(prefix))?.slice(prefix.length);
  const known = ['--candidate=', '--output=', '--envtest-assets=', '--kubernetes-version='];
  const unknown = args.find(argument => !known.some(prefix => argument.startsWith(prefix)));
  if (unknown) throw new Error(`unknown option ${unknown}`);
  const candidateRevision = value('--candidate=');
  const outputDirectory = value('--output=');
  const envtestAssets = value('--envtest-assets=');
  if (!candidateRevision || !outputDirectory || !envtestAssets) {
    throw new Error('usage: release-1-a2-verify.mjs --candidate=SHA --output=DIR --envtest-assets=DIR [--kubernetes-version=1.36.2]');
  }
  runReleaseOneA2OfflineVerification({
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
