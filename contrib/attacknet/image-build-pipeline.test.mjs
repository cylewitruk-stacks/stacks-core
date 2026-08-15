import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  executeImageBuildPipeline,
  planImageBuildPipeline,
  runImageBuildPipeline,
} from './image-build-pipeline.mjs';

const SHA_A = `sha256:${'a'.repeat(64)}`;
const SHA_B = `sha256:${'b'.repeat(64)}`;
const SHA_C = `sha256:${'c'.repeat(64)}`;
const cargoChef = `registry.invalid/cargo-chef@${SHA_A}`;
const runtime = `registry.invalid/debian@${SHA_B}`;

function git(repository, ...args) {
  return execFileSync('git', ['-C', repository, ...args], {encoding: 'utf8'}).trim();
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-image-pipeline-'));
  const repository = join(root, 'repository');
  mkdirSync(repository);
  git(repository, 'init', '--quiet');
  git(repository, 'config', 'user.name', 'Attacknet Test');
  git(repository, 'config', 'user.email', 'attacknet@example.invalid');
  writeFileSync(join(repository, 'Cargo.toml'), '[workspace]\nmembers=[]\n');
  writeFileSync(join(repository, 'tracked.txt'), 'committed\n');
  git(repository, 'add', '.');
  git(repository, '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'released');
  const releasedRevision = git(repository, 'rev-parse', 'HEAD');
  git(repository, 'tag', 'v1');
  writeFileSync(join(repository, 'tracked.txt'), 'current\n');
  git(repository, 'add', '.');
  git(repository, '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'current');
  writeFileSync(join(repository, 'modified.txt'), 'local modification\n');
  const dockerfile = join(root, 'Dockerfile');
  writeFileSync(dockerfile, [
    'ARG CARGO_CHEF_IMAGE=example.invalid/cargo-chef:latest',
    'FROM ${CARGO_CHEF_IMAGE} AS chef',
    'ENV CARGO_INCREMENTAL=0',
    'RUN cargo chef prepare --recipe-path recipe.json',
    'RUN cargo chef cook --recipe-path recipe.json',
    'ARG RUNTIME_IMAGE=debian:latest',
    'FROM ${RUNTIME_IMAGE}',
    '',
  ].join('\n'));
  const input = {
    schemaVersion: 1,
    pipelineId: 'mixed-fixture',
    repository,
    dockerfile,
    imageRepository: 'stacks-core-attacknet',
    targetPlatform: 'linux/arm64',
    baseImages: {cargoChef, runtime},
    profiles: [
      {id: 'current', source: {kind: 'current'}},
      {
        id: 'released',
        source: {kind: 'releasedGitRef', gitRef: 'v1', expectedRevision: releasedRevision},
      },
      {
        id: 'modified',
        source: {kind: 'localModified', baseRef: 'HEAD', changeId: 'adversarial-change'},
      },
    ],
  };
  return {root, repository, dockerfile, releasedRevision, input};
}

test('plan resolves exact current, release, and local-modified sources without executing commands', () => {
  const {input, releasedRevision} = fixture();
  let commands = 0;
  const output = runImageBuildPipeline(input, {
    runner() { commands += 1; throw new Error('must not execute'); },
  });
  assert.equal(commands, 0);
  assert.equal(output.result, null);
  assert.equal(output.plan.execution.defaultMode, 'plan-only');
  assert.equal(output.plan.execution.kubernetesApiMutation, false);
  assert.equal(output.plan.profiles.length, 3);
  assert.equal(output.plan.profiles[1].source.revision, releasedRevision);
  assert.equal(output.plan.profiles[1].source.dirty, false);
  assert.equal(output.plan.profiles[2].source.dirty, true);
  assert.match(output.plan.profiles[0].plannedLocalRef, /:src-[0-9a-f]{24}$/);
  assert.equal(output.plan.acceptanceReady, false);
});

test('execution uses BuildKit provenance, content tags, exact source contexts, and no kind mutation by default', () => {
  const {root, input} = fixture();
  const plan = planImageBuildPipeline(input);
  const calls = [];
  const runner = (command, args, options = {}) => {
    calls.push({command, args, env: options.env});
    if (command === 'docker') {
      const metadataPath = args[args.indexOf('--metadata-file') + 1];
      writeFileSync(metadataPath, JSON.stringify({
        'containerimage.digest': SHA_C,
        'buildx.build.provenance': {materials: [{uri: 'fixture'}]},
      }));
    }
    return {status: 0, stdout: '', stderr: ''};
  };
  const result = executeImageBuildPipeline(plan, {
    outputDirectory: join(root, 'evidence'),
    temporaryRoot: join(root, 'contexts'),
    runner,
  });
  assert.equal(calls.length, 3);
  assert.ok(calls.every(call => call.command === 'docker'));
  for (const call of calls) {
    assert.deepEqual(call.args.slice(0, 2), ['buildx', 'build']);
    assert.ok(call.args.includes('--provenance=mode=max'));
    assert.ok(call.args.includes('--sbom=true'));
    assert.ok(call.args.includes(`CARGO_CHEF_IMAGE=${cargoChef}`));
    assert.ok(call.args.includes(`RUNTIME_IMAGE=${runtime}`));
    assert.ok(call.args.includes('CARGO_INCREMENTAL=0'));
    assert.equal(call.env.CARGO_INCREMENTAL, '0');
    assert.match(call.args[call.args.indexOf('--tag') + 1], /:content-[0-9a-f]{24}$/);
  }
  assert.equal(result.kindMutationPerformed, false);
  assert.equal(result.kubernetesApiMutationPerformed, false);
  assert.equal(result.acceptanceReady, false);
  assert.equal(result.profiles[0].immutableRef, `stacks-core-attacknet@${SHA_C}`);
  assert.equal(result.profiles[0].acceptanceImageRef, `stacks-core-attacknet@${SHA_C}`);
  assert.notEqual(result.profiles[0].acceptanceImageRef, result.profiles[0].localRef);
  assert.equal(result.profiles[0].acceptanceReady, false);
  assert.equal(readFileSync(join(root, 'contexts', 'released', 'tracked.txt'), 'utf8'), 'committed\n');
  assert.equal(readFileSync(join(root, 'contexts', 'current', 'tracked.txt'), 'utf8'), 'current\n');
  assert.equal(readFileSync(join(root, 'contexts', 'modified', 'modified.txt'), 'utf8'), 'local modification\n');
});

test('kind loading is explicit and remains separate from Kubernetes admission', () => {
  const {root, input} = fixture();
  input.profiles = [input.profiles[0]];
  const plan = planImageBuildPipeline(input);
  const calls = [];
  const runner = (command, args) => {
    calls.push([command, ...args]);
    if (command === 'docker') {
      const metadataPath = args[args.indexOf('--metadata-file') + 1];
      writeFileSync(metadataPath, JSON.stringify({
        'containerimage.digest': SHA_C,
        'buildx.build.provenance': {materials: []},
      }));
    }
    return {status: 0, stdout: '', stderr: ''};
  };
  const result = executeImageBuildPipeline(plan, {
    outputDirectory: join(root, 'evidence'),
    temporaryRoot: join(root, 'contexts'),
    loadKindCluster: 'attacknet',
    runner,
  });
  assert.deepEqual(calls[1].slice(0, 4), ['kind', 'load', 'docker-image', result.profiles[0].localRef]);
  assert.deepEqual(calls[1].slice(-2), ['--name', 'attacknet']);
  assert.equal(result.kindMutationPerformed, true);
  assert.equal(result.kubernetesApiMutationPerformed, false);
  assert.equal(result.acceptanceReady, false);
});

test('mutable base images and moved release refs fail before build execution', () => {
  const {input} = fixture();
  input.baseImages.runtime = 'debian:bookworm-slim';
  assert.throws(() => planImageBuildPipeline(input), /baseImages.runtime must be digest-pinned/);

  const second = fixture().input;
  second.profiles[1].source.expectedRevision = '0'.repeat(40);
  assert.throws(() => planImageBuildPipeline(second), /resolved to .* expected 0000/);

  const third = fixture().input;
  delete third.profiles[1].source.expectedRevision;
  assert.throws(() => planImageBuildPipeline(third), /must pin the intended 40-character commit/);
});

test('source changes after planning are rejected rather than mislabeled with the planned content key', () => {
  const {root, repository, input} = fixture();
  input.profiles = [input.profiles[0]];
  const plan = planImageBuildPipeline(input);
  writeFileSync(join(repository, 'modified.txt'), 'changed after planning\n');
  let commands = 0;
  assert.throws(() => executeImageBuildPipeline(plan, {
    outputDirectory: join(root, 'evidence'),
    temporaryRoot: join(root, 'contexts'),
    runner() { commands += 1; },
  }), /changed after planning/);
  assert.equal(commands, 0);
});

test('Dockerfile changes after planning are rejected before any build command', () => {
  const {root, dockerfile, input} = fixture();
  input.profiles = [input.profiles[0]];
  const plan = planImageBuildPipeline(input);
  writeFileSync(dockerfile, `${readFileSync(dockerfile, 'utf8')}\n# changed\n`);
  let commands = 0;
  assert.throws(() => executeImageBuildPipeline(plan, {
    outputDirectory: join(root, 'evidence'),
    temporaryRoot: join(root, 'contexts'),
    runner() { commands += 1; },
  }), /Dockerfile changed after planning/);
  assert.equal(commands, 0);
});

test('BuildKit metadata must contain both an immutable digest and provenance', () => {
  const {root, input} = fixture();
  input.profiles = [input.profiles[0]];
  const plan = planImageBuildPipeline(input);
  const runner = (_command, args) => {
    const metadataPath = args[args.indexOf('--metadata-file') + 1];
    writeFileSync(metadataPath, JSON.stringify({'containerimage.digest': SHA_C}));
    return {status: 0, stdout: '', stderr: ''};
  };
  assert.throws(() => executeImageBuildPipeline(plan, {
    outputDirectory: join(root, 'evidence'),
    temporaryRoot: join(root, 'contexts'),
    runner,
  }), /has no provenance object/);
});
