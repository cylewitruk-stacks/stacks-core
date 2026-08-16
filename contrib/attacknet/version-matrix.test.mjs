import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {compileVersionMatrix} from './version-matrix.mjs';

const SHA_A = `sha256:${'a'.repeat(64)}`;
const SHA_B = `sha256:${'b'.repeat(64)}`;
const SHA_C = `sha256:${'c'.repeat(64)}`;
const SHA_D = `sha256:${'d'.repeat(64)}`;
const image = (name, digest = SHA_A) => `registry.invalid/stacks/${name}@${digest}`;

function git(repository, ...args) {
  return execFileSync('git', ['-C', repository, ...args], {encoding: 'utf8'}).trim();
}

function repositoryFixture() {
  const repository = mkdtempSync(join(tmpdir(), 'attacknet-version-matrix-'));
  git(repository, 'init', '--quiet');
  git(repository, 'config', 'user.name', 'Attacknet Test');
  git(repository, 'config', 'user.email', 'attacknet@example.invalid');
  writeFileSync(join(repository, 'Dockerfile'), 'FROM scratch\n');
  writeFileSync(join(repository, 'Cargo.lock'), '# fixture\n');
  git(repository, 'add', 'Dockerfile', 'Cargo.lock');
  git(repository, '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'fixture');
  git(repository, 'tag', 'v4.0.2');
  return repository;
}

function compatibility(expectation = 'compatible') {
  return {expectation, basis: 'Explicit fixture hypothesis', protocolVersions: [1], epochs: ['3.0']};
}

function prebuilt(repository, kind, requestedRef, extraSource = {}) {
  return {
    source: {kind, repository, ...extraSource},
    image: {
      requestedRef, origin: 'prebuilt', platforms: ['linux/arm64'],
      attestationRef: `oci://${requestedRef}.att`, attestationDigest: SHA_D,
    },
    compatibility: compatibility(),
  };
}

function matrix(repository) {
  return {
    schemaVersion: 1,
    matrixId: 'upgrade-regression',
    targetPlatform: 'linux/arm64',
    bounds: {maxProfiles: 4, maxActors: 8, maxPhases: 4},
    actors: ['miner-1', 'miner-2', 'signer-1', 'signer-node-1'],
    defaultProfile: 'current',
    profiles: {
      current: prebuilt(repository, 'current', image('current')),
      old: prebuilt(repository, 'releasedGitRef', image('4.0.2', SHA_B), {gitRef: 'v4.0.2'}),
    },
    phases: [
      {id: 'baseline', kind: 'baseline', assignments: [], expectedOutcome: 'compatible'},
      {
        id: 'missed-upgrade', kind: 'missed-upgrade', inherits: 'baseline', expectedOutcome: 'observe',
        hypothesis: 'One miner remains on the prior release.',
        assignments: [{profile: 'old', actors: ['miner-2']}],
      },
    ],
  };
}

test('acceptance compilation resolves current and released refs and emits topology overrides', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  const output = compileVersionMatrix(input, {acceptance: true});
  const head = git(repository, 'rev-parse', 'HEAD');
  assert.equal(output.acceptanceReady, true);
  assert.equal(output.profiles.current.source.revision, head);
  assert.equal(output.profiles.old.source.revision, head);
  assert.equal(output.profiles.old.source.requestedRef, 'v4.0.2');
  assert.match(output.matrixDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(output.phases[1].actorImages['miner-2'], image('4.0.2', SHA_B));
  assert.equal(output.phases[1].actorImages['miner-1'], image('current'));
  assert.ok(output.phases[1].topologyArguments.includes(`--actor-image=miner-2=${image('4.0.2', SHA_B)}`));
});

test('planning accepts a mutable image but acceptance rejects it', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  input.profiles.old.image.requestedRef = 'registry.invalid/stacks/core:4.0.2';
  const planned = compileVersionMatrix(input);
  assert.equal(planned.acceptanceReady, false);
  assert.match(planned.unresolvedReasons[0], /mutable or unresolved/);
  assert.throws(() => compileVersionMatrix(input, {acceptance: true}), /mutable or unresolved/);
});

test('a digest-pinned prebuilt image still needs immutable provenance', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  delete input.profiles.old.image.attestationRef;
  delete input.profiles.old.image.attestationDigest;
  const planned = compileVersionMatrix(input);
  assert.equal(planned.acceptanceReady, false);
  assert.ok(planned.unresolvedReasons.some(reason => reason.includes('profiles.old.image.attestationDigest')));
  assert.throws(() => compileVersionMatrix(input, {acceptance: true}), /attestation/);
});

test('local modified builds capture worktree and complete build provenance', () => {
  const repository = repositoryFixture();
  writeFileSync(join(repository, 'modified.txt'), 'adversarial fixture\n');
  const input = matrix(repository);
  input.profiles.modified = {
    source: {kind: 'localModified', repository, changeId: 'drop-validation-response'},
    image: {requestedRef: image('modified', SHA_C), origin: 'localBuild', platforms: ['linux/arm64']},
    build: {
      dockerfile: 'Dockerfile', cargoProfile: 'release-lite', cargoChef: true, cargoIncremental: false,
      cargoFeatures: ['testing', 'slog_json', 'monitoring_prom'],
      builderImage: image('cargo-chef', SHA_B), runtimeImage: image('debian', SHA_D),
      recipeDigest: SHA_A, buildInvocationDigest: SHA_C,
      attestationRef: 'evidence/builds/modified.intoto.jsonl',
      attestationDigest: SHA_D,
    },
    compatibility: compatibility('intentionally-incompatible'),
  };
  input.phases.push({
    id: 'modified-signer', kind: 'modified-actor', inherits: 'baseline', expectedOutcome: 'intentional-failure',
    assignments: [{profile: 'modified', actors: ['signer-1']}],
  });
  const output = compileVersionMatrix(input, {acceptance: true});
  assert.equal(output.profiles.modified.source.dirty, true);
  assert.match(output.profiles.modified.source.sourceStateDigest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(output.profiles.modified.source.untrackedFiles.map(item => item.path), ['modified.txt']);
  assert.equal(output.profiles.modified.build.cargoIncremental, false);
  assert.deepEqual(output.profiles.modified.build.cargoFeatures, ['monitoring_prom', 'slog_json', 'testing']);
  assert.equal(output.phases[2].actorProfiles['signer-1'], 'modified');
});

test('local build feature provenance is bounded and preserves monitoring support', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  input.profiles.current.image.origin = 'localBuild';
  delete input.profiles.current.image.attestationRef;
  delete input.profiles.current.image.attestationDigest;
  input.profiles.current.build = {
    dockerfile: 'Dockerfile', cargoProfile: 'release-lite', cargoChef: true, cargoIncremental: false,
    cargoFeatures: ['testing'], builderImage: image('cargo-chef', SHA_B), runtimeImage: image('debian', SHA_D),
  };
  assert.throws(() => compileVersionMatrix(input), /must include monitoring_prom/);
  input.profiles.current.build.cargoFeatures = ['monitoring_prom', 'slog_json', 'testing', 'testing'];
  assert.throws(() => compileVersionMatrix(input), /must not contain duplicates/);
});

test('local builds without attestations remain plans, never acceptance inputs', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  input.profiles.current.image.origin = 'localBuild';
  delete input.profiles.current.image.attestationRef;
  delete input.profiles.current.image.attestationDigest;
  input.profiles.current.build = {
    dockerfile: 'Dockerfile', cargoProfile: 'release-lite', cargoChef: true, cargoIncremental: false,
    builderImage: 'cargo-chef:latest', runtimeImage: 'debian:bookworm',
  };
  const planned = compileVersionMatrix(input);
  assert.equal(planned.acceptanceReady, false);
  assert.ok(planned.unresolvedReasons.some(reason => reason.includes('recipeDigest')));
  assert.ok(planned.unresolvedReasons.some(reason => reason.includes('builderImage')));
  assert.throws(() => compileVersionMatrix(input, {acceptance: true}), /not digest-pinned|unresolved/);
});

test('matrix bounds, actor ownership, and platform declarations fail closed', () => {
  const repository = repositoryFixture();
  const tooManyActors = matrix(repository);
  tooManyActors.bounds.maxActors = 2;
  assert.throws(() => compileVersionMatrix(tooManyActors), /actors must contain/);

  const duplicateAssignment = matrix(repository);
  duplicateAssignment.phases[1].assignments.push({profile: 'current', actors: ['miner-2']});
  assert.throws(() => compileVersionMatrix(duplicateAssignment), /assigns actor miner-2 more than once/);

  const wrongPlatform = matrix(repository);
  wrongPlatform.profiles.old.image.platforms = ['linux/amd64'];
  assert.throws(() => compileVersionMatrix(wrongPlatform), /does not provide execution platform linux\/arm64/);

  const explicitEmulation = matrix(repository);
  explicitEmulation.profiles.old.image = {
    ...explicitEmulation.profiles.old.image,
    platforms: ['linux/amd64'], execution: 'emulated', executionPlatform: 'linux/amd64',
  };
  const emulated = compileVersionMatrix(explicitEmulation, {acceptance: true});
  assert.equal(emulated.profiles.old.image.execution, 'emulated');
  assert.equal(emulated.profiles.old.image.executionPlatform, 'linux/amd64');

  const unknownActor = matrix(repository);
  unknownActor.phases[1].assignments[0].actors = ['miner-99'];
  assert.throws(() => compileVersionMatrix(unknownActor), /unknown actor miner-99/);
});

test('release expectedRevision prevents a moved or mistaken ref', () => {
  const repository = repositoryFixture();
  const input = matrix(repository);
  input.profiles.old.source.expectedRevision = '0'.repeat(40);
  assert.throws(() => compileVersionMatrix(input), /does not match v4.0.2/);
});
