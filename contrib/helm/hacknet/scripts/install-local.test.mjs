import assert from 'node:assert/strict';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/helm/hacknet/scripts/install-local.sh');
const digest = `sha256:${'a'.repeat(64)}`;

function fixture(status = '', helmVersion = 'v4.2.4') {
  const root = mkdtempSync(join(tmpdir(), 'hacknet-install-'));
  const bin = join(root, 'bin');
  const log = join(root, 'calls.log');
  mkdirSync(bin);
  writeFileSync(log, '');
  const commands = {
    docker: `#!/bin/sh\necho "docker $*" >>"${log}"\necho '${digest}'\n`,
    kubectl: `#!/bin/sh\necho "kubectl $*" >>"${log}"\n`,
    helm: `#!/bin/sh\necho "helm $*" >>"${log}"\nif [ "$1" = version ]; then printf '%s\\n' '${helmVersion}'; fi\nif [ "$1" = status ]; then ${status ? `printf '%s\\n' '{"info":{"status":"${status}"}}'` : 'exit 1'}; fi\n`,
    jq: '#!/bin/sh\nsed -n \'s/.*"status":"\\([^"]*\\)".*/\\1/p\'\n',
  };
  for (const [name, contents] of Object.entries(commands)) {
    const path = join(bin, name);
    writeFileSync(path, contents);
    chmodSync(path, 0o755);
  }
  return {bin, log};
}

function run(item, extra = {}) {
  return spawnSync('bash', [script], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${item.bin}:/usr/bin:/bin`, HACKNET_KIND_IMAGE_LOAD: 'disabled', ...extra},
  });
}

test('installs CRDs before Helm and rolls Pods on exact local image IDs', () => {
  const item = fixture();
  const result = run(item);
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(item.log, 'utf8').trim().split('\n');
  const annotate = calls.findIndex(line => line.startsWith('kubectl annotate namespace hacknet-system chaos-mesh.org/inject=enabled --overwrite'));
  const apply = calls.findIndex(line => line.startsWith('kubectl apply'));
  const wait = calls.findIndex(line => line.startsWith('kubectl wait'));
  const upgrade = calls.findIndex(line => line.startsWith('helm upgrade'));
  assert.ok(annotate >= 0 && apply > annotate && wait > apply && upgrade > wait);
  assert.match(calls[upgrade], new RegExp(`operator\\.podAnnotations\\.attacknet-build=${digest}`));
  assert.match(calls[upgrade], new RegExp(`runOperator\\.podAnnotations\\.attacknet-build=${digest}`));
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-operator:dev stacks-hacknet-operator:local-a{16}/);
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-run-operator:dev stacks-hacknet-run-operator:local-a{16}/);
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-burnchain-clock:dev stacks-hacknet-burnchain-clock:local-a{16}/);
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-io-pressure:dev stacks-hacknet-io-pressure:local-a{16}/);
  assert.match(calls[upgrade], /operator\.image\.tag=local-a{16}/);
  assert.match(calls[upgrade], /runOperator\.image\.tag=local-a{16}/);
  assert.match(calls[upgrade], /burnchainClock\.image\.tag=local-a{16}/);
  assert.match(calls[upgrade], /runOperator\.ioPressureImage\.tag=local-a{16}/);
  assert.match(calls[upgrade], /--rollback-on-failure/);
  assert.doesNotMatch(calls[upgrade], /--atomic/);
  assert.doesNotMatch(calls[upgrade], /--force-conflicts/);
});

test('uses Helm 3 atomic rollback semantics and rejects unsupported majors before mutation', () => {
  const helmThree = fixture('', 'v3.19.0');
  const installed = run(helmThree);
  assert.equal(installed.status, 0, installed.stderr);
  const upgrade = readFileSync(helmThree.log, 'utf8').split('\n')
    .find(line => line.startsWith('helm upgrade'));
  assert.match(upgrade, /--atomic/);
  assert.doesNotMatch(upgrade, /--rollback-on-failure/);

  const unsupported = fixture('', 'v5.0.0');
  const rejected = run(unsupported);
  assert.equal(rejected.status, 1);
  assert.match(rejected.stderr, /unsupported Helm major version/);
  assert.doesNotMatch(readFileSync(unsupported.log, 'utf8'), /docker |kubectl |helm upgrade/);
});

test('help is read-only and unknown arguments fail closed', () => {
  const item = fixture();
  const help = spawnSync('bash', [script, '--help'], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${item.bin}:/usr/bin:/bin`},
  });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /usage: install-local\.sh/);
  assert.equal(readFileSync(item.log, 'utf8'), '');

  const invalid = spawnSync('bash', [script, '--surprise'], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${item.bin}:/usr/bin:/bin`},
  });
  assert.equal(invalid.status, 2);
  assert.equal(readFileSync(item.log, 'utf8'), '');
});

test('failed releases and managed-field takeover require explicit recovery', () => {
  const blocked = fixture('failed');
  const denied = run(blocked);
  assert.equal(denied.status, 1);
  assert.match(denied.stderr, /RECOVER_FAILED_RELEASE/);
  assert.doesNotMatch(readFileSync(blocked.log, 'utf8'), /helm upgrade/);

  const allowed = fixture('failed');
  const recovered = run(allowed, {
    HACKNET_RECOVER_FAILED_RELEASE: '1',
    HACKNET_FORCE_CRD_CONFLICTS: '1',
    HACKNET_FORCE_CONFLICTS: '1',
  });
  assert.equal(recovered.status, 0, recovered.stderr);
  assert.match(readFileSync(allowed.log, 'utf8'), /helm upgrade .*--force-conflicts/);
  assert.match(readFileSync(allowed.log, 'utf8'), /kubectl apply .*--force-conflicts/);
  assert.match(recovered.stderr, /reclaim conflicting CRD schema fields/);
  assert.match(recovered.stderr, /reclaim conflicting managed fields/);
});

test('invalid kind image loading mode fails before CRD or Helm mutation', () => {
  const item = fixture();
  const result = run(item, {HACKNET_KIND_IMAGE_LOAD: 'sometimes'});
  assert.equal(result.status, 2);
  const calls = readFileSync(item.log, 'utf8');
  assert.doesNotMatch(calls, /kubectl |helm /);
});

test('namespace fault injection requires an explicit valid installer policy', () => {
  const disabled = fixture();
  const allowed = run(disabled, {HACKNET_CHAOS_NAMESPACE_INJECTION: 'disabled'});
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.doesNotMatch(readFileSync(disabled.log, 'utf8'), /chaos-mesh.org\/inject=enabled/);

  const invalid = fixture();
  const rejected = run(invalid, {HACKNET_CHAOS_NAMESPACE_INJECTION: 'sometimes'});
  assert.equal(rejected.status, 2);
  assert.match(rejected.stderr, /must be enabled or disabled/);
  assert.doesNotMatch(readFileSync(invalid.log, 'utf8'), /kubectl |helm upgrade/);
});
