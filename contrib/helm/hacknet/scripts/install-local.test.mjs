import assert from 'node:assert/strict';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/helm/hacknet/scripts/install-local.sh');
const digest = `sha256:${'a'.repeat(64)}`;

function fixture(status = '') {
  const root = mkdtempSync(join(tmpdir(), 'hacknet-install-'));
  const bin = join(root, 'bin');
  const log = join(root, 'calls.log');
  mkdirSync(bin);
  writeFileSync(log, '');
  const commands = {
    docker: `#!/bin/sh\necho "docker $*" >>"${log}"\necho '${digest}'\n`,
    kubectl: `#!/bin/sh\necho "kubectl $*" >>"${log}"\n`,
    helm: `#!/bin/sh\necho "helm $*" >>"${log}"\nif [ "$1" = status ]; then ${status ? `printf '%s\\n' '{"info":{"status":"${status}"}}'` : 'exit 1'}; fi\n`,
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
    env: {...process.env, PATH: `${item.bin}:/usr/bin:/bin`, ...extra},
  });
}

test('installs CRDs before Helm and rolls Pods on exact local image IDs', () => {
  const item = fixture();
  const result = run(item);
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(item.log, 'utf8').trim().split('\n');
  const apply = calls.findIndex(line => line.startsWith('kubectl apply'));
  const wait = calls.findIndex(line => line.startsWith('kubectl wait'));
  const upgrade = calls.findIndex(line => line.startsWith('helm upgrade'));
  assert.ok(apply >= 0 && wait > apply && upgrade > wait);
  assert.match(calls[upgrade], new RegExp(`operator\\.podAnnotations\\.attacknet-build=${digest}`));
  assert.match(calls[upgrade], new RegExp(`runOperator\\.podAnnotations\\.attacknet-build=${digest}`));
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-operator:dev stacks-hacknet-operator:local-a{16}/);
  assert.match(calls.join('\n'), /docker image tag stacks-hacknet-run-operator:dev stacks-hacknet-run-operator:local-a{16}/);
  assert.match(calls[upgrade], /operator\.image\.tag=local-a{16}/);
  assert.match(calls[upgrade], /runOperator\.image\.tag=local-a{16}/);
  assert.doesNotMatch(calls[upgrade], /--force-conflicts/);
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
