import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync, chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const backend = resolve('contrib/attacknet/runtime-backend.sh');

test('Kubernetes pause fails closed instead of pretending SIGSTOP froze namespace init', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-backend-pause-'));
  const calls = join(root, 'kubectl.calls');
  const kubectl = join(root, 'kubectl');
  writeFileSync(kubectl, `#!/bin/sh\nprintf '%s\\n' "$*" >>${JSON.stringify(calls)}\n`);
  chmodSync(kubectl, 0o755);
  const result = spawnSync('bash', [backend, 'pause', 'follower-1'], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${root}:${process.env.PATH}`, ATTACKNET_BACKEND: 'kubernetes'},
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /controller-owned FaultCampaign/);
  assert.throws(() => readFileSync(calls), /ENOENT/);
});

test('Kubernetes resume cannot claim cleanup that belongs to a FaultCampaign', () => {
  const result = spawnSync('bash', [backend, 'resume', 'follower-1'], {
    encoding: 'utf8', env: {...process.env, ATTACKNET_BACKEND: 'kubernetes'},
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /FaultCampaign cleanup/);
});

test('Compose adapter applies every rendered file to ordinary and bounded exec calls', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-backend-compose-files-'));
  const calls = join(root, 'docker.calls');
  const docker = join(root, 'docker');
  writeFileSync(docker, `#!/bin/sh\nprintf '%s\\n' "$*" >>${JSON.stringify(calls)}\ncase "$*" in *' ps --all --format json') printf '[]\\n';; esac\n`);
  chmodSync(docker, 0o755);
  const env = {...process.env, PATH: `${root}:${process.env.PATH}`,
    ATTACKNET_BACKEND: 'compose', ATTACKNET_PROJECT: 'proof',
    ATTACKNET_COMPOSE: '/tmp/base.yaml',
    ATTACKNET_COMPOSE_EXTRA: '/tmp/metrics.yaml:/tmp/debug.yaml'};
  const describe = spawnSync('bash', [backend, 'describe'], {encoding: 'utf8', env});
  assert.equal(describe.status, 0, describe.stderr);
  const exec = spawnSync('bash', [backend, 'exec', 'follower-1', 'true'], {encoding: 'utf8', env});
  assert.equal(exec.status, 0, exec.stderr);
  const bounded = spawnSync('bash', [backend, 'prometheus-query', 'proof', 'up', 'follower-1'],
    {encoding: 'utf8', env});
  assert.equal(bounded.status, 0, bounded.stderr);
  const lines = readFileSync(calls, 'utf8').trim().split('\n');
  assert.ok(lines.length >= 3);
  for (const line of lines) {
    assert.match(line, /compose -p proof -f \/tmp\/base\.yaml -f \/tmp\/metrics\.yaml -f \/tmp\/debug\.yaml/);
  }
});

test('Compose readiness accepts both Docker JSON-array and JSON-lines output', () => {
  for (const [name, output] of [
    ['array', '[{"Service":"miner-1","State":"running","Health":"healthy"}]'],
    ['lines', '{"Service":"miner-1","State":"running","Health":"healthy"}'],
  ]) {
    const root = mkdtempSync(join(tmpdir(), `attacknet-backend-compose-${name}-`));
    const docker = join(root, 'docker');
    writeFileSync(docker, `#!/bin/sh\nprintf '%s\\n' '${output}'\n`);
    chmodSync(docker, 0o755);
    const result = spawnSync('bash', [backend, 'unready', 'miner-1'], {encoding: 'utf8',
      env: {...process.env, PATH: `${root}:${process.env.PATH}`, ATTACKNET_BACKEND: 'compose'}});
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
  }
});
