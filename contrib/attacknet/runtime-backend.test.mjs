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
