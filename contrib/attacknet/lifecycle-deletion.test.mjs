import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

test('teardown waits for managed network children but not retained run artifacts', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-lifecycle-delete-'));
  const log = join(root, 'kubectl.log');
  const kubectl = join(root, 'kubectl');
  writeFileSync(kubectl, '#!/bin/sh\nprintf "%s\\n" "$*" >>"$FAKE_KUBECTL_LOG"\n');
  chmodSync(kubectl, 0o755);
  const lifecycle = new URL('./lifecycle.sh', import.meta.url).pathname;
  const child = spawnSync('bash', ['-c',
    'source "$1"; NAMESPACE=hacknet-system; NETWORK=attacknet; TIMEOUT=1; wait_deleted',
    '_', lifecycle], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${root}:${process.env.PATH}`, FAKE_KUBECTL_LOG: log},
  });
  assert.equal(child.status, 0, child.stderr);
  const invocation = readFileSync(log, 'utf8');
  assert.match(invocation, /testing\.stacks\.org\/network=attacknet,!testing\.stacks\.org\/artifact/);
  assert.match(invocation, /pods,pvc,deployments,statefulsets,daemonsets,services,configmaps/);
});
