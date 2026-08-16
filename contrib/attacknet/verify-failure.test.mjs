import assert from 'node:assert/strict';
import {chmodSync, copyFileSync, mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

function executable(path, body) {
  writeFileSync(path, body);
  chmodSync(path, 0o755);
}

test('verifier attributes a bounded actor endpoint failure instead of exiting silently', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-verify-failure-'));
  const verify = join(root, 'verify.sh');
  copyFileSync(resolve('contrib/attacknet/verify.sh'), verify);
  chmodSync(verify, 0o755);
  executable(join(root, 'runtime-backend.sh'), `#!/bin/bash
backend_require() { :; }
backend_unready_actors() { :; }
backend_exec_timeout() { return 1; }
`);
  writeFileSync(join(root, 'manifest-inventory.mjs'), "process.stdout.write('node-1\\n');\n");
  writeFileSync(join(root, 'progress-window.mjs'), "process.stdout.write('1\\n');\n");
  writeFileSync(join(root, 'invariants.mjs'), 'process.exit(99);\n');
  const manifest = join(root, 'manifest.json');
  writeFileSync(manifest, '{}\n');

  const result = spawnSync(verify, [manifest, 'snapshot'], {
    cwd: root,
    encoding: 'utf8',
    env: {...process.env, ATTACKNET_PROBE_TIMEOUT_SECONDS: '7'},
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /node-1 \/v2\/info probe failed within 7s/);
  assert.equal(result.stdout, '');
});
