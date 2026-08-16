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

test('telemetry assertion reports a down actor even when Kubernetes readiness also failed', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-verify-telemetry-'));
  const verify = join(root, 'verify.sh');
  copyFileSync(resolve('contrib/attacknet/verify.sh'), verify);
  writeFileSync(join(root, 'invariants.mjs'), `
process.stdout.write(JSON.stringify({ok:false,rows:[{actor:'follower-1',reasons:['scrape-down']}]}) + '\\n');
process.exitCode = 1;
`);
  chmodSync(verify, 0o755);
  executable(join(root, 'runtime-backend.sh'), `#!/bin/bash
backend_require() { :; }
backend_unready_actors() { echo 'follower-1'; return 99; }
backend_prometheus_query() {
  printf '%s\\n' '{"status":"success","data":{"resultType":"vector","result":[{"metric":{"attacknet_actor":"follower-1","attacknet_role":"follower"},"value":[100,"0"]}]}}'
}
`);
  writeFileSync(join(root, 'manifest-inventory.mjs'), `
const command = process.argv[3];
process.stdout.write(command === 'nodes' ? 'follower-1\\n' : 'follower-1\\n');
`);
  writeFileSync(join(root, 'progress-window.mjs'), "process.stdout.write('1\\n');\n");
  const manifest = join(root, 'manifest.json');
  writeFileSync(manifest, JSON.stringify({
    network: 'testnet', actors: [{service: 'follower-1', role: 'follower'}],
  }));

  const result = spawnSync(verify, [manifest, 'telemetry'], {
    cwd: root,
    encoding: 'utf8',
    env: {...process.env, ATTACKNET_TELEMETRY_MAXIMUM_AGE_SECONDS: '9999999999'},
  });
  assert.equal(result.status, 1, `${result.stdout}\n${result.stderr}`);
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.deepEqual(output.rows[0].reasons, ['scrape-down']);
  assert.doesNotMatch(result.stderr, /Unready actors/);
});
