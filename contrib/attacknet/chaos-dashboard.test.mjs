import assert from 'node:assert/strict';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/attacknet/chaos-dashboard.sh');
const source = readFileSync(script, 'utf8');

function run({serviceAvailable = true, address = '127.0.0.1'} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-chaos-dashboard-'));
  const bin = join(root, 'bin');
  const log = join(root, 'calls');
  mkdirSync(bin);
  writeFileSync(log, '');
  const kubectl = join(bin, 'kubectl');
  writeFileSync(kubectl, `#!/bin/sh\necho "$*" >>"${log}"\ncase " $* " in\n  *" get service/chaos-dashboard "*) exit ${serviceAvailable ? 0 : 1} ;;\n  *" port-forward "*) exit 0 ;;\nesac\n`);
  chmodSync(kubectl, 0o755);
  const result = spawnSync('bash', [script, 'run'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:/usr/bin:/bin`,
      CHAOS_DASHBOARD_ADDRESS: address,
      ATTACKNET_CHAOS_DASHBOARD_ACCESS_ONCE: '1',
      ATTACKNET_CHAOS_DASHBOARD_STATE_DIR: join(root, 'state'),
    },
  });
  return {result, calls: readFileSync(log, 'utf8')};
}

test('forwards the installed Chaos Dashboard Service on loopback', () => {
  const {result, calls} = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(calls, /get service\/chaos-dashboard/);
  assert.match(calls, /port-forward service\/chaos-dashboard 2333:2333 --address=127\.0\.0\.1/);
});

test('reports a missing Dashboard Service without attempting a forward', () => {
  const {result, calls} = run({serviceAvailable: false});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unavailable/);
  assert.doesNotMatch(calls, /port-forward/);
});

test('refuses a non-loopback bind', () => {
  const {result, calls} = run({address: '0.0.0.0'});
  assert.equal(result.status, 2);
  assert.match(result.stderr, /loopback-only/);
  assert.equal(calls, '');
});

test('termination exits the supervisor and tears down its owned forward', () => {
  assert.match(source, /trap 'exit 143' TERM/);
  assert.match(source, /kill "\$\{forward_pid\}"/);
  assert.match(source, /wait "\$\{forward_pid\}"/);
});
