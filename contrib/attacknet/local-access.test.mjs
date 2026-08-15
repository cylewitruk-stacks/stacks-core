import assert from 'node:assert/strict';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/attacknet/local-access.sh');

function run(services) {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-access-'));
  const bin = join(root, 'bin');
  const log = join(root, 'calls');
  mkdirSync(bin);
  const kubectl = join(bin, 'kubectl');
  writeFileSync(kubectl, `#!/bin/sh\necho "$*" >>"${log}"\ncase " $* " in *" get service "*) printf '%s\\n' '${services.join('\n')}' ;; esac\n`);
  chmodSync(kubectl, 0o755);
  const result = spawnSync('bash', [script, 'run'], {
    encoding: 'utf8',
    env: {...process.env, PATH: `${bin}:/usr/bin:/bin`, ATTACKNET_LOCAL_ACCESS_ONCE: '1',
      ATTACKNET_LOCAL_ACCESS_STATE_DIR: join(root, 'state')},
  });
  return {result, calls: readFileSync(log, 'utf8')};
}

test('forwards the single enrolled Grafana Service on loopback', () => {
  const {result, calls} = run(['network-a-attacknet-grafana']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(calls, /get service -l app\.kubernetes\.io\/name=attacknet-grafana/);
  assert.match(calls, /port-forward service\/network-a-attacknet-grafana 3000:3000 --address=127\.0\.0\.1/);
});

test('refuses to choose between two active Grafana Services', () => {
  const {result, calls} = run(['one-grafana', 'two-grafana']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /ambiguous/);
  assert.doesNotMatch(calls, /port-forward/);
});

