import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const lifecycle = new URL('./lifecycle.sh', import.meta.url).pathname;
const campaignRunner = readFileSync(new URL('./campaign-runner.sh', import.meta.url), 'utf8');

test('Attacknet namespaces are explicitly enabled for filtered Chaos Mesh injection', () => {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-namespace-policy-'));
  const calls = join(directory, 'kubectl.calls');
  const kubectl = join(directory, 'kubectl');
  writeFileSync(kubectl, `#!/bin/sh
printf '%s\\n' "$*" >>"${calls}"
case "$*" in
  "get namespace custom-attacknet -o jsonpath={.metadata.annotations.chaos-mesh\\.org/inject}")
    printf enabled
    ;;
esac
`);
  const chmod = spawnSync('chmod', ['+x', kubectl]);
  assert.equal(chmod.status, 0, chmod.stderr?.toString());
  const result = spawnSync('bash', ['-c', `
    source "$1"
    NAMESPACE=custom-attacknet
    ensure_chaos_injection_namespace
  `, 'namespace-policy-test', lifecycle], {
    env: {...process.env, PATH: `${directory}:${process.env.PATH}`},
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(calls, 'utf8').trim().split('\n'), [
    'annotate namespace custom-attacknet chaos-mesh.org/inject=enabled --overwrite',
    'get namespace custom-attacknet -o jsonpath={.metadata.annotations.chaos-mesh\\.org/inject}',
  ]);
});

test('direct campaign recursion exports its compiled namespace and network', () => {
  const exportOffset = campaignRunner.indexOf('export KUBE_NAMESPACE="${namespace}" KUBE_NETWORK="${network}"');
  const lockOffset = campaignRunner.indexOf('exec "${lock_script}" run');
  assert.ok(exportOffset >= 0, 'compiled campaign identity must be exported');
  assert.ok(lockOffset > exportOffset, 'identity must be exported before lock recursion');
});
