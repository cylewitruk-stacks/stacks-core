import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = new URL('.', import.meta.url).pathname;
const lock = join(root, 'environment-lock.sh');

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'attacknet-lock-'));
  const fake = join(dir, 'kubectl');
  writeFileSync(fake, `#!/bin/bash
set -euo pipefail
state="\${LOCK_STATE:?}"
while [ "\${1:-}" = -n ]; do shift 2; done
case "\${1:-}" in
  get)
    name="\${3}"; [ -d "\${state}/\${name}" ] || exit 1
    key="\${5##*.}"; key="\${key%?}"
    [ -f "\${state}/\${name}/\${key}" ] && cat "\${state}/\${name}/\${key}"
    ;;
  create)
    name="\${3}"; mkdir "\${state}/\${name}" 2>/dev/null || exit 1; shift 3
    for arg in "$@"; do case "$arg" in --from-literal=*) pair="\${arg#--from-literal=}"; key="\${pair%%=*}"; value="\${pair#*=}"; printf %s "\${value}" >"\${state}/\${name}/\${key}";; esac; done
    ;;
  delete) rm -rf "\${state}/\${3}" ;;
  *) exit 2 ;;
esac
`);
  chmodSync(fake, 0o755);
  return {dir, fake};
}

function run(f, args, extra = {}) {
  return spawnSync(lock, args, {
    encoding: 'utf8',
    env: {...process.env, ATTACKNET_KUBECTL: f.fake, LOCK_STATE: f.dir,
      ATTACKNET_LOCK_WAIT_SECONDS: '0', ...extra},
  });
}

test('one persistent environment excludes a second network', () => {
  const f = fixture();
  assert.equal(run(f, ['claim', 'net-a', 'agent-a', 'baseline']).status, 0);
  const blocked = run(f, ['claim', 'net-b', 'agent-b', 'smoke']);
  assert.equal(blocked.status, 1);
  assert.match(blocked.stderr, /Refusing a second active attacknet/);
  assert.equal(run(f, ['claim', 'net-a', 'agent-c', 'read-only']).status, 0);
  assert.equal(run(f, ['environment-assert', 'net-a']).status, 0);
  assert.equal(run(f, ['environment-assert', 'net-b']).status, 1);
});

test('mutation owner tokens serialize writers and protect release', () => {
  const f = fixture();
  assert.equal(run(f, ['claim', 'net-a']).status, 0);
  const first = run(f, ['mutation-acquire', 'net-a', 'agent-a', 'rollout']);
  assert.equal(first.status, 0);
  const token = first.stdout.trim();
  assert.ok(token);
  assert.equal(run(f, ['mutation-acquire', 'net-a', 'agent-b', 'fault']).status, 1);
  assert.equal(run(f, ['mutation-release', 'net-a', 'wrong-token']).status, 1);
  assert.equal(run(f, ['mutation-release', 'net-a', token]).status, 0);
  assert.equal(run(f, ['mutation-acquire', 'net-a', 'agent-b', 'fault']).status, 0);
});

test('run exports a verified token only for the bounded command', () => {
  const f = fixture();
  assert.equal(run(f, ['claim', 'net-a']).status, 0);
  const result = run(f, ['run', 'net-a', 'agent-a', 'test', '--', 'bash', '-c',
    'test -n "$ATTACKNET_MUTATION_TOKEN" && printf held']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'held');
  const second = run(f, ['mutation-acquire', 'net-a']);
  assert.equal(second.status, 0, second.stderr);
});
