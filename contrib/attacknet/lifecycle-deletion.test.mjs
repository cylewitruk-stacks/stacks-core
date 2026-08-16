import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

test('teardown waits for managed network children but not retained run artifacts', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-lifecycle-delete-'));
  const log = join(root, 'kubectl.log');
  const ownerPolls = join(root, 'owner-polls');
  const kubectl = join(root, 'kubectl');
  writeFileSync(kubectl, `#!/bin/sh
printf '%s\\n' "$*" >>"$FAKE_KUBECTL_LOG"
case "$*" in
  *'get stacksnetwork attacknet -o name'*)
    polls=0
    [ ! -r "$FAKE_OWNER_POLLS" ] || polls="$(cat "$FAKE_OWNER_POLLS")"
    polls=$((polls + 1))
    printf '%s\\n' "$polls" >"$FAKE_OWNER_POLLS"
    [ "$polls" -gt 1 ] || printf '%s\\n' 'stacksnetwork.testing.stacks.org/attacknet'
    ;;
esac
`);
  chmodSync(kubectl, 0o755);
  const lifecycle = new URL('./lifecycle.sh', import.meta.url).pathname;
  const child = spawnSync('bash', ['-c',
    // The fake owner deliberately survives one two-second poll. Leave enough
    // wall-clock margin for this process-heavy suite to schedule the second
    // poll; the assertion below, not an artificially tight timeout, proves
    // the retained-artifact selector and deletion state machine.
    'source "$1"; NAMESPACE=hacknet-system; NETWORK=attacknet; TIMEOUT=10; wait_deleted',
    '_', lifecycle], {
    encoding: 'utf8',
    env: {
      ...process.env, PATH: `${root}:${process.env.PATH}`,
      FAKE_KUBECTL_LOG: log, FAKE_OWNER_POLLS: ownerPolls,
    },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(Number(readFileSync(ownerPolls, 'utf8')), 2);
  const invocation = readFileSync(log, 'utf8');
  assert.match(invocation, /get stacksnetwork attacknet -o name/);
  assert.match(invocation, /testing\.stacks\.org\/network=attacknet,!testing\.stacks\.org\/artifact/);
  assert.match(invocation, /pods,pvc,deployments,statefulsets,daemonsets,services,configmaps/);
});

test('teardown exports centralized logs before issuing destructive Kubernetes calls', () => {
  const lifecycle = readFileSync(new URL('./lifecycle.sh', import.meta.url), 'utf8');
  const body = lifecycle.slice(lifecycle.indexOf('delete_network() {'), lifecycle.indexOf('\ncapture() {'));
  const exportAt = body.indexOf('export_loki_evidence "${bundle}/loki"');
  const ownerDeleteAt = body.indexOf('delete stacksnetwork "${NETWORK}"');
  const observabilityDeleteAt = body.indexOf('delete deployments,statefulsets,daemonsets');
  assert.ok(exportAt >= 0, 'teardown must export Loki');
  assert.ok(ownerDeleteAt > exportAt, 'owner deletion must follow Loki export');
  assert.ok(observabilityDeleteAt > exportAt, 'observability deletion must follow Loki export');
  assert.doesNotMatch(body.slice(exportAt, ownerDeleteAt), /\|\|\s*true/);
});
