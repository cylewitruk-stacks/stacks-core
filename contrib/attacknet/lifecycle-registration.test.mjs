import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import test from 'node:test';

const lifecycle = resolve('contrib/attacknet/lifecycle.sh');

function exercise({submissionHeight, lockHeight}) {
  const shell = `
    source "$LIFECYCLE"
    fake_height=202
    calls=""
    burst_to_height() { fake_height="$1"; calls="\${calls} $1"; }
    wait_nodes_at_burn_height() { :; }
    clock_status_value() { printf '%s\\n' "$fake_height"; }
    ledger_assertion() { :; }
    wait_stacker_submission_window() {
      [ "$fake_height" -ge "$SUBMISSION_HEIGHT" ]
    }
    signer_accounts_locked() {
      [ "$fake_height" -ge "$LOCK_HEIGHT" ]
    }
    result=0
    establish_signer_set ignored.json 208 215 || result=$?
    printf 'result=%s height=%s calls=%s\\n' "$result" "$fake_height" "$calls"
  `;
  return spawnSync('bash', ['-c', shell], {
    encoding: 'utf8',
    env: {
      ...process.env,
      LIFECYCLE: lifecycle,
      SUBMISSION_HEIGHT: String(submissionHeight),
      LOCK_HEIGHT: String(lockHeight),
    },
  });
}

test('signer enrollment pauses for submission and confirms before the cutoff', () => {
  const result = exercise({submissionHeight: 208, lockHeight: 209});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /result=0 height=209 calls= 208 209/);
});

test('signer enrollment never crosses the reward-set cutoff', () => {
  const result = exercise({submissionHeight: 214, lockHeight: 999});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /result=1 height=214 calls= 208 209 210 211 212 213 214/);
  assert.doesNotMatch(result.stdout, /calls=.* 215/);
});

test('bounded stacker wait is safe under set -u and accepts a pre-cutoff submission', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-stacker-wait-'));
  const backend = join(root, 'runtime-backend.sh');
  writeFileSync(backend, '#!/bin/sh\nprintf \'%s\\n\' \'{"phase":"pox4-submitted","burnHeight":208}\'\n');
  chmodSync(backend, 0o755);
  const result = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    ATTACKNET_DIR="$FAKE_ATTACKNET_DIR"
    wait_stacker_submission_window 1 215
  `], {
    encoding: 'utf8',
    env: {...process.env, LIFECYCLE: lifecycle, FAKE_ATTACKNET_DIR: root},
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /pox4-submitted at burn height 208/);
});

test('burnchain policy initialization never rewinds an admitted generation', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-policy-init-'));
  const calls = join(root, 'calls');
  const policy = join(root, 'policy.json');
  writeFileSync(policy, '{}\n');
  const shell = `
    source "$LIFECYCLE"
    NAMESPACE=hacknet-system
    NETWORK=network-a
    kubectl() {
      printf '%s\\n' "$*" >>"$CALLS"
      if [ "$1 $2 $3 $4" = '-n hacknet-system get configmap' ]; then
        [ "$POLICY_EXISTS" = 1 ]
      fi
    }
    ensure_burnchain_policy "$POLICY"
  `;
  const existing = spawnSync('bash', ['-c', shell], {
    encoding: 'utf8',
    env: {...process.env, LIFECYCLE: lifecycle, CALLS: calls, POLICY: policy, POLICY_EXISTS: '1'},
  });
  assert.equal(existing.status, 0, existing.stderr);
  assert.doesNotMatch(readFileSync(calls, 'utf8'), / apply /);

  writeFileSync(calls, '');
  const missing = spawnSync('bash', ['-c', shell], {
    encoding: 'utf8',
    env: {...process.env, LIFECYCLE: lifecycle, CALLS: calls, POLICY: policy, POLICY_EXISTS: '0'},
  });
  assert.equal(missing.status, 0, missing.stderr);
  assert.match(readFileSync(calls, 'utf8'), /apply -f/);
});

test('bootstrap readiness counts admitted nonzero replicas, not suspended actors as Pods', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-bootstrap-ready-'));
  const backend = join(root, 'runtime-backend.sh');
  writeFileSync(backend, '#!/bin/sh\nexit 0\n');
  chmodSync(backend, 0o755);
  const manifest = join(root, 'manifest.json');
  writeFileSync(manifest, `${JSON.stringify({workloads: Array.from({length: 7}, (_, index) => ({service: `actor-${index}`}))})}\n`);
  const statefulsets = JSON.stringify({
    items: Array.from({length: 7}, (_, index) => ({spec: {replicas: index === 5 ? 0 : 1}})),
  });
  const result = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    ATTACKNET_DIR="$FAKE_ATTACKNET_DIR"
    NAMESPACE=hacknet-system
    NETWORK=network-a
    TIMEOUT=2
    node() {
      if [[ "$1" == *manifest-inventory.mjs ]]; then
        printf '%s\\n' 'actor-0 actor-1 actor-2 actor-3 actor-4 actor-6'
      else
        command node "$@"
      fi
    }
    kubectl() {
      if [[ "$*" == *'get pods'* ]]; then
        printf '%s\\n' 'pod-0 pod-1 pod-2 pod-3 pod-4 pod-6'
      elif [[ "$*" == *'get statefulsets'* ]]; then
        if [[ "$*" == *'testing.stacks.org/actor'* ]]; then
          printf '%s\\n' "$STATEFULSETS"
        else
          printf '%s\\n' "$STATEFULSETS_WITH_OBSERVABILITY"
        fi
      elif [[ "$*" == *'get stacksnetwork'* ]]; then
        printf '%s\\n' '2 2'
      fi
    }
    wait_bootstrap_foundation_ready "$MANIFEST"
  `], {
    encoding: 'utf8',
    env: {
      ...process.env,
      LIFECYCLE: lifecycle,
      FAKE_ATTACKNET_DIR: root,
      MANIFEST: manifest,
      STATEFULSETS: statefulsets,
      STATEFULSETS_WITH_OBSERVABILITY: JSON.stringify({items: [
        ...JSON.parse(statefulsets).items,
        {metadata: {name: 'loki'}, spec: {replicas: 1}},
      ]}),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /6\/6 active Pods, 7\/7 StatefulSets admitted/);
});

test('two-phase bootstrap never receives a second generic clock-start command', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-clock-path-'));
  const bootstrap = join(root, 'stacksnetwork.bootstrap.json');
  writeFileSync(bootstrap, '{}\n');
  const result = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    AUTO_START_BURNCHAIN=1
    if needs_post_ready_clock_start '' "$BOOTSTRAP"; then exit 10; fi
    if ! needs_post_ready_clock_start '' "$MISSING"; then exit 11; fi
    if needs_post_ready_clock_start 'miner-2' "$MISSING"; then exit 12; fi
  `], {
    encoding: 'utf8',
    env: {
      ...process.env,
      LIFECYCLE: lifecycle,
      BOOTSTRAP: bootstrap,
      MISSING: join(root, 'missing.json'),
    },
  });
  assert.equal(result.status, 0, result.stderr);
});
