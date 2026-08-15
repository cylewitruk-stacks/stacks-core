import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
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

test('startup gates require live conversations and canonical global-state support', () => {
  // macOS exposes TMPDIR through /var while import.meta resolves /private/var.
  // Use one canonical path so CLI-entrypoint identity remains true.
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'attacknet-protocol-gates-')));
  // Copy executable modules instead of symlinking them. Node resolves
  // import.meta.url to the real path while process.argv[1] retains a symlink
  // path, which suppresses these modules' CLI entry points and can turn an
  // empty helper result into a false-positive lifecycle test.
  writeFileSync(join(root, 'manifest-inventory.mjs'),
    readFileSync(resolve('contrib/attacknet/manifest-inventory.mjs'), 'utf8'));
  writeFileSync(join(root, 'invariants.mjs'),
    readFileSync(resolve('contrib/attacknet/invariants.mjs'), 'utf8'));
  const backend = join(root, 'runtime-backend.sh');
  writeFileSync(backend, `#!/bin/sh
case "$*" in
  *'/v2/neighbors'*)
    printf '%s\n' '{"bootstrap":[],"sample":[],"inbound":[{"authenticated":true}],"outbound":[]}'
    ;;
  *'31000/metrics'*)
    printf '%s\n' 'stacks_signer_global_state_available 1'
    printf '%s\n' 'stacks_signer_global_state_known_weight 19'
    printf '%s\n' 'stacks_signer_global_state_maximum_view_weight 19'
    printf '%s\n' 'stacks_signer_global_state_canonical_threshold_weight 14'
    ;;
  *) exit 2 ;;
esac
`);
  chmodSync(backend, 0o755);
  const manifest = join(root, 'manifest.json');
  writeFileSync(manifest, `${JSON.stringify({actors: [
    {service: 'miner-1', type: 'node', role: 'miner'},
    {service: 'signer-node-1', type: 'node', role: 'companion'},
    {service: 'signer-1', type: 'signer', role: 'signer'},
    {service: 'signer-2', type: 'signer', role: 'signer'},
  ]})}\n`);
  const result = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    ATTACKNET_DIR="$FAKE_ATTACKNET_DIR"
    NAMESPACE=hacknet-system
    NETWORK=network-a
    # This test deliberately forces one failed peer sample. Leave enough
    # wall-clock budget for the structured diagnostic and succeeding sample.
    TIMEOUT=5
    sleep() { :; }
    node() {
      if [[ "$1" == *invariants.mjs ]] && [ "$2" = peers ] && [ ! -e "$FIRST_SAMPLE" ]; then
        : >"$FIRST_SAMPLE"
        return 1
      fi
      command node "$@"
    }
    apply_error() { : >"$FALSE_FAILURE"; }
    trap 'apply_error $? \${LINENO}' ERR
    wait_live_peer_connectivity "$MANIFEST" nodes
    wait_signer_global_state "$MANIFEST"
  `], {
    encoding: 'utf8',
    env: {
      ...process.env,
      LIFECYCLE: lifecycle,
      FAKE_ATTACKNET_DIR: root,
      MANIFEST: manifest,
      FIRST_SAMPLE: join(root, 'first-sample'),
      FALSE_FAILURE: join(root, 'false-lifecycle-failure'),
    },
  });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  assert.equal(existsSync(join(root, 'first-sample')), true);
  assert.equal(existsSync(join(root, 'false-lifecycle-failure')), false);
  assert.match(result.stdout, /live authenticated P2P connectivity proven/);
  assert.match(result.stdout, /canonical-threshold global state for three samples/);
});

test('startup proves declared signer identities and weights against the live reward set', () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-signer-parity-'));
  writeFileSync(join(root, 'signer-set-parity.mjs'),
    readFileSync(resolve('contrib/attacknet/signer-set-parity.mjs'), 'utf8'));
  const signerKey = `02${'01'.padStart(64, '0')}`;
  const backend = join(root, 'runtime-backend.sh');
  writeFileSync(backend, `#!/bin/sh
case "$*" in
  *'/v2/pox'*) printf '%s\n' '{"current_cycle":{"id":11}}' ;;
  *'/v3/stacker_set/11'*) printf '%s\n' '{"stacker_set":{"signers":[{"signing_key":"${signerKey}","weight":3}]}}' ;;
  *) exit 2 ;;
esac
`);
  chmodSync(backend, 0o755);
  const manifest = join(root, 'manifest.json');
  const actor = {
    service: 'signer-1', type: 'signer', role: 'signer', signerIndex: 1,
    signerPublicKey: signerKey, signerWeight: 3,
  };
  writeFileSync(manifest, `${JSON.stringify({actors: [actor]})}\n`);
  const result = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    ATTACKNET_DIR="$FAKE_ATTACKNET_DIR"
    NAMESPACE=hacknet-system
    NETWORK=network-a
    TIMEOUT=2
    wait_signer_set_parity "$MANIFEST"
  `], {encoding: 'utf8', env: {
    ...process.env, LIFECYCLE: lifecycle, FAKE_ATTACKNET_DIR: root, MANIFEST: manifest,
  }});
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.rewardCycle, 11);
  assert.equal(report.declaredTotalWeight, 3);
  assert.equal(report.observedTotalWeight, 3);

  writeFileSync(manifest, `${JSON.stringify({actors: [{...actor, signerWeight: 2}]})}\n`);
  const mismatch = spawnSync('bash', ['-c', `
    source "$LIFECYCLE"
    ATTACKNET_DIR="$FAKE_ATTACKNET_DIR"
    NAMESPACE=hacknet-system
    NETWORK=network-a
    TIMEOUT=2
    wait_signer_set_parity "$MANIFEST"
  `], {encoding: 'utf8', env: {
    ...process.env, LIFECYCLE: lifecycle, FAKE_ATTACKNET_DIR: root, MANIFEST: manifest,
  }});
  assert.equal(mismatch.status, 1);
  assert.match(mismatch.stderr, /unsafe for fault admission/);
  assert.match(mismatch.stderr, /"declared": 2/);
  assert.match(mismatch.stderr, /"observed": 3/);
});
