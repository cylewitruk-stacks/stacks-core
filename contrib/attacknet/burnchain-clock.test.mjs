import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';

const script = new URL('./burnchain-clock.sh', import.meta.url).pathname;

test('abandons only deduplicated wallet sends absent from the authoritative mempool', () => {
  const directory = mkdtempSync(join(tmpdir(), 'burnchain-clock-'));
  const fake = join(directory, 'bitcoin-cli');
  const calls = join(directory, 'abandoned.txt');
  const staleA = 'a'.repeat(64);
  const staleB = 'b'.repeat(64);
  const active = 'c'.repeat(64);
  const confirmed = 'd'.repeat(64);
  const abandoned = 'e'.repeat(64);
  const incoming = 'f'.repeat(64);
  const transactions = JSON.stringify([
    {txid: staleA}, {txid: staleA}, {txid: active}, {txid: confirmed},
    {txid: abandoned}, {txid: incoming}, {txid: staleB},
  ], null, 2);
  writeFileSync(join(directory, 'transactions.json'), transactions);
  writeFileSync(fake, `#!/bin/bash
set -eu
case " $* " in
  *" listtransactions "*) cat "${directory}/transactions.json" ;;
  *" gettransaction ${staleA} "*) printf '%s\\n' '{' '  "confirmations": 0,' '  "abandoned": false,' '  "category": "send"' '}' ;;
  *" gettransaction ${staleB} "*) printf '%s\\n' '{' '  "confirmations": 0,' '  "abandoned": false,' '  "category": "send"' '}' ;;
  *" gettransaction ${active} "*) printf '%s\\n' '{' '  "confirmations": 0,' '  "abandoned": false,' '  "category": "send"' '}' ;;
  *" gettransaction ${confirmed} "*) printf '%s\\n' '{' '  "confirmations": 3,' '  "abandoned": false,' '  "category": "send"' '}' ;;
  *" gettransaction ${abandoned} "*) printf '%s\\n' '{' '  "confirmations": 0,' '  "abandoned": true,' '  "category": "send"' '}' ;;
  *" gettransaction ${incoming} "*) printf '%s\\n' '{' '  "confirmations": 0,' '  "abandoned": false,' '  "category": "receive"' '}' ;;
  *" getmempoolentry ${active} "*) exit 0 ;;
  *" getmempoolentry "*) exit 1 ;;
  *" abandontransaction "*) printf '%s\\n' "\${!#}" >>"${calls}" ;;
  *) echo "unexpected bitcoin-cli invocation: $*" >&2; exit 2 ;;
esac
`);
  chmodSync(fake, 0o755);

  const result = spawnSync('bash', ['-c', `
    export BITCOIN_CLI_BIN="$1"
    source "$2"
    miner_wallets=(attacknet-miner-1)
    reconcile_inactive_wallet_transactions
  `, '_', fake, script], {encoding: 'utf8'});

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(calls, 'utf8').trim().split('\n'), [staleA, staleB]);
  assert.match(result.stdout, new RegExp(`Abandoned inactive transaction ${staleA}`));
  assert.doesNotMatch(result.stdout, new RegExp(`transaction ${active} `));
});

test('the clock remains sourceable so wallet reconciliation is independently testable', () => {
  const result = spawnSync('bash', ['-c', 'source "$1"; declare -F reconcile_inactive_wallet_transactions', '_', script], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /reconcile_inactive_wallet_transactions/);
});

test('an exact burst target is idempotent across clock restarts', () => {
  const directory = mkdtempSync(join(tmpdir(), 'burnchain-target-'));
  const policy = join(directory, 'policy.env');
  writeFileSync(policy, [
    'GENERATION=7', 'MODE=pause', 'INTERVAL_SECONDS=2', 'JITTER_SECONDS=0',
    'BURST_BLOCKS=5', 'BURST_TARGET_HEIGHT=205', 'ADDRESS_MODE=round-robin',
    'FIXED_ADDRESS_INDEX=0', '',
  ].join('\n'));
  const result = spawnSync('bash', ['-c', `
    export BURNCHAIN_POLICY_FILE="$1"
    source "$2"
    btc_until_success() { printf '%s\\n' "$CURRENT_HEIGHT"; }
    CURRENT_HEIGHT=203
    applied_generation=''
    read_policy
    printf 'before=%s\\n' "$burst_remaining"
    CURRENT_HEIGHT=205
    applied_generation=''
    read_policy
    printf 'after=%s\\n' "$burst_remaining"
  `, '_', policy, script], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^before=2$/m);
  assert.match(result.stdout, /^after=0$/m);
});

test('the health server consumes requests before a clean HTTP close', async () => {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  reservation.close();
  await once(reservation, 'close');

  const child = spawn('bash', ['-c', `
    source "$1"
    export BURNCHAIN_HEALTH_PORT="$2"
    trap 'kill "$health_pid" 2>/dev/null || true; exit 0' TERM INT EXIT
    ensure_health_server
    printf 'READY\\n'
    wait "$health_pid"
  `, '_', script, String(port)], {detached: true, stdio: ['ignore', 'pipe', 'pipe']});

  try {
    let ready = '';
    for await (const chunk of child.stdout) {
      ready += chunk;
      if (ready.includes('READY\n')) break;
    }
    assert.match(ready, /READY/);
    let firstResponse;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        firstResponse = await fetch(`http://127.0.0.1:${port}/`, {signal: AbortSignal.timeout(1000)});
        break;
      } catch (error) {
        if (attempt === 49) throw error;
        await delay(10);
      }
    }
    assert.equal(firstResponse.status, 200);
    assert.equal(await firstResponse.text(), 'ok\n');
    for (let index = 0; index < 50; index += 1) {
      const response = await fetch(`http://127.0.0.1:${port}/`, {signal: AbortSignal.timeout(1000)});
      assert.equal(response.status, 200);
      assert.equal(await response.text(), 'ok\n');
    }
  } finally {
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    await once(child, 'exit').catch(() => {});
  }
});
