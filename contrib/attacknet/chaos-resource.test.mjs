import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = new URL('.', import.meta.url).pathname;
const script = join(root, 'chaos-resource.sh');

function run(mode) {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-chaos-clear-'));
  const resource = join(directory, 'resource.json');
  const output = join(directory, 'clearance.json');
  const kubectl = join(directory, 'kubectl');
  const state = join(directory, 'present');
  writeFileSync(state, 'yes');
  writeFileSync(resource, JSON.stringify({kind: 'PodChaos', metadata: {name: 'fault', namespace: 'hacknet'}}));
  writeFileSync(kubectl, `#!/bin/bash
set -euo pipefail
state="\${FAKE_STATE:?}"; mode="\${FAKE_MODE:?}"
args=" $* "
if [[ "\${args}" == *" get "* ]]; then [ -f "\${state}" ]; exit; fi
if [[ "\${args}" == *" wait "* ]]; then [ "\${mode}" != wait-fails ]; exit; fi
if [[ "\${args}" == *" delete "* ]]; then
  [ "\${mode}" != delete-fails ] || exit 1
  rm -f "\${state}"; exit
fi
exit 2
`);
  chmodSync(kubectl, 0o755);
  const result = spawnSync(script, [resource, output], {encoding: 'utf8', env: {
    ...process.env, ATTACKNET_KUBECTL: kubectl, FAKE_STATE: state, FAKE_MODE: mode,
  }});
  return {result, report: JSON.parse(readFileSync(output, 'utf8'))};
}

test('graceful recovery requires AllRecovered, deletion, and absence', () => {
  const {result, report} = run('success');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(report.graceful, true);
  assert.equal(report.cleared, true);
});

test('forced deletion is recorded as cleared but not graceful', () => {
  const {result, report} = run('wait-fails');
  assert.equal(result.status, 1);
  assert.equal(report.allRecoveredObserved, false);
  assert.equal(report.cleared, true);
  assert.equal(report.graceful, false);
});

test('failed deletion cannot be reported as cleared', () => {
  const {result, report} = run('delete-fails');
  assert.equal(result.status, 1);
  assert.equal(report.deleteSucceeded, false);
  assert.equal(report.resourceAbsent, false);
  assert.equal(report.cleared, false);
});
