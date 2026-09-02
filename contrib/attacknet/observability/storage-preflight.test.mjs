import assert from 'node:assert/strict';
import {chmodSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const root = new URL('.', import.meta.url).pathname;

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'attacknet-storage-preflight-'));
  const kubectl = join(directory, 'kubectl.mjs');
  writeFileSync(kubectl, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'get' && args[1] === 'nodes') {
  process.stdout.write('worker-1\\nworker-2\\n');
} else if (args[0] === 'get' && args[1] === '--raw') {
  const node = args[2].split('/')[4];
  const available = node === process.env.FAKE_LOW_NODE ? 0 : 4096;
  process.stdout.write(JSON.stringify({node:{nodeName:node,fs:{availableBytes:available,capacityBytes:8192},runtime:{imageFs:{availableBytes:available,capacityBytes:8192}}}}));
} else {
  process.stderr.write('unexpected invocation: ' + JSON.stringify(args));
  process.exitCode = 3;
}
`);
  chmodSync(kubectl, 0o755);
  return {directory, kubectl};
}

test('storage preflight records per-node kubelet filesystem evidence', () => {
  const {directory, kubectl} = fixture();
  const output = join(directory, 'report.json');
  const result = spawnSync(join(root, 'storage-preflight.sh'), [output], {
    encoding: 'utf8',
    env: {...process.env, ATTACKNET_KUBECTL: kubectl, ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES: '1024'},
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(report.ok, true);
  assert.equal(report.source, 'kubelet-stats-summary');
  assert.deepEqual(report.nodes.map(node => node.name), ['worker-1', 'worker-2']);
  assert.ok(report.nodes.every(node => node.rootFilesystem.availableBytes === 4096));
});

test('storage preflight fails truthfully when Node DiskPressure could miss zero free bytes', () => {
  const {directory, kubectl} = fixture();
  const output = join(directory, 'report.json');
  const result = spawnSync(join(root, 'storage-preflight.sh'), [output], {
    encoding: 'utf8',
    env: {
      ...process.env,
      ATTACKNET_KUBECTL: kubectl,
      ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES: '1024',
      FAKE_LOW_NODE: 'worker-2',
    },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /less than 1024 free bytes/);
  const report = JSON.parse(readFileSync(output, 'utf8'));
  assert.equal(report.ok, false);
  assert.equal(report.nodes.find(node => node.name === 'worker-2').rootFilesystem.availableBytes, 0);
});

test('storage preflight handles help and rejects option-shaped output paths before kubectl', () => {
  const help = spawnSync(join(root, 'storage-preflight.sh'), ['--help'], {encoding: 'utf8'});
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stderr, /usage:/);

  const invalid = spawnSync(join(root, 'storage-preflight.sh'), ['--not-an-output'], {encoding: 'utf8'});
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /unknown option/);
  assert.doesNotMatch(invalid.stderr, /mkdir:|dirname:/);
});
