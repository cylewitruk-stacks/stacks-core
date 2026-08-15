import assert from 'node:assert/strict';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/helm/hacknet/scripts/load-kind-images.sh');
const imageId = `sha256:${'a'.repeat(64)}`;

function fixture({kind = true} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'hacknet-kind-load-'));
  const bin = join(root, 'bin');
  const log = join(root, 'calls.log');
  const output = join(root, 'receipt.json');
  mkdirSync(bin);
  writeFileSync(log, '');
  const nodes = ['worker-1', 'worker-2'];
  const provider = name => kind ? `kind://docker/demo/${name}` : `aws:///zone/${name}`;
  const kubectl = `#!/bin/sh
echo "kubectl $*" >>"${log}"
cat <<'JSON'
${JSON.stringify({items: nodes.map(name => ({metadata: {name}, spec: {providerID: provider(name)}}))})}
JSON
`;
  const docker = `#!/bin/sh
echo "docker $*" >>"${log}"
if [ "$1 $2" = "image inspect" ]; then echo '${imageId}'; exit 0; fi
if [ "$1" = save ]; then
  while [ "$1" != "--output" ]; do shift; done; shift; : >"$1"; exit 0
fi
if [ "$1 $2" = "container inspect" ]; then exit 0; fi
if [ "$1" = exec ] && echo "$*" | grep -q 'images ls -q'; then
  echo 'docker.io/library/operator:exact'
  echo 'docker.io/library/runner:exact'
  exit 0
fi
if [ "$1" = exec ]; then cat >/dev/null; exit 0; fi
exit 1
`;
  for (const [name, contents] of Object.entries({kubectl, docker})) {
    const path = join(bin, name);
    writeFileSync(path, contents);
    chmodSync(path, 0o755);
  }
  return {root, bin, log, output};
}

function run(item, ...args) {
  return spawnSync('bash', [script, `--output=${item.output}`, ...args], {
    encoding: 'utf8', env: {
      ...process.env, PATH: `${item.bin}:${process.env.PATH}`,
      ATTACKNET_KUBECTL: 'kubectl', ATTACKNET_DOCKER: 'docker',
    },
  });
}

test('loads and verifies every exact image on every kind-on-Docker node', () => {
  const item = fixture();
  const result = run(item, '--mode=require', 'operator:exact', 'runner:exact');
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(readFileSync(item.output, 'utf8'));
  assert.equal(receipt.outcome, 'Loaded');
  assert.equal(receipt.nodes.length, 2);
  assert.equal(receipt.images.length, 4);
  assert.ok(receipt.images.every(row => row.verified && row.hostImageID === imageId));
  const calls = readFileSync(item.log, 'utf8');
  assert.match(calls, /docker exec -i worker-1 ctr -n k8s.io images import --all-platforms -/);
  assert.match(calls, /docker exec -i worker-2 ctr -n k8s.io images import --all-platforms -/);
});

test('auto mode skips a non-kind cluster while require mode fails closed', () => {
  const automatic = fixture({kind: false});
  const skipped = run(automatic, '--mode=auto', 'operator:exact');
  assert.equal(skipped.status, 0, skipped.stderr);
  assert.equal(JSON.parse(readFileSync(automatic.output, 'utf8')).outcome, 'Skipped');
  assert.doesNotMatch(readFileSync(automatic.log, 'utf8'), /docker /);

  const required = fixture({kind: false});
  const denied = run(required, '--mode=require', 'operator:exact');
  assert.equal(denied.status, 1);
  assert.match(denied.stderr, /not entirely kind-on-Docker/);
});

test('help and invalid options do not contact the cluster or Docker', () => {
  const item = fixture();
  const help = spawnSync('bash', [script, '--help'], {
    encoding: 'utf8', env: {...process.env, PATH: `${item.bin}:${process.env.PATH}`},
  });
  assert.equal(help.status, 0);
  assert.equal(readFileSync(item.log, 'utf8'), '');
  const invalid = spawnSync('bash', [script, '--mode=unsafe', 'operator:exact'], {
    encoding: 'utf8', env: {...process.env, PATH: `${item.bin}:${process.env.PATH}`},
  });
  assert.equal(invalid.status, 2);
  assert.equal(readFileSync(item.log, 'utf8'), '');
});
