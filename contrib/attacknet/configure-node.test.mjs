import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const script = resolve('contrib/attacknet/configure-node.sh');

function run(ip) {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-configure-node-'));
  const template = join(root, 'config.toml');
  const output = join(root, 'rendered.toml');
  const marker = join(root, 'started');
  writeFileSync(template, '[node]\np2p_address = "__NODE_IP__:20444"\n[connection_options]\npublic_ip_address = "__NODE_IP__:20444"\n');
  const result = spawnSync('bash', [script, 'sh', '-c', 'printf started >"$MARKER"'], {encoding: 'utf8', env: {
    ...process.env, STACKS_ATTACKNET_CONFIG_TEMPLATE: template, STACKS_ATTACKNET_CONFIG: output,
    STACKS_ATTACKNET_NODE_IP: ip, MARKER: marker,
  }});
  return {root, output, marker, result};
}

test('runtime address rendering accepts a numeric IPv4 socket and starts the actor', () => {
  const {output, marker, result} = run('10.20.30.40');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(marker, 'utf8'), 'started');
  const rendered = readFileSync(output, 'utf8');
  assert.doesNotMatch(rendered, /__NODE_IP__/);
  assert.match(rendered, /10\.20\.30\.40:20444/g);
});

test('invalid, DNS, IPv6, and out-of-range addresses fail before actor startup', () => {
  for (const ip of ['node.default.svc', 'fd00::1', '10.2.3', '10.2.3.999']) {
    const {marker, result} = run(ip);
    assert.notEqual(result.status, 0, `${ip || '<empty>'} should fail`);
    assert.throws(() => readFileSync(marker), /ENOENT/);
    assert.match(result.stderr, /numeric IPv4/);
  }
});
