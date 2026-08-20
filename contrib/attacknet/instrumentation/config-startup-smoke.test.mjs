import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

import {runConfigStartupSmoke, smokeInputsFromNetwork} from './config-startup-smoke.mjs';

const nodeConfig = '[node]\np2p_address = "__NODE_IP__:20444"\nbootstrap_node = "key@${SERVICE:miner-1}:20444"\n';

test('node smoke resolves runtime-only addresses and invokes check-config in a locked-down container', () => {
  let invocation;
  const evidence = runConfigStartupSmoke({
    profileId: 'patched-main', requestedImage: 'stacks:content-abc', actor: 'follower-1', role: 'follower', configContents: nodeConfig,
  }, {
    now: () => '2026-08-18T12:00:00.000Z',
    runner(command, args) { invocation = [command, ...args]; return {status: 0, stdout: 'Loaded config', stderr: ''}; },
  });
  assert.equal(evidence.result, 'Passed');
  assert.equal(evidence.config.runtimeAddressesResolved, true);
  assert.deepEqual(invocation.slice(0, 4), ['docker', 'run', '--rm', '--network=none']);
  assert.ok(invocation.includes('stacks-node'));
  assert.deepEqual(invocation.slice(-3), ['check-config', '--config', '/attacknet-smoke/config.toml']);
  assert.notEqual(evidence.config.sourceDigest, evidence.config.parserInputDigest);
  assert.equal(evidence.config.parserInputSanitized, true);
  assert.match(evidence.evidenceDigest, /^sha256:[0-9a-f]{64}$/);
});

test('signer smoke uses the signer parser and preserves a failed unsupported configuration', () => {
  const evidence = runConfigStartupSmoke({
    profileId: 'release', requestedImage: 'stacks:v1', actor: 'signer-1', role: 'signer', configContents: 'unsupported_field = true\n',
  }, {runner: () => ({status: 2, stdout: '', stderr: 'unknown field'})});
  assert.equal(evidence.result, 'Failed');
  assert.equal(evidence.binary, 'stacks-signer');
  assert.equal(evidence.exitCode, 2);
});

test('signer smoke resolves the service placeholder applied by the operator before parsing', () => {
  let parserInput;
  const evidence = runConfigStartupSmoke({
    profileId: 'release', requestedImage: 'stacks:v1', actor: 'signer-1', role: 'signer',
    configContents: 'node_host = "${SERVICE:signer-node-1}:20443"\n',
  }, {
    runner(_command, args) {
      const mount = args[args.indexOf('--mount') + 1];
      const source = mount.match(/(?:^|,)src=([^,]+)/)?.[1];
      parserInput = readFileSync(source, 'utf8');
      return {status: 0, stdout: '', stderr: ''};
    },
  });
  assert.equal(parserInput, 'node_host = "127.0.0.1:20443"\n');
  assert.equal(evidence.result, 'Passed');
  assert.equal(evidence.config.parserInputSanitized, true);
  assert.equal(evidence.config.runtimeAddressesResolved, true);
});

test('StacksNetwork extraction refuses actors without a primary configuration', () => {
  const network = {kind: 'StacksNetwork', spec: {actors: [{name: 'miner-1', role: 'miner', image: 'stacks:x', config: {key: 'config.toml', files: {'config.toml': nodeConfig}}}]}};
  const [input] = smokeInputsFromNetwork(network, {profileId: 'main', requestedImage: 'stacks:x', actorName: 'miner-1'});
  assert.equal(input.role, 'miner');
  assert.throws(() => smokeInputsFromNetwork({kind: 'StacksNetwork', spec: {actors: [{name: 'bad', role: 'miner'}]}}, {profileId: 'main'}), /no primary config/);
});
