#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROLE = new Set(['miner', 'companion', 'follower', 'signer']);

function fail(message) { throw new Error(message); }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function digestBytes(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function digestValue(value) { return digestBytes(JSON.stringify(canonical(value))); }
function resolveRuntimeConfig(contents, {signer}) {
  const serviceResolved = contents.replace(/\$\{SERVICE:[a-z0-9-]+\}/g, '127.0.0.1');
  return signer ? serviceResolved : serviceResolved.replaceAll('__NODE_IP__', '127.0.0.1');
}
function defaultRunner(command, args) {
  return spawnSync(command, args, {encoding: 'utf8', maxBuffer: 16 * 1024 * 1024});
}

export function runConfigStartupSmoke({profileId, requestedImage, actor, role, configContents}, {runner = defaultRunner, now = () => new Date().toISOString()} = {}) {
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/.test(profileId ?? '')) fail('profileId is invalid');
  if (typeof requestedImage !== 'string' || requestedImage.length === 0) fail('requestedImage is required');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(actor ?? '')) fail('actor is invalid');
  if (!ROLE.has(role)) fail('role is invalid');
  if (typeof configContents !== 'string' || configContents.length === 0) fail('configContents is required');
  const signer = role === 'signer';
  const binary = signer ? 'stacks-signer' : 'stacks-node';
  // The operator resolves service placeholders for every actor before mounting
  // its ConfigMap.  The smoke must exercise the same parser input boundary;
  // otherwise valid signer configs fail on the intentionally unresolved token.
  const config = resolveRuntimeConfig(configContents, {signer});
  const scratch = mkdtempSync(`${tmpdir()}/attacknet-config-smoke-`);
  const path = `${scratch}/${signer ? 'signer.toml' : 'config.toml'}`;
  const containerPath = `/attacknet-smoke/${signer ? 'signer.toml' : 'config.toml'}`;
  try {
    writeFileSync(path, config, {mode: 0o600});
    const command = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
      '--entrypoint', binary, '--mount', `type=bind,src=${path},dst=${containerPath},readonly`, requestedImage,
      'check-config', '--config', containerPath];
    const result = runner(command[0], command.slice(1));
    if (result.error) fail(`could not execute ${binary} smoke: ${result.error.message}`);
    const evidence = {
      schema: 'stacks-attacknet-config-startup-smoke/v1', profileId, requestedImage, actor, role, binary,
      command, checkedAt: now(), result: result.status === 0 ? 'Passed' : 'Failed', exitCode: result.status,
      config: {
        sourceDigest: digestBytes(configContents),
        parserInputDigest: digestBytes(config),
        parserInputSanitized: config !== configContents,
        runtimeAddressesResolved: !config.includes('__NODE_IP__') && !config.includes('${SERVICE:'),
      },
      output: {stdoutDigest: digestBytes(result.stdout ?? ''), stderrDigest: digestBytes(result.stderr ?? '')},
    };
    evidence.evidenceDigest = digestValue(evidence);
    return evidence;
  } finally {
    rmSync(scratch, {recursive: true, force: true});
  }
}

export function smokeInputsFromNetwork(network, {profileId, requestedImage, actorName} = {}) {
  if (network?.kind !== 'StacksNetwork' || !Array.isArray(network.spec?.actors)) fail('input must be a StacksNetwork');
  const actors = network.spec.actors.filter(actor => !actorName || actor.name === actorName);
  if (actors.length === 0) fail(`actor not found: ${actorName ?? '<any>'}`);
  return actors.filter(actor => ['miner', 'companion', 'follower', 'signer'].includes(actor.role)).map(actor => {
    const key = actor.config?.key;
    const configContents = actor.config?.files?.[key];
    if (!key || typeof configContents !== 'string') fail(`actor ${actor.name} has no primary config`);
    return {profileId, requestedImage: requestedImage ?? actor.image, actor: actor.name, role: actor.role, configContents};
  });
}

function option(args, name) { return args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3); }
function main() {
  const args = process.argv.slice(2);
  const [networkPath] = args.filter(arg => !arg.startsWith('--'));
  const profileId = option(args, 'profile-id');
  const requestedImage = option(args, 'image');
  const actorName = option(args, 'actor');
  const output = option(args, 'output');
  if (!networkPath || !profileId || !requestedImage || !actorName) fail('usage: config-startup-smoke.mjs NETWORK.json --profile-id=ID --image=REF --actor=ACTOR [--output=FILE]');
  const network = JSON.parse(readFileSync(resolve(networkPath), 'utf8'));
  const [input] = smokeInputsFromNetwork(network, {profileId, requestedImage, actorName});
  const evidence = runConfigStartupSmoke(input);
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (output) writeFileSync(resolve(output), serialized); else process.stdout.write(serialized);
  if (evidence.result !== 'Passed') process.exitCode = 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(`config startup smoke: ${error.message}`); process.exitCode = 1; }
}
