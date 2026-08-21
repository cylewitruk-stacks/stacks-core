import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

import {captureReadOnlyWalkthrough} from './phase-two-readonly-evidence.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const attacknet = join(directory, 'attacknet');
const registryPath = join(directory, 'command-registry.v1.json');
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
const require = createRequire(import.meta.url);
const {validateRegistry} = require('./command-contract.cjs');

function run(...args) {
  return spawnSync(attacknet, args, {encoding: 'utf8'});
}

function implementationFiles(root, prefix = '') {
  const found = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    const local = join(prefix, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      if (!['evidence', 'generated', 'examples'].includes(entry)) {
        found.push(...implementationFiles(path, local));
      }
    } else if (/\.(?:cjs|mjs|sh|py)$/.test(entry)
        && !/\.test\.mjs$/.test(entry)
        && !/^test_.*\.py$/.test(entry)) {
      found.push(local);
    }
  }
  return found.sort();
}

test('the README keeps the public facade boundary explicit', () => {
  const readme = readFileSync(join(directory, 'README.md'), 'utf8');
  const prose = readme.replace(/^> ?/gm, '').replace(/\s+/g, ' ');
  assert.match(prose, /Maintainer implementation reference/);
  assert.match(prose, /not public CLIs in Release 1/);
  assert.match(prose, /Agents and end users must not automate against them/);
  for (const helper of [
    'burnchain-policy.sh', 'version-matrix.mjs', 'soak-runner.sh',
    'environment-lock.sh', 'local-access.sh', 'capacity-preflight.sh',
    'compose-negative-controls.sh',
  ]) assert.match(prose, new RegExp(helper.replaceAll('.', '\\.')));
});

test('machine discovery returns the exact checked-in versioned registry', () => {
  const result = run('commands', '--json');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), registry);
  assert.equal(registry.schema, 'stacks-attacknet-command-registry/v1');
  assert.match(registry.interfaceVersion, /^\d+\.\d+\.\d+$/);
});

test('every workflow and every implementation entry point is explicitly classified', () => {
  const names = registry.commands.map(command => command.name);
  assert.equal(new Set(names).size, names.length);
  for (const name of ['help', 'commands', 'doctor', 'render', 'verify']) assert.ok(names.includes(name));
  for (const group of ['lifecycle', 'campaign', 'evidence', 'replay', 'minimize', 'dashboard', 'image']) {
    assert.ok(names.some(name => name.startsWith(`${group} `)), `missing ${group}`);
  }

  const internal = [...registry.internalHelpers].sort();
  assert.equal(new Set(internal).size, internal.length);
  assert.deepEqual(internal, implementationFiles(directory));
  for (const helper of internal) assert.ok(statSync(resolve(directory, helper)).isFile(), helper);
  for (const command of registry.commands) {
    assert.equal(typeof command.purpose, 'string');
    assert.equal(typeof command.stability, 'string');
    assert.equal(typeof command.sideEffectClass, 'string');
    assert.equal(typeof command.requiredPrivileges, 'string');
    assert.ok(Array.isArray(command.inputs.positionals));
    assert.ok(Array.isArray(command.inputs.options));
    assert.ok(command.inputs.positionals.every(item => typeof item.name === 'string'
      && typeof item.required === 'boolean' && typeof item.variadic === 'boolean'));
    assert.ok(command.inputs.options.every(item => /^--/.test(item.name)
      && typeof item.required === 'boolean' && typeof item.type === 'string'));
    assert.ok(Array.isArray(command.outputs));
    assert.ok(Array.isArray(command.backendSupport));
    assert.ok(Array.isArray(command.examples));
    assert.equal(typeof command.plan, 'boolean');
    if (command.implementation.visibility === 'internal' && command.implementation.path) {
      assert.ok(internal.includes(command.implementation.path));
    }
  }
});

test('leaf help is generated for every declared command without invoking helpers', () => {
  for (const command of registry.commands) {
    const result = run(...command.name.split(' '), '--help');
    assert.equal(result.status, 0, `${command.name}: ${result.stderr}`);
    assert.match(result.stdout, new RegExp(`^usage: attacknet ${command.name.replaceAll(' ', '\\s+')}`));
    assert.match(result.stdout, new RegExp(command.sideEffectClass.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    for (const [code, description] of Object.entries(registry.exitCodes)) {
      assert.match(result.stdout, new RegExp(`  ${code}  ${description.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    }
  }
});

test('shared validation rejects drift in every dispatch field before help can advertise it', () => {
  const mutations = [
    ['prefix', command => { command.implementation.prefix = ['exportt']; }, /prefix does not match its admitted adapter/],
    ['action', command => { command.implementation.action = 'nuke'; }, /action does not match its admitted adapter/],
    ['program', command => { command.implementation.program = 'bassh'; }, /program does not match its admitted adapter/],
    ['kind', command => { command.implementation.kind = 'teleport'; }, /kind does not match its admitted adapter/],
  ];
  for (const [name, mutate, expected] of mutations) {
    const candidate = structuredClone(registry);
    const command = name === 'action'
      ? candidate.commands.find(item => item.name === 'lifecycle apply')
      : candidate.commands.find(item => item.name === 'evidence export');
    mutate(command);
    assert.throws(() => validateRegistry(candidate, directory), expected, name);
  }
  const fabricated = structuredClone(registry);
  const command = structuredClone(fabricated.commands.find(item => item.name === 'evidence export'));
  command.name = 'evidence teleport';
  fabricated.commands.push(command);
  assert.throws(() => validateRegistry(fabricated, directory), /has no admitted dispatcher adapter/);
});

test('group and unknown-command behavior is discoverable and consistent', () => {
  const group = run('lifecycle', '--help');
  assert.equal(group.status, 0, group.stderr);
  assert.match(group.stdout, /lifecycle apply/);
  assert.match(group.stdout, /lifecycle delete/);

  const unknown = run('lifecycle', 'explode');
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown command lifecycle explode/);
  assert.match(unknown.stderr, /usage: attacknet COMMAND/);
});

test('argument errors always use exit 2 and do not execute an implementation', () => {
  const cases = [
    [['render', 'unexpected'], /expected 0 positional arguments/],
    [['verify'], /expected 2 positional arguments/],
    [['verify', 'manifest.json', 'unknown'], /ACTION must be one of/],
    [['campaign', 'run', 'campaign.json'], /expected 2-3 positional arguments/],
    [['image', 'plan', 'pipeline.json', '--plan'], /unknown option --plan/],
    [['render', '--backend=compose'], /unknown option --backend/],
    [['verify', '--backend=compose', 'manifest.json', 'snapshot'], /positional arguments must precede options/],
    [['commands'], /--json is required/],
    [['campaign', 'plan', '-h', 'manifest.json'], /unknown option -h/],
    [['render', '--miners=NaN'], /must be an integer/],
    [['render', '--probes=perhaps'], /must be one of/],
    [['image', 'build', 'pipeline.json'], /--output-dir is required/],
    [['render', '--plan', '--dry-run'], /aliases; choose one/],
  ];
  for (const [args, expected] of cases) {
    const result = run(...args);
    assert.equal(result.status, 2, `${args.join(' ')}: ${result.stderr}`);
    assert.match(result.stderr, expected);
    assert.match(result.stderr, /usage: attacknet/);
  }
});

test('plan and dry-run resolve but never execute mutating commands', () => {
  for (const option of ['--plan', '--dry-run']) {
    const result = run('campaign', 'run', '/does/not/exist.json', '/also/missing.json', option);
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.schema, 'stacks-attacknet-command-plan/v1');
    assert.equal(plan.command, 'campaign run');
    assert.equal(plan.executed, false);
    assert.match(plan.invocation.args[0], /campaign-runner\.sh$/);
    assert.deepEqual(plan.invocation.args.slice(1), ['/does/not/exist.json', '/also/missing.json']);
  }
  for (const action of ['apply', 'wait', 'capture', 'delete']) {
    const args = ['lifecycle', action, '/does/not/exist'];
    if (action === 'capture') args.push('/also/missing');
    args.push('--backend=kubernetes', '--plan');
    const result = run(...args);
    assert.equal(result.status, 0, `${action}: ${result.stderr}`);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.executed, false);
    assert.equal(plan.invocation.environmentSource.resolved, false);
    assert.match(plan.invocation.environmentSource.path, /does\/not\/exist\/manifest\.json$/);
  }
});

test('a symlinked dispatcher resolves helpers relative to the real installation', t => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-symlink-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const linked = join(root, 'attacknet');
  symlinkSync(attacknet, linked);
  const result = spawnSync(linked, ['commands', '--json'], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).schema, registry.schema);
});

test('offline render remains reachable through the facade', () => {
  const output = execFileSync(attacknet, ['render', '--miners=1', '--signers=1', '--followers=1', '--plan'], {encoding: 'utf8'});
  const plan = JSON.parse(output);
  assert.equal(plan.command, 'render');
  assert.equal(plan.executed, false);
  assert.equal(plan.invocation.executable, process.execPath);
  assert.match(plan.invocation.args[0], /topology\.mjs$/);
});

test('the quickstart topology and fault plan compose through only the public facade', t => {
  const output = mkdtempSync(join(tmpdir(), 'attacknet-command-quickstart-'));
  t.after(() => rmSync(output, {recursive: true, force: true}));
  execFileSync(attacknet, ['render', '--miners=1', '--signers=1', '--followers=1', `--output=${output}`]);
  const campaign = join(directory, 'examples/follower-network-delay.json');
  const compiled = join(output, 'fault.json');
  execFileSync(attacknet, ['campaign', 'plan', campaign, join(output, 'manifest.json'), compiled]);
  const resource = JSON.parse(readFileSync(compiled, 'utf8'));
  assert.equal(resource.apiVersion, 'chaos-mesh.org/v1alpha1');
  assert.equal(resource.kind, 'NetworkChaos');

  const internal = join(directory, 'examples/follower-application-clock-skew.json');
  const rejected = run('campaign', 'run', internal, join(output, 'manifest.json'), join(output, 'internal-evidence'));
  assert.equal(rejected.status, 2);
  assert.match(rejected.stderr, /controller-owned internal policies/);

  const oneShot = join(directory, 'examples/ddmin-live-pod-template.json');
  const oneShotCampaign = JSON.parse(readFileSync(oneShot, 'utf8'));
  oneShotCampaign.spec.networkRef = 'attacknet';
  const oneShotPath = join(output, 'one-shot.json');
  writeFileSync(oneShotPath, `${JSON.stringify(oneShotCampaign, null, 2)}\n`);
  const oneShotRejected = run('campaign', 'run', oneShotPath, join(output, 'manifest.json'), join(output, 'one-shot-evidence'));
  assert.equal(oneShotRejected.status, 2);
  assert.match(oneShotRejected.stderr, /cannot prove AllRecovered for one-shot pod-kill/);

  for (const action of ['apply', 'wait', 'capture', 'delete']) {
    const args = ['lifecycle', action, output];
    if (action === 'capture') args.push(join(output, 'evidence'));
    args.push('--backend=kubernetes', '--plan');
    const plan = JSON.parse(execFileSync(attacknet, args, {encoding: 'utf8'}));
    assert.equal(plan.command, `lifecycle ${action}`);
    assert.equal(plan.executed, false);
  }
});

test('quickstart covers both personas and Phase 2 uses the shared immutable gate', () => {
  const readme = readFileSync(join(directory, 'README.md'), 'utf8');
  const start = readme.indexOf('## Quickstart and command discovery');
  const end = readme.indexOf('## Design boundaries');
  assert.ok(start >= 0, 'Human quickstart heading must exist');
  assert.ok(end > start, 'Design boundaries must follow the quickstart');
  const quickstart = readme.slice(start, end);
  for (const workflow of ['doctor', 'render', 'lifecycle apply', 'verify', 'campaign plan',
    'campaign run', 'evidence capture', 'lifecycle delete', 'commands --json', '--plan']) {
    assert.match(quickstart, new RegExp(workflow.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  const contract = JSON.parse(readFileSync(join(directory, 'release/phase-2-contract.json'), 'utf8'));
  const evidenceReadme = readFileSync(join(directory, 'evidence-packets/phase-2/README.md'), 'utf8');
  assert.equal(contract.phase, 2);
  assert.equal(contract.requiredReviewers.length, 2);
  assert.ok(contract.requirements.includes('human-live-usability'));
  assert.ok(contract.requirements.includes('agent-live-usability'));
  assert.match(evidenceReadme, /phase-two-packet\.mjs/);
  assert.match(evidenceReadme, /toolingDigest/);
  assert.doesNotMatch(evidenceReadme, /dirty-candidate.*completion/i);
});

test('doctor checks port occupancy without binding a listening socket', () => {
  const source = readFileSync(join(directory, 'doctor.mjs'), 'utf8');
  assert.doesNotMatch(source, /net\.createServer/);
  assert.match(source, /net\.createConnection/);
});

test('read-only walkthrough distinguishes registry file bytes from command stdout', t => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-phase-two-evidence-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const output = join(root, 'walkthrough.json');
  const evidence = captureReadOnlyWalkthrough(output);
  assert.equal(evidence.agentPersona.discovery.semanticAgreement, true);
  assert.match(evidence.agentPersona.discovery.registryFileDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(evidence.agentPersona.discovery.registryStdoutDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal('registryDigest' in evidence.agentPersona.discovery, false);
  assert.ok(evidence.humanPersona.every(step => step.exitCode === 0));
  assert.ok(evidence.humanPersona.filter(step => step.result)
    .every(step => step.result.invocation.environmentSource?.resolved !== true
      || step.result.invocation.environmentSource === null));
});
