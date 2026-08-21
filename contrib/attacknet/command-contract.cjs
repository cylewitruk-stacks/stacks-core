'use strict';

const {readFileSync, realpathSync, statSync} = require('node:fs');
const {extname, join, resolve} = require('node:path');

const IMPLEMENTATION_KINDS = new Set(['help', 'commands', 'program', 'lifecycle']);
const PROGRAM_BY_EXTENSION = new Map([['.mjs', 'node'], ['.sh', 'bash']]);
const PREFIX_BY_PATH = new Map([
  ['run-ledger.mjs', [['export']]],
  ['run-descriptor.mjs', [['minimize']]],
  ['attacknet-run-schedule.mjs', [['replay'], ['ddmin-init']]],
  ['chaos-dashboard.sh', [['local'], ['secure'], ['token'], ['start'], ['stop'], ['status']]],
  ['image-build-pipeline.mjs', [[], ['--execute']]],
]);
const LIFECYCLE_ACTIONS = new Set(['apply', 'wait', 'capture', 'delete']);
const ADAPTER_BY_COMMAND = new Map([
  ['help', {kind: 'help'}],
  ['commands', {kind: 'commands'}],
  ['doctor', {kind: 'program', path: 'doctor.mjs', program: 'node', prefix: []}],
  ['render', {kind: 'program', path: 'topology.mjs', program: 'node', prefix: []}],
  ...['apply', 'wait', 'capture', 'delete'].map(action => [`lifecycle ${action}`, {kind: 'lifecycle', action}]),
  ['verify', {kind: 'program', path: 'verify.sh', program: 'bash', prefix: []}],
  ['campaign plan', {kind: 'program', path: 'fault-campaign.mjs', program: 'node', prefix: []}],
  ['campaign run', {kind: 'program', path: 'campaign-runner.sh', program: 'bash', prefix: []}],
  ['evidence capture', {kind: 'program', path: 'evidence-harness.sh', program: 'bash', prefix: []}],
  ['evidence export', {kind: 'program', path: 'run-ledger.mjs', program: 'node', prefix: ['export']}],
  ['replay derive', {kind: 'program', path: 'run-descriptor.mjs', program: 'node', prefix: ['minimize']}],
  ['replay resolve', {kind: 'program', path: 'attacknet-run-schedule.mjs', program: 'node', prefix: ['replay']}],
  ['minimize plan', {kind: 'program', path: 'attacknet-run-schedule.mjs', program: 'node', prefix: ['ddmin-init']}],
  ['minimize execute', {kind: 'program', path: 'kubernetes-ddmin-adapter.mjs', program: 'node', prefix: []}],
  ...['local', 'secure', 'token', 'start', 'stop', 'status']
    .map(action => [`dashboard ${action}`, {kind: 'program', path: 'chaos-dashboard.sh', program: 'bash', prefix: [action]}]),
  ['image plan', {kind: 'program', path: 'image-build-pipeline.mjs', program: 'node', prefix: []}],
  ['image build', {kind: 'program', path: 'image-build-pipeline.mjs', program: 'node', prefix: ['--execute']}],
  ['image admission', {kind: 'program', path: 'image-admission-evidence.mjs', program: 'node', prefix: []}],
]);

function fail(message) { throw new Error(message); }
function strings(value, field) {
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || !item)) fail(`${field} must contain strings`);
  if (new Set(value).size !== value.length) fail(`${field} contains duplicates`);
  return value;
}
function same(left, right) { return JSON.stringify(left) === JSON.stringify(right); }

function validateInputs(command) {
  const inputs = command.inputs;
  if (!inputs || !Array.isArray(inputs.positionals) || !Array.isArray(inputs.options)) fail(`${command.name} inputs are incomplete`);
  let optionalSeen = false;
  for (const [index, positional] of inputs.positionals.entries()) {
    if (!positional || typeof positional.name !== 'string' || !positional.name) fail(`${command.name} positional ${index} has no name`);
    if (typeof positional.required !== 'boolean' || typeof positional.variadic !== 'boolean') fail(`${command.name} positional ${positional.name} flags are invalid`);
    if (optionalSeen && positional.required) fail(`${command.name} requires a positional after an optional one`);
    optionalSeen ||= !positional.required;
    if (positional.enum) strings(positional.enum, `${command.name} positional ${positional.name} enum`);
    if (positional.variadic && index !== inputs.positionals.length - 1) fail(`${command.name} variadic positional must be last`);
    if (positional.maximumItems !== undefined
        && (!positional.variadic || !Number.isSafeInteger(positional.maximumItems) || positional.maximumItems < 1)) {
      fail(`${command.name} positional ${positional.name} maximumItems is invalid`);
    }
  }
  const optionNames = new Set();
  for (const option of inputs.options) {
    if (!option || !/^--[a-z0-9-]+$/.test(option.name ?? '') || optionNames.has(option.name)) fail(`${command.name} option contract is invalid`);
    optionNames.add(option.name);
    if (!['boolean', 'string', 'integer', 'enum'].includes(option.type) || typeof option.required !== 'boolean') fail(`${command.name} ${option.name} type/requiredness is invalid`);
    if (option.type === 'enum') strings(option.enum, `${command.name} ${option.name} enum`);
    if (option.type === 'integer' && (!Number.isSafeInteger(option.minimum) || option.minimum < 0)) fail(`${command.name} ${option.name} minimum is invalid`);
  }
}

function validateImplementation(command, root, internals) {
  const implementation = command.implementation ?? {};
  const expectedAdapter = ADAPTER_BY_COMMAND.get(command.name);
  if (!expectedAdapter) fail(`${command.name} has no admitted dispatcher adapter`);
  for (const field of ['kind', 'path', 'program', 'prefix', 'action']) {
    if (!same(implementation[field], expectedAdapter[field])) fail(`${command.name} ${field} does not match its admitted adapter`);
  }
  if (!IMPLEMENTATION_KINDS.has(implementation.kind)) fail(`${command.name} implementation kind is unsupported`);
  if (['help', 'commands'].includes(implementation.kind)) {
    if (implementation.visibility !== 'builtin' || implementation.path || implementation.program || implementation.prefix || implementation.action) {
      fail(`${command.name} builtin implementation is invalid`);
    }
    return;
  }
  if (implementation.kind === 'lifecycle') {
    if (implementation.visibility !== 'internal' || !LIFECYCLE_ACTIONS.has(implementation.action)) fail(`${command.name} lifecycle action is invalid`);
    for (const script of ['lifecycle.sh', 'compose-lifecycle.sh']) {
      const source = readFileSync(join(root, script), 'utf8');
      if (!new RegExp(`(?:^|[|\\s])${implementation.action}(?:[|)\\s])`, 'm').test(source)) fail(`${command.name} action is absent from ${script}`);
    }
    return;
  }
  if (implementation.visibility !== 'internal' || !internals.has(implementation.path)) fail(`${command.name} path is not classified internal`);
  const fullPath = resolve(root, implementation.path);
  if (!statSync(fullPath).isFile()) fail(`${command.name} implementation is not a file`);
  const expectedProgram = PROGRAM_BY_EXTENSION.get(extname(implementation.path));
  if (implementation.program !== expectedProgram) fail(`${command.name} program must be ${expectedProgram}`);
  const allowedPrefixes = PREFIX_BY_PATH.get(implementation.path) ?? [[]];
  if (!Array.isArray(implementation.prefix) || !allowedPrefixes.some(prefix => same(prefix, implementation.prefix))) {
    fail(`${command.name} prefix is not an admitted adapter for ${implementation.path}`);
  }
}

function validateRegistry(value, root) {
  if (value?.schema !== 'stacks-attacknet-command-registry/v1') fail(`unsupported registry schema ${value?.schema}`);
  if (!/^\d+\.\d+\.\d+$/.test(value.interfaceVersion ?? '')) fail('registry interfaceVersion must be semantic version text');
  const names = new Set();
  const internals = new Set(strings(value.internalHelpers, 'internalHelpers'));
  if (!value.exitCodes || Object.keys(value.exitCodes).sort().join(',') !== '0,1,2') fail('registry exitCodes must define 0, 1, and 2');
  for (const command of value.commands ?? []) {
    if (!command.name || names.has(command.name)) fail(`duplicate or empty command name ${command.name}`);
    names.add(command.name);
    for (const field of ['purpose', 'stability', 'sideEffectClass', 'requiredPrivileges']) {
      if (typeof command[field] !== 'string' || !command[field]) fail(`${command.name} has no ${field}`);
    }
    validateInputs(command);
    strings(command.outputs, `${command.name}.outputs`);
    strings(command.backendSupport, `${command.name}.backendSupport`);
    strings(command.examples, `${command.name}.examples`);
    if (typeof command.plan !== 'boolean') fail(`${command.name}.plan must be boolean`);
    if (!['runtime-none', 'runtime-read', 'local-filesystem-write', 'runtime-read-and-local-write',
      'runtime-mutation', 'destructive-runtime-mutation', 'security-sensitive-runtime-mutation',
      'secret-output-and-runtime-mutation', 'local-process-mutation', 'image-and-runtime-mutation']
      .includes(command.sideEffectClass)) {
      fail(`${command.name} has an unknown sideEffectClass`);
    }
    validateImplementation(command, root, internals);
  }
  for (const required of ['help', 'commands', 'doctor', 'render', 'verify']) if (!names.has(required)) fail(`registry is missing ${required}`);
  for (const group of ['lifecycle', 'campaign', 'evidence', 'replay', 'minimize', 'dashboard', 'image']) {
    if (![...names].some(name => name.startsWith(`${group} `))) fail(`registry is missing the ${group} command group`);
  }
  return value;
}

function loadRegistry(path, root) {
  const registryPath = realpathSync(path);
  return validateRegistry(JSON.parse(readFileSync(registryPath, 'utf8')), root);
}

module.exports = {loadRegistry, validateRegistry};
