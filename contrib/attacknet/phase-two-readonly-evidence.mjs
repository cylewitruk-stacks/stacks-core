#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(directory, '..', '..');
const attacknet = join(directory, 'attacknet');

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function invoke(args) {
  const result = spawnSync(attacknet, args, {cwd: repository, encoding: 'utf8'});
  if (result.error || result.status !== 0) {
    throw new Error(`${args.join(' ')} failed: ${result.error?.message ?? result.stderr.trim()}`);
  }
  return {command: `contrib/attacknet/attacknet ${args.join(' ')}`, exitCode: result.status,
    stdout: result.stdout, stderr: result.stderr};
}

function plan(args) {
  const result = invoke(args);
  const {stdout, ...summary} = result;
  return {...summary, stdoutDigest: sha256(Buffer.from(stdout)), result: JSON.parse(stdout)};
}

export function captureReadOnlyWalkthrough(outputPath) {
  const temporary = mkdtempSync(join(tmpdir(), 'attacknet-phase-2-plan-walkthrough.'));
  try {
    const registryBytes = readFileSync(join(directory, 'command-registry.v1.json'));
    const discovery = invoke(['commands', '--json']);
    const discoveryValue = JSON.parse(discovery.stdout);
    const help = invoke(['help', 'lifecycle', 'apply']);
    const rendered = invoke(['render', '--miners=1', '--signers=1', '--followers=1', `--output=${temporary}`]);
    const manifest = join(temporary, 'manifest.json');
    const campaign = join(directory, 'examples/follower-application-clock-skew.json');
    const fault = join(temporary, 'fault.json');
    const compiled = invoke(['campaign', 'plan', campaign, manifest, fault]);
    const humanPersona = [
      {...rendered, step: 'render', artifact: {manifestFileDigest: sha256(readFileSync(manifest))}},
      {...plan(['lifecycle', 'apply', temporary, '--backend=kubernetes', '--plan']), step: 'start-plan'},
      {...plan(['verify', manifest, 'snapshot', '--backend=kubernetes', '--dry-run']), step: 'inspect-plan'},
      {...compiled, step: 'fault-compile', artifact: {compiledResourceFileDigest: sha256(readFileSync(fault))}},
      {...plan(['campaign', 'run', campaign, manifest, join(temporary, 'evidence/campaign'), '--plan']), step: 'fault-run-plan'},
      {...plan(['evidence', 'capture', join(temporary, 'evidence/capture'), manifest,
        '--backend=kubernetes', '--dry-run']), step: 'capture-plan'},
      {...plan(['lifecycle', 'delete', temporary, '--backend=kubernetes', '--plan']), step: 'delete-plan'},
    ];
    const value = {
      schema: 'stacks-attacknet-phase-2-plan-walkthrough/v1',
      observedAt: new Date().toISOString(),
      mutationPolicy: {docker: 'not invoked', kubernetes: 'not invoked',
        runtimeSteps: 'resolved only through --plan/--dry-run'},
      workspace: {repository, temporaryRenderDirectory: temporary},
      agentPersona: {
        discovery: {command: discovery.command, exitCode: discovery.exitCode,
          schema: discoveryValue.schema, interfaceVersion: discoveryValue.interfaceVersion,
          commandCount: discoveryValue.commands.length,
          registryFileDigest: sha256(registryBytes),
          registryStdoutDigest: sha256(Buffer.from(discovery.stdout)),
          semanticAgreement: JSON.stringify(discoveryValue) === JSON.stringify(JSON.parse(registryBytes))},
        help: {command: help.command, exitCode: help.exitCode, usage: help.stdout.split('\n')[0],
          stdoutDigest: sha256(Buffer.from(help.stdout))},
      },
      humanPersona,
      additionalSurfacePlans: [
        plan(['dashboard', 'status', '--dry-run']),
        plan(['image', 'build', '/tmp/phase-2-pipeline-placeholder.json',
          '--output-dir=/tmp/phase-2-images', '--plan']),
      ],
      conclusion: {agentDiscoveryPassed: true, offlineRenderPassed: true,
        faultCompilationPassed: true, allRuntimeCommandsResolvedWithoutExecution: true,
        liveUsability: 'not exercised; requires explicit authorization for Docker/Kubernetes mutation'},
    };
    writeFileSync(outputPath, `${JSON.stringify(value, null, 2)}\n`);
    return value;
  } finally {
    rmSync(temporary, {recursive: true, force: true});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const output = process.argv[2];
  if (!output) {
    process.stderr.write('usage: phase-two-readonly-evidence.mjs OUTPUT_JSON\n');
    process.exitCode = 2;
  } else {
    captureReadOnlyWalkthrough(resolve(output));
  }
}
