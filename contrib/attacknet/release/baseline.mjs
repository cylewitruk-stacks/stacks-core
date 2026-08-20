#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {accessSync, constants, readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export const BASELINE_SCHEMA = 'stacks-attacknet-release-baseline/v1';

function object(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function string(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function array(value, field) {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${field} must be a non-empty array`);
  return value;
}

function digest(value, field) {
  string(value, field);
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`${field} must be a lowercase sha256 digest`);
  return value;
}

function uniqueBy(items, field, scope) {
  const seen = new Set();
  for (const item of items) {
    const value = string(item[field], `${scope}.${field}`);
    if (seen.has(value)) throw new Error(`${scope} contains duplicate ${field} ${value}`);
    seen.add(value);
  }
}

function fileDigest(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

export function validateBaseline(baseline, options = {}) {
  object(baseline, 'baseline');
  if (baseline.schemaVersion !== BASELINE_SCHEMA) throw new Error(`unsupported baseline schema ${baseline.schemaVersion}`);
  object(baseline.acceptedExecution, 'acceptedExecution');
  string(baseline.acceptedExecution.sourceRevision, 'acceptedExecution.sourceRevision');
  digest(baseline.acceptedExecution.dirtyPatchDigest, 'acceptedExecution.dirtyPatchDigest');
  object(baseline.acceptedExecution.topology, 'acceptedExecution.topology');
  if (baseline.acceptedExecution.topology.protocolActors !== 28 || baseline.acceptedExecution.topology.workloads !== 31) {
    throw new Error('accepted topology must remain the proven 28 protocol actors / 31 workloads');
  }

  object(baseline.offlineVerification, 'offlineVerification');
  string(baseline.offlineVerification.command, 'offlineVerification.command');
  const suites = array(baseline.offlineVerification.suites, 'offlineVerification.suites');
  uniqueBy(suites, 'name', 'offlineVerification.suites');
  for (const suite of suites) {
    if (!Number.isSafeInteger(suite.tests) || suite.tests < 1) throw new Error(`${suite.name}.tests must be positive`);
    if (suite.passed !== suite.tests || suite.failed !== 0) throw new Error(`${suite.name} must be a clean pass`);
  }

  const evidence = array(baseline.evidence, 'evidence');
  uniqueBy(evidence, 'id', 'evidence');
  for (const entry of evidence) {
    string(entry.path, `${entry.id}.path`);
    digest(entry.digest, `${entry.id}.digest`);
    if (entry.status !== 'passed') throw new Error(`${entry.id}.status must be passed`);
  }

  const capabilities = array(baseline.capabilities, 'capabilities');
  uniqueBy(capabilities, 'id', 'capabilities');
  for (const capability of capabilities) {
    if (!new Set(['supported', 'capability-rejected', 'deferred', 'not-done']).has(capability.status)) {
      throw new Error(`${capability.id}.status is unsupported`);
    }
    array(capability.evidence, `${capability.id}.evidence`);
    if (capability.status === 'deferred') {
      for (const field of ['unavailableDependency', 'affectedRequirement', 'currentCapability', 'risk', 'reopenCondition']) {
        string(capability[field], `${capability.id}.${field}`);
      }
    }
    if (capability.status !== 'supported') string(capability.reason, `${capability.id}.reason`);
  }
  const evidenceIds = new Set(evidence.map(item => item.id));
  for (const capability of capabilities) {
    for (const id of capability.evidence) {
      if (!evidenceIds.has(id)) throw new Error(`${capability.id} references unknown evidence ${id}`);
    }
  }

  if (options.verifyEvidence === true) {
    const root = resolve(options.root ?? '.');
    for (const entry of evidence) {
      const path = resolve(root, entry.path);
      accessSync(path, constants.R_OK);
      const actual = fileDigest(path);
      if (actual !== entry.digest) throw new Error(`evidence digest mismatch for ${entry.id}: ${actual}`);
    }
  }
  return true;
}

function usage() {
  console.error('usage: baseline.mjs validate BASELINE [--verify-evidence] [--root=PATH]');
}

function main(argv) {
  if (argv.length < 2 || argv[0] !== 'validate') {
    usage();
    return 2;
  }
  const path = argv[1];
  const rootArg = argv.find(arg => arg.startsWith('--root='));
  const baseline = JSON.parse(readFileSync(path, 'utf8'));
  validateBaseline(baseline, {
    verifyEvidence: argv.includes('--verify-evidence'),
    root: rootArg?.slice('--root='.length) ?? '.',
  });
  console.log('valid');
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
