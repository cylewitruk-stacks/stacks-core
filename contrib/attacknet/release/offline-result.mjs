#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export const OFFLINE_RESULT_SCHEMA = 'stacks-attacknet-offline-check-result/v1';

function suite(value) {
  const parsed = typeof value === 'string'
    ? (() => {
        const [name, testsText, passedText, failedText, ...extra] = value.split(':');
        if (extra.length > 0) throw new Error(`invalid clean suite result ${value}`);
        return {name, tests: Number(testsText), passed: Number(passedText), failed: Number(failedText)};
      })()
    : value;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`invalid clean suite result ${JSON.stringify(value)}`);
  const unknown = Object.keys(parsed).filter(key => !['name', 'tests', 'passed', 'failed'].includes(key));
  if (unknown.length > 0) throw new Error(`unknown suite field ${unknown[0]}`);
  const {name, tests, passed, failed} = parsed;
  if (!name || ![tests, passed, failed].every(Number.isSafeInteger) || tests < 1 || passed !== tests || failed !== 0) {
    throw new Error(`invalid clean suite result ${JSON.stringify(value)}`);
  }
  return {name, tests, passed, failed};
}

export function buildOfflineResult({sourceRevision, suites, command = 'contrib/attacknet/check.sh', recordedAt = new Date().toISOString()}) {
  if (!/^[0-9a-f]{40}$/.test(sourceRevision)) throw new Error('sourceRevision must be an exact commit');
  if (!Array.isArray(suites) || suites.length === 0) throw new Error('at least one observed suite is required');
  if (typeof command !== 'string' || command.length === 0) throw new Error('command must be a non-empty string');
  if (typeof recordedAt !== 'string' || !Number.isFinite(Date.parse(recordedAt))) throw new Error('recordedAt must be an ISO timestamp');
  const result = {
    schemaVersion: OFFLINE_RESULT_SCHEMA,
    sourceRevision,
    status: 'passed',
    recordedAt,
    command,
    suites: suites.map(suite),
  };
  const names = result.suites.map(item => item.name);
  if (new Set(names).size !== names.length) throw new Error('suite names must be unique');
  return result;
}

function main(argv) {
  const output = argv.find(arg => arg.startsWith('--output='))?.slice('--output='.length);
  const sourceRevision = argv.find(arg => arg.startsWith('--source-revision='))?.slice('--source-revision='.length);
  const suites = argv.filter(arg => arg.startsWith('--suite=')).map(arg => arg.slice('--suite='.length));
  if (!output || !sourceRevision || suites.length === 0 || argv.some(arg => !arg.startsWith('--output=') && !arg.startsWith('--source-revision=') && !arg.startsWith('--suite='))) {
    console.error('usage: offline-result.mjs --output=PATH --source-revision=COMMIT --suite=NAME:TESTS:PASSED:FAILED [...]');
    return 2;
  }
  writeFileSync(output, `${JSON.stringify(buildOfflineResult({sourceRevision, suites}), null, 2)}\n`);
  JSON.parse(readFileSync(output, 'utf8'));
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
