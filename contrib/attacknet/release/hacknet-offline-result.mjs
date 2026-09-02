#!/usr/bin/env node

import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export const HACKNET_OFFLINE_RESULT_SCHEMA = 'stacks-hacknet-offline-check-result/v1';

/** Validate the result emitted only after the Hacknet check script completes. */
export function validateHacknetOfflineResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('Hacknet offline result must be an object');
  }
  if (result.schemaVersion !== HACKNET_OFFLINE_RESULT_SCHEMA) {
    throw new Error('Hacknet offline result uses an unsupported schema');
  }
  if (!/^[0-9a-f]{40}$/.test(result.sourceRevision)) {
    throw new Error('Hacknet offline result requires an exact source revision');
  }
  if (result.status !== 'passed') throw new Error('Hacknet offline result is not passed');
  if (!Array.isArray(result.requiredChecks) || result.requiredChecks.length === 0
    || result.requiredChecks.some(check => typeof check !== 'string' || check.length === 0)
    || new Set(result.requiredChecks).size !== result.requiredChecks.length) {
    throw new Error('Hacknet offline result requires unique completed checks');
  }
  const optional = Array.isArray(result.optionalChecks) ? result.optionalChecks : [];
  for (const [index, check] of optional.entries()) {
    if (!check || typeof check !== 'object' || Array.isArray(check)
      || typeof check.name !== 'string' || check.name.length === 0
      || !['passed', 'skipped-unavailable'].includes(check.status)
      || (check.status === 'skipped-unavailable'
        && (typeof check.reason !== 'string' || check.reason.length === 0))) {
      throw new Error(`Hacknet optional check ${index} is incomplete`);
    }
  }
  if (new Set(optional.map(check => check.name)).size !== optional.length) {
    throw new Error('Hacknet offline result contains duplicate optional checks');
  }
  return result;
}

function main(args) {
  const value = prefix => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const output = value('--output=');
  const sourceRevision = value('--source-revision=');
  const requiredChecks = value('--required=')?.split(',').filter(Boolean) ?? [];
  const optionalChecks = args.filter(arg => arg.startsWith('--optional='))
    .map(arg => {
      const [name, status, ...reason] = arg.slice('--optional='.length).split(':');
      return {name, status, ...(reason.length ? {reason: reason.join(':')} : {})};
    });
  if (!output || args.some(arg => ![
    '--output=', '--source-revision=', '--required=', '--optional=',
  ].some(prefix => arg.startsWith(prefix)))) {
    throw new Error('usage: hacknet-offline-result.mjs --output=PATH --source-revision=SHA --required=CHECK,... [--optional=NAME:STATUS:REASON]');
  }
  const result = validateHacknetOfflineResult({
    schemaVersion: HACKNET_OFFLINE_RESULT_SCHEMA,
    sourceRevision,
    status: 'passed',
    requiredChecks,
    optionalChecks,
  });
  writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
}
