#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'node:fs';

export const SOAK_SCHEMA = 'stacks-attacknet-soak/v1';

function integer(value, name, minimum = 0) {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < minimum) {
    throw new Error(`${name} must be an integer >= ${minimum}`);
  }
  return result;
}

function iso(value, name) {
  const result = new Date(value);
  if (!value || Number.isNaN(result.getTime())) throw new Error(`${name} must be an ISO timestamp`);
  return result.toISOString();
}

function validatePausedCohort(cohort, bitcoinHeight, name) {
  if (!cohort || cohort.ok !== true || !Array.isArray(cohort.rows) || cohort.rows.length === 0) {
    throw new Error(`${name} must be a passing non-empty network cohort`);
  }
  if (cohort.burnDrift !== 0 || cohort.stacksDrift !== 0 || (cohort.forkedHeights?.length ?? 0) !== 0) {
    throw new Error(`${name} must have exact burn/Stacks agreement while cadence is paused`);
  }
  for (const row of cohort.rows) {
    if (integer(row.burnHeight, `${name}.${row.actor}.burnHeight`) !== bitcoinHeight) {
      throw new Error(`${name}.${row.actor} burn height does not equal Bitcoin height ${bitcoinHeight}`);
    }
  }
}

export function createSoakContract({
  network,
  startedAt,
  minimumNewBurnBlocks,
  bitcoinHeight,
  cohort,
  faultRunName = null,
}) {
  if (typeof network !== 'string' || network.length === 0) throw new Error('network is required');
  const startHeight = integer(bitcoinHeight, 'bitcoinHeight');
  const minimumBlocks = integer(minimumNewBurnBlocks, 'minimumNewBurnBlocks', 1);
  validatePausedCohort(cohort, startHeight, 'startCohort');
  if (faultRunName !== null && (typeof faultRunName !== 'string' || faultRunName.length === 0)) {
    throw new Error('faultRunName must be null or a non-empty string');
  }
  return {
    schemaVersion: SOAK_SCHEMA,
    status: 'running',
    network,
    startedAt: iso(startedAt, 'startedAt'),
    minimumNewBurnBlocks: minimumBlocks,
    startHeight,
    targetHeight: startHeight + minimumBlocks,
    firstSampleHeight: startHeight,
    startCohort: cohort,
    faultRunName,
  };
}

export function completeSoakContract(contract, {
  completedAt,
  bitcoinHeight,
  cohort,
  sampleCount,
  faultRunPhase = null,
}) {
  if (contract?.schemaVersion !== SOAK_SCHEMA || contract.status !== 'running') {
    throw new Error('contract must be a running stacks-attacknet-soak/v1 document');
  }
  const endHeight = integer(bitcoinHeight, 'bitcoinHeight');
  validatePausedCohort(cohort, endHeight, 'endCohort');
  const observedBlocks = endHeight - integer(contract.startHeight, 'contract.startHeight');
  if (observedBlocks < integer(contract.minimumNewBurnBlocks, 'contract.minimumNewBurnBlocks', 1)) {
    throw new Error(`only ${observedBlocks} new burn blocks were observed; ${contract.minimumNewBurnBlocks} required`);
  }
  if (endHeight < integer(contract.targetHeight, 'contract.targetHeight')) {
    throw new Error(`end height ${endHeight} did not reach target ${contract.targetHeight}`);
  }
  if (contract.firstSampleHeight !== contract.startHeight) {
    throw new Error('first sample is not bound to the measured start height');
  }
  if (contract.faultRunName && faultRunPhase !== 'Passed') {
    throw new Error(`fault run ${contract.faultRunName} finished as ${faultRunPhase ?? '<missing>'}`);
  }
  return {
    ...contract,
    status: 'passed',
    completedAt: iso(completedAt, 'completedAt'),
    endHeight,
    observedNewBurnBlocks: observedBlocks,
    sampleCount: integer(sampleCount, 'sampleCount', 2),
    endCohort: cohort,
    faultRunPhase,
  };
}

function read(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function option(name, fallback = null) {
  const prefix = `--${name}=`;
  const argument = process.argv.find(value => value.startsWith(prefix));
  return argument ? argument.slice(prefix.length) : fallback;
}

function required(name) {
  const value = option(name);
  if (value === null) throw new Error(`--${name} is required`);
  return value;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];
  let result;
  if (command === 'start') {
    result = createSoakContract({
      network: required('network'),
      startedAt: required('started-at'),
      minimumNewBurnBlocks: required('minimum-blocks'),
      bitcoinHeight: required('bitcoin-height'),
      cohort: read(required('cohort')),
      faultRunName: option('fault-run'),
    });
  } else if (command === 'finish') {
    result = completeSoakContract(read(required('contract')), {
      completedAt: required('completed-at'),
      bitcoinHeight: required('bitcoin-height'),
      cohort: read(required('cohort')),
      sampleCount: required('sample-count'),
      faultRunPhase: option('fault-run-phase'),
    });
  } else {
    throw new Error('usage: soak-evidence.mjs {start|finish} --...');
  }
  const encoded = `${JSON.stringify(result, null, 2)}\n`;
  const output = option('output');
  if (output) writeFileSync(output, encoded);
  else process.stdout.write(encoded);
}
