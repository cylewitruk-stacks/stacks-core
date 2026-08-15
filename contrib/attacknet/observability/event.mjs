#!/usr/bin/env node

import {createHash} from 'node:crypto';

function option(args, name, fallback) {
  const prefix = `--${name}=`;
  return args.find(argument => argument.startsWith(prefix))?.slice(prefix.length) ?? fallback;
}

function required(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function boundedEventId(value) {
  if (value === undefined || value === '') return undefined;
  if (value.length <= 128) return value;
  const digest = createHash('sha256').update(value).digest('hex').slice(0, 24);
  return `${value.slice(0, 103)}-${digest}`;
}

export function buildEvent(values, now = () => new Date().toISOString()) {
  const normalized = {...values, eventId: boundedEventId(values.eventId)};
  const event = {
    kind: required(normalized.kind, 'kind'),
    network: required(normalized.network, 'network'),
    runId: required(normalized.runId, 'runId'),
    phase: normalized.phase ?? 'baseline',
    occurredAt: normalized.occurredAt ?? now(),
    details: normalized.details ?? {},
  };
  for (const field of ['eventId', 'instructionId', 'campaign', 'actor', 'role', 'faultType', 'outcome']) {
    if (normalized[field] !== undefined && normalized[field] !== '') event[field] = normalized[field];
  }
  return event;
}

export function runCli(args) {
  const detailsText = option(args, 'details', '{}');
  let details;
  try {
    details = JSON.parse(detailsText);
  } catch (error) {
    throw new Error(`details must be JSON: ${error.message}`);
  }
  if (!details || Array.isArray(details) || typeof details !== 'object') {
    throw new Error('details must be a JSON object');
  }
  return buildEvent({
    kind: option(args, 'kind'),
    network: option(args, 'network'),
    runId: option(args, 'run-id'),
    phase: option(args, 'phase', 'baseline'),
    occurredAt: option(args, 'occurred-at'),
    eventId: option(args, 'event-id'),
    instructionId: option(args, 'instruction-id'),
    campaign: option(args, 'campaign'),
    actor: option(args, 'actor'),
    role: option(args, 'role'),
    faultType: option(args, 'fault-type'),
    outcome: option(args, 'outcome'),
    details,
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.stdout.write(`${JSON.stringify(runCli(process.argv.slice(2)))}\n`);
  } catch (error) {
    process.stderr.write(`attacknet event: ${error.message}\n`);
    process.exitCode = 2;
  }
}
