#!/usr/bin/env node

function option(args, name, fallback) {
  const prefix = `--${name}=`;
  return args.find(argument => argument.startsWith(prefix))?.slice(prefix.length) ?? fallback;
}

function required(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

export function buildEvent(values, now = () => new Date().toISOString()) {
  const event = {
    kind: required(values.kind, 'kind'),
    network: required(values.network, 'network'),
    runId: required(values.runId, 'runId'),
    phase: values.phase ?? 'baseline',
    occurredAt: values.occurredAt ?? now(),
    details: values.details ?? {},
  };
  for (const field of ['eventId', 'instructionId', 'campaign', 'actor', 'role', 'faultType', 'outcome']) {
    if (values[field] !== undefined && values[field] !== '') event[field] = values[field];
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
