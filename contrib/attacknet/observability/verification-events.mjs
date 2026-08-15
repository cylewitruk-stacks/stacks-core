#!/usr/bin/env node

import {readFileSync} from 'node:fs';

function finite(value, field) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`${field} must be finite`);
  return number;
}

function observation(name, passed, value, context = {}) {
  return {name, passed: passed === true, value: finite(value, `${name}.value`), ...context};
}

function cohortObservations(cohort, scope) {
  if (!cohort || typeof cohort !== 'object') throw new Error(`${scope} cohort result is required`);
  const peer = cohort.peerConnectivity ?? {ok: false, minimumAuthenticatedConnections: 0};
  const forkCount = Array.isArray(cohort.forkedHeights) ? cohort.forkedHeights.length : 0;
  return [
    observation(`${scope}.cohort`, cohort.ok, Math.max(finite(cohort.burnDrift, 'burnDrift'), finite(cohort.stacksDrift, 'stacksDrift')), {ceiling: cohort.ceiling}),
    observation(`${scope}.burn-height-drift`, cohort.burnDrift <= cohort.ceiling, cohort.burnDrift, {ceiling: cohort.ceiling}),
    observation(`${scope}.stacks-height-drift`, cohort.stacksDrift <= cohort.ceiling, cohort.stacksDrift, {ceiling: cohort.ceiling}),
    observation(`${scope}.minimum-stacks-height`, cohort.minimumObservedStacksHeight >= cohort.minimumStacksHeight, cohort.minimumObservedStacksHeight, {minimum: cohort.minimumStacksHeight}),
    observation(`${scope}.canonical-tip-agreement`, forkCount === 0, forkCount),
    observation(`${scope}.authenticated-peer-connectivity`, peer.ok, peer.minimumAuthenticatedConnections),
  ];
}

export function verificationObservations(result, scope = 'verification') {
  if (!result || typeof result !== 'object') throw new Error('verification result must be an object');
  // The longest derived suffix is 32 characters, leaving all emitted
  // invariant names within the bridge's 128-character label bound.
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,94}$/.test(scope)) throw new Error('scope must be a bounded label');
  if (!result.progress) return cohortObservations(result, scope);
  const observations = [
    ...cohortObservations(result.startCohort, `${scope}.start`),
    ...cohortObservations(result.cohort, `${scope}.end`),
  ];
  for (const dimension of ['burn', 'stacks']) {
    const progress = result.progress[dimension];
    observations.push(observation(
      `${scope}.${dimension}-progress`,
      progress.delta >= progress.minimumBlocks,
      progress.delta,
      {minimumBlocks: progress.minimumBlocks, startHeight: progress.startHeight, endHeight: progress.endHeight},
    ));
  }
  observations.push(observation(`${scope}.overall`, result.ok, result.ok ? 1 : 0));
  return observations;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [input, scope = 'verification'] = process.argv.slice(2);
  if (!input) throw new Error('usage: verification-events.mjs RESULT_JSON [SCOPE]');
  for (const item of verificationObservations(JSON.parse(readFileSync(input, 'utf8')), scope)) {
    process.stdout.write(`${JSON.stringify(item)}\n`);
  }
}
