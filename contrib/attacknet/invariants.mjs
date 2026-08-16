#!/usr/bin/env node

import {readFileSync} from 'node:fs';

function numeric(value, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`invalid ${name}: ${value}`);
  return number;
}

export function heightCohort(samples, ceiling = 2, minimumStacksHeight = 0) {
  if (samples.length === 0) throw new Error('height cohort has no node samples');
  const rows = samples.map(sample => ({
    actor: sample.actor,
    burnHeight: numeric(sample.info.burn_block_height, `${sample.actor}.burn_block_height`),
    stacksHeight: numeric(sample.info.stacks_tip_height, `${sample.actor}.stacks_tip_height`),
    stacksTip: sample.info.stacks_tip,
  }));
  const burnHeights = rows.map(row => row.burnHeight);
  const stacksHeights = rows.map(row => row.stacksHeight);
  const burnDrift = Math.max(...burnHeights) - Math.min(...burnHeights);
  const stacksDrift = Math.max(...stacksHeights) - Math.min(...stacksHeights);
  const minimumObservedStacksHeight = Math.min(...stacksHeights);
  const tipsByHeight = Object.fromEntries([...new Set(stacksHeights)].sort((a, b) => a - b).map(height => [
    height,
    [...new Set(rows.filter(row => row.stacksHeight === height).map(row => row.stacksTip))].sort(),
  ]));
  const forkedHeights = Object.entries(tipsByHeight)
    .filter(([, tips]) => tips.length > 1)
    .map(([height, tips]) => ({height: Number(height), tips}));
  return {
    ok: burnDrift <= ceiling && stacksDrift <= ceiling
      && minimumObservedStacksHeight >= minimumStacksHeight && forkedHeights.length === 0,
    ceiling,
    minimumStacksHeight,
    minimumObservedStacksHeight,
    burnDrift,
    stacksDrift,
    tipsByHeight,
    forkedHeights,
    rows,
  };
}

export function peerConnectivity(samples) {
  if (samples.length === 0) throw new Error('peer cohort has no node samples');
  const rows = samples.map(sample => {
    if (!sample.neighbors || typeof sample.neighbors !== 'object') {
      throw new Error(`missing ${sample.actor}.neighbors`);
    }
    const inbound = Array.isArray(sample.neighbors.inbound) ? sample.neighbors.inbound : [];
    const outbound = Array.isArray(sample.neighbors.outbound) ? sample.neighbors.outbound : [];
    const live = [...inbound, ...outbound];
    return {
      actor: sample.actor,
      inbound: inbound.length,
      outbound: outbound.length,
      authenticated: live.filter(peer => peer.authenticated === true).length,
      unauthenticated: live.filter(peer => peer.authenticated !== true).length,
      // bootstrap/sample rows are configured or known candidates. The current
      // API hardcodes authenticated=true for them, so they are not live proof.
      configuredCandidates: (Array.isArray(sample.neighbors.bootstrap) ? sample.neighbors.bootstrap.length : 0)
        + (Array.isArray(sample.neighbors.sample) ? sample.neighbors.sample.length : 0),
    };
  });
  return {
    // An unauthenticated conversation is also the normal, transient state of
    // an inbound handshake.  Treating its mere presence as a baseline failure
    // makes a real adversarial network impossible to test: any unauthenticated
    // scanner could fail every run.  Preserve the count for rate/age anomaly
    // analysis, while requiring positive authenticated connectivity here.
    ok: rows.every(row => row.authenticated > 0),
    minimumAuthenticatedConnections: Math.min(...rows.map(row => row.authenticated)),
    maximumUnauthenticatedConnections: Math.max(...rows.map(row => row.unauthenticated)),
    rows,
  };
}

export function networkCohort(samples, ceiling = 2, minimumStacksHeight = 0) {
  const height = heightCohort(samples, ceiling, minimumStacksHeight);
  const peers = peerConnectivity(samples);
  return {...height, ok: height.ok && peers.ok, peerConnectivity: peers};
}

function minimumCohortStacksHeight(samples, name) {
  if (!Array.isArray(samples) || samples.length === 0) {
    throw new Error(`${name} has no node samples`);
  }
  return Math.min(...samples.map(sample => numeric(
    sample.info?.stacks_tip_height,
    `${name}.${sample.actor}.stacks_tip_height`,
  )));
}

export function progress(start, end, minimumBurnBlocks = 1, minimumStacksBlocks = 1) {
  const startHeight = numeric(start.burnHeight, 'start.burnHeight');
  const endHeight = numeric(end.burnHeight, 'end.burnHeight');
  const burnDelta = endHeight - startHeight;
  const startStacksHeight = minimumCohortStacksHeight(start.cohort, 'start.cohort');
  const endStacksHeight = minimumCohortStacksHeight(end.cohort, 'end.cohort');
  const stacksDelta = endStacksHeight - startStacksHeight;
  return {
    ok: burnDelta >= minimumBurnBlocks && stacksDelta >= minimumStacksBlocks,
    burn: {startHeight, endHeight, delta: burnDelta, minimumBlocks: minimumBurnBlocks},
    stacks: {
      startHeight: startStacksHeight,
      endHeight: endStacksHeight,
      delta: stacksDelta,
      minimumBlocks: minimumStacksBlocks,
    },
  };
}

export function telemetryCoverage(apiResponse, manifest, observedAtSeconds, maximumAgeSeconds = 15) {
  if (apiResponse?.status !== 'success' || apiResponse?.data?.resultType !== 'vector'
      || !Array.isArray(apiResponse?.data?.result)) {
    throw new Error('invalid Prometheus instant-vector response');
  }
  const observedAt = Number(observedAtSeconds);
  const maximumAge = Number(maximumAgeSeconds);
  if (!Number.isFinite(observedAt) || !Number.isFinite(maximumAge) || maximumAge < 0) {
    throw new Error('invalid telemetry observation time or age ceiling');
  }
  const expected = new Map((manifest.actors ?? []).map(actor => [actor.service, actor.role]));
  if (expected.size === 0) throw new Error('manifest has no enrolled actors');
  const byActor = new Map();
  for (const sample of apiResponse.data.result) {
    const actor = sample?.metric?.attacknet_actor;
    if (typeof actor !== 'string' || actor.length === 0) continue;
    const rows = byActor.get(actor) ?? [];
    rows.push(sample);
    byActor.set(actor, rows);
  }
  const rows = [...expected.entries()].map(([actor, role]) => {
    const samples = byActor.get(actor) ?? [];
    const sample = samples[0];
    const timestamp = Number(sample?.value?.[0]);
    const value = Number(sample?.value?.[1]);
    const sampleAgeSeconds = Number.isFinite(timestamp) ? Math.max(0, observedAt - timestamp) : null;
    const observedRole = sample?.metric?.attacknet_role ?? null;
    const reasons = [];
    if (samples.length === 0) reasons.push('missing-series');
    if (samples.length > 1) reasons.push('duplicate-series');
    if (samples.length === 1 && observedRole !== role) reasons.push('role-mismatch');
    if (samples.length === 1 && value !== 1) reasons.push('scrape-down');
    if (samples.length === 1 && (!Number.isFinite(sampleAgeSeconds) || sampleAgeSeconds > maximumAge)) {
      reasons.push('stale-sample');
    }
    return {actor, role, observedRole, value: Number.isFinite(value) ? value : null,
      sampleTimestamp: Number.isFinite(timestamp) ? timestamp : null, sampleAgeSeconds, reasons};
  });
  const unexpectedActors = [...byActor.keys()].filter(actor => !expected.has(actor)).sort();
  return {
    ok: rows.every(row => row.reasons.length === 0) && unexpectedActors.length === 0,
    expectedActors: expected.size,
    observedUniqueActors: byActor.size,
    observedAt,
    maximumAgeSeconds: maximumAge,
    unexpectedActors,
    rows,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, inputPath, rawValue, rawMinimum, manifestPath] = process.argv.slice(2);
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  let result;
  if (command === 'cohort') result = networkCohort(input, Number(rawValue ?? 2), Number(rawMinimum ?? 0));
  else if (command === 'peers') result = peerConnectivity(input);
  else if (command === 'progress') {
    result = progress(input.start, input.end, Number(rawValue ?? 1), Number(rawMinimum ?? 1));
  }
  else if (command === 'telemetry') {
    if (!manifestPath) throw new Error('telemetry invariant requires a manifest path');
    result = telemetryCoverage(input, JSON.parse(readFileSync(manifestPath, 'utf8')),
      Number(rawValue), Number(rawMinimum ?? 15));
  }
  else throw new Error('usage: invariants.mjs {cohort|peers|progress|telemetry} INPUT [LIMIT]');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
