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

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, inputPath, rawValue, rawMinimum] = process.argv.slice(2);
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  let result;
  if (command === 'cohort') result = networkCohort(input, Number(rawValue ?? 2), Number(rawMinimum ?? 0));
  else if (command === 'progress') {
    result = progress(input.start, input.end, Number(rawValue ?? 1), Number(rawMinimum ?? 1));
  }
  else throw new Error('usage: invariants.mjs {cohort|progress} INPUT [LIMIT]');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
