#!/usr/bin/env node

import {readFileSync} from 'node:fs';

function numeric(value, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`invalid ${name}: ${value}`);
  return number;
}

export function heightCohort(samples, ceiling = 2) {
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
  return {ok: burnDrift <= ceiling && stacksDrift <= ceiling, ceiling, burnDrift, stacksDrift, rows};
}

export function progress(start, end, minimumBurnBlocks = 1) {
  const startHeight = numeric(start.burnHeight, 'start.burnHeight');
  const endHeight = numeric(end.burnHeight, 'end.burnHeight');
  const delta = endHeight - startHeight;
  return {ok: delta >= minimumBurnBlocks, startHeight, endHeight, delta, minimumBurnBlocks};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, inputPath, rawValue] = process.argv.slice(2);
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  let result;
  if (command === 'cohort') result = heightCohort(input, Number(rawValue ?? 2));
  else if (command === 'progress') result = progress(input.start, input.end, Number(rawValue ?? 1));
  else throw new Error('usage: invariants.mjs {cohort|progress} INPUT [LIMIT]');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
