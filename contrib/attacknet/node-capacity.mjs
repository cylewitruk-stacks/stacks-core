#!/usr/bin/env node

import {readFileSync} from 'node:fs';

export function evaluateNodeCapacity(summaries, minimumAvailableBytes) {
  if (!Number.isSafeInteger(minimumAvailableBytes) || minimumAvailableBytes < 0) {
    throw new Error(`invalid minimumAvailableBytes: ${minimumAvailableBytes}`);
  }
  const nodes = summaries.map(summary => {
    const name = summary?.node?.nodeName;
    const availableBytes = Number(summary?.node?.fs?.availableBytes);
    const capacityBytes = Number(summary?.node?.fs?.capacityBytes);
    if (!name || !Number.isFinite(availableBytes) || !Number.isFinite(capacityBytes)) {
      throw new Error('kubelet summary lacks node.nodeName or node.fs capacity fields');
    }
    return {
      name,
      availableBytes,
      capacityBytes,
      availablePercent: capacityBytes === 0 ? 0 : availableBytes * 100 / capacityBytes,
      ok: availableBytes >= minimumAvailableBytes,
    };
  });
  return {ok: nodes.length > 0 && nodes.every(node => node.ok), minimumAvailableBytes, nodes};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [minimumRaw, ...paths] = process.argv.slice(2);
  if (!minimumRaw || paths.length === 0) {
    throw new Error('usage: node-capacity.mjs MINIMUM_AVAILABLE_BYTES SUMMARY.json ...');
  }
  const result = evaluateNodeCapacity(
    paths.map(path => JSON.parse(readFileSync(path, 'utf8'))),
    Number(minimumRaw),
  );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
