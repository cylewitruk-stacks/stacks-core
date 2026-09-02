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
    const imageAvailableBytes = Number(summary?.node?.runtime?.imageFs?.availableBytes);
    const imageCapacityBytes = Number(summary?.node?.runtime?.imageFs?.capacityBytes);
    if (!name || !Number.isFinite(availableBytes) || !Number.isFinite(capacityBytes)
      || !Number.isFinite(imageAvailableBytes) || !Number.isFinite(imageCapacityBytes)) {
      throw new Error('kubelet summary lacks node name, root filesystem, or image filesystem capacity fields');
    }
    return {
      name,
      // Preserve the original top-level fields for existing capacity evidence
      // readers while making the independently-exhaustible image filesystem
      // explicit.
      availableBytes,
      capacityBytes,
      availablePercent: capacityBytes === 0 ? 0 : availableBytes * 100 / capacityBytes,
      rootFilesystem: {
        availableBytes,
        capacityBytes,
        availablePercent: capacityBytes === 0 ? 0 : availableBytes * 100 / capacityBytes,
      },
      imageFilesystem: {
        availableBytes: imageAvailableBytes,
        capacityBytes: imageCapacityBytes,
        availablePercent: imageCapacityBytes === 0 ? 0 : imageAvailableBytes * 100 / imageCapacityBytes,
      },
      ok: availableBytes >= minimumAvailableBytes && imageAvailableBytes >= minimumAvailableBytes,
    };
  });
  return {ok: nodes.length > 0 && nodes.every(node => node.ok), minimumAvailableBytes, nodes};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [minimumRaw, ...paths] = process.argv.slice(2);
  if (!minimumRaw || paths.length === 0) {
    throw new Error('usage: node-capacity.mjs MINIMUM_AVAILABLE_BYTES SUMMARY.json ...');
  }
  try {
    const result = evaluateNodeCapacity(
      paths.map(path => JSON.parse(readFileSync(path, 'utf8'))),
      Number(minimumRaw),
    );
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ok: false, error: error.message}, null, 2)}\n`);
    process.exitCode = 1;
  }
}
