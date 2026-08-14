#!/usr/bin/env node

import {readFileSync} from 'node:fs';

export function inventory(manifest, group) {
  const actors = manifest.actors ?? [];
  switch (group) {
    case 'actors':
      return actors.map(actor => actor.service);
    case 'nodes':
      return actors.filter(actor => actor.type === 'node').map(actor => actor.service);
    case 'signers':
      return actors.filter(actor => actor.type === 'signer').map(actor => actor.service);
    case 'companions':
      return actors.filter(actor => actor.role === 'companion').map(actor => actor.service);
    case 'miners':
      return actors.filter(actor => actor.role === 'miner').map(actor => actor.service);
    case 'followers':
      return actors.filter(actor => actor.role === 'follower').map(actor => actor.service);
    default:
      throw new Error(`unknown inventory group: ${group}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [manifestPath, group] = process.argv.slice(2);
  if (!manifestPath || !group) {
    console.error('usage: manifest-inventory.mjs MANIFEST GROUP');
    process.exit(2);
  }
  const values = inventory(JSON.parse(readFileSync(manifestPath, 'utf8')), group);
  process.stdout.write(values.join(' '));
}
