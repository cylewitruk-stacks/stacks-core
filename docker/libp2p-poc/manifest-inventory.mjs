import fs from 'node:fs';
import {pathToFileURL} from 'node:url';

export function actorServiceInventory(manifest) {
  if (!Array.isArray(manifest?.actors)) {
    throw new Error('topology manifest actors must be an array');
  }

  const services = new Set();
  for (const actor of manifest.actors) {
    if (!actor || typeof actor.service !== 'string' || actor.service.length === 0) {
      throw new Error('every topology actor must have a non-empty service name');
    }
    if (services.has(actor.service)) {
      throw new Error(`duplicate topology actor service ${actor.service}`);
    }
    services.add(actor.service);
  }

  const matchingServices = predicate => manifest.actors
    .filter(predicate)
    .map(actor => actor.service);
  return {
    actors: matchingServices(() => true),
    nodes: matchingServices(actor => actor.type === 'node'),
    signers: matchingServices(actor => actor.type === 'signer'),
    companions: matchingServices(actor => actor.role === 'companion'),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    const inventory = actorServiceInventory(manifest);
    const selection = process.argv[3];
    if (!Object.hasOwn(inventory, selection)) {
      throw new Error(`unknown actor inventory ${selection}`);
    }
    console.log(inventory[selection].join('\n'));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
}
