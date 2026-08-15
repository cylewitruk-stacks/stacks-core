#!/usr/bin/env node

import {readFileSync, realpathSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const DNS_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

function requiredLabel(value, path) {
  if (typeof value !== 'string' || value.length > 63 || !DNS_LABEL.test(value)) {
    throw new Error(`${path} must be a Kubernetes DNS label`);
  }
  return value;
}

export function readManifestIdentity(directory) {
  const root = resolve(directory);
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  const network = JSON.parse(readFileSync(join(root, 'stacksnetwork.json'), 'utf8'));
  const identity = {
    network: requiredLabel(manifest.network, 'manifest.network'),
    namespace: requiredLabel(manifest.namespace, 'manifest.namespace'),
  };
  if (network?.metadata?.name !== identity.network) {
    throw new Error('manifest.network does not match StacksNetwork metadata.name');
  }
  if (network?.metadata?.namespace !== identity.namespace) {
    throw new Error('manifest.namespace does not match StacksNetwork metadata.namespace');
  }
  return identity;
}

function main() {
  if (process.argv.length !== 3) throw new Error('usage: manifest-identity.mjs GENERATED_DIR');
  process.stdout.write(`${JSON.stringify(readManifestIdentity(process.argv[2]))}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`manifest-identity: ${error.message}`);
    process.exitCode = 1;
  }
}

