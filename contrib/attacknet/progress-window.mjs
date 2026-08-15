#!/usr/bin/env node

import {readFileSync, realpathSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

function positiveInteger(value, path, maximum = 7200) {
  const number = typeof value === 'string' && /^[0-9]+$/.test(value) ? Number(value) : value;
  if (!Number.isInteger(number) || number < 1 || number > maximum) {
    throw new Error(`${path} must be an integer from 1 through ${maximum}`);
  }
  return number;
}

export function resolveProgressWindow(manifest, override = null) {
  if (override !== null && override !== undefined && override !== '') {
    return positiveInteger(override, 'ATTACKNET_PROGRESS_WINDOW_SECONDS');
  }
  const cadence = positiveInteger(
    manifest?.protocol?.steadyBurnIntervalSeconds,
    'manifest.protocol.steadyBurnIntervalSeconds',
    3600,
  );
  // A window equal to the cadence can still begin immediately after a tick
  // and lose to scheduler/polling jitter. Keep a bounded 25% margin with a
  // 15-second floor so at least one burn interval is observable by default.
  return cadence + Math.max(15, Math.ceil(cadence / 4));
}

function main() {
  const [manifestPath, override = null] = process.argv.slice(2);
  if (!manifestPath) throw new Error('usage: progress-window.mjs MANIFEST [OVERRIDE_SECONDS]');
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), 'utf8'));
  process.stdout.write(`${resolveProgressWindow(manifest, override)}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`progress-window: ${error.message}`);
    process.exitCode = 1;
  }
}
