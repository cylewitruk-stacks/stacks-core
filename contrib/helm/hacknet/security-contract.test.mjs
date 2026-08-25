import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const runController = readFileSync(join(root, 'operator', 'internal', 'run', 'reconciler.go'), 'utf8');
const faultController = readFileSync(join(root, 'operator', 'internal', 'fault', 'reconciler.go'), 'utf8');
const ownership = readFileSync(join(root, 'operator', 'internal', 'ownership', 'ownership.go'), 'utf8');

test('run operator owner references are limited to run-domain resources', () => {
  assert.match(ownership, /metav1\.NewControllerRef\(owner, gvk\)/);
  assert.match(runController, /ownership\.Reference\(run, attacknetv1alpha1\.GroupVersion\.WithKind\("AttacknetRun"\)\)/);
  assert.match(faultController, /ownership\.Reference\(campaign, attacknetv1alpha1\.GroupVersion\.WithKind\("FaultCampaign"\)\)/);
  assert.doesNotMatch(`${runController}\n${faultController}`, /ownership\.Reference\(network/);
});
