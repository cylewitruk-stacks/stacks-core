import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
function packageSource(name) {
  const directory = join(root, 'operator', 'internal', name);
  return readdirSync(directory)
    .filter(file => file.endsWith('.go') && !file.endsWith('_test.go'))
    .sort()
    .map(file => readFileSync(join(directory, file), 'utf8'))
    .join('\n');
}

const runController = packageSource('run');
const faultController = packageSource('fault');
const ownership = readFileSync(join(root, 'operator', 'internal', 'ownership', 'ownership.go'), 'utf8');

test('run operator owner references are limited to run-domain resources', () => {
  assert.match(ownership, /metav1\.NewControllerRef\(owner, gvk\)/);
  assert.match(runController, /ownership\.Reference\(run, attacknetv1alpha1\.GroupVersion\.WithKind\("AttacknetRun"\)\)/);
  assert.match(faultController, /ownership\.Reference\(campaign, attacknetv1alpha1\.GroupVersion\.WithKind\("FaultCampaign"\)\)/);
  assert.doesNotMatch(`${runController}\n${faultController}`, /ownership\.Reference\(network/);
});
