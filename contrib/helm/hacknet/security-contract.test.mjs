import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const topologyRbac = readFileSync(join(root, 'templates', 'rbac.yaml'), 'utf8');
const runRbac = readFileSync(join(root, 'templates', 'run-rbac.yaml'), 'utf8');
const runController = readFileSync(join(root, 'operator', 'internal', 'run', 'reconciler.go'), 'utf8');
const faultController = readFileSync(join(root, 'operator', 'internal', 'fault', 'reconciler.go'), 'utf8');
const ownership = readFileSync(join(root, 'operator', 'internal', 'ownership', 'ownership.go'), 'utf8');

test('topology operator owns workloads but has no Chaos Mesh authority', () => {
  assert.match(topologyRbac, /resources: \["statefulsets"\]/);
  assert.match(topologyRbac, /resources: \["configmaps", "services"\]/);
  assert.doesNotMatch(topologyRbac, /chaos-mesh\.org|faultcampaigns|attacknetruns/);
  assert.doesNotMatch(topologyRbac, /"update"/);
});

test('run operator can observe but cannot declare topology workloads', () => {
  assert.match(runRbac, /resources: \["stacksnetworks"\]\s+verbs: \["get", "list", "watch"\]/);
  for (const resource of ['statefulsets', 'services', 'persistentvolumeclaims']) {
    assert.doesNotMatch(runRbac, new RegExp(`resources: \\[.*"${resource}"`));
  }
  assert.match(runRbac, /resources: \["podchaos", "networkchaos", "dnschaos", "iochaos", "timechaos"\]/);
  assert.match(runRbac, /resources: \["configmaps"\]\s+verbs: \["get", "list", "watch", "create", "patch", "delete"\]/);
  assert.match(runRbac, /resources: \["attacknetruns"\]\s+verbs: \["get", "list", "watch"\]/);
  assert.doesNotMatch(runRbac, /"update"/);
});

test('run operator owner references are limited to run-domain resources', () => {
  assert.match(ownership, /metav1\.NewControllerRef\(owner, gvk\)/);
  assert.match(runController, /ownership\.Reference\(run, attacknetv1alpha1\.GroupVersion\.WithKind\("AttacknetRun"\)\)/);
  assert.match(faultController, /ownership\.Reference\(campaign, attacknetv1alpha1\.GroupVersion\.WithKind\("FaultCampaign"\)\)/);
  assert.doesNotMatch(`${runController}\n${faultController}`, /ownership\.Reference\(network/);
});
