import assert from 'node:assert/strict';
import test from 'node:test';

import {resolveCampaignTargets} from './campaign-targets.mjs';

const manifest = {network: 'attacknet', namespace: 'hacknet-system'};
const evidence = {selectedActors: ['signer-node-1']};
const pod = ({network = 'attacknet', uid = 'pod-1', ready = true, deleting = false} = {}) => ({
  metadata: {
    name: 'attacknet-signer-node-1-0', uid,
    deletionTimestamp: deleting ? '2026-01-01T00:00:00Z' : undefined,
    labels: {
      'testing.stacks.org/network': network,
      'testing.stacks.org/actor': 'signer-node-1',
      'testing.stacks.org/role': 'companion',
    },
  },
  spec: {nodeName: 'worker-1'},
  status: {
    phase: 'Running',
    conditions: [{type: 'Ready', status: ready ? 'True' : 'False'}],
    containerStatuses: [{name: 'actor', ready, restartCount: 2, image: 'stacks:main', imageID: 'sha256:abc'}],
  },
});

test('resolves one ready admitted Pod and retains immutable runtime identity', () => {
  const result = resolveCampaignTargets(manifest, evidence, {items: [pod()]});
  assert.equal(result.targets[0].podUid, 'pod-1');
  assert.equal(result.targets[0].node, 'worker-1');
  assert.equal(result.targets[0].resolvedImageId, 'sha256:abc');
  assert.equal(result.targets[0].role, 'companion');
});

test('refuses missing, duplicate, terminating, foreign, or unready targets', () => {
  for (const items of [
    [],
    [pod(), pod({uid: 'pod-2'})],
    [pod({deleting: true})],
    [pod({network: 'other'})],
    [pod({ready: false})],
  ]) {
    assert.throws(() => resolveCampaignTargets(manifest, evidence, {items}), /resolves to|not admitted/);
  }
});
