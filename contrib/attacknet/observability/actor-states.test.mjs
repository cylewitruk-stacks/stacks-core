import assert from 'node:assert/strict';
import test from 'node:test';

import {actorStateEvents} from './actor-states.mjs';

test('Pod admission state becomes trusted actor observations with restart and image evidence', () => {
  const states = actorStateEvents({items: [{
    metadata: {name: 'net-miner-1-0', uid: 'uid-1', labels: {
      'testing.stacks.org/actor': 'miner-1', 'testing.stacks.org/role': 'miner',
    }},
    spec: {nodeName: 'worker-2', containers: [
      {name: 'actor', image: 'stacks-node:4.0.2'},
      {name: 'telemetry', image: 'collector:1'},
    ]},
    status: {
      phase: 'Running', conditions: [{type: 'Ready', status: 'True'}],
      containerStatuses: [
        {name: 'actor', ready: true, restartCount: 2, imageID: 'sha256:abc'},
        {name: 'telemetry', ready: true, restartCount: 1, imageID: 'sha256:def'},
      ],
    },
  }, {metadata: {name: 'observer', labels: {'app.kubernetes.io/name': 'attacknet-events'}}}]});
  assert.equal(states.length, 1);
  assert.equal(states[0].actor, 'miner-1');
  assert.equal(states[0].details.ready, true);
  assert.equal(states[0].details.restarts, 3);
  assert.equal(states[0].details.node, 'worker-2');
  assert.deepEqual(states[0].details.containers.map(container => container.imageId), ['sha256:abc', 'sha256:def']);
  assert.deepEqual(states[0].details.containers.map(container => container.requestedImage), ['stacks-node:4.0.2', 'collector:1']);
});
