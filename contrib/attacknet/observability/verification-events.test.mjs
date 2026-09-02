import assert from 'node:assert/strict';
import test from 'node:test';

import {verificationObservations} from './verification-events.mjs';

function cohort(overrides = {}) {
  return {
    ok: true, ceiling: 2, minimumStacksHeight: 1, minimumObservedStacksHeight: 20,
    burnDrift: 1, stacksDrift: 2, forkedHeights: [],
    peerConnectivity: {ok: true, minimumAuthenticatedConnections: 3},
    ...overrides,
  };
}

test('snapshot results become bounded independently useful invariant observations', () => {
  const observations = verificationObservations(cohort({stacksDrift: 3, ok: false}), 'baseline');
  assert.equal(observations.find(item => item.name === 'baseline.stacks-height-drift').passed, false);
  assert.equal(observations.find(item => item.name === 'baseline.stacks-height-drift').value, 3);
  assert.equal(observations.find(item => item.name === 'baseline.authenticated-peer-connectivity').value, 3);
  assert.ok(observations.every(item => !('rows' in item)));
});

test('progress results expose burn and Stacks progress separately', () => {
  const observations = verificationObservations({
    ok: false,
    startCohort: cohort(),
    cohort: cohort(),
    progress: {
      burn: {startHeight: 10, endHeight: 12, delta: 2, minimumBlocks: 1},
      stacks: {startHeight: 5, endHeight: 5, delta: 0, minimumBlocks: 1},
    },
  }, 'post-chaos');
  assert.equal(observations.find(item => item.name === 'post-chaos.burn-progress').passed, true);
  assert.equal(observations.find(item => item.name === 'post-chaos.stacks-progress').passed, false);
  assert.equal(observations.find(item => item.name === 'post-chaos.overall').passed, false);
});

test('a maximum Kubernetes campaign name fits within derived invariant labels', () => {
  const scope = `campaign-${'c'.repeat(63)}-baseline`;
  const observations = verificationObservations(cohort(), scope);
  assert.ok(observations.every(item => item.name.length <= 128));
});
