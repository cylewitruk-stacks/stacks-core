import assert from 'node:assert/strict';
import test from 'node:test';

import {REQUIRED_COMMAND_CHECKS} from './release-1-a2-evidence.mjs';
import {A2_OFFLINE_CHECK_IDS} from './release-1-a2-verify.mjs';

test('A2 offline producer and evidence validator require the same command checks', () => {
  assert.deepEqual(A2_OFFLINE_CHECK_IDS, REQUIRED_COMMAND_CHECKS);
});
