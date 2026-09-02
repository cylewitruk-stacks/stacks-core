import assert from 'node:assert/strict';
import test from 'node:test';

import {evaluateNodeCapacity} from './node-capacity.mjs';

const summary = (name, availableBytes, capacityBytes = 100, imageAvailableBytes = availableBytes) => ({
  node: {
    nodeName: name,
    fs: {availableBytes, capacityBytes},
    runtime: {imageFs: {availableBytes: imageAvailableBytes, capacityBytes}},
  },
});

test('capacity requires every node filesystem to clear the floor', () => {
  const result = evaluateNodeCapacity([summary('a', 20), summary('b', 9)], 10);
  assert.equal(result.ok, false);
  assert.deepEqual(result.nodes.map(node => node.ok), [true, false]);
});

test('capacity also fails when only the container image filesystem is exhausted', () => {
  const result = evaluateNodeCapacity([summary('a', 20, 100, 9)], 10);
  assert.equal(result.ok, false);
  assert.equal(result.nodes[0].rootFilesystem.availableBytes, 20);
  assert.equal(result.nodes[0].imageFilesystem.availableBytes, 9);
});

test('capacity rejects malformed kubelet summaries', () => {
  assert.throws(() => evaluateNodeCapacity([{node: {nodeName: 'a'}}], 10), /lacks/);
});
