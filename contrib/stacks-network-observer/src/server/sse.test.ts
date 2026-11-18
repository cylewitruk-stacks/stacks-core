import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import test from 'node:test';

import {LatestEventStream, type EventStreamWritable} from './sse.js';

class ControlledWritable extends EventEmitter implements EventStreamWritable {
  readonly messages: string[] = [];
  destroyed = false;
  writableEnded = false;
  blocked = false;

  write(message: string): boolean {
    this.messages.push(message);
    return !this.blocked;
  }

  end(): void {
    this.writableEnded = true;
  }
}

test('coalesces snapshots while backpressured and resumes on drain', () => {
  const writable = new ControlledWritable();
  writable.blocked = true;
  const stream = new LatestEventStream(writable);

  assert.equal(stream.push('snapshot-1'), true);
  assert.equal(stream.push('snapshot-2'), true);
  assert.equal(stream.push('snapshot-3'), true);
  assert.deepEqual(writable.messages, ['snapshot-1']);

  writable.blocked = false;
  writable.emit('drain');
  assert.deepEqual(writable.messages, ['snapshot-1', 'snapshot-3']);
});

test('detached and ended streams reject future snapshots', () => {
  const detachedWritable = new ControlledWritable();
  const detached = new LatestEventStream(detachedWritable);
  detached.detach();
  assert.equal(detached.push('ignored'), false);
  assert.deepEqual(detachedWritable.messages, []);

  const endedWritable = new ControlledWritable();
  const ended = new LatestEventStream(endedWritable);
  ended.end();
  assert.equal(endedWritable.writableEnded, true);
  assert.equal(ended.push('ignored'), false);
});
