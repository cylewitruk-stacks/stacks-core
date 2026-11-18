import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AuthenticationService,
  clearSessionCookie,
  DevelopmentPasswordIdentityProvider,
  encodeDevelopmentPassword,
  LoginRateLimiter,
  MemorySessionStore,
  sessionCookie,
} from './auth.js';

const salt = '00112233445566778899aabbccddeeff';

test('development credentials issue a bounded revocable operator session', async () => {
  const encoded = await encodeDevelopmentPassword('stacks123', salt);
  const sessions = new MemorySessionStore(60_000, 2);
  const auth = new AuthenticationService(
    new DevelopmentPasswordIdentityProvider('user@host.com', encoded),
    sessions,
  );
  assert.equal(await auth.login('user@host.com', 'wrong', 1_000), null);
  const issued = await auth.login('user@host.com', 'stacks123', 1_000);
  assert.ok(issued);
  const cookie = sessionCookie(issued, false, 1_000);
  assert.equal(auth.resolve(cookie, 1_001)?.email, 'user@host.com');
  assert.deepEqual(auth.resolve(cookie, 1_001)?.roles, ['federation-operator']);
  auth.logout(cookie);
  assert.equal(auth.resolve(cookie, 1_002), null);
  assert.match(clearSessionCookie(false), /Max-Age=0/);
});

test('login attempt accounting is bounded and scoped to one credential source', () => {
  const limiter = new LoginRateLimiter(2, 60_000, 2);
  assert.equal(limiter.consume('source-a', 1_000), true);
  assert.equal(limiter.consume('source-a', 1_001), true);
  assert.equal(limiter.consume('source-a', 1_002), false);
  assert.equal(limiter.consume('source-b', 1_002), true);
  assert.equal(limiter.consume('source-c', 1_002), false, 'full accounting fails closed');
  limiter.clear('source-a');
  assert.equal(limiter.consume('source-c', 1_003), true);
});

test('sessions expire and capacity fails closed rather than evicting a live viewer', async () => {
  const encoded = await encodeDevelopmentPassword('stacks123', salt);
  const auth = new AuthenticationService(
    new DevelopmentPasswordIdentityProvider('user@host.com', encoded),
    new MemorySessionStore(60_000, 1),
  );
  const first = await auth.login('user@host.com', 'stacks123', 1_000);
  assert.ok(first);
  await assert.rejects(() => auth.login('user@host.com', 'stacks123', 1_001), /session capacity/);
  assert.equal(auth.resolve(sessionCookie(first, false, 1_000), 61_000), null);
  assert.ok(await auth.login('user@host.com', 'stacks123', 61_001));
});
