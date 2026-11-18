import {createHash, randomBytes, scrypt, timingSafeEqual} from 'node:crypto';

import type {ViewerPrincipal} from '../shared/model.js';

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,189}$/;
const HASH = /^scrypt\$v1\$16384\$8\$1\$([0-9a-f]{32})\$([0-9a-f]{64})$/;
const SESSION_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_BYTES = 32;

export const SESSION_COOKIE = 'stacks_observer_session';

export class LoginRateLimiter {
  private readonly attempts = new Map<string, {windowStartedAt: number; count: number}>();

  constructor(
    private readonly maxAttempts = 5,
    private readonly windowMs = 60_000,
    private readonly capacity = 256,
  ) {}

  consume(key: string, now = Date.now()): boolean {
    for (const [candidate, bucket] of this.attempts) {
      if (now - bucket.windowStartedAt >= this.windowMs) this.attempts.delete(candidate);
    }
    const existing = this.attempts.get(key);
    if (existing) {
      if (existing.count >= this.maxAttempts) return false;
      existing.count += 1;
      return true;
    }
    if (this.attempts.size >= this.capacity) return false;
    this.attempts.set(key, {windowStartedAt: now, count: 1});
    return true;
  }

  clear(key: string): void {
    this.attempts.delete(key);
  }
}

export interface CredentialIdentityProvider {
  authenticate(email: string, password: string): Promise<ViewerPrincipal | null>;
}

export interface IssuedSession {
  token: string;
  expiresAt: number;
  principal: ViewerPrincipal;
}

interface StoredSession {
  principal: ViewerPrincipal;
  expiresAt: number;
}

/** Bounded, fail-closed server-side sessions. Restarting the PoC logs viewers out. */
export class MemorySessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  constructor(
    private readonly ttlMs = 8 * 60 * 60 * 1_000,
    private readonly capacity = 32,
  ) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 60_000 || ttlMs > 24 * 60 * 60 * 1_000) {
      throw new Error('session TTL must be between one minute and one day');
    }
    if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 1_024) {
      throw new Error('session capacity must be between 1 and 1024');
    }
  }

  create(principal: ViewerPrincipal, now = Date.now()): IssuedSession {
    this.expire(now);
    if (this.sessions.size >= this.capacity) throw new Error('session capacity reached');
    const token = randomBytes(32).toString('base64url');
    const expiresAt = now + this.ttlMs;
    this.sessions.set(tokenDigest(token), {principal, expiresAt});
    return {token, expiresAt, principal};
  }

  resolve(token: string | undefined, now = Date.now()): ViewerPrincipal | null {
    if (!token || !SESSION_TOKEN.test(token)) return null;
    const key = tokenDigest(token);
    const session = this.sessions.get(key);
    if (!session) return null;
    if (session.expiresAt <= now) {
      this.sessions.delete(key);
      return null;
    }
    return session.principal;
  }

  revoke(token: string | undefined): void {
    if (token && SESSION_TOKEN.test(token)) this.sessions.delete(tokenDigest(token));
  }

  private expire(now: number): void {
    for (const [key, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(key);
    }
  }
}

/**
 * PoC-only credential verifier. Route authorization consumes ViewerPrincipal,
 * so an OIDC callback can later issue the same session without changing API
 * handlers or authorization policy.
 */
export class DevelopmentPasswordIdentityProvider implements CredentialIdentityProvider {
  private readonly salt: Buffer;
  private readonly expected: Buffer;

  constructor(
    private readonly email: string,
    encodedPassword: string,
  ) {
    if (!EMAIL.test(email) || email.length > 254) throw new Error('development auth email is invalid');
    const parsed = HASH.exec(encodedPassword);
    if (!parsed) throw new Error('development password hash has an invalid format');
    this.salt = Buffer.from(parsed[1]!, 'hex');
    this.expected = Buffer.from(parsed[2]!, 'hex');
  }

  async authenticate(email: string, password: string): Promise<ViewerPrincipal | null> {
    if (email.length > 254 || password.length === 0 || password.length > 256) return null;
    const candidate = await derivePassword(password, this.salt);
    const validPassword = candidate.length === this.expected.length &&
      timingSafeEqual(candidate, this.expected);
    if (!validPassword || email.toLowerCase() !== this.email.toLowerCase()) return null;
    return {
      subject: `development:${this.email.toLowerCase()}`,
      email: this.email,
      roles: ['federation-operator'],
    };
  }
}

export class AuthenticationService {
  constructor(
    private readonly credentials: CredentialIdentityProvider,
    private readonly sessions: MemorySessionStore,
  ) {}

  async login(email: string, password: string, now = Date.now()): Promise<IssuedSession | null> {
    const principal = await this.credentials.authenticate(email, password);
    return principal ? this.sessions.create(principal, now) : null;
  }

  issue(principal: ViewerPrincipal, now = Date.now()): IssuedSession {
    return this.sessions.create(principal, now);
  }

  resolve(cookieHeader: string | undefined, now = Date.now()): ViewerPrincipal | null {
    return this.sessions.resolve(readCookie(cookieHeader, SESSION_COOKIE), now);
  }

  logout(cookieHeader: string | undefined): void {
    this.sessions.revoke(readCookie(cookieHeader, SESSION_COOKIE));
  }
}

export function sessionCookie(session: IssuedSession, secure: boolean, now = Date.now()): string {
  const maxAge = Math.max(0, Math.floor((session.expiresAt - now) / 1_000));
  return `${SESSION_COOKIE}=${session.token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

export function clearSessionCookie(secure: boolean): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;
}

export function readCookie(header: string | undefined, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    return part.slice(separator + 1).trim();
  }
  return undefined;
}

export async function encodeDevelopmentPassword(password: string, saltHex: string): Promise<string> {
  if (!/^[0-9a-f]{32}$/.test(saltHex)) throw new Error('development password salt must be 16 bytes of lowercase hex');
  const derived = await derivePassword(password, Buffer.from(saltHex, 'hex'));
  return `scrypt$v1$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${saltHex}$${derived.toString('hex')}`;
}

function derivePassword(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, SCRYPT_BYTES, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: 64 * 1024 * 1024,
    }, (error, derived) => error ? reject(error) : resolve(derived));
  });
}

function tokenDigest(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
