import {createReadStream, existsSync} from 'node:fs';
import {createServer, type IncomingMessage, type ServerResponse} from 'node:http';
import {extname, join, normalize} from 'node:path';
import {fileURLToPath} from 'node:url';

import {type ApiError, type NetworkSnapshot, type PublicPortalSnapshot} from '../shared/model.js';
import {
  AuthenticationService,
  clearSessionCookie,
  DevelopmentPasswordIdentityProvider,
  LoginRateLimiter,
  MemorySessionStore,
  sessionCookie,
} from './auth.js';
import {loadEnrollments} from './enrollment.js';
import {ChainProgressTracker, FEDERATION_QUERY, projectFederation} from './federation_projection.js';
import {PrometheusClient} from './prometheus.js';
import {StacksPublicDataClient, unavailablePublicNetwork} from './public_chain.js';
import {projectPublicPortal} from './public_projection.js';
import {LatestEventStream} from './sse.js';

const PORT = boundedPort(process.env.PORT, 4319);
const HOST = process.env.HOST ?? '127.0.0.1';
const client = new PrometheusClient(process.env.STACKS_OBSERVER_PROMETHEUS_URL ?? 'http://127.0.0.1:9090');
const expectedActors = loadEnrollments(
  process.env.STACKS_OBSERVER_ENROLLMENTS_FILE,
  process.env.STACKS_OBSERVER_EXPECTED_ACTORS,
);
const publicEndpoint = process.env.STACKS_OBSERVER_STACKS_API_URL ?? '';
const publicClient = publicEndpoint ? new StacksPublicDataClient(publicEndpoint) : null;
const expectedBurnCadenceSeconds = boundedPositiveNumber(
  process.env.STACKS_OBSERVER_EXPECTED_BURN_CADENCE_SECONDS,
  600,
);
const publicNetworkLabel = boundedLabel(process.env.STACKS_OBSERVER_PUBLIC_NETWORK_LABEL, 'Stacks');
const sessionSecure = process.env.STACKS_OBSERVER_SESSION_SECURE === 'true';
const auth = developmentAuthentication(process.env);
const loginRateLimiter = new LoginRateLimiter();
const progressTracker = new ChainProgressTracker();
const MAX_PUBLIC_STREAMS = 128;
const MAX_FEDERATION_STREAMS = 32;
interface SnapshotListener {
  stream: LatestEventStream;
  cookie: string | undefined;
}

const publicListeners = new Set<SnapshotListener>();
const federationListeners = new Set<SnapshotListener>();
let backendHealthy = false;
let publicNetwork = unavailablePublicNetwork(publicEndpoint || 'unconfigured');
let snapshot = projectFederation([], expectedActors, Date.now(), {publicNetwork});
let publicSnapshot = projectPublicPortal(publicNetwork, publicNetworkLabel);

async function refresh(): Promise<void> {
  try {
    const samples = await client.query(FEDERATION_QUERY);
    if (publicClient) {
      try {
        publicNetwork = await publicClient.snapshot();
      } catch (error) {
        publicNetwork = {
          ...publicNetwork,
          health: publicNetwork.signers.length > 0 ? 'degraded' : 'unknown',
          error: error instanceof Error ? error.message : 'public chain query failed',
        };
      }
    }
    const now = Date.now();
    snapshot = projectFederation(samples, expectedActors, now, {
      publicNetwork,
      progress: progressTracker.observe(samples, now),
      expectedBurnCadenceSeconds,
    });
    // Entity attribution is operator-curated but intentionally public. Reuse
    // the projection's validated enrollment join, then copy it through the
    // public whitelist so actor IDs and federation state remain unavailable.
    publicSnapshot = projectPublicPortal(snapshot.publicNetwork, publicNetworkLabel, now);
    backendHealthy = true;
    broadcastPublic(publicSnapshot);
    broadcastFederation(snapshot);
  } catch (error) {
    backendHealthy = false;
    console.error('observer backend query failed', error);
  }
}

void refresh();
setInterval(() => void refresh(), 5_000).unref();

const server = createServer(async (request, response) => {
  try {
    setSecurityHeaders(response);
    const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
    if (request.method === 'GET' && url.pathname === '/healthz') {
      sendJson(response, backendHealthy ? 200 : 503, {
        status: backendHealthy ? 'ok' : 'backend-unavailable',
      });
      return;
    }
    if (request.method === 'GET' && (url.pathname === '/api/public/snapshot' || url.pathname === '/api/snapshot')) {
      sendPrivateJson(response, 200, publicSnapshot);
      return;
    }
    if (request.method === 'GET' && (url.pathname === '/api/public/events' || url.pathname === '/api/events')) {
      if (publicListeners.size >= MAX_PUBLIC_STREAMS) {
        sendError(response, 503, 'stream-capacity', 'public stream capacity reached');
        return;
      }
      response.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      });
      const listener = {stream: new LatestEventStream(response), cookie: undefined};
      publicListeners.add(listener);
      listener.stream.push(snapshotEvent(publicSnapshot));
      request.on('close', () => {
        listener.stream.detach();
        publicListeners.delete(listener);
      });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/session') {
      const principal = auth.resolve(request.headers.cookie);
      sendPrivateJson(response, 200, {authenticated: principal !== null, principal});
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/session/login') {
      requireSameOrigin(request);
      const credentials = await readLogin(request);
      const loginKey = `${request.socket.remoteAddress ?? 'unknown'}:${credentials.email.toLowerCase()}`;
      if (!loginRateLimiter.consume(loginKey)) {
        sendError(response, 429, 'login-rate-limited', 'too many login attempts');
        return;
      }
      const issued = await auth.login(credentials.email, credentials.password);
      if (!issued) {
        sendError(response, 401, 'invalid-credentials', 'email or password is invalid');
        return;
      }
      loginRateLimiter.clear(loginKey);
      response.setHeader('Set-Cookie', sessionCookie(issued, sessionSecure));
      sendPrivateJson(response, 200, {authenticated: true, principal: issued.principal});
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/session/logout') {
      requireSameOrigin(request);
      auth.logout(request.headers.cookie);
      response.setHeader('Set-Cookie', clearSessionCookie(sessionSecure));
      sendPrivateJson(response, 200, {authenticated: false, principal: null});
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/federation/snapshot') {
      if (!requireOperator(request, response)) return;
      sendPrivateJson(response, 200, snapshot);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/federation/events') {
      if (!requireOperator(request, response)) return;
      if (federationListeners.size >= MAX_FEDERATION_STREAMS) {
        sendError(response, 503, 'stream-capacity', 'federation stream capacity reached');
        return;
      }
      const listener = {
        stream: new LatestEventStream(response),
        cookie: request.headers.cookie,
      };
      response.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      });
      federationListeners.add(listener);
      listener.stream.push(snapshotEvent(snapshot));
      request.on('close', () => {
        listener.stream.detach();
        federationListeners.delete(listener);
      });
      return;
    }
    if (request.method === 'GET') {
      serveStatic(url.pathname, response);
      return;
    }
    sendError(response, 404, 'not-found', 'route not found');
  } catch (error) {
    if (error instanceof RequestError) {
      sendError(response, error.status, error.code, error.message);
      return;
    }
    console.error('observer request failed', error);
    sendError(response, 500, 'internal-error', 'request failed');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Stacks Network Observer listening on http://${HOST}:${PORT} (Prometheus-backed federation)`);
});

function boundedPort(value: string | undefined, fallback: number): number {
  const candidate = Number(value ?? fallback);
  return Number.isInteger(candidate) && candidate >= 1 && candidate <= 65_535 ? candidate : fallback;
}

function boundedPositiveNumber(value: string | undefined, fallback: number): number {
  const candidate = Number(value ?? fallback);
  return Number.isFinite(candidate) && candidate >= 1 && candidate <= 86_400 ? candidate : fallback;
}

function boundedLabel(value: string | undefined, fallback: string): string {
  const candidate = value?.trim();
  return candidate && candidate.length <= 64 ? candidate : fallback;
}

function broadcastPublic(value: PublicPortalSnapshot): void {
  broadcast(publicListeners, snapshotEvent(value));
}

function broadcastFederation(value: NetworkSnapshot): void {
  const message = snapshotEvent(value);
  for (const listener of federationListeners) {
    if (!auth.resolve(listener.cookie)) {
      listener.stream.end();
      federationListeners.delete(listener);
      continue;
    }
    if (!listener.stream.push(message)) federationListeners.delete(listener);
  }
}

function broadcast(listeners: Set<SnapshotListener>, message: string): void {
  for (const listener of listeners) {
    if (!listener.stream.push(message)) listeners.delete(listener);
  }
}

function snapshotEvent(value: unknown): string {
  return `event: snapshot\ndata: ${JSON.stringify(value)}\n\n`;
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, {'Content-Type': 'application/json; charset=utf-8'});
  response.end(JSON.stringify(value));
}

function sendPrivateJson(response: ServerResponse, status: number, value: unknown): void {
  response.setHeader('Cache-Control', 'no-store');
  sendJson(response, status, value);
}

function sendError(response: ServerResponse, status: number, code: string, error: string): void {
  sendPrivateJson(response, status, {code, error} satisfies ApiError);
}

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; script-src 'self'");
}

function developmentAuthentication(environment: NodeJS.ProcessEnv): AuthenticationService {
  if (environment.STACKS_OBSERVER_AUTH_MODE !== 'development-password' ||
    environment.STACKS_OBSERVER_ALLOW_INSECURE_DEVELOPMENT_AUTH !== 'true') {
    throw new Error('observer requires an explicitly enabled development-password provider');
  }
  const email = environment.STACKS_OBSERVER_DEV_EMAIL;
  const passwordHash = environment.STACKS_OBSERVER_DEV_PASSWORD_HASH;
  if (!email || !passwordHash) throw new Error('observer development credentials are not configured');
  return new AuthenticationService(
    new DevelopmentPasswordIdentityProvider(email, passwordHash),
    new MemorySessionStore(),
  );
}

function requireOperator(request: IncomingMessage, response: ServerResponse): boolean {
  const principal = auth.resolve(request.headers.cookie);
  if (!principal?.roles.includes('federation-operator')) {
    sendError(response, 401, 'authentication-required', 'federation operator authentication is required');
    return false;
  }
  return true;
}

function requireSameOrigin(request: IncomingMessage): void {
  const origin = request.headers.origin;
  if (!origin) return;
  const expected = `http${sessionSecure ? 's' : ''}://${request.headers.host ?? ''}`;
  if (origin !== expected) throw new RequestError(403, 'origin-rejected', 'request origin is not allowed');
}

async function readLogin(request: IncomingMessage): Promise<{email: string; password: string}> {
  if (!(request.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw new RequestError(415, 'content-type', 'login requires application/json');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 4_096) throw new RequestError(413, 'request-too-large', 'login request is too large');
    chunks.push(bytes);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new RequestError(400, 'invalid-json', 'login request is invalid');
  }
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) {
    throw new RequestError(400, 'invalid-login', 'login request is invalid');
  }
  const {email, password} = decoded as Record<string, unknown>;
  if (typeof email !== 'string' || typeof password !== 'string') {
    throw new RequestError(400, 'invalid-login', 'login request is invalid');
  }
  return {email, password};
}

class RequestError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function serveStatic(pathname: string, response: ServerResponse): void {
  const root = fileURLToPath(new URL('../../client/', import.meta.url));
  const requested = pathname === '/' ? 'index.html' : normalize(pathname).replace(/^[/\\]+/, '');
  const path = join(root, requested);
  if (!path.startsWith(root) || !existsSync(path)) {
    const index = join(root, 'index.html');
    if (existsSync(index)) return pipeFile(index, response);
    return sendError(response, 404, 'ui-not-built', 'dashboard assets are not built');
  }
  pipeFile(path, response);
}

function pipeFile(path: string, response: ServerResponse): void {
  const types: Record<string, string> = {
    '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json',
  };
  response.writeHead(200, {'Content-Type': types[extname(path)] ?? 'application/octet-stream'});
  createReadStream(path).pipe(response);
}
