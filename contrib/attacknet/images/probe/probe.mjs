#!/usr/bin/env node

import {createHash, generateKeyPairSync, sign as signBytes} from 'node:crypto';
import {promises as dns} from 'node:dns';
import {promises as fs} from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import {join, resolve} from 'node:path';
import {performance} from 'node:perf_hooks';

export const RESPONSE_SCHEMA = 'stacks-attacknet-probe-response/v1';
export const ATTESTATION_SCHEMA = 'stacks-attacknet-probe-attestation/v1';

const ACTOR_RE = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
const PORT_RE = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_BODY_BYTES = 8192;
const MAX_ATTEMPTS = 10;
const MAX_IO_BYTES = 1024 * 1024;
const MAX_METRICS_BYTES = 512 * 1024;
const MAX_THROUGHPUT_BYTES = 1024 * 1024;
const PROCESS_WALL_CLOCK_METRIC = 'stacks_node_process_wall_clock_seconds';
const ATTACKNET_POLICY_METRIC = 'stacks_signer_attacknet_policy_matches_total';
const ATTACKNET_POLICY_EVALUATIONS_METRIC = 'stacks_signer_attacknet_policy_evaluations';
const ATTACKNET_POLICY_SESSION_METRIC = 'stacks_signer_attacknet_policy_session_active';
const SIGNER_BEHAVIORS = new Set(['withhold', 'delay', 'suppress-peer-responses']);
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;

function createAttestor() {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const publicKeyBytes = publicKey.export({type: 'spki', format: 'der'});
  return {
    keyId: digest(publicKeyBytes),
    publicKey: publicKeyBytes.toString('base64'),
    sign(payload) {
      const signedPayload = Buffer.from(JSON.stringify(payload));
      return {
        schemaVersion: ATTESTATION_SCHEMA,
        algorithm: 'Ed25519',
        keyId: digest(publicKeyBytes),
        publicKey: publicKeyBytes.toString('base64'),
        signedPayload: signedPayload.toString('base64'),
        signature: signBytes(null, signedPayload, privateKey).toString('base64'),
      };
    },
  };
}

function boundedInteger(value, name, minimum, maximum, fallback) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
    throw new Error(`${name} must be an integer in ${minimum}..${maximum}`);
  }
  return selected;
}

function percentile(values, fraction) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function roundMillis(value) {
  return Math.round(value * 1000) / 1000;
}

function errorText(error) {
  return error instanceof Error ? error.message.slice(0, 1024) : String(error).slice(0, 1024);
}

function positiveErrno(error) {
  if (Number.isInteger(error?.errno) && error.errno !== 0) return String(Math.abs(error.errno));
  // EIO is the conservative bucket for an error without a numeric platform errno.
  return '5';
}

export function parsePeerMap(raw) {
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('peer map must be an object');
  const entries = Object.entries(parsed);
  if (entries.length === 0 || entries.length > 100) throw new Error('peer map must contain 1..100 actors');
  const normalized = {};
  for (const [actor, peer] of entries) {
    if (!ACTOR_RE.test(actor) || actor.length > 63) throw new Error(`invalid peer actor ${actor}`);
    if (!peer || typeof peer !== 'object' || Array.isArray(peer)) throw new Error(`peer ${actor} must be an object`);
    if (typeof peer.host !== 'string' || peer.host.length === 0 || peer.host.length > 253) {
      throw new Error(`peer ${actor} has invalid host`);
    }
    const ports = Object.entries(peer.ports ?? {});
    if (ports.length > 32) throw new Error(`peer ${actor} has too many ports`);
    normalized[actor] = {host: peer.host, ports: {}};
    for (const [name, port] of ports) {
      if (!PORT_RE.test(name) || name.length > 15) throw new Error(`peer ${actor} has invalid port name ${name}`);
      normalized[actor].ports[name] = boundedInteger(port, `${actor}.${name}`, 1, 65535);
    }
  }
  return normalized;
}

function namedPeer(peers, actor) {
  if (typeof actor !== 'string' || !Object.hasOwn(peers, actor)) throw new Error('peer must name an enrolled actor');
  return peers[actor];
}

function namedPort(peer, name) {
  if (typeof name !== 'string' || !Object.hasOwn(peer.ports, name)) throw new Error('port must name an exposed peer port');
  return peer.ports[name];
}

function exactRequestFields(request, fields) {
  for (const field of Object.keys(request)) {
    if (!fields.has(field)) throw new Error(`unsupported ${request.kind ?? 'probe'} field ${field}`);
  }
}

async function connectOnce({host, port, timeoutMs, connect = net.createConnection}) {
  const started = performance.now();
  return new Promise(resolveResult => {
    let completed = false;
    const socket = connect({host, port});
    const finish = (success, error = null) => {
      if (completed) return;
      completed = true;
      socket.destroy();
      resolveResult({success, latencyMs: roundMillis(performance.now() - started), error});
    };
    socket.setTimeout(timeoutMs, () => finish(false, new Error('ETIMEDOUT')));
    socket.once('connect', () => finish(true));
    socket.once('error', error => finish(false, error));
  });
}

async function throughputOnce({host, port, bytes, timeoutMs, get = http.get}) {
  const started = performance.now();
  return new Promise((resolveResult, reject) => {
    let received = 0;
    const outgoing = get({host, port, path: `/v1/payload?bytes=${bytes}`, timeout: timeoutMs}, response => {
      response.on('data', chunk => {
        received += chunk.length;
        if (received > bytes) outgoing.destroy(new Error('throughput response exceeded requested bytes'));
      });
      response.on('end', () => {
        if ((response.statusCode ?? 0) !== 200 || received !== bytes) {
          reject(new Error(`throughput endpoint returned HTTP ${response.statusCode ?? 0} with ${received}/${bytes} bytes`));
          return;
        }
        const seconds = Math.max((performance.now() - started) / 1000, 0.000001);
        resolveResult(received / seconds);
      });
    });
    outgoing.on('timeout', () => outgoing.destroy(new Error('throughput request timed out')));
    outgoing.on('error', reject);
  });
}

export async function networkObservation(request, context) {
  const peer = namedPeer(context.peers, request.peer);
  const port = namedPort(peer, request.port);
  const attempts = boundedInteger(request.attempts, 'attempts', 1, MAX_ATTEMPTS, 5);
  const timeoutMs = boundedInteger(request.timeoutMs, 'timeoutMs', 50, request.throughputBytes === undefined ? 2000 : 10000, 1000);
  const results = await Promise.all(Array.from({length: attempts}, () =>
    connectOnce({host: peer.host, port, timeoutMs, connect: context.connect})));
  const samples = results.filter(sample => sample.success).map(sample => sample.latencyMs);
  const protocolErrors = results.length - samples.length;
  const throughputBytesPerSecond = request.throughputBytes === undefined ? null : await throughputOnce({
    host: peer.host,
    port,
    bytes: boundedInteger(request.throughputBytes, 'throughputBytes', 4096, MAX_THROUGHPUT_BYTES),
    timeoutMs,
    get: context.httpGet,
  });
  return {
    actor: context.actor, probe: 'network', status: 'ok',
    probeName: `${request.peer}-${request.port}`,
    peerActor: request.peer,
    attempts,
    successes: samples.length,
    latencyMsP50: percentile(samples, 0.50),
    latencyMsP95: percentile(samples, 0.95),
    protocolErrors,
    throughputBytesPerSecond,
  };
}

async function lookupOne(host, lookup) {
  try {
    const answers = await lookup(host, {all: true, verbatim: true});
    return {succeeded: true, answers: [...new Set(answers.map(answer => answer.address))].sort()};
  } catch {
    return {succeeded: false, answers: []};
  }
}

export async function dnsObservation(request, context) {
  const selected = namedPeer(context.peers, request.peer);
  const [query, control] = await Promise.all([
    lookupOne(selected.host, context.lookup),
    lookupOne(context.dnsControl, context.lookup),
  ]);
  return {
    actor: context.actor, probe: 'dns', status: 'ok',
    probeName: `${request.peer}-dns`,
    query: selected.host,
    controlQuery: context.dnsControl,
    querySucceeded: query.succeeded,
    controlSucceeded: control.succeeded,
    answers: query.answers,
    controlAnswers: control.answers,
  };
}

function probePath(root, actor, requestedName) {
  if (typeof requestedName !== 'string' || !FILE_RE.test(requestedName)) throw new Error('file must be a bounded basename');
  const directory = resolve(root, `.attacknet-probe-${actor}`);
  const path = resolve(directory, requestedName);
  if (!path.startsWith(`${directory}/`)) throw new Error('probe file escaped configured data root');
  return {directory, path};
}

function bufferFor(actor, name, bytes) {
  const seed = createHash('sha256').update(`${actor}:${name}`).digest();
  const result = Buffer.alloc(bytes);
  for (let index = 0; index < result.length; index += 1) result[index] = seed[index % seed.length];
  return result;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

async function ioOnce(operation, path, content, ioFs) {
  if (operation === 'READ') return ioFs.readFile(path);
  const handle = await ioFs.open(path, 'w', 0o600);
  try {
    await handle.writeFile(content);
    if (operation === 'FSYNC') await handle.sync();
  } finally {
    await handle.close();
  }
  return content;
}

export async function ioObservation(request, context) {
  const operation = String(request.operation ?? '').toUpperCase();
  if (!['READ', 'WRITE', 'FSYNC'].includes(operation)) throw new Error('operation must be READ, WRITE, or FSYNC');
  const attempts = boundedInteger(request.attempts, 'attempts', 1, MAX_ATTEMPTS, 5);
  const bytes = boundedInteger(request.bytes, 'bytes', 1, MAX_IO_BYTES, 4096);
  const {directory, path} = probePath(context.dataRoot, context.actor, request.file ?? 'probe.dat');
  const content = bufferFor(context.actor, request.file ?? 'probe.dat', bytes);
  await context.ioFs.mkdir(directory, {recursive: true, mode: 0o700});
  if (operation === 'READ') {
    try {
      await context.ioFs.access(path);
    } catch {
      await context.ioFs.writeFile(path, content, {mode: 0o600});
    }
  }
  const samples = [];
  const errorCounts = {};
  let lastContent = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const started = performance.now();
    try {
      lastContent = await ioOnce(operation, path, content, context.ioFs);
      samples.push(roundMillis(performance.now() - started));
    } catch (error) {
      const errno = positiveErrno(error);
      errorCounts[errno] = (errorCounts[errno] ?? 0) + 1;
    }
  }
  let attributesDigest = null;
  try {
    const stat = await context.ioFs.stat(path);
    attributesDigest = digest(JSON.stringify({size: stat.size, mode: stat.mode & 0o777, type: stat.isFile() ? 'file' : 'other'}));
  } catch {
    // The errno counts above are authoritative for a failed operation.
  }
  return {
    actor: context.actor, probe: 'io', status: 'ok',
    probeName: `${operation.toLowerCase()}-${request.file ?? 'probe.dat'}`,
    path,
    operation,
    attempts,
    successes: samples.length,
    errorCounts,
    latencyMsP50: percentile(samples, 0.50) ?? 0,
    latencyMsP95: percentile(samples, 0.95) ?? 0,
    contentDigest: lastContent === null ? null : digest(lastContent),
    attributesDigest,
  };
}

export async function clockObservation(request, context) {
  if (request.control !== undefined && typeof request.control !== 'boolean') throw new Error('control must be boolean');
  const before = performance.now();
  const wallEpochSeconds = context.now() / 1000;
  const monotonicSeconds = Number(context.monotonic()) / 1e9;
  return {
    actor: context.actor, probe: 'clock', status: 'ok', control: request.control === true,
    wallEpochSeconds, monotonicSeconds, sampleWindowMs: roundMillis(performance.now() - before),
  };
}

async function getText({host, port, path, timeoutMs}, request = http.get) {
  return new Promise((resolveResult, reject) => {
    const outgoing = request({host, port, path, timeout: timeoutMs}, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > MAX_METRICS_BYTES) {
          outgoing.destroy(new Error(`metrics response exceeds ${MAX_METRICS_BYTES} bytes`));
        } else {
          chunks.push(chunk);
        }
      });
      response.on('end', () => {
        if ((response.statusCode ?? 0) !== 200) {
          reject(new Error(`metrics endpoint returned HTTP ${response.statusCode ?? 0}`));
          return;
        }
        resolveResult(Buffer.concat(chunks).toString('utf8'));
      });
    });
    outgoing.on('timeout', () => outgoing.destroy(new Error('metrics request timed out')));
    outgoing.on('error', reject);
  });
}

function metricValue(text, metric) {
  const lines = text.split('\n').filter(line => line.startsWith(`${metric} `));
  if (lines.length !== 1) throw new Error(`metrics response must contain exactly one ${metric} sample`);
  const value = Number(lines[0].slice(metric.length).trim());
  if (!Number.isFinite(value) || value < 0 || value > 1e12) {
    throw new Error(`${metric} sample is not a bounded timestamp`);
  }
  return value;
}

export async function processClockObservation(request, context) {
  if (request.metric !== PROCESS_WALL_CLOCK_METRIC) {
    throw new Error(`metric must be ${PROCESS_WALL_CLOCK_METRIC}`);
  }
  if (request.control !== undefined && typeof request.control !== 'boolean') throw new Error('control must be boolean');
  const peer = namedPeer(context.peers, request.peer);
  const port = namedPort(peer, request.port);
  const before = performance.now();
  const wallEpochSeconds = metricValue(await getText({
    host: peer.host, port, path: '/metrics', timeoutMs: 2000,
  }, context.httpGet), request.metric);
  return {
    actor: context.actor, probe: 'clock', status: 'ok', control: request.control === true,
    wallEpochSeconds, monotonicSeconds: Number(context.monotonic()) / 1e9,
    sampleWindowMs: roundMillis(performance.now() - before), metric: request.metric,
  };
}

function policyMetricValue(text, metric, behavior) {
  if (!SIGNER_BEHAVIORS.has(behavior)) throw new Error('behavior is not supported');
  const prefix = `${metric}{behavior="${behavior}"} `;
  const lines = text.split('\n').filter(line => line.startsWith(prefix));
  if (lines.length !== 1) throw new Error(`metrics response must contain exactly one ${metric} sample for ${behavior}`);
  const value = Number(lines[0].slice(prefix.length).trim());
  if (!Number.isInteger(value) || value < 0 || value > 1e12) throw new Error(`${metric} sample is not a bounded integer`);
  return value;
}

// signerBehaviorObservation independently scrapes the testing-only signer
// counter through an enrolled endpoint. The signed report proves observer
// provenance; the metric content remains explicitly actor self-reported.
export async function signerBehaviorObservation(request, context) {
  const peer = namedPeer(context.peers, request.peer);
  const port = namedPort(peer, request.port);
  const before = performance.now();
  const metrics = await getText({
    host: peer.host, port, path: '/metrics', timeoutMs: 2000,
  }, context.httpGet);
  const matches = policyMetricValue(metrics, ATTACKNET_POLICY_METRIC, request.behavior);
  const evaluations = policyMetricValue(metrics, ATTACKNET_POLICY_EVALUATIONS_METRIC, request.behavior);
  const session = policyMetricValue(metrics, ATTACKNET_POLICY_SESSION_METRIC, request.behavior);
  if (session > 1) throw new Error('signer behavior session metric must be 0 or 1');
  return {
    actor: context.actor, probe: 'signer-behavior', status: 'ok',
    targetActor: request.peer, behavior: request.behavior, policyMatches: matches,
    policyEvaluations: evaluations, sessionActive: session === 1,
    // Signed reports use the cross-runtime canonical JSON contract, which
    // deliberately permits integers only.
    contentTrust: 'actor-self-reported', sampleWindowMs: Math.round(performance.now() - before),
  };
}

export async function systemObservation(_request, context) {
  return {
    actor: context.actor, probe: 'system', status: 'ok',
    platform: context.platform, architecture: context.architecture,
  };
}

export function createContext(environment = process.env, overrides = {}) {
  const actor = environment.PROBE_ACTOR;
  if (!ACTOR_RE.test(actor ?? '') || actor.length > 63) throw new Error('PROBE_ACTOR is invalid');
  const requestedDataRoot = environment.PROBE_DATA_ROOT || '/target-data';
  if (!requestedDataRoot.startsWith('/')) throw new Error('PROBE_DATA_ROOT must be absolute');
  const dataRoot = resolve(requestedDataRoot);
  const attestor = overrides.attestor ?? createAttestor();
  return {
    actor,
    peers: parsePeerMap(environment.PROBE_PEERS_JSON),
    dataRoot,
    dnsControl: environment.PROBE_DNS_CONTROL || 'kubernetes.default.svc.cluster.local',
    lookup: overrides.lookup ?? dns.lookup,
    connect: overrides.connect ?? net.createConnection,
    httpGet: overrides.httpGet ?? http.get,
    ioFs: overrides.ioFs ?? fs,
    now: overrides.now ?? Date.now,
    monotonic: overrides.monotonic ?? process.hrtime.bigint,
    platform: overrides.platform ?? process.platform,
    architecture: overrides.architecture ?? process.arch,
    attestor,
    adversarialTarget: environment.PROBE_ADVERSARIAL_TARGET || '',
    adversarialPolicyDigest: environment.PROBE_ADVERSARIAL_POLICY_DIGEST || '',
  };
}

export async function dispatchProbe(request, context) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('request must be a JSON object');
  const allowed = {
    network: new Set(['kind', 'peer', 'port', 'attempts', 'timeoutMs', 'throughputBytes', 'nonce']),
    dns: new Set(['kind', 'peer', 'nonce']),
    io: new Set(['kind', 'operation', 'file', 'bytes', 'attempts', 'nonce']),
    clock: new Set(['kind', 'control', 'nonce']),
    processClock: new Set(['kind', 'peer', 'port', 'metric', 'control', 'nonce']),
    signerBehavior: new Set(['kind', 'peer', 'port', 'behavior', 'nonce']),
    system: new Set(['kind', 'nonce']),
  }[request.kind];
  if (!allowed) throw new Error('kind must be network, dns, io, clock, processClock, signerBehavior, or system');
  exactRequestFields(request, allowed);
  const observation = await ({
    network: networkObservation,
    dns: dnsObservation,
    io: ioObservation,
    clock: clockObservation,
    processClock: processClockObservation,
    signerBehavior: signerBehaviorObservation,
    system: systemObservation,
  }[request.kind](request, context));
  if (request.nonce !== undefined && !NONCE_RE.test(request.nonce)) {
    throw new Error('nonce must contain 16..128 URL-safe characters');
  }
  const payload = {
    schemaVersion: RESPONSE_SCHEMA,
    actor: context.actor,
    kind: request.kind,
    nonce: request.nonce ?? '',
    observedAt: new Date(context.now()).toISOString(),
    targetActor: context.adversarialTarget,
    policyDigest: context.adversarialPolicyDigest,
    observation,
  };
  return {...payload, attestation: context.attestor.sign(payload)};
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function send(response, status, body) {
  const encoded = Buffer.from(`${JSON.stringify(body)}\n`);
  response.writeHead(status, {'content-type': 'application/json', 'content-length': encoded.length, 'cache-control': 'no-store'});
  response.end(encoded);
}

export function createServer(context) {
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/healthz') {
        send(response, 200, {status: 'ok', actor: context.actor});
        return;
      }
      const url = new URL(request.url, 'http://attacknet-probe.invalid');
      if (request.method === 'GET' && url.pathname === '/v1/identity') {
        send(response, 200, {
          schemaVersion: ATTESTATION_SCHEMA,
          actor: context.actor,
          targetActor: context.adversarialTarget,
          policyDigest: context.adversarialPolicyDigest,
          algorithm: 'Ed25519',
          keyId: context.attestor.keyId,
          publicKey: context.attestor.publicKey,
        });
        return;
      }
      if (request.method === 'GET' && url.pathname === '/v1/payload') {
        if ([...url.searchParams.keys()].some(key => key !== 'bytes')) throw new Error('unsupported payload parameter');
        const bytes = boundedInteger(Number(url.searchParams.get('bytes')), 'bytes', 4096, MAX_THROUGHPUT_BYTES);
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': bytes,
          'cache-control': 'no-store',
        });
        response.end(Buffer.alloc(bytes));
        return;
      }
      if (request.method !== 'POST' || request.url !== '/v1/probe') {
        send(response, 404, {error: 'not found'});
        return;
      }
      send(response, 200, await dispatchProbe(await readBody(request), context));
    } catch (error) {
      send(response, 400, {error: errorText(error)});
    }
  });
  server.maxConnections = 32;
  server.headersTimeout = 5000;
  server.requestTimeout = 10000;
  server.keepAliveTimeout = 1000;
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const context = createContext();
  const port = boundedInteger(Number.parseInt(process.env.PROBE_PORT ?? '18080', 10), 'PROBE_PORT', 1024, 65535);
  createServer(context).listen(port, '0.0.0.0', () => {
    process.stdout.write(`${JSON.stringify({event: 'probe-listening', actor: context.actor, port})}\n`);
  });
}
