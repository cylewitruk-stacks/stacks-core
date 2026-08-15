#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {promises as dns} from 'node:dns';
import {promises as fs} from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import {join, resolve} from 'node:path';
import {performance} from 'node:perf_hooks';

export const RESPONSE_SCHEMA = 'stacks-attacknet-probe-response/v1';

const ACTOR_RE = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
const PORT_RE = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_BODY_BYTES = 8192;
const MAX_ATTEMPTS = 10;
const MAX_IO_BYTES = 1024 * 1024;

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

export async function networkObservation(request, context) {
  const peer = namedPeer(context.peers, request.peer);
  const port = namedPort(peer, request.port);
  const attempts = boundedInteger(request.attempts, 'attempts', 1, MAX_ATTEMPTS, 5);
  const timeoutMs = boundedInteger(request.timeoutMs, 'timeoutMs', 50, 2000, 1000);
  const results = await Promise.all(Array.from({length: attempts}, () =>
    connectOnce({host: peer.host, port, timeoutMs, connect: context.connect})));
  const samples = results.filter(sample => sample.success).map(sample => sample.latencyMs);
  const protocolErrors = results.length - samples.length;
  return {
    actor: context.actor, probe: 'network', status: 'ok',
    probeName: `${request.peer}-${request.port}`,
    peerActor: request.peer,
    attempts,
    successes: samples.length,
    latencyMsP50: percentile(samples, 0.50),
    latencyMsP95: percentile(samples, 0.95),
    protocolErrors,
    throughputBytesPerSecond: null,
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

export function createContext(environment = process.env, overrides = {}) {
  const actor = environment.PROBE_ACTOR;
  if (!ACTOR_RE.test(actor ?? '') || actor.length > 63) throw new Error('PROBE_ACTOR is invalid');
  const requestedDataRoot = environment.PROBE_DATA_ROOT || '/target-data';
  if (!requestedDataRoot.startsWith('/')) throw new Error('PROBE_DATA_ROOT must be absolute');
  const dataRoot = resolve(requestedDataRoot);
  return {
    actor,
    peers: parsePeerMap(environment.PROBE_PEERS_JSON),
    dataRoot,
    dnsControl: environment.PROBE_DNS_CONTROL || 'kubernetes.default.svc.cluster.local',
    lookup: overrides.lookup ?? dns.lookup,
    connect: overrides.connect ?? net.createConnection,
    ioFs: overrides.ioFs ?? fs,
    now: overrides.now ?? Date.now,
    monotonic: overrides.monotonic ?? process.hrtime.bigint,
  };
}

export async function dispatchProbe(request, context) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('request must be a JSON object');
  const allowed = {
    network: new Set(['kind', 'peer', 'port', 'attempts', 'timeoutMs']),
    dns: new Set(['kind', 'peer']),
    io: new Set(['kind', 'operation', 'file', 'bytes', 'attempts']),
    clock: new Set(['kind', 'control']),
  }[request.kind];
  if (!allowed) throw new Error('kind must be network, dns, io, or clock');
  exactRequestFields(request, allowed);
  const observation = await ({
    network: networkObservation,
    dns: dnsObservation,
    io: ioObservation,
    clock: clockObservation,
  }[request.kind](request, context));
  return {
    schemaVersion: RESPONSE_SCHEMA,
    actor: context.actor,
    kind: request.kind,
    observedAt: new Date(context.now()).toISOString(),
    observation,
  };
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
