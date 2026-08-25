import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';

import {
  RESPONSE_SCHEMA, clockObservation, createContext, createServer, dispatchProbe,
  dnsObservation, ioObservation, parsePeerMap, processClockObservation, systemObservation,
} from './probe.mjs';

function context(overrides = {}) {
  return createContext({
    PROBE_ACTOR: 'signer-node-1',
    PROBE_DATA_ROOT: mkdtempSync(join(tmpdir(), 'attacknet-probe-')),
    PROBE_PEERS_JSON: JSON.stringify({
      'miner-1': {host: 'demo-miner-1', ports: {rpc: 20443, p2p: 20444, probe: 18080}},
      'signer-node-1': {host: 'demo-signer-node-1', ports: {rpc: 20443, metrics: 20446}},
    }),
    PROBE_DNS_CONTROL: 'kubernetes.default.svc.cluster.local',
  }, overrides);
}

test('peer map is an allowlist and rejects malformed or unbounded targets', () => {
  assert.equal(parsePeerMap({'miner-1': {host: 'demo-miner-1', ports: {rpc: 20443}}})['miner-1'].ports.rpc, 20443);
  assert.throws(() => parsePeerMap({'../../host': {host: 'bad', ports: {rpc: 1}}}), /invalid peer actor/);
  assert.throws(() => parsePeerMap({'miner-1': {host: 'ok', ports: {rpc: 70000}}}), /integer/);
  assert.throws(() => createContext({
    PROBE_ACTOR: 'miner-1', PROBE_DATA_ROOT: '../data',
    PROBE_PEERS_JSON: JSON.stringify({'miner-1': {host: 'ok', ports: {rpc: 1}}}),
  }), /must be absolute/);
});

test('DNS observation resolves only selected enrolled peer plus fixed control', async () => {
  const calls = [];
  const result = await dnsObservation({peer: 'miner-1'}, context({lookup: async host => {
    calls.push(host);
    return [{address: host.startsWith('demo-') ? '10.0.0.8' : '10.0.0.1'}];
  }}));
  assert.deepEqual(calls.sort(), ['demo-miner-1', 'kubernetes.default.svc.cluster.local'].sort());
  assert.equal(result.querySucceeded, true);
  assert.equal(result.controlSucceeded, true);
  await assert.rejects(() => dnsObservation({peer: 'example.com'}, context()), /enrolled actor/);
});

test('network observation samples an enrolled named port without arbitrary addressing', async () => {
  class Socket extends EventEmitter {
    setTimeout() {}
    destroy() {}
  }
  const destinations = [];
  const ctx = context({connect: destination => {
    destinations.push(destination);
    const socket = new Socket();
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  }});
  const result = await dispatchProbe({kind: 'network', peer: 'miner-1', port: 'rpc', attempts: 3}, ctx);
  assert.equal(result.observation.successes, 3);
  assert.equal(result.observation.protocolErrors, 0);
  assert.deepEqual(destinations, Array(3).fill({host: 'demo-miner-1', port: 20443}));
  await assert.rejects(
    () => dispatchProbe({kind: 'network', peer: 'miner-1', port: 'admin'}, ctx),
    /exposed peer port/,
  );
});

test('network observation measures bounded throughput through an enrolled probe endpoint', async () => {
  class Socket extends EventEmitter {
    setTimeout() {}
    destroy() {}
  }
  const result = await dispatchProbe({
    kind: 'network', peer: 'miner-1', port: 'probe', attempts: 1,
    timeoutMs: 5000, throughputBytes: 4096,
  }, context({
    connect: () => {
      const socket = new Socket();
      queueMicrotask(() => socket.emit('connect'));
      return socket;
    },
    httpGet: (options, callback) => {
      const outgoing = new EventEmitter();
      outgoing.destroy = error => outgoing.emit('error', error);
      queueMicrotask(() => {
        const response = new EventEmitter();
        response.statusCode = 200;
        callback(response);
        response.emit('data', Buffer.alloc(Number(new URL(options.path, 'http://probe.invalid').searchParams.get('bytes'))));
        response.emit('end');
      });
      return outgoing;
    },
  }));
  assert.equal(result.observation.successes, 1);
  assert.ok(result.observation.throughputBytesPerSecond > 0);
});

test('I/O is confined to a deterministic private directory and returns digests', async () => {
  const root = mkdtempSync(join(tmpdir(), 'attacknet-probe-io-'));
  const ctx = context();
  ctx.dataRoot = root;
  const write = await ioObservation({operation: 'write', file: 'sample.db', bytes: 128, attempts: 2}, ctx);
  assert.equal(write.successes, 2);
  assert.match(write.path, new RegExp(`^${root}/\\.attacknet-probe-signer-node-1/`));
  assert.match(write.contentDigest, /^sha256:[0-9a-f]{64}$/);
  const read = await ioObservation({operation: 'read', file: 'sample.db', bytes: 128}, ctx);
  assert.equal(read.successes, 5);
  assert.equal(read.contentDigest, write.contentDigest);
  await assert.rejects(() => ioObservation({operation: 'write', file: '../escape'}, ctx), /bounded basename/);
  await assert.rejects(() => ioObservation({operation: 'write', file: 'huge', bytes: 2_000_000}, ctx), /integer/);
});

test('clock observation records both wall and monotonic clocks', async () => {
  const result = await clockObservation({control: true}, context({now: () => 1234000, monotonic: () => 5678000000n}));
  assert.equal(result.wallEpochSeconds, 1234);
  assert.equal(result.monotonicSeconds, 5.678);
  assert.equal(result.control, true);
});

test('process clock observation samples only the enrolled node wall-clock metric', async () => {
  const destinations = [];
  const httpGet = (destination, callback) => {
    destinations.push(destination);
    const outgoing = new EventEmitter();
    outgoing.destroy = error => outgoing.emit('error', error);
    queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = 200;
      callback(response);
      response.emit('data', Buffer.from('# TYPE stacks_node_process_wall_clock_seconds gauge\n'));
      response.emit('data', Buffer.from('stacks_node_process_wall_clock_seconds 1234.5\n'));
      response.emit('end');
    });
    return outgoing;
  };
  const result = await processClockObservation({
    peer: 'signer-node-1', port: 'metrics',
    metric: 'stacks_node_process_wall_clock_seconds', control: false,
  }, context({httpGet, monotonic: () => 5678000000n}));
  assert.equal(result.wallEpochSeconds, 1234.5);
  assert.equal(result.monotonicSeconds, 5.678);
  assert.equal(result.metric, 'stacks_node_process_wall_clock_seconds');
  assert.deepEqual(destinations, [{host: 'demo-signer-node-1', port: 20446, path: '/metrics', timeout: 2000}]);
  await assert.rejects(() => processClockObservation({
    peer: 'signer-node-1', port: 'metrics', metric: 'arbitrary_metric',
  }, context({httpGet})), /metric must be stacks_node_process_wall_clock_seconds/);
});

test('system observation exposes the probe runtime architecture without accepting commands', async () => {
  const ctx = context({platform: 'linux', architecture: 'arm64'});
  assert.deepEqual(await systemObservation({}, ctx), {
    actor: 'signer-node-1', probe: 'system', status: 'ok',
    platform: 'linux', architecture: 'arm64',
  });
  const result = await dispatchProbe({kind: 'system'}, ctx);
  assert.equal(result.kind, 'system');
  assert.equal(result.observation.architecture, 'arm64');
  await assert.rejects(() => dispatchProbe({kind: 'system', command: 'uname'}, ctx),
    /unsupported system field/);
});

test('response contract wraps evaluator-compatible observations', async () => {
  const result = await dispatchProbe({kind: 'clock'}, context({now: () => 1234000, monotonic: () => 5000000000n}));
  assert.equal(result.schemaVersion, RESPONSE_SCHEMA);
  assert.equal(result.actor, 'signer-node-1');
  assert.equal(result.kind, 'clock');
  assert.equal(result.observation.probe, 'clock');
  await assert.rejects(() => dispatchProbe({kind: 'clock', command: 'date'}, context()), /unsupported clock field/);
});

test('HTTP API exposes only health and the bounded probe dispatcher', async () => {
  const server = createServer(context({now: () => 1234000, monotonic: () => 5000000000n}));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    const health = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(health.status, 200);
    const payload = await fetch(`http://127.0.0.1:${address.port}/v1/payload?bytes=4096`);
    assert.equal(payload.status, 200);
    assert.equal((await payload.arrayBuffer()).byteLength, 4096);
    const probe = await fetch(`http://127.0.0.1:${address.port}/v1/probe`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({kind: 'clock'}),
    });
    assert.equal((await probe.json()).schemaVersion, RESPONSE_SCHEMA);
    const arbitrary = await fetch(`http://127.0.0.1:${address.port}/v1/probe`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({kind: 'network', peer: 'internet', port: 'https'}),
    });
    assert.equal(arbitrary.status, 400);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
