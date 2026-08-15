import http from 'node:http';

export const PROBE_RESPONSE_SCHEMA = 'stacks-attacknet-probe-response/v1';
export const PROBE_PORT = 18080;

const KIND_TO_PROBE = Object.freeze({
  NetworkChaos: 'network', DNSChaos: 'dns', IOChaos: 'io', TimeChaos: 'clock',
});

function globMatches(pattern, value) {
  const escaped = pattern.split('*')
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${escaped}$`).test(value);
}

function serviceFqdn(network, actor) {
  return `${network.metadata.name}-${actor.name}.${network.metadata.namespace}.svc.cluster.local`;
}

function peerCandidates(network, excluded = new Set()) {
  return (network.spec.actors ?? []).filter(actor => !excluded.has(actor.name));
}

function namedPort(actor, preferred = 'p2p') {
  const ports = actor.ports ?? [];
  return ports.find(port => port.name === preferred)?.name ?? ports[0]?.name ?? null;
}

export function buildProbeRequest({kind, campaign, compiledEvidence, network, target}) {
  const actorsByName = new Map((network.spec.actors ?? []).map(actor => [actor.name, actor]));
  const excluded = new Set([target.actor]);
  if (kind === 'NetworkChaos') {
    const requested = compiledEvidence.peerSelectedActors ?? [];
    const peers = (requested.length ? requested.map(name => actorsByName.get(name)) : peerCandidates(network, excluded))
      .filter(Boolean).filter(actor => actor.name !== target.actor && namedPort(actor));
    const peer = peers.sort((left, right) => left.name.localeCompare(right.name))[0];
    if (!peer) throw new Error(`no enrolled named peer endpoint is available for ${target.actor}`);
    return {kind: 'network', peer: peer.name, port: namedPort(peer), attempts: 5, timeoutMs: 2000};
  }
  if (kind === 'DNSChaos') {
    const patterns = campaign.spec.fault.parameters.patterns;
    const peer = peerCandidates(network, excluded)
      .filter(actor => patterns.some(pattern => globMatches(pattern, serviceFqdn(network, actor))))
      .sort((left, right) => left.name.localeCompare(right.name))[0];
    if (!peer) throw new Error(`no enrolled service name matches the DNS fault patterns for ${target.actor}`);
    return {kind: 'dns', peer: peer.name};
  }
  if (kind === 'IOChaos') {
    const methods = campaign.spec.fault.parameters.methods ?? [];
    const operation = methods.find(method => ['READ', 'WRITE', 'FSYNC'].includes(method)) ?? 'FSYNC';
    return {kind: 'io', operation, attempts: 5, bytes: 4096, file: `${campaign.metadata.name}.dat`};
  }
  if (kind === 'TimeChaos') return {kind: 'clock', control: false};
  throw new Error(`no active probe contract for ${kind}`);
}

export function controlTarget(network, pods, selectedActors) {
  const selected = new Set(selectedActors);
  const actors = new Map((network.spec.actors ?? []).map(actor => [actor.name, actor]));
  const candidates = (pods.items ?? []).filter(pod => {
    const actor = pod.metadata?.labels?.['testing.stacks.org/actor'];
    const ready = (pod.status?.conditions ?? []).some(item => item.type === 'Ready' && item.status === 'True');
    const probeReady = (pod.status?.containerStatuses ?? [])
      .some(item => item.name === 'attacknet-probe' && item.ready === true);
    return actor && actors.has(actor) && !selected.has(actor) && !pod.metadata?.deletionTimestamp
      && pod.status?.phase === 'Running' && ready && probeReady && pod.status?.podIP;
  }).sort((left, right) => {
    const roleOrder = role => ({follower: 0, companion: 1, miner: 2, signer: 3}[role] ?? 9);
    const leftActor = actors.get(left.metadata.labels['testing.stacks.org/actor']);
    const rightActor = actors.get(right.metadata.labels['testing.stacks.org/actor']);
    return roleOrder(leftActor.role) - roleOrder(rightActor.role)
      || leftActor.name.localeCompare(rightActor.name);
  });
  const pod = candidates[0];
  if (!pod) throw new Error('no independent Ready attacknet-probe control Pod is available');
  return {actor: pod.metadata.labels['testing.stacks.org/actor'], podIP: pod.status.podIP};
}

export class ProbeClient {
  constructor({port = PROBE_PORT, timeoutMs = 10_000, request = http.request} = {}) {
    this.port = port;
    this.timeoutMs = timeoutMs;
    this.requestImpl = request;
  }

  async probe(target, body) {
    const payload = Buffer.from(JSON.stringify(body));
    const result = await new Promise((resolve, reject) => {
      const request = this.requestImpl({
        hostname: target.podIP, port: this.port, path: '/v1/probe', method: 'POST',
        timeout: this.timeoutMs,
        headers: {'content-type': 'application/json', 'content-length': payload.length},
      }, response => {
        const chunks = [];
        let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > 131_072) request.destroy(new Error('probe response exceeds 128 KiB'));
          else chunks.push(chunk);
        });
        response.on('end', () => resolve({status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8')}));
      });
      request.on('timeout', () => request.destroy(new Error(`probe ${target.actor} timed out`)));
      request.on('error', reject);
      request.write(payload);
      request.end();
    });
    if (result.status !== 200) throw new Error(`probe ${target.actor} returned HTTP ${result.status}`);
    const parsed = JSON.parse(result.body);
    if (parsed.schemaVersion !== PROBE_RESPONSE_SCHEMA || parsed.actor !== target.actor
        || parsed.kind !== body.kind || !parsed.observation) {
      throw new Error(`probe ${target.actor} returned mismatched identity or schema`);
    }
    return parsed;
  }
}

export function probePhase({kind, phase, responses, allInjectedObserved = false}) {
  const probe = KIND_TO_PROBE[kind];
  if (!probe) throw new Error(`unsupported probe phase kind ${kind}`);
  const authority = kind === 'TimeChaos' ? 'orchestrator-kernel-probe' : 'active-probe';
  return {
    schemaVersion: 'stacks-attacknet-fault-probe/v1', phase,
    source: {trust: 'orchestrator-observed', authority, collector: 'attacknet-probe/v1'},
    capturedAt: new Date().toISOString(),
    injection: {
      allInjectedObserved,
      source: {trust: 'orchestrator-observed', authority: 'chaos-mesh-status', collector: 'attacknet-run-operator/v1'},
    },
    observations: responses.map(item => item.observation ?? {
      actor: item.actor, probe, status: 'error', error: String(item.error ?? 'probe failed').slice(0, 4096),
    }),
  };
}

export function baselineUsable(kind, phase, selectedActors) {
  const selected = new Set(selectedActors);
  const observations = phase.observations.filter(item => selected.has(item.actor));
  if (observations.length !== selected.size || observations.some(item => item.status !== 'ok')) return false;
  if (kind === 'NetworkChaos') return observations.every(item => item.successes > 0);
  if (kind === 'DNSChaos') return observations.every(item => item.querySucceeded && item.controlSucceeded);
  if (kind === 'IOChaos') return observations.every(item => item.successes > 0);
  if (kind === 'TimeChaos') {
    return observations.length === selected.size
      && phase.observations.some(item => item.status === 'ok' && item.control === true && !selected.has(item.actor));
  }
  return false;
}
