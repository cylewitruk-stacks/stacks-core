import type {
  ActorMetricInventory,
  CoarseRegion,
  Health,
  Incident,
  LinkObservation,
  NetworkSnapshot,
  NodeObservation,
  NodeRole,
  PublicNetworkState,
  ReporterState,
  SignerQuorumRound,
  SignerQuorumVote,
  SignerLifecycle,
  SignerMinerState,
} from '../shared/model.js';
import type {ExpectedActor} from './enrollment.js';
import {parseLegacyExpectedActors} from './enrollment.js';
import type {PrometheusSample} from './prometheus.js';
import {unavailablePublicNetwork} from './public_chain.js';

/** Exact series names produced by the reviewed Collector metric contract. */
export const FEDERATION_SERIES_NAMES = [
  'process_cpu_seconds_total',
  'process_resident_memory_bytes',
  'stacks_miner_signer_round_approved_weight',
  'stacks_miner_signer_round_block_height',
  'stacks_miner_signer_round_rejected_weight',
  'stacks_miner_signer_round_unavailable_weight',
  'stacks_miner_signer_round_started_timestamp_seconds',
  'stacks_miner_signer_round_status',
  'stacks_miner_signer_round_threshold_weight',
  'stacks_miner_signer_round_total_weight',
  'stacks_miner_signer_vote_latency_seconds',
  'stacks_miner_signer_vote_weight',
  'stacks_node_burn_block_height',
  'stacks_node_burn_block_last_changed_timestamp_seconds',
  'stacks_node_block_proposal_validation_execution_seconds_bucket',
  'stacks_node_block_proposal_validation_execution_seconds_count',
  'stacks_node_block_proposal_validation_execution_seconds_sum',
  'stacks_node_block_proposal_validation_executions_total',
  'stacks_node_stacks_tip_height',
  'stacks_node_stacks_tip_last_changed_timestamp_seconds',
  'stacks_observability_blocked_on',
  'stacks_observability_spans_dropped_total',
  'stacks_p2p_authenticated_signer_link',
  'stacks_p2p_connected_peer',
  'stacks_p2p_command_queue_residence_seconds',
  'stacks_p2p_connections',
  'stacks_p2p_events_total',
  'stacks_p2p_rendezvous_connections',
  'stacks_p2p_object_cache_bytes',
  'stacks_p2p_object_cache_items',
  'stacks_p2p_oldest_item_waiting_seconds',
  'stacks_p2p_peer_rtt_seconds',
  'stacks_p2p_peer_store_addresses',
  'stacks_p2p_peer_store_peers',
  'stacks_p2p_stall_reason_code',
  'stacks_p2p_swarm_lag_seconds',
  'stacks_p2p_sync_capable_peers',
  'stacks_signer_active_protocol_version',
  'stacks_signer_block_policy_rejections_total',
  'stacks_signer_agreement_state_change_reasons_total',
  'stacks_signer_agreement_state_conflicts_total',
  'stacks_signer_block_proposals_received_total',
  'stacks_signer_block_response_latencies_histogram_bucket',
  'stacks_signer_block_response_latencies_histogram_count',
  'stacks_signer_block_response_latencies_histogram_sum',
  'stacks_signer_block_responses_sent_total',
  'stacks_signer_block_validation_latencies_histogram_bucket',
  'stacks_signer_block_validation_latencies_histogram_count',
  'stacks_signer_block_validation_latencies_histogram_sum',
  'stacks_signer_block_validation_responses_total',
  'stacks_signer_current_reward_cycle',
  'stacks_signer_deferred_miner_authorization_observations_total',
  'stacks_signer_deferred_miner_authorizations_admitted_total',
  'stacks_signer_deferred_miner_authorizations_pending',
  'stacks_signer_deferred_miner_authorizations_resolved_total',
  'stacks_signer_local_state',
  'stacks_signer_miner_state',
  'stacks_signer_native_network_generation_start_timestamp_seconds',
  'stacks_signer_stacks_node_height',
  'stacks_signer_stacks_node_height_last_changed_timestamp_seconds',
  'stacks_signer_stacks_node_height_last_observed_timestamp_seconds',
  'stacks_signer_state_burn_block_height',
  'stacks_signer_state_last_changed_timestamp_seconds',
] as const;

export const FEDERATION_QUERY = `{__name__=~"^(${FEDERATION_SERIES_NAMES.join('|')})$"}`;

export {parseLegacyExpectedActors as parseExpectedActors};
export type {ExpectedActor};

interface ActorSeries {
  labels: Record<string, string>;
  samples: PrometheusSample[];
}

export interface ProgressAges {
  burnAgeSeconds: number | null;
  stacksAgeSeconds: number | null;
}

interface ProgressMark {
  height: number;
  changedAtMs: number;
}

/** Retains only height and change time; it is not an observation store. */
export class ChainProgressTracker {
  private burn: ProgressMark | undefined;
  private stacks: ProgressMark | undefined;

  observe(samples: PrometheusSample[], now = Date.now()): ProgressAges {
    const actors = groupByActor(samples);
    const nodeActors = [...actors.values()].filter(actor => boundedRole(actor.labels.stacks_actor_role) !== 'signer');
    this.burn = updateProgressMark(
      this.burn,
      maximumNullable(nodeActors.map(actor => metric(actor, 'stacks_node_burn_block_height'))),
      maximumNullable(nodeActors.map(actor => metric(actor, 'stacks_node_burn_block_last_changed_timestamp_seconds'))),
      now,
    );
    this.stacks = updateProgressMark(
      this.stacks,
      maximumNullable(nodeActors.map(actor => metric(actor, 'stacks_node_stacks_tip_height'))),
      maximumNullable(nodeActors.map(actor => metric(actor, 'stacks_node_stacks_tip_last_changed_timestamp_seconds'))),
      now,
    );
    return {
      burnAgeSeconds: progressAge(this.burn, now),
      stacksAgeSeconds: progressAge(this.stacks, now),
    };
  }
}

export interface ProjectionOptions {
  publicNetwork?: PublicNetworkState;
  progress?: ProgressAges;
  expectedBurnCadenceSeconds?: number;
  signerCompanionMaxBurnDrift?: number;
  signerStateStaleSeconds?: number;
}

export function projectFederation(
  samples: PrometheusSample[],
  expectedActors: ExpectedActor[],
  now = Date.now(),
  options: ProjectionOptions = {},
): NetworkSnapshot {
  const actors = groupByActor(samples);
  const expected = new Map(expectedActors.map(actor => [actor.id, actor]));
  const ids = new Set([...expected.keys(), ...actors.keys()]);
  const publicNetwork = enrichPublicNetwork(
    options.publicNetwork ?? unavailablePublicNetwork('unconfigured', now),
    expectedActors,
  );
  const publicSigners = new Map(publicNetwork.signers.map(signer => [signer.publicKey, signer]));
  const nodes: NodeObservation[] = [];
  const reporters: ReporterState[] = [];
  const incidents: Incident[] = [];

  for (const id of [...ids].sort()) {
    const series = actors.get(id);
    const configured = expected.get(id);
    const role = boundedRole(series?.labels.stacks_actor_role) ?? configured?.role ?? 'unknown';
    const lastSeenMs = latestTimestamp(series);
    const stale = !series || now - lastSeenMs > 20_000;
    const stallCode = metric(series, 'stacks_p2p_stall_reason_code') ?? 0;
    const blockedOn = activeLabel(series, 'stacks_observability_blocked_on', 'reason') ?? 'none';
    const signerLifecycle = activeLabel(series, 'stacks_signer_local_state', 'state') as SignerLifecycle | null;
    const localIssue = stallCode > 0 || blockedOn !== 'none' || signerLifecycle === 'uninitialized';
    const health: Health = stale ? 'critical' : localIssue ? 'degraded' : 'healthy';
    const stacksHeight = metric(series, role === 'signer'
      ? 'stacks_signer_stacks_node_height'
      : 'stacks_node_stacks_tip_height') ?? 0;
    const stacksTipObservedAt = unixSecondsToIso(metric(series, role === 'signer'
      ? 'stacks_signer_stacks_node_height_last_observed_timestamp_seconds'
      : 'stacks_node_stacks_tip_last_changed_timestamp_seconds'));
    const stateBurnHeight = metric(series, 'stacks_signer_state_burn_block_height');
    const burnHeight = metric(series, 'stacks_node_burn_block_height') ?? stateBurnHeight ?? 0;
    const connections = metric(series, 'stacks_p2p_connections');
    const queueSeconds = Math.max(
      metric(series, 'stacks_p2p_command_queue_residence_seconds') ?? 0,
      metric(series, 'stacks_p2p_oldest_item_waiting_seconds') ?? 0,
    );
    const label = configured?.label ?? id;
    const lastSeen = new Date(lastSeenMs || 0).toISOString();
    const signerIdentity = configured?.signerPublicKey
      ? publicSigners.get(configured.signerPublicKey)
      : undefined;
    const signerState = role === 'signer' ? {
      lifecycle: signerLifecycle ?? 'unknown',
      minerState: (activeLabel(series, 'stacks_signer_miner_state', 'state') as SignerMinerState | null) ?? 'unknown',
      rewardCycle: metric(series, 'stacks_signer_current_reward_cycle'),
      burnBlockHeight: stateBurnHeight,
      protocolVersion: metric(series, 'stacks_signer_active_protocol_version'),
      lastChangedAt: unixSecondsToIso(metric(series, 'stacks_signer_state_last_changed_timestamp_seconds')),
      transitionCounts: labeledCounts(series, 'stacks_signer_agreement_state_change_reasons_total', 'reason')
        .map(item => ({reason: item.label, count: item.count})),
      conflictCounts: labeledCounts(series, 'stacks_signer_agreement_state_conflicts_total', 'conflict')
        .map(item => ({conflict: item.label, count: item.count})),
      source: 'authenticated-telemetry' as const,
    } : null;
    nodes.push({
      id,
      label,
      role,
      transport: 'libp2p',
      health,
      region: boundedRegion(series?.labels.stacks_region),
      burnHeight,
      stacksHeight,
      stacksTipObservedAt,
      canonicalTip: stacksHeight > 0 ? `height-${stacksHeight}` : 'unknown',
      inboundPeers: connections,
      outboundPeers: null,
      dhtPeers: metric(series, 'stacks_p2p_sync_capable_peers'),
      queueResidenceP95Ms: queueSeconds * 1_000,
      queueUtilization: 0,
      cpuUtilization: 0,
      memoryMb: 0,
      syncLag: metric(series, 'stacks_p2p_swarm_lag_seconds') ?? 0,
      blockedOn,
      signerProposals: sumMetric(series, 'stacks_signer_block_proposals_received_total'),
      signerResponses: sumMetric(series, 'stacks_signer_block_responses_sent_total'),
      signerPublicKey: configured?.signerPublicKey ?? null,
      signerEntityName: configured?.entityName ?? signerIdentity?.entityName ?? null,
      signerWeight: signerIdentity?.weight ?? null,
      companionActorId: configured?.companionActorId ?? null,
      signerState,
      lastSeen,
    });
    reporters.push({
      id,
      label,
      role,
      health,
      lastSeen,
      acceptedBatches: new Set(series?.samples.map(sample => sample.metric.__name__)).size,
      rejectedBatches: 0,
      clockSkewMs: lastSeenMs ? Math.max(0, now - lastSeenMs) : 0,
      observedNodes: series ? 1 : 0,
    });
    if (stale) {
      incidents.push({
        id: `telemetry-${id}`,
        severity: 'critical',
        kind: 'telemetry-blind-spot',
        title: `${label} telemetry is missing or stale`,
        evidence: [series ? `last accepted metric was ${Math.round((now - lastSeenMs) / 1_000)}s ago` : 'no accepted metrics'],
        affectedNodes: [id],
        detectedAt: new Date(now).toISOString(),
        status: 'active',
      });
    } else if (localIssue) {
      incidents.push({
        id: `stall-${id}`,
        severity: 'warning',
        kind: stallCode === 1 || stallCode === 2 || stallCode === 5 ? 'sync' : 'resource-pressure',
        title: `${label} reports a bounded local stall`,
        evidence: blockedOn !== 'none'
          ? [`${role} reports blocked_on=${blockedOn}`]
          : signerLifecycle === 'uninitialized'
            ? ['signer local state machine is uninitialized']
            : [`stacks_p2p_stall_reason_code=${stallCode}`],
        affectedNodes: [id],
        detectedAt: new Date(now).toISOString(),
        status: 'active',
      });
    }
  }

  const nodeActors = nodes.filter(node => node.role !== 'signer');
  const maxStacks = maximum(nodeActors.map(node => node.stacksHeight));
  const propagation = projectTipAdoption(nodeActors, maxStacks);
  const links = projectLinks(actors, expectedActors, now);
  const signerQuorumRounds = projectSignerQuorumRounds(actors, expectedActors, publicNetwork, now);
  const actorMetrics = projectActorMetrics(actors, expectedActors);
  const reporting = reporters.filter(reporter => reporter.health !== 'critical').length;
  const maxBurn = maximum(nodeActors.map(node => node.burnHeight));
  const heightAgreement = largestHeightCohort(nodeActors);
  const progress = options.progress ?? {burnAgeSeconds: null, stacksAgeSeconds: null};
  const expectedBurnCadenceSeconds = Math.max(1, options.expectedBurnCadenceSeconds ?? 600);
  appendSignerCompanionDriftIncidents(
    incidents,
    nodes,
    expectedActors,
    Math.max(0, options.signerCompanionMaxBurnDrift ?? 2),
    Math.max(1, options.signerStateStaleSeconds ?? expectedBurnCadenceSeconds * 2),
    now,
  );
  appendProgressIncident(
    incidents,
    nodeActors,
    progress,
    expectedBurnCadenceSeconds,
    now,
  );
  if (publicNetwork.health !== 'healthy') {
    incidents.push({
      id: 'public-chain-data',
      severity: 'warning',
      kind: 'telemetry-blind-spot',
      title: 'Public signer-set enrichment is incomplete',
      evidence: [publicNetwork.error ?? 'the current reward set is not available from the configured public source'],
      affectedNodes: [],
      detectedAt: new Date(now).toISOString(),
      status: 'active',
    });
  }
  const health: Health = incidents.some(incident => incident.severity === 'critical')
    ? 'critical'
    : incidents.length > 0 ? 'degraded' : 'healthy';
  return {
    summary: {
      network: 'regtest · public chain + enrolled OTLP federation',
      generatedAt: new Date(now).toISOString(),
      health,
      stall: incidents[0]?.kind ?? 'none',
      burnHeight: maxBurn,
      stacksHeight: maxStacks,
      heightAgreement,
      reportingNodes: reporting,
      observedNodes: nodes.length,
      observedLinks: links.length,
      propagationP95Ms: propagation[0]?.p95Ms ?? 0,
      signerQuorumMs: 0,
      maxSyncLag: maximum(nodes.map(node => node.syncLag)),
      queueResidenceP95Ms: maximum(nodes.map(node => node.queueResidenceP95Ms)),
      burnProgressAgeSeconds: progress.burnAgeSeconds ?? 0,
      stacksProgressAgeSeconds: progress.stacksAgeSeconds ?? 0,
    },
    nodes,
    links,
    propagation,
    incidents,
    reporters,
    publicNetwork,
    signerQuorumRounds,
    actorMetrics,
  };
}

/**
 * Return the share of node actors in the largest same-height cohort.
 *
 * The newest reported height is intentionally not privileged here: a single
 * leading node is normal while a block propagates and must not turn the
 * health-facing agreement signal red. This is height agreement only; without
 * an index-block-hash metric it makes no claim that same-height tips are equal.
 */
function largestHeightCohort(nodes: NodeObservation[]): number {
  if (nodes.length === 0) return 0;
  const cohorts = new Map<number, number>();
  for (const node of nodes) {
    cohorts.set(node.stacksHeight, (cohorts.get(node.stacksHeight) ?? 0) + 1);
  }
  return Math.max(...cohorts.values()) / nodes.length;
}

function appendSignerCompanionDriftIncidents(
  incidents: Incident[],
  nodes: NodeObservation[],
  expectedActors: ExpectedActor[],
  maxBurnDrift: number,
  staleSeconds: number,
  now: number,
): void {
  const nodesById = new Map(nodes.map(node => [node.id, node]));
  for (const actor of expectedActors) {
    if (actor.role !== 'signer' || !actor.companionActorId) continue;
    const signer = nodesById.get(actor.id);
    const companion = nodesById.get(actor.companionActorId);
    const signerBurn = signer?.signerState?.burnBlockHeight;
    const stateChangedAt = signer?.signerState?.lastChangedAt;
    if (!signer || !companion || signer.health === 'critical' || companion.health === 'critical' ||
      signerBurn === null || signerBurn === undefined || !stateChangedAt) continue;
    const stateChangedAtMs = Date.parse(stateChangedAt);
    if (!Number.isFinite(stateChangedAtMs)) continue;
    const drift = companion.burnHeight - signerBurn;
    const stateAgeSeconds = Math.max(0, (now - stateChangedAtMs) / 1_000);
    if (drift <= maxBurnDrift || stateAgeSeconds < staleSeconds) continue;
    incidents.push({
      id: `signer-companion-drift-${actor.id}`,
      severity: 'critical',
      kind: 'sync',
      title: `${signer.label} state is not following its companion`,
      evidence: [
        `signer state burn height ${signerBurn} trails companion ${actor.companionActorId} at ${companion.burnHeight} by ${drift} blocks`,
        `signer state has not changed for ${Math.floor(stateAgeSeconds)}s`,
      ],
      affectedNodes: [actor.id, actor.companionActorId],
      detectedAt: new Date(now).toISOString(),
      status: 'active',
    });
  }
}

function projectTipAdoption(
  nodes: NodeObservation[],
  height: number,
): NetworkSnapshot['propagation'] {
  if (height <= 0 || nodes.length === 0) return [];
  const observed = nodes
    .filter(node => node.stacksHeight === height && node.stacksTipObservedAt)
    .map(node => ({node, at: Date.parse(node.stacksTipObservedAt!)}))
    .filter(entry => Number.isFinite(entry.at))
    .sort((left, right) => left.at - right.at || left.node.id.localeCompare(right.node.id));
  if (observed.length === 0) return [];
  const startedAt = observed[0]!.at;
  const delays = observed.map(entry => Math.max(0, entry.at - startedAt));
  return [{
    id: `tip-height-${height}`,
    objectKind: 'nakamoto-block',
    objectId: `height-${height}`,
    originNode: observed[0]!.node.id,
    startedAt: new Date(startedAt).toISOString(),
    p50Ms: percentile(delays, 0.5),
    p95Ms: percentile(delays, 0.95),
    coverage: observed.length / nodes.length,
    hops: observed.map((entry, index) => ({
      nodeId: entry.node.id,
      firstSeenMs: delays[index]!,
      validatedMs: delays[index]!,
      source: 'tip-observation',
      accepted: true,
    })),
  }];
}

const SAFE_METRIC_ATTRIBUTES = [
  'conflict',
  'decision',
  'event',
  'observation',
  'reason',
  'reject_code',
  'response_type',
  'resolution',
  'signer_public_key',
  'state',
  'status',
  'subsystem',
] as const;

const HISTOGRAMS = [
  'stacks_signer_block_response_latencies_histogram',
  'stacks_signer_block_validation_latencies_histogram',
] as const;

function projectActorMetrics(
  actors: Map<string, ActorSeries>,
  expectedActors: ExpectedActor[],
): ActorMetricInventory[] {
  const expected = new Map(expectedActors.map(actor => [actor.id, actor]));
  const ids = new Set([...expected.keys(), ...actors.keys()]);
  return [...ids].sort().map(actorId => {
    const actor = actors.get(actorId);
    const configured = expected.get(actorId);
    const role = boundedRole(actor?.labels.stacks_actor_role) ?? configured?.role ?? 'unknown';
    const readings = (actor?.samples ?? [])
      // Transport PeerIds are consumed only by the server-side enrollment
      // join. Do not copy one row per identity into the client catalogue.
      .filter(sample => sample.metric.__name__ !== 'stacks_p2p_connected_peer')
      .filter(sample => !HISTOGRAMS.some(base => sample.metric.__name__?.startsWith(`${base}_`)))
      .map(sample => metricReading(sample))
      .filter((reading): reading is NonNullable<typeof reading> => reading !== null);
    for (const base of HISTOGRAMS) readings.push(...histogramReadings(actor, base));
    readings.sort((left, right) => left.domain.localeCompare(right.domain) ||
      left.label.localeCompare(right.label) || left.id.localeCompare(right.id));
    return {
      actorId,
      actorLabel: configured?.label ?? actorId,
      role,
      readings,
    };
  });
}

function metricReading(sample: PrometheusSample): ActorMetricInventory['readings'][number] | null {
  const name = sample.metric.__name__;
  const value = Number(sample.value[1]);
  if (!name || !FEDERATION_SERIES_NAMES.includes(name as typeof FEDERATION_SERIES_NAMES[number]) ||
    !Number.isFinite(value)) return null;
  const attributes = SAFE_METRIC_ATTRIBUTES.flatMap(key =>
    sample.metric[key] === undefined ? [] : [{key, value: sample.metric[key]!}]);
  return {
    id: `${name}:${attributes.map(attribute => `${attribute.key}=${attribute.value}`).join(',')}`,
    name,
    label: humanizeMetric(name),
    domain: metricDomain(name, sample.metric.event),
    value,
    unit: metricUnit(name),
    attributes,
    observedAt: new Date(sample.value[0] * 1_000).toISOString(),
  };
}

function histogramReadings(
  actor: ActorSeries | undefined,
  base: typeof HISTOGRAMS[number],
): ActorMetricInventory['readings'] {
  const countSample = latestMetricSample(actor, `${base}_count`);
  const sumSample = latestMetricSample(actor, `${base}_sum`);
  if (!countSample || !sumSample) return [];
  const count = Number(countSample.value[1]);
  const sum = Number(sumSample.value[1]);
  if (!Number.isFinite(count) || !Number.isFinite(sum)) return [];
  const observedAt = new Date(Math.max(countSample.value[0], sumSample.value[0]) * 1_000).toISOString();
  const domain = metricDomain(base);
  const label = humanizeMetric(base);
  const readings: ActorMetricInventory['readings'] = [{
    id: `${base}:samples`, name: `${base}_count`, label: `${label} samples`, domain,
    value: count, unit: 'count', attributes: [], observedAt,
  }];
  if (count > 0) {
    readings.push({
      id: `${base}:mean`, name: `${base}_mean`, label: `${label} mean`, domain,
      value: sum / count, unit: 'seconds', attributes: [], observedAt,
    });
    const p95 = histogramPercentile(actor, base, count, 0.95);
    if (p95 !== null) readings.push({
      id: `${base}:p95`, name: `${base}_p95`, label: `${label} p95`, domain,
      value: p95, unit: 'seconds', attributes: [], observedAt,
    });
  }
  return readings;
}

function histogramPercentile(
  actor: ActorSeries | undefined,
  base: string,
  count: number,
  quantile: number,
): number | null {
  const buckets = (actor?.samples ?? [])
    .filter(sample => sample.metric.__name__ === `${base}_bucket`)
    .map(sample => ({bound: Number(sample.metric.le), count: Number(sample.value[1])}))
    .filter(bucket => Number.isFinite(bucket.count))
    .sort((left, right) => left.bound - right.bound);
  const match = buckets.find(bucket => bucket.count >= count * quantile && Number.isFinite(bucket.bound));
  return match?.bound ?? null;
}

function latestMetricSample(actor: ActorSeries | undefined, name: string): PrometheusSample | null {
  return (actor?.samples ?? [])
    .filter(sample => sample.metric.__name__ === name)
    .reduce<PrometheusSample | null>((latest, sample) =>
      !latest || sample.value[0] >= latest.value[0] ? sample : latest, null);
}

function metricDomain(name: string, event?: string): ActorMetricInventory['readings'][number]['domain'] {
  if (name.startsWith('stacks_miner_signer_')) return 'quorum';
  if (name.startsWith('stacks_signer_')) return 'signer';
  if (name.startsWith('stacks_node_')) return 'chain';
  if (name.startsWith('process_') || name.startsWith('stacks_observability_')) return 'telemetry';
  if (name.includes('object_cache') || event?.startsWith('announcement_') ||
    event?.startsWith('object_') || event?.startsWith('fetch_') || event?.startsWith('direct_push_')) return 'content';
  if (event?.startsWith('sync_') || name.includes('sync_capable')) return 'sync';
  if (name.includes('queue') || name.includes('stall') || name.includes('peer_store') ||
    event?.includes('queue') || event?.startsWith('resource_') || event?.startsWith('peer_store_')) return 'resources';
  return 'transport';
}

function metricUnit(name: string): ActorMetricInventory['readings'][number]['unit'] {
  if (name.endsWith('_bytes')) return 'bytes';
  if (name.includes('timestamp_seconds')) return 'timestamp';
  if (name.endsWith('_seconds')) return 'seconds';
  if (name.includes('_height')) return 'height';
  if (name.includes('_weight')) return 'weight';
  if (name.includes('_status') || name.includes('_state') || name.endsWith('_code')) return 'state';
  return 'count';
}

function humanizeMetric(name: string): string {
  return name
    .replace(/^stacks_(?:p2p|node|signer|miner_signer|observability)_/, '')
    .replace(/_total$/, '')
    .replaceAll('_', ' ');
}

function percentile(values: number[], quantile: number): number {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * quantile) - 1)]!;
}

function projectSignerQuorumRounds(
  actors: Map<string, ActorSeries>,
  expectedActors: ExpectedActor[],
  publicNetwork: PublicNetworkState,
  now: number,
): SignerQuorumRound[] {
  const enrolledSigners = expectedActors
    .filter(actor => actor.role === 'signer' && actor.signerPublicKey)
    .map(actor => ({
      actor,
      publicSigner: publicNetwork.signers.find(signer => signer.publicKey === actor.signerPublicKey),
    }))
    .filter((entry): entry is typeof entry & {publicSigner: NonNullable<typeof entry.publicSigner>} =>
      entry.publicSigner !== undefined);
  const rounds: SignerQuorumRound[] = [];
  for (const miner of expectedActors.filter(actor => actor.role === 'miner')) {
    const series = actors.get(miner.id);
    if (!series) continue;
    const status = activeLabel(series, 'stacks_miner_signer_round_status', 'status');
    const blockHeight = metric(series, 'stacks_miner_signer_round_block_height');
    const startedAtSeconds = metric(series, 'stacks_miner_signer_round_started_timestamp_seconds');
    const thresholdWeight = metric(series, 'stacks_miner_signer_round_threshold_weight');
    const totalWeight = metric(series, 'stacks_miner_signer_round_total_weight');
    const approvedWeight = metric(series, 'stacks_miner_signer_round_approved_weight');
    const rejectedWeight = metric(series, 'stacks_miner_signer_round_rejected_weight');
    const unavailableWeight = metric(series, 'stacks_miner_signer_round_unavailable_weight');
    if (!isRoundStatus(status) || blockHeight === null || startedAtSeconds === null ||
      thresholdWeight === null || totalWeight === null || approvedWeight === null ||
      rejectedWeight === null || unavailableWeight === null) continue;
    const votes: SignerQuorumVote[] = enrolledSigners.map(({actor, publicSigner}) => {
      const key = actor.signerPublicKey!;
      const approved = labeledMetric(series, 'stacks_miner_signer_vote_weight', {
        signer_public_key: key, decision: 'approved',
      });
      const rejected = labeledMetric(series, 'stacks_miner_signer_vote_weight', {
        signer_public_key: key, decision: 'rejected',
      });
      const unavailable = labeledMetric(series, 'stacks_miner_signer_vote_weight', {
        signer_public_key: key, decision: 'unavailable',
      });
      const decision = approved !== null && approved > 0
        ? 'approved' as const
        : rejected !== null && rejected > 0
          ? 'rejected' as const
          : unavailable !== null && unavailable > 0 ? 'unavailable' as const : 'missing' as const;
      const reportedWeight = decision === 'approved'
        ? approved
        : decision === 'rejected' ? rejected : decision === 'unavailable' ? unavailable : null;
      const latencySeconds = decision === 'missing' ? null : labeledMetric(
        series,
        'stacks_miner_signer_vote_latency_seconds',
        {signer_public_key: key, decision},
      );
      return {
        signerPublicKey: key,
        entityName: actor.entityName ?? publicSigner.entityName,
        weight: reportedWeight !== null && reportedWeight > 0 ? reportedWeight : publicSigner.weight,
        decision,
        latencyMs: latencySeconds === null ? null : Math.max(0, latencySeconds * 1_000),
      };
    });
    rounds.push({
      minerActorId: miner.id,
      minerLabel: miner.label,
      blockHeight,
      startedAt: new Date(Math.min(now, startedAtSeconds * 1_000)).toISOString(),
      observedAt: new Date(now).toISOString(),
      status,
      thresholdWeight,
      totalWeight,
      approvedWeight,
      rejectedWeight,
      unavailableWeight,
      votes,
      source: 'authenticated-miner-telemetry',
    });
  }
  rounds.sort((left, right) =>
    right.blockHeight - left.blockHeight || right.startedAt.localeCompare(left.startedAt));
  return rounds;
}

function appendProgressIncident(
  incidents: Incident[],
  nodes: NodeObservation[],
  progress: ProgressAges,
  cadenceSeconds: number,
  now: number,
): void {
  if (nodes.length === 0) return;
  const burnThreshold = Math.max(30, cadenceSeconds * 4);
  const stacksThreshold = Math.max(60, cadenceSeconds * 6);
  if (progress.burnAgeSeconds !== null && progress.burnAgeSeconds > burnThreshold) {
    incidents.push({
      id: 'burnchain-progress',
      severity: 'critical',
      kind: 'burnchain',
      title: 'Canonical burnchain view is not advancing',
      evidence: [
        `burn height has not changed for ${Math.floor(progress.burnAgeSeconds)}s`,
        `configured cadence is ${cadenceSeconds}s; critical threshold is ${burnThreshold}s`,
      ],
      affectedNodes: nodes.map(node => node.id),
      detectedAt: new Date(now).toISOString(),
      status: 'active',
    });
  } else if (progress.stacksAgeSeconds !== null && progress.stacksAgeSeconds > stacksThreshold) {
    incidents.push({
      id: 'stacks-progress',
      severity: 'critical',
      kind: 'signer-quorum',
      title: 'Canonical Stacks state is not advancing',
      evidence: [
        `Stacks tip height has not changed for ${Math.floor(progress.stacksAgeSeconds)}s`,
        `configured cadence is ${cadenceSeconds}s; critical threshold is ${stacksThreshold}s`,
      ],
      affectedNodes: nodes.map(node => node.id),
      detectedAt: new Date(now).toISOString(),
      status: 'active',
    });
  }
}

function projectLinks(
  actors: Map<string, ActorSeries>,
  expectedActors: ExpectedActor[],
  now: number,
): LinkObservation[] {
  const actorForKey = new Map(expectedActors.flatMap(actor =>
    actor.signerPublicKey ? [[actor.signerPublicKey, actor.id] as const] : []));
  const actorForPeer = new Map(expectedActors.flatMap(actor =>
    actor.transportPeerId ? [[actor.transportPeerId, actor.id] as const] : []));
  const reports = new Map<string, Set<string>>();
  const evidence = new Map<string, Set<LinkObservation['evidence'][number]>>();
  for (const [source, actor] of actors) {
    for (const sample of actor.samples) {
      if (Number(sample.value[1]) !== 1) continue;
      if (sample.metric.__name__ === 'stacks_p2p_connected_peer') {
        const target = sample.metric.peer_id && actorForPeer.get(sample.metric.peer_id);
        if (target && target !== source) {
          rememberLinkReport(reports, evidence, source, target, source, 'enrolled-transport-peer');
        }
      } else if (sample.metric.__name__ === 'stacks_p2p_authenticated_signer_link') {
        const target = sample.metric.signer_public_key && actorForKey.get(sample.metric.signer_public_key.toLowerCase());
        if (target && target !== source) {
          rememberLinkReport(reports, evidence, source, target, source, 'authenticated-signer-envelope');
        }
      }
    }
  }
  return [...reports.entries()].map(([key, reportedBy]) => {
    const [source, target] = key.split('|') as [string, string];
    const sourceReportsTarget = reportedBy.has(source);
    const targetReportsSource = reportedBy.has(target);
    return {
      source,
      target,
      transport: 'libp2p',
      direction: sourceReportsTarget && !targetReportsSource ? 'outbound' : 'inbound',
      rttP50Ms: null,
      rttP95Ms: null,
      deliveryP95Ms: null,
      errorRate: null,
      connected: true,
      evidence: [...(evidence.get(key) ?? [])].sort(),
      reportedBy: [...reportedBy].sort(),
      corroborated: sourceReportsTarget && targetReportsSource,
      observedAt: new Date(now).toISOString(),
    };
  });
}

function rememberLinkReport(
  reports: Map<string, Set<string>>,
  evidence: Map<string, Set<LinkObservation['evidence'][number]>>,
  left: string,
  right: string,
  reporter: string,
  evidenceKind: LinkObservation['evidence'][number],
): void {
  const [source, target] = [left, right].sort();
  const key = `${source}|${target}`;
  const values = reports.get(key) ?? new Set<string>();
  values.add(reporter);
  reports.set(key, values);
  const kinds = evidence.get(key) ?? new Set<LinkObservation['evidence'][number]>();
  kinds.add(evidenceKind);
  evidence.set(key, kinds);
}

function enrichPublicNetwork(publicNetwork: PublicNetworkState, actors: ExpectedActor[]): PublicNetworkState {
  const byKey = new Map(actors.flatMap(actor => actor.signerPublicKey ? [[actor.signerPublicKey, actor] as const] : []));
  return {
    ...publicNetwork,
    signers: publicNetwork.signers.map(signer => {
      const actor = byKey.get(signer.publicKey);
      return {
        ...signer,
        entityName: actor?.entityName ?? signer.entityName,
        enrolledActorId: actor?.id ?? null,
      };
    }),
  };
}

function groupByActor(samples: PrometheusSample[]): Map<string, ActorSeries> {
  const actors = new Map<string, ActorSeries>();
  for (const sample of samples) {
    const id = sample.metric.stacks_federation_actor_id;
    const name = sample.metric.__name__;
    const value = Number(sample.value[1]);
    if (!id || !name || !Number.isFinite(value)) continue;
    const actor = actors.get(id) ?? {labels: sample.metric, samples: []};
    actor.samples.push(sample);
    actors.set(id, actor);
  }
  return actors;
}

function metric(actor: ActorSeries | undefined, name: string): number | null {
  const samples = actor?.samples.filter(sample => sample.metric.__name__ === name) ?? [];
  const latest = samples.reduce((result, sample) => sample.value[0] >= result.at
    ? {value: Number(sample.value[1]), at: sample.value[0]}
    : result, {value: Number.NaN, at: 0});
  return Number.isFinite(latest.value) ? latest.value : null;
}

function labeledMetric(
  actor: ActorSeries | undefined,
  name: string,
  labels: Record<string, string>,
): number | null {
  const matching = actor?.samples.filter(sample => sample.metric.__name__ === name &&
    Object.entries(labels).every(([key, value]) => sample.metric[key] === value)) ?? [];
  const latest = matching.reduce((result, sample) => sample.value[0] >= result.at
    ? {value: Number(sample.value[1]), at: sample.value[0]}
    : result, {value: Number.NaN, at: 0});
  return Number.isFinite(latest.value) ? latest.value : null;
}

function sumMetric(actor: ActorSeries | undefined, name: string): number {
  return actor?.samples
    .filter(sample => sample.metric.__name__ === name)
    .reduce((total, sample) => total + Number(sample.value[1]), 0) ?? 0;
}

function labeledCounts(
  actor: ActorSeries | undefined,
  name: string,
  label: 'reason' | 'conflict',
): Array<{label: string; count: number}> {
  return (actor?.samples ?? [])
    .filter(sample => sample.metric.__name__ === name && typeof sample.metric[label] === 'string')
    .map(sample => ({label: sample.metric[label]!, count: Number(sample.value[1])}))
    .filter(item => Number.isFinite(item.count) && item.count > 0)
    .sort((left, right) => right.count - left.count);
}

function activeLabel(actor: ActorSeries | undefined, name: string, label: string): string | null {
  const active = actor?.samples.find(sample =>
    sample.metric.__name__ === name && Number(sample.value[1]) === 1);
  return active?.metric[label] ?? null;
}

function latestTimestamp(actor: ActorSeries | undefined): number {
  return maximum((actor?.samples ?? []).map(sample => sample.value[0] * 1_000));
}

function maximum(values: number[]): number {
  return values.reduce((result, value) => Math.max(result, value), 0);
}

function maximumNullable(values: Array<number | null>): number | null {
  const present = values.filter((value): value is number => value !== null);
  return present.length === 0 ? null : maximum(present);
}

function updateProgressMark(
  previous: ProgressMark | undefined,
  height: number | null,
  reportedChangedAtSeconds: number | null,
  now: number,
): ProgressMark | undefined {
  if (height === null) return previous;
  const reportedMs = reportedChangedAtSeconds !== null && reportedChangedAtSeconds > 0
    ? Math.min(now, reportedChangedAtSeconds * 1_000)
    : null;
  if (!previous || previous.height !== height) return {height, changedAtMs: reportedMs ?? now};
  return reportedMs !== null ? {height, changedAtMs: reportedMs} : previous;
}

function progressAge(mark: ProgressMark | undefined, now: number): number | null {
  return mark ? Math.max(0, (now - mark.changedAtMs) / 1_000) : null;
}

function unixSecondsToIso(value: number | null): string | null {
  return value !== null && value > 0 ? new Date(value * 1_000).toISOString() : null;
}

function boundedRole(value: string | undefined): NodeRole | undefined {
  return value === 'miner' || value === 'signer' || value === 'follower' ||
    value === 'bootstrap' || value === 'companion' || value === 'unknown' ? value : undefined;
}

function boundedRegion(value: string | undefined): CoarseRegion {
  return value === 'north-america' || value === 'south-america' || value === 'europe' ||
    value === 'africa' || value === 'asia-pacific' || value === 'local' ? value : 'unknown';
}

function isRoundStatus(value: string | null): value is SignerQuorumRound['status'] {
  return value === 'collecting' || value === 'approved' || value === 'rejected' ||
    value === 'timed-out';
}
