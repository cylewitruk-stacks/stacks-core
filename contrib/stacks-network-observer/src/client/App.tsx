import {useState} from 'react';
import {AppShell} from '@astryxdesign/core/AppShell';
import {Button} from '@astryxdesign/core/Button';
import {Card} from '@astryxdesign/core/Card';
import {Center} from '@astryxdesign/core/Center';
import {FormLayout} from '@astryxdesign/core/FormLayout';
import {Grid} from '@astryxdesign/core/Grid';
import {HStack} from '@astryxdesign/core/HStack';
import {ProgressBar} from '@astryxdesign/core/ProgressBar';
import {Section} from '@astryxdesign/core/Section';
import {SegmentedControl, SegmentedControlItem} from '@astryxdesign/core/SegmentedControl';
import {StatusDot} from '@astryxdesign/core/StatusDot';
import {Table, pixel, proportional, type TableColumn} from '@astryxdesign/core/Table';
import {Text, Heading} from '@astryxdesign/core/Text';
import {TextInput} from '@astryxdesign/core/TextInput';
import {Timestamp} from '@astryxdesign/core/Timestamp';
import {Token} from '@astryxdesign/core/Token';
import {TopNav, TopNavHeading} from '@astryxdesign/core/TopNav';
import {VStack} from '@astryxdesign/core/VStack';

import type {
  ActorMetricInventory,
  Health,
  Incident,
  LinkObservation,
  NetworkSnapshot,
  NodeObservation,
  PublicPortalSnapshot,
  PublicSafeSigner,
  PublicSigner,
  ReporterState,
  MetricReading,
  SignerQuorumRound,
} from '../shared/model';
import {useSnapshot} from './useSnapshot';

type View = 'overview' | 'topology' | 'signers' | 'metrics' | 'federation';

const NODE_POSITIONS: Record<string, [number, number]> = {
  'miner-alpha': [125, 170], 'signer-cedar': [300, 75], 'signer-ember': [470, 70],
  'signer-orbit': [660, 95], 'companion-east': [350, 225], 'companion-north': [570, 230],
  'follower-atlas': [270, 370], 'follower-boreal': [615, 365], 'bootstrap-one': [790, 285],
};

export function App() {
  const {
    publicSnapshot,
    federationSnapshot,
    principal,
    connected,
    sessionLoading,
    error,
    authError,
    login,
    logout,
  } = useSnapshot();
  const [view, setView] = useState<View>('overview');
  if (!principal) {
    return <PublicPortal
      snapshot={publicSnapshot}
      connected={connected}
      loading={sessionLoading}
      telemetryError={error}
      authError={authError}
      login={login}
    />;
  }
  const snapshot = federationSnapshot;
  const status = snapshot?.summary.health ?? 'unknown';

  return (
    <AppShell
      height="auto"
      variant="surface"
      contentPadding={0}
      topNav={
        <TopNav
          heading={<TopNavHeading logo={<ObserverMark />} heading="Stacks Network Observer" subheading="Federated libp2p operations" />}
          endContent={
            <HStack gap={3} align="center">
              <HStack gap={1.5} align="center">
                <StatusDot variant={connected ? 'success' : 'warning'} label={connected ? 'Live telemetry connected' : 'Telemetry reconnecting'} isPulsing={connected} />
                <Text type="supporting">{connected ? 'Live · 2s' : 'Reconnecting'}</Text>
              </HStack>
              <Token label={snapshot?.summary.network ?? 'Loading network'} color="gray" size="sm" />
              <Text type="supporting">{principal.email}</Text>
              <Button label="Sign out" variant="ghost" size="sm" clickAction={logout} />
            </HStack>
          }
        />
      }
    >
      <VStack className="observer-page" gap={0}>
        <Section variant="muted" padding={4} dividers={['bottom']}>
          <HStack justify="between" align="center" wrap="wrap" gap={3}>
            <VStack gap={1}>
              <HStack gap={2} align="center">
                <StatusDot variant={statusVariant(status)} label={`Network status: ${status}`} isPulsing={status === 'critical'} />
                <Heading level={1}>Network operations</Heading>
                <Token label={status.toUpperCase()} color={statusToken(status)} size="sm" />
              </HStack>
              <Text type="supporting" color="secondary">
                Authenticated actor coverage, chain progress, signer activity, and resource evidence
              </Text>
            </VStack>
            <SegmentedControl value={view} onChange={value => setView(value as View)} label="Operations view" size="sm">
              <SegmentedControlItem value="overview" label="Overview" />
              <SegmentedControlItem value="topology" label="Topology" />
              <SegmentedControlItem value="signers" label="Signers" />
              <SegmentedControlItem value="metrics" label="Metrics" />
              <SegmentedControlItem value="federation" label="Federation" />
            </SegmentedControl>
          </HStack>
        </Section>
        {error && (
          <Section variant="muted" padding={3} dividers={['bottom']}>
            <HStack gap={2} align="center">
              <StatusDot variant="warning" label="Telemetry warning" />
              <Text type="supporting">{error}; the last good snapshot remains visible.</Text>
            </HStack>
          </Section>
        )}
        {!snapshot ? <LoadingState /> : <Dashboard snapshot={snapshot} view={view} />}
      </VStack>
    </AppShell>
  );
}

function PublicPortal({
  snapshot,
  connected,
  loading,
  telemetryError,
  authError,
  login,
}: {
  snapshot: PublicPortalSnapshot | null;
  connected: boolean;
  loading: boolean;
  telemetryError: string | null;
  authError: string | null;
  login(email: string, password: string): Promise<boolean>;
}) {
  return (
    <AppShell
      height="auto"
      variant="surface"
      contentPadding={0}
      topNav={<TopNav
        heading={<TopNavHeading logo={<ObserverMark />} heading="Stacks Network Observer" subheading="Public signer network" />}
        endContent={<HStack gap={2} align="center"><StatusDot variant={connected ? 'success' : 'warning'} label={connected ? 'Public data connected' : 'Public data reconnecting'} /><Token label={snapshot?.summary.network ?? 'Loading'} color="gray" size="sm" /></HStack>}
      />}
    >
      <VStack className="observer-page" gap={0}>
        <Section variant="muted" padding={4} dividers={['bottom']}>
          <VStack gap={1}>
            <Heading level={1}>Public signer network</Heading>
            <Text type="supporting" color="secondary">Public reward-set identity and chain state. Live partner operations require federation sign-in.</Text>
          </VStack>
        </Section>
        {telemetryError && <Section variant="muted" padding={3} dividers={['bottom']}><HStack gap={2} align="center"><StatusDot variant="warning" label="Public data warning" /><Text type="supporting">{telemetryError}</Text></HStack></Section>}
        <VStack gap={4} padding={4}>
          {snapshot && <Grid columns={{minWidth: 190, max: 5, repeat: 'fit'}} gap={3}>
            <Metric label="Burn height" value={formatNumber(snapshot.summary.burnHeight)} detail={snapshot.summary.currentEpoch} tone="blue" />
            <Metric label="Reward cycle" value={String(snapshot.summary.currentRewardCycle ?? '—')} detail="current public cycle" tone="cyan" />
            <Metric label="Signer set" value={String(snapshot.summary.signerCount)} detail="current public members" tone="purple" />
            <Metric label="Signer weight" value={String(snapshot.summary.totalWeight)} detail="current total weight" tone="green" />
            <Metric label="Stacked" value={formatMicroStx(snapshot.summary.totalStackedMicroStx)} detail="current signer set" tone="gray" />
          </Grid>}
          <Grid columns={{minWidth: 440, max: 2, repeat: 'fit'}} gap={4}>
            <Card padding={0} elevation="low">
              <Section padding={4} dividers={['bottom']}><VStack gap={1}><Heading level={3}>Public signer registry</Heading><Text type="supporting" color="secondary">Public keys, entity attribution, weight, stake, and current/next membership</Text></VStack></Section>
              {snapshot ? <PublicSignerTable signers={snapshot.publicNetwork.signers} showEnrollment={false} bare /> : <LoadingState />}
            </Card>
            <OperatorLogin loading={loading} error={authError} login={login} />
          </Grid>
        </VStack>
      </VStack>
    </AppShell>
  );
}

function OperatorLogin({loading, error, login}: {
  loading: boolean;
  error: string | null;
  login(email: string, password: string): Promise<boolean>;
}) {
  const [email, setEmail] = useState('user@host.com');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password);
    } finally {
      setSubmitting(false);
    }
  };
  return (
    <Center>
      <Card padding={6} elevation="low" width="100%">
        <form onSubmit={submit}>
          <FormLayout>
            <VStack gap={1}><Heading level={3}>Federation operator sign-in</Heading><Text type="supporting" color="secondary">Unlock partner telemetry and per-signer quorum reconstruction. The PoC password provider is replaceable with OIDC.</Text></VStack>
            <TextInput type="email" label="Email" value={email} onChange={setEmail} isRequired width="100%" />
            <TextInput type="password" label="Password" value={password} onChange={setPassword} isRequired width="100%" status={error ? {type: 'error', message: error} : undefined} />
            <Button type="submit" label="Open federation operations" variant="primary" width="100%" isLoading={loading || submitting} isDisabled={!email || !password} />
          </FormLayout>
        </form>
      </Card>
    </Center>
  );
}

function Dashboard({snapshot, view}: {snapshot: NetworkSnapshot; view: View}) {
  if (view === 'topology') return <TopologyView snapshot={snapshot} />;
  if (view === 'signers') return <SignerView snapshot={snapshot} />;
  if (view === 'metrics') return <MetricsView snapshot={snapshot} />;
  if (view === 'federation') return <FederationView snapshot={snapshot} />;
  return <Overview snapshot={snapshot} />;
}

function Overview({snapshot}: {snapshot: NetworkSnapshot}) {
  const {summary} = snapshot;
  const signers = snapshot.nodes.filter(node => node.role === 'signer');
  const freshSigners = signers.filter(node => node.health !== 'critical').length;
  return (
    <VStack gap={4} padding={4}>
      <Grid columns={{minWidth: 180, max: 6, repeat: 'fit'}} gap={3}>
        <Metric label="Burn height" value={formatNumber(summary.burnHeight)} detail={`last change ${formatDuration(summary.burnProgressAgeSeconds)} ago`} tone={summary.burnProgressAgeSeconds < 40 ? 'blue' : 'red'} />
        <Metric label="Height-cohort agreement" value={formatPercent(summary.heightAgreement)} detail={`largest same-height node cohort · latest ${formatNumber(summary.stacksHeight)}`} tone={summary.heightAgreement >= 0.9 ? 'green' : 'yellow'} />
        <Metric label="Tip adoption spread" value={snapshot.propagation.length ? `${summary.propagationP95Ms} ms` : '—'} detail={snapshot.propagation.length ? `${formatPercent(snapshot.propagation[0]!.coverage)} enrolled-node coverage` : 'waiting for comparable node tips'} tone={snapshot.propagation.length ? (summary.propagationP95Ms < 1500 ? 'green' : 'red') : 'gray'} />
        <Metric label="Signer telemetry" value={`${freshSigners}/${signers.length}`} detail="independent actor streams fresh" tone="purple" />
        <Metric label="Swarm event-loop lag" value={`${summary.maxSyncLag} s`} detail="max enrolled node" tone={summary.maxSyncLag <= 1 ? 'green' : 'orange'} />
        <Metric label="Oldest queue item" value={`${summary.queueResidenceP95Ms} ms`} detail="network command mailbox" tone={summary.queueResidenceP95Ms < 750 ? 'cyan' : 'red'} />
      </Grid>
      <Grid columns={{minWidth: 440, max: 2, repeat: 'fit'}} gap={4}>
        <Panel title="Enrolled actor map" detail={`${summary.reportingNodes}/${summary.observedNodes} fresh · ${summary.observedLinks} evidence-qualified link(s)`}>
          <NetworkMap nodes={snapshot.nodes} links={snapshot.links} compact />
        </Panel>
        <Panel title="Causal stall analysis" detail="Evidence is classified, never inferred from one metric">
          <IncidentPanel incidents={snapshot.incidents} snapshot={snapshot} />
        </Panel>
        <Panel title="Public signer set" detail="Chain-derived identity, weight, and reward-cycle membership">
          <PublicCyclePanel snapshot={snapshot} />
        </Panel>
        <Panel title="Signer self-observation" detail="Independent activity and bounded local blocking state">
          <SignerActivityPanel nodes={signers} />
        </Panel>
      </Grid>
      <NodeTable nodes={snapshot.nodes} />
    </VStack>
  );
}

function TopologyView({snapshot}: {snapshot: NetworkSnapshot}) {
  return (
    <VStack gap={4} padding={4}>
      <Panel title="Authenticated federation connectivity" detail="Blue edges join current transport PeerIds to unique server-enrolled actors; neutral tethers are configured signer–companion service bindings, not connectivity">
        <NetworkMap nodes={snapshot.nodes} links={snapshot.links} />
      </Panel>
      <Grid columns={{minWidth: 420, max: 2, repeat: 'fit'}} gap={4}>
        <Panel title="Reachability and coverage" detail="Per-actor connection totals, coarse server-assigned region, freshness, and enrolled transport-identity links">
          <ReachabilityPanel snapshot={snapshot} />
        </Panel>
        <Panel title="Block propagation evidence" detail="Latest equal-height adoption spread plus bounded announcement, direct-push, and fetch counters">
          <PropagationWaterfall snapshot={snapshot} />
        </Panel>
      </Grid>
      <NodeTable nodes={snapshot.nodes} />
    </VStack>
  );
}

function SignerView({snapshot}: {snapshot: NetworkSnapshot}) {
  const signers = snapshot.nodes.filter(node => node.role === 'signer');
  const proposals = signers.reduce((total, signer) => total + signer.signerProposals, 0);
  const responses = signers.reduce((total, signer) => total + signer.signerResponses, 0);
  const blocked = signers.filter(signer => signer.blockedOn !== 'none').length;
  const publicSigners = snapshot.publicNetwork.signers;
  const currentCycle = snapshot.publicNetwork.currentRewardCycle;
  const currentWeight = publicSigners
    .filter(signer => currentCycle !== null && signer.rewardCycles.includes(currentCycle))
    .reduce((total, signer) => total + signer.weight, 0);
  return (
    <VStack gap={4} padding={4}>
      <Grid columns={{minWidth: 200, max: 4, repeat: 'fit'}} gap={3}>
        <Metric label="Public signer set" value={String(publicSigners.length)} detail={`cycle ${currentCycle ?? 'unknown'} · ${currentWeight} total weight`} tone="purple" />
        <Metric label="Proposals observed" value={formatNumber(proposals)} detail="sum of signer self-reports" tone="blue" />
        <Metric label="Responses sent" value={formatNumber(responses)} detail="accepted and rejected aggregate" tone="green" />
        <Metric label="Locally blocked" value={String(blocked)} detail="bounded blocked_on state" tone={blocked === 0 ? 'green' : 'orange'} />
      </Grid>
      <PublicSignerTable signers={publicSigners} />
      <SignerQuorumFlightRecorder rounds={snapshot.signerQuorumRounds} />
      <DeferredMinerLifecyclePanel inventories={snapshot.actorMetrics.filter(inventory => inventory.role === 'signer')} />
      <Panel title="Authenticated signer state machines" detail="Public-key identity and on-chain weight enriched with each enrolled signer's bounded local state">
        <SignerStateTable nodes={signers} />
      </Panel>
      <Panel title="Signer-related incidents" detail="Each condition comes from the affected signer's own bounded state">
        <IncidentPanel incidents={snapshot.incidents.filter(item => item.affectedNodes.some(id => signers.some(signer => signer.id === id)))} empty="No signer incident is active." />
      </Panel>
    </VStack>
  );
}

interface DeferredLifecycleRow extends Record<string, unknown> {
  actorId: string;
  signer: string;
  admitted: number;
  pending: number;
  released: number;
  expired: number;
  negative: number;
  observations: string;
  policyRejected: number;
  conserved: boolean;
}

function DeferredMinerLifecyclePanel({inventories}: {inventories: ActorMetricInventory[]}) {
  const data: DeferredLifecycleRow[] = inventories.map(inventory => {
    const admitted = metricValue(inventory, 'stacks_signer_deferred_miner_authorizations_admitted_total');
    const pending = metricValue(inventory, 'stacks_signer_deferred_miner_authorizations_pending');
    const released = attributedMetricValue(inventory, 'stacks_signer_deferred_miner_authorizations_resolved_total', 'resolution', 'released');
    const expired = attributedMetricValue(inventory, 'stacks_signer_deferred_miner_authorizations_resolved_total', 'resolution', 'expired');
    const negative = ['unauthorized', 'redundant', 'binding_failed', 'malformed']
      .reduce((total, resolution) => total + attributedMetricValue(
        inventory,
        'stacks_signer_deferred_miner_authorizations_resolved_total',
        'resolution',
        resolution,
      ), 0);
    return {
      actorId: inventory.actorId,
      signer: inventory.actorLabel,
      admitted,
      pending,
      released,
      expired,
      negative,
      observations: `${attributedMetricValue(inventory, 'stacks_signer_deferred_miner_authorization_observations_total', 'observation', 'delivered')} / ${attributedMetricValue(inventory, 'stacks_signer_deferred_miner_authorization_observations_total', 'observation', 'retry')}`,
      policyRejected: metricValue(inventory, 'stacks_signer_block_policy_rejections_total'),
      conserved: admitted === pending + released + expired + negative,
    };
  });
  const columns: TableColumn<DeferredLifecycleRow>[] = [
    {key: 'signer', header: 'Signer', width: proportional(1.5)},
    {key: 'admitted', header: 'Deferred', width: pixel(100), align: 'end'},
    {key: 'pending', header: 'Pending', width: pixel(90), align: 'end'},
    {key: 'released', header: 'Released', width: pixel(100), align: 'end'},
    {key: 'expired', header: 'Expired', width: pixel(90), align: 'end'},
    {key: 'negative', header: 'Negative', width: pixel(100), align: 'end'},
    {key: 'observations', header: 'Observed / retry', width: pixel(140), align: 'end'},
    {key: 'policyRejected', header: 'Policy rejects', width: pixel(120), align: 'end'},
    {key: 'conserved', header: 'Accounting', width: pixel(120), renderCell: row => <Token label={row.conserved ? 'conserved' : 'mismatch'} color={row.conserved ? 'green' : 'red'} size="sm" />},
  ];
  return (
    <Card padding={0} elevation="low">
      <Section padding={4} dividers={['bottom']}>
        <VStack gap={1}>
          <Heading level={3}>Canonical-view deferral lifecycle</Heading>
          <Text type="supporting" color="secondary">Process-generation counters prove whether held envelopes release, expire, or resolve negatively; policy rejects occur before companion validation.</Text>
        </VStack>
      </Section>
      <Table data={data} columns={columns} idKey="actorId" density="compact" dividers="rows" isStriped textOverflow="truncate" />
    </Card>
  );
}

function MetricsView({snapshot}: {snapshot: NetworkSnapshot}) {
  const [actor, setActor] = useState('all');
  const visible = actor === 'all'
    ? snapshot.actorMetrics
    : snapshot.actorMetrics.filter(inventory => inventory.actorId === actor);
  const readings = visible.flatMap(inventory => inventory.readings.map(reading => ({inventory, reading})));
  const connections = sumReadings(snapshot.actorMetrics, 'stacks_p2p_connections');
  const contentReceived = sumEvent(snapshot.actorMetrics, 'announcement_received') +
    sumEvent(snapshot.actorMetrics, 'direct_push_received') +
    sumEvent(snapshot.actorMetrics, 'object_received');
  const deliveryFailures = sumEvent(snapshot.actorMetrics, 'fetch_failed') +
    sumEvent(snapshot.actorMetrics, 'direct_push_failed') + sumEvent(snapshot.actorMetrics, 'sync_failed');
  const signerResponseP95 = maximumReading(
    snapshot.actorMetrics,
    'stacks_signer_block_response_latencies_histogram_p95',
  );
  return (
    <VStack gap={4} padding={4}>
      <Grid columns={{minWidth: 200, max: 4, repeat: 'fit'}} gap={3}>
        <Metric label="Native connections" value={formatNumber(connections)} detail="sum across enrolled actors" tone="blue" />
        <Metric label="Content delivery events" value={formatNumber(contentReceived)} detail="cumulative announcements + pushes + objects" tone="cyan" />
        <Metric label="Delivery failures" value={formatNumber(deliveryFailures)} detail="cumulative fetch + push + sync failures" tone={deliveryFailures === 0 ? 'green' : 'orange'} />
        <Metric label="Signer response p95" value={signerResponseP95 === null ? '—' : formatMetricValue(signerResponseP95, 'seconds')} detail="lifetime maximum across enrolled actors" tone="purple" />
      </Grid>
      <Grid columns={{minWidth: 440, max: 2, repeat: 'fit'}} gap={4}>
        <Panel title="Block propagation" detail="Height adoption is identity-free; counters describe the native delivery path without claiming a per-block causal trace">
          <PropagationWaterfall snapshot={snapshot} />
        </Panel>
        <Panel title="Collection boundary" detail="Only exact allowlisted metrics and bounded labels reach this authenticated catalogue">
          <VStack gap={3}>
            <SignalCheck label="Actor streams" value={`${snapshot.summary.reportingNodes}/${snapshot.actorMetrics.length} fresh`} healthy={snapshot.summary.reportingNodes === snapshot.actorMetrics.length} />
            <SignalCheck label="Metric readings" value={`${formatNumber(snapshot.actorMetrics.reduce((total, inventory) => total + inventory.readings.length, 0))} projected`} healthy={readings.length > 0} />
            <SignalCheck label="Endpoint identifiers" value="not collected" healthy />
            <Text type="supporting" color="secondary">Histogram buckets are aggregated into sample count, mean, and p95. One-hot state series and bounded event reasons remain individually visible.</Text>
          </VStack>
        </Panel>
      </Grid>
      <Card padding={0} elevation="low">
        <Section padding={4} dividers={['bottom']}>
          <VStack gap={3}>
            <VStack gap={1}><Heading level={3}>Authenticated metric catalogue</Heading><Text type="supporting" color="secondary">Every currently available node and signer metric, grouped by server-enrolled actor; missing series remain absent rather than becoming zero.</Text></VStack>
            <SegmentedControl value={actor} onChange={setActor} label="Metric actor" size="sm">
              <SegmentedControlItem value="all" label="All actors" />
              {snapshot.actorMetrics.map(inventory => <SegmentedControlItem key={inventory.actorId} value={inventory.actorId} label={inventory.actorLabel} />)}
            </SegmentedControl>
          </VStack>
        </Section>
        <MetricCatalogueTable inventories={visible} />
      </Card>
    </VStack>
  );
}

interface MetricRow extends Record<string, unknown> {
  id: string;
  actor: string;
  role: string;
  domain: string;
  metric: string;
  attributes: string;
  value: string;
  observedAt: string;
}

function MetricCatalogueTable({inventories}: {inventories: ActorMetricInventory[]}) {
  const data: MetricRow[] = inventories.flatMap(inventory => inventory.readings.map(reading => ({
    id: `${inventory.actorId}:${reading.id}`,
    actor: inventory.actorLabel,
    role: inventory.role,
    domain: reading.domain,
    metric: reading.label,
    attributes: reading.attributes.map(attribute => `${attribute.key}=${attribute.value}`).join(' · ') || '—',
    value: formatMetricValue(reading.value, reading.unit),
    observedAt: reading.observedAt,
  })));
  const columns: TableColumn<MetricRow>[] = [
    {key: 'actor', header: 'Actor', width: proportional(1), renderCell: row => <HStack gap={2} align="center"><Token label={row.role} color={roleToken(row.role)} size="sm" /><Text type="label">{row.actor}</Text></HStack>},
    {key: 'domain', header: 'Domain', width: pixel(110), renderCell: row => <Token label={row.domain} color="gray" size="sm" />},
    {key: 'metric', header: 'Metric', width: proportional(1.5)},
    {key: 'attributes', header: 'Bounded attributes', width: proportional(1.7), renderCell: row => <Text type="code">{row.attributes}</Text>},
    {key: 'value', header: 'Value', width: pixel(130), align: 'end', renderCell: row => <Text type="code" hasTabularNumbers>{row.value}</Text>},
    {key: 'observedAt', header: 'Received', width: pixel(120), renderCell: row => <Timestamp value={row.observedAt} format="relative" />},
  ];
  return <Table data={data} columns={columns} idKey="id" density="compact" dividers="rows" isStriped hasHover textOverflow="truncate" />;
}

function SignerQuorumFlightRecorder({rounds}: {rounds: SignerQuorumRound[]}) {
  const round = rounds[0];
  if (!round) {
    return <Card padding={4} elevation="low"><VStack gap={1}><Heading level={3}>Signer quorum flight recorder</Heading><Text type="supporting" color="secondary">No bounded miner round has arrived through authenticated telemetry.</Text></VStack></Card>;
  }
  const responded = round.votes.filter(vote => vote.decision !== 'missing').length;
  return (
    <VStack gap={3}>
      <Grid columns={{minWidth: 190, max: 5, repeat: 'fit'}} gap={3}>
        <Metric label="Latest round" value={round.status} detail={`${round.minerLabel} · block ${formatNumber(round.blockHeight)}`} tone={round.status === 'approved' ? 'green' : round.status === 'collecting' ? 'blue' : 'red'} />
        <Metric label="Approval weight" value={`${round.approvedWeight}/${round.thresholdWeight}`} detail={`${round.totalWeight} total signer weight`} tone={round.approvedWeight >= round.thresholdWeight ? 'green' : 'yellow'} />
        <Metric label="Rejection weight" value={String(round.rejectedWeight)} detail="authenticated weighted responses" tone={round.rejectedWeight === 0 ? 'gray' : 'red'} />
        <Metric label="Unavailable weight" value={String(round.unavailableWeight)} detail="temporary; never rejection weight" tone={round.unavailableWeight === 0 ? 'gray' : 'yellow'} />
        <Metric label="Responses" value={`${responded}/${round.votes.length}`} detail={`round started ${formatRelativeAge(round.startedAt)} ago`} tone={responded === round.votes.length ? 'green' : 'orange'} />
      </Grid>
      <Card padding={0} elevation="low">
        <Section padding={4} dividers={['bottom']}><VStack gap={1}><HStack gap={2} align="center"><Heading level={3}>Signer quorum flight recorder</Heading><Token label={round.status} color={quorumStatusToken(round.status)} size="sm" /></HStack><Text type="supporting" color="secondary">Latest bounded miner reconstruction · public identity and weight joined to authenticated decision and latency</Text></VStack></Section>
        <SignerQuorumTable round={round} />
      </Card>
    </VStack>
  );
}

interface SignerQuorumRow extends Record<string, unknown> {
  publicKey: string;
  signer: string;
  decision: string;
  weight: number;
  latency: string;
}

function SignerQuorumTable({round}: {round: SignerQuorumRound}) {
  const data: SignerQuorumRow[] = round.votes.map(vote => ({
    publicKey: vote.signerPublicKey,
    signer: `${vote.entityName ?? 'Unknown entity'} · ${shortKey(vote.signerPublicKey)}`,
    decision: vote.decision,
    weight: vote.weight,
    latency: vote.latencyMs === null ? '—' : `${Math.round(vote.latencyMs)} ms`,
  }));
  const columns: TableColumn<SignerQuorumRow>[] = [
    {key: 'signer', header: 'Signer', width: proportional(1.8)},
    {key: 'decision', header: 'Decision', width: pixel(120), renderCell: row => <Token label={row.decision} color={voteDecisionToken(row.decision)} size="sm" />},
    {key: 'weight', header: 'Weight', width: pixel(90), align: 'end'},
    {key: 'latency', header: 'Response latency', width: pixel(150), align: 'end'},
    {key: 'publicKey', header: 'Public key', width: proportional(2), renderCell: row => <Text type="code">{row.publicKey}</Text>},
  ];
  return <Table data={data} columns={columns} idKey="publicKey" density="compact" dividers="rows" isStriped textOverflow="truncate" />;
}

function FederationView({snapshot}: {snapshot: NetworkSnapshot}) {
  return (
    <VStack gap={4} padding={4}>
      <Grid columns={{minWidth: 220, max: 4, repeat: 'fit'}} gap={3}>
        <Metric label="Fresh actors" value={`${snapshot.summary.reportingNodes}/${snapshot.reporters.length}`} detail="within the 20s evidence window" tone="green" />
        <Metric label="Enrolled actors" value={String(snapshot.summary.observedNodes)} detail="server-assigned identities" tone="blue" />
        <Metric label="Enrolled links" value={String(snapshot.links.length)} detail={`${snapshot.links.filter(link => link.corroborated).length} corroborated`} tone="cyan" />
        <Metric label="Privacy posture" value="Endpoint-free" detail="exact metric and label allowlist" tone="purple" />
      </Grid>
      <ReporterTable reporters={snapshot.reporters} />
      <Grid columns={{minWidth: 420, max: 2, repeat: 'fit'}} gap={4}>
        <Panel title="Trust boundary" detail="Partner telemetry is authenticated but remains untrusted evidence">
          <VStack gap={3}>
            <EvidenceStep number="01" title="Private scrape" detail="One isolated actor agent reads only its node or signer Prometheus endpoint." />
            <EvidenceStep number="02" title="Authenticated OTLP" detail="A bearer token is valid only on that actor's isolated central receiver route." />
            <EvidenceStep number="03" title="Server authority" detail="The central pipeline deletes resource attributes and writes actor identity, role, chain, and region." />
            <EvidenceStep number="04" title="Public enrichment" detail="Signer public keys and weights are independently loaded from current/next on-chain reward sets." />
            <EvidenceStep number="05" title="Bounded query" detail="The observer runs one reviewed Prometheus query; missing or stale actors remain explicit blind spots." />
          </VStack>
        </Panel>
        <Panel title="Coverage limits" detail="What this topology can and cannot claim">
          <VStack gap={3}>
            <Coverage label="Reporter freshness" value={snapshot.summary.reportingNodes / Math.max(snapshot.reporters.length, 1)} />
            <Coverage label="Height-cohort agreement" value={snapshot.summary.heightAgreement} />
            <Coverage label="Latest propagation coverage" value={snapshot.propagation[0]?.coverage ?? 0} />
            <Text type="supporting" color="secondary">Edges join bounded transport PeerIds to unique server-enrolled actors. Endpoints, hostnames, fine-grained locations, and unknown external peer identities are not projected to the client.</Text>
          </VStack>
        </Panel>
      </Grid>
    </VStack>
  );
}

function Panel({title, detail, children}: {title: string; detail: string; children: React.ReactNode}) {
  return (
    <Card padding={0} elevation="low" height="100%">
      <Section padding={4} dividers={['bottom']}>
        <VStack gap={1}>
          <Heading level={3}>{title}</Heading>
          <Text type="supporting" color="secondary">{detail}</Text>
        </VStack>
      </Section>
      <Section padding={4}>{children}</Section>
    </Card>
  );
}

function Metric({label, value, detail, tone}: {label: string; value: string; detail: string; tone: React.ComponentProps<typeof Card>['variant']}) {
  return (
    <Card padding={4} variant={tone} height="100%">
      <VStack gap={2}>
        <Text type="label" color="secondary">{label}</Text>
        <Text type="display-3" weight="semibold" hasTabularNumbers>{value}</Text>
        <Text type="supporting" color="secondary">{detail}</Text>
      </VStack>
    </Card>
  );
}

function NetworkMap({nodes, links, compact = false}: {nodes: NodeObservation[]; links: LinkObservation[]; compact?: boolean}) {
  const positions = topologyPositions(nodes);
  const companionBindings = nodes.filter(node => node.companionActorId && positions.has(node.companionActorId));
  const [focusedNode, setFocusedNode] = useState<string | null>(null);
  return (
    <VStack gap={3}>
      <svg className={compact ? 'topology topology--compact' : 'topology'} viewBox="0 0 900 450" role="img" aria-label="Authenticated federation actors and observed libp2p connectivity">
        <defs>
          <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="7" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>
        {companionBindings.map(signer => {
          const start = positions.get(signer.id)!;
          const end = positions.get(signer.companionActorId!)!;
          const isFocused = focusedNode === signer.id || focusedNode === signer.companionActorId;
          return <line key={`companion-${signer.id}`} className={`topology__binding${focusedNode ? isFocused ? ' topology__binding--focused' : ' topology__binding--muted' : ''}`} x1={start[0]} y1={start[1]} x2={end[0]} y2={end[1]}><title>Configured signer–companion service binding; not connectivity evidence</title></line>;
        })}
        {links.map(link => {
          const start = positions.get(link.source);
          const end = positions.get(link.target);
          if (!start || !end) return null;
          const isFocused = focusedNode === link.source || focusedNode === link.target;
          return (
            <line
              key={`${link.source}-${link.target}`}
              className={`topology__link topology__link--${link.transport} topology__link--${link.corroborated ? 'corroborated' : 'reported'}${focusedNode ? isFocused ? ' topology__link--focused' : ' topology__link--muted' : ''}`}
              x1={start[0]}
              y1={start[1]}
              x2={end[0]}
              y2={end[1]}
            >
              <title>{`${link.corroborated ? 'Corroborated by both actors' : `Reported by ${link.reportedBy.join(', ')}`} · ${link.evidence.join(', ')}`}</title>
            </line>
          );
        })}
        {nodes.map(node => {
          const [x, y] = positions.get(node.id)!;
          const peers = peerTotal(node);
          return (
            <g key={node.id} className={`topology__node topology__node--${node.health}${focusedNode && focusedNode !== node.id ? ' topology__node--muted' : ''}`} transform={`translate(${x} ${y})`} tabIndex={0} aria-label={`${node.signerEntityName ?? node.label}, ${node.role}, ${formatOptionalNumber(peers)} connections`} onMouseEnter={() => setFocusedNode(node.id)} onMouseLeave={() => setFocusedNode(null)} onFocus={() => setFocusedNode(node.id)} onBlur={() => setFocusedNode(null)}>
              <title>{`${node.signerEntityName ?? node.label} · ${node.role} · ${node.region} · ${formatOptionalNumber(peers)} connections`}</title>
              <circle className="topology__halo" r="25" />
              <circle className={`topology__dot topology__dot--${node.role}`} r="19" filter={node.role === 'miner' ? 'url(#node-glow)' : undefined} />
              <text className="topology__node-code" textAnchor="middle" dominantBaseline="central">{topologyNodeLabel(node)}</text>
            </g>
          );
        })}
      </svg>
      <HStack gap={3} wrap="wrap">
        <RoleLegend role="miner" label="Miner" /><RoleLegend role="signer" label="Signer" />
        <RoleLegend role="companion" label="Companion" /><RoleLegend role="follower" label="Follower" />
        <RelationshipLegend label="Configured companion binding" />
        <Token label="Edges · enrolled transport identity" color="gray" size="sm" />
        <Token label="Solid · corroborated" color="blue" size="sm" /><Token label="Dashed · one-sided report" color="gray" size="sm" />
        <Token label="Focus actor · isolate its paths" color="gray" size="sm" />
      </HStack>
    </VStack>
  );
}

function topologyPositions(nodes: NodeObservation[]): Map<string, [number, number]> {
  if (nodes.every(node => NODE_POSITIONS[baseNodeId(node.id)])) {
    return new Map(nodes.map(node => [node.id, NODE_POSITIONS[baseNodeId(node.id)]!]));
  }
  const ordered = [...nodes].sort((left, right) => topologyOrder(left) - topologyOrder(right) || left.id.localeCompare(right.id));
  if (ordered.length === 1) return new Map([[ordered[0]!.id, [450, 225]]]);
  return new Map(ordered.map((node, index) => {
    const angle = -Math.PI / 2 + index * Math.PI * 2 / ordered.length;
    return [node.id, [450 + Math.cos(angle) * 330, 225 + Math.sin(angle) * 155]];
  }));
}

function topologyOrder(node: NodeObservation): number {
  const ordinal = Number(node.id.match(/(\d+)$/)?.[1] ?? 0);
  if (node.role === 'miner') return ordinal;
  if (node.role === 'signer') return 100 + ordinal * 2;
  if (node.role === 'companion') return 101 + ordinal * 2;
  if (node.role === 'follower') return 1_000 + ordinal;
  if (node.role === 'bootstrap') return 2_000 + ordinal;
  return 3_000 + ordinal;
}

function topologyNodeLabel(node: NodeObservation): string {
  const rolePrefix: Record<NodeObservation['role'], string> = {
    miner: 'M',
    signer: 'S',
    companion: 'C',
    follower: 'F',
    bootstrap: 'B',
    unknown: '?',
  };
  const ordinal = node.id.match(/(\d+)$/)?.[1] ?? '';
  return `${rolePrefix[node.role]}${ordinal}`;
}

function PropagationWaterfall({snapshot}: {snapshot: NetworkSnapshot}) {
  const trace = snapshot.propagation[0];
  if (!trace) return <Text type="supporting">No propagation trace is available.</Text>;
  const max = Math.max(1, ...trace.hops.map(hop => hop.validatedMs));
  return (
    <VStack gap={3}>
      <HStack justify="between" align="center">
        <HStack gap={2} align="center"><Token label={trace.objectKind} color="blue" size="sm" /><Text type="code">{trace.publicBlockId ?? trace.objectId}</Text></HStack>
        <Text type="supporting" hasTabularNumbers>{formatPercent(trace.coverage)} coverage · {trace.p95Ms} ms p95</Text>
      </HStack>
      <VStack gap={2}>
        {trace.hops.map(hop => (
          <HStack key={hop.nodeId} gap={3} align="center" className="waterfall-row">
            <Text type="supporting" className="waterfall-label" maxLines={1}>{labelFor(snapshot, hop.nodeId)}</Text>
            <svg className="waterfall-track" viewBox="0 0 600 18" preserveAspectRatio="none" aria-label={`${hop.nodeId} validated in ${hop.validatedMs} milliseconds`}>
              <line className="waterfall-base" x1="0" y1="9" x2="600" y2="9" />
              <line className={`waterfall-value waterfall-value--${hop.source}`} x1="0" y1="9" x2={Math.max(5, hop.validatedMs / max * 600)} y2="9" />
              <circle className="waterfall-marker" cx={hop.validatedMs / max * 600} cy="9" r="4" />
            </svg>
            <Text type="code" hasTabularNumbers className="waterfall-time">{hop.validatedMs}ms</Text>
          </HStack>
        ))}
      </VStack>
      <HStack gap={2} wrap="wrap">
        <Token label="Accepted tip observation" color="blue" size="sm" />
        <Text type="supporting" color="secondary">Actors are compared only at the same Stacks height. This measures adoption spread; without a block-ID metric it does not distinguish same-height forks.</Text>
      </HStack>
    </VStack>
  );
}

function SignerActivityPanel({nodes, expanded = false}: {nodes: NodeObservation[]; expanded?: boolean}) {
  if (!nodes.length) return <Text type="supporting">No enrolled signer telemetry is available.</Text>;
  const columns = expanded ? {minWidth: 280, max: 3, repeat: 'fit' as const} : {minWidth: 220, max: 3, repeat: 'fit' as const};
  return (
    <Grid columns={columns} gap={3}>
        {nodes.map(node => (
          <Card key={node.id} variant={node.health === 'healthy' ? 'green' : node.health === 'critical' ? 'red' : 'yellow'} padding={3}>
            <VStack gap={2}>
              <HStack justify="between" align="center"><Text type="label">{node.signerEntityName ?? node.label}</Text><Token label={node.signerState?.lifecycle ?? 'unknown'} color={signerStateToken(node.signerState?.lifecycle)} size="sm" /></HStack>
              <Text type="code" color="secondary" maxLines={1}>{shortKey(node.signerPublicKey)}</Text>
              <HStack gap={2} align="center"><StatusDot variant={statusVariant(node.health)} label={node.health} /><Text type="supporting">{node.signerWeight ?? '—'} wt · {formatNumber(node.signerProposals)} proposals · {formatNumber(node.signerResponses)} responses</Text></HStack>
            </VStack>
          </Card>
        ))}
      </Grid>
  );
}

function PublicCyclePanel({snapshot}: {snapshot: NetworkSnapshot}) {
  const {publicNetwork} = snapshot;
  if (!publicNetwork.rewardCycles.length) {
    return <Text type="supporting">Public reward-set data is unavailable.</Text>;
  }
  return (
    <VStack gap={3}>
      <HStack gap={2} wrap="wrap">
        <Token label={publicNetwork.currentEpoch} color="blue" size="sm" />
        <Token label={`burn ${publicNetwork.burnHeight}`} color="gray" size="sm" />
        <Token label={publicNetwork.health} color={statusToken(publicNetwork.health)} size="sm" />
      </HStack>
      {publicNetwork.rewardCycles.map(cycle => (
        <HStack key={`${cycle.phase}-${cycle.id}`} justify="between" align="center" gap={3}>
          <HStack gap={2} align="center">
            <StatusDot variant={cycle.status === 'available' ? 'success' : cycle.status === 'pending' ? 'warning' : 'error'} label={cycle.status} />
            <Text type="label">{cycle.phase === 'current' ? 'Current' : 'Next'} cycle {cycle.id}</Text>
          </HStack>
          <Text type="supporting" color="secondary" hasTabularNumbers>{cycle.signerKeys.length} signer(s) · {cycle.totalWeight} weight</Text>
        </HStack>
      ))}
    </VStack>
  );
}

interface PublicSignerRow extends Record<string, unknown> {
  publicKey: string;
  entity: string;
  weight: number;
  stacked: string;
  cycles: string;
  enrollment: string;
}

function PublicSignerTable({
  signers,
  showEnrollment = true,
  bare = false,
}: {
  signers: Array<PublicSigner | PublicSafeSigner>;
  showEnrollment?: boolean;
  bare?: boolean;
}) {
  const data: PublicSignerRow[] = signers.map(signer => ({
    publicKey: signer.publicKey,
    entity: signer.entityName ?? 'Unknown entity',
    weight: signer.weight,
    stacked: formatMicroStx(signer.stackedAmountMicroStx),
    cycles: signer.rewardCycles.join(', '),
    enrollment: 'enrolledActorId' in signer ? signer.enrolledActorId ?? 'public only' : 'restricted',
  }));
  const columns: TableColumn<PublicSignerRow>[] = [
    {key: 'entity', header: 'Entity', width: proportional(1), renderCell: row => <Text type="label">{row.entity}</Text>},
    {key: 'publicKey', header: 'Signer public key', width: proportional(1.8), renderCell: row => <Text type="code">{row.publicKey}</Text>},
    {key: 'weight', header: 'Weight', width: pixel(90), align: 'end'},
    {key: 'stacked', header: 'Stacked STX', width: pixel(140), align: 'end'},
    {key: 'cycles', header: 'Cycle(s)', width: pixel(100)},
    ...(showEnrollment ? [{key: 'enrollment', header: 'Telemetry actor', width: proportional(1), renderCell: (row: PublicSignerRow) => <Token label={row.enrollment} color={row.enrollment === 'public only' ? 'gray' : 'green'} size="sm" />} satisfies TableColumn<PublicSignerRow>] : []),
  ];
  const table = <Table data={data} columns={columns} idKey="publicKey" density="compact" dividers="rows" isStriped textOverflow="truncate" />;
  if (bare) return table;
  return (
    <Card padding={0} elevation="low">
      <Section padding={4} dividers={['bottom']}><VStack gap={1}><Heading level={3}>Public signer registry</Heading><Text type="supporting" color="secondary">Current/next reward-set membership from the public Stacks API; entity attribution and enrollment are server-owned metadata</Text></VStack></Section>
      {table}
    </Card>
  );
}

interface SignerStateRow extends Record<string, unknown> {
  id: string;
  signer: string;
  lifecycle: string;
  minerState: string;
  cycle: string;
  burnHeight: string;
  protocol: string;
  changed: string;
  activity: string;
  transitions: string;
  conflicts: string;
}

function SignerStateTable({nodes}: {nodes: NodeObservation[]}) {
  const data: SignerStateRow[] = nodes.map(node => ({
    id: node.id,
    signer: `${node.signerEntityName ?? node.label} · ${shortKey(node.signerPublicKey)}`,
    lifecycle: node.signerState?.lifecycle ?? 'unknown',
    minerState: node.signerState?.minerState ?? 'unknown',
    cycle: formatOptionalNumber(node.signerState?.rewardCycle ?? null),
    burnHeight: formatOptionalNumber(node.signerState?.burnBlockHeight ?? null),
    protocol: formatOptionalNumber(node.signerState?.protocolVersion ?? null),
    changed: node.signerState?.lastChangedAt ?? '',
    activity: `${formatNumber(node.signerProposals)} / ${formatNumber(node.signerResponses)}`,
    transitions: formatLabeledCounts(node.signerState?.transitionCounts ?? [], 'reason'),
    conflicts: formatLabeledCounts(node.signerState?.conflictCounts ?? [], 'conflict'),
  }));
  const columns: TableColumn<SignerStateRow>[] = [
    {key: 'signer', header: 'Signer', width: proportional(1.5)},
    {key: 'lifecycle', header: 'Lifecycle', width: pixel(120), renderCell: row => <Token label={row.lifecycle} color={signerStateToken(row.lifecycle)} size="sm" />},
    {key: 'minerState', header: 'Miner view', width: pixel(130)},
    {key: 'cycle', header: 'Cycle', width: pixel(70), align: 'end'},
    {key: 'burnHeight', header: 'Burn view', width: pixel(90), align: 'end'},
    {key: 'protocol', header: 'Protocol', width: pixel(80), align: 'end'},
    {key: 'changed', header: 'State changed', width: pixel(130), renderCell: row => row.changed ? <Timestamp value={row.changed} format="relative" /> : <Text type="supporting">—</Text>},
    {key: 'activity', header: 'Proposals / responses', width: pixel(160), align: 'end'},
    {key: 'transitions', header: 'Transitions', width: proportional(1.2)},
    {key: 'conflicts', header: 'Conflicts', width: proportional(1)},
  ];
  return <Table data={data} columns={columns} idKey="id" density="compact" dividers="rows" isStriped textOverflow="truncate" />;
}

function IncidentPanel({incidents, empty = 'No causal stall is active.', snapshot}: {incidents: Incident[]; empty?: string; snapshot?: NetworkSnapshot}) {
  const active = incidents.filter(item => item.status !== 'resolved');
  if (!active.length) {
    return <VStack gap={4}>
      <HStack gap={2} align="center"><StatusDot variant="success" label="No active stall" /><Text>{empty}</Text></HStack>
      {snapshot && (
        <VStack gap={3}>
          <SignalCheck label="Federation coverage" value={`${snapshot.summary.reportingNodes} reporter(s) fresh`} healthy={snapshot.summary.reportingNodes > 0} />
          <SignalCheck label="Network mailboxes" value={`${snapshot.summary.queueResidenceP95Ms} ms oldest item`} healthy={snapshot.summary.queueResidenceP95Ms < 750} />
          <SignalCheck label="Signer actors" value={`${snapshot.nodes.filter(node => node.role === 'signer' && node.health !== 'critical').length} fresh`} healthy={snapshot.nodes.filter(node => node.role === 'signer').every(node => node.health !== 'critical')} />
          <SignalCheck label="Tip adoption spread" value={snapshot.propagation.length ? `${snapshot.summary.propagationP95Ms} ms p95` : 'no comparable observations'} healthy={snapshot.propagation.length === 0 || snapshot.summary.propagationP95Ms < 3000} />
          <SignalCheck label="Swarm event loop" value={`${snapshot.summary.maxSyncLag} s max lag`} healthy={snapshot.summary.maxSyncLag <= 3} />
        </VStack>
      )}
    </VStack>;
  }
  return (
    <VStack gap={4}>
      {active.map(item => (
        <VStack key={item.id} gap={2}>
          <HStack gap={2} align="center" wrap="wrap">
            <StatusDot variant={item.severity === 'critical' ? 'error' : 'warning'} label={item.severity} isPulsing={item.severity === 'critical'} />
            <Heading level={4}>{item.title}</Heading>
            <Token label={item.kind} color={item.severity === 'critical' ? 'red' : 'yellow'} size="sm" />
          </HStack>
          {item.evidence.map(evidence => <Text key={evidence} type="supporting" color="secondary">• {evidence}</Text>)}
          <Text type="supporting"><Timestamp value={item.detectedAt} format="relative" /> · {item.affectedNodes.length || 'no'} directly affected node(s)</Text>
        </VStack>
      ))}
    </VStack>
  );
}

interface NodeRow extends Record<string, unknown> {
  id: string; node: string; role: string; status: Health; tip: string; tipObservedAt: string; peers: string; dht: string; queue: string; blocked: string; transport: string;
}

function NodeTable({nodes}: {nodes: NodeObservation[]}) {
  const data: NodeRow[] = nodes.map(node => ({id: node.id, node: node.signerEntityName ?? node.label, role: node.role, status: node.health, tip: formatNumber(node.stacksHeight), tipObservedAt: node.stacksTipObservedAt ?? '', peers: formatOptionalNumber(peerTotal(node)), dht: formatOptionalNumber(node.dhtPeers), queue: `${node.queueResidenceP95Ms}ms`, blocked: node.blockedOn, transport: node.transport}));
  const columns: TableColumn<NodeRow>[] = [
    {key: 'node', header: 'Node', width: proportional(1.4), renderCell: row => <HStack gap={2} align="center"><StatusDot variant={statusVariant(row.status)} label={row.status} /><Text type="label">{row.node}</Text></HStack>},
    {key: 'role', header: 'Role', width: pixel(100), renderCell: row => <Token label={row.role} color={roleToken(row.role)} size="sm" />},
    {key: 'tip', header: 'Observed node tip', width: pixel(130), renderCell: row => <Text type="code" hasTabularNumbers>{row.tip}</Text>},
    {key: 'tipObservedAt', header: 'Tip observed', width: pixel(120), renderCell: row => row.tipObservedAt ? <Timestamp value={row.tipObservedAt} format="relative" /> : <Text type="supporting">—</Text>},
    {key: 'peers', header: 'Peers', width: pixel(80), align: 'end'},
    {key: 'dht', header: 'Discovery', width: pixel(90), align: 'end'},
    {key: 'queue', header: 'Queue · p95', width: pixel(140), align: 'end'},
    {key: 'blocked', header: 'Blocked on', width: pixel(130)},
    {key: 'transport', header: 'Transport', width: pixel(110), renderCell: row => <Token label={row.transport} color="blue" size="sm" />},
  ];
  return (
    <Card padding={0} elevation="low">
      <Section padding={4} dividers={['bottom']}><Heading level={3}>Node state matrix</Heading></Section>
      <Table data={data} columns={columns} idKey="id" density="compact" dividers="rows" isStriped hasHover textOverflow="truncate" />
    </Card>
  );
}

interface ReporterRow extends Record<string, unknown> {id: string; reporter: string; role: string; status: Health; lastSeen: string; accepted: number; rejected: number; skew: string; coverage: number;}

function ReporterTable({reporters}: {reporters: ReporterState[]}) {
  const data: ReporterRow[] = reporters.map(reporter => ({id: reporter.id, reporter: reporter.label, role: reporter.role, status: reporter.health, lastSeen: reporter.lastSeen, accepted: reporter.acceptedBatches, rejected: reporter.rejectedBatches, skew: `${reporter.clockSkewMs} ms`, coverage: reporter.observedNodes}));
  const columns: TableColumn<ReporterRow>[] = [
    {key: 'reporter', header: 'Trusted reporter', width: proportional(1.4), renderCell: row => <HStack gap={2} align="center"><StatusDot variant={statusVariant(row.status)} label={row.status} /><Text type="label">{row.reporter}</Text></HStack>},
    {key: 'role', header: 'Role', width: pixel(100)},
    {key: 'lastSeen', header: 'Last accepted', width: proportional(1), renderCell: row => <Timestamp value={row.lastSeen} format="relative" />},
    {key: 'coverage', header: 'Nodes seen', width: pixel(100), align: 'end'},
    {key: 'accepted', header: 'Metric families', width: pixel(120), align: 'end'},
    {key: 'rejected', header: 'Rejected', width: pixel(90), align: 'end'},
    {key: 'skew', header: 'Freshness', width: pixel(110), align: 'end'},
  ];
  return <Card padding={0} elevation="low"><Section padding={4} dividers={['bottom']}><VStack gap={1}><Heading level={3}>Federation reporters</Heading><Text type="supporting" color="secondary">Freshness, rejection, clock, and coverage health for each telemetry trust relationship</Text></VStack></Section><Table data={data} columns={columns} idKey="id" density="compact" dividers="rows" isStriped /></Card>;
}

function ReachabilityPanel({snapshot}: {snapshot: NetworkSnapshot}) {
  const regions = new Set(snapshot.nodes.map(node => node.region)).size;
  const knownPeerCounts = snapshot.nodes.map(peerTotal).filter((value): value is number => value !== null);
  const peers = knownPeerCounts.reduce((sum, value) => sum + value, 0);
  const linkedActors = new Set(snapshot.links.flatMap(link => [link.source, link.target]));
  return <VStack gap={3}><Coverage label="Actor freshness" value={snapshot.summary.reportingNodes / Math.max(snapshot.reporters.length, 1)} /><Coverage label="Height-cohort agreement" value={snapshot.summary.heightAgreement} /><HStack justify="between" align="center" gap={3}><Text type="label">Observed enrolled-link scope</Text><Text type="code" color="secondary" hasTabularNumbers>{linkedActors.size}/{snapshot.nodes.length} actors</Text></HStack><Grid columns={3} gap={3}><Metric label="Regions" value={String(regions)} detail="server-assigned coarse buckets" tone="blue" /><Metric label="Connection total" value={knownPeerCounts.length ? String(peers) : '—'} detail={`sum of ${knownPeerCounts.length}/${snapshot.nodes.length} actor gauges; not unique links`} tone="cyan" /><Metric label="Enrolled actor links" value={String(snapshot.links.length)} detail={`${snapshot.links.filter(link => link.corroborated).length} corroborated · ${linkedActors.size}/${snapshot.nodes.length} actors`} tone="purple" /></Grid><Text type="supporting" color="secondary">Height agreement is the largest same-height node cohort. Newest-height adoption is shown separately and, without block IDs, neither signal proves same-height fork agreement.</Text></VStack>;
}

function Coverage({label, value}: {label: string; value: number}) {
  return <ProgressBar value={Math.round(value * 100)} max={100} label={label} hasValueLabel variant={value >= 0.9 ? 'success' : value >= 0.7 ? 'warning' : 'error'} />;
}

function EvidenceStep({number, title, detail}: {number: string; title: string; detail: string}) {
  return <HStack gap={3} align="start"><Token label={number} color="blue" size="sm" /><VStack gap={1}><Text type="label">{title}</Text><Text type="supporting" color="secondary">{detail}</Text></VStack></HStack>;
}

function SignalCheck({label, value, healthy}: {label: string; value: string; healthy: boolean}) {
  return <HStack justify="between" align="center" gap={3}><HStack gap={2} align="center"><StatusDot variant={healthy ? 'success' : 'warning'} label={`${label}: ${healthy ? 'within budget' : 'outside budget'}`} /><Text type="label">{label}</Text></HStack><Text type="supporting" color="secondary" hasTabularNumbers>{value}</Text></HStack>;
}

function RoleLegend({role, label}: {role: NodeObservation['role']; label: string}) {
  return <HStack gap={1.5} align="center"><svg className="topology-legend-dot" viewBox="0 0 12 12" aria-hidden="true"><circle className={`topology__dot topology__dot--${role}`} cx="6" cy="6" r="5" /></svg><Text type="supporting">{label}</Text></HStack>;
}

function RelationshipLegend({label}: {label: string}) {
  return <HStack gap={1.5} align="center"><svg className="topology-legend-line" viewBox="0 0 20 12" aria-hidden="true"><line className="topology__binding" x1="1" y1="6" x2="19" y2="6" /></svg><Text type="supporting">{label}</Text></HStack>;
}

function LoadingState() {
  return <Section padding={10}><VStack gap={4} align="center"><StatusDot variant="accent" label="Loading telemetry" isPulsing /><Heading level={3}>Connecting to the collector</Heading><Text type="supporting" color="secondary">Waiting for the first bounded network snapshot…</Text></VStack></Section>;
}

function ObserverMark() {
  return <svg className="observer-mark" viewBox="0 0 28 28" role="img" aria-label="Stacks network observer"><circle cx="14" cy="14" r="12" /><path d="M7 10h14M7 18h14M10 7v14M18 7v14" /></svg>;
}

function labelFor(snapshot: NetworkSnapshot, id: string): string { return snapshot.nodes.find(node => node.id === id)?.label ?? baseNodeId(id); }
function baseNodeId(id: string): string { return id.includes('--') ? id.slice(id.indexOf('--') + 2) : id; }
function formatNumber(value: number): string { return new Intl.NumberFormat('en-US').format(value); }
function formatOptionalNumber(value: number | null): string { return value === null ? '—' : formatNumber(value); }
function formatPercent(value: number): string { return new Intl.NumberFormat('en-US', {style: 'percent', maximumFractionDigits: 0}).format(value); }
function formatDuration(seconds: number): string { return seconds < 1 ? '<1s' : seconds < 60 ? `${Math.floor(seconds)}s` : `${Math.floor(seconds / 60)}m`; }
function formatMetricValue(value: number, unit: MetricReading['unit']): string {
  if (unit === 'bytes') return value < 1_024 ? `${formatNumber(value)} B` : `${new Intl.NumberFormat('en-US', {maximumFractionDigits: 1}).format(value / 1_024)} KiB`;
  if (unit === 'seconds') return value < 1 ? `${Math.round(value * 1_000)} ms` : `${new Intl.NumberFormat('en-US', {maximumFractionDigits: 3}).format(value)} s`;
  if (unit === 'timestamp') return new Date(value * 1_000).toLocaleTimeString();
  return new Intl.NumberFormat('en-US', {maximumFractionDigits: 3}).format(value);
}
function formatRelativeAge(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return 'unknown';
  return formatDuration(Math.max(0, (Date.now() - timestamp) / 1_000));
}
function peerTotal(node: NodeObservation): number | null {
  const values = [node.inboundPeers, node.outboundPeers].filter((value): value is number => value !== null);
  return values.length ? values.reduce((sum, value) => sum + value, 0) : null;
}
function sumReadings(inventories: ActorMetricInventory[], name: string): number {
  return inventories.flatMap(inventory => inventory.readings)
    .filter(reading => reading.name === name)
    .reduce((total, reading) => total + reading.value, 0);
}
function sumEvent(inventories: ActorMetricInventory[], event: string): number {
  return inventories.flatMap(inventory => inventory.readings)
    .filter(reading => reading.name === 'stacks_p2p_events_total' &&
      reading.attributes.some(attribute => attribute.key === 'event' && attribute.value === event))
    .reduce((total, reading) => total + reading.value, 0);
}
function maximumReading(inventories: ActorMetricInventory[], name: string): number | null {
  const values = inventories.flatMap(inventory => inventory.readings)
    .filter(reading => reading.name === name)
    .map(reading => reading.value);
  return values.length ? Math.max(...values) : null;
}
function metricValue(inventory: ActorMetricInventory, name: string): number {
  return inventory.readings
    .filter(reading => reading.name === name)
    .reduce((total, reading) => total + reading.value, 0);
}
function attributedMetricValue(
  inventory: ActorMetricInventory,
  name: string,
  attribute: string,
  value: string,
): number {
  return inventory.readings
    .filter(reading => reading.name === name &&
      reading.attributes.some(item => item.key === attribute && item.value === value))
    .reduce((total, reading) => total + reading.value, 0);
}
function shortKey(value: string | null): string { return value ? `${value.slice(0, 10)}…${value.slice(-8)}` : 'identity unavailable'; }
function formatMicroStx(value: string): string {
  try {
    return `${new Intl.NumberFormat('en-US', {maximumFractionDigits: 2}).format(Number(BigInt(value)) / 1_000_000)} STX`;
  } catch {
    return '—';
  }
}
function formatLabeledCounts(values: Array<Record<string, string | number>>, label: string): string {
  return values.slice(0, 3).map(value => `${String(value[label] ?? 'unknown')} ${formatNumber(Number(value.count ?? 0))}`).join(' · ') || 'none';
}
function statusVariant(value: Health): 'success' | 'warning' | 'error' | 'neutral' { return value === 'healthy' ? 'success' : value === 'degraded' ? 'warning' : value === 'critical' ? 'error' : 'neutral'; }
function statusToken(value: Health): 'green' | 'yellow' | 'red' | 'gray' { return value === 'healthy' ? 'green' : value === 'degraded' ? 'yellow' : value === 'critical' ? 'red' : 'gray'; }
function roleToken(role: string): 'purple' | 'cyan' | 'blue' | 'gray' { return role === 'signer' ? 'purple' : role === 'companion' ? 'cyan' : role === 'miner' ? 'blue' : 'gray'; }
function signerStateToken(state: string | undefined): 'green' | 'yellow' | 'red' | 'gray' { return state === 'initialized' ? 'green' : state === 'pending' ? 'yellow' : state === 'uninitialized' ? 'red' : 'gray'; }
function quorumStatusToken(status: string): 'green' | 'blue' | 'red' | 'gray' {
  return status === 'approved' ? 'green' : status === 'collecting' ? 'blue' : status === 'rejected' || status === 'timed-out' ? 'red' : 'gray';
}
function voteDecisionToken(decision: string): 'green' | 'red' | 'yellow' | 'gray' {
  return decision === 'approved' ? 'green' : decision === 'rejected' ? 'red' : decision === 'unavailable' ? 'yellow' : 'gray';
}
